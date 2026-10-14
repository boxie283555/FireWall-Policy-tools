from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.analyzer import _covers, _dangerous_apps, _dangerous_services, _has_any
from app.models import FirewallObject, PolicyPathRequest, PolicyQuery, PolicyRule


ALLOW_ACTIONS = {"allow", "permit", "accept"}


def filter_policies(policies: list[PolicyRule], query: PolicyQuery) -> list[PolicyRule]:
    filtered = policies
    if query.vendor:
        filtered = [p for p in filtered if p.vendor.value == query.vendor]
    if query.device_name:
        filtered = [p for p in filtered if _contains(p.device_name, query.device_name)]
    if query.action:
        filtered = [p for p in filtered if p.action.lower() == query.action.lower()]
    if query.enabled is not None:
        filtered = [p for p in filtered if p.enabled is query.enabled]
    field_checks = [
        (query.source_zone, lambda p: p.source_zones),
        (query.destination_zone, lambda p: p.destination_zones),
        (query.source, lambda p: p.source_addresses),
        (query.destination, lambda p: p.destination_addresses),
        (query.service, lambda p: p.services),
        (query.application, lambda p: p.applications),
        (query.user, lambda p: p.users),
    ]
    for value, getter in field_checks:
        if value:
            filtered = [p for p in filtered if _matches_field(getter(p), value)]
    if query.query:
        needle = query.query.lower()
        filtered = [p for p in filtered if needle in p.model_dump_json().lower()]
    return filtered


def path_analysis(policies: list[PolicyRule], request: PolicyPathRequest) -> dict[str, Any]:
    query = PolicyQuery(
        vendor=request.vendor,
        device_name=request.device_name,
        source=request.source,
        destination=request.destination,
        service=request.service,
        application=request.application,
        user=request.user,
        source_zone=request.source_zone,
        destination_zone=request.destination_zone,
    )
    candidates = filter_policies([p for p in policies if p.enabled], query)
    candidates = sorted(candidates, key=lambda p: (p.device_name, p.line_no or 10**9, p.rule_name))
    first_match = candidates[0] if candidates else None
    shadowed = []
    for idx, earlier in enumerate(candidates):
        for later in candidates[idx + 1 :]:
            if _covers(earlier, later):
                shadowed.append({"by": _policy_summary(earlier), "policy": _policy_summary(later)})
    return {
        "request": request.model_dump(),
        "first_match": _policy_summary(first_match) if first_match else None,
        "matched_count": len(candidates),
        "matched_policies": [_policy_summary(p) for p in candidates[:100]],
        "shadowed": shadowed[:50],
    }


def zone_matrix(policies: list[PolicyRule]) -> dict[str, Any]:
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    zones: set[str] = set()
    for policy in policies:
        src_zones = policy.source_zones or ["any"]
        dst_zones = policy.destination_zones or ["any"]
        for src in src_zones:
            for dst in dst_zones:
                zones.update([src, dst])
                key = (src, dst)
                cell = cells.setdefault(
                    key,
                    {"source_zone": src, "destination_zone": dst, "count": 0, "allow": 0, "deny": 0, "risk": 0, "policy_ids": []},
                )
                cell["count"] += 1
                cell["policy_ids"].append(policy.id)
                if policy.action.lower() in ALLOW_ACTIONS:
                    cell["allow"] += 1
                else:
                    cell["deny"] += 1
                if _has_any(policy.source_addresses) or _has_any(policy.destination_addresses) or _has_any(policy.services):
                    cell["risk"] += 1
    return {"zones": sorted(zones), "cells": list(cells.values())}


def topology(policies: list[PolicyRule]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for policy in policies:
        src_zones = policy.source_zones or ["any"]
        dst_zones = policy.destination_zones or ["any"]
        for zone in src_zones + dst_zones:
            node = nodes.setdefault(zone, {"id": zone, "label": zone, "policy_count": 0})
            node["policy_count"] += 1
        for src in src_zones:
            for dst in dst_zones:
                key = (src, dst)
                edge = edges.setdefault(key, {"source": src, "target": dst, "count": 0, "allow": 0, "deny": 0, "risk": 0})
                edge["count"] += 1
                if policy.action.lower() in ALLOW_ACTIONS:
                    edge["allow"] += 1
                else:
                    edge["deny"] += 1
                if _dangerous_services(policy.services) or _dangerous_apps(policy.applications):
                    edge["risk"] += 1
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def object_dependencies(policies: list[PolicyRule], objects: list[FirewallObject]) -> dict[str, Any]:
    object_names = {obj.name for obj in objects}
    object_types: dict[str, set[str]] = defaultdict(set)
    for obj in objects:
        object_types[obj.name].add(obj.type)
    references: dict[str, dict[str, Any]] = {
        name: {"object": name, "types": sorted(object_types[name]), "policy_count": 0, "policies": []}
        for name in object_names
    }
    for policy in policies:
        for value in policy.source_addresses + policy.destination_addresses + policy.services + policy.applications:
            name = _object_name(value)
            if name in references:
                references[name]["policy_count"] += 1
                references[name]["policies"].append(_policy_summary(policy))

    top_refs = sorted(references.values(), key=lambda item: item["policy_count"], reverse=True)
    return {
        "referenced": [item for item in top_refs if item["policy_count"] > 0][:300],
        "unreferenced": [item for item in top_refs if item["policy_count"] == 0][:300],
    }


def object_dependency_detail(policies: list[PolicyRule], objects: list[FirewallObject], object_name: str) -> dict[str, Any]:
    needle = object_name.strip().lower()
    matched_objects = [
        obj
        for obj in objects
        if obj.name.lower() == needle or needle in obj.name.lower()
    ]
    exact_names = {obj.name for obj in matched_objects if obj.name.lower() == needle}
    candidate_names = exact_names or {obj.name for obj in matched_objects}

    references: list[dict[str, Any]] = []
    for policy in policies:
        matched_fields: list[dict[str, str]] = []
        for field_name, values in [
            ("source", policy.source_addresses),
            ("destination", policy.destination_addresses),
            ("service", policy.services),
            ("application", policy.applications),
            ("user", policy.users),
        ]:
            for value in values:
                normalized = _object_name(value)
                if normalized in candidate_names or normalized.lower() == needle or needle in normalized.lower():
                    matched_fields.append({"field": field_name, "value": value})
        if matched_fields:
            references.append({"policy": _policy_summary(policy), "fields": matched_fields})

    return {
        "query": object_name,
        "objects": [
            {
                "name": obj.name,
                "type": obj.type,
                "value": obj.value,
                "vendor": obj.vendor.value,
                "device_name": obj.device_name,
            }
            for obj in matched_objects[:100]
        ],
        "reference_count": len(references),
        "references": references[:500],
    }


def policy_dependency_detail(policies: list[PolicyRule], objects: list[FirewallObject], policy_query: str) -> dict[str, Any]:
    needle = policy_query.strip().lower()
    object_map: dict[str, list[FirewallObject]] = defaultdict(list)
    for obj in objects:
        object_map[obj.name].append(obj)

    matched_policies = [
        policy
        for policy in policies
        if policy.id.lower() == needle or policy.rule_name.lower() == needle or needle in policy.rule_name.lower()
    ]

    results: list[dict[str, Any]] = []
    for policy in matched_policies[:100]:
        references = []
        for field_name, values in [
            ("source", policy.source_addresses),
            ("destination", policy.destination_addresses),
            ("service", policy.services),
            ("application", policy.applications),
            ("user", policy.users),
        ]:
            for value in values:
                object_name = _object_name(value)
                definitions = [
                    {
                        "name": obj.name,
                        "type": obj.type,
                        "value": obj.value,
                        "vendor": obj.vendor.value,
                        "device_name": obj.device_name,
                    }
                    for obj in object_map.get(object_name, [])
                ]
                references.append(
                    {
                        "field": field_name,
                        "value": value,
                        "object": object_name,
                        "defined": bool(definitions),
                        "definitions": definitions[:20],
                    }
                )
        results.append({"policy": _policy_summary(policy), "references": references})

    return {
        "query": policy_query,
        "match_count": len(matched_policies),
        "policies": results,
    }


def rule_order(policies: list[PolicyRule]) -> list[dict[str, Any]]:
    ordered = sorted(policies, key=lambda p: (p.vendor.value, p.device_name, p.line_no or 10**9, p.rule_name))
    rows = []
    for idx, policy in enumerate(ordered, start=1):
        covered_by = []
        for earlier in ordered[: idx - 1]:
            if earlier.device_name == policy.device_name and earlier.vendor == policy.vendor and _covers(earlier, policy):
                covered_by.append(earlier.rule_name)
        rows.append(
            {
                **_policy_summary(policy),
                "order": idx,
                "covered_by": covered_by[:5],
                "is_shadow_candidate": bool(covered_by),
            }
        )
    return rows


def _matches_field(values: list[str], needle: str) -> bool:
    if not values:
        return needle.lower() in {"any", "all", "*"}
    needle_lower = needle.lower()
    if _has_any(values):
        return True
    return any(needle_lower == value.lower() or needle_lower in value.lower() for value in values)


def _contains(value: str, needle: str) -> bool:
    return needle.lower() in value.lower()


def _object_name(value: str) -> str:
    if ":" in value:
        return value.split(":", 1)[1]
    return value.strip('"')


def _policy_summary(policy: PolicyRule | None) -> dict[str, Any]:
    if policy is None:
        return {}
    return {
        "id": policy.id,
        "vendor": policy.vendor.value,
        "device_name": policy.device_name,
        "rule_name": policy.rule_name,
        "source_zones": policy.source_zones,
        "destination_zones": policy.destination_zones,
        "source_addresses": policy.source_addresses,
        "destination_addresses": policy.destination_addresses,
        "services": policy.services,
        "applications": policy.applications,
        "users": policy.users,
        "action": policy.action,
        "enabled": policy.enabled,
        "line_no": policy.line_no,
    }
