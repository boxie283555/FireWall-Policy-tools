from __future__ import annotations

import csv
from collections import Counter
from io import StringIO
from typing import Any

from app.models import AnalysisFinding, NatRule, PolicyRule


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def analysis_summary(policy_findings: list[AnalysisFinding], nat_findings: list[dict[str, Any]]) -> dict[str, Any]:
    policy_rows = [finding.model_dump() for finding in policy_findings]
    all_rows = policy_rows + nat_findings
    severity_counts = Counter(str(row.get("severity", "unknown")) for row in all_rows)
    category_counts = Counter(str(row.get("category", "unknown")) for row in all_rows)
    policy_ids_by_category: dict[str, set[str]] = {}
    for row in all_rows:
        category = str(row.get("category", "unknown"))
        ids = row.get("policy_ids") or row.get("rule_ids") or []
        policy_ids_by_category.setdefault(category, set()).update(str(item) for item in ids)

    sorted_rows = sorted(
        all_rows,
        key=lambda row: (SEVERITY_ORDER.get(str(row.get("severity", "unknown")), 99), str(row.get("category", "")), str(row.get("title", ""))),
    )
    return {
        "total_findings": len(all_rows),
        "severity_counts": dict(sorted(severity_counts.items(), key=lambda item: SEVERITY_ORDER.get(item[0], 99))),
        "category_counts": dict(category_counts.most_common()),
        "policy_categories": [
            {"category": category, "affected_count": len(ids)}
            for category, ids in sorted(policy_ids_by_category.items(), key=lambda item: (-len(item[1]), item[0]))
        ],
        "top_findings": sorted_rows[:25],
    }


def findings_csv(policy_findings: list[AnalysisFinding], nat_findings: list[dict[str, Any]]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["type", "severity", "category", "title", "detail", "policy_ids", "recommendation"],
    )
    writer.writeheader()
    for finding in policy_findings:
        writer.writerow(
            {
                "type": "policy",
                "severity": finding.severity,
                "category": finding.category,
                "title": finding.title,
                "detail": finding.detail,
                "policy_ids": " ".join(finding.policy_ids),
                "recommendation": finding.recommendation,
            }
        )
    for finding in nat_findings:
        writer.writerow(
            {
                "type": "nat",
                "severity": finding.get("severity", ""),
                "category": finding.get("category", ""),
                "title": finding.get("title", ""),
                "detail": finding.get("detail", ""),
                "policy_ids": " ".join(str(item) for item in finding.get("rule_ids", [])),
                "recommendation": finding.get("recommendation", ""),
            }
        )
    return output.getvalue()


def policies_csv(policies: list[PolicyRule]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "vendor",
            "device_name",
            "line_no",
            "rule_name",
            "source_zones",
            "destination_zones",
            "source_addresses",
            "destination_addresses",
            "services",
            "applications",
            "users",
            "action",
            "enabled",
            "owner",
            "expires_at",
        ],
    )
    writer.writeheader()
    for policy in policies:
        writer.writerow(
            {
                "vendor": policy.vendor.value,
                "device_name": policy.device_name,
                "line_no": policy.line_no or "",
                "rule_name": policy.rule_name,
                "source_zones": " ".join(policy.source_zones),
                "destination_zones": " ".join(policy.destination_zones),
                "source_addresses": " ".join(policy.source_addresses),
                "destination_addresses": " ".join(policy.destination_addresses),
                "services": " ".join(policy.services),
                "applications": " ".join(policy.applications),
                "users": " ".join(policy.users),
                "action": policy.action,
                "enabled": policy.enabled,
                "owner": policy.owner or "",
                "expires_at": policy.expires_at or "",
            }
        )
    return output.getvalue()


def nat_csv(rules: list[NatRule]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "vendor",
            "device_name",
            "line_no",
            "rule_name",
            "nat_type",
            "source_zones",
            "destination_zones",
            "original_sources",
            "original_destinations",
            "original_services",
            "translated_sources",
            "translated_destinations",
            "translated_services",
            "enabled",
        ],
    )
    writer.writeheader()
    for rule in rules:
        writer.writerow(
            {
                "vendor": rule.vendor.value,
                "device_name": rule.device_name,
                "line_no": rule.line_no or "",
                "rule_name": rule.rule_name,
                "nat_type": rule.nat_type,
                "source_zones": " ".join(rule.source_zones),
                "destination_zones": " ".join(rule.destination_zones),
                "original_sources": " ".join(rule.original_sources),
                "original_destinations": " ".join(rule.original_destinations),
                "original_services": " ".join(rule.original_services),
                "translated_sources": " ".join(rule.translated_sources),
                "translated_destinations": " ".join(rule.translated_destinations),
                "translated_services": " ".join(rule.translated_services),
                "enabled": rule.enabled,
            }
        )
    return output.getvalue()
