from __future__ import annotations

import re
import shlex
from hashlib import sha1

from app.models import FirewallObject, ParseResult, PolicyRule, Vendor

ANY_VALUES = {"any", "any4", "any6", "all", "0.0.0.0/0", "::/0"}


def parse_config(vendor: Vendor, device_name: str, config_text: str) -> ParseResult:
    if vendor == Vendor.cisco_asa:
        return parse_cisco_asa(device_name, config_text)
    if vendor == Vendor.palo_alto:
        return parse_palo_alto(device_name, config_text)
    if vendor in {Vendor.fortinet, Vendor.fortigate}:
        return parse_fortinet(device_name, config_text)
    if vendor == Vendor.huawei:
        return parse_huawei(device_name, config_text)
    raise ValueError(f"Unsupported vendor: {vendor}")


def _rule_id(vendor: Vendor, device_name: str, raw: str, line_no: int | None) -> str:
    seed = f"{vendor}:{device_name}:{line_no}:{raw}"
    return sha1(seed.encode("utf-8")).hexdigest()[:12]


def _split_csvish(value: str) -> list[str]:
    if not value:
        return []
    return [item.strip().strip('"') for item in re.split(r"[,\s]+", value) if item.strip()]


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_cisco_asa(device_name: str, config_text: str) -> ParseResult:
    policies: list[PolicyRule] = []
    objects: list[FirewallObject] = []
    warnings: list[str] = []
    current_object: tuple[str, str] | None = None
    current_group: tuple[str, str] | None = None
    acl_bindings: dict[str, str] = {}

    for line_no, raw_line in enumerate(config_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("!"):
            continue

        access_group_match = re.match(r"^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)", line)
        if access_group_match:
            acl_bindings[access_group_match.group(1)] = f"{access_group_match.group(3)}:{access_group_match.group(2)}"
            continue

        object_match = re.match(r"^object\s+(network|service)\s+(\S+)", line)
        if object_match:
            current_object = (object_match.group(1), object_match.group(2))
            current_group = None
            continue

        group_match = re.match(r"^object-group\s+(network|service)\s+(\S+)", line)
        if group_match:
            current_group = (group_match.group(1), group_match.group(2))
            current_object = None
            objects.append(FirewallObject(name=current_group[1], type=f"{current_group[0]}_group", value="", vendor=Vendor.cisco_asa))
            continue

        if current_object:
            value_match = re.match(r"^(host|subnet|range|service|description)\s+(.+)", line)
            if value_match:
                objects.append(
                    FirewallObject(
                        name=current_object[1],
                        type=current_object[0],
                        value=f"{value_match.group(1)} {value_match.group(2)}",
                        vendor=Vendor.cisco_asa,
                    )
                )
                continue

        if current_group:
            value_match = re.match(r"^(network-object|service-object|group-object|port-object)\s+(.+)", line)
            if value_match:
                objects.append(
                    FirewallObject(
                        name=current_group[1],
                        type=f"{current_group[0]}_group_member",
                        value=f"{value_match.group(1)} {value_match.group(2)}",
                        vendor=Vendor.cisco_asa,
                    )
                )
                continue

        if not line.startswith("access-list "):
            continue

        try:
            tokens = shlex.split(line)
        except ValueError:
            warnings.append(f"Line {line_no}: could not tokenize ASA ACL")
            continue

        if len(tokens) < 6 or "extended" not in tokens:
            continue

        acl_name = tokens[1]
        ext_idx = tokens.index("extended")
        action = tokens[ext_idx + 1] if len(tokens) > ext_idx + 1 else "unknown"
        protocol = tokens[ext_idx + 2] if len(tokens) > ext_idx + 2 else "ip"
        rest = tokens[ext_idx + 3 :]

        src, dst, services = _parse_asa_acl_endpoints(rest, protocol)
        policies.append(
            PolicyRule(
                id=_rule_id(Vendor.cisco_asa, device_name, line, line_no),
                vendor=Vendor.cisco_asa,
                device_name=device_name,
                rule_name=acl_name,
                source_zones=[f"ACL:{acl_name}"],
                source_addresses=src,
                destination_addresses=dst,
                services=services,
                action=action,
                raw=line,
                line_no=line_no,
            )
        )

    for policy in policies:
        if policy.rule_name in acl_bindings:
            policy.source_zones = [acl_bindings[policy.rule_name]]

    return ParseResult(vendor=Vendor.cisco_asa, device_name=device_name, policies=policies, objects=_dedupe_objects(objects), warnings=warnings)


def _parse_asa_acl_endpoints(tokens: list[str], protocol: str) -> tuple[list[str], list[str], list[str]]:
    def parse_endpoint(idx: int) -> tuple[str, int]:
        if idx >= len(tokens):
            return "any", idx
        token = tokens[idx]
        if token == "any":
            return "any", idx + 1
        if token == "host" and idx + 1 < len(tokens):
            return tokens[idx + 1], idx + 2
        if token in {"object", "object-group"} and idx + 1 < len(tokens):
            return f"{token}:{tokens[idx + 1]}", idx + 2
        if idx + 1 < len(tokens) and re.match(r"^\d+\.\d+\.\d+\.\d+$", token):
            return f"{token} {tokens[idx + 1]}", idx + 2
        return token, idx + 1

    src, idx = parse_endpoint(0)
    dst, idx = parse_endpoint(idx)
    services = [protocol]
    if idx < len(tokens):
        op = tokens[idx]
        if op in {"eq", "range", "lt", "gt", "neq"}:
            services = [f"{protocol}/{op} {' '.join(tokens[idx + 1:])}".strip()]
        elif op == "object-group" and idx + 1 < len(tokens):
            services = [f"object-group:{tokens[idx + 1]}"]
    return [src], [dst], services


def parse_palo_alto(device_name: str, config_text: str) -> ParseResult:
    if _looks_like_pan_brace_config(config_text):
        return parse_palo_alto_brace(device_name, config_text)

    policies_by_name: dict[str, PolicyRule] = {}
    objects: list[FirewallObject] = []
    warnings: list[str] = []

    for line_no, raw_line in enumerate(config_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            warnings.append(f"Line {line_no}: could not tokenize Palo Alto set command")
            continue

        if len(tokens) >= 6 and tokens[:3] == ["set", "rulebase", "security"] and tokens[3] == "rules":
            name = tokens[4]
            rule = policies_by_name.setdefault(
                name,
                PolicyRule(
                    id=_rule_id(Vendor.palo_alto, device_name, name, line_no),
                    vendor=Vendor.palo_alto,
                    device_name=device_name,
                    rule_name=name,
                    raw="",
                    line_no=line_no,
                ),
            )
            _apply_pan_rule_tokens(rule, tokens[5:])
            rule.raw = f"{rule.raw}\n{line}".strip()
            continue

        if len(tokens) >= 6 and tokens[:3] == ["set", "address"]:
            name = tokens[2]
            objects.append(FirewallObject(name=name, type="address", value=" ".join(tokens[3:]), vendor=Vendor.palo_alto))
            continue

        if len(tokens) >= 6 and tokens[:3] == ["set", "service"]:
            name = tokens[2]
            objects.append(FirewallObject(name=name, type="service", value=" ".join(tokens[3:]), vendor=Vendor.palo_alto))
            continue

    return ParseResult(vendor=Vendor.palo_alto, device_name=device_name, policies=list(policies_by_name.values()), objects=_dedupe_objects(objects), warnings=warnings)


def _looks_like_pan_brace_config(config_text: str) -> bool:
    sample = config_text[:20000]
    return "config {" in sample and "rulebase {" in config_text and "security {" in config_text and "rules {" in config_text


def parse_palo_alto_brace(device_name: str, config_text: str) -> ParseResult:
    policies: list[PolicyRule] = []
    objects: list[FirewallObject] = []
    warnings: list[str] = []
    stack: list[str] = []
    current_rule: dict[str, object] | None = None
    current_rule_depth = 0
    current_object: dict[str, object] | None = None
    current_object_depth = 0
    object_containers = {"address", "address-group", "service", "service-group"}

    for line_no, raw_line in enumerate(config_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        if current_rule is not None:
            current_rule["raw_lines"].append(raw_line)
            _capture_pan_brace_statement(current_rule["fields"], line)

        if current_object is not None:
            current_object["raw_lines"].append(line)

        if line == "}":
            if current_rule is not None and len(stack) == current_rule_depth:
                policies.append(_pan_brace_rule_from_block(device_name, current_rule))
                current_rule = None
                current_rule_depth = 0
            if current_object is not None and len(stack) == current_object_depth:
                objects.append(_pan_brace_object_from_block(current_object))
                current_object = None
                current_object_depth = 0
            if stack:
                stack.pop()
            else:
                warnings.append(f"Line {line_no}: unmatched closing brace")
            continue

        block_match = re.match(r"^(.+?)\s+\{$", line)
        if block_match:
            block_head = block_match.group(1).strip()
            parent = stack[-1] if stack else ""

            if current_rule is None and stack[-3:] == ["rulebase", "security", "rules"]:
                rule_name = _pan_block_name(block_head)
                current_rule = {
                    "name": rule_name,
                    "line_no": line_no,
                    "raw_lines": [raw_line],
                    "fields": {},
                }
                current_rule_depth = len(stack) + 1

            if current_object is None and parent in object_containers and "rulebase" not in stack:
                object_name = _pan_block_name(block_head)
                current_object = {
                    "name": object_name,
                    "type": parent,
                    "raw_lines": [line],
                }
                current_object_depth = len(stack) + 1

            stack.append(_pan_block_name(block_head))
            continue

        if current_rule is not None:
            _capture_pan_brace_statement(current_rule["fields"], line)

    if current_rule is not None:
        warnings.append(f"Line {current_rule.get('line_no')}: unterminated security rule")
    if current_object is not None:
        warnings.append(f"Object {current_object.get('name')}: unterminated object block")

    return ParseResult(vendor=Vendor.palo_alto, device_name=device_name, policies=policies, objects=_dedupe_objects(objects), warnings=warnings)


def _pan_block_name(block_head: str) -> str:
    try:
        tokens = shlex.split(block_head)
    except ValueError:
        tokens = block_head.split()
    if not tokens:
        return block_head
    return tokens[0]


def _capture_pan_brace_statement(fields: dict[str, list[str]], line: str) -> None:
    match = re.match(r"^([A-Za-z0-9_-]+)\s+(.+);$", line)
    if not match:
        return
    key = match.group(1)
    raw_value = match.group(2).strip()
    if key not in {"from", "to", "source", "destination", "service", "application", "source-user", "action", "disabled", "tag"}:
        return
    fields[key] = _pan_brace_values(raw_value)


def _pan_brace_values(raw_value: str) -> list[str]:
    raw_value = raw_value.strip()
    if raw_value.startswith("[") and raw_value.endswith("]"):
        raw_value = raw_value[1:-1].strip()
    try:
        values = shlex.split(raw_value)
    except ValueError:
        values = raw_value.split()
    return [value for value in values if value]


def _pan_brace_rule_from_block(device_name: str, data: dict[str, object]) -> PolicyRule:
    fields = data["fields"]
    assert isinstance(fields, dict)
    raw = "\n".join(data["raw_lines"])
    line_no = int(data["line_no"])
    name = str(data["name"])
    return PolicyRule(
        id=_rule_id(Vendor.palo_alto, device_name, raw, line_no),
        vendor=Vendor.palo_alto,
        device_name=device_name,
        rule_name=name,
        source_zones=_dedupe(fields.get("from", [])),
        destination_zones=_dedupe(fields.get("to", [])),
        source_addresses=_dedupe(fields.get("source", [])),
        destination_addresses=_dedupe(fields.get("destination", [])),
        services=_dedupe(fields.get("service", [])),
        applications=_dedupe(fields.get("application", [])),
        users=_dedupe(fields.get("source-user", [])),
        action=(fields.get("action", ["unknown"]) or ["unknown"])[0],
        enabled=(fields.get("disabled", ["no"]) or ["no"])[0].lower() not in {"yes", "true"},
        raw=raw,
        line_no=line_no,
        tags=_dedupe(fields.get("tag", [])),
    )


def _pan_brace_object_from_block(data: dict[str, object]) -> FirewallObject:
    raw_lines = data["raw_lines"]
    assert isinstance(raw_lines, list)
    body = " ".join(str(line).strip() for line in raw_lines[1:])
    return FirewallObject(
        name=str(data["name"]),
        type=str(data["type"]),
        value=body,
        vendor=Vendor.palo_alto,
    )


def _apply_pan_rule_tokens(rule: PolicyRule, tokens: list[str]) -> None:
    if not tokens:
        return
    key = tokens[0]
    values = tokens[1:]
    if key == "from":
        rule.source_zones = _dedupe(rule.source_zones + values)
    elif key == "to":
        rule.destination_zones = _dedupe(rule.destination_zones + values)
    elif key == "source":
        rule.source_addresses = _dedupe(rule.source_addresses + values)
    elif key == "destination":
        rule.destination_addresses = _dedupe(rule.destination_addresses + values)
    elif key == "service":
        rule.services = _dedupe(rule.services + values)
    elif key == "application":
        rule.applications = _dedupe(rule.applications + values)
    elif key == "source-user":
        rule.users = _dedupe(rule.users + values)
    elif key == "action" and values:
        rule.action = values[0]
    elif key == "disabled" and values:
        rule.enabled = values[0].lower() not in {"yes", "true"}
    elif key == "tag":
        rule.tags = _dedupe(rule.tags + values)


def parse_fortinet(device_name: str, config_text: str) -> ParseResult:
    policies: list[PolicyRule] = []
    objects: list[FirewallObject] = []
    warnings: list[str] = []
    section: str | None = None
    current_policy: dict[str, str] | None = None
    current_object: dict[str, str] | None = None

    for line_no, raw_line in enumerate(config_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        if line == "config firewall policy":
            section = "policy"
            continue
        if line in {"config firewall address", "config firewall service custom", "config firewall addrgrp", "config firewall service group"}:
            section = line.replace("config firewall ", "")
            continue
        if line == "end":
            section = None
            current_policy = None
            current_object = None
            continue

        edit_match = re.match(r'^edit\s+"?([^"]+)"?$', line)
        if edit_match and section == "policy":
            current_policy = {"policyid": edit_match.group(1), "line_no": str(line_no), "raw": raw_line}
            continue
        if edit_match and section and section != "policy":
            current_object = {"name": edit_match.group(1), "type": section, "value": ""}
            continue

        if line == "next":
            if current_policy:
                policies.append(_fortinet_policy_from_block(Vendor.fortinet, device_name, current_policy))
            if current_object:
                objects.append(
                    FirewallObject(
                        name=current_object["name"],
                        type=current_object["type"],
                        value=current_object.get("value", ""),
                        vendor=Vendor.fortinet,
                    )
                )
            current_policy = None
            current_object = None
            continue

        set_match = re.match(r"^set\s+(\S+)\s+(.+)$", line)
        if set_match and current_policy is not None:
            current_policy[set_match.group(1)] = set_match.group(2)
            current_policy["raw"] = f"{current_policy.get('raw', '')}\n{raw_line}".strip()
            continue
        if set_match and current_object is not None:
            current_object["value"] = f"{current_object.get('value', '')} {set_match.group(1)}={set_match.group(2)}".strip()
            continue

    return ParseResult(vendor=Vendor.fortinet, device_name=device_name, policies=policies, objects=_dedupe_objects(objects), warnings=warnings)


def _fortinet_policy_from_block(vendor: Vendor, device_name: str, data: dict[str, str]) -> PolicyRule:
    raw = data.get("raw", "")
    line_no = int(data.get("line_no", "0")) or None
    policyid = data.get("policyid", "unknown")
    return PolicyRule(
        id=_rule_id(vendor, device_name, raw or policyid, line_no),
        vendor=vendor,
        device_name=device_name,
        rule_name=data.get("name", policyid).strip('"'),
        source_zones=_split_csvish(data.get("srcintf", "")),
        destination_zones=_split_csvish(data.get("dstintf", "")),
        source_addresses=_split_csvish(data.get("srcaddr", "")),
        destination_addresses=_split_csvish(data.get("dstaddr", "")),
        services=_split_csvish(data.get("service", "")),
        applications=[],
        action=data.get("action", "unknown").strip('"'),
        enabled=data.get("status", "enable").strip('"') != "disable",
        raw=raw,
        line_no=line_no,
    )


def parse_huawei(device_name: str, config_text: str) -> ParseResult:
    policies: list[PolicyRule] = []
    objects: list[FirewallObject] = []
    warnings: list[str] = []
    in_security_policy = False
    current_policy: dict[str, object] | None = None

    for line_no, raw_line in enumerate(config_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        if line in {"security-policy", "security-policy ipv6"}:
            in_security_policy = True
            continue

        if line == "#":
            if current_policy:
                policies.append(_huawei_policy_from_block(device_name, current_policy))
                current_policy = None
            in_security_policy = False
            continue

        address_set = re.match(r"^ip address-set\s+(\S+)", line)
        if address_set:
            objects.append(FirewallObject(name=address_set.group(1), type="address-set", value=line, vendor=Vendor.huawei))
            continue

        service_set = re.match(r"^(ip )?service-set\s+(\S+)", line)
        if service_set:
            objects.append(FirewallObject(name=service_set.group(2), type="service-set", value=line, vendor=Vendor.huawei))
            continue

        if not in_security_policy:
            continue

        rule_match = re.match(r"^rule\s+name\s+(.+)$", line)
        if rule_match:
            if current_policy:
                policies.append(_huawei_policy_from_block(device_name, current_policy))
            current_policy = {"name": rule_match.group(1).strip('"'), "line_no": line_no, "raw": raw_line, "fields": {}}
            continue

        if current_policy is None:
            continue

        current_policy["raw"] = f"{current_policy.get('raw', '')}\n{raw_line}".strip()
        fields = current_policy["fields"]
        assert isinstance(fields, dict)

        for key, target in [
            ("source-zone", "source_zones"),
            ("destination-zone", "destination_zones"),
            ("source-address", "source_addresses"),
            ("destination-address", "destination_addresses"),
            ("service", "services"),
            ("application", "applications"),
            ("user", "users"),
        ]:
            if line.startswith(f"{key} "):
                fields.setdefault(target, []).extend(_huawei_values(line[len(key) :].strip()))
                break
        else:
            action_match = re.match(r"^action\s+(\S+)", line)
            if action_match:
                fields["action"] = [action_match.group(1)]
            elif line == "disable":
                fields["enabled"] = ["false"]

    if current_policy:
        policies.append(_huawei_policy_from_block(device_name, current_policy))

    return ParseResult(vendor=Vendor.huawei, device_name=device_name, policies=policies, objects=_dedupe_objects(objects), warnings=warnings)


def _huawei_values(value: str) -> list[str]:
    value = value.replace("address-set", "").replace("service-set", "").strip()
    return _split_csvish(value)


def _huawei_policy_from_block(device_name: str, data: dict[str, object]) -> PolicyRule:
    fields = data.get("fields", {})
    assert isinstance(fields, dict)
    raw = str(data.get("raw", ""))
    line_no = int(data.get("line_no", "0")) or None
    return PolicyRule(
        id=_rule_id(Vendor.huawei, device_name, raw or str(data.get("name")), line_no),
        vendor=Vendor.huawei,
        device_name=device_name,
        rule_name=str(data.get("name", "unknown")),
        source_zones=_dedupe(fields.get("source_zones", [])),
        destination_zones=_dedupe(fields.get("destination_zones", [])),
        source_addresses=_dedupe(fields.get("source_addresses", [])),
        destination_addresses=_dedupe(fields.get("destination_addresses", [])),
        services=_dedupe(fields.get("services", [])),
        applications=_dedupe(fields.get("applications", [])),
        users=_dedupe(fields.get("users", [])),
        action=(fields.get("action", ["unknown"]) or ["unknown"])[0],
        enabled=(fields.get("enabled", ["true"]) or ["true"])[0] != "false",
        raw=raw,
        line_no=line_no,
    )


def _dedupe_objects(objects: list[FirewallObject]) -> list[FirewallObject]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[FirewallObject] = []
    for obj in objects:
        key = (obj.vendor.value, obj.name, obj.type, obj.value)
        if key not in seen:
            seen.add(key)
            out.append(obj)
    return out
