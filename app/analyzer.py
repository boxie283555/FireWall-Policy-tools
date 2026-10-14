from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timedelta

from app.models import AnalysisFinding, PolicyRule
from app.parser import ANY_VALUES

DANGEROUS_SERVICES = {
    "tcp/eq 22": "SSH",
    "tcp/eq 23": "Telnet",
    "tcp/eq 3389": "RDP",
    "tcp/eq 445": "SMB",
    "tcp/eq 1433": "MSSQL",
    "tcp/eq 3306": "MySQL",
    "tcp/eq 5432": "PostgreSQL",
    "service-https": "HTTPS management",
    "ssh": "SSH",
    "telnet": "Telnet",
    "rdp": "RDP",
    "tcp_22": "SSH",
    "tcp_23": "Telnet",
    "tcp_3389": "RDP",
    "tcp_445": "SMB",
    "tcp_1433": "MSSQL",
    "tcp_3306": "MySQL",
    "tcp_5432": "PostgreSQL",
}

DANGEROUS_APPS = {
    "ssh": "SSH",
    "telnet": "Telnet",
    "ms-rdp": "RDP",
    "remote-desktop": "Remote desktop",
    "mysql": "MySQL",
    "mssql": "MSSQL",
    "postgresql": "PostgreSQL",
    "smb": "SMB",
    "ftp": "FTP",
}


def analyze_policies(policies: list[PolicyRule]) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    findings.extend(_lifecycle_findings(policies))
    enabled = [p for p in policies if p.enabled]

    for policy in enabled:
        src_any = _has_any(policy.source_addresses)
        dst_any = _has_any(policy.destination_addresses)
        svc_any = _has_any(policy.services) or not policy.services or "ip" in {s.lower() for s in policy.services}
        is_allow = policy.action.lower() in {"allow", "permit", "accept"}

        if is_allow and src_any and dst_any and svc_any:
            findings.append(
                AnalysisFinding(
                    severity="critical",
                    category="over-permissive",
                    title="Any-Any Allow Rule",
                    detail=f"{policy.rule_name} allows any source to any destination with any service.",
                    policy_ids=[policy.id],
                    recommendation="Split it into explicit source, destination, and service scopes, and add owner and expiration metadata.",
                )
            )
        elif is_allow and (src_any or dst_any or svc_any):
            findings.append(
                AnalysisFinding(
                    severity="high",
                    category="broad-scope",
                    title="Overly Broad Rule Scope",
                    detail=f"{policy.rule_name} includes {'source any' if src_any else ''} {'destination any' if dst_any else ''} {'service any' if svc_any else ''}.",
                    policy_ids=[policy.id],
                    recommendation="Narrow address and service objects according to least privilege.",
                )
            )

        dangerous = _dangerous_services(policy.services)
        dangerous_apps = _dangerous_apps(policy.applications)
        if is_allow and dangerous and (src_any or dst_any):
            findings.append(
                AnalysisFinding(
                    severity="high",
                    category="dangerous-service",
                    title="High-Risk Service Exposure",
                    detail=f"{policy.rule_name} allows {', '.join(dangerous)} with a broad address scope.",
                    policy_ids=[policy.id],
                    recommendation="Restrict management-port sources and prefer a bastion host, VPN, or dedicated management segment.",
                )
            )
        if is_allow and dangerous_apps:
            findings.append(
                AnalysisFinding(
                    severity="medium" if not (src_any or dst_any) else "high",
                    category="dangerous-application",
                    title="High-Risk Application Allowed",
                    detail=f"{policy.rule_name} allows {', '.join(dangerous_apps)}.",
                    policy_ids=[policy.id],
                    recommendation="Confirm the business need, restrict source, destination, and user scope, and enable logging.",
                )
            )

        if is_allow and _cross_zone(policy):
            findings.append(
                AnalysisFinding(
                    severity="medium",
                    category="cross-zone",
                    title="Cross-Zone Access Risk",
                    detail=f"{policy.rule_name} goes from {', '.join(policy.source_zones or ['any'])} to {', '.join(policy.destination_zones or ['any'])}.",
                    policy_ids=[policy.id],
                    recommendation="Verify that the zone boundary matches the business flow; split into more explicit zone pairs if needed.",
                )
            )

        if is_allow and _needs_split(policy):
            findings.append(
                AnalysisFinding(
                    severity="low",
                    category="least-privilege",
                    title="Least-Privilege Optimization",
                    detail=f"{policy.rule_name} contains multiple sources, destinations, or services.",
                    policy_ids=[policy.id],
                    recommendation="Split by application, port, or traffic direction to simplify review, expiration, and hit analysis.",
                )
            )

        if policy.hit_count == 0:
            findings.append(
                AnalysisFinding(
                    severity="medium",
                    category="unused",
                    title="Unused Rule",
                    detail=f"{policy.rule_name} currently has 0 hits.",
                    policy_ids=[policy.id],
                    recommendation="Confirm over an observation period, then disable or remove it.",
                )
            )

    findings.extend(_duplicate_findings(enabled))
    findings.extend(_shadow_findings(enabled))
    findings.extend(_conflict_findings(enabled))
    findings.extend(_merge_findings(enabled))
    return findings


def _lifecycle_findings(policies: list[PolicyRule]) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    today = date.today()
    soon = today + timedelta(days=30)
    for policy in policies:
        is_allow = policy.action.lower() in {"allow", "permit", "accept"}
        if not policy.enabled:
            findings.append(
                AnalysisFinding(
                    severity="low",
                    category="lifecycle",
                    title="Disabled Rule Present",
                    detail=f"{policy.rule_name} is disabled but still present in the rulebase.",
                    policy_ids=[policy.id],
                    recommendation="Confirm whether the disabled rule is still needed; remove stale rules after the retention period.",
                )
            )
            continue

        expires_at = _parse_policy_date(policy.expires_at)
        if expires_at and expires_at < today:
            findings.append(
                AnalysisFinding(
                    severity="high" if is_allow else "medium",
                    category="lifecycle",
                    title="Expired Rule Still Enabled",
                    detail=f"{policy.rule_name} expired on {expires_at.isoformat()} but is still enabled.",
                    policy_ids=[policy.id],
                    recommendation="Disable or remove the rule, or renew the expiration after business approval.",
                )
            )
        elif expires_at and today <= expires_at <= soon:
            findings.append(
                AnalysisFinding(
                    severity="medium",
                    category="lifecycle",
                    title="Rule Expiring Soon",
                    detail=f"{policy.rule_name} expires on {expires_at.isoformat()}.",
                    policy_ids=[policy.id],
                    recommendation="Review with the owner before the expiration date and remove temporary access if no longer needed.",
                )
            )

        risky_allow = is_allow and (
            _has_any(policy.source_addresses)
            or _has_any(policy.destination_addresses)
            or _has_any(policy.services)
            or bool(_dangerous_services(policy.services))
            or bool(_dangerous_apps(policy.applications))
        )
        if risky_allow and not policy.owner:
            findings.append(
                AnalysisFinding(
                    severity="low",
                    category="governance",
                    title="Rule Owner Missing",
                    detail=f"{policy.rule_name} is an allow rule with elevated review need, but no owner metadata was parsed.",
                    policy_ids=[policy.id],
                    recommendation="Add owner metadata in the rule description, tag, or change record so future reviews have an accountable contact.",
                )
            )
        if risky_allow and not policy.expires_at:
            findings.append(
                AnalysisFinding(
                    severity="low",
                    category="governance",
                    title="Expiration Missing",
                    detail=f"{policy.rule_name} is an allow rule with elevated review need, but no expiration metadata was parsed.",
                    policy_ids=[policy.id],
                    recommendation="Add an expiration for temporary or broad access; document permanent access in the business justification.",
                )
            )
    return findings


def _parse_policy_date(value: str | None) -> date | None:
    if not value:
        return None
    text = value.strip()
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%Y%m%d"):
        try:
            return datetime.strptime(text[:10] if fmt in {"%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y"} else text[:8], fmt).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _has_any(values: list[str]) -> bool:
    if not values:
        return True
    return any(v.lower().strip('"') in ANY_VALUES for v in values)


def _dangerous_services(values: list[str]) -> list[str]:
    found: list[str] = []
    for value in values:
        normalized = value.lower().strip('"')
        for token, label in DANGEROUS_SERVICES.items():
            if token in normalized:
                found.append(label)
    return sorted(set(found))


def _dangerous_apps(values: list[str]) -> list[str]:
    found: list[str] = []
    for value in values:
        normalized = value.lower().strip('"')
        for token, label in DANGEROUS_APPS.items():
            if token in normalized:
                found.append(label)
    return sorted(set(found))


def _cross_zone(policy: PolicyRule) -> bool:
    if not policy.source_zones or not policy.destination_zones:
        return False
    if _has_any(policy.source_zones) or _has_any(policy.destination_zones):
        return True
    return set(policy.source_zones) != set(policy.destination_zones)


def _needs_split(policy: PolicyRule) -> bool:
    dimensions = [
        len([v for v in policy.source_addresses if v.lower() not in ANY_VALUES]),
        len([v for v in policy.destination_addresses if v.lower() not in ANY_VALUES]),
        len([v for v in policy.services if v.lower() not in ANY_VALUES]),
        len([v for v in policy.applications if v.lower() not in ANY_VALUES]),
    ]
    return sum(1 for value in dimensions if value > 1) >= 2 or any(value > 8 for value in dimensions)


def _signature(policy: PolicyRule) -> tuple:
    return (
        tuple(sorted(policy.source_zones)),
        tuple(sorted(policy.destination_zones)),
        tuple(sorted(policy.source_addresses)),
        tuple(sorted(policy.destination_addresses)),
        tuple(sorted(policy.services)),
        tuple(sorted(policy.applications)),
        policy.action.lower(),
    )


def _duplicate_findings(policies: list[PolicyRule]) -> list[AnalysisFinding]:
    grouped: dict[tuple, list[PolicyRule]] = defaultdict(list)
    for policy in policies:
        grouped[_signature(policy)].append(policy)

    findings: list[AnalysisFinding] = []
    for group in grouped.values():
        if len(group) > 1:
            findings.append(
                AnalysisFinding(
                    severity="medium",
                    category="duplicate",
                    title="Duplicate Rules",
                    detail=", ".join(p.rule_name for p in group) + " have the same match conditions and action.",
                    policy_ids=[p.id for p in group],
                    recommendation="Keep one canonical rule, merge descriptions, tags, and owner metadata, then remove duplicates.",
                )
            )
    return findings


def _conflict_signature(policy: PolicyRule) -> tuple:
    return (
        tuple(sorted(policy.source_zones)),
        tuple(sorted(policy.destination_zones)),
        tuple(sorted(policy.source_addresses)),
        tuple(sorted(policy.destination_addresses)),
        tuple(sorted(policy.services)),
        tuple(sorted(policy.applications)),
        tuple(sorted(policy.users)),
    )


def _conflict_findings(policies: list[PolicyRule]) -> list[AnalysisFinding]:
    grouped: dict[tuple, list[PolicyRule]] = defaultdict(list)
    for policy in policies:
        grouped[_conflict_signature(policy)].append(policy)

    findings: list[AnalysisFinding] = []
    for group in grouped.values():
        actions = {p.action.lower() for p in group}
        if len(group) > 1 and len(actions) > 1:
            findings.append(
                AnalysisFinding(
                    severity="high",
                    category="conflict",
                    title="Conflicting Rules",
                    detail=", ".join(p.rule_name for p in group) + " have the same match conditions but different actions.",
                    policy_ids=[p.id for p in group],
                    recommendation="Confirm the expected business action, keep one clear result, and adjust rule order or remove conflicts.",
                )
            )
    return findings


def _merge_findings(policies: list[PolicyRule]) -> list[AnalysisFinding]:
    grouped: dict[tuple, list[PolicyRule]] = defaultdict(list)
    for policy in policies:
        key = (
            policy.vendor.value,
            policy.device_name,
            tuple(sorted(policy.source_zones)),
            tuple(sorted(policy.destination_zones)),
            tuple(sorted(policy.source_addresses)),
            tuple(sorted(policy.destination_addresses)),
            tuple(sorted(policy.applications)),
            tuple(sorted(policy.users)),
            policy.action.lower(),
        )
        grouped[key].append(policy)

    findings: list[AnalysisFinding] = []
    for group in grouped.values():
        service_sets = {tuple(sorted(p.services)) for p in group}
        if len(group) >= 3 and len(service_sets) == len(group):
            findings.append(
                AnalysisFinding(
                    severity="low",
                    category="merge-suggestion",
                    title="Rule Merge Suggestion",
                    detail=", ".join(p.rule_name for p in group[:6]) + (" and others" if len(group) > 6 else "") + " differ only by service.",
                    policy_ids=[p.id for p in group],
                    recommendation="If they belong to the same application, merge them into a service-group rule; keep them split if lifecycles differ.",
                )
            )
    return findings[:25]


def _shadow_findings(policies: list[PolicyRule]) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    for idx, earlier in enumerate(policies):
        for later in policies[idx + 1 :]:
            if _covers(earlier, later) and earlier.action.lower() != later.action.lower():
                findings.append(
                    AnalysisFinding(
                        severity="high",
                        category="shadowed",
                        title="Possible Shadowed Rule",
                        detail=f"{earlier.rule_name} appears earlier and covers {later.rule_name}, while the actions differ.",
                        policy_ids=[earlier.id, later.id],
                        recommendation="Review rule order, then move, narrow, or remove the shadowed rule as appropriate.",
                    )
                )
    return findings


def _covers(a: PolicyRule, b: PolicyRule) -> bool:
    return (
        _field_covers(a.source_addresses, b.source_addresses)
        and _field_covers(a.destination_addresses, b.destination_addresses)
        and _field_covers(a.services, b.services)
        and _field_covers(a.applications, b.applications)
        and _field_covers(a.source_zones, b.source_zones)
        and _field_covers(a.destination_zones, b.destination_zones)
    )


def _field_covers(a_values: list[str], b_values: list[str]) -> bool:
    if _has_any(a_values):
        return True
    if not b_values:
        return False
    return set(b_values).issubset(set(a_values))
