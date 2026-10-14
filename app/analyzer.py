from __future__ import annotations

from collections import defaultdict

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
                    title="Any-Any 放行策略",
                    detail=f"{policy.rule_name} 允许任意源到任意目的的任意服务。",
                    policy_ids=[policy.id],
                    recommendation="拆分为明确的源、目的和服务范围，并增加业务责任人与到期时间。",
                )
            )
        elif is_allow and (src_any or dst_any or svc_any):
            findings.append(
                AnalysisFinding(
                    severity="high",
                    category="broad-scope",
                    title="策略范围过宽",
                    detail=f"{policy.rule_name} 包含 {'源Any' if src_any else ''} {'目的Any' if dst_any else ''} {'服务Any' if svc_any else ''}。",
                    policy_ids=[policy.id],
                    recommendation="按最小权限原则收敛地址和服务对象。",
                )
            )

        dangerous = _dangerous_services(policy.services)
        dangerous_apps = _dangerous_apps(policy.applications)
        if is_allow and dangerous and (src_any or dst_any):
            findings.append(
                AnalysisFinding(
                    severity="high",
                    category="dangerous-service",
                    title="高危服务暴露",
                    detail=f"{policy.rule_name} 放行 {', '.join(dangerous)}，且地址范围较宽。",
                    policy_ids=[policy.id],
                    recommendation="限制管理端口来源，优先使用堡垒机、VPN 或专用管理网段。",
                )
            )
        if is_allow and dangerous_apps:
            findings.append(
                AnalysisFinding(
                    severity="medium" if not (src_any or dst_any) else "high",
                    category="dangerous-application",
                    title="高危应用放行",
                    detail=f"{policy.rule_name} 放行 {', '.join(dangerous_apps)}。",
                    policy_ids=[policy.id],
                    recommendation="确认业务必要性，限制来源、目的和用户范围，并开启日志审计。",
                )
            )

        if is_allow and _cross_zone(policy):
            findings.append(
                AnalysisFinding(
                    severity="medium",
                    category="cross-zone",
                    title="跨区域访问风险",
                    detail=f"{policy.rule_name} 从 {', '.join(policy.source_zones or ['any'])} 到 {', '.join(policy.destination_zones or ['any'])}。",
                    policy_ids=[policy.id],
                    recommendation="确认区域边界是否符合业务流向，必要时拆分为更明确的区域对。",
                )
            )

        if is_allow and _needs_split(policy):
            findings.append(
                AnalysisFinding(
                    severity="low",
                    category="least-privilege",
                    title="最小权限优化建议",
                    detail=f"{policy.rule_name} 同时包含多个源、目的或服务。",
                    policy_ids=[policy.id],
                    recommendation="按业务系统、端口或访问方向拆分策略，便于复核、到期和命中分析。",
                )
            )

        if policy.hit_count == 0:
            findings.append(
                AnalysisFinding(
                    severity="medium",
                    category="unused",
                    title="未命中策略",
                    detail=f"{policy.rule_name} 当前命中次数为 0。",
                    policy_ids=[policy.id],
                    recommendation="结合观察期确认后禁用或删除。",
                )
            )

    findings.extend(_duplicate_findings(enabled))
    findings.extend(_shadow_findings(enabled))
    findings.extend(_conflict_findings(enabled))
    findings.extend(_merge_findings(enabled))
    return findings


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
                    title="重复策略",
                    detail="、".join(p.rule_name for p in group) + " 的匹配条件和动作相同。",
                    policy_ids=[p.id for p in group],
                    recommendation="保留一条规范策略，合并说明、标签和责任人后删除重复项。",
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
                    title="冲突策略",
                    detail="、".join(p.rule_name for p in group) + " 匹配条件相同但动作不同。",
                    policy_ids=[p.id for p in group],
                    recommendation="确认业务预期动作，保留一个明确结果，并调整规则顺序或删除冲突项。",
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
                    title="策略合并建议",
                    detail="、".join(p.rule_name for p in group[:6]) + (" 等" if len(group) > 6 else "") + " 仅服务不同。",
                    policy_ids=[p.id for p in group],
                    recommendation="如属于同一业务，可合并为服务组策略；如生命周期不同，保留拆分。",
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
                        title="疑似遮挡策略",
                        detail=f"{earlier.rule_name} 位于前面且范围覆盖 {later.rule_name}，两者动作不同。",
                        policy_ids=[earlier.id, later.id],
                        recommendation="检查策略顺序，确认后移动、收敛或删除被遮挡策略。",
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
