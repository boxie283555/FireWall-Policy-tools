from __future__ import annotations

from typing import Any

from app.analyzer import _covers, _has_any
from app.models import PolicyPrecheckIssue, PolicyPrecheckRequest, PolicyPrecheckResult, PolicyRule, Vendor
from app.visualization import ALLOW_ACTIONS, _policy_summary


BLOCK_ACTIONS = {"deny", "drop", "reject", "block"}


def precheck_policy_request(policies: list[PolicyRule], request: PolicyPrecheckRequest) -> PolicyPrecheckResult:
    candidate = _candidate_rule(request)
    scope = [p for p in policies if p.enabled]
    if request.vendor:
        scope = [p for p in scope if p.vendor.value == request.vendor]
    if request.device_name:
        scope = [p for p in scope if p.device_name == request.device_name]

    issues: list[PolicyPrecheckIssue] = []
    matched: list[PolicyRule] = []
    candidate_allows = candidate.action.lower() in ALLOW_ACTIONS
    target_devices = {(p.vendor.value, p.device_name) for p in scope}

    if not request.device_name and len(target_devices) > 1:
        issues.append(
            PolicyPrecheckIssue(
                severity="medium",
                category="target-device-missing",
                title="未选择目标设备",
                detail="当前筛选范围包含多个设备，无法准确判断插入位置。",
                policy_ids=[],
                recommendation="请在顶部或申请表单中选择具体目标设备后再执行预验证。",
            )
        )

    for policy in scope:
        relation = _relation(policy, candidate)
        if relation == "none":
            continue
        matched.append(policy)
        same_action = _same_action(policy.action, candidate.action)

        if relation == "same" and same_action:
            issues.append(
                _issue(
                    "medium",
                    "duplicate",
                    "已存在等价策略",
                    f"{policy.rule_name} 与新增策略匹配条件和动作一致。",
                    policy,
                    "无需新增规则；可复用现有策略或补充备注/责任人。",
                )
            )
        elif relation in {"existing-covers-new", "same"} and not same_action:
            issues.append(
                _issue(
                    "critical",
                    "mutual-exclusion",
                    "现有策略与新增动作互斥",
                    f"{policy.rule_name} 已覆盖新增访问，但动作为 {policy.action}。",
                    policy,
                    "检查规则顺序和业务意图；若新增为放行，需要确认前置拒绝规则是否应调整。",
                )
            )
        elif relation == "new-covers-existing" and not same_action:
            issues.append(
                _issue(
                    "high",
                    "conflict",
                    "新增策略会覆盖现有相反动作",
                    f"新增策略范围覆盖 {policy.rule_name}，但动作不同。",
                    policy,
                    "收敛新增策略范围，避免把已有拒绝/允许规则一并覆盖。",
                )
            )
        elif relation == "overlap" and not same_action:
            issues.append(
                _issue(
                    "high",
                    "overlap-conflict",
                    "新增策略与现有策略部分重叠且动作不同",
                    f"新增策略与 {policy.rule_name} 存在源/目的/服务/区域交集，但动作不同。",
                    policy,
                    "拆分新增策略或明确优先顺序，避免同一流量得到不同处置。",
                )
            )
        elif relation == "existing-covers-new" and same_action:
            issues.append(
                _issue(
                    "low",
                    "already-covered",
                    "新增访问已被现有策略覆盖",
                    f"{policy.rule_name} 已覆盖新增访问，动作为 {policy.action}。",
                    policy,
                    "通常无需新增；如需审计隔离，可创建更窄规则并调整顺序。",
                )
            )
        elif relation == "new-covers-existing" and same_action:
            issues.append(
                _issue(
                    "medium",
                    "broadening",
                    "新增策略范围大于现有同动作策略",
                    f"新增策略覆盖现有 {policy.rule_name}，可能扩大访问范围。",
                    policy,
                    "确认是否应复用或扩展现有规则；优先保持最小权限。",
                )
            )
        elif relation == "overlap" and same_action:
            issues.append(
                _issue(
                    "low",
                    "overlap",
                    "新增策略与现有策略部分重叠",
                    f"新增策略与 {policy.rule_name} 部分重叠且动作相同。",
                    policy,
                    "检查是否可合并到同一业务规则，或拆分避免职责混杂。",
                )
            )

    if candidate_allows and (_has_any(candidate.source_addresses) or _has_any(candidate.destination_addresses) or _has_any(candidate.services)):
        issues.append(
            PolicyPrecheckIssue(
                severity="high",
                category="broad-scope",
                title="新增策略范围过宽",
                detail="新增放行策略包含 Any/All 或未填写的源、目的或服务范围。",
                policy_ids=[],
                recommendation="填写明确源、目的和服务；临时策略建议设置到期时间。",
            )
        )

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_severity = max((severity_rank.get(issue.severity, 0) for issue in issues), default=0)
    if max_severity >= 4:
        verdict = "block"
        summary = "预验证发现互斥或已被相反动作覆盖，建议先调整申请。"
    elif max_severity >= 3:
        verdict = "review"
        summary = "预验证发现冲突、重叠或过宽风险，需要人工复核。"
    elif max_severity >= 1:
        verdict = "pass-with-warnings"
        summary = "预验证未发现阻断问题，但存在重复、覆盖或优化建议。"
    else:
        verdict = "pass"
        summary = "预验证通过，未发现与现有策略的明显冲突或重叠。"

    return PolicyPrecheckResult(
        verdict=verdict,
        summary=summary,
        issues=issues[:200],
        matched_policies=[_policy_summary(policy) for policy in matched[:100]],
        placement=_placement(candidate, scope, matched, issues),
        deployment={
            "mode": "request-only",
            "will_push_to_device": False,
            "detail": "当前提交只保存策略申请和预验证结果，不会直接下发到防火墙设备。实施时应按建议位置生成厂商命令并经审批后执行。",
        },
    )


def _candidate_rule(request: PolicyPrecheckRequest) -> PolicyRule:
    vendor = Vendor(request.vendor) if request.vendor in {v.value for v in Vendor} else Vendor.palo_alto
    return PolicyRule(
        id="candidate",
        vendor=vendor,
        device_name=request.device_name or "candidate",
        rule_name="candidate-change",
        source_zones=_split(request.source_zone),
        destination_zones=_split(request.destination_zone),
        source_addresses=_split(request.source),
        destination_addresses=_split(request.destination),
        services=_split(request.service),
        applications=_split(request.application),
        users=_split(request.user),
        action=request.action,
        enabled=True,
    )


def _split(value: str | None) -> list[str]:
    if not value:
        return []
    normalized = value.replace(",", " ")
    return [item.strip() for item in normalized.split() if item.strip()]


def _relation(existing: PolicyRule, candidate: PolicyRule) -> str:
    existing_covers = _covers(existing, candidate)
    candidate_covers = _covers(candidate, existing)
    if existing_covers and candidate_covers:
        return "same"
    if existing_covers:
        return "existing-covers-new"
    if candidate_covers:
        return "new-covers-existing"
    if _overlaps(existing, candidate):
        return "overlap"
    return "none"


def _overlaps(a: PolicyRule, b: PolicyRule) -> bool:
    return (
        _field_overlaps(a.source_zones, b.source_zones)
        and _field_overlaps(a.destination_zones, b.destination_zones)
        and _field_overlaps(a.source_addresses, b.source_addresses)
        and _field_overlaps(a.destination_addresses, b.destination_addresses)
        and _field_overlaps(a.services, b.services)
        and _field_overlaps(a.applications, b.applications)
        and _field_overlaps(a.users, b.users)
    )


def _field_overlaps(a_values: list[str], b_values: list[str]) -> bool:
    if _has_any(a_values) or _has_any(b_values):
        return True
    return bool(set(_norm(a_values)).intersection(set(_norm(b_values))))


def _norm(values: list[str]) -> list[str]:
    return [value.lower().strip('"') for value in values]


def _same_action(a_action: str, b_action: str) -> bool:
    a = a_action.lower()
    b = b_action.lower()
    if a in ALLOW_ACTIONS and b in ALLOW_ACTIONS:
        return True
    if a in BLOCK_ACTIONS and b in BLOCK_ACTIONS:
        return True
    return a == b


def _issue(
    severity: str,
    category: str,
    title: str,
    detail: str,
    policy: PolicyRule,
    recommendation: str,
) -> PolicyPrecheckIssue:
    return PolicyPrecheckIssue(
        severity=severity,
        category=category,
        title=title,
        detail=detail,
        policy_ids=[policy.id],
        recommendation=recommendation,
    )


def _placement(
    candidate: PolicyRule,
    policies: list[PolicyRule],
    matched: list[PolicyRule],
    issues: list[PolicyPrecheckIssue],
) -> dict[str, Any]:
    ordered = sorted(policies, key=lambda p: (p.line_no or 10**9, p.rule_name))
    opposite_cover = [
        policy
        for policy in matched
        if not _same_action(policy.action, candidate.action) and (_covers(policy, candidate) or _covers(candidate, policy))
    ]
    same_cover = [policy for policy in matched if _same_action(policy.action, candidate.action) and _covers(policy, candidate)]
    if opposite_cover:
        anchor = min(opposite_cover, key=lambda p: p.line_no or 10**9)
        return {
            "strategy": "before_conflicting_rule",
            "recommended_line": anchor.line_no,
            "anchor_rule": _policy_summary(anchor),
            "detail": f"建议放在现有相反动作规则 {anchor.rule_name} 之前，或先调整该规则；不会自动提交到设备。",
        }
    if same_cover:
        anchor = min(same_cover, key=lambda p: p.line_no or 10**9)
        return {
            "strategy": "reuse_existing_rule",
            "recommended_line": anchor.line_no,
            "anchor_rule": _policy_summary(anchor),
            "detail": f"现有规则 {anchor.rule_name} 已覆盖该访问，通常无需新增行。",
        }
    same_context = [
        policy
        for policy in ordered
        if policy.source_zones == candidate.source_zones
        and policy.destination_zones == candidate.destination_zones
        and _same_action(policy.action, candidate.action)
    ]
    if same_context:
        anchor = max(same_context, key=lambda p: p.line_no or 0)
        return {
            "strategy": "after_same_context",
            "recommended_line": (anchor.line_no + 1) if anchor.line_no else None,
            "anchor_rule": _policy_summary(anchor),
            "detail": f"建议放在同区域/同 ACL 上下文的相同动作规则 {anchor.rule_name} 附近之后。",
        }
    return {
        "strategy": "append_to_policy_section",
        "recommended_line": None,
        "anchor_rule": None,
        "detail": "未找到明显上下文锚点，建议追加到对应设备的策略段末尾，再结合厂商最佳实践调整顺序。",
    }
