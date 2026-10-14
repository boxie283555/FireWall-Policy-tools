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
                title="Target Device Not Selected",
                detail="The current filter scope contains multiple devices, so the insertion position cannot be determined accurately.",
                policy_ids=[],
                recommendation="Select a specific target device in the top filter or request form before running precheck.",
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
                    "Equivalent Rule Already Exists",
                    f"{policy.rule_name} has the same match conditions and action as the new rule.",
                    policy,
                    "No new rule is usually needed; reuse the existing rule or add notes/owner metadata.",
                )
            )
        elif relation in {"existing-covers-new", "same"} and not same_action:
            issues.append(
                _issue(
                    "critical",
                    "mutual-exclusion",
                    "Existing Rule Conflicts with New Action",
                    f"{policy.rule_name} already covers the requested access, but its action is {policy.action}.",
                    policy,
                    "Review rule order and business intent; if the new rule is an allow, confirm whether the preceding deny rule should be adjusted.",
                )
            )
        elif relation == "new-covers-existing" and not same_action:
            issues.append(
                _issue(
                    "high",
                    "conflict",
                    "New Rule Would Cover Existing Opposite Action",
                    f"The new rule scope covers {policy.rule_name}, but the action differs.",
                    policy,
                    "Narrow the new rule scope to avoid covering existing deny/allow rules unintentionally.",
                )
            )
        elif relation == "overlap" and not same_action:
            issues.append(
                _issue(
                    "high",
                    "overlap-conflict",
                    "New Rule Partially Overlaps with a Different Action",
                    f"The new rule overlaps with {policy.rule_name} in source, destination, service, or zone, but the action differs.",
                    policy,
                    "Split the new rule or define explicit priority to avoid different handling for the same traffic.",
                )
            )
        elif relation == "existing-covers-new" and same_action:
            issues.append(
                _issue(
                    "low",
                    "already-covered",
                    "Requested Access Is Already Covered",
                    f"{policy.rule_name} already covers the requested access with action {policy.action}.",
                    policy,
                    "A new rule is usually unnecessary; if audit separation is required, create a narrower rule and adjust ordering.",
                )
            )
        elif relation == "new-covers-existing" and same_action:
            issues.append(
                _issue(
                    "medium",
                    "broadening",
                    "New Rule Is Broader Than Existing Same-Action Rule",
                    f"The new rule covers existing rule {policy.rule_name} and may expand access.",
                    policy,
                    "Confirm whether to reuse or extend the existing rule; keep least privilege as the default.",
                )
            )
        elif relation == "overlap" and same_action:
            issues.append(
                _issue(
                    "low",
                    "overlap",
                    "New Rule Partially Overlaps Existing Rule",
                    f"The new rule partially overlaps with {policy.rule_name} and has the same action.",
                    policy,
                    "Check whether it should be merged into one business rule, or split to avoid mixed ownership.",
                )
            )

    if candidate_allows and (_has_any(candidate.source_addresses) or _has_any(candidate.destination_addresses) or _has_any(candidate.services)):
        issues.append(
            PolicyPrecheckIssue(
                severity="high",
                category="broad-scope",
                title="New Rule Scope Is Too Broad",
                detail="The new allow rule contains Any/All or empty source, destination, or service scope.",
                policy_ids=[],
                recommendation="Use explicit source, destination, and service values; set an expiration for temporary access.",
            )
        )

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_severity = max((severity_rank.get(issue.severity, 0) for issue in issues), default=0)
    if max_severity >= 4:
        verdict = "block"
        summary = "Precheck found a mutual exclusion or opposite-action coverage. Adjust the request first."
    elif max_severity >= 3:
        verdict = "review"
        summary = "Precheck found conflicts, overlap, or broad-scope risk. Manual review is required."
    elif max_severity >= 1:
        verdict = "pass-with-warnings"
        summary = "Precheck found no blocking issue, but there are duplicate, coverage, or optimization warnings."
    else:
        verdict = "pass"
        summary = "Precheck passed. No obvious conflict or overlap with existing rules was found."

    return PolicyPrecheckResult(
        verdict=verdict,
        summary=summary,
        issues=issues[:200],
        matched_policies=[_policy_summary(policy) for policy in matched[:100]],
        placement=_placement(candidate, scope, matched, issues),
        deployment={
            "mode": "request-only",
            "will_push_to_device": False,
            "detail": "This submission only saves the policy request and precheck result. It will not push changes to firewall devices automatically. Generate vendor commands using the recommended placement and execute them after approval.",
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
            "detail": f"Place it before existing opposite-action rule {anchor.rule_name}, or adjust that rule first. It will not be pushed automatically.",
        }
    if same_cover:
        anchor = min(same_cover, key=lambda p: p.line_no or 10**9)
        return {
            "strategy": "reuse_existing_rule",
            "recommended_line": anchor.line_no,
            "anchor_rule": _policy_summary(anchor),
            "detail": f"Existing rule {anchor.rule_name} already covers this access, so a new line is usually unnecessary.",
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
            "detail": f"Place it near and after same-action rule {anchor.rule_name} in the same zone or ACL context.",
        }
    return {
        "strategy": "append_to_policy_section",
        "recommended_line": None,
        "anchor_rule": None,
        "detail": "No clear context anchor was found. Append it to the target device policy section, then adjust order according to vendor best practices.",
    }
