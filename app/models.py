from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Vendor(str, Enum):
    cisco_asa = "cisco_asa"
    palo_alto = "palo_alto"
    fortinet = "fortinet"
    fortigate = "fortigate"
    huawei = "huawei"


class FirewallObject(BaseModel):
    name: str
    type: str
    value: str
    vendor: Vendor
    device_name: str = "imported"


class PolicyRule(BaseModel):
    id: str
    vendor: Vendor
    device_name: str = "imported"
    rule_name: str
    source_zones: list[str] = Field(default_factory=list)
    destination_zones: list[str] = Field(default_factory=list)
    source_addresses: list[str] = Field(default_factory=list)
    destination_addresses: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    applications: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    action: str = "unknown"
    enabled: bool = True
    raw: str = ""
    line_no: int | None = None
    tags: list[str] = Field(default_factory=list)
    owner: str | None = None
    expires_at: str | None = None
    hit_count: int | None = None
    last_hit_at: str | None = None


class ParseResult(BaseModel):
    vendor: Vendor
    device_name: str
    policies: list[PolicyRule]
    objects: list[FirewallObject]
    warnings: list[str] = Field(default_factory=list)


class ImportRequest(BaseModel):
    vendor: Vendor
    device_name: str = "imported"
    config_text: str


class AnalysisFinding(BaseModel):
    severity: str
    category: str
    title: str
    detail: str
    policy_ids: list[str] = Field(default_factory=list)
    recommendation: str


class PolicyQuery(BaseModel):
    vendor: str | None = None
    device_name: str | None = None
    source: str | None = None
    destination: str | None = None
    service: str | None = None
    application: str | None = None
    user: str | None = None
    source_zone: str | None = None
    destination_zone: str | None = None
    action: str | None = None
    enabled: bool | None = None
    query: str | None = None


class PolicyPathRequest(BaseModel):
    source: str | None = None
    destination: str | None = None
    service: str | None = None
    application: str | None = None
    user: str | None = None
    source_zone: str | None = None
    destination_zone: str | None = None
    vendor: str | None = None
    device_name: str | None = None


class PolicyPrecheckRequest(BaseModel):
    vendor: str | None = None
    device_name: str | None = None
    source_zone: str | None = None
    destination_zone: str | None = None
    source: str
    destination: str
    service: str
    application: str | None = None
    user: str | None = None
    action: str = "allow"


class PolicyPrecheckIssue(BaseModel):
    severity: str
    category: str
    title: str
    detail: str
    policy_ids: list[str] = Field(default_factory=list)
    recommendation: str


class PolicyPrecheckResult(BaseModel):
    verdict: str
    summary: str
    issues: list[PolicyPrecheckIssue]
    matched_policies: list[dict[str, Any]]
    placement: dict[str, Any]
    deployment: dict[str, Any]


class ChangeRequest(BaseModel):
    title: str
    requester: str
    business_reason: str
    vendor: str | None = None
    device_name: str | None = None
    source_zone: str | None = None
    destination_zone: str | None = None
    source: str
    destination: str
    service: str
    application: str | None = None
    user: str | None = None
    action: str = "allow"
    expires_at: str | None = None
    status: str = "draft"


class StoredChangeRequest(ChangeRequest):
    id: int
    created_at: str


class Dashboard(BaseModel):
    policy_count: int
    object_count: int
    change_request_count: int
    finding_count: int
    high_risk_count: int
    vendor_counts: dict[str, int]
    action_counts: dict[str, int]
    recent_audit: list[dict[str, Any]]
