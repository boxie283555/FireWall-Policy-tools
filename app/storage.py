from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from app.analyzer import analyze_policies
from app.models import ChangeRequest, Dashboard, FirewallObject, ParseResult, PolicyRule

DATA_DIR = Path("data")
DB_PATH = DATA_DIR / "firewall_policy_tools.db"


def _vendor_filter_values(vendor: str | None) -> list[str]:
    if vendor == "fortinet":
        return ["fortinet", "fortigate"]
    return [vendor] if vendor else []


def _display_vendor(vendor: str) -> str:
    return "fortinet" if vendor == "fortigate" else vendor


def get_conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            create table if not exists policies (
              id text primary key,
              vendor text not null,
              device_name text not null,
              payload text not null,
              imported_at text default current_timestamp
            );
            create table if not exists objects (
              id integer primary key autoincrement,
              vendor text not null,
              device_name text not null,
              name text not null,
              type text not null,
              value text not null
            );
            create table if not exists change_requests (
              id integer primary key autoincrement,
              title text not null,
              requester text not null,
              business_reason text not null,
              vendor text,
              device_name text,
              source_zone text,
              destination_zone text,
              source text not null,
              destination text not null,
              service text not null,
              application text,
              user text,
              action text not null,
              expires_at text,
              status text not null,
              created_at text default current_timestamp
            );
            create table if not exists audit_log (
              id integer primary key autoincrement,
              event text not null,
              detail text not null,
              created_at text default current_timestamp
            );
            """
        )
        _ensure_column(conn, "change_requests", "source_zone", "text")
        _ensure_column(conn, "change_requests", "destination_zone", "text")
        _ensure_column(conn, "change_requests", "application", "text")
        _ensure_column(conn, "change_requests", "user", "text")
        _ensure_column(conn, "change_requests", "vendor", "text")
        _ensure_column(conn, "change_requests", "device_name", "text")


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    existing = {row["name"] for row in conn.execute(f"pragma table_info({table})")}
    if column not in existing:
        conn.execute(f"alter table {table} add column {column} {definition}")


def save_parse_result(result: ParseResult) -> dict[str, int]:
    with get_conn() as conn:
        vendor_values = _vendor_filter_values(result.vendor.value)
        conn.execute(
            "delete from policies where vendor in (" + ",".join("?" for _ in vendor_values) + ") and device_name = ?",
            (*vendor_values, result.device_name),
        )
        for policy in result.policies:
            conn.execute(
                """
                insert or replace into policies(id, vendor, device_name, payload)
                values (?, ?, ?, ?)
                """,
                (policy.id, policy.vendor.value, policy.device_name, policy.model_dump_json()),
            )
        conn.execute(
            "delete from objects where vendor in (" + ",".join("?" for _ in vendor_values) + ") and device_name = ?",
            (*vendor_values, result.device_name),
        )
        for obj in result.objects:
            stored_obj = obj.model_copy(update={"device_name": result.device_name})
            conn.execute(
                "insert into objects(vendor, device_name, name, type, value) values (?, ?, ?, ?, ?)",
                (stored_obj.vendor.value, stored_obj.device_name, stored_obj.name, stored_obj.type, stored_obj.value),
            )
        conn.execute(
            "insert into audit_log(event, detail) values (?, ?)",
            ("import_config", f"{result.device_name} {result.vendor.value}: {len(result.policies)} policies, {len(result.objects)} objects"),
        )
    return {"policies": len(result.policies), "objects": len(result.objects), "warnings": len(result.warnings)}


def list_policies(vendor: str | None = None, query: str | None = None, action: str | None = None, device_name: str | None = None) -> list[PolicyRule]:
    sql = "select payload from policies"
    params: list[Any] = []
    clauses: list[str] = []
    vendor_values = _vendor_filter_values(vendor)
    if vendor_values:
        clauses.append("vendor in (" + ",".join("?" for _ in vendor_values) + ")")
        params.extend(vendor_values)
    if device_name:
        clauses.append("device_name = ?")
        params.append(device_name)
    if clauses:
        sql += " where " + " and ".join(clauses)
    sql += " order by imported_at desc"

    with get_conn() as conn:
        policies = [PolicyRule.model_validate_json(row["payload"]) for row in conn.execute(sql, params)]

    if action:
        policies = [p for p in policies if p.action.lower() == action.lower()]
    if query:
        q = query.lower()
        policies = [p for p in policies if q in p.model_dump_json().lower()]
    return policies


def list_objects(vendor: str | None = None, query: str | None = None, device_name: str | None = None) -> list[FirewallObject]:
    sql = "select vendor, device_name, name, type, value from objects"
    params: list[Any] = []
    clauses: list[str] = []
    vendor_values = _vendor_filter_values(vendor)
    if vendor_values:
        clauses.append("vendor in (" + ",".join("?" for _ in vendor_values) + ")")
        params.extend(vendor_values)
    if device_name:
        clauses.append("device_name = ?")
        params.append(device_name)
    if clauses:
        sql += " where " + " and ".join(clauses)
    sql += " order by name"
    with get_conn() as conn:
        objects = [FirewallObject(**dict(row)) for row in conn.execute(sql, params)]
    if query:
        q = query.lower()
        objects = [obj for obj in objects if q in obj.model_dump_json().lower()]
    return objects


def create_change_request(request: ChangeRequest) -> dict[str, Any]:
    with get_conn() as conn:
        cur = conn.execute(
            """
            insert into change_requests(title, requester, business_reason, vendor, device_name, source_zone, destination_zone, source, destination, service, application, user, action, expires_at, status)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.title,
                request.requester,
                request.business_reason,
                request.vendor,
                request.device_name,
                request.source_zone,
                request.destination_zone,
                request.source,
                request.destination,
                request.service,
                request.application,
                request.user,
                request.action,
                request.expires_at,
                request.status,
            ),
        )
        request_id = cur.lastrowid
        conn.execute("insert into audit_log(event, detail) values (?, ?)", ("create_change_request", f"#{request_id} {request.title}"))
    return {"id": request_id, **request.model_dump()}


def list_change_requests() -> list[dict[str, Any]]:
    with get_conn() as conn:
        return [dict(row) for row in conn.execute("select * from change_requests order by id desc")]


def list_audit_log(limit: int = 50) -> list[dict[str, Any]]:
    with get_conn() as conn:
        return [dict(row) for row in conn.execute("select * from audit_log order by id desc limit ?", (limit,))]


def inventory(vendor: str | None = None, device_name: str | None = None) -> dict[str, Any]:
    policies = list_policies(vendor=vendor, device_name=device_name)
    objects = list_objects(vendor=vendor, device_name=device_name)
    devices: dict[tuple[str, str], dict[str, Any]] = {}
    values: dict[str, set[str]] = {
        "zones": set(),
        "addresses": {"any"},
        "services": {"any"},
        "applications": {"any"},
        "users": {"any"},
        "actions": set(),
        "policies": set(),
    }
    for policy in policies:
        display_vendor = _display_vendor(policy.vendor.value)
        key = (display_vendor, policy.device_name)
        device = devices.setdefault(
            key,
            {
                "vendor": display_vendor,
                "device_name": policy.device_name,
                "policy_count": 0,
                "object_count": 0,
                "context_label": "ACL / Interface" if display_vendor == "cisco_asa" else "Zone",
            },
        )
        device["policy_count"] += 1
        values["zones"].update(policy.source_zones)
        values["zones"].update(policy.destination_zones)
        values["addresses"].update(policy.source_addresses)
        values["addresses"].update(policy.destination_addresses)
        values["services"].update(policy.services)
        values["applications"].update(policy.applications)
        values["users"].update(policy.users)
        values["actions"].add(policy.action)
        values["policies"].add(policy.rule_name)
    for obj in objects:
        display_vendor = _display_vendor(obj.vendor.value)
        key = (display_vendor, obj.device_name)
        device = devices.setdefault(
            key,
            {
                "vendor": display_vendor,
                "device_name": obj.device_name,
                "policy_count": 0,
                "object_count": 0,
                "context_label": "ACL / Interface" if display_vendor == "cisco_asa" else "Zone",
            },
        )
        device["object_count"] += 1
        if "service" in obj.type:
            values["services"].add(obj.name)
        else:
            values["addresses"].add(obj.name)

    return {
        "devices": sorted(devices.values(), key=lambda item: (item["vendor"], item["device_name"])),
        "values": {key: sorted(value)[:3000] for key, value in values.items()},
    }


def dashboard(vendor: str | None = None, device_name: str | None = None) -> Dashboard:
    policies = list_policies(vendor=vendor, device_name=device_name)
    objects = list_objects(vendor=vendor, device_name=device_name)
    findings = analyze_policies(policies)
    vendor_counts: dict[str, int] = {}
    action_counts: dict[str, int] = {}
    for policy in policies:
        display_vendor = _display_vendor(policy.vendor.value)
        vendor_counts[display_vendor] = vendor_counts.get(display_vendor, 0) + 1
        action_counts[policy.action] = action_counts.get(policy.action, 0) + 1
    with get_conn() as conn:
        cr_count = conn.execute("select count(*) as c from change_requests").fetchone()["c"]
    return Dashboard(
        policy_count=len(policies),
        object_count=len(objects),
        change_request_count=cr_count,
        finding_count=len(findings),
        high_risk_count=sum(1 for f in findings if f.severity in {"critical", "high"}),
        vendor_counts=vendor_counts,
        action_counts=action_counts,
        recent_audit=list_audit_log(8),
    )
