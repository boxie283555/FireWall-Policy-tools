from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from app.analyzer import analyze_policies
from app.models import ChangeRequest, Dashboard, DeviceConnection, DeviceConnectionRequest, FirewallObject, NatRule, ParseResult, PolicyRule

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
            create table if not exists nat_rules (
              id text primary key,
              vendor text not null,
              device_name text not null,
              payload text not null,
              imported_at text default current_timestamp
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
            create table if not exists device_connections (
              id integer primary key autoincrement,
              name text not null unique,
              vendor text not null,
              host text not null,
              port integer not null default 22,
              protocol text not null default 'ssh',
              username text not null,
              enable_password_required integer not null default 0,
              notes text,
              last_status text,
              last_error text,
              last_fetched_at text,
              created_at text default current_timestamp,
              updated_at text default current_timestamp
            );
            """
        )
        _ensure_column(conn, "change_requests", "source_zone", "text")
        _ensure_column(conn, "change_requests", "destination_zone", "text")
        _ensure_column(conn, "change_requests", "application", "text")
        _ensure_column(conn, "change_requests", "user", "text")
        _ensure_column(conn, "change_requests", "vendor", "text")
        _ensure_column(conn, "change_requests", "device_name", "text")
        _ensure_column(conn, "device_connections", "enable_password_required", "integer not null default 0")
        _ensure_column(conn, "device_connections", "notes", "text")
        _ensure_column(conn, "device_connections", "last_status", "text")
        _ensure_column(conn, "device_connections", "last_error", "text")
        _ensure_column(conn, "device_connections", "last_fetched_at", "text")
        _ensure_column(conn, "device_connections", "updated_at", "text")


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
            "delete from nat_rules where vendor in (" + ",".join("?" for _ in vendor_values) + ") and device_name = ?",
            (*vendor_values, result.device_name),
        )
        for nat_rule in result.nat_rules:
            conn.execute(
                """
                insert or replace into nat_rules(id, vendor, device_name, payload)
                values (?, ?, ?, ?)
                """,
                (nat_rule.id, nat_rule.vendor.value, nat_rule.device_name, nat_rule.model_dump_json()),
            )
        conn.execute(
            "insert into audit_log(event, detail) values (?, ?)",
            (
                "import_config",
                f"{result.device_name} {result.vendor.value}: {len(result.policies)} policies, {len(result.objects)} objects, {len(result.nat_rules)} NAT rules",
            ),
        )
    return {"policies": len(result.policies), "objects": len(result.objects), "nat_rules": len(result.nat_rules), "warnings": len(result.warnings)}


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


def list_nat_rules(vendor: str | None = None, query: str | None = None, device_name: str | None = None, nat_type: str | None = None) -> list[NatRule]:
    sql = "select payload from nat_rules"
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
        rules = [NatRule.model_validate_json(row["payload"]) for row in conn.execute(sql, params)]
    if nat_type:
        rules = [rule for rule in rules if rule.nat_type.lower() == nat_type.lower()]
    if query:
        q = query.lower()
        rules = [rule for rule in rules if q in rule.model_dump_json().lower()]
    return rules


def analyze_nat_rules(rules: list[NatRule]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: dict[tuple, list[NatRule]] = {}
    for rule in rules:
        key = (
            tuple(sorted(rule.source_zones)),
            tuple(sorted(rule.destination_zones)),
            tuple(sorted(rule.original_sources)),
            tuple(sorted(rule.original_destinations)),
            tuple(sorted(rule.original_services)),
            tuple(sorted(rule.translated_sources)),
            tuple(sorted(rule.translated_destinations)),
            rule.nat_type,
        )
        seen.setdefault(key, []).append(rule)
        broad_src = _has_nat_any(rule.original_sources)
        broad_dst = _has_nat_any(rule.original_destinations)
        broad_svc = _has_nat_any(rule.original_services)
        if rule.enabled and broad_src and broad_dst:
            findings.append(
                {
                    "severity": "high",
                    "category": "broad-nat",
                    "title": "Broad NAT Match",
                    "detail": f"{rule.rule_name} matches any source and any destination.",
                    "rule_ids": [rule.id],
                    "recommendation": "Narrow original source and destination, or confirm this is an intentional catch-all NAT rule.",
                }
            )
        if rule.enabled and broad_svc and rule.nat_type in {"destination", "dnat", "static"}:
            findings.append(
                {
                    "severity": "medium",
                    "category": "broad-service-nat",
                    "title": "Broad Service Translation",
                    "detail": f"{rule.rule_name} has no explicit service limit.",
                    "rule_ids": [rule.id],
                    "recommendation": "Limit destination/static NAT to required services where possible.",
                }
            )
        if rule.enabled and rule.translated_destinations and _has_nat_any(rule.original_sources):
            findings.append(
                {
                    "severity": "medium",
                    "category": "public-inbound-nat",
                    "title": "Inbound NAT from Any Source",
                    "detail": f"{rule.rule_name} translates to {', '.join(rule.translated_destinations)} from any source.",
                    "rule_ids": [rule.id],
                    "recommendation": "Restrict allowed source networks in both NAT and security policy.",
                }
            )
    for group in seen.values():
        if len(group) > 1:
            findings.append(
                {
                    "severity": "medium",
                    "category": "duplicate-nat",
                    "title": "Duplicate NAT Rules",
                    "detail": ", ".join(rule.rule_name for rule in group) + " have the same NAT match and translation.",
                    "rule_ids": [rule.id for rule in group],
                    "recommendation": "Keep one canonical NAT rule and remove or disable duplicates after validation.",
                }
            )
    return findings[:300]


def _has_nat_any(values: list[str]) -> bool:
    if not values:
        return True
    return any(value.lower().strip('"') in {"any", "all", "0.0.0.0/0", "::/0"} for value in values)


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


def upsert_device_connection(request: DeviceConnectionRequest) -> DeviceConnection:
    with get_conn() as conn:
        existing = conn.execute("select id from device_connections where name = ?", (request.name,)).fetchone()
        if existing:
            conn.execute(
                """
                update device_connections
                set vendor = ?, host = ?, port = ?, protocol = ?, username = ?,
                    enable_password_required = ?, notes = ?, updated_at = current_timestamp
                where id = ?
                """,
                (
                    request.vendor.value,
                    request.host,
                    request.port,
                    request.protocol,
                    request.username,
                    1 if request.enable_password_required else 0,
                    request.notes,
                    existing["id"],
                ),
            )
            device_id = existing["id"]
            event = "update_device_connection"
        else:
            cur = conn.execute(
                """
                insert into device_connections(name, vendor, host, port, protocol, username, enable_password_required, notes)
                values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.name,
                    request.vendor.value,
                    request.host,
                    request.port,
                    request.protocol,
                    request.username,
                    1 if request.enable_password_required else 0,
                    request.notes,
                ),
            )
            device_id = cur.lastrowid
            event = "create_device_connection"
        conn.execute("insert into audit_log(event, detail) values (?, ?)", (event, f"{request.name} {request.vendor.value} {request.host}:{request.port}"))
    return get_device_connection(device_id)


def get_device_connection(device_id: int) -> DeviceConnection:
    with get_conn() as conn:
        row = conn.execute("select * from device_connections where id = ?", (device_id,)).fetchone()
    if row is None:
        raise KeyError(f"device connection {device_id} not found")
    return _device_connection_from_row(row)


def list_device_connections() -> list[DeviceConnection]:
    with get_conn() as conn:
        rows = conn.execute("select * from device_connections order by vendor, name").fetchall()
    return [_device_connection_from_row(row) for row in rows]


def update_device_connection_status(device_id: int, status: str, error: str | None = None, fetched: bool = False) -> None:
    fetched_sql = ", last_fetched_at = current_timestamp" if fetched else ""
    with get_conn() as conn:
        conn.execute(
            f"""
            update device_connections
            set last_status = ?, last_error = ?, updated_at = current_timestamp{fetched_sql}
            where id = ?
            """,
            (status, error, device_id),
        )
        detail = f"#{device_id} {status}" + (f": {error}" if error else "")
        conn.execute("insert into audit_log(event, detail) values (?, ?)", ("device_connection_status", detail))


def _device_connection_from_row(row: sqlite3.Row) -> DeviceConnection:
    data = dict(row)
    data["enable_password_required"] = bool(data["enable_password_required"])
    return DeviceConnection(**data)


def list_change_requests() -> list[dict[str, Any]]:
    with get_conn() as conn:
        return [dict(row) for row in conn.execute("select * from change_requests order by id desc")]


def list_audit_log(limit: int = 50) -> list[dict[str, Any]]:
    with get_conn() as conn:
        return [dict(row) for row in conn.execute("select * from audit_log order by id desc limit ?", (limit,))]


def inventory(vendor: str | None = None, device_name: str | None = None) -> dict[str, Any]:
    policies = list_policies(vendor=vendor, device_name=device_name)
    objects = list_objects(vendor=vendor, device_name=device_name)
    nat_rules = list_nat_rules(vendor=vendor, device_name=device_name)
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
                "nat_rule_count": 0,
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
                "nat_rule_count": 0,
                "object_count": 0,
                "context_label": "ACL / Interface" if display_vendor == "cisco_asa" else "Zone",
            },
        )
        device["object_count"] += 1
        if "service" in obj.type:
            values["services"].add(obj.name)
        else:
            values["addresses"].add(obj.name)
    for rule in nat_rules:
        display_vendor = _display_vendor(rule.vendor.value)
        key = (display_vendor, rule.device_name)
        device = devices.setdefault(
            key,
            {
                "vendor": display_vendor,
                "device_name": rule.device_name,
                "policy_count": 0,
                "nat_rule_count": 0,
                "object_count": 0,
                "context_label": "ACL / Interface" if display_vendor == "cisco_asa" else "Zone",
            },
        )
        device["nat_rule_count"] += 1

    return {
        "devices": sorted(devices.values(), key=lambda item: (item["vendor"], item["device_name"])),
        "values": {key: sorted(value)[:3000] for key, value in values.items()},
    }


def dashboard(vendor: str | None = None, device_name: str | None = None) -> Dashboard:
    policies = list_policies(vendor=vendor, device_name=device_name)
    objects = list_objects(vendor=vendor, device_name=device_name)
    nat_rules = list_nat_rules(vendor=vendor, device_name=device_name)
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
        nat_rule_count=len(nat_rules),
        object_count=len(objects),
        change_request_count=cr_count,
        finding_count=len(findings),
        high_risk_count=sum(1 for f in findings if f.severity in {"critical", "high"}),
        vendor_counts=vendor_counts,
        action_counts=action_counts,
        recent_audit=list_audit_log(8),
    )
