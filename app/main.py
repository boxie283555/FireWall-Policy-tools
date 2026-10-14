from __future__ import annotations

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from app.analyzer import analyze_policies
from app.device_access import FetchConfigError, fetch_running_config, test_device_connection
from app.models import ChangeRequest, ChangeStatusRequest, DeviceConnectionRequest, DeviceCredentialRequest, ImportRequest, PolicyPrecheckRequest, Vendor
from app.parser import parse_config
from app.precheck import precheck_policy_request
from app.reporting import analysis_summary, findings_csv, nat_csv, policies_csv
from app.storage import (
    create_change_request,
    analyze_nat_rules,
    dashboard,
    get_device_connection,
    init_db,
    inventory,
    list_audit_log,
    list_change_requests,
    list_nat_rules,
    list_device_connections,
    list_objects,
    list_policies,
    save_parse_result,
    update_change_request_status,
    update_device_connection_status,
    upsert_device_connection,
)
from app.visualization import object_dependencies, object_dependency_detail, path_analysis, policy_dependency_detail, rule_order, topology, zone_matrix

app = FastAPI(title="Firewall Policy Tools", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/")
def index() -> FileResponse:
    return FileResponse("app/static/index.html")


@app.get("/api/dashboard")
def api_dashboard(vendor: str | None = None, device_name: str | None = None):
    return dashboard(vendor=vendor, device_name=device_name)


@app.get("/api/inventory")
def api_inventory(vendor: str | None = None, device_name: str | None = None):
    if vendor and vendor not in {v.value for v in Vendor}:
        raise HTTPException(status_code=400, detail="Unsupported vendor")
    return inventory(vendor=vendor, device_name=device_name)


@app.post("/api/import")
def api_import(request: ImportRequest):
    result = parse_config(request.vendor, request.device_name, request.config_text)
    saved = save_parse_result(result)
    return {"saved": saved, "warnings": result.warnings}


@app.post("/api/import-file")
async def api_import_file(vendor: Vendor = Form(...), device_name: str = Form("imported"), file: UploadFile = File(...)):
    content = await file.read()
    try:
        config_text = content.decode("utf-8")
    except UnicodeDecodeError:
        config_text = content.decode("latin-1")
    result = parse_config(vendor, device_name, config_text)
    saved = save_parse_result(result)
    return {"saved": saved, "warnings": result.warnings}


@app.get("/api/device-connections")
def api_device_connections():
    return list_device_connections()


@app.post("/api/device-connections")
def api_upsert_device_connection(request: DeviceConnectionRequest):
    if request.vendor not in Vendor:
        raise HTTPException(status_code=400, detail="Unsupported vendor")
    if request.protocol not in {"ssh", "telnet", "api_https", "netconf"}:
        raise HTTPException(status_code=400, detail="Only SSH, Telnet, API/HTTPS, and NETCONF are supported.")
    return upsert_device_connection(request)


@app.post("/api/device-connections/{device_id}/test")
def api_test_device_connection(device_id: int, credentials: DeviceCredentialRequest):
    try:
        device = get_device_connection(device_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Device connection not found") from None
    try:
        result = test_device_connection(device, credentials.password)
        update_device_connection_status(device_id, "test_ok", result["detail"])
        return result
    except Exception as exc:
        update_device_connection_status(device_id, "test_failed", str(exc))
        raise HTTPException(status_code=400, detail=f"Connection failed: {exc}") from exc


@app.post("/api/device-connections/{device_id}/fetch")
def api_fetch_device_config(device_id: int, credentials: DeviceCredentialRequest):
    try:
        device = get_device_connection(device_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Device connection not found") from None
    try:
        fetched = fetch_running_config(device, credentials.password, credentials.enable_password)
        result = parse_config(device.vendor, device.name, fetched.config_text)
        saved = save_parse_result(result)
        update_device_connection_status(device_id, "fetch_ok", None, fetched=True)
        return {
            "status": "ok",
            "device_name": device.name,
            "vendor": device.vendor,
            "saved": saved,
            "warnings": result.warnings,
            "commands": fetched.command_log,
            "config_size": len(fetched.config_text),
            "config_preview": fetched.config_text[:8000],
            "session_preview": fetched.session_text[-8000:],
        }
    except FetchConfigError as exc:
        update_device_connection_status(device_id, "fetch_failed", str(exc))
        raise HTTPException(status_code=400, detail=exc.payload()) from exc
    except Exception as exc:
        update_device_connection_status(device_id, "fetch_failed", str(exc))
        raise HTTPException(status_code=400, detail=f"Fetch failed: {exc}") from exc


@app.get("/api/policies")
def api_policies(
    vendor: str | None = None,
    query: str | None = None,
    action: str | None = None,
    device_name: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    service: str | None = None,
    application: str | None = None,
    user: str | None = None,
    source_zone: str | None = None,
    destination_zone: str | None = None,
    enabled: bool | None = None,
):
    if vendor and vendor not in {v.value for v in Vendor}:
        raise HTTPException(status_code=400, detail="Unsupported vendor")
    from app.models import PolicyQuery
    from app.visualization import filter_policies

    return filter_policies(
        list_policies(vendor=vendor, device_name=device_name),
        PolicyQuery(
            vendor=vendor,
            query=query,
            action=action,
            device_name=device_name,
            source=source,
            destination=destination,
            service=service,
            application=application,
            user=user,
            source_zone=source_zone,
            destination_zone=destination_zone,
            enabled=enabled,
        ),
    )


@app.get("/api/objects")
def api_objects(vendor: str | None = None, query: str | None = None, device_name: str | None = None):
    if vendor and vendor not in {v.value for v in Vendor}:
        raise HTTPException(status_code=400, detail="Unsupported vendor")
    return list_objects(vendor=vendor, query=query, device_name=device_name)


@app.get("/api/nat-rules")
def api_nat_rules(vendor: str | None = None, query: str | None = None, device_name: str | None = None, nat_type: str | None = None):
    if vendor and vendor not in {v.value for v in Vendor}:
        raise HTTPException(status_code=400, detail="Unsupported vendor")
    return list_nat_rules(vendor=vendor, query=query, device_name=device_name, nat_type=nat_type)


@app.get("/api/nat-analysis")
def api_nat_analysis(vendor: str | None = None, device_name: str | None = None):
    return analyze_nat_rules(list_nat_rules(vendor=vendor, device_name=device_name))


@app.get("/api/analysis")
def api_analysis(vendor: str | None = None, device_name: str | None = None):
    return analyze_policies(list_policies(vendor=vendor, device_name=device_name))


@app.get("/api/report/summary")
def api_report_summary(vendor: str | None = None, device_name: str | None = None):
    policies = list_policies(vendor=vendor, device_name=device_name)
    nat_rules = list_nat_rules(vendor=vendor, device_name=device_name)
    return analysis_summary(analyze_policies(policies), analyze_nat_rules(nat_rules))


@app.get("/api/export/findings.csv")
def api_export_findings(vendor: str | None = None, device_name: str | None = None):
    policies = list_policies(vendor=vendor, device_name=device_name)
    nat_rules = list_nat_rules(vendor=vendor, device_name=device_name)
    return _csv_response("firewall-findings.csv", findings_csv(analyze_policies(policies), analyze_nat_rules(nat_rules)))


@app.get("/api/export/policies.csv")
def api_export_policies(vendor: str | None = None, device_name: str | None = None):
    return _csv_response("firewall-policies.csv", policies_csv(list_policies(vendor=vendor, device_name=device_name)))


@app.get("/api/export/nat.csv")
def api_export_nat(vendor: str | None = None, device_name: str | None = None):
    return _csv_response("firewall-nat.csv", nat_csv(list_nat_rules(vendor=vendor, device_name=device_name)))


@app.get("/api/visualization/matrix")
def api_matrix(vendor: str | None = None, device_name: str | None = None):
    return zone_matrix(list_policies(vendor=vendor, device_name=device_name))


@app.get("/api/visualization/topology")
def api_topology(vendor: str | None = None, device_name: str | None = None):
    return topology(list_policies(vendor=vendor, device_name=device_name))


@app.get("/api/visualization/dependencies")
def api_dependencies(vendor: str | None = None, device_name: str | None = None):
    return object_dependencies(list_policies(vendor=vendor, device_name=device_name), list_objects(vendor=vendor, device_name=device_name))


@app.get("/api/visualization/dependencies/object")
def api_dependency_object(name: str, vendor: str | None = None, device_name: str | None = None):
    return object_dependency_detail(
        list_policies(vendor=vendor, device_name=device_name),
        list_objects(vendor=vendor, device_name=device_name),
        name,
    )


@app.get("/api/visualization/dependencies/policy")
def api_dependency_policy(policy: str, vendor: str | None = None, device_name: str | None = None):
    return policy_dependency_detail(
        list_policies(vendor=vendor, device_name=device_name),
        list_objects(vendor=vendor, device_name=device_name),
        policy,
    )


@app.get("/api/visualization/order")
def api_order(vendor: str | None = None, device_name: str | None = None):
    return rule_order(list_policies(vendor=vendor, device_name=device_name))


@app.get("/api/path-analysis")
def api_path_analysis(
    vendor: str | None = None,
    device_name: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    service: str | None = None,
    application: str | None = None,
    user: str | None = None,
    source_zone: str | None = None,
    destination_zone: str | None = None,
):
    from app.models import PolicyPathRequest

    return path_analysis(
        list_policies(vendor=vendor, device_name=device_name),
        PolicyPathRequest(
            vendor=vendor,
            device_name=device_name,
            source=source,
            destination=destination,
            service=service,
            application=application,
            user=user,
            source_zone=source_zone,
            destination_zone=destination_zone,
        ),
    )


@app.post("/api/precheck-policy")
def api_precheck_policy(request: PolicyPrecheckRequest):
    if request.vendor and request.vendor not in {v.value for v in Vendor}:
        raise HTTPException(status_code=400, detail="Unsupported vendor")
    return precheck_policy_request(list_policies(vendor=request.vendor, device_name=request.device_name), request)


@app.post("/api/change-requests")
def api_create_change_request(request: ChangeRequest):
    return create_change_request(request)


@app.get("/api/change-requests")
def api_change_requests():
    return list_change_requests()


@app.patch("/api/change-requests/{request_id}/status")
def api_update_change_request_status(request_id: int, request: ChangeStatusRequest):
    if request.status not in {"draft", "review", "approved", "rejected", "implemented"}:
        raise HTTPException(status_code=400, detail="Unsupported change status")
    try:
        return update_change_request_status(request_id, request.status)
    except KeyError:
        raise HTTPException(status_code=404, detail="Change request not found") from None


@app.get("/api/audit")
def api_audit(limit: int = 50):
    return list_audit_log(limit)


def _csv_response(filename: str, content: str) -> Response:
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
