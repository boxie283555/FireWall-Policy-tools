"""PAN-OS candidate-policy editing with explicit preview and separate commit."""
from __future__ import annotations

import copy
import difflib
import hashlib
import ipaddress
import re
import secrets
import ssl
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Literal
from urllib import parse, request, error

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field, SecretStr, field_validator

from app.analyzer import analyze_policies
from app.models import PolicyRule, Vendor
from app.storage import get_conn

router = APIRouter(prefix='/api/panos', tags=['PAN-OS Online'])
TTL = 1800
PLAN_TTL = 600


class Connect(BaseModel):
    host: str
    port: int = Field(default=443, ge=1, le=65535)
    username: str = Field(default='admin', min_length=1)
    credential: SecretStr
    auth_mode: Literal['password', 'api_key'] = 'password'
    verify_tls: bool = True
    read_only: bool = True

    @field_validator('host')
    @classmethod
    def host_only(cls, value):
        value = value.strip()
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', value):
                raise ValueError('Enter a hostname or IP address, without a URL or path.')
        return value


class Scope(BaseModel):
    vsys: str = Field(default='vsys1', min_length=1, max_length=128)
    kind: Literal['security', 'nat'] = 'security'


class Preview(Scope):
    operation: Literal['create', 'edit', 'delete', 'move']
    name: str = Field(min_length=1, max_length=255)
    revision: str
    xml: str = Field(default='', max_length=200000)
    where: Literal['before', 'after', 'top', 'bottom'] = 'before'
    destination: str = ''


class Execute(BaseModel):
    preview_id: str
    confirm: bool = False


@dataclass
class Session:
    host: str
    port: int
    username: str
    key: str = field(repr=False)
    verify_tls: bool = True
    read_only: bool = True
    expires: float = field(default_factory=lambda: time.monotonic() + TTL)
    plans: dict = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)


_sessions: dict[str, Session] = {}
_sessions_lock = threading.RLock()


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_call(session, params):
    if session.read_only and (params.get("type") == "commit" or (params.get("type") == "config" and params.get("action") not in {"get", "show"})):
        raise HTTPException(403, "Read-only connection: policy writes and commits are disabled. Reconnect in edit mode to execute a reviewed change.")
    host = f'[{session.host}]' if ':' in session.host else session.host
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    if session.key:
        headers['X-PAN-KEY'] = session.key
    req = request.Request(f'https://{host}:{session.port}/api/', data=parse.urlencode(params).encode(), headers=headers, method='POST')
    context = ssl.create_default_context() if session.verify_tls else ssl._create_unverified_context()
    opener = request.build_opener(NoRedirect(), request.HTTPSHandler(context=context))
    try:
        started = time.monotonic()
        with opener.open(req, timeout=35) as response:
            chunks, size = [], 0
            while size <= 32 * 1024 * 1024:
                chunk = response.read1(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if time.monotonic() - started > 40:
                    raise TimeoutError()
            body = b''.join(chunks)
    except error.HTTPError as exc:
        raise HTTPException(502, f'PAN-OS returned HTTP {exc.code}; check credentials and API permissions.') from None
    except (error.URLError, TimeoutError, OSError):
        raise HTTPException(502, 'PAN-OS connection failed. Check reachability and the selected TLS certificate setting. For a write timeout, reload candidate configuration before retrying.') from None
    if len(body) > 32 * 1024 * 1024 or b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():
        raise HTTPException(502, 'Unsupported PAN-OS response.')
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        raise HTTPException(502, 'PAN-OS returned invalid XML.') from None
    if root.tag != 'response' or root.get('status') != 'success':
        # Do not return request payloads or authentication response bodies.
        if params.get('type') == 'keygen':
            message = 'Authentication failed.'
        else:
            message = ' '.join(root.find('msg').itertext()) if root.find('msg') is not None else 'API operation failed.'
            if session.key:
                message = message.replace(session.key, '[redacted]')
        raise HTTPException(502, f'PAN-OS error {root.get("code", "unknown")}: {message[:1500]}')
    return root


def session_for(token):
    with _sessions_lock:
        now = time.monotonic()
        for key in list(_sessions):
            if _sessions[key].expires <= now:
                del _sessions[key]
        session = _sessions.get(token or '')
        if session is None:
            raise HTTPException(401, 'PAN-OS session expired. Connect again.')
        session.expires = now + TTL
        return session


def literal(value):
    if any(ord(c) < 32 for c in value):
        raise HTTPException(422, 'Names cannot contain control characters.')
    if "'" not in value:
        return "'" + value + "'"
    if '"' not in value:
        return '"' + value + '"'
    raise HTTPException(422, 'Names containing both quote styles are not supported.')


def clean(element):
    result = copy.deepcopy(element)
    for node in result.iter():
        for key in ('admin', 'dirtyId', 'time'):
            node.attrib.pop(key, None)
        node.attrib = dict(sorted(node.attrib.items()))
        if node.text is not None and not node.text.strip():
            node.text = None
        node.tail = None
    return result


def serialize(element):
    return ET.tostring(clean(element), encoding='unicode')


def revision(element):
    return hashlib.sha256(serialize(element).encode()).hexdigest()


def config(session, action='get'):
    # Operational candidate output excludes expanded defaults and the enormous
    # predefined application catalog returned by configuration action=get.
    params = {'type': 'op', 'cmd': '<show><config><candidate/></config></show>'} if action == 'get' else {'type': 'config', 'action': 'show', 'xpath': '/config'}
    root = api_call(session, params)
    result = root.find('./result/config')
    if result is None:
        raise HTTPException(502, 'PAN-OS did not return the requested configuration.')
    result = clean(result)
    # Compare editable configuration, not software version / catalog metadata.
    result.attrib.clear()
    predefined = result.find('predefined')
    if predefined is not None:
        result.remove(predefined)
    return result


def pending_changes(session):
    root = api_call(session, {'type': 'op', 'cmd': '<check><pending-changes/></check>'})
    value = (root.findtext('./result') or '').strip().lower()
    if value not in {'yes', 'no'}:
        raise HTTPException(502, 'PAN-OS did not return a recognized pending-change status.')
    return value == 'yes'


def rules_node(root, scope, create=False):
    devices = root.findall('./devices/entry')
    if len(devices) != 1:
        raise HTTPException(400, 'Only a directly connected firewall with one local device configuration is supported.')
    device = devices[0]
    vsys = next((v for v in device.findall('./vsys/entry') if v.get('name') == scope.vsys), None)
    if vsys is None:
        raise HTTPException(404, 'Virtual system not found.')
    node = vsys
    for tag in ('rulebase', scope.kind, 'rules'):
        child = node.find(tag)
        if child is None:
            if not create:
                return ET.Element('rules'), device.get('name')
            child = ET.SubElement(node, tag)
        node = child
    return node, device.get('name')


def pretty(element, redact=False):
    result = clean(element)
    if redact:
        for node in result.iter():
            if any(word in node.tag.lower() for word in ('password', 'phash', 'private-key', 'api-key', 'secret', 'passphrase')):
                for child in list(node):
                    node.remove(child)
                node.text = '[redacted]'
    ET.indent(result, space='  ')
    return ET.tostring(result, encoding='unicode')


def diff(before, after, redact=False):
    return '\n'.join(difflib.unified_diff(pretty(before, redact).splitlines(), pretty(after, redact).splitlines(), fromfile='before', tofile='after', lineterm=''))


def policy_findings(rules, session, scope):
    if scope.kind != 'security':
        return []
    policies = []
    for index, entry in enumerate(rules.findall('entry')):
        members = lambda name: [node.text or '' for node in entry.findall(f'./{name}/member')]
        policies.append(PolicyRule(id=entry.get('name', str(index)), vendor=Vendor.palo_alto, device_name=session.host, rule_name=entry.get('name', ''), source_zones=members('from'), destination_zones=members('to'), source_addresses=members('source'), destination_addresses=members('destination'), services=members('service'), applications=members('application'), users=members('source-user'), action=entry.findtext('action') or 'unknown', enabled=entry.findtext('disabled') != 'yes', line_no=index + 1))
    return [item.model_dump() for item in analyze_policies(policies)]


def audit(session, event, detail):
    with get_conn() as conn:
        conn.execute('insert into audit_log(event,detail) values (?,?)', (event, f'{session.host} user={session.username} {detail}'))


def keep_plan(session, plan):
    now = time.monotonic()
    session.plans = {key: value for key, value in session.plans.items() if value['expires'] > now}
    if len(session.plans) >= 20:
        session.plans.pop(next(iter(session.plans)))
    key = secrets.token_urlsafe(24)
    plan['expires'] = now + PLAN_TTL
    session.plans[key] = plan
    return key


@router.post('/connect')
def connect(body: Connect):
    session = Session(body.host, body.port, body.username, '', body.verify_tls, read_only=body.read_only)
    if body.auth_mode == 'password':
        root = api_call(session, {'type': 'keygen', 'user': body.username, 'password': body.credential.get_secret_value()})
        session.key = root.findtext('./result/key') or ''
    else:
        session.key = body.credential.get_secret_value()
    if not session.key:
        raise HTTPException(502, 'PAN-OS did not provide an API key.')
    info = api_call(session, {'type': 'op', 'cmd': '<show><system><info/></system></show>'})
    if info.findtext('.//model') == 'Panorama':
        raise HTTPException(400, 'Connect directly to a firewall; Panorama is not supported here.')
    current = config(session)
    systems = [v.get('name') for v in current.findall('./devices/entry/vsys/entry')]
    if not systems:
        raise HTTPException(403, 'No local virtual systems are accessible to this account.')
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        for key in list(_sessions):
            if _sessions[key].expires < time.monotonic():
                del _sessions[key]
        if len(_sessions) >= 32:
            raise HTTPException(429, 'Too many active PAN-OS connections.')
        _sessions[token] = session
    return {'session': token, 'host': body.host, 'hostname': info.findtext('.//hostname'), 'version': info.findtext('.//sw-version'), 'vsys': systems, 'expires_in': TTL, 'read_only': session.read_only}


@router.delete('/session')
def disconnect(x_pan_session: str = Header(default='')):
    with _sessions_lock:
        _sessions.pop(x_pan_session, None)
    return {'disconnected': True}


@router.post('/rules')
def read_rules(scope: Scope, x_pan_session: str = Header(default='')):
    session = session_for(x_pan_session)
    with session.lock:
        current = config(session)
        running = config(session, 'show')
        rules, _ = rules_node(current, scope)
        running_rules, _ = rules_node(running, scope)
        rows = []
        for i, entry in enumerate(rules.findall('entry')):
            rows.append({'name': entry.get('name'), 'position': i + 1, 'enabled': entry.findtext('disabled') != 'yes', 'action': entry.findtext('action') or scope.kind, 'source': [m.text for m in entry.findall('./source/member')], 'destination': [m.text for m in entry.findall('./destination/member')], 'service': [m.text for m in entry.findall('./service/member')], 'xml': pretty(entry)})
        return {'revision': revision(current), 'rules': rows, 'findings': policy_findings(rules, session, scope), 'candidate_diff': diff(running_rules, rules), 'has_pending_changes': pending_changes(session), 'has_config_differences': revision(current) != revision(running)}


@router.post('/preview')
def preview(body: Preview, x_pan_session: str = Header(default='')):
    session = session_for(x_pan_session)
    with session.lock:
        current = config(session)
        if revision(current) != body.revision:
            raise HTTPException(409, 'Candidate configuration changed. Reload policies and review again.')
        modified = copy.deepcopy(current)
        rules, device = rules_node(modified, body, create=True)
        existing = next((entry for entry in rules if entry.get('name') == body.name), None)
        if body.operation == 'create' and existing is not None:
            raise HTTPException(409, 'A rule with this name already exists.')
        if body.operation != 'create' and existing is None:
            raise HTTPException(404, 'Rule not found.')
        xpath = f'/config/devices/entry[@name={literal(device)}]/vsys/entry[@name={literal(body.vsys)}]/rulebase/{body.kind}/rules'
        params = {'type': 'config'}
        if body.operation in {'create', 'edit'}:
            if '<!DOCTYPE' in body.xml.upper() or '<!ENTITY' in body.xml.upper():
                raise HTTPException(422, 'DTD/entity declarations are not supported.')
            try:
                entry = clean(ET.fromstring(body.xml))
            except ET.ParseError:
                raise HTTPException(422, 'Rule XML is invalid.') from None
            if entry.tag != 'entry' or entry.get('name') != body.name:
                raise HTTPException(422, 'Provide one entry element with the selected rule name; rename is not supported.')
            for key in ('from', 'to', 'source', 'destination'):
                if not entry.findall(f'./{key}/member') or any(not (m.text or '').strip() for m in entry.findall(f'./{key}/member')):
                    raise HTTPException(422, f'{key} must contain nonempty members.')
            if body.kind == 'security':
                for key in ('service', 'application'):
                    if not entry.findall(f'./{key}/member') or any(not (m.text or '').strip() for m in entry.findall(f'./{key}/member')):
                        raise HTTPException(422, f'{key} must contain nonempty members.')
                if entry.findtext('action') not in {'allow', 'deny', 'drop', 'reset-client', 'reset-server', 'reset-both'}:
                    raise HTTPException(422, 'Select a valid security rule action.')
            if body.operation == 'create':
                rules.append(entry)
                params.update(action='set', xpath=xpath, element=serialize(entry))
            else:
                position = list(rules).index(existing)
                rules.remove(existing); rules.insert(position, entry)
                params.update(action='edit', xpath=xpath + f'/entry[@name={literal(body.name)}]', element=serialize(entry))
        elif body.operation == 'delete':
            rules.remove(existing)
            params.update(action='delete', xpath=xpath + f'/entry[@name={literal(body.name)}]')
        else:
            other = next((e for e in rules if e.get('name') == body.destination), None)
            if body.where in {'before', 'after'} and (other is None or other is existing):
                raise HTTPException(422, 'Choose another existing reference rule.')
            rules.remove(existing)
            index = 0 if body.where == 'top' else len(rules)
            if body.where in {'before', 'after'}:
                index = list(rules).index(other) + (body.where == 'after')
            rules.insert(index, existing)
            params.update(action='move', xpath=xpath + f'/entry[@name={literal(body.name)}]', where=body.where)
            if body.where in {'before', 'after'}:
                params['dst'] = body.destination
        original, _ = rules_node(current, body)
        delta = diff(original, rules)
        if not delta:
            raise HTTPException(400, 'There are no changes to apply.')
        plan = {'type': 'policy', 'revision': revision(current), 'params': params, 'scope': body.model_dump(include={'vsys', 'kind'}), 'name': body.name, 'operation': body.operation}
        key = keep_plan(session, plan)
        before_findings = policy_findings(original, session, body)
        after_findings = policy_findings(rules, session, body)
        identity = lambda item: (item['category'], item['title'], item['severity'], tuple(item['policy_ids']))
        before_keys = {identity(item) for item in before_findings}
        after_keys = {identity(item) for item in after_findings}
        risk_changes = {'before_count': len(before_findings), 'after_count': len(after_findings),
                        'resolved': [item for item in before_findings if identity(item) not in after_keys],
                        'introduced': [item for item in after_findings if identity(item) not in before_keys]}
        return {'preview_id': key, 'diff': delta, 'findings': after_findings, 'risk_changes': risk_changes, 'message': 'Preview only. Save to Candidate writes this one operation; Commit is separate. Risk checks are heuristic and do not replace device validation.'}


@router.post('/apply')
def apply(body: Execute, x_pan_session: str = Header(default='')):
    session = session_for(x_pan_session)
    if session.read_only:
        raise HTTPException(403, "Read-only connection: execution is disabled; previews remain available.")
    with session.lock:
        plan = session.plans.get(body.preview_id)
        if not body.confirm or not plan or plan['type'] != 'policy' or plan['expires'] <= time.monotonic():
            raise HTTPException(400, 'A current preview and explicit confirmation are required.')
        if revision(config(session)) != plan['revision']:
            raise HTTPException(409, 'Candidate configuration changed. Reload and preview again.')
        # Consume before sending: do not replay a write after a timeout.
        del session.plans[body.preview_id]
        audit(session, 'panos_policy_attempt', f'{plan["operation"]} {plan["scope"]} rule={plan["name"]}')
        result = api_call(session, plan['params'])
        audit(session, 'panos_policy_candidate_saved', f'{plan["operation"]} {plan["scope"]} rule={plan["name"]}')
        return {'saved_to_candidate': True, 'committed': False, 'message': 'Candidate updated. Reload and review pending changes before Commit.'}


@router.post('/commit-preview')
def commit_preview(x_pan_session: str = Header(default='')):
    session = session_for(x_pan_session)
    with session.lock:
        current, running = config(session), config(session, 'show')
        if not pending_changes(session):
            raise HTTPException(400, 'The device reports no pending configuration changes.')
        key = keep_plan(session, {'type': 'commit', 'revision': revision(current), 'running_revision': revision(running)})
        return {'preview_id': key, 'diff': diff(running, current, redact=True), 'message': 'Full-device commit includes ALL pending candidate changes, including other administrators and settings outside policy. Review the complete diff. Sensitive values are masked.'}


@router.post('/commit')
def commit(body: Execute, x_pan_session: str = Header(default='')):
    session = session_for(x_pan_session)
    if session.read_only:
        raise HTTPException(403, "Read-only connection: execution is disabled; previews remain available.")
    with session.lock:
        plan = session.plans.get(body.preview_id)
        if not body.confirm or not plan or plan['type'] != 'commit' or plan['expires'] <= time.monotonic():
            raise HTTPException(400, 'Review a current full-device commit preview and confirm first.')
        if revision(config(session)) != plan['revision'] or revision(config(session, 'show')) != plan['running_revision']:
            raise HTTPException(409, 'Configuration changed. Review a new commit preview.')
        del session.plans[body.preview_id]
        audit(session, 'panos_commit_attempt', 'full-device commit requested')
        result = api_call(session, {'type': 'commit', 'cmd': '<commit></commit>'})
        job = result.findtext('./result/job')
        message = ' '.join(result.itertext()).strip()
        audit(session, 'panos_commit_response', f'job={job or "none"}')
        return {'job_id': job, 'message': message, 'completed': False}


@router.get('/jobs/{job_id}')
def job_status(job_id: int, x_pan_session: str = Header(default='')):
    if job_id < 0:
        raise HTTPException(422, 'Invalid job ID.')
    session = session_for(x_pan_session)
    result = api_call(session, {'type': 'op', 'cmd': f'<show><jobs><id>{job_id}</id></jobs></show>'})
    job = result.find('./result/job')
    if job is None:
        raise HTTPException(404, 'Job is not available.')
    return {'job_id': job_id, 'status': job.findtext('status'), 'result': job.findtext('result'), 'details': ' '.join(job.itertext()).strip(), 'succeeded': job.findtext('status') == 'FIN' and job.findtext('result') == 'OK'}
