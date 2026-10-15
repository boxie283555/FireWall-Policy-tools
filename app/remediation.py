"""Persist remediation work separately from requests to add new policies."""
from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field
from app.storage import get_conn, list_policies, list_nat_rules


class CommandRequest(BaseModel):
    kind: Literal['policy', 'nat']
    rule_id: str
    operation: Literal['disable', 'source', 'destination', 'service'] = 'disable'
    values: list[str] = Field(default_factory=list, max_length=100)
    context: str = Field(min_length=1, max_length=200)


class RemediationRequest(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    owner: str = Field(min_length=1, max_length=200)
    category: str
    kind: Literal['policy', 'nat']
    rule_ids: list[str] = Field(min_length=1)
    plan: str = Field(min_length=1, max_length=30000)
    commands: str = Field(default='', max_length=50000)
    rollback: str = Field(default='', max_length=50000)
    status: Literal['draft', 'review', 'approved', 'in_progress', 'implemented', 'verified', 'rejected'] = 'draft'


def init_remediation():
    with get_conn() as conn:
        conn.execute('''create table if not exists remediations (
            id integer primary key autoincrement, payload text not null,
            created_at text default current_timestamp, updated_at text default current_timestamp)''')


def rules_for(kind):
    return list_policies() if kind == 'policy' else list_nat_rules()


def save_remediation(request, record_id=None):
    rules = {rule.id: rule for rule in rules_for(request.kind)}
    if record_id is None and any(key not in rules for key in request.rule_ids):
        raise ValueError('An affected rule is no longer in inventory. Refresh the risk analysis.')
    payload = request.model_dump()
    # Preserve a rule snapshot so later imports do not erase the evidence.
    with get_conn() as conn:
        if record_id is None:
            payload['rule_snapshots'] = [rules[key].model_dump(mode='json') for key in request.rule_ids]
            cursor = conn.execute('insert into remediations(payload) values (?)', (json.dumps(payload),))
            record_id = cursor.lastrowid
            event = 'create_remediation'
        else:
            row = conn.execute('select payload from remediations where id=?', (record_id,)).fetchone()
            if not row:
                raise KeyError(record_id)
            old = json.loads(row['payload'])
            if any(payload[key] != old[key] for key in ('kind', 'category', 'rule_ids')):
                raise ValueError('Affected rules and risk category cannot change on an existing remediation.')
            payload['rule_snapshots'] = old.get('rule_snapshots', [])
            conn.execute('update remediations set payload=?, updated_at=current_timestamp where id=?', (json.dumps(payload), record_id))
            event = 'update_remediation'
        conn.execute('insert into audit_log(event,detail) values (?,?)', (event, f'#{record_id} {request.title} owner={request.owner} status={request.status}'))
    return {'id': record_id, **payload}


def list_remediations():
    with get_conn() as conn:
        return [dict(id=row['id'], created_at=row['created_at'], updated_at=row['updated_at'], **json.loads(row['payload'])) for row in conn.execute('select * from remediations order by id desc')]


def quote(value):
    if not value or any(ord(char) < 32 or char in '\\";[]' for char in value):
        raise ValueError('CLI values cannot contain control characters, quotes, backslashes, brackets or semicolons.')
    return '"' + value + '"'


def generate_commands(request):
    rule = next((r for r in rules_for(request.kind) if r.id == request.rule_id), None)
    if rule is None:
        raise KeyError(request.rule_id)
    vendor = rule.vendor.value
    name = quote(rule.rule_name)
    operation = request.operation
    values = request.values
    if operation != 'disable' and not values:
        raise ValueError('Enter the complete replacement list of existing address/service objects.')
    quoted = ' '.join(quote(v) for v in values)
    notes = ['Candidate commands for manual review only. Confirm the selected device, software version and context.',
             'Back up current configuration; compare the imported rule with the live rule before execution.',
             'Test required and denied flows, then reimport and rerun risk analysis. Marking a ticket verified is a manual attestation.']
    before = []
    if operation != 'disable':
        field = {'source': 'source_addresses', 'destination': 'destination_addresses', 'service': 'services'}[operation] if request.kind == 'policy' else {'source': 'original_sources', 'destination': 'original_destinations', 'service': 'original_services'}[operation]
        before = getattr(rule, field)
        if not before:
            raise ValueError('Original field is unavailable; reimport a complete configuration before generating rollback commands.')
    if vendor == 'palo_alto':
        if request.context != 'local-rulebase':
            raise ValueError('Only a confirmed local PAN-OS rulebase is supported. Panorama pre/post-rulebase requires a context-aware template.')
        base = f'rulebase {"security" if request.kind == "policy" else "nat"} rules {name}'
        if operation == 'disable':
            change = [f'set {base} disabled yes']
            undo = [f'set {base} disabled {"no" if rule.enabled else "yes"}']
        else:
            if request.kind == 'nat' and operation == 'service' and len(values) != 1:
                raise ValueError('PAN-OS NAT requires one original service.')
            def field_set(items):
                value = ' '.join(quote(v) for v in items)
                return f'set {base} {operation} ' + (value if operation == 'service' and request.kind == 'nat' else f'[ {value} ]')
            change = [f'delete {base} {operation}', field_set(values)]
            undo = [f'delete {base} {operation}', field_set(before)]
        commands = '\n'.join(['configure', *change, 'show ' + base])
        rollback = '\n'.join(['configure', *undo, 'show ' + base])
        notes.append('Enter the correct vsys before running these commands. Review the candidate diff and commit manually; commit is intentionally omitted. Replacement uses delete + set to avoid appending to an any scope.')
    elif vendor in {'fortinet', 'fortigate'} and request.kind == 'policy':
        match = re.search(r'^\s*edit\s+"?(\d+)"?\s*$', rule.raw, re.M)
        if not match:
            raise ValueError('Numeric FortiGate policy ID is missing from the original configuration.')
        if request.context != 'firewall-policy':
            raise ValueError('Confirm the firewall policy table in the correct VDOM.')
        field = {'source': 'srcaddr', 'destination': 'dstaddr', 'service': 'service', 'disable': 'status'}[operation]
        new = 'disable' if operation == 'disable' else quoted
        old = ('enable' if rule.enabled else 'disable') if operation == 'disable' else ' '.join(quote(v) for v in before)
        prefix = ['config firewall policy', f'edit {match.group(1)}']
        commands = '\n'.join([*prefix, f'set {field} {new}', 'next', 'end'])
        rollback = '\n'.join([*prefix, f'set {field} {old}', 'next', 'end'])
        notes.append('Select the correct VDOM first. Changes apply immediately. Address and service names must already exist; raw CIDRs/ports are not automatically created as objects.')
    else:
        raise ValueError(f'{vendor} {request.kind}: automatic commands are not available for this operation/context. Create a remediation ticket and attach a manually reviewed vendor command plan; no guessed command is emitted.')
    return {'commands': commands, 'rollback': rollback, 'notes': notes, 'rule_id': rule.id, 'device_name': rule.device_name, 'vendor': vendor, 'operation': operation, 'context': request.context}
