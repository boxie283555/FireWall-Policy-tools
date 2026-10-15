// Session credentials stay on the server; the opaque handle lives only in this page.
let panSession = null;
let panSnapshot = null;
let panPage = 0;
let panEditing = null;
let panPreview = null;
let panLoadSequence = 0;
let panRiskTarget = null;

async function panApi(path, payload, method = 'POST') {
  if (!panSession) throw new Error('Connect to a PAN-OS firewall first.');
  return api(`/api/panos${path}`, { method, headers: {'Content-Type':'application/json', 'X-Pan-Session':panSession.session}, ...(payload !== undefined ? {body:JSON.stringify(payload)} : {}) });
}
function panScope() { return {vsys: $('#pan-vsys').value, kind: $('#pan-kind').value}; }
function panSetStatus(message) { $('#pan-status').textContent = message; }
async function panBusy(button, action, target = '#pan-status') {
  button.disabled = true;
  try { await action(); } catch (error) { $(target).textContent = error.message; }
  finally { button.disabled = false; }
}
function panClear() {
  panLoadSequence++;
  panSession = null; panSnapshot = null; panPreview = null; panEditing = null;
  $('#pan-workspace').hidden = true;
  $('#pan-rules').innerHTML = ''; $('#pan-findings').innerHTML = '';
  $('#pan-connect').elements.credential.value = '';
  for (const id of ['#pan-editor', '#pan-preview']) if ($(id).open) $(id).close();
}
$('#pan-connect').addEventListener('submit', event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  panBusy(form.querySelector('button[type=submit]'), async () => {
    const old = panSession;
    if (old) await panApi('/session', undefined, 'DELETE');
    panClear();
    panSetStatus('Connecting and reading configuration…');
    try {
      panSession = await api('/api/panos/connect', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({...data, port:Number(data.port), verify_tls:data.verify_tls === 'true', read_only:data.read_only === 'true'})});
    } finally { form.elements.credential.value = ''; }
    $('#pan-vsys').innerHTML = panSession.vsys.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join('');
    if (panRiskTarget) $('#pan-kind').value = panRiskTarget.kind;
    $('#pan-workspace').hidden = false;
    await panReload();
  });
});
$('#pan-disconnect').addEventListener('click', event => panBusy(event.currentTarget, async () => {
  try { if (panSession) await panApi('/session', undefined, 'DELETE'); }
  finally { panClear(); panSetStatus('Disconnected.'); }
}));

async function panReload() {
  const sequence = ++panLoadSequence;
  panSnapshot = null; panPreview = null;
  $('#pan-rules').innerHTML = '<tr><td colspan="7">Loading candidate policies…</td></tr>';
  $('#pan-findings').innerHTML = '';
  const snapshot = await panApi('/rules', panScope());
  if (sequence !== panLoadSequence) return;
  panSnapshot = snapshot; panPage = 0;
  panSetStatus(`Connected to ${panSession.hostname} (${panSession.host}), PAN-OS ${panSession.version}. ${panSession.read_only ? "Read-only / Preview mode." : "Edit mode."} ${snapshot.rules.length} local ${panScope().kind} rules loaded.`);
  $('#pan-pending').textContent = snapshot.has_pending_changes ? 'This device has pending candidate changes. Full commit may include changes outside this rule scope.' : snapshot.has_config_differences ? 'The device reports no pending changes. Stored configuration snapshots differ; review the rule-scope diff below before editing.' : 'Candidate and running configuration match. No pending changes.';
  $('#pan-scope-diff').textContent = snapshot.candidate_diff || 'No differences in this rule scope.';
  if (panRiskTarget) $('#pan-search').value = panRiskTarget.name;
  panRenderRules(); panRenderFindings();
}
function panRenderRules() {
  if (!panSnapshot) return;
  const query = $('#pan-search').value.toLowerCase();
  const rows = panSnapshot.rules.filter(r => [r.name, ...r.source, ...r.destination].join(' ').toLowerCase().includes(query));
  const pages = Math.max(1, Math.ceil(rows.length / 50));
  panPage = Math.min(panPage, pages - 1);
  $('#pan-rules').innerHTML = rows.slice(panPage * 50, (panPage + 1) * 50).map(r => `<tr><td>${r.position}</td><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.source.join(', '))}</td><td>${escapeHtml(r.destination.join(', '))}</td><td>${escapeHtml(r.action)}</td><td>${r.enabled ? 'Enabled':'Disabled'}</td><td><button type="button" class="secondary pan-edit" data-name="${escapeHtml(r.name)}">Edit / Optimize</button> <button type="button" class="secondary pan-delete-rule" data-name="${escapeHtml(r.name)}">Delete Rule</button></td></tr>`).join('') || '<tr><td colspan="7">No matching local rules. Check the selected firewall, vsys and rule type.</td></tr>';
  $('#pan-page').textContent = `${rows.length} rules · Page ${panPage + 1} / ${pages}`;
  $('#pan-prev').disabled = panPage === 0; $('#pan-next').disabled = panPage >= pages - 1;
  $$('.pan-edit').forEach(b => b.addEventListener('click', () => panOpen(b.dataset.name)));
  $$('.pan-delete-rule').forEach(b => b.addEventListener('click', () => panBusy(b, async () => {
    if (!panSnapshot) throw new Error('Reload policies first.');
    const name = b.dataset.name;
    const result = await panApi('/preview', {...panScope(), operation:'delete', name, revision:panSnapshot.revision});
    panShowPreview(result, false, 'delete', name);
  })));

}
function panRenderFindings() {
  const findings = panSnapshot.findings;
  $('#pan-findings').innerHTML = findings.length ? `<p>${findings.length} findings. Showing the first ${Math.min(200, findings.length)}.</p>` + findings.slice(0,200).map(f => `<article class="mini-card"><strong>${escapeHtml(f.title)} · ${escapeHtml(f.severity)}</strong><p>${escapeHtml(f.detail)}</p><p>${escapeHtml(f.recommendation)}</p><div class="form-actions">${f.policy_ids.map(name => `<button type="button" class="secondary pan-optimize" data-name="${escapeHtml(name)}">Optimize: ${escapeHtml(name)}</button>`).join('')}</div></article>`).join('') : `<p>${panScope().kind === 'nat' ? 'Use NAT Rules for imported NAT analysis; online editing uses full rule XML.' : 'No policy findings.'}</p>`;
  $$('.pan-optimize').forEach(b => b.addEventListener('click', () => panOpen(b.dataset.name)));
}
$('#pan-reload').addEventListener('click', e => panBusy(e.currentTarget, panReload));
for (const id of ['#pan-vsys','#pan-kind']) $(id).addEventListener('change', () => { panRiskTarget = null; $('#pan-target').textContent = ''; panReload().catch(e => panSetStatus(e.message)); });
$('#pan-search').addEventListener('input', () => {panPage=0; panRenderRules();});
$('#pan-prev').addEventListener('click', () => {panPage--; panRenderRules();});
$('#pan-next').addEventListener('click', () => {panPage++; panRenderRules();});
$('#pan-new').addEventListener('click', () => panOpen(null));

function panParse(text) {
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) throw new Error('DTD/entity declarations are not supported.');
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.querySelector('parsererror') || doc.documentElement.tagName !== 'entry') throw new Error('Provide one valid entry XML element.');
  return doc;
}
function panChild(entry, tag) { return [...entry.children].find(node => node.tagName === tag); }
function panOpen(name) {
  if (!panSnapshot) {panSetStatus('Reload policies first.'); return;}
  const rule = name === null ? null : panSnapshot.rules.find(r => r.name === name);
  if (name !== null && !rule) {panSetStatus('Rule no longer exists. Reload policies.'); return;}
  const kind = panScope().kind;
  const template = kind === 'security' ? '<entry name=""><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><service><member>application-default</member></service><application><member>any</member></application><action>deny</action><disabled>yes</disabled></entry>' : '<entry name=""><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><service>any</service><disabled>yes</disabled></entry>';
  panEditing = {rule, xml:rule?.xml || template, revision:panSnapshot.revision, scope:panScope()};
  $('#pan-edit-form').reset();
  $('#pan-editor-title').textContent = rule ? 'Edit Online Rule' : 'Add Online Rule';
  $('#pan-edit-form button[type=submit]').textContent = rule ? 'Preview Edit & Risks' : 'Preview Add & Risks';
  $('#pan-name').value = rule?.name || ''; $('#pan-name').readOnly = !!rule;
  $('#pan-enabled').value = rule ? (rule.enabled?'yes':'no') : 'no';
  const root = panParse(panEditing.xml).documentElement;
  $('#pan-security-fields').hidden = kind !== 'security'; $('#pan-nat-field').hidden = kind !== 'nat';
  $$('#pan-security-fields textarea').forEach(el => el.required = kind === 'security');
  for (const tag of ['from','to','source','destination','service','application']) $('#pan-'+tag).value = [...(panChild(root,tag)?.children || [])].map(m => m.textContent).join('\n');
  $('#pan-action').value = panChild(root,'action')?.textContent || 'deny';
  $('#pan-description').value = panChild(root,'description')?.textContent || '';
  $('#pan-nat-xml').value = panEditing.xml;
  $('#pan-original').textContent = panEditing.xml;
  $('#pan-edit-context').textContent = `${panSession.hostname} (${panSession.host}) / ${panScope().vsys} / ${kind}. Changes go to candidate configuration after review. Existing fields outside this form are preserved.`;
  $('#pan-delete').hidden = !rule; $('#pan-move-controls').hidden = !rule;
  $('#pan-destination-rule').innerHTML = panSnapshot.rules.filter(r => r.name !== name).map(r => `<option value="${escapeHtml(r.name)}">${escapeHtml(r.name)}</option>`).join('');
  $('#pan-edit-status').textContent = '';
  $('#pan-editor').showModal();
}
function panEditedXML() {
  const doc = panParse(panEditing.scope.kind === 'nat' ? $('#pan-nat-xml').value : panEditing.xml);
  const root = doc.documentElement; root.setAttribute('name', $('#pan-name').value.trim());
  function replace(tag, text, members=false) {
    const old = panChild(root,tag); const el = doc.createElement(tag);
    if (members) {
      const values = text.split('\n').map(s => s.trim()).filter(Boolean);
      if (!values.length) throw new Error(`${tag} requires at least one value.`);
      for (const value of values) {const member=doc.createElement('member'); member.textContent=value; el.appendChild(member);}
    } else {el.textContent=text;}
    if (old) root.replaceChild(el,old); else root.appendChild(el);
  }
  if (panChild(root,'disabled') || $('#pan-enabled').value === 'no') replace('disabled', $('#pan-enabled').value === 'yes' ? 'no':'yes');
  if (panEditing.scope.kind === 'security') {
    for (const tag of ['from','to','source','destination','service','application']) replace(tag, $('#pan-'+tag).value, true);
    replace('action', $('#pan-action').value);
    if ($('#pan-description').value || panChild(root,'description')) replace('description', $('#pan-description').value);
  }
  return new XMLSerializer().serializeToString(root);
}
async function panPrepare(operation) {
  const body = {...panEditing.scope, operation, name:$('#pan-name').value.trim(), revision:panEditing.revision, where:$('#pan-where').value, destination:$('#pan-destination-rule').value};
  if (operation === 'edit' || operation === 'create') body.xml=panEditedXML();
  const result = await panApi('/preview', body);
  panShowPreview(result, false, operation, body.name);
}
$('#pan-edit-form').addEventListener('submit', e => {e.preventDefault(); panBusy(e.submitter, () => panPrepare(panEditing.rule?'edit':'create'), '#pan-edit-status');});
$('#pan-delete').addEventListener('click', e => panBusy(e.currentTarget, () => panPrepare('delete'), '#pan-edit-status'));
$('#pan-move').addEventListener('click', e => panBusy(e.currentTarget, () => panPrepare('move'), '#pan-edit-status'));
$('#pan-edit-close').addEventListener('click', () => $('#pan-editor').close());
function panShowPreview(result, commit, operation, name) {
  panPreview={...result,commit};
  $('#pan-preview-title').textContent = commit ? 'Review Full-Device Commit' : `${operation === 'delete' ? 'Review Rule Deletion' : operation === 'create' ? 'Review New Rule' : 'Review Candidate Policy Change'}: ${name || ''}`;
  $('#pan-preview-message').textContent=result.message;
  $('#pan-preview-diff').textContent=result.diff;
  $('#pan-preview-findings').innerHTML=(result.findings || []).slice(0,200).map(f => `<p><strong>${escapeHtml(f.severity)} · ${escapeHtml(f.title)}</strong> ${escapeHtml(f.detail)}</p>`).join('') || 'No findings reported for this preview.';
  $('#pan-execute').textContent=commit?'Confirm Full Commit':operation === 'delete'?'Confirm Delete from Candidate':'Confirm Save to Candidate';
  $('#pan-execute').disabled=panSession.read_only;
  if (panSession.read_only) $('#pan-execute').textContent='Read-only connection';
  const changes = result.risk_changes;
  $('#pan-risk-changes').textContent = changes ? `Risk findings: ${changes.before_count} before → ${changes.after_count} after. ${changes.resolved.length} resolved; ${changes.introduced.length} introduced. These are heuristic findings, not device validation.` : '';
   $('#pan-job-controls').hidden=true; $('#pan-execute-status').textContent='';
  $('#pan-preview').showModal();
}
$('#pan-commit-preview').addEventListener('click', e => panBusy(e.currentTarget, async () => panShowPreview(await panApi('/commit-preview'), true)));
$('#pan-preview-close').addEventListener('click', () => $('#pan-preview').close());
$('#pan-execute').addEventListener('click', async event => {
  const button=event.currentTarget; button.disabled=true;
  const preview=panPreview;
  try {
    if (!preview) throw new Error('Create a new preview first.');
    const result=await panApi(preview.commit?'/commit':'/apply', {preview_id:preview.preview_id,confirm:true});
    $('#pan-execute-status').textContent=result.message;
    if (preview.commit && result.job_id) {$('#pan-job').value=result.job_id; $('#pan-job-controls').hidden=false;}
    else if (!preview.commit) {
      if ($('#pan-editor').open) $('#pan-editor').close();
      await panReload();
    }
  } catch(error) {$('#pan-execute-status').textContent=error.message + ' Reload and create a new preview before retrying.';}
  // A timeout can mean the device applied the write. Never re-enable replay.
});
$('#pan-job-check').addEventListener('click', e => panBusy(e.currentTarget, async () => {
  const job=$('#pan-job').value;
  if (!/^\d+$/.test(job)) throw new Error('Enter a valid commit job ID.');
  const result=await panApi('/jobs/'+job, undefined, 'GET');
  $('#pan-execute-status').textContent=`Job ${result.job_id}: ${result.status} / ${result.result}\n${result.details}`;
  if (result.succeeded) {await panReload(); $('#pan-execute-status').textContent += '\nCommit completed successfully; candidate policies refreshed.';}
}, '#pan-execute-status'));
$('#pan-download-diff').addEventListener('click', () => {
  const blob=new Blob([$('#pan-preview-message').textContent+'\n\n'+$('#pan-preview-diff').textContent],{type:'text/plain;charset=utf-8'});
  const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='panos-policy-change.diff.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});

async function openPanosRisk(rule) {
  setView('panos');
  const kind=rule.kind==='nat'?'nat':'security';
  panRiskTarget={name:rule.rule_name, kind};
  $('#pan-target').textContent=`From risk analysis: ${rule.device_name} / ${rule.rule_name}. Confirm the matching management host and vsys, then edit the live rule.`;
  $('#pan-kind').value=kind;
  if (panSession && [panSession.hostname,panSession.host].includes(rule.device_name)) {
    await panReload().catch(e => panSetStatus(e.message));
  } else {
    try {
      const devices=await api('/api/device-connections');
      const device=devices.find(d => d.name===rule.device_name && d.vendor==='palo_alto');
      if (device) $('#pan-connect').elements.host.value=device.host;
      if (panSession) {await panApi('/session',undefined,'DELETE'); panClear();}
      panSetStatus('Connect to the matching firewall to load this rule. Imported data alone does not identify the live vsys.');
    } catch(error) {panSetStatus(error.message);}
  }
}

$('#pan-existing-job-check').addEventListener('click', e => panBusy(e.currentTarget, async () => {
  const job = $('#pan-existing-job').value;
  if (!/^\d+$/.test(job)) throw new Error('Enter a valid commit job ID.');
  const result = await panApi('/jobs/' + job, undefined, 'GET');
  $('#pan-existing-job-status').textContent = `Job ${result.job_id}: ${result.status} / ${result.result}\n${result.details}`;
}, '#pan-existing-job-status'));
