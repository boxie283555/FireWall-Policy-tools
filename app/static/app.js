const titles = {
  panos: ["PAN-OS Online", "Edit and optimize live candidate policies; review and commit separately."],
  dashboard: ["Dashboard", "Device policy inventory and risk status."],
  devices: ["Device Access", "Add firewall management IPs and fetch running configuration over SSH, Telnet, API/HTTPS, or NETCONF."],
  import: ["Import Config", "Load ASA, PAN-OS, Fortinet, or Huawei configuration files."],
  policies: ["Access Rules", "Query by source, destination, service, application, user, zone, and action."],
  nat: ["NAT Rules", "Query NAT policies, translations, and NAT risk findings."],
  objects: ["Objects", "Address, service, and object group inventory."],
  visualization: ["Path / Topology", "Path analysis, zone matrix, topology, dependencies, and rule order."],
  analysis: ["Risk Findings", "Conflicts, duplicates, shadowed rules, broad access, and optimization advice."],
  changes: ["Change Requests", "Policy change request records."],
  audit: ["Audit Log", "Import and workflow history."],
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
let inventoryCache = { devices: [], values: {} };
const debounce = (fn, delay = 250) => {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
};

class ApiError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = "ApiError";
    this.detail = detail;
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, cache: "no-store" });
  if (!response.ok) {
    const text = await response.text();
    let detail = text;
    try {
      detail = JSON.parse(text).detail;
    } catch {
      detail = text;
    }
    const message = typeof detail === "string" ? detail : detail?.error || JSON.stringify(detail);
    throw new ApiError(message, detail);
  }
  return response.json();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function textList(items, limit = 6) {
  if (!items || !items.length) return '<span class="pill">any</span>';
  const shown = items.slice(0, limit).map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join("");
  if (items.length > limit) {
    const remaining = items.slice(limit).map(item => `<span class="pill">${escapeHtml(item)}</span>`).join("");
    return `${shown}<details class="address-list-more"><summary class="pill" aria-label="Show all items"><span class="address-more-count">+${items.length - limit}</span><span class="address-more-less">Show less</span></summary>${remaining}</details>`;
  }
  return shown;
}

function globalVendor() {
  return $("#global-vendor").value;
}

function globalDevice() {
  return $("#global-device").value;
}

function paramsFrom(values) {
  const params = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== null && String(value).trim() !== "") params.set(key, value);
  });
  if (globalVendor()) params.set("vendor", globalVendor());
  if (globalDevice()) params.set("device_name", globalDevice());
  return params;
}

function setView(view) {
  $$(".view").forEach((item) => item.classList.toggle("active", item.id === view));
  $$(".nav").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  $("#page-title").textContent = titles[view][0];
  $("#page-subtitle").textContent = titles[view][1];
  loadView(view);
}

async function loadDashboard() {
  const data = await api(`/api/dashboard?${paramsFrom({})}`);
  $("#metric-policies").textContent = data.policy_count;
  $("#metric-nat").textContent = data.nat_rule_count || 0;
  $("#metric-objects").textContent = data.object_count;
  $("#metric-findings").textContent = data.finding_count;
  $("#metric-high").textContent = data.high_risk_count;
  renderBars("#vendor-bars", data.vendor_counts);
  renderBars("#action-bars", data.action_counts);
}

async function loadInventory() {
  const params = new URLSearchParams();
  if (globalVendor()) params.set("vendor", globalVendor());
  inventoryCache = await api(`/api/inventory?${params}`);
  if (globalDevice()) {
    const valueParams = new URLSearchParams(params);
    valueParams.set("device_name", globalDevice());
    const deviceInventory = await api(`/api/inventory?${valueParams}`);
    inventoryCache.values = deviceInventory.values || inventoryCache.values;
  }
  renderDeviceSelectors();
  renderDatalists(inventoryCache.values || {});
}

function renderDeviceSelectors() {
  const selected = globalDevice();
  const devices = inventoryCache.devices || [];
  $("#global-device").innerHTML = '<option value="">All Devices</option>' + devices.map((device) => `<option value="${escapeHtml(device.device_name)}">${escapeHtml(device.device_name)} (${escapeHtml(device.vendor)})</option>`).join("");
  if (devices.some((device) => device.device_name === selected)) $("#global-device").value = selected;
  $("#change-device").innerHTML = '<option value="">Use selected device</option>' + devices.map((device) => `<option value="${escapeHtml(device.device_name)}">${escapeHtml(device.device_name)} (${escapeHtml(device.vendor)})</option>`).join("");
  const vendorLabels = {
    cisco_asa: "Cisco ASA",
    palo_alto: "Palo Alto",
    fortinet: "Fortinet",
    fortigate: "Fortinet",
    huawei: "Huawei",
  };
  const grouped = devices.reduce((acc, device) => {
    acc[device.vendor] = acc[device.vendor] || [];
    acc[device.vendor].push(device);
    return acc;
  }, {});
  $("#device-tree").innerHTML = devices.length
    ? Object.entries(grouped)
        .map(([vendor, vendorDevices]) => {
          const policyCount = vendorDevices.reduce((sum, device) => sum + device.policy_count, 0);
          const natCount = vendorDevices.reduce((sum, device) => sum + (device.nat_rule_count || 0), 0);
          const objectCount = vendorDevices.reduce((sum, device) => sum + device.object_count, 0);
          const vendorActive = globalVendor() === vendor && !globalDevice();
          return `<div class="device-vendor">
            <button class="vendor-node ${vendorActive ? "active" : ""}" data-vendor="${escapeHtml(vendor)}">
              <span class="tree-caret">▾</span>
              <strong>${escapeHtml(vendorLabels[vendor] || vendor)}</strong>
              <em>${vendorDevices.length} devices / ${policyCount} rules / ${natCount} NAT / ${objectCount} objects</em>
            </button>
            <div class="device-children">
              ${vendorDevices
                .map(
                  (device) => `<button class="device-node ${globalVendor() === device.vendor && globalDevice() === device.device_name ? "active" : ""}" data-vendor="${escapeHtml(device.vendor)}" data-device="${escapeHtml(device.device_name)}">
                    <strong>${escapeHtml(device.device_name)}</strong>
                    <span>${device.policy_count} rules / ${device.nat_rule_count || 0} NAT / ${device.object_count} objects</span>
                    <em>${escapeHtml(device.context_label)}</em>
                  </button>`
                )
                .join("")}
            </div>
          </div>`;
        })
        .join("")
    : '<div class="muted">No devices imported</div>';
  $$(".vendor-node").forEach((button) =>
    button.addEventListener("click", () => {
      $("#global-vendor").value = button.dataset.vendor;
      $("#global-device").value = "";
      loadInventory().then(() => loadView());
    })
  );
  $$(".device-node").forEach((button) =>
    button.addEventListener("click", () => {
      $("#global-vendor").value = button.dataset.vendor;
      loadInventory().then(() => {
        $("#global-device").value = button.dataset.device;
        loadInventory().then(() => loadView());
      });
    })
  );
}

function renderDatalists(values) {
  const map = {
    "zone-options": values.zones || [],
    "address-options": values.addresses || [],
    "service-options": values.services || [],
    "application-options": values.applications || [],
    "user-options": values.users || [],
    "policy-options": values.policies || [],
  };
  Object.entries(map).forEach(([id, items]) => {
    $(`#${id}`).innerHTML = items.slice(0, 1500).map((item) => `<option value="${escapeHtml(item)}"></option>`).join("");
  });
}

function renderBars(selector, values) {
  const entries = Object.entries(values || {});
  const max = Math.max(1, ...entries.map(([, value]) => value));
  $(selector).innerHTML = entries.length
    ? entries
        .map(
          ([key, value]) => `
          <div class="bar-row">
            <span>${escapeHtml(key)}</span>
            <div class="bar-track"><div class="bar-fill" style="width:${(value / max) * 100}%"></div></div>
            <strong>${value}</strong>
          </div>`
        )
        .join("")
    : '<p>No data</p>';
}

function policyFilterParams() {
  return paramsFrom({
    source_zone: $("#policy-source-zone").value,
    destination_zone: $("#policy-destination-zone").value,
    source: $("#policy-source").value,
    destination: $("#policy-destination").value,
    service: $("#policy-service").value,
    application: $("#policy-application").value,
    user: $("#policy-user").value,
    action: $("#policy-action").value,
    query: $("#policy-query").value,
  });
}

function clearPolicyFilters() {
  ["policy-source-zone", "policy-destination-zone", "policy-source", "policy-destination", "policy-service", "policy-application", "policy-user", "policy-query"].forEach((id) => {
    $(`#${id}`).value = "";
  });
  $("#policy-action").value = "";
  policyColumnFilters = {};
  loadPolicies();
}

let policyTableRows = [];
let policyColumnFilters = {};
let policyTableLoadSequence = 0;
const policyColumns = {
  Vendor: p => [p.vendor], Device: p => [p.device_name], Rule: p => [p.rule_name],
  Zone: p => [...(p.source_zones || []), ...(p.destination_zones || [])],
  Source: p => p.source_addresses || [], Destination: p => p.destination_addresses || [],
  Service: p => p.services || [], 'App/User': p => [...(p.applications || []), ...(p.users || [])],
  Action: p => [p.action], Status: p => [p.enabled ? 'enabled' : 'disabled'],
};
function matchesPolicyColumns(policy, except) {
  return Object.entries(policyColumnFilters).every(([column, value]) =>
    column === except || !value || policyColumns[column](policy).includes(value));
}
function renderPolicyTable() {
  for (const [column, valuesFor] of Object.entries(policyColumns)) {
    const select = document.querySelector(`[data-policy-column="${column}"]`);
    const values = new Set(policyTableRows.filter(p => matchesPolicyColumns(p, column)).flatMap(valuesFor).filter(Boolean));
    const selected = policyColumnFilters[column] || '';
    if (selected) values.add(selected);
    select.replaceChildren(new Option('All', ''));
    [...values].sort((a, b) => a.localeCompare(b)).forEach(value => select.add(new Option(value, value)));
    select.value = selected;
    select.classList.toggle('column-filter-active', !!selected);
  }
  const policies = policyTableRows.filter(p => matchesPolicyColumns(p));
  $("#policy-count").textContent = policies.length;
  $("#policy-table").innerHTML = policies
    .map(
      (p, index) => `<tr>
        <td>${index + 1}</td>
        <td>${escapeHtml(p.line_no ?? "—")}</td>
        <td>${escapeHtml(p.vendor)}</td>
        <td>${escapeHtml(p.device_name)}</td>
        <td><strong>${escapeHtml(p.rule_name)}</strong></td>
        <td>${textList(p.source_zones, 3)}<span class="arrow">→</span>${textList(p.destination_zones, 3)}</td>
        <td>${textList(p.source_addresses)}</td>
        <td>${textList(p.destination_addresses)}</td>
        <td>${textList(p.services)}</td>
        <td>${textList([...(p.applications || []), ...(p.users || [])])}</td>
        <td><span class="action ${escapeHtml(p.action).toLowerCase()}">${escapeHtml(p.action)}</span></td>
        <td>${p.enabled ? "enabled" : "disabled"}</td>
      </tr>`
    )
    .join("");
}

async function loadPolicies() {
  const sequence = ++policyTableLoadSequence;
  const policies = await api(`/api/policies?${policyFilterParams()}`);
  if (sequence !== policyTableLoadSequence) return;
  policyTableRows = policies;
  renderPolicyTable();
}
for (const column of Object.keys(policyColumns)) {
  const header = [...document.querySelectorAll('#policies thead th')].find(th => th.textContent === column);
  const select = document.createElement('select');
  select.dataset.policyColumn = column; select.className = 'policy-column-filter';
  select.setAttribute('aria-label', `Filter ${column}`);
  select.add(new Option('All', ''));
  select.addEventListener('change', () => { policyColumnFilters[column] = select.value; renderPolicyTable(); });
  header.append(select);
}

function natFilterParams() {
  return paramsFrom({
    query: $("#nat-query").value,
    nat_type: $("#nat-type").value,
  });
}

function clearNatFilters() {
  $("#nat-query").value = "";
  $("#nat-type").value = "";
  natColumnFilters = {};
  Object.keys(natFieldFilters).forEach(id => document.getElementById(id).value = "");
  loadNatRules();
}

let natTableRows = [];
let natColumnFilters = {};
let natLoadSequence = 0;
const natFieldFilters = {
  'nat-source-zone': p => p.source_zones || [], 'nat-destination-zone': p => p.destination_zones || [],
  'nat-original-source': p => p.original_sources || [], 'nat-original-destination': p => p.original_destinations || [],
  'nat-translated-source': p => p.translated_sources || [], 'nat-translated-destination': p => p.translated_destinations || [],
  'nat-service': p => [...(p.original_services || []), ...(p.translated_services || [])],
};
const natColumns = {
  Vendor: p => [p.vendor], Device: p => [p.device_name], 'NAT Rule': p => [p.rule_name], Type: p => [p.nat_type],
  Zone: p => [...(p.source_zones || []), ...(p.destination_zones || [])],
  Original: p => [...(p.original_sources || []), ...(p.original_destinations || [])],
  Translated: p => [...(p.translated_sources || []), ...(p.translated_destinations || [])],
  Service: natFieldFilters['nat-service'], Status: p => [p.enabled ? 'enabled' : 'disabled'],
};
function matchesNatFilters(rule, except) {
  return Object.entries(natColumnFilters).every(([column, value]) => column === except || !value || natColumns[column](rule).includes(value)) &&
    Object.entries(natFieldFilters).every(([id, valuesFor]) => {
      const query = document.getElementById(id).value.trim().toLowerCase();
      return !query || valuesFor(rule).some(value => value.toLowerCase().includes(query));
    });
}
function renderNatTable() {
  for (const [column, valuesFor] of Object.entries(natColumns)) {
    const select = document.querySelector(`[data-nat-column="${column}"]`);
    const values = new Set(natTableRows.filter(rule => matchesNatFilters(rule, column)).flatMap(valuesFor).filter(Boolean));
    const selected = natColumnFilters[column] || '';
    if (selected) values.add(selected);
    select.replaceChildren(new Option('All', ''));
    [...values].sort((a,b) => a.localeCompare(b)).forEach(value => select.add(new Option(value, value)));
    select.value = selected; select.classList.toggle('column-filter-active', !!selected);
  }
  const rules = natTableRows.filter(rule => matchesNatFilters(rule));
  $("#nat-count").textContent = rules.length;
  $("#nat-table").innerHTML = rules
    .map(
      (rule, index) => `<tr>
        <td>${index + 1}</td>
        <td>${escapeHtml(rule.line_no ?? "—")}</td>
        <td>${escapeHtml(rule.vendor)}</td>
        <td>${escapeHtml(rule.device_name)}</td>
        <td><strong>${escapeHtml(rule.rule_name)}</strong></td>
        <td>${escapeHtml(rule.nat_type)}</td>
        <td>${textList(rule.source_zones, 2)}<span class="arrow">→</span>${textList(rule.destination_zones, 2)}</td>
        <td>${textList([...(rule.original_sources || []), ...(rule.original_destinations || [])], 5)}</td>
        <td>${textList([...(rule.translated_sources || []), ...(rule.translated_destinations || [])], 5)}</td>
        <td>${textList([...(rule.original_services || []), ...(rule.translated_services || [])], 4)}</td>
        <td>${rule.enabled ? "enabled" : "disabled"}</td>
      </tr>`
    )
    .join("");
}
for (const column of Object.keys(natColumns)) {
  const header = [...document.querySelectorAll('#nat thead th')].find(th => th.textContent === column);
  const select = document.createElement('select'); select.dataset.natColumn = column;
  select.className = 'policy-column-filter'; select.setAttribute('aria-label', `Filter NAT ${column}`);
  select.add(new Option('All', ''));
  select.addEventListener('change', () => { natColumnFilters[column] = select.value; renderNatTable(); });
  header.append(select);
}
Object.keys(natFieldFilters).forEach(id => document.getElementById(id).addEventListener('input', renderNatTable));

async function loadNatRules() {
  const sequence = ++natLoadSequence;
  const [rules, findings] = await Promise.all([api(`/api/nat-rules?${natFilterParams()}`), api(`/api/nat-analysis?${paramsFrom({})}`)]);
  if (sequence !== natLoadSequence) return;
  natTableRows = rules;
  renderNatTable();
  $("#nat-analysis-list").innerHTML = findings.length
    ? findings
        .map(
          (finding) => `<article class="card finding">
            <div class="card-title">
              <span>${escapeHtml(finding.title)}</span>
              <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
            </div>
            <p>${escapeHtml(finding.detail)}</p>
            <p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p>
          </article>`
        )
        .join("")
    : '<div class="card">No NAT findings.</div>';
}

async function loadObjects() {
  const params = paramsFrom({ query: $("#object-query").value });
  const objects = await api(`/api/objects?${params}`);
  $("#object-table").innerHTML = objects
    .slice(0, 2000)
    .map(
      (obj) => `<tr>
        <td>${escapeHtml(obj.vendor)}</td>
        <td>${escapeHtml(obj.name)}</td>
        <td>${escapeHtml(obj.type)}</td>
        <td>${escapeHtml(obj.value)}</td>
      </tr>`
    )
    .join("");
}

async function loadDevices() {
  const devices = await api("/api/device-connections");
  $("#device-access-table").innerHTML = devices.length
    ? devices
        .map(
          (device) => `<tr>
            <td><strong>${escapeHtml(device.name)}</strong><div class="muted">${escapeHtml(device.notes || "")}</div></td>
            <td>${escapeHtml(device.vendor)}</td>
            <td>${escapeHtml(device.protocol)}</td>
            <td>${escapeHtml(device.host)}:${escapeHtml(device.port)}</td>
            <td>${escapeHtml(device.username)}</td>
            <td><span class="status-badge ${statusClass(device.last_status)}">${escapeHtml(device.last_status || "new")}</span>${device.last_error ? `<div class="muted">${escapeHtml(device.last_error).slice(0, 100)}</div>` : ""}</td>
            <td>${escapeHtml(device.last_fetched_at || "")}</td>
            <td>
              <button class="secondary row-action" data-action="fill-device" data-id="${device.id}">Fill</button>
              <button class="secondary row-action" data-action="test-device" data-id="${device.id}">Test</button>
              <button class="primary row-action" data-action="fetch-device" data-id="${device.id}">Fetch</button>
            </td>
          </tr>`
        )
        .join("")
    : '<tr><td colspan="8">No device access profiles.</td></tr>';
  $$(".row-action").forEach((button) => {
    button.addEventListener("click", () => handleDeviceRowAction(button.dataset.action, Number(button.dataset.id), devices));
  });
}

function statusClass(status) {
  if (!status) return "";
  if (status.includes("ok")) return "ok";
  if (status.includes("failed")) return "failed";
  return "";
}

function deviceFormPayload() {
  const data = Object.fromEntries(new FormData($("#device-form")).entries());
  return {
    connection: {
      name: data.name,
      vendor: data.vendor,
      host: data.host,
      port: Number(data.port || 22),
      protocol: data.protocol || "ssh",
      username: data.username,
      enable_password_required: data.enable_password_required === "on",
      notes: data.notes || null,
    },
    credentials: {
      password: data.password || "",
      enable_password: data.enable_password || null,
    },
  };
}

async function saveDeviceConnection() {
  const payload = deviceFormPayload();
  const device = await api("/api/device-connections", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload.connection),
  });
  renderDeviceResult({ saved: device, note: "Password was not saved. Enter it in the form when testing or fetching." });
  await loadDevices();
  return { device, credentials: payload.credentials };
}

async function testDeviceConnection(deviceId, credentials) {
  if (!credentials.password) throw new Error("Please enter the device password.");
  try {
    const result = await api(`/api/device-connections/${deviceId}/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentials),
    });
    renderDeviceResult(result);
  } catch (error) {
    renderDeviceResult(errorResult(error));
    throw error;
  } finally {
    await loadDevices();
  }
}

async function fetchDeviceConfig(deviceId, credentials) {
  if (!credentials.password) throw new Error("Please enter the device password.");
  try {
    const result = await api(`/api/device-connections/${deviceId}/fetch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentials),
    });
    renderDeviceResult(result);
    await loadInventory();
    await loadDashboard();
  } catch (error) {
    renderDeviceResult(errorResult(error));
    throw error;
  } finally {
    await loadDevices();
  }
}

async function handleDeviceRowAction(action, deviceId, devices) {
  const device = devices.find((item) => item.id === deviceId);
  if (!device) return;
  if (action === "fill-device") {
    const form = $("#device-form");
    form.elements["name"].value = device.name;
    form.elements["vendor"].value = device.vendor;
    form.elements["protocol"].value = device.protocol || "ssh";
    form.elements["host"].value = device.host;
    form.elements["port"].value = device.port;
    form.elements["username"].value = device.username;
    form.elements["enable_password_required"].checked = Boolean(device.enable_password_required);
    form.elements["notes"].value = device.notes || "";
    syncDeviceProtocolFields();
    renderDeviceResult({ note: "Device profile loaded into the form. Passwords are not saved; enter the password again before testing or fetching." });
    return;
  }
  const credentials = deviceFormPayload().credentials;
  if (action === "test-device") await testDeviceConnection(deviceId, credentials);
  if (action === "fetch-device") await fetchDeviceConfig(deviceId, credentials);
}

function renderDeviceResult(result) {
  const summary = {
    status: result.status,
    error: result.error,
    note: result.note,
    device_name: result.device_name,
    vendor: result.vendor,
    saved: result.saved,
    warnings: result.warnings,
    commands: result.commands,
    config_size: result.config_size,
    detail: result.detail,
    preview: result.preview,
  };
  $("#device-result").innerHTML = `
    <pre>${escapeHtml(JSON.stringify(summary, null, 2))}</pre>
    ${
      result.config_preview
        ? `<h3>Fetched Configuration Preview</h3><pre>${escapeHtml(result.config_preview)}</pre>`
        : ""
    }
    ${
      result.session_preview
        ? `<h3>Raw Session Preview</h3><pre>${escapeHtml(result.session_preview)}</pre>`
        : ""
    }`;
}

function errorResult(error) {
  if (error instanceof ApiError && typeof error.detail === "object" && error.detail) {
    return { status: "error", ...error.detail };
  }
  return { status: "error", error: error.message || String(error) };
}

const remediationSteps = {
  "over-permissive": ["Confirm the required business flows with the owner; record exact source, destination and ports.", "Create explicit address/service objects and replacement rules; validate required and denied flows before retiring the Any-Any rule."],
  "broad-scope": ["Identify which any source, destination or service fields are required using traffic logs.", "Replace broad fields with approved hosts, subnets and services; retain exceptions only with an owner and review date."],
  "dangerous-service": ["Confirm the exposed management/database ports and approved clients.", "Limit sources to the bastion, VPN or management subnet; remove unneeded ports and verify unauthorized clients are denied."],
  "dangerous-application": ["Confirm the application's business owner, clients and servers.", "Restrict applications, users and address scope; enable session logging and review allowed and blocked traffic."],
  "cross-zone": ["Confirm the intended trust-boundary crossing and traffic direction.", "Split access into explicit zone pairs and required services; test both forward and return traffic."],
  "least-privilege": ["Map each source/destination/service combination to an approved business flow.", "Split unrelated flows into separately owned rules without creating additional allowed combinations."],
  unused: ["Check hit-counter reset time and observe a representative business cycle, including periodic jobs.", "After owner approval, disable the rule during a change window; monitor failures before permanently removing it."],
  duplicate: ["Compare rule order, logging, schedules, objects and business ownership on the device.", "Keep the approved canonical rule, preserve metadata and disable redundant rules; remove them after observation."],
  conflict: ["Confirm the expected allow/deny result with the owner and inspect first-match rule order.", "Narrow or reorder the conflicting rules to express that decision; test an allowed flow and a denied flow."],
  shadowed: ["Compare the earlier covering rule with the later rule, including resolved objects and schedules.", "Narrow the earlier rule or reposition the intended exception after approval; verify first-match behavior."],
  "merge-suggestion": ["Confirm that the rules share an application, owner, schedule and expiration.", "Combine only the required services into a service group; compare permitted traffic before disabling the old rules."],
  "broad-nat": ["Confirm whether this is an intentional catch-all translation and inspect rule precedence.", "Limit original sources and destinations to approved networks; test translation and return traffic."],
  "broad-service-nat": ["List the published services and their original and translated ports.", "Limit destination/static NAT to those services and align the security policy; test required and blocked ports."],
  "public-inbound-nat": ["Confirm the published destination and approved external client networks.", "Restrict sources in both NAT and security policy; verify external access, translation and return traffic."],
  "duplicate-nat": ["Compare match conditions, translation, interfaces and precedence on the device.", "Keep the canonical NAT rule and disable duplicates after approval; test new sessions and reverse translation."],
};

function riskSteps(finding) {
  if (finding.category === "lifecycle") {
    if (finding.title === "Expired Rule Still Enabled") return ["Ask the owner whether access is still required and record approval for any renewal.", "Disable expired access or renew its expiration after approval; verify required traffic and review the next expiration date."];
    if (finding.title === "Rule Expiring Soon") return ["Contact the owner before the displayed expiration date and confirm continued business need.", "Record an approved renewal or schedule removal; verify access at the change window."];
    return ["Confirm why the rule was disabled and the required retention period.", "After owner approval and backup, remove stale disabled rules and confirm no dependencies remain."];
  }
  if (finding.category === "governance") return finding.title === "Rule Owner Missing"
    ? ["Identify the accountable business owner and confirm the purpose of this access.", "Add owner metadata to the device rule description/tag or linked change record; reimport and verify the finding clears."]
    : ["Confirm whether access is temporary or permanent with the owner.", "Add an approved expiration for temporary access, or document permanent access and its review date; reimport the updated configuration."];
  return remediationSteps[finding.category] || [finding.recommendation];
}

let riskRows = [];
let riskRules = [];
let remediationTickets = [];
let activeRemediation = null;

async function loadAnalysis() {
  const params = paramsFrom({}).toString();
  const [findings, summary, natFindings, policies, natRules] = await Promise.all([
    api(`/api/analysis?${params}`), api(`/api/report/summary?${params}`),
    api(`/api/nat-analysis?${params}`), api(`/api/policies?${params}`), api(`/api/nat-rules?${params}`),
  ]);
  renderRiskSummary(summary);
  const rows = [...findings.map(f => ({ ...f, kind: "policy" })), ...natFindings.map(f => ({ ...f, kind: "nat" }))];
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  rows.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
  riskRows = rows;
  riskRules = [...policies.map(r => ({...r, kind: "policy"})), ...natRules.map(r => ({...r, kind: "nat"}))];
  const related = f => {
    const ids = new Set(f.policy_ids || f.rule_ids || []);
    return (f.kind === "nat" ? natRules : policies).filter(rule => ids.has(rule.id));
  };
  const rendered = rows.map((f, index) => {
    const rules = related(f);
    return `<details class="panel finding risk-leaf"><summary>${escapeHtml(f.title)} <span class="severity ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></summary><div>
      <div class="card-title"><strong>${escapeHtml(f.title)}</strong><span class="severity ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></div>
      <p class="muted">${escapeHtml(f.kind.toUpperCase())} · ${escapeHtml(f.category)}</p>
      <p>${escapeHtml(f.detail)}</p>
      <p><strong>Recommended improvement:</strong> ${escapeHtml(f.recommendation)}</p>
      <ol>${riskSteps(f).map(step => `<li>${escapeHtml(step)}</li>`).join("")}
        <li>Back up the configuration and record rollback steps before the change. After implementation, reimport the configuration and rerun the risk review.</li></ol>
      <div class="form-actions">${rules.filter(r => r.vendor === "palo_alto").map(r => `<button type="button" class="secondary risk-online" data-rule-id="${escapeHtml(r.id)}">Edit online: ${escapeHtml(r.device_name)} / ${escapeHtml(r.rule_name)}</button>`).join("")}<button class="primary risk-start" data-index="${index}" type="button">Start Remediation</button><button class="secondary risk-command" data-index="${index}" type="button">Generate Commands</button><button class="secondary risk-download" data-index="${index}" type="button">Download Remediation Plan</button></div>
      <details class="risk-rules"><summary>Inspect affected rules (${rules.length})</summary>
        ${rules.length ? rules.map(rule => `<div class="mini-card"><strong>${escapeHtml(rule.device_name)} / ${escapeHtml(rule.rule_name)}</strong>
          <span>${escapeHtml(rule.vendor)} · ID: ${escapeHtml(rule.id)} · Line: ${escapeHtml(rule.line_no ?? "unknown")} · ${rule.enabled ? "Enabled" : "Disabled"}</span>
          <pre>${escapeHtml(JSON.stringify(Object.fromEntries(Object.entries(rule).filter(([key]) => key !== "raw")), null, 2))}</pre>
          <details><summary>Original configuration</summary><pre>${escapeHtml(rule.raw || "Original configuration unavailable.")}</pre></details></div>`).join("") : "<p>Associated rules are unavailable in the current inventory. Refresh or reimport before planning changes.</p>"}
      </details></div></details>`;
  });
  const categoryLabels = { "over-permissive": "Any-Any Access", "broad-scope": "Broad Access Scope", "dangerous-service": "High-Risk Services", "dangerous-application": "High-Risk Applications", "cross-zone": "Zone Boundaries", "least-privilege": "Least Privilege", unused: "Unused Rules", duplicate: "Duplicate Rules", conflict: "Conflicting Rules", shadowed: "Shadowed Rules", "merge-suggestion": "Merge Opportunities", lifecycle: "Rule Lifecycle", governance: "Ownership & Expiration", "broad-nat": "Broad NAT Match", "broad-service-nat": "Broad NAT Services", "public-inbound-nat": "Inbound NAT Exposure", "duplicate-nat": "Duplicate NAT" };
  $("#finding-list").innerHTML = rows.length ? ["policy", "nat"].map(kind => {
    const categories = [...new Set(rows.filter(f => f.kind === kind).map(f => f.category))];
    const count = rows.filter(f => f.kind === kind).length;
    if (!count) return "";
    return `<details class="risk-branch panel" open><summary>${kind === "policy" ? "Security Policy Risks" : "NAT Risks"} (${count})</summary>${categories.map(category => {
      const indexes = rows.map((f, i) => f.kind === kind && f.category === category ? i : -1).filter(i => i >= 0);
      return `<details class="risk-branch"><summary>${escapeHtml(categoryLabels[category] || category)} (${indexes.length})</summary>${indexes.map(i => rendered[i]).join("")}</details>`;
    }).join("")}</details>`;
  }).join("") : '<div class="card">No risk findings.</div>';
  $$(".risk-start, .risk-command").forEach(button => button.addEventListener("click", () => {
    openRemediation(rows[Number(button.dataset.index)]);
    if (button.classList.contains("risk-command")) $("#remediation-operation").focus();
  }));
  $$(".risk-online").forEach(button => button.addEventListener("click", () => {
    const rule = riskRules.find(r => r.id === button.dataset.ruleId);
    if (rule) openPanosRisk(rule);
  }));
  await loadRemediations();
  $$(".risk-download").forEach(button => button.addEventListener("click", () => {
    const finding = rows[Number(button.dataset.index)];
    const plan = [finding.title, `Severity: ${finding.severity} | Type: ${finding.kind} | Category: ${finding.category}`,
      finding.detail, `Recommendation: ${finding.recommendation}`, "", "Implementation steps:",
      ...riskSteps(finding).map((step, i) => `${i + 1}. ${step}`),
      "", "Before implementation: obtain approval, back up configuration and record rollback steps.",
      "Validation: test approved and denied flows, monitor logs, reimport configuration and rerun risk analysis.",
      "Rollback: restore the backed-up rule configuration and order if validation fails.",
      "", "Affected rules:", ...related(finding).map(rule => JSON.stringify(rule, null, 2))].join("\n");
    const url = URL.createObjectURL(new Blob([plan], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url; link.download = `remediation-${finding.kind}-${finding.category}.txt`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }));
}

function renderRiskSummary(summary) {
  const severity = summary.severity_counts || {};
  $("#risk-summary").innerHTML = [
    ["Total", summary.total_findings || 0],
    ["Critical", severity.critical || 0],
    ["High", severity.high || 0],
    ["Medium", severity.medium || 0],
    ["Low", severity.low || 0],
  ]
    .map(([label, value]) => `<div class="summary-item"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`)
    .join("");
  const categories = summary.policy_categories || [];
  $("#category-summary").innerHTML = categories.length
    ? categories
        .slice(0, 12)
        .map(
          (item) => `<article class="mini-card">
            <strong>${escapeHtml(item.category)}</strong>
            <span>${escapeHtml(item.affected_count)} affected rules</span>
          </article>`
        )
        .join("")
    : '<article class="mini-card">No affected policy categories.</article>';
}

function exportCsv(kind) {
  const endpoints = {
    findings: "/api/export/findings.csv",
    policies: "/api/export/policies.csv",
    nat: "/api/export/nat.csv",
  };
  const endpoint = endpoints[kind];
  if (!endpoint) return;
  window.location.href = `${endpoint}?${paramsFrom({})}`;
}

async function loadVisualization() {
  const active = $(".tab.active").dataset.tab;
  if (active === "matrix") return loadMatrix();
  if (active === "topology") return loadTopology();
  if (active === "dependencies") return loadDependencies();
  if (active === "order") return loadOrder();
}

async function loadMatrix() {
  const data = await api(`/api/visualization/matrix?${paramsFrom({})}`);
  const zones = data.zones.slice(0, 24);
  const cells = new Map(data.cells.map((cell) => [`${cell.source_zone}|${cell.destination_zone}`, cell]));
  $("#matrix-head").innerHTML = `<tr><th>From \\ To</th>${zones.map((zone) => `<th>${escapeHtml(zone)}</th>`).join("")}</tr>`;
  $("#matrix-body").innerHTML = zones
    .map(
      (src) => `<tr><th>${escapeHtml(src)}</th>${zones
        .map((dst) => {
          const cell = cells.get(`${src}|${dst}`);
          return `<td class="${cell && cell.risk ? "risk-cell" : ""}">${cell ? `${cell.count}<div class="muted">A:${cell.allow} D:${cell.deny}</div>` : ""}</td>`;
        })
        .join("")}</tr>`
    )
    .join("");
}

async function loadTopology() {
  const data = await api(`/api/visualization/topology?${paramsFrom({})}`);
  const topEdges = data.edges.sort((a, b) => b.count - a.count).slice(0, 40);
  $("#topology-canvas").innerHTML = topEdges.length
    ? topEdges
        .map(
          (edge) => `<div class="topology-edge">
            <span>${escapeHtml(edge.source)}</span>
            <strong>${edge.count}</strong>
            <span>${escapeHtml(edge.target)}</span>
            <em>${edge.risk} risky</em>
          </div>`
        )
        .join("")
    : '<div class="card">No topology data.</div>';
}

async function loadDependencies() {
  const data = await api(`/api/visualization/dependencies?${paramsFrom({})}`);
  $("#dependency-referenced").innerHTML = renderDependencyCards(data.referenced);
  $("#dependency-unreferenced").innerHTML = renderDependencyCards(data.unreferenced);
  renderDependencyGraph(data.referenced);
}

async function runDependencyObjectSearch(event) {
  event.preventDefault();
  const name = $("#dependency-object-query").value.trim();
  if (!name) return;
  const result = await api(`/api/visualization/dependencies/object?${paramsFrom({ name })}`);
  renderDependencyObjectResult(result);
}

async function runPolicyDependencySearch(event) {
  event.preventDefault();
  const policy = $("#dependency-policy-query").value.trim();
  if (!policy) return;
  const result = await api(`/api/visualization/dependencies/policy?${paramsFrom({ policy })}`);
  renderPolicyDependencyResult(result);
}

function renderDependencyObjectResult(result) {
  const objectCards = result.objects.length
    ? result.objects
        .map(
          (obj) => `<article class="mini-card">
            <strong>${escapeHtml(obj.name)}</strong>
            <span>${escapeHtml(obj.type)} / ${escapeHtml(obj.vendor)} / ${escapeHtml(obj.device_name)}</span>
            <em>${escapeHtml(obj.value).slice(0, 120)}</em>
          </article>`
        )
        .join("")
    : '<article class="mini-card">No matching object definition was found, but direct policy references are still checked.</article>';
  const referenceRows = result.references.length
    ? `<div class="table-wrap compact"><table>
        <thead><tr><th>#</th><th>Device</th><th>Policy</th><th>Referenced Field</th><th>Action</th><th>Line</th></tr></thead>
        <tbody>${result.references
          .map(
            (ref, index) => `<tr>
              <td>${index + 1}</td>
              <td>${escapeHtml(ref.policy.device_name)}</td>
              <td>${escapeHtml(ref.policy.rule_name)}</td>
              <td>${escapeHtml(ref.fields.map((field) => `${field.field}: ${field.value}`).join(", "))}</td>
              <td>${escapeHtml(ref.policy.action)}</td>
              <td>${escapeHtml(ref.policy.line_no || "")}</td>
            </tr>`
          )
          .join("")}</tbody>
      </table></div>`
    : '<article class="card">No policy references found.</article>';
  $("#dependency-search-result").innerHTML = `
    <section class="panel">
      <h2>${escapeHtml(result.query)} References <span class="muted">${result.reference_count} policies</span></h2>
      <div id="dependency-object-graph" class="dependency-graph"></div>
    </section>
    <section class="panel">
      <h2>Object Definitions</h2>
      <div class="cards">${objectCards}</div>
    </section>
    <section class="panel">
      <h2>Referencing Policies</h2>
      ${referenceRows}
    </section>`;
  renderDependencyObjectGraph(result);
}

function renderPolicyDependencyResult(result) {
  const sections = result.policies.length
    ? result.policies
        .map((item, index) => {
          const rows = item.references.length
            ? item.references
                .map(
                  (ref, refIndex) => `<tr>
                    <td>${refIndex + 1}</td>
                    <td>${escapeHtml(ref.field)}</td>
                    <td>${escapeHtml(ref.value)}</td>
                    <td>${escapeHtml(ref.object)}</td>
                    <td>${ref.defined ? "yes" : "direct/literal"}</td>
                    <td>${escapeHtml((ref.definitions || []).map((definition) => `${definition.type}: ${definition.value}`).join(" | ")).slice(0, 220)}</td>
                  </tr>`
                )
                .join("")
            : '<tr><td colspan="6">No object references were parsed for this policy.</td></tr>';
          return `<section class="panel">
            <h2>${escapeHtml(item.policy.rule_name)} <span class="muted">${item.references.length} references</span></h2>
            <div id="policy-object-graph-${index}" class="dependency-graph"></div>
            <div class="table-wrap compact">
              <table>
                <thead><tr><th>#</th><th>Field</th><th>Referenced Value</th><th>Object Name</th><th>Defined</th><th>Object Definition</th></tr></thead>
                <tbody>${rows}</tbody>
              </table>
            </div>
          </section>`;
        })
        .join("")
    : '<article class="card">No matching policy found.</article>';
  $("#policy-dependency-search-result").innerHTML = `
    <article class="card">
      <div class="card-title"><span>${escapeHtml(result.query)} Policy Object References</span><span>${result.match_count} matched</span></div>
      <p>Results are grouped by matching policy, not ranked by reference count.</p>
    </article>
    ${sections}`;
  result.policies.forEach((item, index) => renderPolicyObjectGraph(item, `#policy-object-graph-${index}`));
}

function renderDependencyCards(items) {
  return items.length
    ? items
        .slice(0, 80)
        .map(
          (item) => `<article class="mini-card">
            <strong>${escapeHtml(item.object)}</strong>
            <span>${escapeHtml((item.types || []).join(", "))}</span>
            <em>${item.policy_count} rules</em>
          </article>`
        )
        .join("")
    : '<div class="mini-card">No data</div>';
}

function renderDependencyGraph(items) {
  const objects = items.slice(0, 18);
  if (!objects.length) {
    $("#dependency-graph").innerHTML = '<div class="mini-card">No visualization data</div>';
    return;
  }
  const policyMap = new Map();
  objects.forEach((item) => {
    (item.policies || []).slice(0, 6).forEach((policy) => {
      if (!policyMap.has(policy.id)) policyMap.set(policy.id, policy);
    });
  });
  const policies = [...policyMap.values()].slice(0, 28);
  const width = 1180;
  const rowHeight = 46;
  const topOffset = 54;
  const height = Math.max(320, Math.max(objects.length, policies.length) * rowHeight + 95);
  const objectX = 300;
  const policyX = 790;
  const objectY = (index) => topOffset + index * rowHeight;
  const policyY = (index) => topOffset + index * rowHeight;
  const policyIndex = new Map(policies.map((policy, index) => [policy.id, index]));
  const edges = [];
  objects.forEach((item, objectIndex) => {
    (item.policies || []).forEach((policy) => {
      if (policyIndex.has(policy.id)) edges.push({ objectIndex, policyIndex: policyIndex.get(policy.id) });
    });
  });
  $("#dependency-graph").innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Object dependency graph">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#7a8a9c"></path>
        </marker>
      </defs>
      <text x="${objectX - 260}" y="26" class="graph-title">Objects</text>
      <text x="${policyX}" y="26" class="graph-title">Policies</text>
      ${edges
        .map((edge) => {
          const y1 = objectY(edge.objectIndex);
          const y2 = policyY(edge.policyIndex);
          return `<path class="graph-edge" d="M ${objectX} ${y1} C ${objectX + 145} ${y1}, ${policyX - 165} ${y2}, ${policyX - 8} ${y2}" marker-end="url(#arrow)"></path>`;
        })
        .join("")}
      ${objects
        .map((item, index) => {
          const y = objectY(index);
          return `<g>
            <rect class="graph-node object" x="${objectX - 260}" y="${y - 16}" width="260" height="32" rx="3"></rect>
            <text x="${objectX - 250}" y="${y + 4}">${svgLabel(item.object, 32)}</text>
            <text class="graph-count" x="${objectX - 45}" y="${y + 4}">${item.policy_count}</text>
          </g>`;
        })
        .join("")}
      ${policies
        .map((policy, index) => {
          const y = policyY(index);
          return `<g>
            <rect class="graph-node policy" x="${policyX}" y="${y - 16}" width="340" height="32" rx="3"></rect>
            <text x="${policyX + 10}" y="${y + 4}">${svgLabel(policy.rule_name, 46)}</text>
          </g>`;
        })
        .join("")}
    </svg>`;
}

function renderDependencyObjectGraph(result) {
  const refs = result.references.slice(0, 60);
  if (!refs.length) {
    $("#dependency-object-graph").innerHTML = '<div class="mini-card">No reference graph for this object.</div>';
    return;
  }
  const width = 1180;
  const rowHeight = 44;
  const topOffset = 56;
  const height = Math.max(260, refs.length * rowHeight + 100);
  const objectX = 320;
  const policyX = 760;
  const objectY = Math.max(70, height / 2);
  $("#dependency-object-graph").innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Single object dependency graph">
      <defs>
        <marker id="single-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#7a8a9c"></path>
        </marker>
      </defs>
      <text x="35" y="22" class="graph-title">Object</text>
      <text x="${policyX}" y="22" class="graph-title">Referenced By Policies</text>
      <rect class="graph-node object" x="35" y="${objectY - 24}" width="${objectX - 45}" height="48" rx="3"></rect>
      <text x="47" y="${objectY + 4}">${svgLabel(result.query, 38)}</text>
      ${refs
        .map((ref, index) => {
          const y = topOffset + index * rowHeight;
          const sourceY = graphPortY(index, refs.length, objectY);
          return `<path class="graph-edge" d="M ${objectX} ${sourceY} C ${objectX + 135} ${sourceY}, ${policyX - 155} ${y}, ${policyX - 8} ${y}" marker-end="url(#single-arrow)"></path>
          <g>
            <rect class="graph-node policy" x="${policyX}" y="${y - 16}" width="380" height="32" rx="3"></rect>
            <text x="${policyX + 10}" y="${y + 4}">${svgLabel(ref.policy.rule_name, 38)}</text>
            <text class="graph-count" x="${policyX + 285}" y="${y + 4}">${svgLabel(ref.fields.map((field) => field.field).join("/"), 18)}</text>
          </g>`;
        })
        .join("")}
    </svg>`;
}

function renderPolicyObjectGraph(item, selector) {
  const refs = item.references.slice(0, 70);
  if (!refs.length) {
    $(selector).innerHTML = '<div class="mini-card">No object reference graph for this policy.</div>';
    return;
  }
  const width = 1180;
  const rowHeight = 44;
  const topOffset = 56;
  const height = Math.max(260, refs.length * rowHeight + 100);
  const policyX = 35;
  const objectX = 690;
  const policyY = Math.max(70, height / 2);
  $(selector).innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Policy object dependency graph">
      <defs>
        <marker id="policy-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#7a8a9c"></path>
        </marker>
      </defs>
      <text x="${policyX}" y="22" class="graph-title">Policy</text>
      <text x="${objectX}" y="22" class="graph-title">Referenced Objects / Literals</text>
      <rect class="graph-node policy" x="${policyX}" y="${policyY - 24}" width="390" height="48" rx="3"></rect>
      <text x="${policyX + 12}" y="${policyY + 4}">${svgLabel(item.policy.rule_name, 52)}</text>
      ${refs
        .map((ref, index) => {
          const y = topOffset + index * rowHeight;
          const sourceY = graphPortY(index, refs.length, policyY);
          return `<path class="graph-edge" d="M ${policyX + 390} ${sourceY} C ${policyX + 525} ${sourceY}, ${objectX - 155} ${y}, ${objectX - 8} ${y}" marker-end="url(#policy-arrow)"></path>
          <g>
            <rect class="graph-node object" x="${objectX}" y="${y - 16}" width="430" height="32" rx="3"></rect>
            <text x="${objectX + 10}" y="${y + 4}">${svgLabel(`${ref.field}: ${ref.object}`, 54)}</text>
            <text class="graph-count" x="${objectX + 342}" y="${y + 4}">${ref.defined ? "object" : "literal"}</text>
          </g>`;
        })
        .join("")}
    </svg>`;
}

function graphPortY(index, total, centerY) {
  const spread = Math.min(140, Math.max(36, (total - 1) * 7));
  if (total <= 1) return centerY;
  return centerY - spread / 2 + (index / (total - 1)) * spread;
}

function svgLabel(value, maxLength) {
  const text = String(value ?? "");
  const clipped = text.length > maxLength ? `${text.slice(0, Math.max(0, maxLength - 1))}…` : text;
  return escapeSvg(clipped);
}

function escapeSvg(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

async function loadOrder() {
  const rows = await api(`/api/visualization/order?${paramsFrom({})}`);
  $("#order-table").innerHTML = rows
    .slice(0, 1200)
    .map(
      (row) => `<tr class="${row.is_shadow_candidate ? "shadow-row" : ""}">
        <td>${row.order}</td>
        <td>${escapeHtml(row.device_name)}</td>
        <td>${escapeHtml(row.rule_name)}</td>
        <td>${textList(row.source_zones, 2)}<span class="arrow">→</span>${textList(row.destination_zones, 2)}</td>
        <td>${escapeHtml(row.action)}</td>
        <td>${escapeHtml((row.covered_by || []).join(", "))}</td>
      </tr>`
    )
    .join("");
}

async function runPathAnalysis(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget).entries());
  const result = await api(`/api/path-analysis?${paramsFrom(data)}`);
  const first = result.first_match;
  const hitRows = (result.hit_path || [])
    .map(
      (item) => `<tr class="${item.effective ? "hit-row" : ""}">
        <td>${escapeHtml(item.order)}</td>
        <td>${item.effective ? "effective" : "later match"}</td>
        <td>${escapeHtml(item.policy.device_name)}</td>
        <td>${escapeHtml(item.policy.rule_name)}</td>
        <td>${escapeHtml(item.policy.action)}</td>
        <td>${textList(item.policy.source_zones, 2)}<span class="arrow">→</span>${textList(item.policy.destination_zones, 2)}</td>
        <td>${textList(item.policy.source_addresses, 3)}<span class="arrow">→</span>${textList(item.policy.destination_addresses, 3)}</td>
        <td>${textList(item.policy.services, 3)}</td>
        <td>${escapeHtml([...(item.matched_fields || []), ...(item.wildcard_fields || []).map((field) => `${field}:any`)].join(", "))}</td>
      </tr>`
    )
    .join("");
  $("#path-result").innerHTML = `
    <article class="card hit-summary ${first ? "hit-allow" : "hit-deny"}">
      <div class="card-title"><span>Final Action: ${escapeHtml(result.final_action)}</span><span>${result.matched_count} matches / ${result.checked_count} checked</span></div>
      ${
        first
          ? `<p><strong>${escapeHtml(first.rule_name)}</strong> is the first effective match at order ${escapeHtml(result.first_match_order || "")} on ${escapeHtml(first.device_name)}.</p>
             <p>${textList(first.source_zones)} ${textList(first.source_addresses)} <span class="arrow">→</span> ${textList(first.destination_zones)} ${textList(first.destination_addresses)}</p>`
          : "<p>No enabled rule matched this traffic in the selected scope. The result is implicit deny.</p>"
      }
    </article>
    <article class="card">
      <div class="card-title"><span>Hit Path</span><span>First 100 matches</span></div>
      <div class="table-wrap compact">
        <table>
          <thead><tr><th>Order</th><th>Role</th><th>Device</th><th>Rule</th><th>Action</th><th>Zone</th><th>Address</th><th>Service</th><th>Matched By</th></tr></thead>
          <tbody>${hitRows || '<tr><td colspan="9">No matching enabled policy.</td></tr>'}</tbody>
        </table>
      </div>
    </article>
    <article class="card">
      <div class="card-title"><span>Path Notes</span><span>${(result.later_matches || []).length} later matches</span></div>
      <p>${first ? "Later matching rules are shown for troubleshooting, but they do not take effect because the first matching rule stops evaluation." : "Add a specific allow rule before the implicit deny if this traffic should be permitted."}</p>
    </article>`;
}

async function loadChanges() {
  const changes = await api("/api/change-requests");
  $("#change-list").innerHTML = changes
    .map(
      (c) => `<article class="card">
        <div class="card-title"><span>#${c.id} ${escapeHtml(c.title)}</span><span>${escapeHtml(c.status)}</span></div>
        <p>${escapeHtml(c.source_zone || "any")} ${escapeHtml(c.source)} → ${escapeHtml(c.destination_zone || "any")} ${escapeHtml(c.destination)} / ${escapeHtml(c.service)} / ${escapeHtml(c.application || "any")} / ${escapeHtml(c.user || "any")} / ${escapeHtml(c.action)}</p>
        <p>${escapeHtml(c.business_reason)}</p>
        <div class="form-actions status-actions">
          ${["review", "approved", "rejected", "implemented"]
            .map((status) => `<button class="secondary change-status" type="button" data-id="${c.id}" data-status="${status}">${status}</button>`)
            .join("")}
        </div>
      </article>`
    )
    .join("");
  $$(".change-status").forEach((button) => {
    button.addEventListener("click", () => updateChangeStatus(Number(button.dataset.id), button.dataset.status).catch((error) => alert(error.message)));
  });
}

async function updateChangeStatus(requestId, status) {
  await api(`/api/change-requests/${requestId}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  await loadChanges();
  await loadAudit();
}

async function runPolicyPrecheck() {
  const data = Object.fromEntries(new FormData($("#change-form")).entries());
  const payload = {
    vendor: data.vendor || globalVendor() || null,
    device_name: data.device_name || globalDevice() || null,
    source_zone: data.source_zone || null,
    destination_zone: data.destination_zone || null,
    source: data.source,
    destination: data.destination,
    service: data.service,
    application: data.application || null,
    user: data.user || null,
    action: data.action || "allow",
  };
  if (!payload.source || !payload.destination || !payload.service) {
    $("#precheck-result").innerHTML = '<article class="card"><div class="card-title"><span>Precheck</span><span class="severity high">missing</span></div><p>Please fill in source, destination, and service first.</p></article>';
    return;
  }
  const result = await api("/api/precheck-policy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  $("#precheck-result").innerHTML = `
    <article class="card precheck ${escapeHtml(result.verdict)}">
      <div class="card-title"><span>Precheck: ${escapeHtml(result.verdict)}</span><span>${result.issues.length} issues</span></div>
      <p>${escapeHtml(result.summary)}</p>
      <p><strong>Deployment:</strong> ${escapeHtml(result.deployment.detail)}</p>
      <p><strong>Recommended placement:</strong> ${escapeHtml(result.placement.detail)}${result.placement.recommended_line ? ` Line ${escapeHtml(result.placement.recommended_line)}` : ""}</p>
    </article>
    ${result.issues
      .map(
        (issue) => `<article class="card">
          <div class="card-title">
            <span>${escapeHtml(issue.title)}</span>
            <span class="severity ${escapeHtml(issue.severity)}">${escapeHtml(issue.severity)}</span>
          </div>
          <p>${escapeHtml(issue.detail)}</p>
          <p><strong>Recommendation:</strong> ${escapeHtml(issue.recommendation)}</p>
        </article>`
      )
      .join("")}
    ${
      result.matched_policies.length
        ? `<article class="card"><div class="card-title"><span>Related Rules</span><span>Top ${result.matched_policies.length}</span></div><div class="rule-list">${result.matched_policies
            .map((p) => `<div><strong>${escapeHtml(p.rule_name)}</strong><span>${escapeHtml(p.action)} line ${escapeHtml(p.line_no || "")}</span></div>`)
            .join("")}</div></article>`
        : ""
    }`;
  return result;
}

async function loadAudit() {
  const audit = await api("/api/audit");
  $("#audit-list").innerHTML = audit
    .map(
      (a) => `<article class="card">
        <div class="card-title"><span>${escapeHtml(a.event)}</span><span>${escapeHtml(a.created_at)}</span></div>
        <p>${escapeHtml(a.detail)}</p>
      </article>`
    )
    .join("");
}

function loadView(view = document.querySelector(".view.active").id) {
  const loaders = {
    dashboard: loadDashboard,
    policies: loadPolicies,
    nat: loadNatRules,
    objects: loadObjects,
    visualization: loadVisualization,
    analysis: loadAnalysis,
    changes: loadChanges,
    audit: loadAudit,
    devices: loadDevices,
    panos: async () => { if (panSession) await panReload(); },
    import: async () => {},
  };
  return loaders[view]().catch((error) => alert(error.message));
}

$$(".nav").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
$$(".tab").forEach((button) =>
  button.addEventListener("click", () => {
    $$(".tab").forEach((tab) => tab.classList.toggle("active", tab === button));
    $$(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.id === `tab-${button.dataset.tab}`));
    loadVisualization();
  })
);

$("#refresh-btn").addEventListener("click", () => loadInventory().then(() => loadView()).catch(error => alert(error.message)));
$("#global-vendor").addEventListener("change", () => {
  $("#global-device").value = "";
  loadInventory().then(() => loadView());
});
$("#global-device").addEventListener("change", () => {
  loadInventory().then(() => loadView());
});
const debouncedLoadPolicies = debounce(loadPolicies);
["policy-source-zone", "policy-destination-zone", "policy-source", "policy-destination", "policy-service", "policy-application", "policy-user", "policy-query"].forEach((id) => {
  $(`#${id}`).addEventListener("input", debouncedLoadPolicies);
});
$("#policy-action").addEventListener("change", loadPolicies);
$("#clear-policy-filters").addEventListener("click", clearPolicyFilters);
$("#nat-query").addEventListener("input", debounce(loadNatRules));
$("#nat-type").addEventListener("change", loadNatRules);
$("#clear-nat-filters").addEventListener("click", clearNatFilters);
$("#object-query").addEventListener("input", loadObjects);
$("#path-form").addEventListener("submit", runPathAnalysis);
$("#dependency-search-form").addEventListener("submit", (event) => runDependencyObjectSearch(event).catch((error) => alert(error.message)));
$("#policy-dependency-search-form").addEventListener("submit", (event) => runPolicyDependencySearch(event).catch((error) => alert(error.message)));
$("#precheck-btn").addEventListener("click", () => runPolicyPrecheck().catch((error) => alert(error.message)));
$("#export-findings").addEventListener("click", () => exportCsv("findings"));
$("#export-policies").addEventListener("click", () => exportCsv("policies"));
$("#export-nat").addEventListener("click", () => exportCsv("nat"));
function syncDeviceProtocolFields() {
  const form = $("#device-form");
  const protocol = form.elements["protocol"].value;
  const vendor = form.elements["vendor"].value;
  const port = $("#device-form").elements["port"];
  const password = form.elements["password"];
  if (protocol === "telnet" && (!port.value || port.value === "22" || port.value === "443" || port.value === "830")) port.value = "23";
  if (protocol === "ssh" && (!port.value || port.value === "23" || port.value === "443" || port.value === "830")) port.value = "22";
  if (protocol === "api_https" && (!port.value || port.value === "22" || port.value === "23" || port.value === "830")) port.value = "443";
  if (protocol === "netconf" && (!port.value || port.value === "22" || port.value === "23" || port.value === "443")) port.value = "830";
  if (protocol === "api_https" && vendor === "palo_alto") {
    password.placeholder = "PAN-OS API key, or password for API keygen; not saved";
  } else if (protocol === "api_https" && (vendor === "fortinet" || vendor === "fortigate")) {
    password.placeholder = "Fortinet API token; not saved";
  } else if (protocol === "netconf") {
    password.placeholder = "NETCONF password; not saved";
  } else {
    password.placeholder = "Password, used only for this test/fetch";
  }
}

$("#device-form").elements["protocol"].addEventListener("change", syncDeviceProtocolFields);
$("#device-form").elements["vendor"].addEventListener("change", syncDeviceProtocolFields);
syncDeviceProtocolFields();

$("#device-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await saveDeviceConnection().catch((error) => alert(error.message));
});
$("#device-save-test").addEventListener("click", async () => {
  const saved = await saveDeviceConnection().catch((error) => {
    alert(error.message);
    return null;
  });
  if (saved) await testDeviceConnection(saved.device.id, saved.credentials).catch((error) => alert(error.message));
});
$("#device-save-fetch").addEventListener("click", async () => {
  const saved = await saveDeviceConnection().catch((error) => {
    alert(error.message);
    return null;
  });
  if (saved) await fetchDeviceConfig(saved.device.id, saved.credentials).catch((error) => alert(error.message));
});

$("#import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  let result;
  if (data.get("file") && data.get("file").size) {
    result = await api("/api/import-file", { method: "POST", body: data });
  } else {
    result = await api("/api/import", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        vendor: data.get("vendor"),
        device_name: data.get("device_name"),
        config_text: data.get("config_text"),
      }),
    });
  }
  $("#import-result").textContent = JSON.stringify(result, null, 2);
  await loadDashboard();
});

$("#change-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget).entries());
  data.vendor = data.vendor || globalVendor() || "";
  data.device_name = data.device_name || globalDevice() || "";
  const created = await api("/api/change-requests", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  const precheck = await runPolicyPrecheck().catch(() => null);
  if (precheck) {
    $("#precheck-result").insertAdjacentHTML(
      "afterbegin",
      `<article class="card">
        <div class="card-title"><span>Submit Result</span><span>#${escapeHtml(created.id)}</span></div>
        <p>The request was saved and will not be pushed to the device automatically. Recommended placement: ${escapeHtml(precheck.placement.detail)}${precheck.placement.recommended_line ? ` Line ${escapeHtml(precheck.placement.recommended_line)}` : ""}</p>
      </article>`
    );
  }
  event.currentTarget.reset();
  await loadChanges();
});

loadInventory().then(loadDashboard);


async function loadRemediations() {
  remediationTickets = await api("/api/remediations");
  const filtered = remediationTickets.filter(t => t.rule_snapshots.some(r => (!globalVendor() || r.vendor === globalVendor() || globalVendor() === "fortinet" && r.vendor === "fortigate") && (!globalDevice() || r.device_name === globalDevice())));
  $("#remediation-list").innerHTML = filtered.length ? filtered.map(t => `<article class="card"><div class="card-title"><strong>#${t.id} ${escapeHtml(t.title)}</strong><span>${escapeHtml(t.status)}</span></div><p>Owner: ${escapeHtml(t.owner)} · ${escapeHtml(t.kind)} / ${escapeHtml(t.category)}</p><p>${escapeHtml(t.plan)}</p><button type="button" class="secondary remediation-edit" data-id="${t.id}">Edit / Track Remediation</button></article>`).join("") : '<p class="muted">No remediation tickets in the selected device scope.</p>';
  $$(".remediation-edit").forEach(button => button.addEventListener("click", () => openRemediation(null, remediationTickets.find(t => t.id === Number(button.dataset.id)))));
}

function openRemediation(finding, ticket = null) {
  const form = $("#remediation-form");
  form.reset();
  activeRemediation = ticket || { kind: finding.kind, category: finding.category, rule_ids: finding.policy_ids || finding.rule_ids || [] };
  const snapshots = ticket ? ticket.rule_snapshots : riskRules.filter(r => r.kind === finding.kind && activeRemediation.rule_ids.includes(r.id));
  activeRemediation = { ...activeRemediation, rule_snapshots: snapshots };
  for (const key of ["title", "owner", "status", "plan", "commands", "rollback"]) form.elements[key].value = ticket?.[key] || (key === "status" ? "draft" : "");
  if (!ticket) {
    form.elements.title.value = finding.title;
    form.elements.plan.value = [finding.detail, finding.recommendation, ...riskSteps(finding).map((step, i) => `${i + 1}. ${step}`), "Validation: test approved and denied flows, reimport configuration, rerun risk analysis."].join("\n");
    form.elements.rollback.value = "Back up the live configuration and rule order before implementation. Restore them if validation fails.";
  }
  $("#remediation-rule").innerHTML = snapshots.map(r => `<option value="${escapeHtml(r.id)}">${escapeHtml(r.device_name)} / ${escapeHtml(r.rule_name)} (line ${escapeHtml(r.line_no ?? "unknown")})</option>`).join("");
  $("#remediation-feedback").textContent = "";
  $("#remediation-notes").textContent = "Command generation supports PAN-OS local policy/NAT and FortiGate security policy. Other contexts require a manually reviewed command plan. Each generation targets only the selected rule.";
  $("#remediation-dialog").showModal();
}

$("#risk-expand").addEventListener("click", () => $$("#finding-list .risk-branch, #finding-list .risk-leaf").forEach(el => el.open = true));
$("#risk-collapse").addEventListener("click", () => $$("#finding-list details").forEach(el => el.open = false));
$("#risk-tickets").addEventListener("click", () => $("#remediation-list").scrollIntoView({ behavior: "smooth" }));
$("#remediation-close").addEventListener("click", () => $("#remediation-dialog").close());
$("#remediation-generate").addEventListener("click", async () => {
  const button = $("#remediation-generate"); button.disabled = true;
  try {
    const result = await api("/api/remediation-commands", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({
      kind: activeRemediation.kind, rule_id: $("#remediation-rule").value, operation: $("#remediation-operation").value,
      values: $("#remediation-values").value.split("\n").map(v => v.trim()).filter(Boolean), context: $("#remediation-context").value,
    }) });
    const form = $("#remediation-form");
    form.elements.commands.value = `# Device: ${JSON.stringify(result.device_name)} | Rule ID: ${result.rule_id} | Operation: ${result.operation}\n${result.notes.map(n => `# ${n}`).join("\n")}\n${result.commands}`;
    form.elements.rollback.value = result.rollback;
    $("#remediation-notes").textContent = result.notes.join(" ");
    $("#remediation-feedback").textContent = "Commands generated for the selected rule. Review before saving or executing manually.";
  } catch (error) { $("#remediation-feedback").textContent = error.message; }
  finally { button.disabled = false; }
});
$("#remediation-copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#remediation-form").elements.commands.value); $("#remediation-feedback").textContent = "Commands copied."; }
  catch { $("#remediation-feedback").textContent = "Copy unavailable. Select the command text and copy manually."; }
});
$("#remediation-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("#remediation-save"); button.disabled = true;
  try {
    const data = Object.fromEntries(new FormData(event.currentTarget));
    const payload = { ...data, kind: activeRemediation.kind, category: activeRemediation.category, rule_ids: activeRemediation.rule_ids };
    const saved = await api(activeRemediation.id ? `/api/remediations/${activeRemediation.id}` : "/api/remediations", { method: activeRemediation.id ? "PUT" : "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload) });
    activeRemediation = saved;
    $("#remediation-feedback").textContent = `Saved remediation #${saved.id} (${saved.status}).`;
    await loadRemediations();
  } catch (error) { $("#remediation-feedback").textContent = error.message; }
  finally { button.disabled = false; }
});

// Explicit dropdowns complement free-text policy filters.
const policyChoiceFields = {
  'policy-source-zone': 'zones', 'policy-destination-zone': 'zones',
  'policy-source': 'addresses', 'policy-destination': 'addresses',
  'policy-service': 'services', 'policy-application': 'applications',
  'policy-user': 'users', 'policy-query': 'policies',
};
const allChoiceFields = {...policyChoiceFields, ...natFieldFilters, 'nat-query': p => [p.rule_name]};
for (const [id, field] of Object.entries(allChoiceFields)) {
  const input = document.getElementById(id);
  const wrapper = document.createElement('div'); wrapper.className = 'policy-choice';
  input.before(wrapper); wrapper.append(input);
  const picker = document.createElement('details'); picker.className = 'policy-choice-picker';
  picker.innerHTML = `<summary aria-label="Choose ${escapeHtml(input.placeholder)}">▾</summary><div class="policy-choice-menu"><input type="search" placeholder="Search options" aria-label="Search ${escapeHtml(input.placeholder)} options"><div class="policy-choice-options"></div><span class="muted policy-choice-count"></span></div>`;
  wrapper.append(picker);
  const search = picker.querySelector('input');
  const options = picker.querySelector('.policy-choice-options');
  function renderChoices() {
    const query = search.value.toLowerCase();
    const available = typeof field === 'function' ? natTableRows.flatMap(field) : (inventoryCache?.values?.[field] || []);
    const values = [...new Set(available)].filter(value => String(value).toLowerCase().includes(query));
    options.replaceChildren();
    for (const value of ['', ...values.slice(0, 100)]) {
      const button = document.createElement('button'); button.type = 'button';
      button.textContent = value || 'All / Clear filter';
      button.addEventListener('click', () => {
        input.value = value; picker.open = false;
        input.dispatchEvent(new Event('input', {bubbles:true})); input.focus();
      });
      options.append(button);
    }
    picker.querySelector('.policy-choice-count').textContent = values.length > 100 ? `${values.length} options. Showing 100; search to narrow.` : `${values.length} options`;
  }
  picker.querySelector('summary').addEventListener('click', () => {
    if (picker.open) return;
    document.querySelectorAll('.policy-choice-picker').forEach(other => { if (other !== picker) other.open = false; });
    search.value = ''; renderChoices();
    requestAnimationFrame(() => { if (picker.open) search.focus(); });
  });
  search.addEventListener('input', renderChoices);
  picker.addEventListener('keydown', event => { if (event.key === 'Escape') { picker.open = false; picker.querySelector('summary').focus(); } });
}
document.addEventListener('click', event => {
  document.querySelectorAll('.policy-choice-picker[open]').forEach(picker => { if (!picker.contains(event.target)) picker.open = false; });
});
