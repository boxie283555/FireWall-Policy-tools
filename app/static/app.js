const titles = {
  dashboard: ["Dashboard", "Device policy inventory and risk status."],
  devices: ["Device Access", "Add firewall management IPs and fetch running configuration over SSH."],
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

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error(await response.text());
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
  return items.length > limit ? `${shown}<span class="pill">+${items.length - limit}</span>` : shown;
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
  loadPolicies();
}

async function loadPolicies() {
  const policies = await api(`/api/policies?${policyFilterParams()}`);
  $("#policy-count").textContent = policies.length;
  $("#policy-table").innerHTML = policies
    .map(
      (p, index) => `<tr>
        <td>${index + 1}</td>
        <td>${escapeHtml(p.vendor)}</td>
        <td>${escapeHtml(p.device_name)}</td>
        <td><strong>${escapeHtml(p.rule_name)}</strong><div class="muted">line ${escapeHtml(p.line_no || "")}</div></td>
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

function natFilterParams() {
  return paramsFrom({
    query: $("#nat-query").value,
    nat_type: $("#nat-type").value,
  });
}

function clearNatFilters() {
  $("#nat-query").value = "";
  $("#nat-type").value = "";
  loadNatRules();
}

async function loadNatRules() {
  const [rules, findings] = await Promise.all([api(`/api/nat-rules?${natFilterParams()}`), api(`/api/nat-analysis?${paramsFrom({})}`)]);
  $("#nat-count").textContent = rules.length;
  $("#nat-table").innerHTML = rules
    .map(
      (rule, index) => `<tr>
        <td>${index + 1}</td>
        <td>${escapeHtml(rule.vendor)}</td>
        <td>${escapeHtml(rule.device_name)}</td>
        <td><strong>${escapeHtml(rule.rule_name)}</strong><div class="muted">line ${escapeHtml(rule.line_no || "")}</div></td>
        <td>${escapeHtml(rule.nat_type)}</td>
        <td>${textList(rule.source_zones, 2)}<span class="arrow">→</span>${textList(rule.destination_zones, 2)}</td>
        <td>${textList([...(rule.original_sources || []), ...(rule.original_destinations || [])], 5)}</td>
        <td>${textList([...(rule.translated_sources || []), ...(rule.translated_destinations || [])], 5)}</td>
        <td>${textList([...(rule.original_services || []), ...(rule.translated_services || [])], 4)}</td>
        <td>${rule.enabled ? "enabled" : "disabled"}</td>
      </tr>`
    )
    .join("");
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
  $("#device-result").textContent = JSON.stringify({ saved: device, note: "Password was not saved. Enter it in the form when testing or fetching." }, null, 2);
  await loadDevices();
  return { device, credentials: payload.credentials };
}

async function testDeviceConnection(deviceId, credentials) {
  if (!credentials.password) throw new Error("Please enter the device password.");
  const result = await api(`/api/device-connections/${deviceId}/test`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credentials),
  });
  $("#device-result").textContent = JSON.stringify(result, null, 2);
  await loadDevices();
}

async function fetchDeviceConfig(deviceId, credentials) {
  if (!credentials.password) throw new Error("Please enter the device password.");
  const result = await api(`/api/device-connections/${deviceId}/fetch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credentials),
  });
  $("#device-result").textContent = JSON.stringify(result, null, 2);
  await loadInventory();
  await loadDashboard();
  await loadDevices();
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
    $("#device-result").textContent = "Device profile loaded into the form. Passwords are not saved; enter the password again before testing or fetching.";
    return;
  }
  const credentials = deviceFormPayload().credentials;
  if (action === "test-device") await testDeviceConnection(deviceId, credentials);
  if (action === "fetch-device") await fetchDeviceConfig(deviceId, credentials);
}

async function loadAnalysis() {
  const findings = await api(`/api/analysis?${paramsFrom({})}`);
  const grouped = findings.reduce((acc, finding) => {
    acc[finding.category] = acc[finding.category] || [];
    acc[finding.category].push(finding);
    return acc;
  }, {});
  $("#finding-list").innerHTML = Object.keys(grouped).length
    ? Object.entries(grouped)
        .map(
          ([category, items]) => `<section class="panel">
            <h2>${escapeHtml(category)} <span class="muted">${items.length}</span></h2>
            <div class="cards">${items
              .map(
                (f) => `<article class="card finding">
                  <div class="card-title">
                    <span>${escapeHtml(f.title)}</span>
                    <span class="severity ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
                  </div>
                  <p>${escapeHtml(f.detail)}</p>
                  <p><strong>Recommendation:</strong> ${escapeHtml(f.recommendation)}</p>
                </article>`
              )
              .join("")}</div>
          </section>`
        )
        .join("")
    : '<div class="card">No risk findings.</div>';
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
  $("#path-result").innerHTML = `
    <article class="card">
      <div class="card-title"><span>First Match</span><span>${result.matched_count} candidates</span></div>
      ${
        first
          ? `<p><strong>${escapeHtml(first.rule_name)}</strong> / ${escapeHtml(first.action)} / ${escapeHtml(first.device_name)}</p>
             <p>${textList(first.source_zones)} ${textList(first.source_addresses)} <span class="arrow">→</span> ${textList(first.destination_zones)} ${textList(first.destination_addresses)}</p>`
          : "<p>No matching policy.</p>"
      }
    </article>
    <article class="card">
      <div class="card-title"><span>Matched Rules</span><span>Top 100</span></div>
      <div class="rule-list">${result.matched_policies
        .map((p) => `<div><strong>${escapeHtml(p.rule_name)}</strong><span>${escapeHtml(p.action)} line ${escapeHtml(p.line_no || "")}</span></div>`)
        .join("")}</div>
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
      </article>`
    )
    .join("");
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

$("#refresh-btn").addEventListener("click", () => loadView());
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
$("#device-form").elements["protocol"].addEventListener("change", (event) => {
  const port = $("#device-form").elements["port"];
  if (event.target.value === "telnet" && (!port.value || port.value === "22")) port.value = "23";
  if (event.target.value === "ssh" && (!port.value || port.value === "23")) port.value = "22";
});

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
