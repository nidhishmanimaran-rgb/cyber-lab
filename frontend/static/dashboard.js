const pages = [
  ["overview", "Overview", ""],
  ["network", "Network", ""],
  ["apk", "APK Guard", ""],
  ["websec", "WebSec Lab", ""],
  ["hashlab", "HashLab", ""],
  ["alerts", "Alerts", ""],
  ["events", "Events", ""],
  ["settings", "Settings", ""],
];

const state = {
  currentPage: "overview",
  apiToken: localStorage.getItem("ccc_api_token") || "",
  events: [],
  eventFilters: { severity: "", source: "", query: "" },
  alertFilters: { severity: "", status: "" },
  deviceFilters: { query: "", status: "", known: "" },
  lastVerifier: "",
};

const pageTitle = document.querySelector("#page-title");
const content = document.querySelector("#page-content");
const apiState = document.querySelector("#api-state");
const banner = document.querySelector("#alert-banner");
const nav = document.querySelector("#navigation");
let pollingTimer = null;

function apiHeaders() {
  return state.apiToken ? { Authorization: `Bearer ${state.apiToken}` } : {};
}

async function apiGet(path) {
  const response = await fetch(path, { headers: apiHeaders() });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

function isUnauthorizedError(error) {
  return String(error?.message || "").startsWith("401 ");
}

async function apiPatch(path, body = null) {
  const headers = apiHeaders();
  const options = { method: "PATCH", headers };
  if (body) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function apiPost(path, body, extraHeaders = {}) {
  const headers = { ...apiHeaders(), ...extraHeaders };
  if (body && typeof body === "object" && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(body);
  }
  const response = await fetch(path, { method: "POST", headers, body });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(detail.detail || `${response.status} ${response.statusText}`);
  }
  return response.json();
}

function setApiState(status, text) {
  apiState.className = `api-state ${status}`;
  apiState.textContent = text;
}

function showBanner(message) {
  banner.textContent = message;
  banner.classList.remove("hidden");
}

function hideBanner() {
  banner.classList.add("hidden");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatTime(value) {
  if (!value) return "n/a";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function severityBadge(severity) {
  const clean = String(severity || "LOW").toUpperCase();
  return `<span class="severity ${clean.toLowerCase()}">${clean}</span>`;
}

function statusPill(status) {
  return `<span class="status-pill">${escapeHtml(status || "unknown")}</span>`;
}

async function runAction(action) {
  try {
    await action();
  } catch (error) {
    showBanner(error.message || "Action failed.");
  }
}

function renderNavigation() {
  nav.innerHTML = pages
    .map(([id, label, phase]) => {
      const active = id === state.currentPage ? " active" : "";
      const suffix = phase ? `<small>${phase}</small>` : "";
      return `<a class="nav-link${active}" href="#${id}" data-page="${id}"><span>${label}</span>${suffix}</a>`;
    })
    .join("");
}

function metric(label, value, className = "") {
  return `<article class="metric-card"><span>${label}</span><strong class="${className}">${escapeHtml(value)}</strong></article>`;
}

function help(title, why, action) {
  return `
    <div class="panel help-box">
      <h3>${escapeHtml(title)}</h3>
      <p><strong>What is this?</strong> ${escapeHtml(why)}</p>
      <p><strong>What should I do?</strong> ${escapeHtml(action)}</p>
    </div>
  `;
}

async function renderOverview() {
  const status = await apiGet("/api/status");
  let stats = null;
  try {
    stats = await apiGet("/api/stats");
  } catch (error) {
    if (!isUnauthorizedError(error)) {
      throw error;
    }
  }

  const counts = status.counts || {};
  const overview = stats || {
    network_devices: counts.devices || 0,
    apks_scanned: counts.apk_scans || 0,
    web_findings: 0,
    security_events: counts.events || 0,
    active_alerts: status.active_alerts || counts.alerts || 0,
    overall_lab_risk: "LOW",
    lab_risk_score: 0,
    risk_reasons: ["Save a valid API token in Settings to unlock detailed stats."],
    recent_activity: [],
  };
  overview.active_alerts = overview.active_alerts ?? status.active_alerts ?? 0;
  overview.network_devices = overview.network_devices ?? counts.devices ?? 0;
  overview.apks_scanned = overview.apks_scanned ?? counts.apk_scans ?? 0;
  overview.security_events = overview.security_events ?? counts.events ?? 0;

  const hasData =
    overview.network_devices > 0 ||
    overview.apks_scanned > 0 ||
    overview.web_findings > 0 ||
    overview.security_events > 0;

  if (!hasData) {
    content.innerHTML = `
      <section class="panel welcome-box">
        <h1>Welcome to Cyber Command Center</h1>
        <p>Your personal cybersecurity lab helps you understand and monitor your digital environment.</p>
        <p class="empty-state">Protected metrics are locked until you save your API token in Settings.</p>
        <div class="onboarding-grid">
          <div class="onboarding-card">
            <h3>📡 Network Monitor</h3>
            <p>See what devices are connected to your Wi-Fi.</p>
            <a href="#network" class="ghost-button">Get Started</a>
          </div>
          <div class="onboarding-card">
            <h3>🛡️ APK Guard</h3>
            <p>Analyze Android apps for security risks.</p>
            <a href="#apk" class="ghost-button">Get Started</a>
          </div>
          <div class="onboarding-card">
            <h3>🌐 Web Security</h3>
            <p>Check websites for common vulnerabilities.</p>
            <a href="#websec" class="ghost-button">Get Started</a>
          </div>
          <div class="onboarding-card">
            <h3>🔐 Password Lab</h3>
            <p>Learn how to protect passwords properly.</p>
            <a href="#hashlab" class="ghost-button">Get Started</a>
          </div>
        </div>
      </section>
    `;
    return;
  }

  const riskClass = `risk-${String(stats.overall_lab_risk || "low").toLowerCase()}`;
  const activity = stats.recent_activity || [];

  let statusText = "Everything looks normal.";
  if (stats.overall_lab_risk === "MEDIUM") statusText = "A few things need your attention.";
  if (stats.overall_lab_risk === "HIGH" || stats.overall_lab_risk === "CRITICAL") statusText = "Important security findings need review.";

  content.innerHTML = `
    <section class="panel status-hero ${riskClass}">
      <div class="hero-content">
        <span>YOUR SECURITY STATUS</span>
        <h1>${stats.overall_lab_risk || "LOW"}</h1>
        <p>${statusText}</p>
      </div>
      <div class="hero-score">${stats.lab_risk_score ?? 0}/100</div>
    </section>

    <section class="metric-grid">
      ${metric("Network Devices", stats.network_devices)}
      ${metric("APK Scans", stats.apks_scanned)}
      ${metric("Web Findings", stats.web_findings)}
      ${metric("Security Events", stats.security_events)}
      ${metric("Active Alerts", stats.active_alerts)}
    </section>

    <section class="panel">
      <div class="panel-header"><h2>What Needs Your Attention</h2></div>
      ${
        stats.active_alerts > 0
          ? `<p class="activity-item">🔴 ${stats.active_alerts} active alert(s) require review in the Alerts tab.</p>`
          : ""
      }
      ${
        (stats.risk_reasons || []).length > 0
          ? `<ul class="activity-list">${stats.risk_reasons.map(r => `<li class="activity-item">⚠️ ${escapeHtml(r)}</li>`).join("")}</ul>`
          : `<p class="empty-state">No immediate issues detected. Your lab is running normally.</p>`
      }
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2>Recent Activity</h2>
        <span class="chip">Newest first</span>
      </div>
      ${
        activity.length
          ? `<ul class="activity-list">${activity
              .map(
                (item) => `
                  <li class="activity-item">
                    ${severityBadge(item.severity)}
                    <div>
                      <strong>${escapeHtml(item.event_type)}</strong>
                      <div>${escapeHtml(item.message)}</div>
                      <small>${formatTime(item.timestamp)} / ${escapeHtml(item.source)}</small>
                    </div>
                  </li>`,
              )
              .join("")}</ul>`
          : `<p class="empty-state">No activity yet. Try scanning your network or an APK.</p>`
      }
    </section>

    <div class="toolbar center">
      <a class="primary-button" href="#network">Check Network</a>
      <a class="primary-button" href="#apk">Analyze APK</a>
      <a class="primary-button" href="#websec">Run Web Security Check</a>
    </div>
  `;
}

async function renderNetwork() {
  const [devices, scopes] = await Promise.all([apiGet("/api/devices"), apiGet("/api/network/scopes")]);
  const items = (devices.items || []).filter((item) => {
    const query = state.deviceFilters.query.toLowerCase();
    const text = [item.ip_address, item.mac_address, item.hostname, item.vendor].join(" ").toLowerCase();
    return (!query || text.includes(query)) &&
      (!state.deviceFilters.status || item.status === state.deviceFilters.status) &&
      (!state.deviceFilters.known || String(item.known) === state.deviceFilters.known);
  });
  content.innerHTML = `
    ${help("Network Monitor", "Shows devices connected to your local network.", "If you recognize a device, mark it as 'Known'. If you don't, it might be an unauthorized device.")}
    <section class="metric-grid">
      ${metric("Total", devices.summary?.total || 0)}
      ${metric("Online", devices.summary?.online || 0, "risk-low")}
      ${metric("Unknown", devices.summary?.unknown || 0, devices.summary?.unknown > 0 ? "risk-medium" : "")}
    </section>
    <section class="panel">
      <div class="panel-header">
        <h2>Network Devices</h2>
        <div class="toolbar">
          <label class="field">Scope
            <select id="network-scope">${(scopes.items || []).map((scope) => `<option value="${escapeHtml(scope)}">${escapeHtml(scope)}</option>`).join("")}</select>
          </label>
          <button id="refresh-network" class="primary-button" type="button">Refresh Scan</button>
          <label class="field">Search <input id="device-search" type="search" value="${escapeHtml(state.deviceFilters.query)}" placeholder="IP, MAC, hostname" /></label>
          <label class="field">Status <select id="device-status"><option value="">All</option><option value="online" ${state.deviceFilters.status === "online" ? "selected" : ""}>Online</option><option value="offline" ${state.deviceFilters.status === "offline" ? "selected" : ""}>Offline</option></select></label>
          <label class="field">Known <select id="device-known"><option value="">All</option><option value="true" ${state.deviceFilters.known === "true" ? "selected" : ""}>Known</option><option value="false" ${state.deviceFilters.known === "false" ? "selected" : ""}>Unknown</option></select></label>
        </div>
      </div>
      ${items.length ? `<div class="table-wrap"><table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Status</th><th>Known</th><th>First seen</th><th>Last seen</th><th>Vendor</th><th>Services</th></tr></thead><tbody>${items.map((item) => `<tr><td>${escapeHtml(item.ip_address)}</td><td>${escapeHtml(item.mac_address || "n/a")}</td><td>${escapeHtml(item.hostname || "Unknown")}</td><td>${statusPill(item.status)}</td><td><button class="ghost-button" data-device-known="${item.id}" data-known-next="${item.known ? "false" : "true"}" type="button">${item.known ? "Known" : "Unknown"}</button></td><td>${formatTime(item.first_seen)}</td><td>${formatTime(item.last_seen)}</td><td>${escapeHtml(item.vendor || "Unknown")}</td><td>${escapeHtml((item.services || []).map((svc) => `${svc.port}/${svc.name}`).join(", ") || "n/a")}</td></tr>`).join("")}</tbody></table></div>` : `<p class="empty-state">No devices discovered yet. Run a refresh scan on an authorized local scope.</p>`}
    </section>`;
}

async function renderApk() {
  const data = await apiGet("/api/apk");
  const latest = (data.items || [])[0];
  content.innerHTML = `
    ${help("APK Guard", "Analyzes Android app files (APKs) for suspicious permissions and potential security risks.", "Upload an APK file to see what permissions it requests. Only use apps from trusted sources.")}
    <section class="panel">
      <div class="panel-header"><h2>APK Guard</h2><span class="chip">Static analysis only</span></div>
      <div class="toolbar">
        <label class="field">APK file <input id="apk-file" type="file" accept=".apk,application/vnd.android.package-archive" /></label>
        <button id="scan-apk" class="primary-button" type="button">Scan APK</button>
      </div>
    </section>
    ${latest ? renderApkReport(latest) : `<section class="panel"><p class="empty-state">No APK scans yet.</p></section>`}
    <section class="panel"><div class="panel-header"><h2>Scan History</h2></div>${renderApkHistory(data.items || [])}</section>`;
}

function renderApkReport(scan) {
  return `<section class="panel"><div class="panel-header"><h2>Latest APK Report</h2>${severityBadge(scan.risk_level)}</div>
    <div class="settings-grid">
      ${[["Package", scan.package_name || "Unknown"], ["Version", scan.version_name || scan.version_code || "Unknown"], ["SHA-256", scan.sha256], ["Risk score", scan.risk_score]].map(([label, value]) => `<div class="setting-item"><span>${label}</span><strong>${escapeHtml(value)}</strong></div>`).join("")}
    </div>
    <div class="panel-header"><h2>Findings</h2></div>
    ${renderFindings(scan.findings)}
    <div class="panel-header"><h2>Permissions</h2></div>
    <p class="empty-state">${escapeHtml((scan.permissions || []).join(", ") || "No permissions detected.")}</p>
  </section>`;
}

function renderApkHistory(items) {
  if (!items.length) return `<p class="empty-state">No scans stored.</p>`;
  return `<div class="table-wrap"><table><thead><tr><th>Time</th><th>File</th><th>Package</th><th>Risk</th><th>Findings</th></tr></thead><tbody>${items.map((item) => `<tr><td>${formatTime(item.scan_time)}</td><td>${escapeHtml(item.filename)}</td><td>${escapeHtml(item.package_name || "Unknown")}</td><td>${severityBadge(item.risk_level)} ${item.risk_score}</td><td>${(item.findings || []).length}</td></tr>`).join("")}</tbody></table></div>`;
}

async function renderWebsec() {
  const [history, targets] = await Promise.all([apiGet("/api/websec"), apiGet("/api/websec/targets")]);
  const latest = (history.items || [])[0];
  content.innerHTML = `
    ${help("WebSec Lab", "Scans websites for common security weaknesses like missing protection headers.", "Run a scan on the 'Local Lab' to see how security headers protect a website.")}
    <section class="panel"><div class="panel-header"><h2>WebSec Lab</h2><span class="chip">Authorized targets only</span></div>
      <div class="toolbar">
        <label class="field">Target <input id="websec-target" list="websec-targets" value="${escapeHtml((targets.items || [])[0] || "http://127.0.0.1:8000")}" /></label>
        <datalist id="websec-targets">${(targets.items || []).map((target) => `<option value="${escapeHtml(target)}"></option>`).join("")}</datalist>
        <button id="scan-websec" class="primary-button" type="button">Scan Target</button>
      </div>
    </section>
    ${latest ? `<section class="panel"><div class="panel-header"><h2>Latest WebSec Results</h2>${severityBadge(latest.risk_level)}</div>${renderFindings(latest.findings)}</section>` : `<section class="panel"><p class="empty-state">No WebSec scans yet. Start the local lab app, then scan an authorized target.</p></section>`}
    <section class="panel"><div class="panel-header"><h2>History</h2></div>${renderWebHistory(history.items || [])}</section>`;
}

function renderWebHistory(items) {
  if (!items.length) return `<p class="empty-state">No WebSec history stored.</p>`;
  return `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Target</th><th>Risk</th><th>Findings</th></tr></thead><tbody>${items.map((item) => `<tr><td>${formatTime(item.scan_time)}</td><td>${escapeHtml(item.target)}</td><td>${severityBadge(item.risk_level)} ${item.risk_score}</td><td>${(item.findings || []).length}</td></tr>`).join("")}</tbody></table></div>`;
}

function renderFindings(findings) {
  if (!findings || !findings.length) return `<p class="empty-state">No findings detected.</p>`;
  return `<ul class="activity-list">${findings.map((item) => `<li class="activity-item">${severityBadge(item.severity)}<div><strong>${escapeHtml(item.title)}</strong><div>${escapeHtml(item.explanation)}</div><small>${escapeHtml(item.evidence)} / ${escapeHtml(item.remediation)}</small></div></li>`).join("")}</ul>`;
}

async function renderHashlab() {
  content.innerHTML = `
    ${help("Password Lab", "Demonstrates how passwords should be safely protected using 'Hashing'.", "Enter a password to see how it's transformed into a secure 'Verifier'. Never store real passwords in plaintext.")}
    <section class="panel"><div class="panel-header"><h2>HashLab</h2><span class="chip">No plaintext storage</span></div>
      <div class="toolbar">
        <label class="field">Password <input id="hash-password" type="password" autocomplete="new-password" /></label>
        <button id="make-hash" class="primary-button" type="button">Generate Verifier</button>
      </div>
      <div id="hash-result" class="setting-item"><span>Verifier</span><strong>${escapeHtml(state.lastVerifier || "Generate a verifier to begin.")}</strong></div>
    </section>
    <section class="panel"><div class="panel-header"><h2>Verify Password</h2></div>
      <div class="toolbar">
        <label class="field">Password <input id="verify-password" type="password" autocomplete="off" /></label>
        <label class="field">Verifier <input id="verify-verifier" value="${escapeHtml(state.lastVerifier)}" /></label>
        <button id="verify-hash" class="primary-button" type="button">Verify</button>
      </div>
      <p id="verify-result" class="empty-state">Hashing is one-way. Verification recomputes the KDF output and compares it safely.</p>
    </section>`;
}

async function renderEvents() {
  const params = new URLSearchParams();
  if (state.eventFilters.severity) params.set("severity", state.eventFilters.severity);
  if (state.eventFilters.source) params.set("source", state.eventFilters.source);
  const data = await apiGet(`/api/events?${params.toString()}`);
  state.events = data.items || [];
  const query = state.eventFilters.query.trim().toLowerCase();
  const filtered = query
    ? state.events.filter((item) =>
        [item.message, item.event_type, item.source, item.status]
          .join(" ")
          .toLowerCase()
          .includes(query),
      )
    : state.events;

  content.innerHTML = `
    <section class="panel">
      <div class="panel-header">
        <h2>Security Events</h2>
        <div class="toolbar">
          <label class="field">Search
            <input id="event-search" type="search" value="${escapeHtml(state.eventFilters.query)}" placeholder="Message, source, type" />
          </label>
          <label class="field">Severity
            <select id="event-severity">
              <option value="">All</option>
              ${(data.filters?.severities || []).map((item) => `<option value="${item}" ${state.eventFilters.severity === item ? "selected" : ""}>${item}</option>`).join("")}
            </select>
          </label>
          <label class="field">Source
            <select id="event-source">
              <option value="">All</option>
              ${(data.filters?.sources || []).map((item) => `<option value="${escapeHtml(item)}" ${state.eventFilters.source === item ? "selected" : ""}>${escapeHtml(item)}</option>`).join("")}
            </select>
          </label>
        </div>
      </div>
      ${renderEventTable(filtered)}
    </section>
  `;
}

function renderEventTable(events) {
  if (!events.length) return `<p class="empty-state">No security events match the current filters.</p>`;
  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Event type</th>
            <th>Message</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${events
            .map(
              (item) => `
                <tr>
                  <td>${formatTime(item.timestamp)}</td>
                  <td>${severityBadge(item.severity)}</td>
                  <td>${escapeHtml(item.source)}</td>
                  <td>${escapeHtml(item.event_type)}</td>
                  <td>${escapeHtml(item.message)}</td>
                  <td>${statusPill(item.status)}</td>
                </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>`;
}

async function renderAlerts() {
  const params = new URLSearchParams();
  if (state.alertFilters.severity) params.set("severity", state.alertFilters.severity);
  if (state.alertFilters.status) params.set("status", state.alertFilters.status);
  const data = await apiGet(`/api/alerts?${params.toString()}`);
  const alerts = data.items || [];
  content.innerHTML = `
    <section class="panel">
      <div class="panel-header">
        <h2>Alerts</h2>
        <div class="toolbar">
          <label class="field">Severity
            <select id="alert-severity">
              <option value="">All</option>
              ${(data.filters?.severities || []).map((item) => `<option value="${item}" ${state.alertFilters.severity === item ? "selected" : ""}>${item}</option>`).join("")}
            </select>
          </label>
          <label class="field">Status
            <select id="alert-status">
              <option value="">All</option>
              ${(data.filters?.statuses || []).map((item) => `<option value="${item}" ${state.alertFilters.status === item ? "selected" : ""}>${item}</option>`).join("")}
            </select>
          </label>
        </div>
      </div>
      ${renderAlertTable(alerts)}
    </section>
  `;
}

function renderAlertTable(alerts) {
  if (!alerts.length) return `<p class="empty-state">No alerts found.</p>`;
  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Severity</th>
            <th>Title</th>
            <th>Description</th>
            <th>Source</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${alerts
            .map(
              (item) => `
                <tr>
                  <td>${formatTime(item.timestamp)}</td>
                  <td>${severityBadge(item.severity)}</td>
                  <td>${escapeHtml(item.title)}</td>
                  <td>${escapeHtml(item.description)}</td>
                  <td>${escapeHtml(item.source)}</td>
                  <td>${statusPill(item.status)}</td>
                  <td>${
                    item.status === "active"
                      ? `<button class="ghost-button" data-ack-alert="${item.id}" type="button">Acknowledge</button>`
                      : `<span class="chip">Done</span>`
                  }</td>
                </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>`;
}

async function renderSettings() {
  let settings = null;
  if (state.apiToken) {
    try {
      settings = await apiGet("/api/settings");
    } catch (error) {
      if (!isUnauthorizedError(error)) {
        throw error;
      }
    }
  }
  const rows = settings
    ? [
        ["API host", settings.api_host],
        ["API port", settings.api_port],
        ["Authentication", settings.auth_enabled ? "Enabled" : "Disabled"],
        ["Database type", settings.database_type],
        ["Log level", settings.log_level],
        ["Network interval", `${settings.network_monitor_interval_seconds}s`],
        ["High alert threshold", settings.alert_high_threshold],
        ["Critical alert threshold", settings.alert_critical_threshold],
        ["Auth failure threshold", settings.auth_failure_threshold],
        ["Auth failure window", `${settings.auth_failure_window_minutes}m`],
        ["Authorized scan targets", (settings.authorized_scan_targets || []).join(", ") || "None configured"],
        ["CORS origins", (settings.cors_allowed_origins || []).join(", ") || "None configured"],
      ]
    : [
        ["Backend settings", "Locked until a valid API token is saved locally."],
        ["Dashboard access", "Overview remains public; protected modules need auth."],
      ];
  content.innerHTML = `
    <section class="panel">
      <div class="panel-header">
        <h2>Dashboard Settings</h2>
        <span class="chip">Secrets hidden</span>
      </div>
      <div class="settings-grid">
        ${rows.map(([label, value]) => `<div class="setting-item"><span>${label}</span><strong>${escapeHtml(value)}</strong></div>`).join("")}
      </div>
    </section>
    <section class="panel">
      <div class="panel-header"><h2>API Access</h2></div>
      <div class="toolbar">
        <label class="field">API token
          <input id="api-token" type="password" value="${escapeHtml(state.apiToken)}" placeholder="Only needed when auth is enabled" autocomplete="off" />
        </label>
        <button id="save-token" class="primary-button" type="button">Save token locally</button>
        <button id="clear-token" class="ghost-button" type="button">Clear</button>
      </div>
    </section>
  `;
}

function renderAuthGate(pageName) {
  return `
    <section class="panel">
      <div class="panel-header">
        <h2>${escapeHtml(pageName)}</h2>
        <span class="chip">Auth required</span>
      </div>
      <p class="empty-state">
        Save your API token in Settings to unlock this page. The public status page still works without auth.
      </p>
      <div class="toolbar">
        <label class="field">API token
          <input id="api-token" type="password" value="${escapeHtml(state.apiToken)}" placeholder="Paste your token here" autocomplete="off" />
        </label>
        <button id="save-token" class="primary-button" type="button">Save token locally</button>
      </div>
    </section>
  `;
}

function renderModulePlaceholder(label, phase, description) {
  content.innerHTML = `
    <section class="module-grid">
      <article class="module-placeholder">
        <span>${phase}</span>
        <strong>${label}</strong>
        <p class="empty-state">${description}</p>
      </article>
    </section>
  `;
}

async function renderCurrentPage() {
  hideBanner();
  renderNavigation();
  const page = pages.find(([id]) => id === state.currentPage) || pages[0];
  pageTitle.textContent = page[1];
  try {
    if (state.currentPage === "overview") await renderOverview();
    else if (state.currentPage === "events") await renderEvents();
    else if (state.currentPage === "alerts") await renderAlerts();
    else if (state.currentPage === "settings") await renderSettings();
    else if (state.currentPage === "network") await renderNetwork();
    else if (state.currentPage === "apk") await renderApk();
    else if (state.currentPage === "websec") await renderWebsec();
    else if (state.currentPage === "hashlab") await renderHashlab();
    setApiState("ok", "API online");
  } catch (error) {
    if (isUnauthorizedError(error)) {
      setApiState("error", "Auth required");
      content.innerHTML = renderAuthGate(page[1]);
      showBanner("This page is protected. Save a valid API token in Settings to unlock it.");
      return;
    }
    setApiState("error", "API error");
    content.innerHTML = `<section class="panel"><p class="empty-state">The dashboard could not load data from the backend.</p></section>`;
    showBanner(`Backend request failed: ${error.message}. Check that the API is running and, if auth is enabled, save a valid API token in Settings.`);
  }
}

function startPolling() {
  if (pollingTimer) clearInterval(pollingTimer);
  pollingTimer = setInterval(() => {
    if (!["settings", "hashlab"].includes(state.currentPage)) {
      renderCurrentPage();
    }
  }, 15000);
}

window.addEventListener("hashchange", () => {
  state.currentPage = location.hash.replace("#", "") || "overview";
  document.body.classList.remove("nav-open");
  renderCurrentPage();
});

document.addEventListener("click", async (event) => {
  const navToggle = event.target.closest("#nav-toggle");
  if (navToggle) document.body.classList.toggle("nav-open");

  const ackButton = event.target.closest("[data-ack-alert]");
  if (ackButton) {
    ackButton.disabled = true;
    try {
      await apiPatch(`/api/alerts/${ackButton.dataset.ackAlert}/acknowledge`);
      await renderCurrentPage();
    } catch (error) {
      showBanner(`Alert acknowledgement failed: ${error.message}`);
      ackButton.disabled = false;
    }
  }

  const knownButton = event.target.closest("[data-device-known]");
  if (knownButton) {
    knownButton.disabled = true;
    await runAction(async () => {
      await apiPatch(`/api/devices/${knownButton.dataset.deviceKnown}/known`, {
        known: knownButton.dataset.knownNext === "true",
      });
      await renderCurrentPage();
    });
    knownButton.disabled = false;
  }

  if (event.target.closest("#save-token")) {
    const token = document.querySelector("#api-token").value.trim();
    state.apiToken = token;
    localStorage.setItem("ccc_api_token", token);
    await renderCurrentPage();
  }

  if (event.target.closest("#clear-token")) {
    state.apiToken = "";
    localStorage.removeItem("ccc_api_token");
    await renderCurrentPage();
  }

  if (event.target.closest("#refresh-network")) {
    await runAction(async () => {
      const scope = document.querySelector("#network-scope")?.value;
      showBanner("Network scan running. This may take a short moment.");
      await apiPost("/api/network/scan", { cidr: scope });
      await renderCurrentPage();
    });
  }

  if (event.target.closest("#scan-apk")) {
    const file = document.querySelector("#apk-file")?.files?.[0];
    if (!file) {
      showBanner("Choose an APK file first.");
      return;
    }
    await runAction(async () => {
      const content = await file.arrayBuffer();
      await apiPost("/api/apk/scan", content, {
        "Content-Type": "application/vnd.android.package-archive",
        "x-filename": file.name,
      });
      await renderCurrentPage();
    });
  }

  if (event.target.closest("#scan-websec")) {
    await runAction(async () => {
      const target = document.querySelector("#websec-target")?.value?.trim();
      await apiPost("/api/websec/scan", { target });
      await renderCurrentPage();
    });
  }

  if (event.target.closest("#make-hash")) {
    await runAction(async () => {
      const password = document.querySelector("#hash-password")?.value || "";
      const result = await apiPost("/api/crypto/hash", { password });
      state.lastVerifier = result.verifier;
      document.querySelector("#hash-result").innerHTML = `<span>Verifier</span><strong>${escapeHtml(result.verifier)}</strong><p class="empty-state">Strength: ${escapeHtml(result.strength.label)} (${result.strength.score}/100). ${escapeHtml(result.education)}</p>`;
      document.querySelector("#hash-password").value = "";
    });
  }

  if (event.target.closest("#verify-hash")) {
    await runAction(async () => {
      const password = document.querySelector("#verify-password")?.value || "";
      const verifier = document.querySelector("#verify-verifier")?.value || "";
      const result = await apiPost("/api/crypto/verify", { password, verifier });
      document.querySelector("#verify-result").textContent = result.valid ? "Password matches the verifier." : "Password does not match the verifier.";
      document.querySelector("#verify-password").value = "";
    });
  }
});

document.addEventListener("input", (event) => {
  if (event.target.id === "event-search") {
    state.eventFilters.query = event.target.value;
    renderEvents().catch((error) => showBanner(`Event filtering failed: ${error.message}`));
  }
  if (event.target.id === "device-search") {
    state.deviceFilters.query = event.target.value;
    renderNetwork().catch((error) => showBanner(`Device filtering failed: ${error.message}`));
  }
});

document.addEventListener("change", (event) => {
  if (event.target.id === "event-severity") {
    state.eventFilters.severity = event.target.value;
    renderCurrentPage();
  }
  if (event.target.id === "event-source") {
    state.eventFilters.source = event.target.value;
    renderCurrentPage();
  }
  if (event.target.id === "alert-severity") {
    state.alertFilters.severity = event.target.value;
    renderCurrentPage();
  }
  if (event.target.id === "alert-status") {
    state.alertFilters.status = event.target.value;
    renderCurrentPage();
  }
  if (event.target.id === "device-status") {
    state.deviceFilters.status = event.target.value;
    renderCurrentPage();
  }
  if (event.target.id === "device-known") {
    state.deviceFilters.known = event.target.value;
    renderCurrentPage();
  }
});

state.currentPage = location.hash.replace("#", "") || "overview";
renderCurrentPage();
startPolling();
