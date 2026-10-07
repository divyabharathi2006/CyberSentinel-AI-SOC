(() => {
  "use strict";

  const page = document.body.dataset.page;
  const tokenKey = "cybersentinel_access_token";
  const userKey = "cybersentinel_user";
  const siteOptions = window.CYBERSENTINEL_OPTIONS;
  const token = () => sessionStorage.getItem(tokenKey);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
  const toast = (message) => {
    const region = document.getElementById("toast-region");
    if (!region) return;
    const item = document.createElement("div");
    item.className = "toast-message";
    item.textContent = message;
    region.append(item);
    window.setTimeout(() => item.remove(), 4500);
  };
  const api = async (path, options = {}) => {
    const headers = new Headers(options.headers || {});
    if (token()) headers.set("Authorization", `Bearer ${token()}`);
    if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
    const response = await fetch(`/api${path}`, {...options, headers});
    if (response.status === 401) {
      sessionStorage.removeItem(tokenKey);
      sessionStorage.removeItem(userKey);
      window.location.assign("/login");
      throw new Error("Session expired. Please sign in again.");
    }
    const contentType = response.headers.get("Content-Type") || "";
    const data = contentType.includes("application/json") ? await response.json() : null;
    if (!response.ok) throw new Error(data?.error?.message || `Request failed (${response.status})`);
    return data;
  };
  const table = (headers, rows) => `<table><thead><tr>${headers.map((item) => `<th>${esc(item.label)}</th>`).join("")}</tr></thead><tbody>${rows.length ? rows.map((row) => `<tr>${headers.map((item) => `<td>${item.render ? item.render(row) : esc(row[item.key])}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${headers.length}" class="text-center muted">No records found.</td></tr>`}</tbody></table>`;
  const optionTags = (values, selected) => values.map((value) => `<option value="${esc(value)}"${value === selected ? " selected" : ""}>${esc(value.replaceAll("_", " "))}</option>`).join("");
  const severity = (value) => `<span class="badge sev-${esc(String(value || "informational").toLowerCase())}">${esc(value || "informational")}</span>`;
  const state = (value) => `<span class="badge status-badge">${esc(value)}</span>`;
  const timestamp = (value) => value ? esc(new Date(value).toLocaleString()) : "—";
  const showError = (container, error) => {
    if (container) container.innerHTML = `<div class="result-card">${esc(error.message || error)}</div>`;
    else toast(error.message || String(error));
  };
  const compactList = (items, labelKey, valueKey) => items.length
    ? items.map((item) => `<div class="compact-item"><span>${esc(item[labelKey])}</span><b>${esc(item[valueKey])}</b></div>`).join("")
    : `<div class="loading">No activity in the selected window.</div>`;

  if (page === "login") {
    if (token()) window.location.replace("/");
    document.getElementById("login-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const error = document.getElementById("login-error");
      error.textContent = "";
      const form = new FormData(event.currentTarget);
      try {
        const result = await api("/auth/login", {method: "POST", body: JSON.stringify({
          username: form.get("username"), password: form.get("password")
        })});
        sessionStorage.setItem(tokenKey, result.access_token);
        sessionStorage.setItem(userKey, JSON.stringify(result.user));
        window.location.assign("/");
      } catch (exception) {
        error.textContent = exception.message;
      }
    });
    return;
  }

  if (!token()) {
    window.location.replace("/login");
    return;
  }
  const user = (() => {
    try { return JSON.parse(sessionStorage.getItem(userKey) || "{}"); } catch { return {}; }
  })();
  const userLabel = document.getElementById("user-label");
  if (userLabel) userLabel.textContent = `${user.username || ""} · ${user.role || ""}`;
  document.querySelectorAll("[data-nav]").forEach((link) => {
    if (link.dataset.nav === page) link.classList.add("active");
    const roles = link.dataset.role?.split(",") || [];
    if (roles.length && !roles.includes(user.role)) link.hidden = true;
  });
  document.getElementById("menu-toggle")?.addEventListener("click", () => document.getElementById("sidebar")?.classList.toggle("open"));
  document.getElementById("logout")?.addEventListener("click", async () => {
    try { await api("/auth/logout", {method: "POST"}); } catch { /* Sign-out is still completed client-side. */ }
    sessionStorage.removeItem(tokenKey);
    sessionStorage.removeItem(userKey);
    window.location.assign("/login");
  });

  const loadDashboard = async () => {
    const errorContainer = document.getElementById("dashboard-error");
    try {
      const [{summary}, alertData] = await Promise.all([api("/dashboard/summary"), api("/alerts?per_page=6")]);
      const set = (id, value) => { const node = document.getElementById(id); if (node) node.textContent = value; };
      set("metric-events", summary.total_events.toLocaleString());
      set("metric-epm", summary.events_per_minute.toLocaleString());
      set("metric-critical", summary.critical_alerts.toLocaleString());
      set("metric-high", summary.high_alerts.toLocaleString());
      set("metric-incidents", summary.open_incidents.toLocaleString());
      set("metric-resolved", summary.resolved_incidents.toLocaleString());
      set("metric-rate", summary.detection_rate);
      set("metric-anomalies", summary.anomaly_count.toLocaleString());
      set("metric-suspicious-ips", summary.active_suspicious_ips.toLocaleString());
      set("ml-state", summary.ml_available ? "Anomaly model active · advisory signal" : "ML unavailable · rules remain active");
      const alertRows = alertData.items.map((alert) => ({
        ...alert,
        title: `<a class="text-link clickable" data-alert-id="${alert.id}">${esc(alert.title)}</a>`
      }));
      const recent = document.getElementById("recent-alerts");
      if (recent) recent.innerHTML = table([
        {label: "Signal", key: "title", render: (row) => row.title},
        {label: "Severity", key: "severity", render: (row) => severity(row.severity)},
        {label: "Risk", key: "risk_score"},
        {label: "Status", key: "status", render: (row) => state(row.status)}
      ], alertRows);
      recent?.querySelectorAll("[data-alert-id]").forEach((link) => link.addEventListener("click", () => window.location.assign("/alerts")));
      const ips = document.getElementById("top-ips");
      if (ips) ips.innerHTML = summary.top_source_ips.length ? summary.top_source_ips.map((item) => `<div class="compact-item"><span>${esc(item.ip)}</span><b>${esc(item.count)}</b></div>`).join("") : `<div class="loading">No source IP events in the selected window.</div>`;
      const destinations = document.getElementById("top-destinations");
      if (destinations) destinations.innerHTML = compactList(summary.top_destination_ips, "ip", "count");
      const users = document.getElementById("top-users");
      if (users) users.innerHTML = compactList(summary.top_users, "username", "count");
      const ports = document.getElementById("top-ports");
      if (ports) ports.innerHTML = compactList(summary.top_destination_ports, "port", "count");
      if (window.Chart) {
        const eventsNode = document.getElementById("events-chart");
        if (eventsNode) {
          window.cyberEventsChart?.destroy();
          window.cyberEventsChart = new Chart(eventsNode, {
            type: "line", data: {labels: summary.events_over_time.map((item) => new Date(item.hour).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"})), datasets: [{label: "Events", data: summary.events_over_time.map((item) => item.count), borderColor: "#5397ff", backgroundColor: "#5397ff22", fill: true, tension: .3, pointRadius: 2}]},
            options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {display: false}}, scales: {x: {ticks: {color: "#8095af"}, grid: {color: "#233247"}}, y: {beginAtZero: true, ticks: {color: "#8095af"}, grid: {color: "#233247"}}}}
          });
        }
        const severityNode = document.getElementById("severity-chart");
        if (severityNode) {
          window.cyberSeverityChart?.destroy();
          window.cyberSeverityChart = new Chart(severityNode, {
            type: "doughnut", data: {labels: ["Critical", "High", "Medium", "Low"], datasets: [{data: [summary.critical_alerts, summary.high_alerts, summary.medium_alerts, summary.low_alerts], backgroundColor: ["#f45c70", "#f49a56", "#f4c05c", "#5397ff"], borderWidth: 0}]},
            options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {position: "bottom", labels: {color: "#b5c5d9", boxWidth: 8, font: {size: 10}}}}}
          });
        }
        const categoryNode = document.getElementById("threat-category-chart");
        if (categoryNode) {
          window.cyberCategoryChart?.destroy();
          window.cyberCategoryChart = new Chart(categoryNode, {
            type: "bar",
            data: {
              labels: summary.threat_categories.map((item) => item.category),
              datasets: [{label: "Alerts", data: summary.threat_categories.map((item) => item.count), backgroundColor: "#48d4c688", borderColor: "#48d4c6", borderWidth: 1}]
            },
            options: {indexAxis: "y", responsive: true, maintainAspectRatio: false, plugins: {legend: {display: false}}, scales: {x: {beginAtZero: true, ticks: {color: "#8095af", precision: 0}, grid: {color: "#233247"}}, y: {ticks: {color: "#b5c5d9"}, grid: {display: false}}}}
          });
        }
        const alertNode = document.getElementById("alerts-chart");
        if (alertNode) {
          window.cyberAlertsChart?.destroy();
          window.cyberAlertsChart = new Chart(alertNode, {
            type: "line",
            data: {labels: summary.alerts_over_time.map((item) => new Date(item.hour).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"})), datasets: [{label: "Alerts", data: summary.alerts_over_time.map((item) => item.count), borderColor: "#f6b950", backgroundColor: "#f6b95022", fill: true, tension: .3, pointRadius: 2}]},
            options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {display: false}}, scales: {x: {ticks: {color: "#8095af"}, grid: {color: "#233247"}}, y: {beginAtZero: true, ticks: {color: "#8095af", precision: 0}, grid: {color: "#233247"}}}}
          });
        }
      }
    } catch (error) { showError(errorContainer, error); }
  };
  if (page === "dashboard") {
    loadDashboard();
    document.getElementById("refresh-dashboard")?.addEventListener("click", loadDashboard);
  }

  let eventPage = 1;
  const loadEvents = async (pageNum = 1) => {
    eventPage = pageNum;
    const container = document.getElementById("events-table");
    const params = new URLSearchParams({page: String(pageNum), per_page: "30"});
    const search = document.getElementById("event-search")?.value.trim();
    const severityValue = document.getElementById("event-severity")?.value;
    if (search) params.set("q", search);
    if (severityValue) params.set("severity", severityValue);
    try {
      const result = await api(`/events?${params}`);
      container.innerHTML = table([
        {label: "Time", key: "timestamp", render: (row) => timestamp(row.timestamp)},
        {label: "Event", key: "event_type"},
        {label: "Severity", key: "severity", render: (row) => severity(row.severity)},
        {label: "Source IP", key: "source_ip"},
        {label: "User", key: "username"},
        {label: "Status", key: "status"},
        {label: "Host", key: "hostname"}
      ], result.items.map((row) => ({...row, id: row.id})));
      container.querySelectorAll("tbody tr").forEach((row, index) => {
        if (result.items[index]) {
          row.classList.add("clickable");
          row.addEventListener("click", () => showEvent(result.items[index].id));
        }
      });
      const pagination = document.getElementById("events-pagination");
      pagination.innerHTML = `<span>${result.pagination.total} events · page ${result.pagination.page} of ${Math.max(1, result.pagination.pages)}</span><span><button class="page-button" data-page="${Math.max(1, pageNum - 1)}">Previous</button><button class="page-button" data-page="${Math.min(result.pagination.pages || 1, pageNum + 1)}">Next</button></span>`;
      pagination.querySelectorAll("[data-page]").forEach((button) => button.addEventListener("click", () => loadEvents(Number(button.dataset.page))));
    } catch (error) { showError(container, error); }
  };
  const showEvent = async (id) => {
    try {
      const {event} = await api(`/events/${id}`);
      let detail = document.getElementById("event-detail");
      if (!detail) {
        detail = document.createElement("section");
        detail.id = "event-detail";
        detail.className = "panel detail-panel";
        document.getElementById("events-table").after(detail);
      }
      detail.innerHTML = `<div class="panel-head"><h2>Event #${event.id} context</h2>${severity(event.severity)}</div><pre class="result-card">${esc(JSON.stringify(event, null, 2))}</pre>`;
      detail.scrollIntoView({behavior: "smooth", block: "start"});
    } catch (error) { toast(error.message); }
  };
  if (page === "events") {
    loadEvents();
    document.getElementById("event-search-button")?.addEventListener("click", () => loadEvents(1));
    document.getElementById("event-search")?.addEventListener("keydown", (event) => { if (event.key === "Enter") loadEvents(1); });
    document.getElementById("toggle-ingest")?.addEventListener("click", () => { document.getElementById("ingest-panel").hidden = !document.getElementById("ingest-panel").hidden; });
    document.getElementById("event-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const result = await api("/events", {method: "POST", body: document.getElementById("event-json").value});
        toast(result.queued
          ? `${result.queued} event(s) queued for real-time processing.`
          : `${result.accepted} event(s) accepted; ${result.alerts.length} alert(s) generated.`);
        loadEvents(1);
      } catch (error) { toast(error.message); }
    });
    document.getElementById("upload-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = new FormData();
      form.append("file", document.getElementById("event-file").files[0]);
      try {
        const result = await api("/events/upload", {method: "POST", body: form});
        toast(result.queued
          ? `${result.queued} event(s) queued; ${result.rejected.length} rejected.`
          : `${result.accepted} event(s) accepted; ${result.rejected.length} rejected.`);
        loadEvents(1);
      } catch (error) { toast(error.message); }
    });
  }

  const showNetworkEvent = async (eventId) => {
    const detail = document.getElementById("network-event-detail");
    try {
      const {event} = await api(`/events/${eventId}`);
      detail.hidden = false;
      detail.innerHTML = `<div class="panel-head"><h2>Network event #${event.id}</h2>${severity(event.severity)}</div><pre class="result-card">${esc(JSON.stringify(event, null, 2))}</pre>`;
      detail.scrollIntoView({behavior: "smooth", block: "start"});
    } catch (error) { showError(detail, error); detail.hidden = false; }
  };
  const loadNetwork = async () => {
    try {
      const {summary} = await api("/network/summary");
      document.getElementById("network-event-count").textContent = summary.network_events.toLocaleString();
      document.getElementById("network-source-count").textContent = summary.active_sources.toLocaleString();
      document.getElementById("network-destination-count").textContent = summary.active_destinations.toLocaleString();
      document.getElementById("network-sources").innerHTML = compactList(summary.top_sources, "ip", "count");
      document.getElementById("network-destinations").innerHTML = compactList(summary.top_destinations, "ip", "count");
      document.getElementById("network-ports").innerHTML = compactList(summary.top_destination_ports, "port", "count");
      document.getElementById("network-suspicious").innerHTML = table([
        {label: "Source IP", key: "ip"},
        {label: "Unresolved alerts", key: "alert_count"},
        {label: "Reputation", key: "reputation", render: () => "Not enriched"}
      ], summary.suspicious_sources);
      const events = document.getElementById("network-events");
      events.innerHTML = table([
        {label: "Time", key: "timestamp", render: (row) => timestamp(row.timestamp)},
        {label: "Type", key: "event_type"},
        {label: "Source IP", key: "source_ip"},
        {label: "Destination IP", key: "destination_ip"},
        {label: "Port", key: "destination_port"},
        {label: "Protocol", key: "protocol"},
        {label: "Severity", key: "severity", render: (row) => severity(row.severity)}
      ], summary.recent_events);
      events.querySelectorAll("tbody tr").forEach((row, index) => {
        if (summary.recent_events[index]) {
          row.classList.add("clickable");
          row.addEventListener("click", () => showNetworkEvent(summary.recent_events[index].id));
        }
      });
    } catch (error) { showError(document.getElementById("network-events"), error); }
  };
  if (page === "network") {
    loadNetwork();
    document.getElementById("refresh-network")?.addEventListener("click", loadNetwork);
  }

  let alertPage = 1;
  const loadAlerts = async (pageNum = 1) => {
    alertPage = pageNum;
    const container = document.getElementById("alerts-table");
    const params = new URLSearchParams({page: String(pageNum), per_page: "40"});
    const statusFilter = document.getElementById("alert-status-filter")?.value;
    if (statusFilter) params.set("status", statusFilter);
    try {
      const result = await api(`/alerts?${params}`);
      const rows = result.items.map((alert) => ({...alert, _title: `<button class="text-link border-0 bg-transparent p-0" data-alert-id="${alert.id}">${esc(alert.title)}</button>`}));
      container.innerHTML = table([
        {label: "Created", key: "created_at", render: (row) => timestamp(row.created_at)},
        {label: "Detection", key: "_title", render: (row) => row._title},
        {label: "Severity", key: "severity", render: (row) => severity(row.severity)},
        {label: "Risk", key: "risk_score"},
        {label: "Source", key: "source_ip"},
        {label: "User", key: "username"},
        {label: "Status", key: "status", render: (row) => state(row.status)}
      ], rows);
      container.querySelectorAll("[data-alert-id]").forEach((button) => button.addEventListener("click", () => showAlert(Number(button.dataset.alertId))));
      document.getElementById("alerts-pagination").innerHTML = `<span>${result.pagination.total} detections · page ${pageNum}/${Math.max(1, result.pagination.pages)}</span><span><button class="page-button" data-alert-page="${Math.max(1, pageNum - 1)}">Previous</button><button class="page-button" data-alert-page="${Math.min(result.pagination.pages || 1, pageNum + 1)}">Next</button></span>`;
      document.querySelectorAll("[data-alert-page]").forEach((button) => button.addEventListener("click", () => loadAlerts(Number(button.dataset.alertPage))));
    } catch (error) { showError(container, error); }
  };
  const showAlert = async (id) => {
    const panel = document.getElementById("alert-detail");
    try {
      const result = await api(`/alerts/${id}`);
      const alert = result.alert;
      panel.hidden = false;
      panel.innerHTML = `<div class="panel-head"><div><span class="eyebrow">${esc(alert.rule_id)} · ${esc(alert.rule_name)}</span><h2 class="mt-2">${esc(alert.title)}</h2><p>${esc(alert.description)}</p></div>${severity(alert.severity)}</div>
      <div class="detail-grid"><div class="detail-item"><small>Risk score</small><b>${alert.risk_score}/100</b></div><div class="detail-item"><small>Confidence</small><b>${Math.round(alert.confidence * 100)}% · indicative only</b></div><div class="detail-item"><small>Created</small><b>${timestamp(alert.created_at)}</b></div><div class="detail-item"><small>Anomaly score</small><b>${alert.anomaly_score == null ? "Unavailable" : esc(alert.anomaly_score)}</b></div><div class="detail-item"><small>Source / user</small><b>${esc(alert.source_ip || "—")} · ${esc(alert.username || "—")}</b></div><div class="detail-item"><small>Assigned analyst</small><b>${esc(alert.assigned_to?.username || "Unassigned")}</b></div></div>
      <div class="detail-section"><h3>Evidence and timeline</h3>${result.events.map((item) => `<div class="evidence-row"><b>${timestamp(item.timestamp)} · ${esc(item.event_type)} · ${esc(item.status || "unspecified")}</b><br>${esc(item.message || "No message")} · ${esc(item.source_ip || "")} · ${esc(item.username || "")}</div>`).join("") || `<p class="muted">No linked event evidence.</p>`}</div>
      <div class="detail-section"><h3>Risk factors</h3><pre class="result-card">${esc(JSON.stringify(alert.score_breakdown, null, 2))}</pre></div>
      <div class="detail-section"><h3>Recommended analyst action</h3><p>${esc(alert.recommended_action)}</p></div>
      <div class="detail-section"><h3>Threat intelligence</h3>${result.threat_intelligence ? `<div class="evidence-row">${esc(result.threat_intelligence.indicator)} · ${esc(result.threat_intelligence.reputation)} · ${Math.round(result.threat_intelligence.confidence * 100)}% · ${esc(result.threat_intelligence.source)}</div>` : `<p class="muted">No configured or cached enrichment is available.</p>`}</div>
      <div class="detail-section"><h3>ATT&CK mapping</h3>${alert.mitre?.length ? alert.mitre.map((item) => `<div class="evidence-row">${esc(item.id)} · ${esc(item.name)} · ${esc(item.tactic)}<br>${esc(item.reason)}</div>`).join("") : `<p class="muted">No mapping assigned; evidence is insufficient.</p>`}</div>
      <div class="detail-section"><h3>Analyst notes</h3>${(alert.analyst_notes || []).map((item) => `<div class="evidence-row">${esc(item.note)} <small>· ${timestamp(item.created_at)}</small></div>`).join("") || `<p class="muted">No notes yet.</p>`}</div>
      <div class="detail-section action-row"><label class="visually-hidden" for="alert-state">Alert status</label><select id="alert-state" class="form-select">${optionTags(siteOptions.alert_statuses, alert.status)}</select><button id="save-alert-state" class="btn btn-outline-light">Update status</button><button id="add-alert-note" class="btn btn-outline-light">Add note</button><button id="create-alert-incident" class="btn btn-primary">Create incident</button></div>`;
      panel.querySelector("#save-alert-state").addEventListener("click", async () => {
        try { await api(`/alerts/${id}`, {method: "PATCH", body: JSON.stringify({status: panel.querySelector("#alert-state").value})}); toast("Alert status updated."); loadAlerts(alertPage); showAlert(id); }
        catch (error) { toast(error.message); }
      });
      panel.querySelector("#add-alert-note").addEventListener("click", async () => {
        const note = window.prompt("Add an investigation note (do not include credentials or secrets):");
        if (!note) return;
        try { await api(`/alerts/${id}`, {method: "PATCH", body: JSON.stringify({note})}); showAlert(id); }
        catch (error) { toast(error.message); }
      });
      panel.querySelector("#create-alert-incident").addEventListener("click", async () => {
        try { const created = await api(`/alerts/${id}/incidents`, {method: "POST"}); toast(`Incident #${created.incident.id} created.`); window.location.assign("/incidents"); }
        catch (error) { toast(error.message); }
      });
      panel.scrollIntoView({behavior: "smooth", block: "start"});
    } catch (error) { showError(panel, error); panel.hidden = false; }
  };
  if (page === "alerts") {
    loadAlerts();
    document.getElementById("refresh-alerts")?.addEventListener("click", () => loadAlerts(alertPage));
    document.getElementById("alert-status-filter")?.addEventListener("change", () => loadAlerts(1));
  }

  const loadIncidents = async () => {
    const container = document.getElementById("incidents-table");
    try {
      const result = await api("/incidents?per_page=100");
      const rows = result.items.map((incident) => ({...incident, _title: `<button class="text-link border-0 bg-transparent p-0" data-incident-id="${incident.id}">${esc(incident.title)}</button>`}));
      container.innerHTML = table([
        {label: "Created", key: "created_at", render: (row) => timestamp(row.created_at)},
        {label: "Incident", key: "_title", render: (row) => row._title},
        {label: "Severity", key: "severity", render: (row) => severity(row.severity)},
        {label: "Status", key: "status", render: (row) => state(row.status)},
        {label: "Assignee", key: "assigned_to", render: (row) => esc(row.assigned_to?.username || "Unassigned")},
        {label: "Alerts", key: "alert_ids", render: (row) => esc(row.alert_ids.length)}
      ], rows);
      container.querySelectorAll("[data-incident-id]").forEach((button) => button.addEventListener("click", () => showIncident(Number(button.dataset.incidentId))));
    } catch (error) { showError(container, error); }
  };
  const showIncident = async (id) => {
    const panel = document.getElementById("incident-detail");
    try {
      const result = await api(`/incidents/${id}`);
      const incident = result.incident;
      panel.hidden = false;
      panel.innerHTML = `<div class="panel-head"><div><h2>${esc(incident.title)}</h2><p>${esc(incident.description)}</p></div>${severity(incident.severity)}</div><div class="detail-grid"><div class="detail-item"><small>Status</small><b>${esc(incident.status)}</b></div><div class="detail-item"><small>Created</small><b>${timestamp(incident.created_at)}</b></div><div class="detail-item"><small>Related alert IDs</small><b>${esc(incident.alert_ids.join(", ") || "None")}</b></div></div><div class="detail-section"><a class="btn btn-outline-light" href="/timeline?incident_id=${encodeURIComponent(id)}">Open full attack timeline</a></div><div class="detail-section"><h3>Timeline</h3>${(incident.timeline || []).map((item) => `<div class="evidence-row">${esc(item.action)} · ${timestamp(item.at)} · ${esc(item.fields?.join(", ") || "")}</div>`).join("")}</div><div class="detail-section"><h3>Notes</h3>${(incident.notes || []).map((item) => `<div class="evidence-row">${esc(item.note)} · ${timestamp(item.created_at)}</div>`).join("") || `<p class="muted">No notes.</p>`}</div><div class="detail-section action-row"><select id="incident-state" class="form-select">${optionTags(siteOptions.incident_statuses, incident.status)}</select><button id="save-incident-state" class="btn btn-outline-light">Update status</button><button id="add-incident-note" class="btn btn-outline-light">Add note</button></div>`;
      panel.querySelector("#save-incident-state").addEventListener("click", async () => {
        try { await api(`/incidents/${id}`, {method: "PATCH", body: JSON.stringify({status: panel.querySelector("#incident-state").value})}); toast("Incident updated."); loadIncidents(); showIncident(id); }
        catch (error) { toast(error.message); }
      });
      panel.querySelector("#add-incident-note").addEventListener("click", async () => {
        const note = window.prompt("Add an investigation note:");
        if (!note) return;
        try { await api(`/incidents/${id}`, {method: "PATCH", body: JSON.stringify({note})}); showIncident(id); }
        catch (error) { toast(error.message); }
      });
      panel.scrollIntoView({behavior: "smooth", block: "start"});
    } catch (error) { showError(panel, error); panel.hidden = false; }
  };
  if (page === "incidents") {
    loadIncidents();
    document.getElementById("new-incident")?.addEventListener("click", () => { document.getElementById("incident-create-panel").hidden = !document.getElementById("incident-create-panel").hidden; });
    document.getElementById("incident-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(event.currentTarget));
      data.alert_ids = data.alert_ids ? data.alert_ids.split(",").map((value) => Number(value.trim())).filter(Number.isInteger) : [];
      try { const result = await api("/incidents", {method: "POST", body: JSON.stringify(data)}); toast(`Incident #${result.incident.id} created.`); event.currentTarget.reset(); loadIncidents(); }
      catch (error) { toast(error.message); }
    });
  }

  const loadIncidentTimeline = async (incidentId) => {
    const container = document.getElementById("timeline-items");
    const summary = document.getElementById("timeline-summary");
    if (!incidentId) {
      container.innerHTML = `<div class="loading">Choose an incident to view its timeline.</div>`;
      summary.textContent = "";
      return;
    }
    try {
      const result = await api(`/timeline/${encodeURIComponent(incidentId)}`);
      summary.textContent = `${result.incident_title} · ${result.event_count} linked events · ${result.alert_count} linked alerts${result.ml_available ? " · ML model available" : " · ML model unavailable"}`;
      container.innerHTML = result.timeline.length ? result.timeline.map((item) => `
        <article class="timeline-item timeline-${esc(item.kind)}">
          <time>${timestamp(item.at)}</time><div><b>${esc(item.title)}</b><p>${esc(item.detail || "")}</p>
          ${item.event_id ? `<button class="btn btn-sm btn-outline-light" data-timeline-event="${esc(item.event_id)}">Inspect event #${esc(item.event_id)}</button>` : ""}
          ${item.alert_id ? `<a class="btn btn-sm btn-outline-light" href="/alerts">Review alert #${esc(item.alert_id)}</a>` : ""}
          </div>
        </article>`).join("") : `<div class="loading">This incident has no linked event, alert, note, or update entries yet.</div>`;
      container.querySelectorAll("[data-timeline-event]").forEach((button) => button.addEventListener("click", async () => {
        const detail = document.getElementById("timeline-event-detail");
        try {
          const {event} = await api(`/events/${encodeURIComponent(button.dataset.timelineEvent)}`);
          detail.hidden = false;
          detail.innerHTML = `<div class="panel-head"><h2>Event #${event.id}</h2>${severity(event.severity)}</div><pre class="result-card">${esc(JSON.stringify(event, null, 2))}</pre>`;
          detail.scrollIntoView({behavior: "smooth", block: "start"});
        } catch (error) { showError(detail, error); detail.hidden = false; }
      }));
    } catch (error) { showError(container, error); }
  };
  if (page === "timeline") {
    const selector = document.getElementById("timeline-incident");
    const requestedId = new URLSearchParams(window.location.search).get("incident_id");
    api("/incidents?per_page=100").then(({items}) => {
      selector.innerHTML = `<option value="">Select an incident</option>${items.map((incident) => `<option value="${esc(incident.id)}">${esc(`#${incident.id} · ${incident.title} · ${incident.status}`)}</option>`).join("")}`;
      if (requestedId && items.some((incident) => String(incident.id) === requestedId)) {
        selector.value = requestedId;
        loadIncidentTimeline(requestedId);
      }
    }).catch((error) => showError(document.getElementById("timeline-items"), error));
    selector.addEventListener("change", () => loadIncidentTimeline(selector.value));
    document.getElementById("refresh-timeline")?.addEventListener("click", () => loadIncidentTimeline(selector.value));
  }

  const loadMlAnalytics = async () => {
    try {
      const {analytics} = await api("/ml/analytics");
      document.getElementById("ml-model-status").textContent = analytics.model_available ? "Active" : "Unavailable";
      document.getElementById("ml-model-version").textContent = analytics.model_version ? `Model ${analytics.model_version}` : "No model version loaded";
      document.getElementById("ml-sample-count").textContent = analytics.sample_count.toLocaleString();
      document.getElementById("ml-anomaly-count").textContent = analytics.anomaly_alert_count.toLocaleString();
      document.getElementById("ml-average-score").textContent = analytics.average_anomaly_score === null ? "—" : `${Math.round(analytics.average_anomaly_score * 100)}%`;
      document.getElementById("ml-threshold").textContent = `Alert threshold ${Math.round(analytics.alert_threshold * 100)}%`;
      document.getElementById("ml-distribution").innerHTML = compactList([
        {label: "Below threshold", count: analytics.score_distribution.below_threshold},
        {label: "At or above threshold", count: analytics.score_distribution.at_or_above_threshold}
      ], "label", "count");
      document.getElementById("ml-alerts-table").innerHTML = table([
        {label: "Time", key: "created_at", render: (row) => timestamp(row.created_at)},
        {label: "Alert", key: "title"},
        {label: "Severity", key: "severity", render: (row) => severity(row.severity)},
        {label: "Score", key: "anomaly_score", render: (row) => `${Math.round(row.anomaly_score * 100)}%`},
        {label: "Classification", key: "classification"},
        {label: "Model", key: "model_version"}
      ], analytics.recent_alerts);
      document.getElementById("ml-interpretation").textContent = analytics.interpretation;
      if (window.Chart) {
        const canvas = document.getElementById("ml-alerts-chart");
        window.cyberMlAlertsChart?.destroy();
        window.cyberMlAlertsChart = new Chart(canvas, {
          type: "bar",
          data: {labels: analytics.alerts_over_time.map((item) => new Date(item.hour).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"})), datasets: [{label: "Scored alerts", data: analytics.alerts_over_time.map((item) => item.count), backgroundColor: "#5397ff88", borderColor: "#5397ff", borderWidth: 1}]},
          options: {responsive: true, maintainAspectRatio: false, plugins: {legend: {display: false}}, scales: {x: {ticks: {color: "#8095af"}, grid: {color: "#233247"}}, y: {beginAtZero: true, ticks: {color: "#8095af", precision: 0}, grid: {color: "#233247"}}}}
        });
      }
    } catch (error) { showError(document.getElementById("ml-alerts-table"), error); }
  };
  if (page === "ml-analytics") {
    loadMlAnalytics();
    document.getElementById("refresh-ml")?.addEventListener("click", loadMlAnalytics);
  }

  if (page === "threat-intel") {
    document.getElementById("threat-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const input = document.getElementById("indicator").value.trim();
      const output = document.getElementById("threat-result");
      output.textContent = "Checking provider and cached intelligence…";
      try {
        const result = await api(`/threat-intel/${encodeURIComponent(input)}`);
        output.innerHTML = result.result ? `<div class="result-card"><b>${esc(result.result.indicator)}</b> · ${esc(result.result.reputation)}<p>Confidence: ${Math.round(result.result.confidence * 100)}% · Source: ${esc(result.result.source)}</p><p>Tags: ${esc((result.result.tags || []).join(", ") || "None reported")}</p></div>` : `<div class="result-card">No provider result is available for this indicator. No reputation has been inferred.</div>`;
      } catch (error) { showError(output, error); }
    });
  }

  if (page === "reports") {
    document.querySelectorAll(".download-report").forEach((button) => button.addEventListener("click", async () => {
      const format = button.closest(".report-card").querySelector(".report-format").value;
      try {
        const headers = new Headers({Authorization: `Bearer ${token()}`});
        const response = await fetch(`/api/reports?type=${encodeURIComponent(button.dataset.kind)}&format=${encodeURIComponent(format)}`, {headers});
        if (!response.ok) {
          const err = await response.json();
          throw new Error(err.error?.message || "Report export failed");
        }
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = response.headers.get("Content-Disposition")?.match(/filename="([^"]+)"/)?.[1] || "cybersentinel-report";
        anchor.click();
        URL.revokeObjectURL(url);
      } catch (error) { toast(error.message); }
    }));
  }

  const loadHealth = async () => {
    const grid = document.getElementById("health-grid");
    try {
      const response = await fetch("/api/health");
      const {components} = await response.json();
      let pipeline = null;
      try {
        const pipelineResponse = await fetch("/api/pipeline/status", {
          headers: {Authorization: `******;`}
        });
        const result = await pipelineResponse.json();
        pipeline = result.status || null;
      } catch (error) {
        showError(grid, error);
        return;
      }
      const cards = Object.entries(components).map(([name, status]) => ({
        name: name.replaceAll("_", " "),
        status,
        healthy: status === "healthy" || status === "disabled" || status === "unconfigured",
      }));
      if (pipeline?.workers) {
        for (const worker of pipeline.workers) {
          cards.push({
            name: `worker ${worker.worker_id} · lag`,
            status: `${worker.state} · ${worker.consumer_lag} queued · ${worker.events_processed} processed · ${worker.messages_dead_lettered} dead-lettered`,
            healthy: worker.state === "healthy" && worker.consumer_lag <= pipeline.max_healthy_lag,
          });
        }
        if (!pipeline.workers.length && pipeline.state !== "disabled") {
          cards.push({name: "event pipeline workers", status: "no active worker heartbeat", healthy: false});
        }
      }
      grid.innerHTML = cards.map(({name, status, healthy}) => `<div class="health-card ${healthy ? "ok" : "warn"}"><b>${esc(name)}</b><span>${esc(status)}</span></div>`).join("");
    } catch (error) { showError(grid, error); }
  };
  if (page === "health") {
    loadHealth();
    document.getElementById("refresh-health")?.addEventListener("click", loadHealth);
  }

  if (page === "settings") {
    const grid = document.getElementById("settings-grid");
    const loadSettings = async () => {
      try {
        const {settings} = await api("/settings");
        const {event_pipeline: pipeline, ...integrations} = settings.integrations;
        const sections = [
          ["Runtime", settings.application],
          ["Detection", settings.detection],
          ["Integrations", integrations],
          ["Event pipeline", {status: pipeline}]
        ];
        grid.innerHTML = sections.map(([title, values]) => `
          <section class="settings-group"><h3>${esc(title)}</h3>
            <dl>${Object.entries(values).map(([key, value]) => `
              <div><dt>${esc(key.replaceAll("_", " "))}</dt><dd>${esc(
                value === null ? "Not available" : typeof value === "object"
                    ? JSON.stringify(value)
                  : typeof value === "boolean" ? value ? "Enabled" : "Disabled" : value
              )}</dd></div>`).join("")}</dl>
          </section>`).join("");
      } catch (error) { showError(grid, error); }
    };
    loadSettings();
    document.getElementById("refresh-settings")?.addEventListener("click", loadSettings);
    document.getElementById("generate-demo")?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      const result = document.getElementById("demo-result");
      if (!window.confirm("Generate and ingest synthetic events into this database? This adds demo records.")) return;
      button.disabled = true;
      result.textContent = "Generating synthetic telemetry…";
      try {
        const response = await api("/demo/generate", {method: "POST", body: JSON.stringify({})});
        result.textContent = response.queued
          ? `Queued ${response.queued} synthetic events. They will appear in Events and Alerts as the worker processes them.`
          : `Generated ${response.accepted} events and ${response.alert_count} alerts. Open Events or Alerts to review the results.`;
        toast(response.queued ? "Synthetic telemetry queued." : "Demo telemetry generated.");
      } catch (error) {
        result.textContent = error.message;
        toast(error.message);
      } finally { button.disabled = false; }
    });
  }

  if (page === "users") {
    const loadUsers = async () => {
      const container = document.getElementById("users-table");
      try {
        const result = await api("/users");
        container.innerHTML = table([
          {label: "Username", key: "username"},
          {label: "Email", key: "email"},
          {label: "Role", key: "role"},
          {label: "Active", key: "is_active", render: (row) => row.is_active ? "Yes" : "No"},
          {label: "ID", key: "id"}
        ], result.items);
      } catch (error) { showError(container, error); }
    };
    loadUsers();
    document.getElementById("toggle-user-form")?.addEventListener("click", () => { document.getElementById("user-create-panel").hidden = !document.getElementById("user-create-panel").hidden; });
    document.getElementById("user-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = Object.fromEntries(new FormData(event.currentTarget));
      try { await api("/users", {method: "POST", body: JSON.stringify(data)}); toast("Account created."); event.currentTarget.reset(); loadUsers(); }
      catch (error) { toast(error.message); }
    });
  }

  if (window.io) {
    const socket = window.io("/soc", {auth: {token: token()}, transports: ["websocket", "polling"]});
    socket.on("new_alert", () => { if (page === "dashboard") loadDashboard(); if (page === "alerts") loadAlerts(alertPage); });
    socket.on("new_event", () => {
      if (page === "dashboard") loadDashboard();
      if (page === "events") loadEvents(eventPage);
      if (page === "network") loadNetwork();
    });
    socket.on("connect_error", () => {});
  }
})();
