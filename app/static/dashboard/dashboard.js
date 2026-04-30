const totalEventsEl = document.getElementById("totalEvents");
const totalIncidentsEl = document.getElementById("totalIncidents");
const openIncidentsEl = document.getElementById("openIncidents");
const topSeverityEl = document.getElementById("topSeverity");

const incidentTableBody = document.getElementById("incidentTableBody");
const incidentCountEl = document.getElementById("incidentCount");
const incidentDetailEl = document.getElementById("incidentDetail");
const incidentTimelineEl = document.getElementById("incidentTimeline");

const refreshButton = document.getElementById("refreshButton");
const applyFiltersButton = document.getElementById("applyFiltersButton");

const statusFilterEl = document.getElementById("statusFilter");
const severityFilterEl = document.getElementById("severityFilter");
const titleFilterEl = document.getElementById("titleFilter");

const toggleIncidentStatusButton = document.getElementById("toggleIncidentStatusButton");
const incidentActionMessage = document.getElementById("incidentActionMessage");

const apiKeyInputEl = document.getElementById("apiKeyInput");
const saveApiKeyButton = document.getElementById("saveApiKeyButton");
const clearApiKeyButton = document.getElementById("clearApiKeyButton");
const authStatusMessageEl = document.getElementById("authStatusMessage");

const STORAGE_KEY = "netsentinel_api_key";

let selectedIncidentId = null;
let selectedIncidentStatus = null;

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function getTopSeverityLabel(incidentsBySeverity) {
  const order = ["critical", "high", "medium", "low"];

  for (const severity of order) {
    if ((incidentsBySeverity?.[severity] || 0) > 0) {
      return severity;
    }
  }

  return "-";
}

function getSavedApiKey() {
  return localStorage.getItem(STORAGE_KEY) || "";
}

function getActiveApiKey() {
  return apiKeyInputEl.value.trim() || getSavedApiKey();
}

function setAuthStatus(message = "", type = "") {
  authStatusMessageEl.textContent = message;
  authStatusMessageEl.className = "auth-status";
  if (type) {
    authStatusMessageEl.classList.add(type);
  }
}

function setActionMessage(message = "", type = "") {
  incidentActionMessage.textContent = message;
  incidentActionMessage.className = "action-message";
  if (type) {
    incidentActionMessage.classList.add(type);
  }
}

function updateIncidentActionButton() {
  if (!selectedIncidentId || !selectedIncidentStatus) {
    toggleIncidentStatusButton.disabled = true;
    toggleIncidentStatusButton.textContent = "Select an incident";
    return;
  }

  toggleIncidentStatusButton.disabled = false;
  toggleIncidentStatusButton.textContent =
    selectedIncidentStatus === "open" ? "Close incident" : "Reopen incident";
}

function buildHeaders(extraHeaders = {}) {
  const headers = { ...extraHeaders };
  const apiKey = getActiveApiKey();

  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }

  return headers;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: buildHeaders(options.headers || {}),
  });

  if (response.status === 401) {
    throw new Error("unauthorized");
  }

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || "Request failed");
  }

  return response.json();
}

async function loadSummary() {
  const data = await fetchJson("/stats/summary");

  totalEventsEl.textContent = data.total_events ?? 0;
  totalIncidentsEl.textContent = data.total_incidents ?? 0;
  openIncidentsEl.textContent = data.open_incidents ?? 0;
  topSeverityEl.textContent = getTopSeverityLabel(data.incidents_by_severity);
}

function buildIncidentQuery() {
  const params = new URLSearchParams();
  params.set("limit", "50");
  params.set("sort_by", "last_seen");
  params.set("sort_order", "desc");

  if (statusFilterEl.value) {
    params.set("status", statusFilterEl.value);
  }

  if (severityFilterEl.value) {
    params.set("severity", severityFilterEl.value);
  }

  if (titleFilterEl.value.trim()) {
    params.set("title_contains", titleFilterEl.value.trim());
  }

  return `/incidents?${params.toString()}`;
}

async function loadIncidents(preferredIncidentId = selectedIncidentId) {
  incidentTableBody.innerHTML = `
    <tr>
      <td colspan="4" class="empty-state">Loading incidents...</td>
    </tr>
  `;

  const incidents = await fetchJson(buildIncidentQuery());

  incidentCountEl.textContent = `${incidents.length} result(s)`;

  if (!incidents.length) {
    incidentTableBody.innerHTML = `
      <tr>
        <td colspan="4" class="empty-state">No incidents found.</td>
      </tr>
    `;
    incidentDetailEl.textContent = "Select an incident to inspect details.";
    incidentTimelineEl.textContent = "Timeline will appear here after selecting an incident.";
    selectedIncidentId = null;
    selectedIncidentStatus = null;
    updateIncidentActionButton();
    return;
  }

  incidentTableBody.innerHTML = incidents
    .map(
      (incident) => `
        <tr
          data-incident-id="${incident.id}"
          class="${String(incident.id) === String(preferredIncidentId) ? "selected-row" : ""}"
        >
          <td>${escapeHtml(incident.title)}</td>
          <td><span class="badge">${escapeHtml(incident.severity)}</span></td>
          <td>${escapeHtml(incident.status)}</td>
          <td>${escapeHtml(formatDate(incident.last_seen))}</td>
        </tr>
      `
    )
    .join("");

  incidentTableBody.querySelectorAll("tr[data-incident-id]").forEach((row) => {
    row.addEventListener("click", () => {
      const incidentId = row.getAttribute("data-incident-id");
      selectedIncidentId = incidentId;
      setActionMessage("");
      loadIncidents(incidentId);
      loadIncidentDetail(incidentId);
      loadIncidentTimeline(incidentId);
    });
  });

  const selectedStillExists = incidents.some(
    (incident) => String(incident.id) === String(preferredIncidentId)
  );

  const targetIncidentId = selectedStillExists ? preferredIncidentId : incidents[0].id;
  selectedIncidentId = targetIncidentId;

  await loadIncidentDetail(targetIncidentId);
  await loadIncidentTimeline(targetIncidentId);
}

async function loadIncidentDetail(incidentId) {
  incidentDetailEl.innerHTML = "Loading detail...";

  const data = await fetchJson(`/incidents/${incidentId}/detail`);

  selectedIncidentStatus = data.incident.status;
  updateIncidentActionButton();

  incidentDetailEl.innerHTML = `
    <div class="detail-block">
      <div class="meta-list">
        <div><strong>Title:</strong> ${escapeHtml(data.incident.title)}</div>
        <div><strong>Severity:</strong> ${escapeHtml(data.incident.severity)}</div>
        <div><strong>Status:</strong> ${escapeHtml(data.incident.status)}</div>
        <div><strong>First seen:</strong> ${escapeHtml(formatDate(data.incident.first_seen))}</div>
        <div><strong>Last seen:</strong> ${escapeHtml(formatDate(data.incident.last_seen))}</div>
        <div><strong>Linked events:</strong> ${escapeHtml(data.event_count)}</div>
      </div>
    </div>
    <div class="detail-block">
      <strong>Description</strong>
      <div>${escapeHtml(data.incident.description || "-")}</div>
    </div>
  `;
}

async function loadIncidentTimeline(incidentId) {
  incidentTimelineEl.innerHTML = "Loading timeline...";

  const data = await fetchJson(`/incidents/${incidentId}/timeline`);

  if (!data.timeline.length) {
    incidentTimelineEl.innerHTML = `<div class="detail-block">No timeline events found.</div>`;
    return;
  }

  incidentTimelineEl.innerHTML = data.timeline
    .map(
      (item) => `
        <div class="timeline-item">
          <div><strong>${escapeHtml(item.event_type)}</strong></div>
          <div>${escapeHtml(item.summary)}</div>
          <div>${escapeHtml(formatDate(item.created_at))}</div>
          <div>Source: ${escapeHtml(item.source)} | Severity: ${escapeHtml(item.severity)}</div>
        </div>
      `
    )
    .join("");
}

async function toggleSelectedIncidentStatus() {
  if (!selectedIncidentId || !selectedIncidentStatus) {
    return;
  }

  const nextStatus = selectedIncidentStatus === "open" ? "closed" : "open";

  toggleIncidentStatusButton.disabled = true;
  setActionMessage("Updating incident status...");

  try {
    const updatedIncident = await fetchJson(`/incidents/${selectedIncidentId}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ status: nextStatus }),
    });

    selectedIncidentStatus = updatedIncident.status;
    updateIncidentActionButton();

    setActionMessage(`Incident updated to '${updatedIncident.status}'.`, "success");

    await loadSummary();
    await loadIncidents(selectedIncidentId);
  } catch (error) {
    if (error.message === "unauthorized") {
      setActionMessage("Unauthorized. Save a valid API key.", "error");
    } else {
      setActionMessage("Could not update incident status.", "error");
    }
    updateIncidentActionButton();
  }
}

async function refreshDashboard() {
  setActionMessage("");

  try {
    await loadSummary();
    await loadIncidents();
    setAuthStatus(getActiveApiKey() ? "API key loaded." : "Auth disabled or no key saved.");
  } catch (error) {
    totalEventsEl.textContent = "-";
    totalIncidentsEl.textContent = "-";
    openIncidentsEl.textContent = "-";
    topSeverityEl.textContent = "-";
    incidentTableBody.innerHTML = `
      <tr>
        <td colspan="4" class="empty-state">Could not load incidents.</td>
      </tr>
    `;
    incidentDetailEl.textContent = "Select an incident to inspect details.";
    incidentTimelineEl.textContent = "Timeline will appear here after selecting an incident.";
    selectedIncidentId = null;
    selectedIncidentStatus = null;
    updateIncidentActionButton();

    if (error.message === "unauthorized") {
      setAuthStatus("Unauthorized. Enter and save a valid API key.", "error");
    } else {
      setAuthStatus("Could not load dashboard data.", "error");
    }
  }
}

function saveApiKey() {
  const value = apiKeyInputEl.value.trim();

  if (!value) {
    setAuthStatus("Enter an API key before saving.", "error");
    return;
  }

  localStorage.setItem(STORAGE_KEY, value);
  setAuthStatus("API key saved.", "success");
  refreshDashboard();
}

function clearApiKey() {
  localStorage.removeItem(STORAGE_KEY);
  apiKeyInputEl.value = "";
  setAuthStatus("API key cleared.");
  refreshDashboard();
}

apiKeyInputEl.value = getSavedApiKey();

refreshButton.addEventListener("click", refreshDashboard);
applyFiltersButton.addEventListener("click", async () => {
  setActionMessage("");
  await loadIncidents();
});
toggleIncidentStatusButton.addEventListener("click", toggleSelectedIncidentStatus);
saveApiKeyButton.addEventListener("click", saveApiKey);
clearApiKeyButton.addEventListener("click", clearApiKey);

refreshDashboard();