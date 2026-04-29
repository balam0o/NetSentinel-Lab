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

let selectedIncidentId = null;

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

async function loadSummary() {
  const response = await fetch("/stats/summary");
  const data = await response.json();

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

async function loadIncidents() {
  incidentTableBody.innerHTML = `
    <tr>
      <td colspan="4" class="empty-state">Loading incidents...</td>
    </tr>
  `;

  const response = await fetch(buildIncidentQuery());
  const incidents = await response.json();

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
    return;
  }

  incidentTableBody.innerHTML = incidents
    .map(
      (incident) => `
        <tr data-incident-id="${incident.id}">
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
      loadIncidentDetail(incidentId);
      loadIncidentTimeline(incidentId);
    });
  });

  const firstIncidentId = incidents[0].id;
  selectedIncidentId = firstIncidentId;
  loadIncidentDetail(firstIncidentId);
  loadIncidentTimeline(firstIncidentId);
}

async function loadIncidentDetail(incidentId) {
  incidentDetailEl.innerHTML = "Loading detail...";

  const response = await fetch(`/incidents/${incidentId}/detail`);
  const data = await response.json();

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

  const response = await fetch(`/incidents/${incidentId}/timeline`);
  const data = await response.json();

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

async function refreshDashboard() {
  await loadSummary();
  await loadIncidents();
}

refreshButton.addEventListener("click", refreshDashboard);
applyFiltersButton.addEventListener("click", loadIncidents);

refreshDashboard();