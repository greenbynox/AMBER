const state = {
  project: localStorage.getItem("ember_project") || "",
  key: localStorage.getItem("ember_key") || "",
  issues: [],
  selected: null,
  cursor: null,
};

const elProject = document.getElementById("project");
const elKey = document.getElementById("key");
const elSave = document.getElementById("save");
const elStatus = document.getElementById("status");
const elLevel = document.getElementById("level");
const elQ = document.getElementById("q");
const elRefresh = document.getElementById("refresh");
const elList = document.getElementById("list");
const elLoadMore = document.getElementById("loadMore");
const elDetail = document.getElementById("detail");

elProject.value = state.project;
elKey.value = state.key;

elSave.onclick = () => {
  state.project = elProject.value.trim();
  state.key = elKey.value.trim();
  localStorage.setItem("ember_project", state.project);
  localStorage.setItem("ember_key", state.key);
  loadIssues(true);
};

elRefresh.onclick = () => loadIssues(true);
elLoadMore.onclick = () => loadIssues(false);

async function loadIssues(reset) {
  if (!state.project || !state.key) {
    elList.innerHTML = "<div class='muted'>Renseigne project + key</div>";
    return;
  }

  if (reset) {
    state.cursor = null;
    state.issues = [];
  }

  const params = new URLSearchParams();
  if (elStatus.value) params.set("status", elStatus.value);
  if (elLevel.value) params.set("level", elLevel.value);
  if (elQ.value) params.set("q", elQ.value);
  if (state.cursor) params.set("before", state.cursor);

  const res = await fetch(`/issues?${params}`, {
    headers: {
      "x-ember-project": state.project,
      "x-ember-key": state.key,
    },
  });

  if (!res.ok) {
    elList.innerHTML = "<div class='muted'>Erreur chargement</div>";
    return;
  }

  const data = await res.json();
  state.cursor = data.next_before || null;
  state.issues.push(...data.items);
  renderList();
}

function renderList() {
  elList.innerHTML = "";
  if (!state.issues.length) {
    elList.innerHTML = "<div class='muted'>Aucune issue</div>";
    elDetail.innerHTML = "";
    return;
  }

  state.issues.forEach((issue) => {
    const card = document.createElement("div");
    card.className = "item";
    card.innerHTML = `
      <div><strong>${escapeHtml(issue.title)}</strong></div>
      <div class="muted">${issue.level} • ${issue.status} • ${issue.assignee || "-"}</div>
      <div class="muted">last: ${issue.last_seen} • events: ${issue.count_24h} • users: ${issue.affected_users_24h || 0}</div>
      <div class="muted">last user: ${issue.last_user || "-"}</div>
    `;
    card.onclick = () => loadDetail(issue.id);
    elList.appendChild(card);
  });
}

async function loadDetail(id) {
  const res = await fetch(`/issues/${id}`, {
    headers: {
      "x-ember-project": state.project,
      "x-ember-key": state.key,
    },
  });
  if (!res.ok) {
    elDetail.innerHTML = "<div class='muted'>Impossible de charger</div>";
    return;
  }
  const data = await res.json();
  const lastEvent = data.last_event;
  elDetail.innerHTML = `
    <h2>${escapeHtml(data.title)}</h2>
    <div class="muted">${data.level} • ${data.status} • ${data.assignee || "-"}</div>
    <div class="muted">release: ${data.first_release || "-"} → ${data.last_release || "-"}</div>
    <div class="muted">regression: ${data.regressed_at || "-"}</div>
    <div class="muted">last user: ${data.last_user || "-"}</div>
    <div class="muted">github: ${data.github_issue_url ? `<a href='${data.github_issue_url}' target='_blank'>issue</a>` : "-"}</div>
    <div class="muted">first: ${data.first_seen} • last: ${data.last_seen}</div>
    <div class="muted">total: ${data.count_total}</div>
    <div class="actions">
      <button data-status="open">open</button>
      <button data-status="resolved">resolved</button>
      <button data-status="ignored">ignored</button>
      <input id="assigneeInput" placeholder="assign" />
      <button id="assignBtn">assign</button>
    </div>
    ${renderEvent(lastEvent)}
  `;

  document.querySelectorAll(".actions button[data-status]").forEach((btn) => {
    btn.onclick = () => updateStatus(data.id, btn.dataset.status);
  });
  const assigneeInput = document.getElementById("assigneeInput");
  const assignBtn = document.getElementById("assignBtn");
  assignBtn.onclick = () => assignIssue(data.id, assigneeInput.value);
}

async function updateStatus(id, status) {
  await fetch(`/issues/${id}/status`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-ember-project": state.project,
      "x-ember-key": state.key,
    },
    body: JSON.stringify({ status }),
  });
  loadDetail(id);
  loadIssues(true);
}

async function assignIssue(id, assignee) {
  await fetch(`/issues/${id}/assign`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-ember-project": state.project,
      "x-ember-key": state.key,
    },
    body: JSON.stringify({ assignee }),
  });
  loadDetail(id);
  loadIssues(true);
}

function renderEvent(event) {
  if (!event) return "<div class='muted'>Aucun event</div>";
  const stack = event.stacktrace ? `<pre>${escapeHtml(JSON.stringify(event.stacktrace, null, 2))}</pre>` : "";
  const crumbs = event.context && event.context.breadcrumbs ? `<h4>Breadcrumbs</h4><pre>${escapeHtml(JSON.stringify(event.context.breadcrumbs, null, 2))}</pre>` : "";
  return `
    <h3>Dernier event</h3>
    <div>${escapeHtml(event.exception_type)}: ${escapeHtml(event.exception_message)}</div>
    ${stack}
    ${crumbs}
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

loadIssues(true);
