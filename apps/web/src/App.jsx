import React, { useEffect, useMemo, useState } from "react";
import { apiFetch } from "./api.js";

const DEFAULT_BASE = "http://localhost:3002";

const STORAGE_KEY = "ember.ui.settings";

const emptyIssue = {
  id: "",
  title: "",
  level: "",
  status: "",
  assignee: "",
  first_release: "",
  last_release: "",
  regressed_at: "",
  first_seen: "",
  last_seen: "",
  count_total: 0
};

export default function App() {
  const [baseUrl, setBaseUrl] = useState(DEFAULT_BASE);
  const [authMode, setAuthMode] = useState("token");
  const [token, setToken] = useState("");
  const [projectId, setProjectId] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState("");
  const [adminKey, setAdminKey] = useState("");
  const [orgs, setOrgs] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState("");
  const [integrations, setIntegrations] = useState([]);
  const [orgIntegrations, setOrgIntegrations] = useState([]);
  const [selectedIntegrationKey, setSelectedIntegrationKey] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [oauthUrl, setOauthUrl] = useState("");
  const [ingestUrl, setIngestUrl] = useState("http://localhost:3001/ingest");
  const [ingestProjectId, setIngestProjectId] = useState("");
  const [ingestApiKey, setIngestApiKey] = useState("");
  const [onboardingDone, setOnboardingDone] = useState(false);

  const [costDaily, setCostDaily] = useState([]);
  const [costUnits, setCostUnits] = useState([]);
  const [groupingStats, setGroupingStats] = useState(null);
  const [rcaStats, setRcaStats] = useState(null);
  const [rcaPolicy, setRcaPolicy] = useState(null);
  const [rcaPolicyInput, setRcaPolicyInput] = useState("0.5");
  const [ingestDrops, setIngestDrops] = useState([]);

  const [issues, setIssues] = useState([]);
  const [nextBefore, setNextBefore] = useState(null);
  const [filters, setFilters] = useState({ status: "", level: "", q: "" });
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [issueEvents, setIssueEvents] = useState([]);
  const [issueInsights, setIssueInsights] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        setBaseUrl(parsed.baseUrl || DEFAULT_BASE);
        setAuthMode(parsed.authMode || "token");
        setToken(parsed.token || "");
        setProjectId(parsed.projectId || "");
        setApiKey(parsed.apiKey || "");
        setSelectedProject(parsed.selectedProject || "");
        setAdminKey(parsed.adminKey || "");
        setSelectedOrg(parsed.selectedOrg || "");
        setIngestUrl(parsed.ingestUrl || "http://localhost:3001/ingest");
        setIngestProjectId(parsed.ingestProjectId || "");
        setIngestApiKey(parsed.ingestApiKey || "");
        setOnboardingDone(parsed.onboardingDone || false);
      } catch {
        // ignore
      }
    }
  }, []);

  useEffect(() => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ baseUrl, authMode, token, projectId, apiKey, selectedProject, adminKey, selectedOrg })
    );
  }, [baseUrl, authMode, token, projectId, apiKey, selectedProject, adminKey, selectedOrg, ingestUrl, ingestProjectId, ingestApiKey, onboardingDone]);

  useEffect(() => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        baseUrl,
        authMode,
        token,
        projectId,
        apiKey,
        selectedProject,
        adminKey,
        selectedOrg,
        ingestUrl,
        ingestProjectId,
        ingestApiKey,
        onboardingDone
      })
    );
  }, [baseUrl, authMode, token, projectId, apiKey, selectedProject, adminKey, selectedOrg, ingestUrl, ingestProjectId, ingestApiKey, onboardingDone]);

  const authHeaders = useMemo(() => {
    const headers = {};
    if (authMode === "token") {
      if (token) headers["x-ember-token"] = token;
    } else {
      if (apiKey) headers["x-ember-key"] = apiKey;
    }
    return headers;
  }, [authMode, token, apiKey]);

  const projectHeader = useMemo(() => {
    const pid = authMode === "token" ? selectedProject : projectId;
    return pid ? { "x-ember-project": pid } : {};
  }, [authMode, projectId, selectedProject]);

  const fullHeaders = useMemo(() => ({ ...authHeaders, ...projectHeader }), [authHeaders, projectHeader]);

  const adminHeaders = useMemo(() => {
    return adminKey ? { "x-ember-admin": adminKey } : {};
  }, [adminKey]);

  const currentProjectId = useMemo(() => {
    return authMode === "token" ? selectedProject : projectId;
  }, [authMode, selectedProject, projectId]);

  const quickstartProjectId = ingestProjectId || currentProjectId || "";
  const quickstartApiKey = ingestApiKey || apiKey || "";

  const loadProjects = async () => {
    setError("");
    setLoading(true);
    try {
      if (authMode === "token") {
        const data = await apiFetch({ baseUrl, path: "/me/projects", headers: authHeaders });
        setProjects(data);
        if (!selectedProject && data.length > 0) {
          setSelectedProject(data[0].id);
        }
      } else {
        setProjects([]);
      }
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadOrgs = async () => {
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({ baseUrl, path: "/orgs", headers: adminHeaders });
      setOrgs(data);
      if (!selectedOrg && data.length > 0) {
        setSelectedOrg(data[0].id);
      }
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadIntegrations = async () => {
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({ baseUrl, path: "/integrations", headers: adminHeaders });
      setIntegrations(data);
      if (!selectedIntegrationKey && data.length > 0) {
        setSelectedIntegrationKey(data[0].key);
      }
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadOrgIntegrations = async () => {
    if (!selectedOrg) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({ baseUrl, path: `/orgs/${selectedOrg}/integrations`, headers: adminHeaders });
      setOrgIntegrations(data);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const upsertIntegration = async () => {
    if (!selectedOrg || !selectedIntegrationKey) return;
    setError("");
    setLoading(true);
    try {
      await apiFetch({
        baseUrl,
        path: `/orgs/${selectedOrg}/integrations`,
        method: "POST",
        headers: adminHeaders,
        body: {
          integration_key: selectedIntegrationKey,
          config: webhookUrl ? { webhook_url: webhookUrl } : null,
          enabled: true
        }
      });
      await loadOrgIntegrations();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const testIntegration = async () => {
    if (!selectedOrg || !selectedIntegrationKey) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/orgs/${selectedOrg}/integrations/${selectedIntegrationKey}/test`,
        method: "POST",
        headers: adminHeaders
      });
      if (!data.ok) {
        setError(`Test failed (status ${data.status})`);
      }
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const startOAuth = async () => {
    if (!selectedOrg || !selectedIntegrationKey) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/orgs/${selectedOrg}/integrations/${selectedIntegrationKey}/oauth/start`,
        headers: adminHeaders
      });
      setOauthUrl(data.authorize_url || "");
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadCostDaily = async () => {
    if (!currentProjectId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/cost/daily?limit=30`,
        headers: adminHeaders
      });
      setCostDaily(data || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadCostUnits = async () => {
    if (!currentProjectId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/cost?limit=50`,
        headers: adminHeaders
      });
      setCostUnits(data || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadGroupingStats = async () => {
    if (!currentProjectId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/grouping/decisions/stats?window_minutes=1440`,
        headers: adminHeaders
      });
      setGroupingStats(data || null);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadRcaStats = async () => {
    if (!currentProjectId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/rca/stats?window_minutes=1440`,
        headers: adminHeaders
      });
      setRcaStats(data || null);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadRcaPolicy = async () => {
    if (!currentProjectId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/rca-policy`,
        headers: adminHeaders
      });
      setRcaPolicy(data || null);
      if (data?.min_confidence !== undefined) {
        setRcaPolicyInput(String(data.min_confidence));
      }
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadIngestDrops = async () => {
    if (!currentProjectId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/ingest/drops?limit=30`,
        headers: adminHeaders
      });
      setIngestDrops(data || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const updateRcaPolicy = async () => {
    if (!currentProjectId) return;
    setError("");
    setLoading(true);
    try {
      const min_confidence = Number(rcaPolicyInput);
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/rca-policy`,
        method: "POST",
        headers: adminHeaders,
        body: { min_confidence }
      });
      setRcaPolicy(data || null);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadIssues = async ({ before } = {}) => {
    if (!projectHeader["x-ember-project"]) {
      setError("Projet manquant");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filters.status) params.set("status", filters.status);
      if (filters.level) params.set("level", filters.level);
      if (filters.q) params.set("q", filters.q);
      if (before) params.set("before", before);
      const data = await apiFetch({
        baseUrl,
        path: `/issues?${params.toString()}`,
        headers: fullHeaders
      });
      setIssues(before ? [...issues, ...data.items] : data.items);
      setNextBefore(data.next_before || null);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadIssueDetail = async (issueId) => {
    setError("");
    setLoading(true);
    try {
      const detail = await apiFetch({ baseUrl, path: `/issues/${issueId}`, headers: fullHeaders });
      const events = await apiFetch({ baseUrl, path: `/issues/${issueId}/events`, headers: fullHeaders });
      let insights = null;
      try {
        insights = await apiFetch({ baseUrl, path: `/issues/${issueId}/insights`, headers: fullHeaders });
      } catch {
        insights = null;
      }
      setSelectedIssue(detail);
      setIssueEvents(events.items || []);
      setIssueInsights(insights);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const updateStatus = async (issueId, status) => {
    setError("");
    try {
      const detail = await apiFetch({
        baseUrl,
        path: `/issues/${issueId}/status`,
        method: "POST",
        headers: fullHeaders,
        body: { status }
      });
      setSelectedIssue(detail);
      await loadIssues();
    } catch (err) {
      setError(err.message || String(err));
    }
  };

  const updateAssignee = async (issueId, assignee) => {
    setError("");
    try {
      const detail = await apiFetch({
        baseUrl,
        path: `/issues/${issueId}/assign`,
        method: "POST",
        headers: fullHeaders,
        body: { assignee }
      });
      setSelectedIssue(detail);
      await loadIssues();
    } catch (err) {
      setError(err.message || String(err));
    }
  };

  const copyToClipboard = async (value) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // ignore
    }
  };

  const sendTestEvent = async () => {
    if (!ingestUrl || !quickstartProjectId || !quickstartApiKey) {
      setError("Ingest URL, Project ID et Project key requis");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const eventPayload = {
        project_id: quickstartProjectId,
        event_id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
        timestamp: new Date().toISOString(),
        level: "error",
        message: "Test event depuis EMBER",
        exception: {
          kind: "TestError",
          message: "Erreur de test pour vérifier la pipeline",
          stacktrace: []
        },
        context: { runtime: { name: "ember-ui" } },
        sdk: { name: "ember-ui", version: "0.1" },
        schema_version: "v1"
      };

      const res = await fetch(ingestUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-ember-key": quickstartApiKey
        },
        body: JSON.stringify(eventPayload)
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `Ingest failed (${res.status})`);
      }
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (authMode === "token" && token) {
      loadProjects();
    }
  }, [authMode, token]);

  const currentIssue = selectedIssue || emptyIssue;
  const latestEvent = issueEvents[0];
  const culprit = latestEvent?.context?.culprit;
  const rcaSummary = issueInsights?.summary;
  const rcaChain = issueInsights?.causal_chain;
  const rcaRegression = issueInsights?.regression_map;
  const rcaConfidence = issueInsights?.confidence;
  const rcaPublished = issueInsights?.published !== false;

  const quickstartCurl = `curl -X POST ${ingestUrl} \\\n+  -H "Content-Type: application/json" \\\n+  -H "x-ember-key: ${quickstartApiKey || "<PROJECT_KEY>"}" \\\n+  -d '{"project_id":"${quickstartProjectId || "<PROJECT_ID>"}","event_id":"${Date.now()}","timestamp":"${new Date().toISOString()}","level":"error","message":"Test error","exception":{"kind":"TestError","message":"Example","stacktrace":[]},"schema_version":"v1"}'`;

  const quickstartJs = `fetch("${ingestUrl}", {\n  method: "POST",\n  headers: {\n    "Content-Type": "application/json",\n    "x-ember-key": "${quickstartApiKey || "<PROJECT_KEY>"}"\n  },\n  body: JSON.stringify({\n    project_id: "${quickstartProjectId || "<PROJECT_ID>"}",\n    event_id: crypto.randomUUID(),\n    timestamp: new Date().toISOString(),\n    level: "error",\n    message: "Test error",\n    exception: { kind: "TestError", message: "Example", stacktrace: [] },\n    schema_version: "v1"\n  })\n});`;

  const steps = [
    {
      key: "connect",
      label: "Connecter l'API",
      done: Boolean(baseUrl) && ((authMode === "token" && token) || (authMode === "project" && projectId && apiKey))
    },
    {
      key: "project",
      label: "Choisir un projet",
      done: Boolean(currentProjectId)
    },
    {
      key: "ingest",
      label: "Configurer l’ingest",
      done: Boolean(ingestUrl) && Boolean(quickstartProjectId) && Boolean(quickstartApiKey)
    },
    {
      key: "event",
      label: "Envoyer un event test",
      done: onboardingDone
    }
  ];

  return (
    <div className="app">
      <header className="app-header">
        <div>
          <h1>EMBER</h1>
          <p>Observabilité d’erreurs moderne, rapide et claire.</p>
        </div>
        <div className="pill">v0.1</div>
      </header>

      <section className="card hero">
        <div>
          <h2>Onboarding express</h2>
          <p className="muted">4 étapes, 2 minutes, et vos erreurs apparaissent.</p>
        </div>
        <div className="steps">
          {steps.map((step) => (
            <div key={step.key} className={`step ${step.done ? "done" : ""}`}>
              <span>{step.done ? "✓" : "•"}</span>
              <p>{step.label}</p>
            </div>
          ))}
        </div>
        <div className="actions">
          <button
            onClick={() => {
              if (currentProjectId && !ingestProjectId) {
                setIngestProjectId(currentProjectId);
              }
            }}
            disabled={!currentProjectId}
          >
            Utiliser le projet courant
          </button>
          <button
            onClick={() => setOnboardingDone(true)}
            disabled={onboardingDone}
          >
            Marquer onboarding OK
          </button>
        </div>
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Quickstart plug‑and‑play</h2>
          <button onClick={sendTestEvent} disabled={loading || !quickstartProjectId || !quickstartApiKey || !ingestUrl}>
            Envoyer un event test
          </button>
        </div>
        <div className="grid">
          <label>
            Ingest URL
            <input value={ingestUrl} onChange={(e) => setIngestUrl(e.target.value)} />
          </label>
          <label>
            Project ID (ingest)
            <input value={ingestProjectId} onChange={(e) => setIngestProjectId(e.target.value)} />
          </label>
          <label>
            Project key (ingest)
            <input value={ingestApiKey} onChange={(e) => setIngestApiKey(e.target.value)} />
          </label>
        </div>
        <div className="snippet">
          <div className="snippet-header">
            <span>cURL</span>
            <button onClick={() => copyToClipboard(quickstartCurl)}>Copier</button>
          </div>
          <pre>{quickstartCurl}</pre>
        </div>
        <div className="snippet">
          <div className="snippet-header">
            <span>JavaScript</span>
            <button onClick={() => copyToClipboard(quickstartJs)}>Copier</button>
          </div>
          <pre>{quickstartJs}</pre>
        </div>
      </section>

      <section className="card">
        <h2>Connexion</h2>
        <div className="grid">
          <label>
            API URL
            <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
          </label>
          <label>
            Mode
            <select value={authMode} onChange={(e) => setAuthMode(e.target.value)}>
              <option value="token">Team token</option>
              <option value="project">Project key</option>
            </select>
          </label>
          {authMode === "token" ? (
            <label>
              Team token
              <input value={token} onChange={(e) => setToken(e.target.value)} />
            </label>
          ) : (
            <>
              <label>
                Project ID
                <input value={projectId} onChange={(e) => setProjectId(e.target.value)} />
              </label>
              <label>
                Project key
                <input value={apiKey} onChange={(e) => setApiKey(e.target.value)} />
              </label>
            </>
          )}
        </div>
        {authMode === "token" && (
          <div className="actions">
            <button onClick={loadProjects} disabled={loading || !token}>
              Charger les projets
            </button>
            {projects.length > 0 && (
              <label>
                Projet
                <select value={selectedProject} onChange={(e) => setSelectedProject(e.target.value)}>
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.name} ({project.id})
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Marketplace</h2>
          <button onClick={() => { loadOrgs(); loadIntegrations(); }} disabled={loading || !adminKey}>
            Charger orgs + intégrations
          </button>
        </div>
        <div className="grid">
          <label>
            Admin key
            <input value={adminKey} onChange={(e) => setAdminKey(e.target.value)} />
          </label>
          <label>
            Org
            <select value={selectedOrg} onChange={(e) => setSelectedOrg(e.target.value)}>
              <option value="">—</option>
              {orgs.map((org) => (
                <option key={org.id} value={org.id}>
                  {org.name} ({org.id})
                </option>
              ))}
            </select>
          </label>
          <label>
            Integration
            <select value={selectedIntegrationKey} onChange={(e) => setSelectedIntegrationKey(e.target.value)}>
              <option value="">—</option>
              {integrations.map((integration) => (
                <option key={integration.key} value={integration.key}>
                  {integration.name} ({integration.key})
                </option>
              ))}
            </select>
          </label>
          <label>
            Webhook URL
            <input value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} />
          </label>
        </div>
        <div className="actions">
          <button onClick={loadOrgIntegrations} disabled={loading || !selectedOrg || !adminKey}>
            Charger config org
          </button>
          <button onClick={upsertIntegration} disabled={loading || !selectedOrg || !selectedIntegrationKey || !adminKey}>
            Sauver config
          </button>
          <button onClick={testIntegration} disabled={loading || !selectedOrg || !selectedIntegrationKey || !adminKey}>
            Tester webhook
          </button>
          <button onClick={startOAuth} disabled={loading || !selectedOrg || !selectedIntegrationKey || !adminKey}>
            Démarrer OAuth
          </button>
        </div>
        {oauthUrl && (
          <div className="actions">
            <a href={oauthUrl} target="_blank" rel="noreferrer">
              Continuer OAuth
            </a>
          </div>
        )}
        {orgIntegrations.length > 0 && (
          <div className="table" style={{ marginTop: 12 }}>
            <div className="table-row header">
              <span>Integration</span>
              <span>Enabled</span>
              <span>Config</span>
              <span>Créé le</span>
            </div>
            {orgIntegrations.map((item) => (
              <div key={item.id} className="table-row">
                <span>{item.integration_key}</span>
                <span>{item.enabled ? "oui" : "non"}</span>
                <span className="title">{item.config ? JSON.stringify(item.config) : "-"}</span>
                <span>{new Date(item.created_at).toLocaleString()}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Costs & algorithmes</h2>
          <button onClick={() => { loadCostDaily(); loadCostUnits(); loadGroupingStats(); loadRcaStats(); loadRcaPolicy(); loadIngestDrops(); }} disabled={loading || !adminKey || !currentProjectId}>
            Charger coûts + stats
          </button>
        </div>
        <div className="grid">
          <label>
            Admin key
            <input value={adminKey} onChange={(e) => setAdminKey(e.target.value)} />
          </label>
          <label>
            Projet
            <input value={currentProjectId || ""} readOnly />
          </label>
        </div>
        {costDaily.length > 0 && (
          <div className="table" style={{ marginTop: 12 }}>
            <div className="table-row header">
              <span>Jour</span>
              <span>Units</span>
              <span>Storage (bytes)</span>
            </div>
            {costDaily.map((row, idx) => (
              <div key={idx} className="table-row">
                <span>{row.day}</span>
                <span>{row.units.toFixed(2)}</span>
                <span>{row.storage_bytes}</span>
              </div>
            ))}
          </div>
        )}
        {costUnits.length > 0 && (
          <div className="table" style={{ marginTop: 12 }}>
            <div className="table-row header">
              <span>Kind</span>
              <span>Units</span>
              <span>Storage</span>
              <span>Créé le</span>
            </div>
            {costUnits.map((row) => (
              <div key={row.id} className="table-row">
                <span>{row.kind}</span>
                <span>{row.units.toFixed(2)}</span>
                <span>{row.storage_bytes}</span>
                <span>{new Date(row.created_at).toLocaleString()}</span>
              </div>
            ))}
          </div>
        )}
        {groupingStats && (
          <div className="grid" style={{ marginTop: 12 }}>
            <div>
              <h4>Décisions (raison)</h4>
              {groupingStats.by_reason?.map((row, idx) => (
                <div key={idx} className="table-row">
                  <span>{row.key}</span>
                  <span>{row.count}</span>
                </div>
              ))}
            </div>
            <div>
              <h4>Décisions (version)</h4>
              {groupingStats.by_version?.map((row, idx) => (
                <div key={idx} className="table-row">
                  <span>{row.key}</span>
                  <span>{row.count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {rcaStats && (
          <div style={{ marginTop: 12 }}>
            <h4>RCA confidence (24h)</h4>
            <div className="table-row">
              <span>Moyenne</span>
              <span>{(rcaStats.avg_confidence * 100).toFixed(1)}%</span>
            </div>
            <div className="table-row">
              <span>Min</span>
              <span>{(rcaStats.min_confidence * 100).toFixed(1)}%</span>
            </div>
            <div className="table-row">
              <span>Max</span>
              <span>{(rcaStats.max_confidence * 100).toFixed(1)}%</span>
            </div>
            <div className="table-row">
              <span>Samples</span>
              <span>{rcaStats.count}</span>
            </div>
          </div>
        )}
        <div style={{ marginTop: 12 }}>
          <h4>RCA policy</h4>
          <div className="table-row">
            <span>Min confidence</span>
            <input
              style={{ maxWidth: 120 }}
              value={rcaPolicyInput}
              onChange={(e) => setRcaPolicyInput(e.target.value)}
            />
            <button onClick={updateRcaPolicy} disabled={loading || !adminKey || !currentProjectId}>
              Sauver
            </button>
          </div>
          {rcaPolicy && (
            <div className="table-row">
              <span>Updated</span>
              <span>{new Date(rcaPolicy.updated_at).toLocaleString()}</span>
            </div>
          )}
        </div>
        {ingestDrops.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <h4>Ingest drops (30j)</h4>
            <div className="table">
              <div className="table-row header">
                <span>Jour</span>
                <span>Raison</span>
                <span>Count</span>
              </div>
              {ingestDrops.map((row, idx) => (
                <div key={idx} className="table-row">
                  <span>{row.day}</span>
                  <span>{row.reason}</span>
                  <span>{row.count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Issues</h2>
          <button onClick={() => loadIssues()} disabled={loading}>
            Rafraîchir
          </button>
        </div>
        <div className="filters">
          <label>
            Status
            <select value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
              <option value="">Tous</option>
              <option value="open">open</option>
              <option value="resolved">resolved</option>
              <option value="ignored">ignored</option>
            </select>
          </label>
          <label>
            Niveau
            <select value={filters.level} onChange={(e) => setFilters({ ...filters, level: e.target.value })}>
              <option value="">Tous</option>
              <option value="error">error</option>
              <option value="warning">warning</option>
              <option value="info">info</option>
              <option value="debug">debug</option>
            </select>
          </label>
          <label>
            Recherche
            <input value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
          </label>
          <button onClick={() => loadIssues()} disabled={loading}>
            Appliquer
          </button>
        </div>
        <div className="table">
          <div className="table-row header">
            <span>Titre</span>
            <span>Niveau</span>
            <span>Status</span>
            <span>Assigné</span>
            <span>Users 24h</span>
            <span>Dernier</span>
          </div>
          {issues.length === 0 && (
            <div className="empty-state">
              <h4>Aucune issue pour le moment</h4>
              <p className="muted">Envoyez un event test pour vérifier la pipeline.</p>
              <button onClick={sendTestEvent} disabled={loading || !quickstartProjectId || !quickstartApiKey || !ingestUrl}>
                Envoyer un event test
              </button>
            </div>
          )}
          {issues.map((issue) => (
            <button key={issue.id} className="table-row" onClick={() => loadIssueDetail(issue.id)}>
              <span className="title">{issue.title}</span>
              <span>{issue.level}</span>
              <span>{issue.status}</span>
              <span>{issue.assignee || "-"}</span>
              <span>{issue.affected_users_24h}</span>
              <span>{new Date(issue.last_seen).toLocaleString()}</span>
            </button>
          ))}
        </div>
        {nextBefore && (
          <div className="actions">
            <button onClick={() => loadIssues({ before: nextBefore })} disabled={loading}>
              Charger plus
            </button>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Détail</h2>
        <div className="detail">
          <div>
            <h3>{currentIssue.title || "Sélectionne une issue"}</h3>
            <p className="muted">{currentIssue.id}</p>
            <div className="detail-meta">
              <span>{currentIssue.level}</span>
              <span>{currentIssue.status}</span>
              <span>{currentIssue.count_total} events</span>
            </div>
            <div className="detail-meta">
              <span>Release: {currentIssue.first_release || "-"} → {currentIssue.last_release || "-"}</span>
              <span>Régression: {currentIssue.regressed_at ? new Date(currentIssue.regressed_at).toLocaleString() : "-"}</span>
            </div>
            <div className="detail-actions">
              <button onClick={() => updateStatus(currentIssue.id, "open")} disabled={!currentIssue.id}>
                Ouvrir
              </button>
              <button onClick={() => updateStatus(currentIssue.id, "resolved")} disabled={!currentIssue.id}>
                Résoudre
              </button>
              <button onClick={() => updateStatus(currentIssue.id, "ignored")} disabled={!currentIssue.id}>
                Ignorer
              </button>
            </div>
            <label>
              Assigné
              <input
                value={currentIssue.assignee || ""}
                onChange={(e) => setSelectedIssue({ ...currentIssue, assignee: e.target.value })}
                onBlur={(e) => currentIssue.id && updateAssignee(currentIssue.id, e.target.value)}
                disabled={!currentIssue.id}
              />
            </label>
          </div>
          <div className="events">
            <h4>Événements récents</h4>
            {rcaPublished && (rcaSummary || (Array.isArray(rcaChain) && rcaChain.length > 0) || rcaRegression) && (
              <div className="event">
                <div className="event-header">
                  <span>RCA assistant</span>
                  {typeof rcaConfidence === "number" && (
                    <span>{Math.round(rcaConfidence * 100)}% confiance</span>
                  )}
                </div>
                {rcaSummary && <p>{rcaSummary}</p>}
                {Array.isArray(rcaChain) && rcaChain.length > 0 && (
                  <div className="muted">
                    <strong>Chaîne causale</strong>
                    <ol>
                      {rcaChain.map((step, idx) => (
                        <li key={idx}>
                          {step.function || "(unknown)"} — {step.file}:{step.line}
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
                {rcaRegression && (
                  <div className="muted">
                    <strong>Regression map</strong>
                    <p>
                      Release suspecte: {rcaRegression.last_release || rcaRegression.event_release || "-"}
                      {rcaRegression.regressed_at
                        ? ` • Régression: ${new Date(rcaRegression.regressed_at).toLocaleString()}`
                        : ""}
                    </p>
                    {rcaRegression.regression_window && (
                      <p>
                        Fenêtre: {rcaRegression.regression_window.from} → {rcaRegression.regression_window.to}
                      </p>
                    )}
                    {Array.isArray(rcaRegression.candidate_commits) && rcaRegression.candidate_commits.length > 0 && (
                      <ul>
                        {rcaRegression.candidate_commits.map((commit, idx) => (
                          <li key={idx}>
                            {commit.sha} {commit.message ? `— ${commit.message}` : ""}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>
            )}
            {!rcaPublished && (
              <div className="event">
                <div className="event-header">
                  <span>RCA assistant</span>
                  <span>confidence trop faible</span>
                </div>
                <p className="muted">RCA non publiée (seuil de confiance).</p>
              </div>
            )}
            {culprit && (
              <div className="event">
                <div className="event-header">
                  <span>Culprit</span>
                </div>
                <p>{culprit}</p>
              </div>
            )}
            {issueEvents.map((evt, idx) => (
              <div key={idx} className="event">
                <div className="event-header">
                  <span>{new Date(evt.occurred_at).toLocaleString()}</span>
                  <span>{evt.exception_type}</span>
                </div>
                <p>{evt.exception_message}</p>
                {evt.message && <p className="muted">{evt.message}</p>}
                {evt.stacktrace && (
                  <pre>{JSON.stringify(evt.stacktrace, null, 2)}</pre>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {error && <div className="error">{error}</div>}
      {loading && <div className="loading">Chargement…</div>}
    </div>
  );
}
