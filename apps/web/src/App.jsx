import React, { useEffect, useMemo, useState } from "react";
import { apiFetch } from "./api.js";

const DEFAULT_BASE = "http://localhost:3002";

const STORAGE_KEY = "ember.ui.settings";
const DASHBOARD_KEY = "ember.ui.dashboard.widgets";

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
  const [integrationCategory, setIntegrationCategory] = useState("all");
  const [integrationEnabled, setIntegrationEnabled] = useState(true);
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

  const [releases, setReleases] = useState([]);
  const [selectedRelease, setSelectedRelease] = useState(null);
  const [releaseRegressions, setReleaseRegressions] = useState([]);
  const [releaseSuspects, setReleaseSuspects] = useState([]);

  const [replays, setReplays] = useState([]);
  const [selectedReplay, setSelectedReplay] = useState(null);
  const [replayTimeline, setReplayTimeline] = useState([]);
  const [replayLinks, setReplayLinks] = useState([]);
  const [issueReplays, setIssueReplays] = useState([]);

  const [traceIdInput, setTraceIdInput] = useState("");
  const [traceWaterfall, setTraceWaterfall] = useState([]);
  const [traceCorrelations, setTraceCorrelations] = useState(null);
  const [traceReplayLinks, setTraceReplayLinks] = useState([]);
  const [traceBreakdown, setTraceBreakdown] = useState([]);
  const [traceTopRegressions, setTraceTopRegressions] = useState([]);

  const [profileTraceId, setProfileTraceId] = useState("");
  const [profileList, setProfileList] = useState([]);
  const [profileHotPaths, setProfileHotPaths] = useState([]);
  const [profileDiff, setProfileDiff] = useState(null);
  const [profileBaseId, setProfileBaseId] = useState("");
  const [profileCompareId, setProfileCompareId] = useState("");

  const [uptimeMonitors, setUptimeMonitors] = useState([]);
  const [uptimeChecks, setUptimeChecks] = useState([]);
  const [selectedUptimeMonitorId, setSelectedUptimeMonitorId] = useState("");
  const [uptimeName, setUptimeName] = useState("");
  const [uptimeUrl, setUptimeUrl] = useState("");
  const [uptimeInterval, setUptimeInterval] = useState("5");
  const [uptimeExpected, setUptimeExpected] = useState("200");
  const [uptimeTimeout, setUptimeTimeout] = useState("5000");

  const [cronMonitors, setCronMonitors] = useState([]);
  const [cronCheckins, setCronCheckins] = useState([]);
  const [selectedCronMonitorId, setSelectedCronMonitorId] = useState("");
  const [cronName, setCronName] = useState("");
  const [cronSchedule, setCronSchedule] = useState("60");
  const [cronGrace, setCronGrace] = useState("5");

  const [issues, setIssues] = useState([]);
  const [nextBefore, setNextBefore] = useState(null);
  const [filters, setFilters] = useState({ status: "", level: "", q: "" });
  const [triageTab, setTriageTab] = useState("all");
  const [issueStats, setIssueStats] = useState(null);
  const [selectedIssueIds, setSelectedIssueIds] = useState([]);
  const [bulkAssignee, setBulkAssignee] = useState("");
  const [discoverQuery, setDiscoverQuery] = useState("");
  const [discoverGroupBy, setDiscoverGroupBy] = useState("issue");
  const [discoverEvents, setDiscoverEvents] = useState([]);
  const [discoverStats, setDiscoverStats] = useState([]);
  const [savedQueries, setSavedQueries] = useState([]);
  const [selectedSavedQueryId, setSelectedSavedQueryId] = useState("");
  const [newSavedQueryName, setNewSavedQueryName] = useState("");
  const [dashboardWidgets, setDashboardWidgets] = useState([]);
  const [dashboardData, setDashboardData] = useState({});
  const [dashboardName, setDashboardName] = useState("");
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
        setTriageTab(parsed.triageTab || "all");
      } catch {
        // ignore
      }
    }
  }, []);

  useEffect(() => {
    const saved = localStorage.getItem(DASHBOARD_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) {
          setDashboardWidgets(parsed);
        }
      } catch {
        // ignore
      }
    }
  }, []);

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
        onboardingDone,
        triageTab
      })
    );
  }, [baseUrl, authMode, token, projectId, apiKey, selectedProject, adminKey, selectedOrg, ingestUrl, ingestProjectId, ingestApiKey, onboardingDone, triageTab]);

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
        onboardingDone,
        triageTab
      })
    );
  }, [baseUrl, authMode, token, projectId, apiKey, selectedProject, adminKey, selectedOrg, ingestUrl, ingestProjectId, ingestApiKey, onboardingDone, triageTab]);

  useEffect(() => {
    localStorage.setItem(DASHBOARD_KEY, JSON.stringify(dashboardWidgets));
  }, [dashboardWidgets]);

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

  const orgIntegrationMap = useMemo(() => {
    return new Map(orgIntegrations.map((item) => [item.integration_key, item]));
  }, [orgIntegrations]);

  const integrationCategories = useMemo(() => {
    const categories = new Set();
    integrations.forEach((integration) => {
      categories.add(integration.category || "other");
    });
    return ["all", ...Array.from(categories).sort()];
  }, [integrations]);

  const filteredIntegrations = useMemo(() => {
    return integrations.filter((integration) => {
      const category = integration.category || "other";
      const matchesCategory = integrationCategory === "all" || integrationCategory === category;
      if (!matchesCategory) return false;
      if (!integrationEnabled) return true;
      return orgIntegrationMap.has(integration.key);
    });
  }, [integrations, integrationCategory, integrationEnabled, orgIntegrationMap]);

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

  const toggleOrgIntegration = async (integrationKey) => {
    if (!selectedOrg || !integrationKey) return;
    setError("");
    setLoading(true);
    try {
      const existing = orgIntegrationMap.get(integrationKey);
      await apiFetch({
        baseUrl,
        path: `/orgs/${selectedOrg}/integrations`,
        method: "POST",
        headers: adminHeaders,
        body: {
          integration_key: integrationKey,
          config: existing?.config || null,
          enabled: !existing?.enabled
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
      const tabStatus = ["open", "resolved", "ignored"].includes(triageTab) ? triageTab : filters.status;
      if (tabStatus) params.set("status", tabStatus);
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
      if (!before) {
        setSelectedIssueIds([]);
      }
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadIssueStats = async () => {
    if (!projectHeader["x-ember-project"]) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: "/issues/stats?window_minutes=1440&sla_minutes=1440",
        headers: fullHeaders
      });
      setIssueStats(data || null);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadSavedQueries = async () => {
    if (!projectHeader["x-ember-project"]) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/saved-queries`,
        headers: fullHeaders
      });
      setSavedQueries(data || []);
      if (!selectedSavedQueryId && data.length > 0) {
        setSelectedSavedQueryId(data[0].id);
      }
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const createSavedQuery = async () => {
    if (!currentProjectId || !newSavedQueryName.trim()) return;
    setError("");
    setLoading(true);
    try {
      await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/saved-queries`,
        method: "POST",
        headers: fullHeaders,
        body: { name: newSavedQueryName.trim(), query: discoverQuery.trim() }
      });
      setNewSavedQueryName("");
      await loadSavedQueries();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const deleteSavedQuery = async (id) => {
    if (!currentProjectId || !id) return;
    setError("");
    setLoading(true);
    try {
      await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/saved-queries/${id}`,
        method: "DELETE",
        headers: fullHeaders
      });
      if (selectedSavedQueryId === id) {
        setSelectedSavedQueryId("");
      }
      await loadSavedQueries();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadDiscover = async () => {
    if (!projectHeader["x-ember-project"]) return;
    setError("");
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (discoverQuery.trim()) params.set("q", discoverQuery.trim());
      if (selectedSavedQueryId) params.set("saved_query_id", selectedSavedQueryId);
      const data = await apiFetch({
        baseUrl,
        path: `/discover/events?${params.toString()}`,
        headers: fullHeaders
      });
      setDiscoverEvents(data.items || []);
      await loadDiscoverStats();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadDiscoverStats = async () => {
    if (!projectHeader["x-ember-project"]) return;
    const params = new URLSearchParams();
    if (discoverQuery.trim()) params.set("q", discoverQuery.trim());
    if (selectedSavedQueryId) params.set("saved_query_id", selectedSavedQueryId);
    if (discoverGroupBy) params.set("group_by", discoverGroupBy);
    const data = await apiFetch({
      baseUrl,
      path: `/discover/stats?${params.toString()}`,
      headers: fullHeaders
    });
    setDiscoverStats(data || []);
  };

  const toggleIssueSelection = (issueId) => {
    setSelectedIssueIds((current) =>
      current.includes(issueId) ? current.filter((id) => id !== issueId) : [...current, issueId]
    );
  };

  const selectAllIssues = () => {
    const ids = displayIssues.map((issue) => issue.id);
    setSelectedIssueIds(ids);
  };

  const clearSelectedIssues = () => {
    setSelectedIssueIds([]);
  };

  const bulkUpdateIssues = async ({ status, assignee } = {}) => {
    if (!selectedIssueIds.length) return;
    setError("");
    setLoading(true);
    try {
      await apiFetch({
        baseUrl,
        path: "/issues/bulk",
        method: "POST",
        headers: fullHeaders,
        body: {
          issue_ids: selectedIssueIds,
          status: status || undefined,
          assignee: assignee || undefined
        }
      });
      setBulkAssignee("");
      await loadIssues();
      await loadIssueStats();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const addDashboardWidget = async () => {
    if (!selectedSavedQueryId || !dashboardName.trim()) return;
    const widget = {
      id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
      name: dashboardName.trim(),
      savedQueryId: selectedSavedQueryId,
      groupBy: discoverGroupBy
    };
    setDashboardWidgets((current) => [...current, widget]);
    setDashboardName("");
    await refreshDashboard();
  };

  const removeDashboardWidget = (id) => {
    setDashboardWidgets((current) => current.filter((widget) => widget.id !== id));
    setDashboardData((current) => {
      const updated = { ...current };
      delete updated[id];
      return updated;
    });
  };

  const refreshDashboard = async () => {
    if (!projectHeader["x-ember-project"]) return;
    const nextData = {};
    for (const widget of dashboardWidgets) {
      const params = new URLSearchParams();
      params.set("saved_query_id", widget.savedQueryId);
      params.set("group_by", widget.groupBy || "issue");
      try {
        const data = await apiFetch({
          baseUrl,
          path: `/discover/stats?${params.toString()}`,
          headers: fullHeaders
        });
        nextData[widget.id] = data || [];
      } catch {
        nextData[widget.id] = [];
      }
    }
    setDashboardData(nextData);
  };

  const loadIssueDetail = async (issueId) => {
    setError("");
    setLoading(true);
    try {
      const detail = await apiFetch({ baseUrl, path: `/issues/${issueId}`, headers: fullHeaders });
      const events = await apiFetch({ baseUrl, path: `/issues/${issueId}/events`, headers: fullHeaders });
      let replays = [];
      try {
        const data = await apiFetch({ baseUrl, path: `/issues/${issueId}/replays`, headers: fullHeaders });
        replays = data || [];
      } catch {
        replays = [];
      }
      let insights = null;
      try {
        insights = await apiFetch({ baseUrl, path: `/issues/${issueId}/insights`, headers: fullHeaders });
      } catch {
        insights = null;
      }
      setSelectedIssue(detail);
      setIssueEvents(events.items || []);
      setIssueReplays(replays);
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

  const loadReleases = async () => {
    if (!currentProjectId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/releases`,
        headers: fullHeaders
      });
      setReleases(data || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadReleaseDetail = async (version) => {
    if (!currentProjectId || !version) return;
    setError("");
    setLoading(true);
    try {
      const detail = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/releases/${encodeURIComponent(version)}`,
        headers: fullHeaders
      });
      const regressions = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/releases/${encodeURIComponent(version)}/regressions`,
        headers: fullHeaders
      });
      const suspects = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/releases/${encodeURIComponent(version)}/suspect-commits`,
        headers: fullHeaders
      });
      setSelectedRelease(detail);
      setReleaseRegressions(regressions || []);
      setReleaseSuspects(suspects || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadReplays = async () => {
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({ baseUrl, path: "/replays", headers: fullHeaders });
      setReplays(data || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadReplayDetail = async (replayId) => {
    setError("");
    setLoading(true);
    try {
      const detail = await apiFetch({ baseUrl, path: `/replays/${replayId}`, headers: fullHeaders });
      const timeline = await apiFetch({ baseUrl, path: `/replays/${replayId}/timeline`, headers: fullHeaders });
      const links = await apiFetch({ baseUrl, path: `/replays/${replayId}/links`, headers: fullHeaders });
      setSelectedReplay(detail);
      setReplayTimeline(timeline.items || []);
      setReplayLinks(links || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const linkReplayToIssue = async () => {
    if (!selectedReplay?.id || !selectedIssue?.id) return;
    setError("");
    setLoading(true);
    try {
      await apiFetch({
        baseUrl,
        path: `/replays/${selectedReplay.id}/link`,
        method: "POST",
        headers: fullHeaders,
        body: { issue_id: selectedIssue.id }
      });
      await loadReplayDetail(selectedReplay.id);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadTraceExplorer = async () => {
    if (!traceIdInput.trim()) return;
    setError("");
    setLoading(true);
    try {
      const waterfall = await apiFetch({ baseUrl, path: `/traces/${traceIdInput}/waterfall`, headers: fullHeaders });
      const correlations = await apiFetch({ baseUrl, path: `/traces/${traceIdInput}/correlations`, headers: fullHeaders });
      const replays = await apiFetch({ baseUrl, path: `/traces/${traceIdInput}/replays`, headers: fullHeaders });
      setTraceWaterfall(waterfall.spans || []);
      setTraceCorrelations(correlations || null);
      setTraceReplayLinks(replays || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadTraceInsights = async () => {
    if (!currentProjectId) return;
    try {
      const top = await apiFetch({
        baseUrl,
        path: "/traces/top-regressions?window_minutes=1440&limit=10",
        headers: fullHeaders
      });
      const breakdown = await apiFetch({
        baseUrl,
        path: "/traces/breakdown?window_minutes=1440",
        headers: fullHeaders
      });
      setTraceTopRegressions(top || []);
      setTraceBreakdown(breakdown || []);
    } catch {
      setTraceTopRegressions([]);
      setTraceBreakdown([]);
    }
  };

  const loadProfiles = async () => {
    if (!profileTraceId.trim()) return;
    setError("");
    setLoading(true);
    try {
      const list = await apiFetch({ baseUrl, path: `/profiles/${profileTraceId}/list?limit=20`, headers: fullHeaders });
      const hot = await apiFetch({ baseUrl, path: `/profiles/${profileTraceId}/hot-paths?limit=10`, headers: fullHeaders });
      setProfileList(list || []);
      setProfileHotPaths(hot.items || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadProfileDiff = async () => {
    if (!profileTraceId.trim() || !profileBaseId || !profileCompareId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/profiles/${profileTraceId}/diff?base_id=${profileBaseId}&compare_id=${profileCompareId}&limit=10`,
        headers: fullHeaders
      });
      setProfileDiff(data || null);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadUptimeMonitors = async () => {
    if (!currentProjectId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/uptime/monitors`,
        headers: fullHeaders
      });
      setUptimeMonitors(data || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadUptimeChecks = async (monitorId) => {
    if (!currentProjectId || !monitorId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/uptime/monitors/${monitorId}/checks?limit=20`,
        headers: fullHeaders
      });
      setUptimeChecks(data || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const createUptimeMonitor = async () => {
    if (!currentProjectId || !uptimeName.trim() || !uptimeUrl.trim()) return;
    const interval = Number(uptimeInterval) || 5;
    const expected = Number(uptimeExpected) || 200;
    const timeout = Number(uptimeTimeout) || 5000;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/uptime/monitors`,
        method: "POST",
        headers: fullHeaders,
        body: {
          name: uptimeName.trim(),
          url: uptimeUrl.trim(),
          method: "GET",
          expected_status: expected,
          timeout_ms: timeout,
          interval_minutes: interval,
          enabled: true
        }
      });
      setSelectedUptimeMonitorId(data.id);
      setUptimeName("");
      setUptimeUrl("");
      await loadUptimeMonitors();
      await loadUptimeChecks(data.id);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const runUptimeMonitor = async (monitorId) => {
    if (!currentProjectId || !monitorId) return;
    setError("");
    setLoading(true);
    try {
      await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/uptime/monitors/${monitorId}/run`,
        method: "POST",
        headers: fullHeaders
      });
      await loadUptimeMonitors();
      await loadUptimeChecks(monitorId);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadCronMonitors = async () => {
    if (!currentProjectId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/crons/monitors`,
        headers: fullHeaders
      });
      setCronMonitors(data || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadCronCheckins = async (monitorId) => {
    if (!currentProjectId || !monitorId) return;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/crons/monitors/${monitorId}/checkins?limit=20`,
        headers: fullHeaders
      });
      setCronCheckins(data || []);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const createCronMonitor = async () => {
    if (!currentProjectId || !cronName.trim()) return;
    const schedule = Number(cronSchedule) || 60;
    const grace = Number(cronGrace) || 5;
    setError("");
    setLoading(true);
    try {
      const data = await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/crons/monitors`,
        method: "POST",
        headers: fullHeaders,
        body: {
          name: cronName.trim(),
          schedule_minutes: schedule,
          grace_minutes: grace,
          timezone: "UTC",
          enabled: true
        }
      });
      setSelectedCronMonitorId(data.id);
      setCronName("");
      await loadCronMonitors();
      await loadCronCheckins(data.id);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  };

  const createCronCheckin = async (monitorId, status) => {
    if (!currentProjectId || !monitorId) return;
    setError("");
    setLoading(true);
    try {
      await apiFetch({
        baseUrl,
        path: `/projects/${currentProjectId}/crons/monitors/${monitorId}/checkins`,
        method: "POST",
        headers: fullHeaders,
        body: { status }
      });
      await loadCronMonitors();
      await loadCronCheckins(monitorId);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
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

  useEffect(() => {
    if (currentProjectId) {
      loadIssueStats();
      loadSavedQueries();
      loadReleases();
      loadReplays();
      loadTraceInsights();
      loadUptimeMonitors();
      loadCronMonitors();
    }
  }, [currentProjectId]);

  const displayIssues = issues.filter((issue) => {
    if (triageTab === "regressed") {
      return Boolean(issue.regressed_at);
    }
    if (triageTab === "unassigned") {
      return !issue.assignee;
    }
    if (triageTab === "open") return issue.status === "open";
    if (triageTab === "resolved") return issue.status === "resolved";
    if (triageTab === "ignored") return issue.status === "ignored";
    return true;
  });

  const currentIssue = selectedIssue || emptyIssue;
  const latestEvent = issueEvents[0];
  const culprit = latestEvent?.context?.culprit;
  const rcaSummary = issueInsights?.summary;
  const rcaChain = issueInsights?.causal_chain;
  const rcaRegression = issueInsights?.regression_map;
  const rcaConfidence = issueInsights?.confidence;
  const rcaPublished = issueInsights?.published !== false;

  const quickstartCurl = `curl -X POST ${ingestUrl} \\\n  -H "Content-Type: application/json" \\\n  -H "x-ember-key: ${quickstartApiKey || "<PROJECT_KEY>"}" \\\n  -d '{"project_id":"${quickstartProjectId || "<PROJECT_ID>"}","event_id":"${Date.now()}","timestamp":"${new Date().toISOString()}","level":"error","message":"Test error","exception":{"kind":"TestError","message":"Example","stacktrace":[]},"schema_version":"v1"}'`;

  const quickstartJs = `fetch("${ingestUrl}", {\n  method: "POST",\n  headers: {\n    "Content-Type": "application/json",\n    "x-ember-key": "${quickstartApiKey || "<PROJECT_KEY>"}"\n  },\n  body: JSON.stringify({\n    project_id: "${quickstartProjectId || "<PROJECT_ID>"}",\n    event_id: crypto.randomUUID(),\n    timestamp: new Date().toISOString(),\n    level: "error",\n    message: "Test error",\n    exception: { kind: "TestError", message: "Example", stacktrace: [] },\n    schema_version: "v1"\n  })\n});`;

  const sdkNodeSnippet = `const ember = require("@ember/sdk");\n\nember.init({\n  endpoint: "${baseUrl || "http://localhost:3002"}",\n  projectId: "${currentProjectId || "<PROJECT_ID>"}",\n  apiKey: "${quickstartApiKey || "<PROJECT_KEY>"}",\n  environment: "prod",\n  release: "1.0.0",\n  autoCapture: true,\n});\n\ntry {\n  throw new Error("Boom");\n} catch (err) {\n  ember.captureException(err, { tags: { feature: "checkout" } });\n}`;

  const sdkExpressSnippet = `const { emberRequestHandler, emberErrorHandler } = require("@ember/sdk/express");\n\napp.use(emberRequestHandler({\n  userResolver: (req) => ({ id: req.user?.id, email: req.user?.email }),\n}));\n\napp.use(emberErrorHandler());`;

  const sdkPythonSnippet = `import ember_sdk as ember\n\nember.init(\n    endpoint="${baseUrl || "http://localhost:3002"}",\n    project_id="${currentProjectId || "<PROJECT_ID>"}",\n    api_key="${quickstartApiKey || "<PROJECT_KEY>"}",\n    environment="prod",\n    release="1.0.0",\n    auto_capture=True,\n)\n\ntry:\n    raise Exception("Boom")\nexcept Exception as err:\n    ember.capture_exception(err, {"tags": {"feature": "checkout"}})`;

  const sdkFastapiSnippet = `from ember_sdk import add_fastapi_handlers\n\nadd_fastapi_handlers(app, user_resolver=lambda req: {"id": "42"})`;

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
        <div className="card-header">
          <h2>SDKs & auto‑instrumentation</h2>
        </div>
        <p className="muted">Les SDK capturent automatiquement les exceptions et enrichissent les événements via les middlewares.</p>
        <div className="snippet">
          <div className="snippet-header">
            <span>Node.js</span>
            <button onClick={() => copyToClipboard(sdkNodeSnippet)}>Copier</button>
          </div>
          <pre>{sdkNodeSnippet}</pre>
        </div>
        <div className="snippet">
          <div className="snippet-header">
            <span>Express middleware</span>
            <button onClick={() => copyToClipboard(sdkExpressSnippet)}>Copier</button>
          </div>
          <pre>{sdkExpressSnippet}</pre>
        </div>
        <div className="snippet">
          <div className="snippet-header">
            <span>Python</span>
            <button onClick={() => copyToClipboard(sdkPythonSnippet)}>Copier</button>
          </div>
          <pre>{sdkPythonSnippet}</pre>
        </div>
        <div className="snippet">
          <div className="snippet-header">
            <span>FastAPI</span>
            <button onClick={() => copyToClipboard(sdkFastapiSnippet)}>Copier</button>
          </div>
          <pre>{sdkFastapiSnippet}</pre>
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
            Catégorie
            <select value={integrationCategory} onChange={(e) => setIntegrationCategory(e.target.value)}>
              {integrationCategories.map((category) => (
                <option key={category} value={category}>
                  {category}
                </option>
              ))}
            </select>
          </label>
          <label>
            Filtre
            <select value={integrationEnabled ? "enabled" : "all"} onChange={(e) => setIntegrationEnabled(e.target.value === "enabled")}>
              <option value="all">Tous</option>
              <option value="enabled">Actifs</option>
            </select>
          </label>
        </div>
        <div className="actions">
          <button onClick={loadOrgIntegrations} disabled={loading || !selectedOrg || !adminKey}>
            Charger config org
          </button>
        </div>
        <div className="marketplace-grid">
          {filteredIntegrations.map((integration) => {
            const enabled = orgIntegrationMap.get(integration.key)?.enabled;
            return (
              <div key={integration.key} className={`marketplace-card ${enabled ? "enabled" : ""}`}>
                <div>
                  <strong>{integration.name}</strong>
                  <p className="muted">{integration.category || "other"}</p>
                  <p className="muted">{integration.description || ""}</p>
                </div>
                <div className="actions">
                  <button
                    onClick={() => {
                      setSelectedIntegrationKey(integration.key);
                      setWebhookUrl(orgIntegrationMap.get(integration.key)?.config?.webhook_url || "");
                    }}
                  >
                    Configurer
                  </button>
                  <button onClick={() => toggleOrgIntegration(integration.key)} disabled={!selectedOrg || !adminKey}>
                    {enabled ? "Désactiver" : "Activer"}
                  </button>
                </div>
              </div>
            );
          })}
          {filteredIntegrations.length === 0 && <p className="muted">Aucune intégration pour ce filtre.</p>}
        </div>
        {selectedIntegrationKey && (
          <div style={{ marginTop: 12 }}>
            <h4>Configurer: {selectedIntegrationKey}</h4>
            <div className="grid">
              <label>
                Webhook URL
                <input value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} />
              </label>
            </div>
            <div className="actions">
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
          </div>
        )}
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
          <h2>Triage & stats</h2>
          <div className="actions">
            <button onClick={loadIssueStats} disabled={loading}>
              Rafraîchir stats
            </button>
          </div>
        </div>
        {issueStats && (
          <div className="stat-grid">
            <div className="stat-card">
              <span>Open issues</span>
              <strong>{issueStats.open_issues}</strong>
            </div>
            <div className="stat-card">
              <span>SLA breaches</span>
              <strong>{issueStats.sla_breaches}</strong>
            </div>
            <div className="stat-card">
              <span>By status</span>
              <strong>{issueStats.by_status?.[0]?.count || 0}</strong>
            </div>
            <div className="stat-card">
              <span>Top assignee</span>
              <strong>{issueStats.by_assignee?.[0]?.key || "-"}</strong>
            </div>
          </div>
        )}
        <div className="tabs">
          {[
            { key: "all", label: "All" },
            { key: "open", label: "Open" },
            { key: "resolved", label: "Resolved" },
            { key: "ignored", label: "Ignored" },
            { key: "regressed", label: "Regressed" },
            { key: "unassigned", label: "Unassigned" }
          ].map((tab) => (
            <button
              key={tab.key}
              className={`tab ${triageTab === tab.key ? "active" : ""}`}
              onClick={() => {
                setTriageTab(tab.key);
                loadIssues();
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <div className="bulk-actions">
          <button onClick={selectAllIssues} disabled={displayIssues.length === 0}>
            Tout sélectionner
          </button>
          <button onClick={clearSelectedIssues} disabled={selectedIssueIds.length === 0}>
            Clear
          </button>
          <button onClick={() => bulkUpdateIssues({ status: "resolved" })} disabled={selectedIssueIds.length === 0}>
            Résoudre
          </button>
          <button onClick={() => bulkUpdateIssues({ status: "ignored" })} disabled={selectedIssueIds.length === 0}>
            Ignorer
          </button>
          <label>
            Assigner à
            <input value={bulkAssignee} onChange={(e) => setBulkAssignee(e.target.value)} />
          </label>
          <button onClick={() => bulkUpdateIssues({ assignee: bulkAssignee })} disabled={selectedIssueIds.length === 0 || !bulkAssignee.trim()}>
            Assigner
          </button>
        </div>
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Discover</h2>
          <div className="actions">
            <button onClick={loadDiscover} disabled={loading || !currentProjectId}>
              Lancer la requête
            </button>
          </div>
        </div>
        <div className="grid">
          <label>
            Query
            <input value={discoverQuery} onChange={(e) => setDiscoverQuery(e.target.value)} placeholder="level:error release:1.2.3" />
          </label>
          <label>
            Saved query
            <select value={selectedSavedQueryId} onChange={(e) => setSelectedSavedQueryId(e.target.value)}>
              <option value="">—</option>
              {savedQueries.map((query) => (
                <option key={query.id} value={query.id}>
                  {query.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Group by
            <select value={discoverGroupBy} onChange={(e) => setDiscoverGroupBy(e.target.value)}>
              <option value="issue">Issue</option>
              <option value="release">Release</option>
              <option value="exception_type">Exception</option>
              <option value="level">Level</option>
              <option value="user">User</option>
            </select>
          </label>
        </div>
        <div className="actions">
          <label>
            Nom de requête
            <input value={newSavedQueryName} onChange={(e) => setNewSavedQueryName(e.target.value)} />
          </label>
          <button onClick={createSavedQuery} disabled={!newSavedQueryName.trim() || !currentProjectId}>
            Sauver
          </button>
          {selectedSavedQueryId && (
            <button onClick={() => deleteSavedQuery(selectedSavedQueryId)} disabled={!currentProjectId}>
              Supprimer
            </button>
          )}
        </div>
        {discoverStats.length > 0 && (
          <div className="table" style={{ marginTop: 12 }}>
            <div className="table-row header">
              <span>Key</span>
              <span>Count</span>
            </div>
            {discoverStats.map((row, idx) => (
              <div key={idx} className="table-row">
                <span className="title">{row.key}</span>
                <span>{row.count}</span>
              </div>
            ))}
          </div>
        )}
        {discoverEvents.length > 0 && (
          <div className="table" style={{ marginTop: 12 }}>
            <div className="table-row header">
              <span>Issue</span>
              <span>Level</span>
              <span>Release</span>
              <span>User</span>
              <span>Last</span>
            </div>
            {discoverEvents.map((evt) => (
              <div key={evt.id} className="table-row">
                <span className="title">{evt.issue_title}</span>
                <span>{evt.level}</span>
                <span>{evt.release || "-"}</span>
                <span>{evt.user_email || evt.user_id || "-"}</span>
                <span>{new Date(evt.occurred_at).toLocaleString()}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Dashboards</h2>
          <button onClick={refreshDashboard} disabled={loading || !currentProjectId}>
            Rafraîchir
          </button>
        </div>
        <div className="grid">
          <label>
            Nom du widget
            <input value={dashboardName} onChange={(e) => setDashboardName(e.target.value)} />
          </label>
          <label>
            Saved query
            <select value={selectedSavedQueryId} onChange={(e) => setSelectedSavedQueryId(e.target.value)}>
              <option value="">—</option>
              {savedQueries.map((query) => (
                <option key={query.id} value={query.id}>
                  {query.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Group by
            <select value={discoverGroupBy} onChange={(e) => setDiscoverGroupBy(e.target.value)}>
              <option value="issue">Issue</option>
              <option value="release">Release</option>
              <option value="exception_type">Exception</option>
              <option value="level">Level</option>
              <option value="user">User</option>
            </select>
          </label>
          <button onClick={addDashboardWidget} disabled={!dashboardName.trim() || !selectedSavedQueryId}>
            Ajouter
          </button>
        </div>
        <div className="dashboard-grid">
          {dashboardWidgets.map((widget) => (
            <div key={widget.id} className="widget-card">
              <div className="widget-header">
                <strong>{widget.name}</strong>
                <button onClick={() => removeDashboardWidget(widget.id)}>✕</button>
              </div>
              {(dashboardData[widget.id] || []).slice(0, 6).map((row, idx) => (
                <div key={idx} className="table-row">
                  <span className="title">{row.key}</span>
                  <span>{row.count}</span>
                </div>
              ))}
              {(dashboardData[widget.id] || []).length === 0 && (
                <p className="muted">Aucune donnée.</p>
              )}
            </div>
          ))}
        </div>
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
          <div className="table-row header issues-row">
            <span></span>
            <span>Titre</span>
            <span>Niveau</span>
            <span>Status</span>
            <span>Assigné</span>
            <span>Users 24h</span>
            <span>Dernier</span>
          </div>
          {displayIssues.length === 0 && (
            <div className="empty-state">
              <h4>Aucune issue pour le moment</h4>
              <p className="muted">Envoyez un event test pour vérifier la pipeline.</p>
              <button onClick={sendTestEvent} disabled={loading || !quickstartProjectId || !quickstartApiKey || !ingestUrl}>
                Envoyer un event test
              </button>
            </div>
          )}
          {displayIssues.map((issue) => (
            <button key={issue.id} className="table-row issues-row" onClick={() => loadIssueDetail(issue.id)}>
              <span>
                <input
                  type="checkbox"
                  checked={selectedIssueIds.includes(issue.id)}
                  onChange={(e) => {
                    e.stopPropagation();
                    toggleIssueSelection(issue.id);
                  }}
                />
              </span>
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
        <div className="card-header">
          <h2>Releases</h2>
          <button onClick={loadReleases} disabled={loading || !currentProjectId}>
            Rafraîchir
          </button>
        </div>
        <div className="table">
          <div className="table-row header">
            <span>Version</span>
            <span>Adoption</span>
            <span>Events 24h</span>
            <span>New issues</span>
            <span>Regressions</span>
            <span>Créée</span>
          </div>
          {releases.map((release) => (
            <button key={release.id} className="table-row" onClick={() => loadReleaseDetail(release.version)}>
              <span className="title">{release.version}</span>
              <span>{(release.adoption_rate * 100).toFixed(1)}%</span>
              <span>{release.events_24h}</span>
              <span>{release.new_issues_24h}</span>
              <span>{release.regressions_24h}</span>
              <span>{new Date(release.created_at).toLocaleString()}</span>
            </button>
          ))}
        </div>
        {selectedRelease && (
          <div style={{ marginTop: 16 }}>
            <h4>Détail release: {selectedRelease.version}</h4>
            <div className="grid">
              <div>
                <h5>Regressions</h5>
                {releaseRegressions.map((issue) => (
                  <div key={issue.id} className="table-row">
                    <span className="title">{issue.title}</span>
                    <span>{issue.level}</span>
                  </div>
                ))}
              </div>
              <div>
                <h5>Suspect commits</h5>
                {releaseSuspects.map((commit, idx) => (
                  <div key={idx} className="table-row">
                    <span className="title">{commit.commit_sha}</span>
                    <span>{commit.author || "-"}</span>
                    <span>{commit.new_issues + commit.regressions}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Replays</h2>
          <button onClick={loadReplays} disabled={loading}>
            Rafraîchir
          </button>
        </div>
        <div className="table">
          <div className="table-row header">
            <span>Session</span>
            <span>Durée</span>
            <span>URL</span>
            <span>User</span>
            <span>Créé</span>
          </div>
          {replays.map((replay) => (
            <button key={replay.id} className="table-row" onClick={() => loadReplayDetail(replay.id)}>
              <span className="title">{replay.session_id}</span>
              <span>{Math.round(replay.duration_ms)} ms</span>
              <span>{replay.url || "-"}</span>
              <span>{replay.user_email || replay.user_id || "-"}</span>
              <span>{new Date(replay.created_at).toLocaleString()}</span>
            </button>
          ))}
        </div>
        {selectedReplay && (
          <div style={{ marginTop: 16 }}>
            <h4>Replay detail</h4>
            <div className="actions">
              <button onClick={linkReplayToIssue} disabled={!selectedIssue?.id}>
                Lier à l'issue courante
              </button>
            </div>
            {replayLinks.length > 0 && (
              <div className="table" style={{ marginTop: 12 }}>
                <div className="table-row header">
                  <span>Issue</span>
                  <span>Trace</span>
                  <span>Créé</span>
                </div>
                {replayLinks.map((link, idx) => (
                  <div key={idx} className="table-row">
                    <span>{link.issue_id || "-"}</span>
                    <span>{link.trace_id || "-"}</span>
                    <span>{new Date(link.created_at).toLocaleString()}</span>
                  </div>
                ))}
              </div>
            )}
            {replayTimeline.length > 0 && (
              <div className="table" style={{ marginTop: 12 }}>
                <div className="table-row header">
                  <span>Time</span>
                  <span>Kind</span>
                  <span>Message</span>
                </div>
                {replayTimeline.slice(0, 20).map((item, idx) => (
                  <div key={idx} className="table-row">
                    <span>{new Date(item.timestamp).toLocaleString()}</span>
                    <span>{item.kind}</span>
                    <span className="title">{item.message || "-"}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Trace Explorer</h2>
          <button onClick={loadTraceInsights} disabled={loading || !currentProjectId}>
            Rafraîchir insights
          </button>
        </div>
        <div className="grid">
          <label>
            Trace ID
            <input value={traceIdInput} onChange={(e) => setTraceIdInput(e.target.value)} />
          </label>
          <button onClick={loadTraceExplorer} disabled={!traceIdInput.trim()}>
            Charger trace
          </button>
        </div>
        {traceWaterfall.length > 0 && (
          <div className="table" style={{ marginTop: 12 }}>
            <div className="table-row header">
              <span>Span</span>
              <span>Op</span>
              <span>Duration</span>
              <span>Status</span>
              <span>Start</span>
            </div>
            {traceWaterfall.slice(0, 20).map((span) => (
              <div key={span.span_id} className="table-row">
                <span className="title">{span.span_id}</span>
                <span>{span.op || "-"}</span>
                <span>{Math.round(span.duration_ms)} ms</span>
                <span>{span.status || "-"}</span>
                <span>{new Date(span.start_ts).toLocaleString()}</span>
              </div>
            ))}
          </div>
        )}
        {traceCorrelations && (
          <div className="grid" style={{ marginTop: 12 }}>
            <div>
              <h4>Issues liées</h4>
              {(traceCorrelations.issues || []).map((issue) => (
                <div key={issue.id} className="table-row">
                  <span className="title">{issue.title}</span>
                  <span>{issue.status}</span>
                </div>
              ))}
            </div>
            <div>
              <h4>Replays liés</h4>
              {traceReplayLinks.map((replay) => (
                <div key={replay.id} className="table-row">
                  <span className="title">{replay.session_id}</span>
                  <span>{Math.round(replay.duration_ms)} ms</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {traceTopRegressions.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <h4>Top regressions (24h)</h4>
            {traceTopRegressions.map((row) => (
              <div key={row.id} className="table-row">
                <span className="title">{row.title}</span>
                <span>{row.events_24h}</span>
                <span>{row.last_release || "-"}</span>
              </div>
            ))}
          </div>
        )}
        {traceBreakdown.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <h4>Trace breakdown</h4>
            {traceBreakdown.map((row, idx) => (
              <div key={idx} className="table-row">
                <span className="title">{row.op || "-"}</span>
                <span>{row.count}</span>
                <span>{Math.round(row.p95_ms)} ms p95</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Profiling</h2>
        </div>
        <div className="grid">
          <label>
            Trace ID
            <input value={profileTraceId} onChange={(e) => setProfileTraceId(e.target.value)} />
          </label>
          <button onClick={loadProfiles} disabled={!profileTraceId.trim()}>
            Charger profils
          </button>
        </div>
        {profileHotPaths.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <h4>Hot paths</h4>
            {profileHotPaths.map((item, idx) => (
              <div key={idx} className="table-row">
                <span className="title">{item.frame}</span>
                <span>{item.weight.toFixed(2)}</span>
              </div>
            ))}
          </div>
        )}
        {profileList.length > 0 && (
          <div className="grid" style={{ marginTop: 12 }}>
            <label>
              Base profile
              <select value={profileBaseId} onChange={(e) => setProfileBaseId(e.target.value)}>
                <option value="">—</option>
                {profileList.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.id}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Compare profile
              <select value={profileCompareId} onChange={(e) => setProfileCompareId(e.target.value)}>
                <option value="">—</option>
                {profileList.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.id}
                  </option>
                ))}
              </select>
            </label>
            <button onClick={loadProfileDiff} disabled={!profileBaseId || !profileCompareId}>
              Diff
            </button>
          </div>
        )}
        {profileDiff && (
          <div style={{ marginTop: 12 }}>
            <h4>Profile diff</h4>
            {profileDiff.items?.map((entry, idx) => (
              <div key={idx} className="table-row">
                <span className="title">{entry.frame}</span>
                <span>{entry.delta.toFixed(2)}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Uptime</h2>
          <div className="actions">
            <button onClick={loadUptimeMonitors} disabled={loading || !currentProjectId}>
              Rafraîchir
            </button>
            <button onClick={() => runUptimeMonitor(selectedUptimeMonitorId)} disabled={loading || !selectedUptimeMonitorId}>
              Lancer check
            </button>
          </div>
        </div>
        <div className="grid">
          <label>
            Nom
            <input value={uptimeName} onChange={(e) => setUptimeName(e.target.value)} />
          </label>
          <label>
            URL
            <input value={uptimeUrl} onChange={(e) => setUptimeUrl(e.target.value)} />
          </label>
          <label>
            Interval (min)
            <input value={uptimeInterval} onChange={(e) => setUptimeInterval(e.target.value)} />
          </label>
          <label>
            Expected status
            <input value={uptimeExpected} onChange={(e) => setUptimeExpected(e.target.value)} />
          </label>
          <label>
            Timeout (ms)
            <input value={uptimeTimeout} onChange={(e) => setUptimeTimeout(e.target.value)} />
          </label>
          <button onClick={createUptimeMonitor} disabled={!uptimeName.trim() || !uptimeUrl.trim() || !currentProjectId}>
            Ajouter
          </button>
        </div>
        <div className="table">
          <div className="table-row header uptime-row">
            <span>Nom</span>
            <span>URL</span>
            <span>Status</span>
            <span>Dernier</span>
            <span>Prochain</span>
            <span>Interval</span>
          </div>
          {uptimeMonitors.map((monitor) => (
            <button
              key={monitor.id}
              className="table-row uptime-row"
              onClick={() => {
                setSelectedUptimeMonitorId(monitor.id);
                loadUptimeChecks(monitor.id);
              }}
            >
              <span className="title">{monitor.name}</span>
              <span className="title">{monitor.url}</span>
              <span>{monitor.status}</span>
              <span>{monitor.last_check_at ? new Date(monitor.last_check_at).toLocaleString() : "-"}</span>
              <span>{monitor.next_check_at ? new Date(monitor.next_check_at).toLocaleString() : "-"}</span>
              <span>{monitor.interval_minutes}m</span>
            </button>
          ))}
        </div>
        {selectedUptimeMonitorId && uptimeChecks.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <h4>Derniers checks</h4>
            <div className="table">
              <div className="table-row header uptime-row">
                <span>Status</span>
                <span>Code</span>
                <span>Durée</span>
                <span>Erreur</span>
                <span>Checked at</span>
                <span></span>
              </div>
              {uptimeChecks.map((check) => (
                <div key={check.id} className="table-row uptime-row">
                  <span>{check.status}</span>
                  <span>{check.status_code ?? "-"}</span>
                  <span>{check.duration_ms ? `${check.duration_ms} ms` : "-"}</span>
                  <span className="title">{check.error || "-"}</span>
                  <span>{new Date(check.checked_at).toLocaleString()}</span>
                  <span></span>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <h2>Crons</h2>
          <button onClick={loadCronMonitors} disabled={loading || !currentProjectId}>
            Rafraîchir
          </button>
        </div>
        <div className="grid">
          <label>
            Nom
            <input value={cronName} onChange={(e) => setCronName(e.target.value)} />
          </label>
          <label>
            Schedule (min)
            <input value={cronSchedule} onChange={(e) => setCronSchedule(e.target.value)} />
          </label>
          <label>
            Grace (min)
            <input value={cronGrace} onChange={(e) => setCronGrace(e.target.value)} />
          </label>
          <button onClick={createCronMonitor} disabled={!cronName.trim() || !currentProjectId}>
            Ajouter
          </button>
        </div>
        <div className="table">
          <div className="table-row header cron-row">
            <span>Nom</span>
            <span>Status</span>
            <span>Dernier</span>
            <span>Prochain</span>
          </div>
          {cronMonitors.map((monitor) => (
            <button
              key={monitor.id}
              className="table-row cron-row"
              onClick={() => {
                setSelectedCronMonitorId(monitor.id);
                loadCronCheckins(monitor.id);
              }}
            >
              <span className="title">{monitor.name}</span>
              <span>{monitor.status}</span>
              <span>{monitor.last_checkin_at ? new Date(monitor.last_checkin_at).toLocaleString() : "-"}</span>
              <span>{monitor.next_expected_at ? new Date(monitor.next_expected_at).toLocaleString() : "-"}</span>
            </button>
          ))}
        </div>
        {selectedCronMonitorId && (
          <div style={{ marginTop: 12 }}>
            <div className="actions">
              <button onClick={() => createCronCheckin(selectedCronMonitorId, "ok")} disabled={loading}>
                Check-in OK
              </button>
              <button onClick={() => createCronCheckin(selectedCronMonitorId, "error")} disabled={loading}>
                Check-in Error
              </button>
            </div>
            {cronCheckins.length > 0 && (
              <div className="table" style={{ marginTop: 12 }}>
                <div className="table-row header cron-row">
                  <span>Status</span>
                  <span>Message</span>
                  <span>Checked at</span>
                  <span></span>
                </div>
                {cronCheckins.map((checkin) => (
                  <div key={checkin.id} className="table-row cron-row">
                    <span>{checkin.status}</span>
                    <span className="title">{checkin.message || "-"}</span>
                    <span>{new Date(checkin.checked_in_at).toLocaleString()}</span>
                    <span></span>
                  </div>
                ))}
              </div>
            )}
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
            {issueReplays.length > 0 && (
              <div className="event">
                <div className="event-header">
                  <span>Replays liés</span>
                </div>
                <ul>
                  {issueReplays.map((replay) => (
                    <li key={replay.id}>
                      {replay.session_id} — {new Date(replay.created_at).toLocaleString()}
                    </li>
                  ))}
                </ul>
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
