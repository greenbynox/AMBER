-- EMBER minimal PostgreSQL schema
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    api_key TEXT NOT NULL UNIQUE,
    webhook_url TEXT,
    slack_webhook_url TEXT,
    github_repo TEXT,
    github_token TEXT,
    api_key_last_used_at TIMESTAMPTZ,
    api_key_rotated_at TIMESTAMPTZ,
    rate_limit_per_min INT,
    quota_soft_limit BIGINT,
    quota_hard_limit BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    sso_domain TEXT,
    data_region TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS teams (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS org_users (
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS team_memberships (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS project_teams (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, team_id)
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'member',
    created_by TEXT,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    payload JSONB,
    ip TEXT,
    user_agent TEXT,
    request_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    last_error TEXT,
    run_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    dead_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS issues (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    level TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    count_total BIGINT NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open',
    assignee TEXT,
    first_release TEXT,
    last_release TEXT,
    regressed_at TIMESTAMPTZ,
    last_user_id TEXT,
    last_user_email TEXT,
    github_issue_url TEXT,
    UNIQUE(project_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY,
    issue_id UUID NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    occurred_at TIMESTAMPTZ NOT NULL,
    level TEXT NOT NULL,
    release TEXT,
    user_id TEXT,
    user_email TEXT,
    message TEXT,
    exception_type TEXT NOT NULL,
    exception_message TEXT NOT NULL,
    stacktrace JSONB,
    context JSONB,
    sdk JSONB,
    raw JSONB,
    schema_version TEXT NOT NULL DEFAULT 'v1',
    storage_tier TEXT NOT NULL DEFAULT 'hot'
);

CREATE TABLE IF NOT EXISTS sourcemaps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release TEXT NOT NULL,
    minified_url TEXT NOT NULL,
    map_text TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, release, minified_url)
);

CREATE TABLE IF NOT EXISTS grouping_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS grouping_overrides (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_fingerprint TEXT NOT NULL,
    target_fingerprint TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, source_fingerprint)
);

CREATE TABLE IF NOT EXISTS releases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    commit_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, version)
);

CREATE TABLE IF NOT EXISTS release_commits (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    message TEXT,
    author TEXT,
    timestamp TIMESTAMPTZ,
    PRIMARY KEY (project_id, release, commit_sha)
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'event_rate',
    threshold INT NOT NULL,
    window_minutes INT NOT NULL DEFAULT 5,
    cooldown_minutes INT NOT NULL DEFAULT 0,
    max_triggers_per_day INT NOT NULL DEFAULT 0,
    threshold_multiplier DOUBLE PRECISION,
    baseline_minutes INT,
    channel TEXT NOT NULL,
    webhook_url TEXT,
    slack_webhook_url TEXT,
    email_to TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alert_silences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES alert_rules(id) ON DELETE CASCADE,
    reason TEXT,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alert_rule_triggers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ok',
    duration_ms DOUBLE PRECISION NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    tags JSONB,
    measurements JSONB,
    storage_tier TEXT NOT NULL DEFAULT 'hot'
);

CREATE TABLE IF NOT EXISTS spans (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    parent_id TEXT,
    op TEXT,
    description TEXT,
    status TEXT,
    start_ts TIMESTAMPTZ NOT NULL,
    duration_ms DOUBLE PRECISION NOT NULL,
    tags JSONB,
    PRIMARY KEY (project_id, span_id)
);

CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    trace_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    profile JSONB NOT NULL,
    storage_tier TEXT NOT NULL DEFAULT 'hot'
);

CREATE TABLE IF NOT EXISTS replays (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    duration_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
    url TEXT,
    user_id TEXT,
    user_email TEXT,
    breadcrumbs JSONB,
    events JSONB,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    storage_tier TEXT NOT NULL DEFAULT 'hot'
);

CREATE TABLE IF NOT EXISTS issue_insights (
    issue_id UUID PRIMARY KEY REFERENCES issues(id) ON DELETE CASCADE,
    summary TEXT NOT NULL,
    culprit TEXT,
    last_release TEXT,
    regressed_at TIMESTAMPTZ,
    causal_chain JSONB,
    regression_map JSONB,
    confidence DOUBLE PRECISION,
    published BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rca_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    min_confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS analysis_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    kind TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    rolled_back_to UUID,
    deployed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(kind, version)
);

CREATE TABLE IF NOT EXISTS reprocess_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    issue_id UUID REFERENCES issues(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    target_version TEXT,
    range_start TIMESTAMPTZ,
    range_end TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS grouping_decisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    issue_id UUID NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS grouping_rules_applied (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    decision_id UUID NOT NULL REFERENCES grouping_decisions(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES grouping_rules(id) ON DELETE CASCADE,
    rule_name TEXT NOT NULL,
    matched BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS signal_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    correlation_score DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, source_type, source_id, target_type, target_id)
);

CREATE TABLE IF NOT EXISTS cost_units (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    entity_id UUID NOT NULL,
    kind TEXT NOT NULL,
    units DOUBLE PRECISION NOT NULL,
    storage_bytes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project_cost_daily (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    units DOUBLE PRECISION NOT NULL DEFAULT 0,
    storage_bytes BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, day)
);

CREATE TABLE IF NOT EXISTS ingest_drops_daily (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    reason TEXT NOT NULL,
    count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, day, reason)
);

CREATE TABLE IF NOT EXISTS assignment_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    assignee TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sso_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    saml_metadata TEXT,
    oidc_client_id TEXT,
    oidc_client_secret TEXT,
    oidc_issuer_url TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    enforce_domain BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id)
);

CREATE TABLE IF NOT EXISTS scim_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS integrations_catalog (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    auth_type TEXT NOT NULL,
    oauth_authorize_url TEXT,
    oauth_token_url TEXT,
    oauth_scopes TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS org_integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    integration_key TEXT NOT NULL REFERENCES integrations_catalog(key) ON DELETE CASCADE,
    config JSONB,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, integration_key)
);

CREATE TABLE IF NOT EXISTS oauth_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    integration_key TEXT NOT NULL REFERENCES integrations_catalog(key) ON DELETE CASCADE,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, integration_key)
);

CREATE TABLE IF NOT EXISTS saved_queries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    query TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ownership_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    owner TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS replay_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    replay_id UUID NOT NULL REFERENCES replays(id) ON DELETE CASCADE,
    issue_id UUID REFERENCES issues(id) ON DELETE SET NULL,
    trace_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS data_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    subject_email TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    requested_by TEXT,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pii_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    scrub_emails BOOLEAN NOT NULL DEFAULT true,
    scrub_ips BOOLEAN NOT NULL DEFAULT true,
    scrub_secrets BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS data_request_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id UUID NOT NULL REFERENCES data_requests(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sampling_rules (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    target_events_per_min INT NOT NULL DEFAULT 0,
    min_rate DOUBLE PRECISION NOT NULL DEFAULT 0.1,
    max_rate DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sla_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    sla_minutes INT NOT NULL DEFAULT 1440,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS slo_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    target_error_rate DOUBLE PRECISION NOT NULL DEFAULT 0.01,
    window_minutes INT NOT NULL DEFAULT 1440,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS storage_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    hot_days INT NOT NULL DEFAULT 30,
    cold_days INT NOT NULL DEFAULT 365,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    status_code INT,
    error TEXT,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS uptime_monitors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    expected_status INT NOT NULL DEFAULT 200,
    timeout_ms INT NOT NULL DEFAULT 5000,
    interval_minutes INT NOT NULL DEFAULT 5,
    headers JSONB,
    enabled BOOLEAN NOT NULL DEFAULT true,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_check_at TIMESTAMPTZ,
    next_check_at TIMESTAMPTZ,
    last_duration_ms INT,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS uptime_checks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    monitor_id UUID NOT NULL REFERENCES uptime_monitors(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    status_code INT,
    duration_ms INT,
    error TEXT,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cron_monitors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    schedule_minutes INT NOT NULL DEFAULT 60,
    grace_minutes INT NOT NULL DEFAULT 5,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    enabled BOOLEAN NOT NULL DEFAULT true,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_checkin_at TIMESTAMPTZ,
    next_expected_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cron_checkins (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    monitor_id UUID NOT NULL REFERENCES cron_monitors(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    message TEXT,
    checked_in_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project_usage_daily (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, day)
);

CREATE TABLE IF NOT EXISTS regions (
    name TEXT PRIMARY KEY,
    api_base_url TEXT NOT NULL,
    ingest_url TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_issue_time ON events(issue_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_issues_project_last_seen ON issues(project_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_issues_regressed_at ON issues(regressed_at DESC);
CREATE INDEX IF NOT EXISTS idx_sourcemaps_project_release ON sourcemaps(project_id, release);
CREATE INDEX IF NOT EXISTS idx_jobs_status_run_at ON jobs(status, run_at);
CREATE INDEX IF NOT EXISTS idx_jobs_project_status ON jobs(project_id, status);
CREATE INDEX IF NOT EXISTS idx_jobs_dead_at ON jobs(dead_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_tokens_revoked_at ON api_tokens(revoked_at);
CREATE INDEX IF NOT EXISTS idx_api_tokens_last_used ON api_tokens(last_used_at DESC);
CREATE INDEX IF NOT EXISTS idx_projects_api_key_last_used ON projects(api_key_last_used_at DESC);
CREATE INDEX IF NOT EXISTS idx_org_users_org ON org_users(org_id);
CREATE INDEX IF NOT EXISTS idx_org_users_user ON org_users(user_id);
CREATE INDEX IF NOT EXISTS idx_grouping_rules_project ON grouping_rules(project_id);
CREATE INDEX IF NOT EXISTS idx_grouping_overrides_project ON grouping_overrides(project_id);
CREATE INDEX IF NOT EXISTS idx_alert_rules_project ON alert_rules(project_id);
CREATE INDEX IF NOT EXISTS idx_alert_silences_project ON alert_silences(project_id, starts_at, ends_at);
CREATE INDEX IF NOT EXISTS idx_alert_silences_rule ON alert_silences(rule_id, starts_at, ends_at);
CREATE INDEX IF NOT EXISTS idx_alert_rule_triggers_rule ON alert_rule_triggers(rule_id, triggered_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_project_time ON transactions(project_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_project_name ON transactions(project_id, name);
CREATE INDEX IF NOT EXISTS idx_transactions_trace ON transactions(project_id, trace_id);
CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(project_id, trace_id);
CREATE INDEX IF NOT EXISTS idx_profiles_trace ON profiles(project_id, trace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_replays_project_time ON replays(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_replays_session ON replays(project_id, session_id);
CREATE INDEX IF NOT EXISTS idx_assignment_rules_project ON assignment_rules(project_id);
CREATE INDEX IF NOT EXISTS idx_analysis_versions_kind ON analysis_versions(kind, deployed_at DESC);
CREATE INDEX IF NOT EXISTS idx_reprocess_jobs_status ON reprocess_jobs(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reprocess_jobs_project ON reprocess_jobs(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_grouping_decisions_event ON grouping_decisions(event_id);
CREATE INDEX IF NOT EXISTS idx_grouping_decisions_issue ON grouping_decisions(issue_id);
CREATE INDEX IF NOT EXISTS idx_signal_links_source ON signal_links(project_id, source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_signal_links_target ON signal_links(project_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_cost_units_project_time ON cost_units(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cost_units_entity ON cost_units(entity_id);
CREATE INDEX IF NOT EXISTS idx_project_cost_daily_project_day ON project_cost_daily(project_id, day DESC);
CREATE INDEX IF NOT EXISTS idx_ingest_drops_project_day ON ingest_drops_daily(project_id, day DESC);
CREATE INDEX IF NOT EXISTS idx_sso_configs_org ON sso_configs(org_id);
CREATE INDEX IF NOT EXISTS idx_scim_tokens_org ON scim_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_org_integrations_org ON org_integrations(org_id);
CREATE INDEX IF NOT EXISTS idx_oauth_connections_org ON oauth_connections(org_id);
CREATE INDEX IF NOT EXISTS idx_saved_queries_project ON saved_queries(project_id);
CREATE INDEX IF NOT EXISTS idx_ownership_rules_project ON ownership_rules(project_id);
CREATE INDEX IF NOT EXISTS idx_replay_links_project ON replay_links(project_id);
CREATE INDEX IF NOT EXISTS idx_replay_links_issue ON replay_links(issue_id);
CREATE INDEX IF NOT EXISTS idx_replay_links_trace ON replay_links(trace_id);
CREATE INDEX IF NOT EXISTS idx_replay_links_replay ON replay_links(replay_id);
CREATE INDEX IF NOT EXISTS idx_rca_policies_project ON rca_policies(project_id);
CREATE INDEX IF NOT EXISTS idx_data_requests_org ON data_requests(org_id);
CREATE INDEX IF NOT EXISTS idx_data_requests_status ON data_requests(status);
CREATE INDEX IF NOT EXISTS idx_data_request_results_request ON data_request_results(request_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_project_usage_project_day ON project_usage_daily(project_id, day DESC);
CREATE INDEX IF NOT EXISTS idx_sla_policies_project ON sla_policies(project_id);
CREATE INDEX IF NOT EXISTS idx_slo_policies_project ON slo_policies(project_id);
CREATE INDEX IF NOT EXISTS idx_releases_project_created_at ON releases(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_release_commits_project_release_ts ON release_commits(project_id, release, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_project_release_time ON events(project_id, release, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_issues_project_first_release ON issues(project_id, first_release);
CREATE INDEX IF NOT EXISTS idx_issues_project_last_release_regressed ON issues(project_id, last_release, regressed_at DESC);
CREATE INDEX IF NOT EXISTS idx_issues_title_fts ON issues USING GIN (to_tsvector('simple', title));
CREATE INDEX IF NOT EXISTS idx_events_text_fts ON events USING GIN (to_tsvector('simple', coalesce(message, '') || ' ' || exception_message || ' ' || exception_type));
CREATE INDEX IF NOT EXISTS idx_spans_project_trace_start ON spans(project_id, trace_id, start_ts ASC);
CREATE INDEX IF NOT EXISTS idx_transactions_project_trace_time ON transactions(project_id, trace_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_replay_links_project_trace ON replay_links(project_id, trace_id);
CREATE INDEX IF NOT EXISTS idx_issues_project_regressed_at ON issues(project_id, regressed_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_issue_time_desc ON events(issue_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_project_created_at ON profiles(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_replays_project_started_at ON replays(project_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_sampling_rules_project ON sampling_rules(project_id);
CREATE INDEX IF NOT EXISTS idx_events_storage_tier ON events(project_id, storage_tier, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_replays_storage_tier ON replays(project_id, storage_tier, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_storage_tier ON profiles(project_id, storage_tier, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_storage_tier ON transactions(project_id, storage_tier, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_storage_policies_project ON storage_policies(project_id);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_project ON webhook_endpoints(project_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint ON webhook_deliveries(endpoint_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_uptime_monitors_project ON uptime_monitors(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_uptime_monitors_next_check ON uptime_monitors(next_check_at ASC);
CREATE INDEX IF NOT EXISTS idx_uptime_checks_monitor ON uptime_checks(monitor_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_cron_monitors_project ON cron_monitors(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cron_monitors_next_expected ON cron_monitors(next_expected_at ASC);
CREATE INDEX IF NOT EXISTS idx_cron_checkins_monitor ON cron_checkins(monitor_id, checked_in_at DESC);
