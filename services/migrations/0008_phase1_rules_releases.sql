CREATE TABLE IF NOT EXISTS grouping_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_grouping_rules_project ON grouping_rules(project_id);

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
    channel TEXT NOT NULL,
    webhook_url TEXT,
    slack_webhook_url TEXT,
    email_to TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_triggered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alert_rules_project ON alert_rules(project_id);
