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
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_replays_project_time ON replays(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_replays_session ON replays(project_id, session_id);

CREATE TABLE IF NOT EXISTS issue_insights (
    issue_id UUID PRIMARY KEY REFERENCES issues(id) ON DELETE CASCADE,
    summary TEXT NOT NULL,
    culprit TEXT,
    last_release TEXT,
    regressed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
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

CREATE INDEX IF NOT EXISTS idx_assignment_rules_project ON assignment_rules(project_id);
