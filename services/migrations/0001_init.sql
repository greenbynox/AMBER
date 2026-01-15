CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    api_key TEXT NOT NULL UNIQUE,
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
    UNIQUE(project_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY,
    issue_id UUID NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    occurred_at TIMESTAMPTZ NOT NULL,
    level TEXT NOT NULL,
    message TEXT,
    exception_type TEXT NOT NULL,
    exception_message TEXT NOT NULL,
    stacktrace JSONB,
    context JSONB,
    sdk JSONB,
    raw JSONB
);

CREATE INDEX IF NOT EXISTS idx_events_issue_time ON events(issue_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_issues_project_last_seen ON issues(project_id, last_seen DESC);
