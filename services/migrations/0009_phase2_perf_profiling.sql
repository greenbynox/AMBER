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
    measurements JSONB
);

CREATE INDEX IF NOT EXISTS idx_transactions_project_time ON transactions(project_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_project_name ON transactions(project_id, name);
CREATE INDEX IF NOT EXISTS idx_transactions_trace ON transactions(project_id, trace_id);

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

CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(project_id, trace_id);

CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    trace_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    profile JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_profiles_trace ON profiles(project_id, trace_id, created_at DESC);
