-- Grouping overrides
CREATE TABLE IF NOT EXISTS grouping_overrides (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_fingerprint TEXT NOT NULL,
    target_fingerprint TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, source_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_grouping_overrides_project ON grouping_overrides(project_id);
