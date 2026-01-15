ALTER TABLE issue_insights
    ADD COLUMN IF NOT EXISTS published BOOLEAN NOT NULL DEFAULT true;

CREATE TABLE IF NOT EXISTS rca_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    min_confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rca_policies_project ON rca_policies(project_id);
