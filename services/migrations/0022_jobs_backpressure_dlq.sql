ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS project_id TEXT,
    ADD COLUMN IF NOT EXISTS max_attempts INT NOT NULL DEFAULT 5,
    ADD COLUMN IF NOT EXISTS dead_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_jobs_project_status ON jobs(project_id, status);
CREATE INDEX IF NOT EXISTS idx_jobs_dead_at ON jobs(dead_at DESC);