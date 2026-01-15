ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS rate_limit_per_min INT,
    ADD COLUMN IF NOT EXISTS quota_soft_limit BIGINT,
    ADD COLUMN IF NOT EXISTS quota_hard_limit BIGINT;

CREATE TABLE IF NOT EXISTS project_usage_daily (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, day)
);

CREATE INDEX IF NOT EXISTS idx_project_usage_project_day ON project_usage_daily(project_id, day DESC);