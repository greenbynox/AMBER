CREATE TABLE IF NOT EXISTS ingest_drops_daily (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    reason TEXT NOT NULL,
    count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, day, reason)
);

CREATE INDEX IF NOT EXISTS idx_ingest_drops_project_day ON ingest_drops_daily(project_id, day DESC);
