-- Replay UX v2 indexes
CREATE INDEX IF NOT EXISTS idx_replays_project_started_at ON replays(project_id, started_at DESC);
