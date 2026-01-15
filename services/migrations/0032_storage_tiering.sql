-- Storage tiering
ALTER TABLE events ADD COLUMN IF NOT EXISTS storage_tier TEXT NOT NULL DEFAULT 'hot';
ALTER TABLE replays ADD COLUMN IF NOT EXISTS storage_tier TEXT NOT NULL DEFAULT 'hot';
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS storage_tier TEXT NOT NULL DEFAULT 'hot';
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS storage_tier TEXT NOT NULL DEFAULT 'hot';

CREATE TABLE IF NOT EXISTS storage_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    hot_days INT NOT NULL DEFAULT 30,
    cold_days INT NOT NULL DEFAULT 365,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_storage_tier ON events(project_id, storage_tier, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_replays_storage_tier ON replays(project_id, storage_tier, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_storage_tier ON profiles(project_id, storage_tier, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_storage_tier ON transactions(project_id, storage_tier, occurred_at DESC);
