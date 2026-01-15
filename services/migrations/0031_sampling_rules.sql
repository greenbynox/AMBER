-- Adaptive sampling rules
CREATE TABLE IF NOT EXISTS sampling_rules (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    target_events_per_min INT NOT NULL DEFAULT 0,
    min_rate DOUBLE PRECISION NOT NULL DEFAULT 0.1,
    max_rate DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);