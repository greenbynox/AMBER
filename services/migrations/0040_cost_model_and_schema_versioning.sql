ALTER TABLE events
    ADD COLUMN IF NOT EXISTS schema_version TEXT NOT NULL DEFAULT 'v1';

CREATE TABLE IF NOT EXISTS cost_units (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    entity_id UUID NOT NULL,
    kind TEXT NOT NULL,
    units DOUBLE PRECISION NOT NULL,
    storage_bytes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project_cost_daily (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    units DOUBLE PRECISION NOT NULL DEFAULT 0,
    storage_bytes BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, day)
);

CREATE INDEX IF NOT EXISTS idx_cost_units_project_time ON cost_units(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cost_units_entity ON cost_units(entity_id);
CREATE INDEX IF NOT EXISTS idx_project_cost_daily_project_day ON project_cost_daily(project_id, day DESC);
