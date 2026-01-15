CREATE TABLE IF NOT EXISTS sourcemaps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release TEXT NOT NULL,
    minified_url TEXT NOT NULL,
    map_text TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, release, minified_url)
);

CREATE INDEX IF NOT EXISTS idx_sourcemaps_project_release ON sourcemaps(project_id, release);
