-- Releases v2: adoption/regressions/suspect commits performance indexes
CREATE INDEX IF NOT EXISTS idx_releases_project_created_at ON releases(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_release_commits_project_release_ts ON release_commits(project_id, release, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_project_release_time ON events(project_id, release, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_issues_project_first_release ON issues(project_id, first_release);
CREATE INDEX IF NOT EXISTS idx_issues_project_last_release_regressed ON issues(project_id, last_release, regressed_at DESC);
