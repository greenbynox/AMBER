-- Top regressions indexes
CREATE INDEX IF NOT EXISTS idx_issues_project_regressed_at ON issues(project_id, regressed_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_issue_time_desc ON events(issue_id, occurred_at DESC);
