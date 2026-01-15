-- Full-text search indexes for issues and events
CREATE INDEX IF NOT EXISTS idx_issues_title_fts ON issues USING GIN (to_tsvector('simple', title));
CREATE INDEX IF NOT EXISTS idx_events_text_fts ON events USING GIN (
    to_tsvector('simple', coalesce(message, '') || ' ' || exception_message || ' ' || exception_type)
);
