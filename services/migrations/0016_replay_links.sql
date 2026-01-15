CREATE TABLE IF NOT EXISTS replay_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    replay_id UUID NOT NULL REFERENCES replays(id) ON DELETE CASCADE,
    issue_id UUID REFERENCES issues(id) ON DELETE SET NULL,
    trace_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_replay_links_project ON replay_links(project_id);
CREATE INDEX IF NOT EXISTS idx_replay_links_issue ON replay_links(issue_id);
CREATE INDEX IF NOT EXISTS idx_replay_links_trace ON replay_links(trace_id);
CREATE INDEX IF NOT EXISTS idx_replay_links_replay ON replay_links(replay_id);
