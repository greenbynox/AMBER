CREATE TABLE IF NOT EXISTS analysis_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    kind TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    rolled_back_to UUID,
    deployed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(kind, version)
);

CREATE TABLE IF NOT EXISTS reprocess_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    issue_id UUID REFERENCES issues(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    target_version TEXT,
    range_start TIMESTAMPTZ,
    range_end TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS grouping_decisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    issue_id UUID NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS grouping_rules_applied (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    decision_id UUID NOT NULL REFERENCES grouping_decisions(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES grouping_rules(id) ON DELETE CASCADE,
    rule_name TEXT NOT NULL,
    matched BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS signal_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    correlation_score DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(project_id, source_type, source_id, target_type, target_id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_versions_kind ON analysis_versions(kind, deployed_at DESC);
CREATE INDEX IF NOT EXISTS idx_reprocess_jobs_status ON reprocess_jobs(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reprocess_jobs_project ON reprocess_jobs(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_grouping_decisions_event ON grouping_decisions(event_id);
CREATE INDEX IF NOT EXISTS idx_grouping_decisions_issue ON grouping_decisions(issue_id);
CREATE INDEX IF NOT EXISTS idx_signal_links_source ON signal_links(project_id, source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_signal_links_target ON signal_links(project_id, target_type, target_id);
