CREATE TABLE IF NOT EXISTS data_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    subject_email TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    requested_by TEXT,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_data_requests_org ON data_requests(org_id);
CREATE INDEX IF NOT EXISTS idx_data_requests_status ON data_requests(status);
