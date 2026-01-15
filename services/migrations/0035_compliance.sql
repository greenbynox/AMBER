-- Compliance: data requests results + PII policies + secrets encryption support

CREATE TABLE IF NOT EXISTS pii_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    scrub_emails BOOLEAN NOT NULL DEFAULT true,
    scrub_ips BOOLEAN NOT NULL DEFAULT true,
    scrub_secrets BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS data_request_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id UUID NOT NULL REFERENCES data_requests(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_data_request_results_request ON data_request_results(request_id, created_at DESC);
