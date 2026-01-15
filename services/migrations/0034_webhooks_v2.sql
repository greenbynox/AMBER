-- Webhooks v2 (retry/signature/dashboard)
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    status_code INT,
    error TEXT,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_project ON webhook_endpoints(project_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint ON webhook_deliveries(endpoint_id, created_at DESC);
