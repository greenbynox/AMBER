ALTER TABLE integrations_catalog ADD COLUMN IF NOT EXISTS oauth_authorize_url TEXT;
ALTER TABLE integrations_catalog ADD COLUMN IF NOT EXISTS oauth_token_url TEXT;
ALTER TABLE integrations_catalog ADD COLUMN IF NOT EXISTS oauth_scopes TEXT;

CREATE TABLE IF NOT EXISTS oauth_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    integration_key TEXT NOT NULL REFERENCES integrations_catalog(key) ON DELETE CASCADE,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, integration_key)
);

CREATE INDEX IF NOT EXISTS idx_oauth_connections_org ON oauth_connections(org_id);
