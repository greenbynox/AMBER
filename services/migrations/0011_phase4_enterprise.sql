ALTER TABLE organizations ADD COLUMN IF NOT EXISTS sso_domain TEXT;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS data_region TEXT;

CREATE TABLE IF NOT EXISTS sso_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    saml_metadata TEXT,
    oidc_client_id TEXT,
    oidc_client_secret TEXT,
    oidc_issuer_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id)
);

CREATE TABLE IF NOT EXISTS scim_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS integrations_catalog (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    auth_type TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS org_integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    integration_key TEXT NOT NULL REFERENCES integrations_catalog(key) ON DELETE CASCADE,
    config JSONB,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, integration_key)
);

INSERT INTO integrations_catalog (key, name, category, description, auth_type)
VALUES
    ('github', 'GitHub', 'code', 'Sync issues and link commits/releases', 'token'),
    ('jira', 'Jira', 'pm', 'Create and sync issues in Jira', 'token'),
    ('slack', 'Slack', 'chat', 'Send alerts and issue updates to Slack', 'webhook'),
    ('teams', 'Microsoft Teams', 'chat', 'Send alerts and issue updates to Teams', 'webhook')
ON CONFLICT (key) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_sso_configs_org ON sso_configs(org_id);
CREATE INDEX IF NOT EXISTS idx_scim_tokens_org ON scim_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_org_integrations_org ON org_integrations(org_id);
