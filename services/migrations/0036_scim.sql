-- SCIM provisioning: org users mapping

CREATE TABLE IF NOT EXISTS org_users (
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_users_org ON org_users(org_id);
CREATE INDEX IF NOT EXISTS idx_org_users_user ON org_users(user_id);
