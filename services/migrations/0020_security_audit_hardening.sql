ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS ip TEXT,
    ADD COLUMN IF NOT EXISTS user_agent TEXT,
    ADD COLUMN IF NOT EXISTS request_id TEXT;

ALTER TABLE api_tokens
    ADD COLUMN IF NOT EXISTS created_by TEXT,
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS api_key_last_used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS api_key_rotated_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_api_tokens_revoked_at ON api_tokens(revoked_at);
CREATE INDEX IF NOT EXISTS idx_api_tokens_last_used ON api_tokens(last_used_at DESC);
CREATE INDEX IF NOT EXISTS idx_projects_api_key_last_used ON projects(api_key_last_used_at DESC);