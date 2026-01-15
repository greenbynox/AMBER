-- Marketplace v1 catalog seed (OAuth + webhook providers)
INSERT INTO integrations_catalog (key, name, category, description, auth_type, oauth_authorize_url, oauth_token_url, oauth_scopes, enabled)
VALUES
    ('github', 'GitHub', 'scm', 'Créer et lier des issues GitHub', 'oauth', 'https://github.com/login/oauth/authorize', 'https://github.com/login/oauth/access_token', 'repo', true),
    ('gitlab', 'GitLab', 'scm', 'Créer et lier des issues GitLab', 'oauth', 'https://gitlab.com/oauth/authorize', 'https://gitlab.com/oauth/token', 'api', true),
    ('jira', 'Jira', 'issue-tracker', 'Créer et lier des tickets Jira', 'oauth', 'https://auth.atlassian.com/authorize', 'https://auth.atlassian.com/oauth/token', 'read:jira-work write:jira-work', true),
    ('slack', 'Slack', 'chat', 'Notifications Slack (OAuth)', 'oauth', 'https://slack.com/oauth/v2/authorize', 'https://slack.com/api/oauth.v2.access', 'chat:write,channels:read', true),
    ('teams', 'Microsoft Teams', 'chat', 'Notifications Teams via webhook entrant', 'webhook', NULL, NULL, NULL, true)
ON CONFLICT (key) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    description = EXCLUDED.description,
    auth_type = EXCLUDED.auth_type,
    oauth_authorize_url = EXCLUDED.oauth_authorize_url,
    oauth_token_url = EXCLUDED.oauth_token_url,
    oauth_scopes = EXCLUDED.oauth_scopes,
    enabled = EXCLUDED.enabled;
