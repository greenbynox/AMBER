# Marketplace v1 (PR‑022)

## Objectif
Catalogue d’intégrations avec OAuth et webhooks pour GitHub, GitLab, Jira, Slack et Teams.

## Catalogue
`GET /integrations`

Chaque entrée contient : `key`, `name`, `category`, `description`, `auth_type`, `oauth_authorize_url`, `oauth_scopes`.

## Connexions OAuth
1. Démarrer : `GET /orgs/:id/integrations/:key/oauth/start`
2. Callback : `GET /integrations/oauth/callback`

## Notes
- Teams est en mode webhook entrant (pas d’OAuth).
- Les intégrations sont activables/désactivables par organisation.
