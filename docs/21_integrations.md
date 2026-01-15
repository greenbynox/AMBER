# Intégrations & Marketplace v1

## Marketplace (catalogue)
Le catalogue est exposé via :
- `GET /integrations`

Il inclut : GitHub, GitLab, Jira, Slack, Teams.

## Intégrations d’organisation (OAuth)
- `GET /orgs/:id/integrations`
- `POST /orgs/:id/integrations`
- `GET /orgs/:id/integrations/:key/oauth/start`
- `GET /integrations/oauth/callback`

Exemple body:
```
{
	"integration_key": "github",
	"config": {
		"webhook_url": "https://example.com/hook"
	},
	"enabled": true
}
```

## Intégrations projet (webhook + GitHub)
- `POST /projects/:id/integrations`

Pour les webhooks v2 (multiples endpoints, signatures, retries):
- `GET /projects/:id/webhooks`
- `POST /projects/:id/webhooks`
- `POST /projects/:id/webhooks/:webhook_id` (delete)
- `GET /projects/:id/webhooks/:webhook_id/deliveries`

Body:
```
{
	"webhook_url": "https://example.com/webhook",
	"slack_webhook_url": "https://hooks.slack.com/...",
	"github_repo": "owner/repo",
	"github_token": "ghp_..."
}
```
