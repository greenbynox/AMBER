# API (MVP)

## Ingestion
- `POST /ingest` (ingest service)
- `POST /ingest/transaction`
- `POST /ingest/profile`
- `POST /ingest/replay`

## Observability
- `GET /metrics` (Prometheus counters for ingestion + API)

## Rate limit
Ingestion endpoints return:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`

## Quotas
Ingestion endpoints also return:
- `X-Quota-Limit`
- `X-Quota-Remaining`
- `X-Quota-Reset`
- `X-Quota-Status` (`ok` | `soft` | `hard`)

## Read
- `GET /issues` (issue list)
- `GET /issues/stats` (dashboard counters)
- `POST /issues/bulk` (bulk status/assignee)
- `GET /issues/:id` (issue detail)
- `GET /issues/:id/insights` (RCA assistant)
- `GET /issues/:id/events` (latest events)
- `POST /issues/:id/status` (open | resolved | ignored)
- `POST /issues/:id/assign` (assignee)
- `GET /events/:id` (event detail)
- `GET /discover/events` (free event filtering + cursor pagination)
- `GET /discover/stats` (aggregations: level | release | exception_type)
- `GET /issues/:id/replays`
- `GET /replays/:id/links`
- `GET /traces/:trace_id/replays`
- `GET /replays/:id/timeline`
- `GET /replays/:id/scrubbed`
- `POST /replays/:id/link`
- `GET /traces/:trace_id/waterfall`
- `GET /traces/:trace_id/correlations`
- `GET /traces/top-regressions`
- `GET /traces/service-map`
- `GET /traces/breakdown`

## Admin (projects)
- `GET /projects`
- `POST /projects`
- `GET /projects/:id`
- `POST /projects/:id/rotate-key`
- `POST /projects/:id/webhook`
- `POST /projects/:id/integrations`
- `GET /projects/:id/webhooks`
- `POST /projects/:id/webhooks`
- `POST /projects/:id/webhooks/:webhook_id` (delete)
- `GET /projects/:id/webhooks/:webhook_id/deliveries`
- `GET /projects/:id/sampling`
- `POST /projects/:id/sampling`
- `GET /projects/:id/cost`
- `GET /projects/:id/cost/daily`
- `GET /projects/:id/rca/stats`
- `GET /projects/:id/rca-policy`
- `POST /projects/:id/rca-policy`
- `GET /projects/:id/ingest/drops`
- `GET /projects/:id/pii-policy`
- `POST /projects/:id/pii-policy`
- `GET /projects/:id/sla-policy`
- `POST /projects/:id/sla-policy`
- `GET /projects/:id/sla-report`
- `GET /projects/:id/slo`
- `POST /projects/:id/slo`
- `GET /projects/:id/slo/report`
- `GET /projects/:id/storage-policy`
- `POST /projects/:id/storage-policy`
- `POST /projects/:id/storage-tier/run`
- `GET /projects/:id/releases`
- `POST /projects/:id/releases`
- `GET /projects/:id/releases/:version`
- `POST /projects/:id/releases/:version/commits`
- `GET /projects/:id/releases/:version/regressions`
- `GET /projects/:id/releases/:version/suspect-commits`
- `GET /projects/:id/alert-rules`
- `POST /projects/:id/alert-rules`
- `GET /projects/:id/alert-silences`
- `POST /projects/:id/alert-silences`
- `POST /projects/:id/alert-silences/:silence_id` (delete)
- `GET /projects/:id/saved-queries`
- `POST /projects/:id/saved-queries`
- `GET /projects/:id/saved-queries/:query_id`
- `DELETE /projects/:id/saved-queries/:query_id`
- `GET /projects/:id/grouping-overrides`
- `POST /projects/:id/grouping-overrides`
- `POST /projects/:id/grouping-overrides/:override_id` (delete)
- `GET /projects/:id/grouping/decisions/stats`
- `GET /projects/:id/grouping/decisions`
- `GET /projects/:id/grouping/decisions/:decision_id/rules`
- `GET /projects/:id/ownership-rules`
- `POST /projects/:id/ownership-rules`

## Enterprise (SSO)
- `GET /orgs/:id/sso`
- `POST /orgs/:id/sso`
- `POST /orgs/:id/sso/validate`
- `POST /orgs/:id/scim-token`
- `GET /scim/v2/Users`
- `POST /scim/v2/Users`
- `GET /scim/v2/Users/:id`
- `PUT /scim/v2/Users/:id`
- `DELETE /scim/v2/Users/:id`
- `GET /scim/v2/Groups`
- `POST /scim/v2/Groups`
- `GET /scim/v2/Groups/:id`
- `PUT /scim/v2/Groups/:id`
- `DELETE /scim/v2/Groups/:id`

## Integrations
- `GET /integrations` (catalog)
- `GET /orgs/:id/integrations`
- `POST /orgs/:id/integrations`
- `POST /orgs/:id/integrations/:key/test`
- `GET /orgs/:id/integrations/:key/oauth/start`
- `GET /integrations/oauth/callback`

## Compliance
- `GET /orgs/:id/data-requests`
- `POST /orgs/:id/data-requests`
- `POST /data-requests/:id/complete`
- `POST /data-requests/:id/run`
- `GET /data-requests/:id/results`

## Multi‑region
- `GET /regions`
- `POST /orgs/:id` (field `data_region`)
- `GET /routing` (résolution région par projet)

## Sourcemaps
- `POST /sourcemaps`

## Profiling
- `GET /profiles/:trace_id`
- `GET /profiles/:trace_id/list`
- `GET /profiles/:trace_id/hot-paths`
- `GET /profiles/:trace_id/diff`

## SPA
- `GET /app`

## Search
- `GET /search/issues?query=...`
- `GET /search/issues/v2?query=...&limit=...&before=...&window_minutes=...` (full-text + facettes)

## Auth (MVP)
Requires headers:
- `x-ember-project`
- `x-ember-key`

Admin endpoints require:
- `x-ember-admin` (equals `EMBER_SECRET`)
Optional hardening:
- `ADMIN_ALLOWED_IPS` (comma-separated IPs/CIDRs) restricts admin access by IP.
- `ADMIN_TOTP_SECRET` enables 2FA and requires header `x-ember-otp` (6-digit TOTP).

## Auth JWT (team tokens)
- Team tokens can be used as **Bearer JWT**.
- Header: `Authorization: Bearer <jwt>`
- The JWT is signed with `EMBER_JWT_SECRET`.
- `POST /teams/:id/tokens` now returns a `jwt` field (optional) with the role.
- `POST /teams/:id/tokens/:token_id/revoke` revokes a team token (admin).

### Roles & scopes
- Supported roles: `member`, `admin`, `owner`.
- Scopes derived from role:
	- `member` → `project:read`, `project:triage`
	- `admin` → `project:read`, `project:triage`, `project:write`, `project:admin`
	- `owner` → `project:read`, `project:triage`, `project:write`, `project:admin`, `org:admin`

### Enforcement (project)
- `project:triage` required for `POST /issues/:id/status` and `POST /issues/:id/assign`.
- `project:write` required for `POST /sourcemaps` and `POST /projects/:id/saved-queries`.

## Audit log
- Audit entries include `ip`, `user_agent`, and `request_id` when available.

## Pagination
`GET /issues` accepts:
- `limit` (max 200)
- `before` (RFC3339)
Response: `next_before`

`GET /issues/stats` accepts:
- `window_minutes` (default 1440)
- `sla_minutes` (default 1440)
Response includes `by_status`, `by_level`, `by_assignee`, `open_issues`, `sla_breaches`.

`POST /issues/bulk` body:
```json
{
	"issue_ids": ["uuid", "uuid"],
	"status": "open|resolved|ignored",
	"assignee": "user@acme.tld"
}
```

`GET /discover/events` accepts:
- `cursor` (format: `RFC3339|event_id`)
- `limit` (max 200)
Response: `next_cursor`

Discover filters:
- `q` free text (title/message/exception)
- `saved_query_id`
- `level`, `release`, `exception_type`, `user`, `issue_id`

## Issue response (detail)
Includes:
- issue metadata (status, count_total, first/last seen)
- latest event (message, exception, stacktrace)

## Issue insights (RCA assistant)
`GET /issues/:id/insights` returns:
- `summary`
- `culprit`
- `last_release`, `regressed_at`
- `causal_chain` (ordered frames)
- `regression_map` (release window + suspect commits)
- `confidence` (0–1 heuristic)
