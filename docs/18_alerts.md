# Alerts

## Webhooks (issue events)
Admin endpoint:
`POST /projects/:id/webhook`

Body:
```
{ "url": "https://example.com/webhook" }
```

Events sent:
- `new_issue`
- `regression`

Payload:
```
{
  "kind": "new_issue",
  "project_id": "demo",
  "issue_id": "...",
  "fingerprint": "...",
  "title": "..."
}
```

## Alert rules (event rate)
Create a rule:
`POST /projects/:id/alert-rules`

Body:
```
{
  "name": "High error rate",
  "kind": "event_rate",
  "threshold": 50,
  "window_minutes": 5,
  "cooldown_minutes": 30,
  "max_triggers_per_day": 10,
  "threshold_multiplier": 2.5,
  "baseline_minutes": 60,
  "channel": "webhook",
  "webhook_url": "https://example.com/hook"
}
```

Notes:
- `cooldown_minutes` enforces fatigue control (minimum time between triggers).
- `max_triggers_per_day` caps daily triggers (0 disables the cap).
- `threshold_multiplier` + `baseline_minutes` enables dynamic thresholds based on recent baseline volume.

## Alert rule kinds (drift)
Additional kinds are supported for algorithm drift:

- `grouping_default_rate` — triggers when the percentage of grouping decisions with `reason=default` exceeds `threshold` (0–100).
- `rca_avg_confidence_below` — triggers when average RCA confidence drops below `threshold` (0–100).

Example:
```
{
  "name": "Grouping drift",
  "kind": "grouping_default_rate",
  "threshold": 85,
  "window_minutes": 60,
  "cooldown_minutes": 120,
  "max_triggers_per_day": 3,
  "channel": "slack",
  "slack_webhook_url": "https://hooks.slack.com/services/..."
}
```

## Alert silences
Create a silence:
`POST /projects/:id/alert-silences`

Body:
```
{
  "rule_id": "<alert_rule_uuid>",
  "reason": "maintenance",
  "starts_at": "2024-01-01T00:00:00Z",
  "ends_at": "2024-01-01T06:00:00Z"
}
```

`rule_id` is optional. If omitted, the silence applies to all alert rules in the project.

## Email (optional)
Variables:
- `SMTP_HOST`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM`
- `SMTP_TO`

If configured, EMBER sends an email for `new_issue`, `regression`, and alert rules.
