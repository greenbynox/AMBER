# Replay UX v2

## Endpoints
### Timeline
`GET /replays/:id/timeline`

Réponse:
- `items[]` triés par timestamp (`breadcrumbs` + `events`).

### Scrub PII
`GET /replays/:id/scrubbed`

Masque emails, IPs et clés sensibles (`password`, `token`, `secret`).

### Lier replay → issue/trace
`POST /replays/:id/link`

Body:
```
{ "issue_id": "<uuid>", "trace_id": "<trace_id>" }
```

## Notes
- `timeline` assemble `breadcrumbs` et `events` avec `timestamp`/`message`.
- Le scrub est best‑effort et ne modifie pas les données stockées.
