# Tracing UX v2

## Objectifs
- **Waterfall rapide** : structure des spans avec profondeur et self‑time.
- **Corrélations** : relier traces ↔ replays ↔ issues.
- **Breakdown** : déjà exposé via `/traces/breakdown`.

## Endpoints
### Waterfall
`GET /traces/:trace_id/waterfall`

Réponse:
- `trace_id`
- `spans[]` : `span_id`, `parent_id`, `op`, `description`, `status`, `start_ts`, `duration_ms`, `self_time_ms`, `depth`, `tags`

### Corrélations
`GET /traces/:trace_id/correlations`

Réponse:
- `issues[]` issues reliées via `replay_links`
- `replays[]` replays associés à la trace

### Breakdown
`GET /traces/breakdown?window_minutes=60`

## Notes
- `self_time_ms` est calculé comme `duration_ms` moins la somme des durées des enfants directs.
- Les corrélations s’appuient sur `replay_links`.
