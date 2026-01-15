# Profiling v2

## Endpoints
### Liste des profiles d’une trace
`GET /profiles/:trace_id/list?limit=20`

### Hot paths
`GET /profiles/:trace_id/hot-paths?limit=20`

Réponse:
- `frame`
- `weight`

### Diff entre profiles
`GET /profiles/:trace_id/diff?base_id=<uuid>&compare_id=<uuid>&limit=20`

Si `base_id`/`compare_id` ne sont pas fournis, utilise les 2 profiles les plus récents.

Réponse:
- `items[]` avec `frame`, `base_weight`, `compare_weight`, `delta`

## Notes
- L’extraction est best‑effort selon la structure JSON (`frames`, `stacks`, `samples`).
- `weight` peut provenir de `weight`, `value` ou `duration` dans les samples.
