# Top regressions (tracing)

## Endpoint
`GET /traces/top-regressions?window_minutes=1440&limit=50`

## Réponse
Liste d’issues triées par volume d’événements récents et date de régression.
Champs:
- `id`, `title`, `level`, `status`, `assignee`
- `regressed_at`, `last_seen`, `last_release`
- `events_24h`

## Notes
- `window_minutes` contrôle la fenêtre d’agrégation des événements (par défaut 24h).
