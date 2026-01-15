# Recherche full‑text + facettes

## Endpoint
`GET /search/issues/v2`

Paramètres:
- `query` (obligatoire) : chaîne full‑text.
- `limit` (optionnel, défaut 50)
- `before` (optionnel, RFC3339) : pagination par `last_seen`.
- `window_minutes` (optionnel, défaut 1440) : fenêtre d’agrégation des facettes.

## Réponse
- `items` : mêmes champs que `/issues`.
- `next_before` : curseur de pagination.
- `facets` :
  - `release`
  - `exception_type`
  - `env`
  - `tags` (format `key:value`)

## Notes
- Le full‑text couvre `issues.title` et le texte d’événements (`message`, `exception_message`, `exception_type`).
- Les facettes sont calculées sur les événements des issues matchées.
