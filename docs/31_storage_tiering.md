# Storage tiering (PR‑021)

## Objectif
Réduire les coûts via un **hot/cold tiering** et une purge automatique des données les plus anciennes.

## Configuration
`GET /projects/:id/storage-policy`
`POST /projects/:id/storage-policy`

Body:
```
{
  "hot_days": 30,
  "cold_days": 365
}
```

## Exécution
`POST /projects/:id/storage-tier/run`

Body (optionnel):
```
{ "dry_run": true }
```

## Comportement
- Les données plus anciennes que `hot_days` passent en `storage_tier = 'cold'`.
- Les données plus anciennes que `cold_days` sont supprimées.
- Cible: `events`, `transactions`, `replays`, `profiles`.

## Notes
- Le `dry_run` retourne les compteurs sans modifier la base.
