# Échantillonnage adaptatif (PR‑020)

## Objectif
Maintenir un **coût fixe par projet** en ajustant dynamiquement le taux d’échantillonnage en fonction du volume récent.

## Configuration
`GET /projects/:id/sampling`
`POST /projects/:id/sampling`

Body:
```
{
  "target_events_per_min": 120,
  "min_rate": 0.1,
  "max_rate": 1.0
}
```

## Comportement
- Si `target_events_per_min <= 0` → pas d’échantillonnage.
- Le taux est calculé à partir des événements de la dernière minute.
- L’ingest répond `sampled` quand un événement/transaction est filtré.

## Notes
- `min_rate` et `max_rate` bornent le taux dynamique.
- L’échantillonnage s’applique aux événements et transactions.
