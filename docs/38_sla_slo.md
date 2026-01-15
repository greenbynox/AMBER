# SLA & SLO dashboards

## SLA (issues)
Configuration par projet :
- `GET /projects/:id/sla-policy`
- `POST /projects/:id/sla-policy`

Rapport :
- `GET /projects/:id/sla-report`

Le rapport renvoie :
- nombre d’issues ouvertes
- nombre de breaches (issues ouvertes au‑delà de `sla_minutes`)
- âge de la plus ancienne issue ouverte

## SLO (transactions)
Configuration par projet :
- `GET /projects/:id/slo`
- `POST /projects/:id/slo`

Rapport :
- `GET /projects/:id/slo/report`

Le rapport calcule la **taux d’erreur** sur les transactions de la fenêtre définie (`window_minutes`) et le **budget restant** relatif à la cible (`target_error_rate`).
