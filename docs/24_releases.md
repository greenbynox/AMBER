# Releases v2

## Objectifs
- **Adoption** : part d’événements du projet attribuée à une release sur une fenêtre donnée.
- **Régressions** : issues qui régressent sur une release.
- **Suspect commits** : commits d’une release associés à des nouvelles issues ou régressions.

## Endpoints
### Liste des releases
`GET /projects/:id/releases?window_minutes=1440`

Champs supplémentaires :
- `adoption_rate`
- `events_24h`
- `new_issues_24h`
- `regressions_24h`

### Détail d’une release
`GET /projects/:id/releases/:version?window_minutes=1440`

### Régressions d’une release
`GET /projects/:id/releases/:version/regressions?limit=50`

### Suspect commits
`GET /projects/:id/releases/:version/suspect-commits`

Heuristique : chaque issue (nouvelle ou régression) est associée au **commit le plus récent** de la release dont le timestamp est antérieur à `first_seen` (nouvelle issue) ou `regressed_at` (régression).

## Notes
- `window_minutes` permet de contrôler la fenêtre d’adoption (par défaut 24h).
- Les commits sans `timestamp` ne peuvent pas être attribués.
