# Webhooks v2

## Objectif
Les webhooks v2 permettent de gérer plusieurs endpoints par projet, d’ajouter une signature HMAC et de tracer les livraisons (status/error).

## Endpoints API
- `GET /projects/:id/webhooks`
- `POST /projects/:id/webhooks`
- `POST /projects/:id/webhooks/:webhook_id` (delete)
- `GET /projects/:id/webhooks/:webhook_id/deliveries`

## Création d’un endpoint
Body:
```
{
  "url": "https://example.com/hooks/ember",
  "secret": "optional-shared-secret",
  "enabled": true
}
```

## Livraison & payload
Lorsqu’un **nouvel incident** ou une **régression** est détecté, un job `webhook_v2` est émis.
Le body envoyé ressemble à :
```
{
  "kind": "new_issue" | "regression" | "alert_rule",
  "project_id": "project",
  "issue_id": "uuid",
  "fingerprint": "hash",
  "title": "..."
}
```

## Signatures
Si `secret` est fourni, une signature HMAC SHA‑256 est ajoutée :
- Header: `X-Ember-Signature: sha256=<hex>`
- Header: `X-Ember-Event: <kind>`

Le HMAC est calculé sur le **body JSON brut** envoyé (UTF‑8).

## Retries
Les deliveries utilisent le même système de retry que les autres jobs:
- backoff exponentiel (`JOB_RETRY_BASE_SECONDS`)
- jitter aléatoire
- statut `dead` si `max_attempts` atteint

## Dashboard (deliveries)
`GET /projects/:id/webhooks/:webhook_id/deliveries` retourne les dernières tentatives (status code ou erreur).
