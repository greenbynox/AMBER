# Compliance (export/delete, PII policy, secrets)

## Data requests (export / delete)
Les demandes de conformité sont gérées au niveau organisation :
- `GET /orgs/:id/data-requests`
- `POST /orgs/:id/data-requests`
- `POST /data-requests/:id/run`
- `GET /data-requests/:id/results`

### Export
Retourne un résumé des données liées à un email utilisateur (compteurs + échantillons d’IDs).

### Delete
Supprime les événements et replays associés à l’email, et anonymise les issues.

## PII policy (scrubbing)
Politique par projet :
- `GET /projects/:id/pii-policy`
- `POST /projects/:id/pii-policy`

Champs :
- `scrub_emails` (bool)
- `scrub_ips` (bool)
- `scrub_secrets` (bool)

## Secrets encryption
Les secrets sensibles (OAuth tokens, GitHub token) sont chiffrés avec AES‑GCM.

Variable requise :
- `EMBER_SECRETS_KEY` (base64, 32 octets)

Format stocké : `v1:<nonce_b64>:<ciphertext_b64>`.

> Si la clé n’est pas fournie, les endpoints qui écrivent des secrets renvoient une erreur.
