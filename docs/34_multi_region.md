# Multi‑region routing & data residency

## Objectif
Permettre à chaque organisation d’imposer une région de résidence des données, et guider les SDKs vers la bonne région pour l’ingestion et l’API.

## Modèle de données
- `organizations.data_region` : région par défaut de l’organisation.
- `regions` : catalogue des régions actives avec URLs d’API et d’ingestion.

## API
- `GET /regions` (admin) : liste des régions disponibles.
- `POST /orgs/:id` (admin) : mise à jour de `data_region`.
- `GET /routing` (auth projet) : retourne la région cible pour le projet courant.

Réponse `GET /routing` :
```
{
  "project_id": "project-id",
  "region": "eu-west",
  "api_base_url": "https://api.eu.ember.example",
  "ingest_url": "https://ingest.eu.ember.example/ingest"
}
```

## Routage côté ingestion
Le service d’ingestion vérifie la variable d’environnement `REGION_NAME`.
Si la région courante ne correspond pas à la région de résidence du projet, il répond :
- `307 Temporary Redirect`
- Header `Location: <ingest_url>`
- Header `X-Ember-Region: <region>`

## Fallbacks
- Si `data_region` est absent, le service utilise `DEFAULT_REGION` (env) ou la première région active.

## Variables d’environnement
- `REGION_NAME` : nom de la région du service courant.
- `DEFAULT_REGION` : région par défaut si aucune résidence n’est définie.
