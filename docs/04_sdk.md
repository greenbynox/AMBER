# SDK

## Minimal API
- `captureException(error, context?)`
- `captureMessage(message, level?, context?)`

## Context
- `setContext(key, value)`
- `setTag(key, value)`
- `setUser({id, email})`
- `setRelease(version)`

## Sent vs inferred
- Sent: stacktrace, message, type, tags, user, release.
- Inferred server‑side: framework, sourcemaps, owners.

## Auto‑instrumentation
Les SDKs installent des hooks pour capturer automatiquement les erreurs non gérées et ajouter des breadcrumbs (HTTP, console, requêtes). Les frameworks disposent de middlewares prêts à l’emploi.

## SDKs disponibles
- Node: `sdk/node` (autoCapture + Express middleware)
- Python: `sdk/python` (FastAPI, Django, Flask helpers)
- Mobile: `sdk/android`, `sdk/ios`
- Autres: `sdk/go`, `sdk/java`, `sdk/dotnet`

Voir aussi: `docs/22_sdk_frameworks.md`.
