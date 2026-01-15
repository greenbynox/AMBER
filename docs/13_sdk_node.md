# Node SDK

Minimal SDK to capture an exception and send it to EMBER.

- Folder: `sdk/node`
- API: `init`, `captureException`, `addBreadcrumb`, `clearBreadcrumbs`

The SDK uses the `POST /ingest` endpoint.

## Auto-capture
By default, captures `uncaughtException` and `unhandledRejection`.

## Express
Middleware available via `@ember/sdk/express`.
