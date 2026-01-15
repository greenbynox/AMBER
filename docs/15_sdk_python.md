# Python SDK

Minimal SDK to capture an exception and send it to EMBER.

- Folder: `sdk/python`
- API: `init`, `capture_exception`, `add_breadcrumb`, `clear_breadcrumbs`

The SDK uses the `POST /ingest` endpoint.

## Auto-capture
- By default, captures unhandled exceptions (sys.excepthook).

## FastAPI
Helper `add_fastapi_handlers(app)`.

## Django
Middleware `EmberMiddleware`.
