# SDK Frameworks

## Express
Middleware available via `@ember/sdk/express`.
Includes request middleware + error handler.
Adds HTTP breadcrumbs and auto-captures unhandled errors.

## FastAPI
Helper `add_fastapi_handlers(app)`.
Adds automatic exception capture and request metadata.

## Django
Middleware `EmberMiddleware`.
Captures unhandled exceptions and request info.

## Flask
Helper `add_flask_handlers(app)`.
Captures errors + request context.

## Go
Minimal SDK in `sdk/go` + `ember.Middleware(client, handler)`.

## Java
Minimal SDK in `sdk/java` + `EmberFilter` (Servlet Filter).

## .NET
Minimal SDK in `sdk/dotnet` + ASP.NET Core middleware `UseEmber`.

## Android
Minimal SDK in `sdk/android`.

## iOS
Minimal SDK in `sdk/ios`.
