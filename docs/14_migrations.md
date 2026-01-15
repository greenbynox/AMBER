# Automatic migrations

The `ember-api` and `ember-ingest` services run migrations automatically on startup via `sqlx::migrate!`.

## Migrations folder
`services/migrations`

## Add a migration
1. Create a file `xxxx_description.sql`
2. Restart the services

## Quick guide
1. Set `DATABASE_URL` for your Postgres instance.
2. Start `ember-api` or `ember-ingest` (they auto-apply migrations).
3. Check logs for "Migration DB" success.

For a clean local reset:
1. Drop and recreate the `public` schema in Postgres.
2. Restart the services to re-apply all migrations.
