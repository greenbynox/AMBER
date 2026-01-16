# EMBER plug-and-play

## Launcher (recommandé)
- Double‑clic sur `ember-launcher.exe` (Windows) ou `ember-launcher` (macOS/Linux)
- Le launcher gère Docker, démarre les services et ouvre le navigateur.

Commandes:
- `ember-launcher start`
- `ember-launcher stop`
- `ember-launcher status`
- `ember-launcher update`

## One-click (Windows)
1. Install Docker Desktop.
2. Double-click `scripts/start.ps1`.
3. Open `http://localhost:3002/app`.

## One-click (Linux/macOS)
1. Install Docker.
2. Run `scripts/start.sh`.
3. Open `http://localhost:3002/app`.

## What this does
- Starts Docker Compose infra and AMBER services.
- Builds and runs `amber-api`, `amber-ingest`, `amber-worker`, `amber-web`.
- Launches services and opens the UI.

## Minimal Docker bundle
If Docker is missing, the script provides `docker-min.zip` (Postgres-only) so you can keep just the minimum.

## If it fails
- Check Docker is running.
- Ensure ports 3001/3002/5432 are free.
- Update `.env` with valid secrets if needed.
