#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f ".env" ]; then
  if [ -f ".env.example" ]; then
    cp .env.example .env
  else
    printf "DATABASE_URL=postgres://ember:ember@localhost:5432/ember\nEMBER_SECRET=change_me\nEMBER_JWT_SECRET=change_me_jwt\nEMBER_SECRETS_KEY=BASE64_32_BYTES\n" > .env
  fi
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker n'est pas installé. Installe-le puis relance."
  exit 1
fi

echo "Démarrage infra..."
docker compose up -d

echo "Build services (release)..."
cargo build --release -p ember-api -p ember-ingest -p ember-worker

echo "Démarrage services..."
"$ROOT_DIR/target/release/ember-ingest" &
"$ROOT_DIR/target/release/ember-worker" &
"$ROOT_DIR/target/release/ember-api" &

sleep 2
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://localhost:3002/app" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
  open "http://localhost:3002/app" >/dev/null 2>&1 || true
fi

echo "EMBER est lancé. UI: http://localhost:3002/app"
