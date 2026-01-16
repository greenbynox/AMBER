#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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

if ! command -v cargo >/dev/null 2>&1; then
  echo "Cargo n'est pas installé. Installe Rust puis relance."
  exit 1
fi

echo "Démarrage infra (docker compose)..."
docker compose up -d

echo "Build services (release)..."
cargo build --release -p ember-api -p ember-ingest -p ember-worker

mkdir -p logs

echo "Installation terminée."
echo "Pour démarrer: ./scripts/start.sh"
