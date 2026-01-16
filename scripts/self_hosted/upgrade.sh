#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if ! command -v git >/dev/null 2>&1; then
  echo "Git n'est pas installé. Installe-le puis relance."
  exit 1
fi

echo "Mise à jour du code..."
git pull --rebase

echo "Mise à jour infra (docker compose)..."
docker compose up -d

echo "Rebuild services (release)..."
cargo build --release -p ember-api -p ember-ingest -p ember-worker

echo "Upgrade terminé. Redémarre les services si besoin."
