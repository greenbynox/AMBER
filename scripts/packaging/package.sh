#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-dist}"
DIST="$ROOT_DIR/$OUT_DIR"

mkdir -p "$DIST"

echo "Build release binaries (current OS)..."
cargo build --release -p ember-api -p ember-ingest -p ember-worker -p ember-launcher

OS_NAME="amber-linux"
UNAME="$(uname -s)"
if [ "$UNAME" = "Darwin" ]; then
  OS_NAME="amber-macos"
fi

TARGET_DIR="$DIST/$OS_NAME"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR/bin" "$TARGET_DIR/scripts"

cp "$ROOT_DIR/target/release/ember-api" "$TARGET_DIR/bin/"
cp "$ROOT_DIR/target/release/ember-ingest" "$TARGET_DIR/bin/"
cp "$ROOT_DIR/target/release/ember-worker" "$TARGET_DIR/bin/"
cp "$ROOT_DIR/target/release/ember-launcher" "$TARGET_DIR/bin/"
cp "$ROOT_DIR/scripts/start.sh" "$TARGET_DIR/scripts/"
cp "$ROOT_DIR/.env.example" "$TARGET_DIR/"
[ -f "$ROOT_DIR/docker-min.zip" ] && cp "$ROOT_DIR/docker-min.zip" "$TARGET_DIR/" || true

chmod +x "$TARGET_DIR/scripts/start.sh"

echo "Package ready: $TARGET_DIR"
