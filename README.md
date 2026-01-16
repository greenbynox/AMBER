# EMBER

![CI](https://github.com/amber/amber/actions/workflows/ci.yml/badge.svg)

EMBER is an open‑source, self‑hosted alternative to Sentry, built to reduce noise and accelerate error understanding.

## Goals
- Replace paid solutions for 70–80% of real‑world needs.
- 5‑minute setup maximum.
- Fewer dashboards, more useful explanations.

## Repository contents (foundation phase)
- Canonical event schema (`schemas/event.schema.json`)
- Minimal Rust backend (ingestion + API)
- Clear, opinionated documentation

## Philosophy
- Open‑source (AGPL‑3.0)
- Self‑hosted by default
- Optional LLM (never required)
- Understand > Collect

## Getting started (next steps)
This base contains the structure and first services.

### Prerequisites
- Rust (cargo) via https://rustup.rs
- Postgres (DATABASE_URL)
- Docker (for optional Kafka/ClickHouse/Redis)

### Run the API
- `npm run dev` (starts `ember-api`)

### Run ingestion
- `npm run ingest`

### Run the relay (Kafka)
- `npm run relay`

### Run the pipeline (Kafka -> ClickHouse -> ingest)
- `npm run pipeline`

### Run the worker (async jobs)
- `npm run worker`

### React UI (modern client)
- `cd apps/web` then `npm install`
- `npm run dev` (Vite at http://localhost:5173)

### Infra (Postgres/Kafka/Redis/ClickHouse)
- `docker compose up -d`

### Full stack (API/ingest/worker/web + infra)
- `docker compose up -d`

## Documentation
See `docs/` for scope, architecture, MVP, and the implementation plan.

## Plug-and-play
See `docs/PLUG_AND_PLAY.md` for one-click startup.

## Packaging
See `docs/PACKAGING.md` to generate Windows/macOS/Linux bundles.

## Self-hosted installer
See `docs/SELF_HOSTED.md` for install/upgrade scripts.
