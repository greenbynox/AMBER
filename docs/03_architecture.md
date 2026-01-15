# Technical architecture

## Language choice
- Rust for ingestion and API (performance, memory safety, low infra cost).

## Pipeline
1. HTTP ingest
2. Normalization
3. Deterministic fingerprint
4. Lightweight enrichment
5. Postgres storage

## Storage
- Postgres at first (everything).
- ClickHouse optional for heavy analytics.

## Separation of responsibilities
- `ember-ingest`: intake + normalization
- `ember-api`: read/sort/filter
- `ember-shared`: shared schemas

## LLM
- Optional: summaries and hypotheses.
- Fallback without LLM: rules + templates.
