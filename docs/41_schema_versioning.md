# Schema versioning & SDK contract

## Goals
- Version all ingestion schemas.
- Enforce compatibility between SDKs and ingest.

## Rules
- `schemas/event.schema.vN.json` is the source of truth.
- `schema_version` is required in the envelope.
- New fields must be backward compatible within the same major version.
- Breaking changes require a new schema version.

## Ingest behavior
- Missing version defaults to `v1` (temporary). Future versions should require explicit version.
- Validation must reject unknown versions.

## Deprecation
- Define end-of-life dates for older schema versions.
- Provide SDK warnings before removal.
