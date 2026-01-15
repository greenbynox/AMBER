# Admin CLI

The admin CLI provides operational commands for key rotation, audit export, and DLQ replay.

## Build and run

```
cd services/admin-cli
cargo run -- --help
```

## Commands

### Rotate project key

```
cargo run -- rotate-project-key --project-id demo
```

### Export audit log

JSON to stdout:

```
cargo run -- audit-export --format json
```

CSV to file with a time filter:

```
cargo run -- audit-export --format csv --since 2026-01-01T00:00:00Z --output audit.csv
```

### Replay DLQ jobs

Dry run:

```
cargo run -- replay-dlq --dry-run
```

Replay a specific kind:

```
cargo run -- replay-dlq --kind webhook --reset-attempts true
```

## Environment

- `DATABASE_URL` (required)
- `ADMIN_ACTOR` (optional, default: `admin-cli`)
