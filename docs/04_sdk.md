# SDK

## Minimal API
- `captureException(error, context?)`
- `captureMessage(message, level?, context?)`

## Context
- `setContext(key, value)`
- `setTag(key, value)`
- `setUser({id, email})`
- `setRelease(version)`

## Sent vs inferred
- Sent: stacktrace, message, type, tags, user, release.
- Inferred server‑side: framework, sourcemaps, owners.
