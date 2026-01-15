# Chaos harness (minimal)

This folder contains reproducible failure-mode scenarios to validate AMBER robustness.

## Scenarios
1. **Postgres read-only**
   - Force DB into read-only mode.
   - Expected: ingestion fails fast, no partial writes.

2. **ClickHouse unavailable**
   - Stop ClickHouse service.
   - Expected: pipeline retries, no data loss, DLQ growth bounded.

3. **Kafka lag / slow broker**
   - Throttle Kafka or introduce latency.
   - Expected: backpressure engaged, ingestion response remains stable.

4. **Quota reached mid-ingest**
   - Set quota low; ingest until threshold exceeded.
   - Expected: graceful drop + summary metrics.
