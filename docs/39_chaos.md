# Chaos scenarios (robustness validation)

## Goal
Provide deterministic, reproducible failure-mode testing that proves system behavior under stress and partial outages.

## Scenarios
1. **Postgres read-only**
   - Setup: switch DB to read-only.
   - Expectation: ingestion rejects writes, no partial state.

2. **ClickHouse unavailable**
   - Setup: stop ClickHouse.
   - Expectation: pipeline retries, no data loss, queue bounded.

3. **Kafka lag / slow broker**
   - Setup: throttle Kafka or introduce latency.
   - Expectation: backpressure triggers, ingestion remains stable.

4. **Quota reached mid-ingest**
   - Setup: very low quota; ingest until over limit.
   - Expectation: graceful drop + metrics summary.

## Result format
Each scenario must include:
- steps to reproduce
- expected outputs/logs
- rollback steps
