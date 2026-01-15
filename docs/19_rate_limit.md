# Rate limiting

Ingestion applies a per‑project rate limit (in‑memory token bucket).

## Variables
`RATE_LIMIT_PER_MIN` (default: 120)
`QUOTA_SOFT_PER_MONTH` (default: 500000)
`QUOTA_HARD_PER_MONTH` (default: 750000)
`JOB_BACKPRESSURE_MAX` (default: 1000)
`JOB_RETRY_BASE_SECONDS` (default: 60)

## Behavior
- Returns 429 when exceeded.
- Progressive refill (per minute).
- On soft quota overage, `X-Quota-Status=soft`.
- On hard quota overage, 429 + `X-Quota-Status=hard`.
- Job backpressure: if the queue exceeds the threshold, non‑critical jobs are skipped.
