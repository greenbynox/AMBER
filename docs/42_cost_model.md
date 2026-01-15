# Deterministic cost model

## Goal
Provide a predictable, deterministic cost bound per ingested signal.

## Recorded data
- `cost_units`: per entity (event/transaction/profile/replay).
- `project_cost_daily`: daily aggregation.

## Cost formula (v1)
```
units = base(kind) + (storage_bytes / 1024) * 0.01
```
- Base values:
  - event: 1.0
  - transaction: 0.6
  - profile: 1.2
  - replay: 2.0

## Guarantees
- Deterministic for equal input.
- Bounded by payload size + constant base.

## Next steps
- Expose costs in admin API.
- Add graceful drop summaries when quotas are exceeded.
