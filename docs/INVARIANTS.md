# AMBER Invariants (data + behavior)

_Date: 2026-01-15_

This document defines **explicit invariants** for AMBER. These are non‑negotiable guarantees that must hold in production. Any change that violates an invariant must be treated as a breaking change or a bug.

---

## 1) Determinism
- **Deterministic at equal input**: identical inputs must produce identical outputs.
- **Deterministic at equal algorithm version**: same input + same algorithm version → same result.
- **Non‑determinism is only allowed if versioned** (e.g., ML) and clearly labeled.

---

## 2) Grouping invariants
- **Grouping stability**: same event payload → same issue (under identical rules + versions).
- **Grouping traceability**: every grouping decision can be explained by stored inputs + versioned rules.

---

## 3) Ingestion idempotence
- **Retry safety**: re‑ingesting the same event must not double‑count or create duplicate issues.
- **At‑least‑once safe**: ingestion can be replayed without changing results.

---

## 4) Ordering guarantees
- **Event vs release**: release metadata must not regress event interpretation.
- **Insights**: insights must reflect the latest known event state for the issue.

---

## 5) Replay safety
- **No partial sessions**: a replay is either fully persisted or not visible.
- **Replay ↔ issue links** are consistent (no dangling references).

---

## 6) Data‑level invariants
- **No ghost data**: no issue exists without at least one event.
- **No dangling references**: `signal_links` must resolve to existing signals.
- **Monotonic counters**: `event_count`, `first_seen`, `last_seen` never regress.
- **Immutability rules**: write‑once fields (e.g., `first_seen`, `first_release`) cannot change.

---

## 7) Ownership & responsibility
- **Issue ownership**: every issue has a clear human owner (assignee or team policy).
- **Grouping rule ownership**: each rule has an owner and audit trail.
- **RCA ownership**: conclusions are labeled as `auto` or `reviewed`.
- **Automation yields**: human decisions override automation.

---

## 8) Non‑objectives (hard limits)
- No live production debugging.
- No silent mutation of issues.
- No RCA auto‑publish if confidence is below a defined threshold.

---

## 9) Enforcement
- **Automated tests** must deliberately violate each invariant and fail.
- **Metrics** must detect drift (grouping churn, RCA drift, split/merge rate).
- **Change control**: invariant‑breaking changes require explicit versioning + migration.
