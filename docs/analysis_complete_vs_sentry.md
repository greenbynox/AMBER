# Complete technical review of AMBER + detailed comparison with Sentry

_Analysis date: January 15, 2026_

This report is a factual, repo‑based review of the **current workspace**. It documents what exists, how it works, and where it is limited, then compares AMBER to Sentry across concrete axes.

## 1) Repository map (A→Z)

**Top‑level**
- `.env`, `.env.example`: configuration and secret placeholders.
- `.github/`: CI workflows and GitHub settings (presence indicated by CI badge in README).
- `AMBER.sln`: .NET solution file (tooling/interop).
- `apps/`: React UI (Vite) for issues/insights and admin views.
- `crates/`: shared Rust crate(s) (e.g., `ember_shared`).
- `docs/`: product + architecture + API + roadmap documentation.
- `schemas/`: canonical database schemas (Postgres/ClickHouse).
- `sdk/`: SDKs and framework middleware (Node/Python/etc.) + mobile SDKs.
- `services/`: Rust services (api/ingest/worker/relay/pipeline/admin‑cli).
- `scripts/`: helper scripts (not audited in depth here).
- `docker-compose.yml`: local infra stack (Postgres/Kafka/Redis/ClickHouse).
- `Cargo.toml`, `Cargo.lock`, `package.json`: workspace dependency manifests.
- `target/`: build artifacts (not part of runtime review).

**Services directory**
- `services/api`: REST API for issues, events, insights, search, admin endpoints.
- `services/ingest`: event intake, grouping, enrichment, storage.
- `services/worker`: async jobs (webhook/email/Slack/GitHub).
- `services/relay`: Kafka proxy (phase 0).
- `services/pipeline`: Kafka → ClickHouse → ingest (phase 0).
- `services/migrations`: SQL migrations applied by ingest/API.
- `services/admin-cli`: admin utilities (CLI).

## 2) Data model (Postgres)

Core entities observed in `schemas/postgres.sql`:
- **Projects/Teams/Orgs**: `projects`, `teams`, `organizations`, membership tables.
- **Issues & Events**: `issues`, `events`, `issue_insights`.
- **Releases**: `releases`, `release_commits`.
- **Alerting**: `alert_rules`, `alert_silences`, `alert_rule_triggers`.
- **Performance**: `transactions`, `spans`, `profiles`.
- **Replay**: `replays`, `replay_links`.
- **Search & Discover**: `saved_queries`.
- **Sampling & quotas**: `sampling_rules`, `project_usage_daily`.
- **Compliance & security**: `pii_policies`, `data_requests`, `data_request_results`, `audit_log`.
- **Enterprise**: `sso_configs`, `scim_tokens`, `org_users`.
- **Integrations**: `integrations_catalog`, `org_integrations`, `oauth_connections`.
- **Multi‑region**: `regions`.

**RCA data** in `issue_insights`:
- `summary`, `culprit`, `last_release`, `regressed_at`.
- `causal_chain`, `regression_map`, `confidence` (RCA assistant v1).

## 3) Ingestion flow (services/ingest)

Observed behavior in `services/ingest/src/main.rs`:
1. **Auth** via `x-ember-key` and project check.
2. **Rate limiting** + **quota** checks per project.
3. **Grouping** by fingerprint with overrides/rules.
4. **Event insert** into `events`, issue upsert in `issues`.
5. **RCA insight update** in `issue_insights`.
6. **Alert rule evaluation** and **async jobs** enqueue.
7. **Usage tracking** by day.

RCA enrichment logic:
- **Culprit** derived from in‑app stack frames.
- **Causal chain**: ordered in‑app frames (fallback to any frames).
- **Regression map**: release window + suspect commits if present.
- **Confidence**: heuristic score from signal presence (frames, in‑app, context, release, regression).

## 4) API layer (services/api)

The API exposes:
- Issues list/detail + bulk update.
- Event and replay lookups.
- Discover filters/stats and full‑text search (v2).
- RCA insights via `GET /issues/:id/insights`.
- Admin endpoints for projects, webhooks, sampling, storage tiering, releases, alerts, saved queries, ownership rules.
- Enterprise endpoints for SSO/SCIM.
- Integrations catalog and OAuth flow.

Auth mechanisms observed:
- `x-ember-project` + `x-ember-key` (project access).
- `x-ember-admin` (admin access).
- JWT team tokens (Bearer) and optional 2FA/IP allowlist (documented).

## 5) UI (apps/web)

The React UI (single‑page) provides:
- Project selection and issues list.
- Issue detail with events and RCA summary.
- Basic marketplace/config views for integrations.

This UI is functional but minimal compared to Sentry’s dashboards and workflows.

## 6) SDKs

From `sdk/` and `docs/` indices:
- Node, Python SDKs + framework middleware.
- Auto‑instrumentation for Go/Java/.NET.
- Mobile SDKs (Android/iOS).

Coverage is broad for a self‑hosted stack, but maturity is not audited here beyond presence.

## 7) Observability & operations

- `/metrics` endpoint for ingestion (Prometheus‑style counters).
- Docker Compose for local infra: Postgres + Kafka + Redis + ClickHouse.
- Optional Kafka/ClickHouse pipeline staged via relay/pipeline services.

## 8) Tests & build status

- Workspace builds with `cargo test --workspace`.
- Current run result: **pass**, with a warning about `sqlx-postgres` future incompatibility.

## 9) Gaps observed (facts)

- **UI depth**: only core issue/insight views are implemented; no advanced dashboards in the current UI code.
- **Integrations**: catalog + org config exists; marketplace scope is limited compared to Sentry.
- **Enterprise compliance**: SSO/SCIM present, but no evidence of broader certification work inside the repo.

## 10) Detailed comparison: AMBER vs Sentry

### Feature coverage
| Axis | AMBER (repo observed) | Sentry (market reference) |
|---|---|---|
| Error tracking | Issues/events, grouping, status | Mature end‑to‑end workflows |
| RCA/Insights | Summary + culprit + regression + causal chain | Deeper insights, richer context | 
| Performance | Transactions + spans + profiling | Advanced UI + analytics | 
| Replay | Data storage + read | Mature replay UX | 
| Alerts | Rules + channels (webhook/Slack/email) | Complex routing/escalation | 
| Discover/search | FTS v2, facets, basic discover | Richer query + dashboards | 
| Integrations | Catalog + org config | Large marketplace | 
| Auth/RBAC | Header auth + JWT team tokens | Fine‑grained RBAC | 
| Compliance | Data requests + PII policies | Enterprise compliance & audits | 
| Multi‑region | Routing + region table | Mature global infra | 
| SDK ecosystem | Wide but early | Large, polished, maintained | 

### Operational scale
- **AMBER**: designed for self‑hosted cost control; pipeline staged but not proven in code with large‑scale orchestration.
- **Sentry**: battle‑tested at scale with global ingestion and mature ops tooling.

### UX and workflow maturity
- **AMBER**: clear, minimal UI focused on issues and insight summaries.
- **Sentry**: multi‑step investigation workflows, dashboards, alert management, team collaboration UX.

### Cost profile
- **AMBER**: self‑hosted stack prioritizes lower infra cost and simplicity.
- **Sentry**: commercial pricing; self‑hosted enterprise options add overhead.

## 11) Bottom line (facts)

AMBER provides a **broad, technically coherent** foundation: ingestion, storage, performance, replay, RCA, and enterprise primitives are present. The current gap with Sentry is **product maturity and ecosystem**—especially UI depth, marketplace breadth, and enterprise compliance. The repo is a solid engineering base, but it is not yet at Sentry’s functional or operational maturity level.
