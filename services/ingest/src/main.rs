use axum::{extract::State, http::HeaderMap, http::StatusCode, routing::get, routing::post, Json, Router};
use axum::response::{IntoResponse, Response};
use axum::http::HeaderValue;
use chrono::{DateTime, Duration, Utc, Datelike, TimeZone};
use ember_shared::{EventEnvelope, EventLevel, ProfileEnvelope, ReplayEnvelope, StackFrame, TransactionEnvelope};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sourcemap::SourceMap;
use sqlx::{PgPool, Row};
use std::env;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::sync::OnceLock;
use tracing::{error, info, warn};
use uuid::Uuid;
use tokio::sync::Mutex;
use rand::Rng;
use data_encoding::BASE64;
use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}};

#[derive(Clone)]
struct AppState {
    db: PgPool,
    limiter: RateLimiter,
    metrics: Metrics,
}

#[derive(Clone)]
struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, Bucket>>>,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

struct RateLimitInfo {
    limit: i64,
    remaining: i64,
    reset: i64,
    allowed: bool,
}

struct QuotaInfo {
    limit: i64,
    remaining: i64,
    reset: i64,
    status: String,
    allowed: bool,
}

struct RegionTarget {
    name: String,
    ingest_url: String,
}

#[derive(Clone)]
struct Metrics {
    events_total: Arc<AtomicU64>,
    events_rate_limited_total: Arc<AtomicU64>,
    events_quota_limited_total: Arc<AtomicU64>,
    transactions_total: Arc<AtomicU64>,
    transactions_sampled_total: Arc<AtomicU64>,
    profiles_total: Arc<AtomicU64>,
    replays_total: Arc<AtomicU64>,
    grouping_default_total: Arc<AtomicU64>,
    grouping_rule_total: Arc<AtomicU64>,
    grouping_override_total: Arc<AtomicU64>,
    rca_confidence_sum: Arc<AtomicU64>,
    rca_confidence_count: Arc<AtomicU64>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL manquant");
    let db = PgPool::connect(&database_url).await.expect("Connexion DB échouée");
    sqlx::migrate!("../migrations")
        .run(&db)
        .await
        .expect("Migration DB échouée");
    let limiter = RateLimiter::new(env::var("RATE_LIMIT_PER_MIN").ok().and_then(|v| v.parse().ok()).unwrap_or(120));
    let metrics = Metrics::new();
    let state = AppState { db, limiter, metrics };

    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .route("/ingest", post(ingest))
        .route("/ingest/transaction", post(ingest_transaction))
        .route("/ingest/profile", post(ingest_profile))
        .route("/ingest/replay", post(ingest_replay))
        .with_state(state);

    let addr = "0.0.0.0:3001";
    info!("ingest listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "ok"
}

async fn metrics_handler(State(state): State<AppState>) -> Result<String, (StatusCode, String)> {
    Ok(state.metrics.render())
}

async fn evaluate_limits(
    state: &AppState,
    project_id: &str,
    units: i64,
) -> Result<(RateLimitInfo, QuotaInfo), (StatusCode, String)> {
    let (rate_limit, quota_soft, quota_hard) = get_project_limits(&state.db, project_id).await?;
    let rate = state.limiter.check(project_id, rate_limit as u32).await;
    let quota = check_quota(&state.db, project_id, quota_soft, quota_hard, units).await?;
    Ok((rate, quota))
}

async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<EventEnvelope>,
) -> Result<Response, (StatusCode, String)> {
    let api_key = get_api_key(&headers)?;
    ensure_project(&state.db, &event.project_id, &api_key).await?;
    if let Some(response) = maybe_redirect_region(&state.db, &event.project_id).await? {
        return Ok(response);
    }
    let (rate, quota) = evaluate_limits(&state, &event.project_id, 1).await?;
    if !rate.allowed {
        state.metrics.events_rate_limited_total.fetch_add(1, Ordering::Relaxed);
        let _ = record_ingest_drop(&state.db, &event.project_id, "rate_limit").await;
        return Ok(respond_with_limits(StatusCode::TOO_MANY_REQUESTS, "rate limit", &rate, Some(&quota)));
    }
    if !quota.allowed {
        state.metrics.events_quota_limited_total.fetch_add(1, Ordering::Relaxed);
        let reason = if quota.status == "hard" { "quota_hard" } else { "quota_soft" };
        let _ = record_ingest_drop(&state.db, &event.project_id, reason).await;
        return Ok(respond_with_limits(StatusCode::TOO_MANY_REQUESTS, "quota exceeded", &rate, Some(&quota)));
    }
    state.metrics.events_total.fetch_add(1, Ordering::Relaxed);

    let sampling_rate = adaptive_sampling_rate(&state.db, &event.project_id).await?;
    if sampling_rate < 1.0 && !should_sample(sampling_rate) {
        return Ok(respond_with_limits(StatusCode::OK, "sampled", &rate, Some(&quota)));
    }

    let release = event
        .context
        .as_ref()
        .and_then(|ctx| ctx.release.as_ref())
        .cloned();
    let schema_version = event
        .schema_version
        .as_deref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "v1".to_string());

    let mut stacktrace = event.exception.stacktrace.clone();
    let (user_id, user_email) = extract_user(&event);
    if let (Some(release), Some(frames)) = (release.as_deref(), stacktrace.as_ref()) {
        let symbolicated = symbolicate_frames(&state.db, &event.project_id, release, frames).await;
        if let Ok(symbolicated) = symbolicated {
            stacktrace = Some(symbolicated);
        }
    }

    let stacktrace_ref = stacktrace.as_ref();
    let title = build_title(&event);
    let default_fingerprint = build_fingerprint(&event, stacktrace_ref);
    let grouping_match = apply_grouping_rules(&state.db, &event.project_id, &title, &event.exception.message)
        .await
        .unwrap_or(None);
    let mut fingerprint = grouping_match
        .as_ref()
        .map(|value| value.fingerprint.clone())
        .unwrap_or(default_fingerprint);
    let mut decision_reason = if grouping_match.is_some() { "rule" } else { "default" };
    if let Ok(Some(override_fp)) = resolve_grouping_override(&state.db, &event.project_id, &fingerprint).await {
        fingerprint = override_fp;
        decision_reason = "override";
    }
    let level = level_to_string(&event.level);
    let occurred_at = parse_timestamp(&event.timestamp);

    let event_uuid = Uuid::parse_str(&event.event_id).unwrap_or_else(|_| Uuid::new_v4());

    let context = build_context_with_culprit(&event.context, stacktrace_ref);
    let stacktrace_json = to_json(&stacktrace);
    let sdk = to_json(&event.sdk);
    let raw = to_json(&event);

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let existing_project = sqlx::query("SELECT api_key, webhook_url, slack_webhook_url, github_repo, github_token FROM projects WHERE id = $1")
        .bind(&event.project_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut webhook_url: Option<String> = None;
    let mut slack_webhook_url: Option<String> = None;
    let mut github_repo: Option<String> = None;
    let mut github_token: Option<String> = None;

    if let Some(row) = existing_project {
        let stored_key: String = row
            .try_get("api_key")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        webhook_url = row
            .try_get("webhook_url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        slack_webhook_url = row
            .try_get("slack_webhook_url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        github_repo = row
            .try_get("github_repo")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        github_token = row
            .try_get("github_token")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        if stored_key != api_key {
            return Err((StatusCode::UNAUTHORIZED, "api key invalide".to_string()));
        }
    } else {
        sqlx::query("INSERT INTO projects (id, name, api_key) VALUES ($1, $1, $2)")
            .bind(&event.project_id)
            .bind(&api_key)
            .execute(&mut *tx)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    }

    let existing_issue = sqlx::query("SELECT id, status FROM issues WHERE project_id = $1 AND fingerprint = $2")
        .bind(&event.project_id)
        .bind(&fingerprint)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut is_new_issue = false;
    let mut is_regression = false;

    let issue_id = if let Some(row) = existing_issue {
        let issue_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        if status == "resolved" {
            is_regression = true;
            sqlx::query(
                "UPDATE issues SET status = 'open', regressed_at = $1 WHERE id = $2",
            )
            .bind(occurred_at)
            .bind(issue_id)
            .execute(&mut *tx)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        }

        sqlx::query(
            "UPDATE issues SET last_seen = $1, count_total = count_total + 1, last_release = COALESCE($3, last_release), last_user_id = COALESCE($4, last_user_id), last_user_email = COALESCE($5, last_user_email) WHERE id = $2",
        )
        .bind(occurred_at)
        .bind(issue_id)
        .bind(&release)
        .bind(&user_id)
        .bind(&user_email)
        .execute(&mut *tx)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        issue_id
    } else {
        let new_issue_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO issues (id, project_id, fingerprint, title, level, first_seen, last_seen, count_total, first_release, last_release, last_user_id, last_user_email)\
            VALUES ($1, $2, $3, $4, $5, $6, $6, 1, $7, $7, $8, $9)",
        )
        .bind(new_issue_id)
        .bind(&event.project_id)
        .bind(&fingerprint)
        .bind(&title)
        .bind(level)
        .bind(occurred_at)
        .bind(&release)
        .bind(&user_id)
        .bind(&user_email)
        .execute(&mut *tx)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        is_new_issue = true;

        new_issue_id
    };

    sqlx::query(
        "INSERT INTO events (id, issue_id, project_id, occurred_at, level, release, user_id, user_email, message, exception_type, exception_message, stacktrace, context, sdk, raw, schema_version)\
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(event_uuid)
    .bind(issue_id)
    .bind(&event.project_id)
    .bind(occurred_at)
    .bind(level)
    .bind(&release)
    .bind(&user_id)
    .bind(&user_email)
    .bind(&event.message)
    .bind(&event.exception.kind)
    .bind(&event.exception.message)
    .bind(stacktrace_json)
    .bind(context)
    .bind(sdk)
    .bind(&raw)
    .bind(&schema_version)
    .execute(&mut *tx)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let algorithm_version = env::var("GROUPING_ALGO_VERSION").unwrap_or_else(|_| "v1".to_string());
    let decision_row = sqlx::query(
        "INSERT INTO grouping_decisions (event_id, issue_id, project_id, fingerprint, algorithm_version, reason)\
        VALUES ($1, $2, $3, $4, $5, $6)\
        RETURNING id",
    )
    .bind(event_uuid)
    .bind(issue_id)
    .bind(&event.project_id)
    .bind(&fingerprint)
    .bind(&algorithm_version)
    .bind(decision_reason)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    if decision_reason == "rule" {
        state.metrics.grouping_rule_total.fetch_add(1, Ordering::Relaxed);
        if let Some(rule_match) = grouping_match.as_ref() {
            let decision_id: Uuid = decision_row
                .try_get("id")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            sqlx::query(
                "INSERT INTO grouping_rules_applied (decision_id, rule_id, rule_name, matched)\
                VALUES ($1, $2, $3, true)",
            )
            .bind(decision_id)
            .bind(rule_match.rule_id)
            .bind(&rule_match.rule_name)
            .execute(&mut *tx)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        }
    } else if decision_reason == "override" {
        state.metrics.grouping_override_total.fetch_add(1, Ordering::Relaxed);
    } else {
        state.metrics.grouping_default_total.fetch_add(1, Ordering::Relaxed);
    }

    tx.commit()
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    info!("event ingéré pour project_id={}, issue_id={}", event.project_id, issue_id);

    if let Some(token) = github_token {
        github_token = match decrypt_secret(&token) {
            Ok(value) => Some(value),
            Err(err) => {
                warn!("github token decrypt failed: {}", err);
                None
            }
        };
    }

    if is_new_issue || is_regression {
        let kind = if is_regression { "regression" } else { "new_issue" };
        let webhook_endpoints = sqlx::query(
            "SELECT id, url, secret FROM webhook_endpoints WHERE project_id = $1 AND enabled = true",
        )
        .bind(&event.project_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        if let Some(url) = webhook_url {
            let _ = enqueue_job(
                &state.db,
                Some(&event.project_id),
                "webhook",
                json!({
                    "url": url,
                    "kind": kind,
                    "project_id": event.project_id,
                    "issue_id": issue_id.to_string(),
                    "fingerprint": fingerprint,
                    "title": title
                }),
            )
            .await;
        }
        if !webhook_endpoints.is_empty() {
            for endpoint in webhook_endpoints {
                let endpoint_id: Uuid = endpoint.try_get("id").unwrap_or_else(|_| Uuid::new_v4());
                let url: Option<String> = endpoint.try_get("url").ok();
                if let Some(url) = url {
                    let secret: Option<String> = endpoint.try_get("secret").ok();
                    let _ = enqueue_job(
                        &state.db,
                        Some(&event.project_id),
                        "webhook_v2",
                        json!({
                            "endpoint_id": endpoint_id.to_string(),
                            "url": url,
                            "secret": secret,
                            "kind": kind,
                            "project_id": event.project_id,
                            "issue_id": issue_id.to_string(),
                            "fingerprint": fingerprint,
                            "title": title
                        }),
                    )
                    .await;
                }
            }
        }
        if let Some(url) = slack_webhook_url {
            let _ = enqueue_job(
                &state.db,
                Some(&event.project_id),
                "slack",
                json!({
                    "url": url,
                    "kind": kind,
                    "project_id": event.project_id,
                    "issue_id": issue_id.to_string(),
                    "title": title
                }),
            )
            .await;
        }
        if is_new_issue {
            if let (Some(repo), Some(token)) = (github_repo.as_deref(), github_token.as_deref()) {
                let _ = enqueue_job(
                    &state.db,
                    Some(&event.project_id),
                    "github_issue",
                    json!({
                        "repo": repo,
                        "token": token,
                        "title": title,
                        "issue_id": issue_id.to_string(),
                        "project_id": event.project_id
                    }),
                )
                .await;
            }
        }
        let _ = enqueue_job(
            &state.db,
            Some(&event.project_id),
            "email",
            json!({
                "kind": kind,
                "project_id": event.project_id,
                "issue_id": issue_id.to_string(),
                "title": title
            }),
        )
        .await;
    }

    let _ = apply_assignment_rules(&state.db, &event.project_id, &title, &event.exception.message, issue_id).await;
    let _ = apply_ownership_rules(&state.db, &event.project_id, &title, &event.exception.message, issue_id).await;
    let insight_confidence = upsert_issue_insight(
        &state.db,
        &event.project_id,
        issue_id,
        &title,
        stacktrace_ref,
        release.as_deref(),
        is_regression.then_some(occurred_at),
    )
    .await
    .unwrap_or(None);
    if let Some(confidence) = insight_confidence {
        let scaled = (confidence * 1000.0).round().max(0.0) as u64;
        state.metrics.rca_confidence_sum.fetch_add(scaled, Ordering::Relaxed);
        state.metrics.rca_confidence_count.fetch_add(1, Ordering::Relaxed);
    }

    let _ = apply_alert_rules(&state.db, &event.project_id).await;
    let cost_bytes = estimate_value_bytes(&raw);
    let cost_units = estimate_cost_units("event", cost_bytes);
    let _ = record_cost(
        &state.db,
        &event.project_id,
        event_uuid,
        "event",
        cost_units,
        cost_bytes as i64,
    )
    .await;

    increment_usage(&state.db, &event.project_id, 1).await?;
    Ok(respond_with_limits(StatusCode::OK, "accepted", &rate, Some(&quota)))
}

async fn ingest_replay(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(replay): Json<ReplayEnvelope>,
) -> Result<Response, (StatusCode, String)> {
    let api_key = get_api_key(&headers)?;
    ensure_project(&state.db, &replay.project_id, &api_key).await?;
    if let Some(response) = maybe_redirect_region(&state.db, &replay.project_id).await? {
        return Ok(response);
    }
    let (rate, quota) = evaluate_limits(&state, &replay.project_id, 1).await?;
    if !rate.allowed {
        state.metrics.events_rate_limited_total.fetch_add(1, Ordering::Relaxed);
        return Ok(respond_with_limits(StatusCode::TOO_MANY_REQUESTS, "rate limit", &rate, Some(&quota)));
    }
    if !quota.allowed {
        state.metrics.events_quota_limited_total.fetch_add(1, Ordering::Relaxed);
        return Ok(respond_with_limits(StatusCode::TOO_MANY_REQUESTS, "quota exceeded", &rate, Some(&quota)));
    }
    state.metrics.replays_total.fetch_add(1, Ordering::Relaxed);

    let started_at = parse_timestamp(&replay.timestamp);
    let duration = replay.duration_ms.unwrap_or(0.0);
    let user_id = replay.user.as_ref().and_then(|u| u.id.clone());
    let user_email = replay.user.as_ref().and_then(|u| u.email.clone());

    let replay_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO replays (id, project_id, session_id, started_at, duration_ms, url, user_id, user_email, breadcrumbs, events, payload)\
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(replay_id)
    .bind(&replay.project_id)
    .bind(&replay.session_id)
    .bind(started_at)
    .bind(duration)
    .bind(&replay.url)
    .bind(&user_id)
    .bind(&user_email)
    .bind(to_json(&replay.breadcrumbs))
    .bind(to_json(&replay.events))
    .bind(&replay.payload)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let (trace_id, issue_id) = extract_replay_links(&replay.payload, &replay.events);
    if trace_id.is_some() || issue_id.is_some() {
        let issue_uuid = issue_id
            .as_deref()
            .and_then(|value| Uuid::parse_str(value).ok());

        sqlx::query(
            "INSERT INTO replay_links (project_id, replay_id, issue_id, trace_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(&replay.project_id)
        .bind(replay_id)
        .bind(issue_uuid)
        .bind(trace_id.as_deref())
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    }

    if let Some(trace_id) = trace_id.as_deref() {
        let _ = insert_signal_link(
            &state.db,
            &replay.project_id,
            "trace",
            trace_id,
            "replay",
            &replay_id.to_string(),
            Some(1.0),
        )
        .await;
    }
    if let Some(issue_uuid) = issue_id.as_deref().and_then(|value| Uuid::parse_str(value).ok()) {
        let _ = insert_signal_link(
            &state.db,
            &replay.project_id,
            "issue",
            &issue_uuid.to_string(),
            "replay",
            &replay_id.to_string(),
            Some(1.0),
        )
        .await;
    }

    let replay_bytes = estimate_value_bytes(&replay.payload);
    let replay_units = estimate_cost_units("replay", replay_bytes);
    let _ = record_cost(
        &state.db,
        &replay.project_id,
        replay_id,
        "replay",
        replay_units,
        replay_bytes as i64,
    )
    .await;

    increment_usage(&state.db, &replay.project_id, 1).await?;
    Ok(respond_with_limits(StatusCode::OK, "accepted", &rate, Some(&quota)))
}

async fn ingest_transaction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(tx): Json<TransactionEnvelope>,
) -> Result<Response, (StatusCode, String)> {
    let api_key = get_api_key(&headers)?;
    ensure_project(&state.db, &tx.project_id, &api_key).await?;
    if let Some(response) = maybe_redirect_region(&state.db, &tx.project_id).await? {
        return Ok(response);
    }
    let (rate, quota) = evaluate_limits(&state, &tx.project_id, 1).await?;
    if !rate.allowed {
        state.metrics.events_rate_limited_total.fetch_add(1, Ordering::Relaxed);
        return Ok(respond_with_limits(StatusCode::TOO_MANY_REQUESTS, "rate limit", &rate, Some(&quota)));
    }
    if !quota.allowed {
        state.metrics.events_quota_limited_total.fetch_add(1, Ordering::Relaxed);
        return Ok(respond_with_limits(StatusCode::TOO_MANY_REQUESTS, "quota exceeded", &rate, Some(&quota)));
    }
    state.metrics.transactions_total.fetch_add(1, Ordering::Relaxed);

    let adaptive_rate = adaptive_sampling_rate(&state.db, &tx.project_id).await?;
    let sample_rate = (tx.sample_rate.unwrap_or(1.0).clamp(0.0, 1.0) * adaptive_rate).clamp(0.0, 1.0);
    if sample_rate < 1.0 {
        let mut rng = rand::thread_rng();
        let value: f64 = rng.gen();
        if value > sample_rate {
            state.metrics.transactions_sampled_total.fetch_add(1, Ordering::Relaxed);
            return Ok(respond_with_limits(StatusCode::OK, "sampled", &rate, Some(&quota)));
        }
    }

    let occurred_at = parse_timestamp(&tx.timestamp);
    let status = tx.status.clone().unwrap_or_else(|| "ok".to_string());

    let transaction_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO transactions (id, project_id, trace_id, span_id, name, status, duration_ms, occurred_at, tags, measurements)\
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(transaction_id)
    .bind(&tx.project_id)
    .bind(&tx.trace_id)
    .bind(&tx.span_id)
    .bind(&tx.name)
    .bind(&status)
    .bind(tx.duration_ms)
    .bind(occurred_at)
    .bind(to_json(&tx.tags))
    .bind(to_json(&tx.measurements))
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let _ = insert_signal_link(
        &state.db,
        &tx.project_id,
        "trace",
        &tx.trace_id,
        "transaction",
        &transaction_id.to_string(),
        Some(1.0),
    )
    .await;

    if let Some(ref spans) = tx.spans {
        for span in spans {
            let start_ts = parse_timestamp(&span.start_timestamp);
            sqlx::query(
                "INSERT INTO spans (project_id, trace_id, span_id, parent_id, op, description, status, start_ts, duration_ms, tags)\
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)\
                ON CONFLICT (project_id, span_id) DO UPDATE SET\
                    parent_id = EXCLUDED.parent_id,\
                    op = EXCLUDED.op,\
                    description = EXCLUDED.description,\
                    status = EXCLUDED.status,\
                    start_ts = EXCLUDED.start_ts,\
                    duration_ms = EXCLUDED.duration_ms,\
                    tags = EXCLUDED.tags",
            )
            .bind(&tx.project_id)
            .bind(&tx.trace_id)
            .bind(&span.span_id)
            .bind(&span.parent_id)
            .bind(&span.op)
            .bind(&span.description)
            .bind(&span.status)
            .bind(start_ts)
            .bind(span.duration_ms)
            .bind(to_json(&span.tags))
            .execute(&state.db)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        }
    }

    let tx_bytes = estimate_value_bytes(&to_json(&tx));
    let tx_units = estimate_cost_units("transaction", tx_bytes);
    let _ = record_cost(
        &state.db,
        &tx.project_id,
        transaction_id,
        "transaction",
        tx_units,
        tx_bytes as i64,
    )
    .await;

    increment_usage(&state.db, &tx.project_id, 1).await?;
    Ok(respond_with_limits(StatusCode::OK, "accepted", &rate, Some(&quota)))
}

async fn ingest_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(profile): Json<ProfileEnvelope>,
) -> Result<Response, (StatusCode, String)> {
    let api_key = get_api_key(&headers)?;
    ensure_project(&state.db, &profile.project_id, &api_key).await?;
    if let Some(response) = maybe_redirect_region(&state.db, &profile.project_id).await? {
        return Ok(response);
    }
    let (rate, quota) = evaluate_limits(&state, &profile.project_id, 1).await?;
    if !rate.allowed {
        state.metrics.events_rate_limited_total.fetch_add(1, Ordering::Relaxed);
        return Ok(respond_with_limits(StatusCode::TOO_MANY_REQUESTS, "rate limit", &rate, Some(&quota)));
    }
    if !quota.allowed {
        state.metrics.events_quota_limited_total.fetch_add(1, Ordering::Relaxed);
        return Ok(respond_with_limits(StatusCode::TOO_MANY_REQUESTS, "quota exceeded", &rate, Some(&quota)));
    }
    state.metrics.profiles_total.fetch_add(1, Ordering::Relaxed);

    let profile_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO profiles (id, project_id, trace_id, profile) VALUES ($1, $2, $3, $4)",
    )
    .bind(profile_id)
    .bind(&profile.project_id)
    .bind(&profile.trace_id)
    .bind(&profile.profile)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let _ = insert_signal_link(
        &state.db,
        &profile.project_id,
        "trace",
        &profile.trace_id,
        "profile",
        &profile_id.to_string(),
        Some(1.0),
    )
    .await;

    let profile_bytes = estimate_value_bytes(&profile.profile);
    let profile_units = estimate_cost_units("profile", profile_bytes);
    let _ = record_cost(
        &state.db,
        &profile.project_id,
        profile_id,
        "profile",
        profile_units,
        profile_bytes as i64,
    )
    .await;

    increment_usage(&state.db, &profile.project_id, 1).await?;
    Ok(respond_with_limits(StatusCode::OK, "accepted", &rate, Some(&quota)))
}

fn get_api_key(headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    let key = headers
        .get("x-ember-key")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string());

    match key {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err((StatusCode::UNAUTHORIZED, "api key manquante".to_string())),
    }
}

fn load_secrets_key() -> Result<aes_gcm::Key<Aes256Gcm>, String> {
    let raw = env::var("EMBER_SECRETS_KEY").map_err(|_| "EMBER_SECRETS_KEY manquant".to_string())?;
    let key_bytes = BASE64
        .decode(raw.trim().as_bytes())
        .map_err(|_| "EMBER_SECRETS_KEY invalide".to_string())?;
    if key_bytes.len() != 32 {
        return Err("EMBER_SECRETS_KEY doit faire 32 octets (base64)".to_string());
    }
    Ok(*aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes))
}

fn decrypt_secret(value: &str) -> Result<String, String> {
    if !value.starts_with("v1:") {
        return Ok(value.to_string());
    }
    let mut parts = value.splitn(3, ':');
    let _ = parts.next();
    let nonce_b64 = parts.next().ok_or("secret invalide".to_string())?;
    let ciphertext_b64 = parts.next().ok_or("secret invalide".to_string())?;
    let key = load_secrets_key()?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = BASE64
        .decode(nonce_b64.as_bytes())
        .map_err(|_| "secret invalide".to_string())?;
    let ciphertext = BASE64
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| "secret invalide".to_string())?;
    let plaintext = cipher
        .decrypt(aes_gcm::Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "secret invalide".to_string())?;
    String::from_utf8(plaintext).map_err(|_| "secret invalide".to_string())
}

async fn ensure_project(
    db: &PgPool,
    project_id: &str,
    api_key: &str,
) -> Result<(), (StatusCode, String)> {
    let row = sqlx::query("SELECT api_key FROM projects WHERE id = $1")
        .bind(project_id)
        .fetch_optional(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    if let Some(row) = row {
        let stored_key: String = row
            .try_get("api_key")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        if stored_key != api_key {
            return Err((StatusCode::UNAUTHORIZED, "api key invalide".to_string()));
        }
        sqlx::query("UPDATE projects SET api_key_last_used_at = now() WHERE id = $1")
            .bind(project_id)
            .execute(db)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        return Ok(());
    }

    sqlx::query("INSERT INTO projects (id, name, api_key, api_key_last_used_at, api_key_rotated_at) VALUES ($1, $1, $2, now(), now())")
        .bind(project_id)
        .bind(api_key)
        .execute(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(())
}

fn default_rate_limit_per_min() -> i64 {
    env::var("RATE_LIMIT_PER_MIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120)
}

fn default_quota_soft() -> i64 {
    env::var("QUOTA_SOFT_PER_MONTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500000)
}

fn default_quota_hard() -> i64 {
    env::var("QUOTA_HARD_PER_MONTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(750000)
}

async fn get_project_limits(db: &PgPool, project_id: &str) -> Result<(i64, i64, i64), (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT rate_limit_per_min, quota_soft_limit, quota_hard_limit FROM projects WHERE id = $1",
    )
    .bind(project_id)
    .fetch_optional(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    if let Some(row) = row {
        let rate_limit: Option<i64> = row
            .try_get("rate_limit_per_min")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let quota_soft: Option<i64> = row
            .try_get("quota_soft_limit")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let quota_hard: Option<i64> = row
            .try_get("quota_hard_limit")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        return Ok((
            rate_limit.unwrap_or_else(default_rate_limit_per_min),
            quota_soft.unwrap_or_else(default_quota_soft),
            quota_hard.unwrap_or_else(default_quota_hard),
        ));
    }

    Ok((default_rate_limit_per_min(), default_quota_soft(), default_quota_hard()))
}

async fn maybe_redirect_region(
    db: &PgPool,
    project_id: &str,
) -> Result<Option<Response>, (StatusCode, String)> {
    let current = env::var("REGION_NAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let Some(current_region) = current else {
        return Ok(None);
    };

    let target = resolve_project_region(db, project_id).await?;
    if let Some(target) = target {
        if target.name != current_region {
            let mut response = (StatusCode::TEMPORARY_REDIRECT, "wrong region").into_response();
            let headers = response.headers_mut();
            let _ = headers.insert("Location", HeaderValue::from_str(&target.ingest_url).unwrap());
            let _ = headers.insert("X-Ember-Region", HeaderValue::from_str(&target.name).unwrap());
            return Ok(Some(response));
        }
    }

    Ok(None)
}

async fn resolve_project_region(
    db: &PgPool,
    project_id: &str,
) -> Result<Option<RegionTarget>, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT o.data_region AS data_region\
        FROM organizations o\
        JOIN teams t ON t.org_id = o.id\
        JOIN project_teams pt ON pt.team_id = t.id\
        WHERE pt.project_id = $1\
        LIMIT 1",
    )
    .bind(project_id)
    .fetch_optional(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut region_name = row
        .and_then(|row| row.try_get::<Option<String>, _>("data_region").ok())
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if region_name.is_none() {
        region_name = env::var("DEFAULT_REGION")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
    }

    let region_row = if let Some(region) = region_name.as_deref() {
        sqlx::query(
            "SELECT name, api_base_url, ingest_url FROM regions WHERE name = $1 AND active = true",
        )
        .bind(region)
        .fetch_optional(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        sqlx::query(
            "SELECT name, api_base_url, ingest_url FROM regions WHERE active = true ORDER BY name ASC LIMIT 1",
        )
        .fetch_optional(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    };

    let Some(region_row) = region_row else {
        return Ok(None);
    };

    let name: String = region_row
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let ingest_url: String = region_row
        .try_get("ingest_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Some(RegionTarget {
        name,
        ingest_url,
    }))
}

async fn get_monthly_usage(db: &PgPool, project_id: &str) -> Result<i64, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT COALESCE(SUM(count), 0)::bigint AS total FROM project_usage_daily\
        WHERE project_id = $1 AND day >= date_trunc('month', now())::date",
    )
    .bind(project_id)
    .fetch_one(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let total: i64 = row
        .try_get("total")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(total)
}

async fn increment_usage(db: &PgPool, project_id: &str, count: i64) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "INSERT INTO project_usage_daily (project_id, day, count) VALUES ($1, CURRENT_DATE, $2)\
        ON CONFLICT (project_id, day) DO UPDATE SET count = project_usage_daily.count + EXCLUDED.count",
    )
    .bind(project_id)
    .bind(count)
    .execute(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(())
}

async fn record_ingest_drop(db: &PgPool, project_id: &str, reason: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ingest_drops_daily (project_id, day, reason, count)\
        VALUES ($1, CURRENT_DATE, $2, 1)\
        ON CONFLICT (project_id, day, reason) DO UPDATE SET\
            count = ingest_drops_daily.count + 1",
    )
    .bind(project_id)
    .bind(reason)
    .execute(db)
    .await?;
    Ok(())
}

fn quota_reset_seconds() -> i64 {
    let now = Utc::now();
    let mut year = now.year();
    let mut month = now.month();
    if month == 12 {
        year += 1;
        month = 1;
    } else {
        month += 1;
    }
    let next = Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0).unwrap();
    (next - now).num_seconds().max(0)
}

async fn check_quota(db: &PgPool, project_id: &str, soft: i64, hard: i64, count: i64) -> Result<QuotaInfo, (StatusCode, String)> {
    let current = get_monthly_usage(db, project_id).await?;
    let next_total = current + count;
    let limit = hard.max(soft);

    if hard > 0 && next_total > hard {
        return Ok(QuotaInfo {
            limit,
            remaining: (hard - current).max(0),
            reset: quota_reset_seconds(),
            status: "hard".to_string(),
            allowed: false,
        });
    }

    let status = if soft > 0 && next_total > soft {
        "soft"
    } else {
        "ok"
    };

    let remaining = if hard > 0 { (hard - next_total).max(0) } else { 0 };

    Ok(QuotaInfo {
        limit,
        remaining,
        reset: quota_reset_seconds(),
        status: status.to_string(),
        allowed: true,
    })
}

fn build_title(event: &EventEnvelope) -> String {
    let mut title = format!("{}: {}", event.exception.kind, event.exception.message);
    if title.len() > 140 {
        title.truncate(140);
    }
    title
}

fn build_fingerprint(event: &EventEnvelope, stacktrace: Option<&Vec<ember_shared::StackFrame>>) -> String {
    let mut hasher = Sha256::new();
    let normalized_message = normalize_message(&event.exception.message);
    hasher.update(event.exception.kind.as_bytes());
    hasher.update(b"|");
    hasher.update(normalized_message.as_bytes());

    if let Some(frames) = stacktrace {
        let mut added = 0;
        let mut candidates: Vec<_> = frames
            .iter()
            .filter(|f| !is_noise_frame(f))
            .collect();

        candidates.sort_by_key(|f| !f.in_app.unwrap_or(true));

        for frame in candidates {
            if added >= 5 {
                break;
            }
            hasher.update(b"|");
            hasher.update(frame.function.as_bytes());
            hasher.update(b"|");
            hasher.update(frame.filename.as_bytes());
            hasher.update(b"|");
            hasher.update(frame.line.to_string().as_bytes());
            added += 1;
        }
    }

    hex::encode(hasher.finalize())
}

fn normalize_message(message: &str) -> String {
    let uuid_re = regex_uuid();
    let number_re = regex_number();
    let hex_re = regex_hex();

    let mut normalized = message.to_lowercase();
    normalized = uuid_re.replace_all(&normalized, "{uuid}").into_owned();
    normalized = hex_re.replace_all(&normalized, "{hex}").into_owned();
    normalized = number_re.replace_all(&normalized, "{num}").into_owned();
    normalized
}

fn is_noise_frame(frame: &ember_shared::StackFrame) -> bool {
    let filename = frame.filename.to_lowercase();
    let module = frame.module.as_ref().map(|m| m.to_lowercase());

    filename.contains("node_modules")
        || filename.contains("/rustc/")
        || filename.contains("/lib/")
        || filename.contains("\\windows\\")
        || module.map(|m| m.contains("std"))
            .unwrap_or(false)
}

fn regex_uuid() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}").unwrap())
}

fn regex_number() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\b\d+\b").unwrap())
}

fn regex_hex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\b0x[0-9a-f]+\b").unwrap())
}

fn level_to_string(level: &EventLevel) -> &'static str {
    match level {
        EventLevel::Error => "error",
        EventLevel::Warning => "warning",
        EventLevel::Info => "info",
        EventLevel::Debug => "debug",
    }
}

fn parse_timestamp(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|err| {
            error!("timestamp invalide: {}", err);
            Utc::now()
        })
}

fn to_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn estimate_value_bytes(value: &Value) -> usize {
    value.to_string().as_bytes().len()
}

fn estimate_cost_units(kind: &str, storage_bytes: usize) -> f64 {
    let base = match kind {
        "event" => 1.0,
        "transaction" => 0.6,
        "profile" => 1.2,
        "replay" => 2.0,
        _ => 1.0,
    };
    let storage_units = (storage_bytes as f64) / 1024.0 * 0.01;
    (base + storage_units).max(0.1)
}

async fn record_cost(
    db: &PgPool,
    project_id: &str,
    entity_id: Uuid,
    kind: &str,
    units: f64,
    storage_bytes: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO cost_units (project_id, entity_id, kind, units, storage_bytes)\
        VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(project_id)
    .bind(entity_id)
    .bind(kind)
    .bind(units)
    .bind(storage_bytes)
    .execute(db)
    .await?;

    sqlx::query(
        "INSERT INTO project_cost_daily (project_id, day, units, storage_bytes)\
        VALUES ($1, CURRENT_DATE, $2, $3)\
        ON CONFLICT (project_id, day) DO UPDATE SET\
            units = project_cost_daily.units + EXCLUDED.units,\
            storage_bytes = project_cost_daily.storage_bytes + EXCLUDED.storage_bytes",
    )
    .bind(project_id)
    .bind(units)
    .bind(storage_bytes)
    .execute(db)
    .await?;

    Ok(())
}

impl RateLimiter {
    fn new(_per_minute: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn check(&self, key: &str, per_minute: u32) -> RateLimitInfo {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();
        let per_minute = per_minute.max(10);
        let rate = per_minute as f64 / 60.0;

        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: per_minute as f64,
            last: now,
        });

        let elapsed = (now - bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(per_minute as f64);
        bucket.last = now;

        let limit = per_minute as i64;
        let mut allowed = false;

        if bucket.tokens >= 1.0 {
            allowed = true;
            bucket.tokens -= 1.0;
        }

        let remaining = bucket.tokens.floor().max(0.0) as i64;
        let reset = if bucket.tokens >= 1.0 || rate == 0.0 {
            0
        } else {
            ((1.0 - bucket.tokens) / rate).ceil() as i64
        };

        RateLimitInfo {
            limit,
            remaining,
            reset,
            allowed,
        }
    }
}

fn respond_with_limits(status: StatusCode, body: &'static str, rate: &RateLimitInfo, quota: Option<&QuotaInfo>) -> Response {
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    let _ = headers.insert("x-ratelimit-limit", HeaderValue::from_str(&rate.limit.to_string()).unwrap());
    let _ = headers.insert("x-ratelimit-remaining", HeaderValue::from_str(&rate.remaining.to_string()).unwrap());
    let _ = headers.insert("x-ratelimit-reset", HeaderValue::from_str(&rate.reset.to_string()).unwrap());
    if let Some(quota) = quota {
        let _ = headers.insert("x-quota-limit", HeaderValue::from_str(&quota.limit.to_string()).unwrap());
        let _ = headers.insert("x-quota-remaining", HeaderValue::from_str(&quota.remaining.to_string()).unwrap());
        let _ = headers.insert("x-quota-reset", HeaderValue::from_str(&quota.reset.to_string()).unwrap());
        let _ = headers.insert("x-quota-status", HeaderValue::from_str(&quota.status).unwrap());
    }
    response
}

fn job_backpressure_limit() -> i64 {
    env::var("JOB_BACKPRESSURE_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
}

fn job_max_attempts() -> i64 {
    env::var("JOB_MAX_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5)
}

impl Metrics {
    fn new() -> Self {
        Self {
            events_total: Arc::new(AtomicU64::new(0)),
            events_rate_limited_total: Arc::new(AtomicU64::new(0)),
            events_quota_limited_total: Arc::new(AtomicU64::new(0)),
            transactions_total: Arc::new(AtomicU64::new(0)),
            transactions_sampled_total: Arc::new(AtomicU64::new(0)),
            profiles_total: Arc::new(AtomicU64::new(0)),
            replays_total: Arc::new(AtomicU64::new(0)),
            grouping_default_total: Arc::new(AtomicU64::new(0)),
            grouping_rule_total: Arc::new(AtomicU64::new(0)),
            grouping_override_total: Arc::new(AtomicU64::new(0)),
            rca_confidence_sum: Arc::new(AtomicU64::new(0)),
            rca_confidence_count: Arc::new(AtomicU64::new(0)),
        }
    }

    fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# TYPE ember_ingest_events_total counter\n");
        out.push_str(&format!("ember_ingest_events_total {}\n", self.events_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_ingest_events_rate_limited_total counter\n");
        out.push_str(&format!("ember_ingest_events_rate_limited_total {}\n", self.events_rate_limited_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_ingest_events_quota_limited_total counter\n");
        out.push_str(&format!("ember_ingest_events_quota_limited_total {}\n", self.events_quota_limited_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_ingest_transactions_total counter\n");
        out.push_str(&format!("ember_ingest_transactions_total {}\n", self.transactions_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_ingest_transactions_sampled_total counter\n");
        out.push_str(&format!("ember_ingest_transactions_sampled_total {}\n", self.transactions_sampled_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_ingest_profiles_total counter\n");
        out.push_str(&format!("ember_ingest_profiles_total {}\n", self.profiles_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_ingest_replays_total counter\n");
        out.push_str(&format!("ember_ingest_replays_total {}\n", self.replays_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_grouping_default_total counter\n");
        out.push_str(&format!("ember_grouping_default_total {}\n", self.grouping_default_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_grouping_rule_total counter\n");
        out.push_str(&format!("ember_grouping_rule_total {}\n", self.grouping_rule_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_grouping_override_total counter\n");
        out.push_str(&format!("ember_grouping_override_total {}\n", self.grouping_override_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_rca_confidence_sum counter\n");
        out.push_str(&format!("ember_rca_confidence_sum {}\n", self.rca_confidence_sum.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_rca_confidence_count counter\n");
        out.push_str(&format!("ember_rca_confidence_count {}\n", self.rca_confidence_count.load(Ordering::Relaxed)));
        out
    }
}

async fn symbolicate_frames(
    db: &PgPool,
    project_id: &str,
    release: &str,
    frames: &[ember_shared::StackFrame],
) -> Result<Vec<ember_shared::StackFrame>, sqlx::Error> {
    use std::collections::HashMap;

    let mut cache: HashMap<String, SourceMap> = HashMap::new();
    let mut output = Vec::with_capacity(frames.len());

    for frame in frames {
        let minified = frame.filename.clone();
        let mapped = if let (Some(line), Some(col)) = (Some(frame.line), frame.col) {
            if let Some(map) = cache.get(&minified) {
                map.lookup_token(line as u32, col as u32)
            } else {
                let row = sqlx::query("SELECT map_text FROM sourcemaps WHERE project_id = $1 AND release = $2 AND minified_url = $3")
                    .bind(project_id)
                    .bind(release)
                    .bind(&minified)
                    .fetch_optional(db)
                    .await?;

                if let Some(row) = row {
                    let map_text: String = row.try_get("map_text")?;
                    if let Ok(map) = SourceMap::from_slice(map_text.as_bytes()) {
                        cache.insert(minified.clone(), map);
                        cache.get(&minified).and_then(|map| map.lookup_token(line as u32, col as u32))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        } else {
            None
        };

        if let Some(token) = mapped {
            let source = token.get_source().unwrap_or(&minified).to_string();
            let src_line = token.get_src_line();
            let (pre_context, context_line, post_context) =
                extract_source_context(cache.get(&minified), &source, src_line);

            output.push(ember_shared::StackFrame {
                function: token.get_name().unwrap_or("(anonymous)").to_string(),
                filename: source.clone(),
                line: src_line as i64,
                col: Some(token.get_src_col() as i64),
                module: frame.module.clone(),
                in_app: Some(true),
                pre_context,
                context_line,
                post_context,
                source_language: infer_source_language(&source),
            });
        } else {
            output.push(frame.clone());
        }
    }

    Ok(output)
}

fn extract_source_context(
    map: Option<&SourceMap>,
    source: &str,
    src_line: u32,
) -> (Option<Vec<String>>, Option<String>, Option<Vec<String>>) {
    let map = match map {
        Some(map) => map,
        None => return (None, None, None),
    };

    let mut source_idx = None;
    let source_count = map.get_source_count();
    for idx in 0..source_count {
        if let Some(value) = map.get_source(idx) {
            if value == source {
                source_idx = Some(idx);
                break;
            }
        }
    }
    let source_idx = match source_idx {
        Some(value) => value,
        None => return (None, None, None),
    };
    let contents = match map.get_source_contents(source_idx) {
        Some(value) if !value.is_empty() => value,
        _ => return (None, None, None),
    };

    let lines: Vec<&str> = contents.lines().collect();
    if lines.is_empty() {
        return (None, None, None);
    }

    let idx = src_line.saturating_sub(1) as usize;
    if idx >= lines.len() {
        return (None, None, None);
    }

    let start = idx.saturating_sub(3);
    let end = (idx + 3).min(lines.len().saturating_sub(1));
    let pre_context = if start < idx {
        Some(lines[start..idx].iter().map(|value| value.to_string()).collect())
    } else {
        None
    };
    let context_line = Some(lines[idx].to_string());
    let post_context = if idx + 1 <= end {
        Some(lines[idx + 1..=end].iter().map(|value| value.to_string()).collect())
    } else {
        None
    };

    (pre_context, context_line, post_context)
}

fn infer_source_language(filename: &str) -> Option<String> {
    let lower = filename.to_lowercase();
    let ext = lower.split('.').last().unwrap_or("");
    let language = match ext {
        "js" | "mjs" | "cjs" => "javascript",
        "jsx" => "javascript",
        "ts" => "typescript",
        "tsx" => "typescript",
        "py" => "python",
        "rb" => "ruby",
        "java" => "java",
        "kt" | "kts" => "kotlin",
        "cs" => "csharp",
        "go" => "go",
        "rs" => "rust",
        "php" => "php",
        "swift" => "swift",
        _ => return None,
    };

    Some(language.to_string())
}

fn extract_user(event: &EventEnvelope) -> (Option<String>, Option<String>) {
    let user = event.context.as_ref().and_then(|ctx| ctx.user.as_ref());
    let id = user.and_then(|u| u.id.clone()).filter(|v| !v.is_empty());
    let email = user.and_then(|u| u.email.clone()).filter(|v| !v.is_empty());
    (id, email)
}

fn build_context_with_culprit(
    context: &Option<ember_shared::EventContext>,
    stacktrace: Option<&Vec<StackFrame>>,
) -> Value {
    let mut value = to_json(context);
    if let Some(culprit) = build_culprit(stacktrace) {
        if let Some(obj) = value.as_object_mut() {
            obj.insert("culprit".to_string(), Value::String(culprit));
        } else {
            value = json!({ "culprit": culprit });
        }
    }
    value
}

fn build_culprit(stacktrace: Option<&Vec<StackFrame>>) -> Option<String> {
    let frames = stacktrace?;
    let mut best: Option<&StackFrame> = None;
    for frame in frames {
        if frame.in_app.unwrap_or(false) {
            best = Some(frame);
            break;
        }
    }
    let frame = best.or_else(|| frames.first())?;
    let location = format!("{}:{}", frame.filename, frame.line);
    Some(format!("{} @ {}", frame.function, location))
}

struct GroupingRuleMatch {
    rule_id: Uuid,
    rule_name: String,
    fingerprint: String,
}

fn build_causal_chain(stacktrace: Option<&Vec<StackFrame>>) -> Option<Value> {
    let frames = stacktrace?;
    if frames.is_empty() {
        return None;
    }

    let in_app: Vec<&StackFrame> = frames.iter().filter(|f| f.in_app.unwrap_or(false)).collect();
    let mut candidates: Vec<&StackFrame> = if in_app.is_empty() {
        frames.iter().collect()
    } else {
        in_app
    };

    if candidates.len() > 5 {
        candidates.truncate(5);
    }

    let steps: Vec<Value> = candidates
        .iter()
        .enumerate()
        .map(|(idx, frame)| {
            json!({
                "rank": idx + 1,
                "function": frame.function,
                "file": frame.filename,
                "line": frame.line,
                "module": frame.module,
                "in_app": frame.in_app.unwrap_or(false),
                "context": frame.context_line,
                "language": frame.source_language
            })
        })
        .collect();

    if steps.is_empty() {
        None
    } else {
        Some(Value::Array(steps))
    }
}

fn build_rca_confidence(
    stacktrace: Option<&Vec<StackFrame>>,
    release: Option<&str>,
    regressed_at: Option<DateTime<Utc>>,
) -> f64 {
    let mut score: f64 = 0.35;
    let mut has_in_app = false;
    let mut has_context = false;

    if let Some(frames) = stacktrace {
        score += 0.1;
        has_in_app = frames.iter().any(|f| f.in_app.unwrap_or(false));
        has_context = frames
            .iter()
            .any(|f| f.context_line.as_ref().map(|v| !v.trim().is_empty()).unwrap_or(false));
    }

    if has_in_app {
        score += 0.2;
    }
    if has_context {
        score += 0.1;
    }
    if release.is_some() {
        score += 0.1;
    }
    if regressed_at.is_some() {
        score += 0.1;
    }

    score.clamp(0.2, 0.95)
}

async fn build_regression_map(
    db: &PgPool,
    issue_id: Uuid,
    release: Option<&str>,
    regressed_at: Option<DateTime<Utc>>,
) -> Result<Option<Value>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT project_id, first_release, last_release, regressed_at FROM issues WHERE id = $1",
    )
    .bind(issue_id)
    .fetch_optional(db)
    .await?;

    let row = match row {
        Some(row) => row,
        None => return Ok(None),
    };

    let project_id: String = row.try_get("project_id")?;
    let first_release: Option<String> = row.try_get("first_release")?;
    let last_release: Option<String> = row.try_get("last_release")?;
    let stored_regressed_at: Option<DateTime<Utc>> = row.try_get("regressed_at")?;
    let regressed_at = regressed_at.or(stored_regressed_at);

    let candidate_release = release.map(|value| value.to_string()).or_else(|| last_release.clone());
    let mut commits = Vec::new();
    if let Some(release) = candidate_release.as_deref() {
        let rows = sqlx::query(
            "SELECT commit_sha, message, author, timestamp FROM release_commits\
            WHERE project_id = $1 AND release = $2\
            ORDER BY timestamp DESC NULLS LAST\
            LIMIT 5",
        )
        .bind(&project_id)
        .bind(release)
        .fetch_all(db)
        .await?;

        for row in rows {
            let commit_sha: String = row.try_get("commit_sha")?;
            let message: Option<String> = row.try_get("message")?;
            let author: Option<String> = row.try_get("author")?;
            let timestamp: Option<DateTime<Utc>> = row.try_get("timestamp")?;
            commits.push(json!({
                "sha": commit_sha,
                "message": message,
                "author": author,
                "timestamp": timestamp.map(|value| value.to_rfc3339())
            }));
        }
    }

    let regression_window = match (first_release.as_deref(), last_release.as_deref()) {
        (Some(first), Some(last)) if first != last => Some(json!({ "from": first, "to": last })),
        _ => None,
    };

    Ok(Some(json!({
        "first_release": first_release,
        "last_release": last_release,
        "event_release": release,
        "regressed_at": regressed_at.map(|value| value.to_rfc3339()),
        "regression_window": regression_window,
        "candidate_commits": commits
    })))
}

fn extract_replay_links(
    payload: &Value,
    events: &Option<Vec<Value>>,
) -> (Option<String>, Option<String>) {
    let trace_id = find_string_field(payload, &["trace_id", "traceId"])
        .or_else(|| events.as_ref().and_then(|items| find_string_in_events(items, &["trace_id", "traceId"])));
    let issue_id = find_string_field(payload, &["issue_id", "issueId", "issue"])
        .or_else(|| events.as_ref().and_then(|items| find_string_in_events(items, &["issue_id", "issueId", "issue"])));

    (trace_id, issue_id)
}

fn find_string_in_events(items: &[Value], keys: &[&str]) -> Option<String> {
    for item in items {
        if let Some(value) = find_string_field(item, keys) {
            return Some(value);
        }
    }
    None
}

fn find_string_field(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(found) = map.get(*key).and_then(|v| v.as_str()) {
                    let trimmed = found.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
            for (_key, child) in map {
                if let Some(found) = find_string_field(child, keys) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => {
            for child in items {
                if let Some(found) = find_string_field(child, keys) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

async fn apply_grouping_rules(
    db: &PgPool,
    project_id: &str,
    title: &str,
    message: &str,
) -> Result<Option<GroupingRuleMatch>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, name, pattern, fingerprint FROM grouping_rules\
        WHERE project_id = $1 AND enabled = true\
        ORDER BY created_at ASC",
    )
    .bind(project_id)
    .fetch_all(db)
    .await?;

    for row in rows {
        let rule_id: Uuid = row.try_get("id")?;
        let rule_name: String = row.try_get("name")?;
        let pattern: String = row.try_get("pattern")?;
        let fingerprint: String = row.try_get("fingerprint")?;
        if let Ok(re) = Regex::new(&pattern) {
            if re.is_match(title) || re.is_match(message) {
                if !fingerprint.trim().is_empty() {
                    return Ok(Some(GroupingRuleMatch {
                        rule_id,
                        rule_name,
                        fingerprint,
                    }));
                }
            }
        }
    }

    Ok(None)
}

async fn insert_signal_link(
    db: &PgPool,
    project_id: &str,
    source_type: &str,
    source_id: &str,
    target_type: &str,
    target_id: &str,
    score: Option<f64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO signal_links (project_id, source_type, source_id, target_type, target_id, correlation_score)\
        VALUES ($1, $2, $3, $4, $5, $6)\
        ON CONFLICT DO NOTHING",
    )
    .bind(project_id)
    .bind(source_type)
    .bind(source_id)
    .bind(target_type)
    .bind(target_id)
    .bind(score)
    .execute(db)
    .await?;

    Ok(())
}

async fn resolve_grouping_override(
    db: &PgPool,
    project_id: &str,
    fingerprint: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT target_fingerprint FROM grouping_overrides WHERE project_id = $1 AND source_fingerprint = $2",
    )
    .bind(project_id)
    .bind(fingerprint)
    .fetch_optional(db)
    .await?;

    if let Some(row) = row {
        let target: String = row.try_get("target_fingerprint")?;
        if !target.trim().is_empty() {
            return Ok(Some(target));
        }
    }

    Ok(None)
}

async fn apply_alert_rules(db: &PgPool, project_id: &str) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, name, kind, threshold, window_minutes, cooldown_minutes, max_triggers_per_day, threshold_multiplier, baseline_minutes, channel, webhook_url, slack_webhook_url, email_to, last_triggered_at\
        FROM alert_rules\
        WHERE project_id = $1 AND enabled = true",
    )
    .bind(project_id)
    .fetch_all(db)
    .await?;

    let now = Utc::now();

    for row in rows {
        let rule_id: Uuid = row.try_get("id")?;
        let name: String = row.try_get("name")?;
        let kind: String = row.try_get("kind")?;
        let threshold: i32 = row.try_get("threshold")?;
        let window_minutes: i32 = row.try_get("window_minutes")?;
        let channel: String = row.try_get("channel")?;
        let cooldown_minutes: i32 = row.try_get("cooldown_minutes")?;
        let max_triggers_per_day: i32 = row.try_get("max_triggers_per_day")?;
        let threshold_multiplier: Option<f64> = row.try_get("threshold_multiplier")?;
        let baseline_minutes: Option<i32> = row.try_get("baseline_minutes")?;
        let webhook_url: Option<String> = row.try_get("webhook_url")?;
        let slack_webhook_url: Option<String> = row.try_get("slack_webhook_url")?;
        let email_to: Option<String> = row.try_get("email_to")?;
        let last_triggered_at: Option<DateTime<Utc>> = row.try_get("last_triggered_at")?;
        if is_alert_silenced(db, project_id, rule_id).await? {
            continue;
        }

        let can_trigger = match last_triggered_at {
            Some(last) => now - last > Duration::minutes(cooldown_minutes.max(1) as i64),
            None => true,
        };

        match kind.as_str() {
            "event_rate" => {
                let window_minutes = window_minutes.max(1) as i64;
                let mut threshold = threshold.max(1) as i64;

                let count_row = sqlx::query(
                    "SELECT COUNT(*)::bigint AS count\
                    FROM events\
                    WHERE project_id = $1\
                    AND occurred_at > now() - make_interval(mins => $2)",
                )
                .bind(project_id)
                .bind(window_minutes)
                .fetch_one(db)
                .await?;

                let count: i64 = count_row.try_get("count")?;
                if let (Some(multiplier), Some(baseline_minutes)) = (threshold_multiplier, baseline_minutes) {
                    let baseline_minutes = baseline_minutes.max(1) as i64;
                    let baseline_row = sqlx::query(
                        "SELECT COUNT(*)::bigint AS count\
                        FROM events\
                        WHERE project_id = $1\
                        AND occurred_at > now() - make_interval(mins => $2)",
                    )
                    .bind(project_id)
                    .bind(baseline_minutes)
                    .fetch_one(db)
                    .await?;
                    let baseline_count: i64 = baseline_row.try_get("count")?;
                    let dynamic_threshold = ((baseline_count as f64) * multiplier).ceil() as i64;
                    if dynamic_threshold > threshold {
                        threshold = dynamic_threshold;
                    }
                }

                if max_triggers_per_day > 0 {
                    let trigger_count = alert_trigger_count(db, rule_id).await?;
                    if trigger_count >= max_triggers_per_day as i64 {
                        continue;
                    }
                }

                if count < threshold || !can_trigger {
                    continue;
                }

                sqlx::query("UPDATE alert_rules SET last_triggered_at = now() WHERE id = $1")
                    .bind(rule_id)
                    .execute(db)
                    .await?;
                record_alert_trigger(db, rule_id).await?;

                let text = format!(
                    "EMBER alert: {}\nProject: {}\nCount: {} in {} min",
                    name, project_id, count, window_minutes
                );
                let payload = json!({
                    "kind": "alert_rule",
                    "project_id": project_id,
                    "title": text,
                    "rule": name,
                    "count": count,
                    "window_minutes": window_minutes
                });
                enqueue_alert_notification(
                    db,
                    project_id,
                    &channel,
                    payload,
                    webhook_url,
                    slack_webhook_url,
                    email_to,
                )
                .await?;
            }
            "grouping_default_rate" => {
                let window_minutes = window_minutes.max(1) as i64;
                let threshold_percent = threshold.clamp(0, 100) as f64;

                let row = sqlx::query(
                    "SELECT COUNT(*)::bigint AS total,\
                        COALESCE(SUM(CASE WHEN reason = 'default' THEN 1 ELSE 0 END), 0)::bigint AS default_count\
                    FROM grouping_decisions\
                    WHERE project_id = $1\
                    AND created_at > now() - make_interval(mins => $2)",
                )
                .bind(project_id)
                .bind(window_minutes)
                .fetch_one(db)
                .await?;

                let total: i64 = row.try_get("total")?;
                let default_count: i64 = row.try_get("default_count")?;
                if total <= 0 {
                    continue;
                }
                let default_rate = (default_count as f64) * 100.0 / (total as f64);
                if default_rate < threshold_percent || !can_trigger {
                    continue;
                }

                if max_triggers_per_day > 0 {
                    let trigger_count = alert_trigger_count(db, rule_id).await?;
                    if trigger_count >= max_triggers_per_day as i64 {
                        continue;
                    }
                }

                sqlx::query("UPDATE alert_rules SET last_triggered_at = now() WHERE id = $1")
                    .bind(rule_id)
                    .execute(db)
                    .await?;
                record_alert_trigger(db, rule_id).await?;

                let text = format!(
                    "EMBER alert: {}\nProject: {}\nDefault grouping rate: {:.1}% ({} / {}) in {} min",
                    name, project_id, default_rate, default_count, total, window_minutes
                );
                let payload = json!({
                    "kind": "alert_rule",
                    "project_id": project_id,
                    "title": text,
                    "rule": name,
                    "default_rate": default_rate,
                    "default_count": default_count,
                    "total": total,
                    "window_minutes": window_minutes
                });
                enqueue_alert_notification(
                    db,
                    project_id,
                    &channel,
                    payload,
                    webhook_url,
                    slack_webhook_url,
                    email_to,
                )
                .await?;
            }
            "rca_avg_confidence_below" => {
                let window_minutes = window_minutes.max(1) as i64;
                let threshold_percent = threshold.clamp(0, 100) as f64;
                let row = sqlx::query(
                    "SELECT COALESCE(AVG(ii.confidence), 0)::float8 AS avg_confidence,\
                        COUNT(*)::bigint AS total\
                    FROM issue_insights ii\
                    JOIN issues i ON i.id = ii.issue_id\
                    WHERE i.project_id = $1\
                    AND ii.updated_at > now() - make_interval(mins => $2)",
                )
                .bind(project_id)
                .bind(window_minutes)
                .fetch_one(db)
                .await?;

                let avg_confidence: f64 = row.try_get("avg_confidence")?;
                let total: i64 = row.try_get("total")?;
                if total <= 0 {
                    continue;
                }
                let avg_percent = avg_confidence * 100.0;
                if avg_percent >= threshold_percent || !can_trigger {
                    continue;
                }

                if max_triggers_per_day > 0 {
                    let trigger_count = alert_trigger_count(db, rule_id).await?;
                    if trigger_count >= max_triggers_per_day as i64 {
                        continue;
                    }
                }

                sqlx::query("UPDATE alert_rules SET last_triggered_at = now() WHERE id = $1")
                    .bind(rule_id)
                    .execute(db)
                    .await?;
                record_alert_trigger(db, rule_id).await?;

                let text = format!(
                    "EMBER alert: {}\nProject: {}\nRCA avg confidence: {:.2} ({} issues) in {} min",
                    name, project_id, avg_confidence, total, window_minutes
                );
                let payload = json!({
                    "kind": "alert_rule",
                    "project_id": project_id,
                    "title": text,
                    "rule": name,
                    "avg_confidence": avg_confidence,
                    "total": total,
                    "window_minutes": window_minutes
                });
                enqueue_alert_notification(
                    db,
                    project_id,
                    &channel,
                    payload,
                    webhook_url,
                    slack_webhook_url,
                    email_to,
                )
                .await?;
            }
            _ => {
                continue;
            }
        }
    }

    Ok(())
}

async fn enqueue_alert_notification(
    db: &PgPool,
    project_id: &str,
    channel: &str,
    payload: Value,
    webhook_url: Option<String>,
    slack_webhook_url: Option<String>,
    email_to: Option<String>,
) -> Result<(), sqlx::Error> {
    match channel {
        "webhook" => {
            if let Some(url) = webhook_url {
                let mut body = payload.clone();
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("url".to_string(), Value::String(url));
                }
                enqueue_job(db, Some(project_id), "webhook", body).await?;
            }
        }
        "slack" => {
            if let Some(url) = slack_webhook_url {
                let mut body = payload.clone();
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("url".to_string(), Value::String(url));
                    if let Some(title) = obj.get("title").cloned() {
                        obj.insert("text".to_string(), title);
                    }
                }
                enqueue_job(db, Some(project_id), "slack", body).await?;
            }
        }
        "email" => {
            let mut body = payload.clone();
            if let Some(obj) = body.as_object_mut() {
                obj.insert("issue_id".to_string(), Value::String("-".to_string()));
                obj.insert("email_to".to_string(), email_to.map(Value::String).unwrap_or(Value::Null));
            }
            enqueue_job(db, Some(project_id), "email", body).await?;
        }
        _ => {}
    }

    Ok(())
}

async fn is_alert_silenced(
    db: &PgPool,
    project_id: &str,
    rule_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT EXISTS(\
            SELECT 1\
            FROM alert_silences\
            WHERE project_id = $1\
            AND (rule_id IS NULL OR rule_id = $2)\
            AND (starts_at IS NULL OR starts_at <= now())\
            AND (ends_at IS NULL OR ends_at >= now())\
        ) AS active",
    )
    .bind(project_id)
    .bind(rule_id)
    .fetch_one(db)
    .await?;
    let active: bool = row.try_get("active")?;
    Ok(active)
}

async fn alert_trigger_count(db: &PgPool, rule_id: Uuid) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count\
        FROM alert_rule_triggers\
        WHERE alert_rule_id = $1\
        AND triggered_at >= date_trunc('day', now())",
    )
    .bind(rule_id)
    .fetch_one(db)
    .await?;
    let count: i64 = row.try_get("count")?;
    Ok(count)
}

async fn record_alert_trigger(db: &PgPool, rule_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO alert_rule_triggers (alert_rule_id, triggered_at)\
        VALUES ($1, now())",
    )
    .bind(rule_id)
    .execute(db)
    .await?;
    Ok(())
}

async fn apply_assignment_rules(
    db: &PgPool,
    project_id: &str,
    title: &str,
    message: &str,
    issue_id: Uuid,
) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT pattern, assignee FROM assignment_rules\
        WHERE project_id = $1 AND enabled = true\
        ORDER BY created_at ASC",
    )
    .bind(project_id)
    .fetch_all(db)
    .await?;

    for row in rows {
        let pattern: String = row.try_get("pattern")?;
        let assignee: String = row.try_get("assignee")?;
        if let Ok(re) = Regex::new(&pattern) {
            if re.is_match(title) || re.is_match(message) {
                sqlx::query("UPDATE issues SET assignee = $1 WHERE id = $2")
                    .bind(&assignee)
                    .bind(issue_id)
                    .execute(db)
                    .await?;
                break;
            }
        }
    }

    Ok(())
}

async fn apply_ownership_rules(
    db: &PgPool,
    project_id: &str,
    title: &str,
    message: &str,
    issue_id: Uuid,
) -> Result<(), sqlx::Error> {
    let assignee_row = sqlx::query("SELECT assignee FROM issues WHERE id = $1")
        .bind(issue_id)
        .fetch_one(db)
        .await?;

    let assignee: Option<String> = assignee_row.try_get("assignee")?;
    if assignee.is_some() {
        return Ok(());
    }

    let rows = sqlx::query(
        "SELECT pattern, owner FROM ownership_rules\
        WHERE project_id = $1 AND enabled = true\
        ORDER BY created_at ASC",
    )
    .bind(project_id)
    .fetch_all(db)
    .await?;

    for row in rows {
        let pattern: String = row.try_get("pattern")?;
        let owner: String = row.try_get("owner")?;
        if let Ok(re) = Regex::new(&pattern) {
            if re.is_match(title) || re.is_match(message) {
                sqlx::query("UPDATE issues SET assignee = $1 WHERE id = $2")
                    .bind(&owner)
                    .bind(issue_id)
                    .execute(db)
                    .await?;
                break;
            }
        }
    }

    Ok(())
}

async fn upsert_issue_insight(
    db: &PgPool,
    project_id: &str,
    issue_id: Uuid,
    title: &str,
    stacktrace: Option<&Vec<StackFrame>>,
    release: Option<&str>,
    regressed_at: Option<DateTime<Utc>>,
) -> Result<Option<f64>, sqlx::Error> {
    let culprit = build_culprit(stacktrace);
    let causal_chain = build_causal_chain(stacktrace);
    let confidence = build_rca_confidence(stacktrace, release, regressed_at);
    let regression_map = build_regression_map(db, issue_id, release, regressed_at).await?;
    let min_confidence = fetch_rca_min_confidence(db, project_id).await.unwrap_or(0.5);
    let published = confidence >= min_confidence;
    let mut summary = title.to_string();
    if let Some(culprit) = culprit.as_deref() {
        summary = format!("{} | culprit: {}", summary, culprit);
    }
    if let Some(release) = release {
        summary = format!("{} | release: {}", summary, release);
    }

    sqlx::query(
        "INSERT INTO issue_insights (issue_id, summary, culprit, last_release, regressed_at, causal_chain, regression_map, confidence, published)\
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)\
        ON CONFLICT (issue_id) DO UPDATE SET\
            summary = EXCLUDED.summary,\
            culprit = EXCLUDED.culprit,\
            last_release = EXCLUDED.last_release,\
            regressed_at = COALESCE(EXCLUDED.regressed_at, issue_insights.regressed_at),\
            causal_chain = EXCLUDED.causal_chain,\
            regression_map = EXCLUDED.regression_map,\
            confidence = EXCLUDED.confidence,\
            published = EXCLUDED.published,\
            updated_at = now()",
    )
    .bind(issue_id)
    .bind(&summary)
    .bind(&culprit)
    .bind(release)
    .bind(regressed_at)
    .bind(causal_chain)
    .bind(regression_map)
    .bind(confidence)
    .bind(published)
    .execute(db)
    .await?;

    Ok(Some(confidence))
}

async fn fetch_rca_min_confidence(db: &PgPool, project_id: &str) -> Result<f64, sqlx::Error> {
    let row = sqlx::query("SELECT min_confidence FROM rca_policies WHERE project_id = $1")
        .bind(project_id)
        .fetch_optional(db)
        .await?;
    let min_confidence = row
        .and_then(|row| row.try_get::<f64, _>("min_confidence").ok())
        .unwrap_or(0.5);
    Ok(min_confidence)
}

async fn enqueue_job(
    db: &PgPool,
    project_id: Option<&str>,
    kind: &str,
    payload: Value,
) -> Result<(), sqlx::Error> {
    let limit = job_backpressure_limit();
    let pending_count: i64 = if let Some(project_id) = project_id {
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS count FROM jobs WHERE status IN ('pending', 'running') AND project_id = $1",
        )
        .bind(project_id)
        .fetch_one(db)
        .await?;
        row.try_get("count")?
    } else {
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS count FROM jobs WHERE status IN ('pending', 'running')",
        )
        .fetch_one(db)
        .await?;
        row.try_get("count")?
    };

    if pending_count >= limit {
        warn!("jobs backpressure active for project {:?} ({} >= {})", project_id, pending_count, limit);
        return Ok(());
    }

    sqlx::query("INSERT INTO jobs (project_id, kind, payload, max_attempts) VALUES ($1, $2, $3, $4)")
        .bind(project_id)
        .bind(kind)
        .bind(payload)
        .bind(job_max_attempts())
        .execute(db)
        .await?;
    Ok(())
}

async fn adaptive_sampling_rate(db: &PgPool, project_id: &str) -> Result<f64, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT target_events_per_min, min_rate, max_rate FROM sampling_rules WHERE project_id = $1",
    )
    .bind(project_id)
    .fetch_optional(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let (target, min_rate, max_rate) = match row {
        Some(row) => (
            row.try_get::<i32, _>("target_events_per_min")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            row.try_get::<f64, _>("min_rate")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            row.try_get::<f64, _>("max_rate")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        ),
        None => return Ok(1.0),
    };

    if target <= 0 {
        return Ok(1.0);
    }

    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count FROM events WHERE project_id = $1 AND occurred_at > now() - interval '1 minute'",
    )
    .bind(project_id)
    .fetch_one(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let current: i64 = row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut rate = if current <= 0 {
        max_rate
    } else {
        (target as f64) / (current as f64)
    };

    if rate.is_nan() || !rate.is_finite() {
        rate = 1.0;
    }

    Ok(rate.clamp(min_rate, max_rate))
}

fn should_sample(rate: f64) -> bool {
    if rate >= 1.0 {
        return true;
    }
    let mut rng = rand::thread_rng();
    rng.gen::<f64>() <= rate
}
