use reqwest::Client;
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::env;
use chrono::{Duration as ChronoDuration, Utc};
use rand::Rng;
use tokio::time::{sleep, Duration};
use std::time::Instant;
use reqwest::Method;
use tracing::{error, info};
use uuid::Uuid;
use lettre::{AsyncSmtpTransport, Tokio1Executor, message::Message, transport::smtp::authentication::Credentials, AsyncTransport};
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    http: Client,
    email: Emailer,
}

#[derive(Clone)]
struct Emailer {
    mailer: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from: Option<String>,
    to: Option<String>,
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

    let http = Client::new();
    let email = Emailer::new_from_env();
    let state = AppState { db, http, email };

    info!("worker started");

    loop {
        if let Err(err) = process_jobs(&state).await {
            error!("job processing failed: {}", err);
        }
        if let Err(err) = process_uptime_monitors(&state).await {
            error!("uptime processing failed: {}", err);
        }
        if let Err(err) = process_cron_monitors(&state).await {
            error!("cron processing failed: {}", err);
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn process_uptime_monitors(state: &AppState) -> Result<(), String> {
    let rows = sqlx::query(
        "SELECT id, project_id, url, method, expected_status, timeout_ms, interval_minutes, headers\
        FROM uptime_monitors\
        WHERE enabled = true AND (next_check_at IS NULL OR next_check_at <= now())\
        ORDER BY next_check_at NULLS FIRST\
        LIMIT 10",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    for row in rows {
        let monitor_id: Uuid = row.try_get("id").map_err(|err| err.to_string())?;
        let project_id: String = row.try_get("project_id").map_err(|err| err.to_string())?;
        let url: String = row.try_get("url").map_err(|err| err.to_string())?;
        let method: String = row.try_get("method").map_err(|err| err.to_string())?;
        let expected_status: i32 = row.try_get("expected_status").map_err(|err| err.to_string())?;
        let timeout_ms: i32 = row.try_get("timeout_ms").map_err(|err| err.to_string())?;
        let interval_minutes: i32 = row.try_get("interval_minutes").map_err(|err| err.to_string())?;
        let headers: Option<Value> = row.try_get("headers").map_err(|err| err.to_string())?;

        let method = Method::from_bytes(method.as_bytes()).map_err(|_| "method invalide".to_string())?;
        let mut request = state
            .http
            .request(method, &url)
            .timeout(Duration::from_millis(timeout_ms.max(100) as u64));

        if let Some(Value::Object(map)) = headers {
            for (key, value) in map {
                if let Some(text) = value.as_str() {
                    request = request.header(key, text);
                }
            }
        }

        let start = Instant::now();
        let result = request.send().await;
        let duration_ms = start.elapsed().as_millis() as i32;

        let (status, status_code, error) = match result {
            Ok(response) => {
                let code = response.status().as_u16() as i32;
                if code == expected_status {
                    ("up".to_string(), Some(code), None)
                } else {
                    ("down".to_string(), Some(code), Some(format!("status {}", code)))
                }
            }
            Err(err) => ("down".to_string(), None, Some(err.to_string())),
        };

        let _ = sqlx::query(
            "INSERT INTO uptime_checks (monitor_id, project_id, status, status_code, duration_ms, error)\
            VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(monitor_id)
        .bind(&project_id)
        .bind(&status)
        .bind(status_code)
        .bind(duration_ms)
        .bind(&error)
        .execute(&state.db)
        .await;

        let _ = sqlx::query(
            "UPDATE uptime_monitors SET status = $1, last_check_at = now(), next_check_at = now() + make_interval(mins => $2), last_duration_ms = $3, last_error = $4, updated_at = now()\
            WHERE id = $5",
        )
        .bind(&status)
        .bind(interval_minutes)
        .bind(duration_ms)
        .bind(&error)
        .bind(monitor_id)
        .execute(&state.db)
        .await;
    }

    Ok(())
}

async fn process_cron_monitors(state: &AppState) -> Result<(), String> {
    sqlx::query(
        "UPDATE cron_monitors SET next_expected_at = now() + make_interval(mins => schedule_minutes)\
        WHERE enabled = true AND next_expected_at IS NULL",
    )
    .execute(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    let rows = sqlx::query(
        "SELECT id, project_id, schedule_minutes, grace_minutes FROM cron_monitors\
        WHERE enabled = true AND next_expected_at IS NOT NULL\
        AND next_expected_at + make_interval(mins => grace_minutes) < now()\
        ORDER BY next_expected_at ASC\
        LIMIT 10",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| err.to_string())?;

    for row in rows {
        let monitor_id: Uuid = row.try_get("id").map_err(|err| err.to_string())?;
        let project_id: String = row.try_get("project_id").map_err(|err| err.to_string())?;
        let schedule_minutes: i32 = row.try_get("schedule_minutes").map_err(|err| err.to_string())?;

        let _ = sqlx::query(
            "INSERT INTO cron_checkins (monitor_id, project_id, status, message) VALUES ($1, $2, 'missed', 'missed check-in')",
        )
        .bind(monitor_id)
        .bind(&project_id)
        .execute(&state.db)
        .await;

        let _ = sqlx::query(
            "UPDATE cron_monitors SET status = 'missed', next_expected_at = now() + make_interval(mins => $1), updated_at = now()\
            WHERE id = $2",
        )
        .bind(schedule_minutes)
        .bind(monitor_id)
        .execute(&state.db)
        .await;
    }

    Ok(())
}

async fn process_jobs(state: &AppState) -> Result<(), String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|err| err.to_string())?;

    let rows = sqlx::query(
        "SELECT id, kind, payload, attempts, max_attempts FROM jobs\
        WHERE status = 'pending' AND run_at <= now()\
        ORDER BY run_at ASC\
        LIMIT 10\
        FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|err| err.to_string())?;

    for row in &rows {
        let id: Uuid = row.try_get("id").map_err(|err| err.to_string())?;
        sqlx::query("UPDATE jobs SET status = 'running' WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|err| err.to_string())?;
    }

    tx.commit().await.map_err(|err| err.to_string())?;

    for row in rows {
        let id: Uuid = row.try_get("id").map_err(|err| err.to_string())?;
        let kind: String = row.try_get("kind").map_err(|err| err.to_string())?;
        let payload: Value = row.try_get("payload").map_err(|err| err.to_string())?;
        let attempts: i32 = row.try_get("attempts").map_err(|err| err.to_string())?;
        let max_attempts: i32 = row.try_get("max_attempts").map_err(|err| err.to_string())?;

        let result = handle_job(state, &kind, &payload).await;
        match result {
            Ok(()) => {
                sqlx::query(
                    "UPDATE jobs SET status = 'done', attempts = attempts + 1, last_error = NULL WHERE id = $1",
                )
                .bind(id)
                .execute(&state.db)
                .await
                .map_err(|err| err.to_string())?;
            }
            Err(err) => {
                let next_attempts = attempts + 1;
                if max_attempts > 0 && next_attempts >= max_attempts {
                    sqlx::query(
                        "UPDATE jobs SET status = 'dead', attempts = $2, last_error = $3, dead_at = now() WHERE id = $1",
                    )
                    .bind(id)
                    .bind(next_attempts)
                    .bind(&err)
                    .execute(&state.db)
                    .await
                    .map_err(|err| err.to_string())?;
                } else {
                    let base = env::var("JOB_RETRY_BASE_SECONDS").ok().and_then(|v| v.parse::<i64>().ok()).unwrap_or(60);
                    let backoff = base * 2_i64.pow(attempts.max(0) as u32);
                    let jitter: i64 = rand::thread_rng().gen_range(0..=30);
                    let delay = (backoff + jitter).min(3600);
                    let next_run = Utc::now() + ChronoDuration::seconds(delay);
                    sqlx::query(
                        "UPDATE jobs SET status = 'pending', attempts = $2, last_error = $3, run_at = $4 WHERE id = $1",
                    )
                    .bind(id)
                    .bind(next_attempts)
                    .bind(&err)
                    .bind(next_run)
                    .execute(&state.db)
                    .await
                    .map_err(|err| err.to_string())?;
                }
            }
        }
    }

    Ok(())
}

async fn handle_job(state: &AppState, kind: &str, payload: &Value) -> Result<(), String> {
    match kind {
        "webhook" => handle_webhook(&state.http, payload).await,
        "webhook_v2" => handle_webhook_v2(&state.http, &state.db, payload).await,
        "slack" => handle_slack(&state.http, payload).await,
        "github_issue" => handle_github_issue(&state.http, &state.db, payload).await,
        "email" => handle_email(&state.email, payload).await,
        _ => Err("unknown job kind".to_string()),
    }
}

async fn handle_webhook(client: &Client, payload: &Value) -> Result<(), String> {
    let url = payload.get("url").and_then(|v| v.as_str()).ok_or("url manquant")?;
    client
        .post(url)
        .json(payload)
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?;
    Ok(())
}

async fn handle_webhook_v2(client: &Client, db: &PgPool, payload: &Value) -> Result<(), String> {
    let url = payload.get("url").and_then(|v| v.as_str()).ok_or("url manquant")?;
    let endpoint_id = payload
        .get("endpoint_id")
        .and_then(|v| v.as_str())
        .ok_or("endpoint_id manquant")?;
    let endpoint_uuid = Uuid::parse_str(endpoint_id).map_err(|_| "endpoint_id invalide".to_string())?;
    let secret = payload.get("secret").and_then(|v| v.as_str()).map(|v| v.to_string());

    let mut body_value = payload.clone();
    if let Some(obj) = body_value.as_object_mut() {
        obj.remove("url");
        obj.remove("secret");
        obj.remove("endpoint_id");
    }
    let body = serde_json::to_vec(&body_value).map_err(|err| err.to_string())?;

    let mut request = client.post(url).body(body.clone()).header("Content-Type", "application/json");
    if let Some(secret) = &secret {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| "secret invalide".to_string())?;
        mac.update(&body);
        let signature = hex::encode(mac.finalize().into_bytes());
        request = request.header("X-Ember-Signature", format!("sha256={}", signature));
    }
    if let Some(kind) = body_value.get("kind").and_then(|v| v.as_str()) {
        request = request.header("X-Ember-Event", kind);
    }

    let result = request.send().await;
    match result {
        Ok(response) => {
            let status = response.status();
            let status_code = status.as_u16() as i32;
            let success = response.error_for_status().is_ok();
            record_webhook_delivery(db, endpoint_uuid, &body_value, Some(status_code), if success { None } else { Some(format!("status {}", status_code)) }).await;
            if success {
                Ok(())
            } else {
                Err(format!("webhook status {}", status_code))
            }
        }
        Err(err) => {
            record_webhook_delivery(db, endpoint_uuid, &body_value, None, Some(err.to_string())).await;
            Err(err.to_string())
        }
    }
}

async fn record_webhook_delivery(
    db: &PgPool,
    endpoint_id: Uuid,
    payload: &Value,
    status_code: Option<i32>,
    error: Option<String>,
) {
    let _ = sqlx::query(
        "INSERT INTO webhook_deliveries (endpoint_id, payload, status_code, error) VALUES ($1, $2, $3, $4)",
    )
    .bind(endpoint_id)
    .bind(payload)
    .bind(status_code)
    .bind(error)
    .execute(db)
    .await;
}

async fn handle_slack(client: &Client, payload: &Value) -> Result<(), String> {
    let url = payload.get("url").and_then(|v| v.as_str()).ok_or("url manquant")?;
    let text = if let Some(text) = payload.get("text").and_then(|v| v.as_str()) {
        text.to_string()
    } else {
        let kind = payload.get("kind").and_then(|v| v.as_str()).unwrap_or("event");
        let project_id = payload.get("project_id").and_then(|v| v.as_str()).unwrap_or("-");
        let issue_id = payload.get("issue_id").and_then(|v| v.as_str()).unwrap_or("-");
        let title = payload.get("title").and_then(|v| v.as_str()).unwrap_or("-");
        format!("EMBER {}\nProject: {}\nIssue: {}\n{}", kind, project_id, issue_id, title)
    };

    let message = serde_json::json!({
        "text": text,
        "username": "EMBER"
    });

    client
        .post(url)
        .json(&message)
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?;

    Ok(())
}

async fn handle_github_issue(client: &Client, db: &PgPool, payload: &Value) -> Result<(), String> {
    let repo = payload.get("repo").and_then(|v| v.as_str()).ok_or("repo manquant")?;
    let token = payload.get("token").and_then(|v| v.as_str()).ok_or("token manquant")?;
    let title = payload.get("title").and_then(|v| v.as_str()).ok_or("title manquant")?;
    let issue_id = payload.get("issue_id").and_then(|v| v.as_str()).ok_or("issue_id manquant")?;
    let project_id = payload.get("project_id").and_then(|v| v.as_str()).ok_or("project_id manquant")?;

    let body = format!("Issue créé depuis EMBER\n\nproject: {}\nissue: {}", project_id, issue_id);
    let request = serde_json::json!({
        "title": title,
        "body": body
    });

    let url = format!("https://api.github.com/repos/{}/issues", repo);
    let res = client
        .post(url)
        .bearer_auth(token)
        .header("User-Agent", "EMBER")
        .json(&request)
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?;

    let json: Value = res.json().await.map_err(|err| err.to_string())?;
    let html_url = json.get("html_url").and_then(|v| v.as_str()).ok_or("html_url manquant")?;

    let issue_uuid = Uuid::parse_str(issue_id).map_err(|_| "issue_id invalide".to_string())?;
    sqlx::query("UPDATE issues SET github_issue_url = $1 WHERE id = $2")
        .bind(html_url)
        .bind(issue_uuid)
        .execute(db)
        .await
        .map_err(|err| err.to_string())?;

    Ok(())
}

async fn handle_email(emailer: &Emailer, payload: &Value) -> Result<(), String> {
    let kind = payload.get("kind").and_then(|v| v.as_str()).unwrap_or("event");
    let project_id = payload.get("project_id").and_then(|v| v.as_str()).unwrap_or("-");
    let issue_id = payload.get("issue_id").and_then(|v| v.as_str()).unwrap_or("-");
    let title = payload.get("title").and_then(|v| v.as_str()).unwrap_or("-");
    let email_to = payload.get("email_to").and_then(|v| v.as_str());

    emailer.send(kind, project_id, issue_id, title, email_to).await
}


impl Emailer {
    fn new_from_env() -> Self {
        let host = env::var("SMTP_HOST").ok();
        let user = env::var("SMTP_USER").ok();
        let pass = env::var("SMTP_PASS").ok();
        let from = env::var("SMTP_FROM").ok();
        let to = env::var("SMTP_TO").ok();

        if let (Some(host), Some(user), Some(pass), Some(from), Some(to)) = (host, user, pass, from.clone(), to.clone()) {
            let creds = Credentials::new(user, pass);
            let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
                .ok()
                .map(|builder| builder.credentials(creds).build());
            Self { mailer, from: Some(from), to: Some(to) }
        } else {
            Self { mailer: None, from: None, to: None }
        }
    }

    async fn send(
        &self,
        kind: &str,
        project_id: &str,
        issue_id: &str,
        title: &str,
        override_to: Option<&str>,
    ) -> Result<(), String> {
        let mailer = match &self.mailer {
            Some(mailer) => mailer,
            None => return Ok(()),
        };
        let from = match &self.from {
            Some(from) => from,
            None => return Ok(()),
        };
        let to = override_to
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.to_string())
            .or_else(|| self.to.clone())
            .ok_or_else(|| "adresse to manquante".to_string())?;

        let subject = format!("EMBER {}: {}", kind, title);
        let body = format!("kind: {}\nproject: {}\nissue: {}\n\n{}", kind, project_id, issue_id, title);

        let from_addr = from.parse().map_err(|_| "adresse from invalide".to_string())?;
        let to_addr = to.parse().map_err(|_| "adresse to invalide".to_string())?;

        let email = Message::builder()
            .from(from_addr)
            .to(to_addr)
            .subject(subject)
            .body(body)
            .map_err(|_| "construction email invalide".to_string())?;

        mailer.send(email).await.map_err(|err| err.to_string())?;
        Ok(())
    }
}
