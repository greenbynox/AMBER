use axum::{extract::State, http::HeaderMap, http::StatusCode, routing::post, Json, Router};
use chrono::Utc;
use rdkafka::{producer::FutureProducer, producer::FutureRecord, ClientConfig};
use serde_json::{json, Value};
use std::env;
use std::time::Duration;
use tracing::info;

#[derive(Clone)]
struct AppState {
    producer: FutureProducer,
    topic: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    dotenvy::dotenv().ok();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "localhost:9092".to_string());
    let topic = env::var("KAFKA_TOPIC").unwrap_or_else(|_| "ember-events".to_string());

    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("message.timeout.ms", "5000")
        .create()
        .expect("Kafka producer init failed");

    let state = AppState { producer, topic };

    let app = Router::new().route("/ingest", post(ingest)).with_state(state);
    let addr = "0.0.0.0:3000";
    info!("relay listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<Value>,
) -> Result<&'static str, (StatusCode, String)> {
    let api_key = headers
        .get("x-ember-key")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or((StatusCode::UNAUTHORIZED, "api key manquante".to_string()))?;

    let project_id = event
        .get("project_id")
        .and_then(|value| value.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "project_id manquant".to_string()))?;

    let event_id = event
        .get("event_id")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");

    let envelope = json!({
        "received_at": Utc::now().to_rfc3339(),
        "project_id": project_id,
        "event_id": event_id,
        "api_key": api_key,
        "event": event
    });

    let payload = serde_json::to_string(&envelope)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    state
        .producer
        .send(
            FutureRecord::to(&state.topic)
                .payload(&payload)
                .key(project_id),
            Duration::from_secs(5),
        )
        .await
        .map_err(|(err, _)| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok("accepted")
}
