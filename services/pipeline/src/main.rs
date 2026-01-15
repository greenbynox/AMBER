use chrono::{DateTime, Utc};
use clickhouse::Client as ClickhouseClient;
use rdkafka::{consumer::Consumer, consumer::StreamConsumer, message::BorrowedMessage, ClientConfig, Message};
use serde::Serialize;
use serde_json::Value;
use std::env;
use tracing::{error, info};

#[derive(clickhouse::Row, Serialize)]
struct RawEventRow {
    received_at: DateTime<Utc>,
    project_id: String,
    event_id: String,
    payload: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    dotenvy::dotenv().ok();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "localhost:9092".to_string());
    let topic = env::var("KAFKA_TOPIC").unwrap_or_else(|_| "ember-events".to_string());
    let ingest_url = env::var("INGEST_URL").unwrap_or_else(|_| "http://localhost:3001/ingest".to_string());
    let clickhouse_url = env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());

    let ch = ClickhouseClient::default().with_url(clickhouse_url);
    ch.query("CREATE DATABASE IF NOT EXISTS ember")
        .execute()
        .await
        .expect("clickhouse db init failed");
    ch.query(
        "CREATE TABLE IF NOT EXISTS ember.raw_events (\
            received_at DateTime DEFAULT now(),\
            project_id String,\
            event_id String,\
            payload String\
        ) ENGINE = MergeTree()\
        ORDER BY (project_id, event_id, received_at)",
    )
    .execute()
    .await
    .expect("clickhouse table init failed");

    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", "ember-pipeline")
        .set("bootstrap.servers", &brokers)
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", "6000")
        .set("enable.auto.commit", "true")
        .create()
        .expect("Kafka consumer init failed");

    consumer.subscribe(&[&topic]).expect("subscribe failed");

    info!("pipeline consuming from {}", topic);

    loop {
        match consumer.recv().await {
            Err(err) => error!("kafka error: {}", err),
            Ok(msg) => {
                if let Err(err) = handle_message(&ch, &ingest_url, &msg).await {
                    error!("pipeline error: {}", err);
                }
            }
        }
    }
}

async fn handle_message(
    ch: &ClickhouseClient,
    ingest_url: &str,
    msg: &BorrowedMessage<'_>,
) -> Result<(), String> {
    let payload = match msg.payload() {
        Some(payload) => payload,
        None => return Ok(()),
    };

    let envelope: Value = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
    let project_id = envelope
        .get("project_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let event_id = envelope
        .get("event_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let api_key = envelope
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let event = envelope.get("event").cloned().unwrap_or(Value::Null);

    let row = serde_json::to_string(&event).map_err(|err| err.to_string())?;

    let mut insert = ch.insert("ember.raw_events").map_err(|err| err.to_string())?;
    insert
        .write(&RawEventRow {
            received_at: Utc::now(),
            project_id: project_id.to_string(),
            event_id: event_id.to_string(),
            payload: row,
        })
        .await
        .map_err(|err| err.to_string())?;
    insert.end().await.map_err(|err| err.to_string())?;

    if !api_key.is_empty() {
        let client = reqwest::Client::new();
        client
            .post(ingest_url)
            .header("x-ember-key", api_key)
            .json(&event)
            .send()
            .await
            .map_err(|err| err.to_string())?
            .error_for_status()
            .map_err(|err| err.to_string())?;
    }

    Ok(())
}
