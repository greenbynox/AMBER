use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EventEnvelope {
    pub event_id: String,
    pub project_id: String,
    pub schema_version: Option<String>,
    pub timestamp: String,
    pub level: EventLevel,
    pub message: Option<String>,
    pub exception: Exception,
    pub context: Option<EventContext>,
    pub sdk: Option<SdkInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum EventLevel {
    Error,
    Warning,
    Info,
    Debug,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Exception {
    #[serde(rename = "type")]
    pub kind: String,
    pub message: String,
    pub stacktrace: Option<Vec<StackFrame>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StackFrame {
    pub function: String,
    pub filename: String,
    pub line: i64,
    pub col: Option<i64>,
    pub module: Option<String>,
    pub in_app: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_context: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_context: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_language: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EventContext {
    pub user: Option<UserContext>,
    pub tags: Option<std::collections::BTreeMap<String, String>>,
    pub env: Option<String>,
    pub release: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserContext {
    pub id: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SdkInfo {
    pub name: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionEnvelope {
    pub event_id: String,
    pub project_id: String,
    pub trace_id: String,
    pub span_id: String,
    pub name: String,
    pub status: Option<String>,
    pub timestamp: String,
    pub duration_ms: f64,
    pub tags: Option<std::collections::BTreeMap<String, String>>,
    pub measurements: Option<std::collections::BTreeMap<String, f64>>,
    pub spans: Option<Vec<Span>>,
    pub sample_rate: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Span {
    pub span_id: String,
    pub parent_id: Option<String>,
    pub op: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub start_timestamp: String,
    pub duration_ms: f64,
    pub tags: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProfileEnvelope {
    pub event_id: String,
    pub project_id: String,
    pub trace_id: String,
    pub timestamp: String,
    pub profile: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReplayEnvelope {
    pub event_id: String,
    pub project_id: String,
    pub session_id: String,
    pub timestamp: String,
    pub duration_ms: Option<f64>,
    pub url: Option<String>,
    pub user: Option<UserContext>,
    pub breadcrumbs: Option<Vec<serde_json::Value>>,
    pub events: Option<Vec<serde_json::Value>>,
    pub payload: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_level_serializes_lowercase() {
        let json = serde_json::to_string(&EventLevel::Error).expect("serialize level");
        assert_eq!(json, "\"error\"");
    }

    #[test]
    fn event_envelope_roundtrip() {
        let envelope = EventEnvelope {
            event_id: "evt_123".to_string(),
            project_id: "demo".to_string(),
            schema_version: Some("v1".to_string()),
            timestamp: "2026-01-15T00:00:00Z".to_string(),
            level: EventLevel::Info,
            message: Some("Hello".to_string()),
            exception: Exception {
                kind: "Error".to_string(),
                message: "Boom".to_string(),
                stacktrace: Some(vec![StackFrame {
                    function: "main".to_string(),
                    filename: "app.rs".to_string(),
                    line: 42,
                    col: Some(7),
                    module: Some("app".to_string()),
                    in_app: Some(true),
                    pre_context: None,
                    context_line: None,
                    post_context: None,
                    source_language: None,
                }]),
            },
            context: Some(EventContext {
                user: Some(UserContext {
                    id: Some("42".to_string()),
                    email: Some("dev@local".to_string()),
                }),
                tags: Some(std::collections::BTreeMap::from([
                    ("feature".to_string(), "checkout".to_string()),
                ])),
                env: Some("local".to_string()),
                release: Some("dev".to_string()),
            }),
            sdk: Some(SdkInfo {
                name: Some("ember".to_string()),
                version: Some("0.1.0".to_string()),
            }),
        };

        let json = serde_json::to_string(&envelope).expect("serialize envelope");
        let decoded: EventEnvelope = serde_json::from_str(&json).expect("deserialize envelope");

        assert_eq!(decoded.event_id, envelope.event_id);
        assert_eq!(decoded.project_id, envelope.project_id);
        assert!(matches!(decoded.level, EventLevel::Info));
        assert_eq!(decoded.message, envelope.message);
        assert_eq!(decoded.exception.kind, envelope.exception.kind);
        assert_eq!(decoded.exception.message, envelope.exception.message);
    }
}
