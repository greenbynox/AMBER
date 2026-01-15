use axum::{extract::Path, extract::Query, extract::State, http::HeaderMap, http::StatusCode, routing::get, routing::post, routing::get_service, Json, Router};
use axum::middleware::{self, Next};
use axum::http::Request;
use axum::body::Body;
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::env;
use uuid::Uuid;
use tracing::info;
use serde_json::{json, Value};
use regex::Regex;
use tower_http::services::{ServeDir, ServeFile};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use reqwest::Client;
use std::sync::{Arc};
use std::sync::atomic::{AtomicU64, Ordering};
use data_encoding::{BASE32_NOPAD, BASE64};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use ipnet::IpNet;
use std::net::IpAddr;
use aes_gcm::{Aes256Gcm, AeadCore, aead::{Aead, KeyInit, OsRng}};

#[derive(Clone)]
struct AppState {
    db: PgPool,
    metrics: Metrics,
}

#[derive(Clone)]
struct Metrics {
    requests_total: Arc<AtomicU64>,
    requests_error_total: Arc<AtomicU64>,
    requests_unauthorized_total: Arc<AtomicU64>,
}

impl Metrics {
    fn new() -> Self {
        Self {
            requests_total: Arc::new(AtomicU64::new(0)),
            requests_error_total: Arc::new(AtomicU64::new(0)),
            requests_unauthorized_total: Arc::new(AtomicU64::new(0)),
        }
    }

    fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# TYPE ember_api_requests_total counter\n");
        out.push_str(&format!("ember_api_requests_total {}\n", self.requests_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_api_requests_error_total counter\n");
        out.push_str(&format!("ember_api_requests_error_total {}\n", self.requests_error_total.load(Ordering::Relaxed)));
        out.push_str("# TYPE ember_api_requests_unauthorized_total counter\n");
        out.push_str(&format!("ember_api_requests_unauthorized_total {}\n", self.requests_unauthorized_total.load(Ordering::Relaxed)));
        out
    }
}

#[derive(Clone)]
#[allow(dead_code)]
struct AuthContext {
    project_id: String,
    actor: String,
    team_id: Option<Uuid>,
    token_id: Option<Uuid>,
    role: Option<String>,
}

#[derive(Clone)]
struct TeamTokenContext {
    team_id: Uuid,
    token_id: Uuid,
    actor: String,
    role: String,
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
    let metrics = Metrics::new();
    let state = AppState { db, metrics };

    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(api_metrics))
        .route("/issues", get(list_issues))
        .route("/issues/stats", get(issue_stats))
        .route("/issues/bulk", post(bulk_update_issues))
        .route("/issues/:id", get(get_issue))
        .route("/issues/:id/events", get(list_issue_events))
        .route("/issues/:id/status", post(update_issue_status))
        .route("/issues/:id/assign", post(assign_issue))
        .route("/search/issues", get(search_issues))
        .route("/search/issues/v2", get(search_issues_v2))
        .route("/events/:id", get(get_event))
        .route("/transactions", get(list_transactions))
        .route("/transactions/stats", get(list_transaction_stats))
        .route("/traces/:trace_id", get(get_trace))
        .route("/traces/:trace_id/waterfall", get(get_trace_waterfall))
        .route("/traces/:trace_id/correlations", get(get_trace_correlations))
        .route("/traces/:trace_id/replays", get(list_trace_replays))
        .route("/traces/top-regressions", get(get_top_regressions))
        .route("/traces/service-map", get(get_service_map))
        .route("/traces/breakdown", get(get_trace_breakdown))
        .route("/profiles/:trace_id", get(get_profile))
        .route("/profiles/:trace_id/list", get(list_profiles))
        .route("/profiles/:trace_id/hot-paths", get(get_profile_hot_paths))
        .route("/profiles/:trace_id/diff", get(diff_profiles))
        .route("/issues/:id/insights", get(get_issue_insights))
        .route("/replays", get(list_replays))
        .route("/replays/:id", get(get_replay))
        .route("/replays/:id/timeline", get(get_replay_timeline))
        .route("/replays/:id/scrubbed", get(get_replay_scrubbed))
        .route("/replays/:id/link", post(link_replay_issue))
        .route("/replays/:id/links", get(list_replay_links))
        .route("/issues/:id/replays", get(list_issue_replays))
        .route("/discover/events", get(list_discover_events))
        .route("/discover/stats", get(list_discover_stats))
        .route("/projects", get(list_projects).post(create_project))
        .route("/projects/:id", get(get_project))
        .route("/projects/:id/rotate-key", post(rotate_project_key))
        .route("/projects/:id/webhook", post(update_project_webhook))
        .route("/projects/:id/integrations", post(update_project_integrations))
        .route("/projects/:id/sampling", get(get_sampling_rule).post(update_sampling_rule))
        .route("/projects/:id/cost", get(list_project_cost_units))
        .route("/projects/:id/cost/daily", get(list_project_cost_daily))
        .route("/projects/:id/rca/stats", get(get_rca_stats))
        .route("/projects/:id/rca-policy", get(get_rca_policy).post(update_rca_policy))
        .route("/projects/:id/ingest/drops", get(list_ingest_drops))
        .route("/projects/:id/pii-policy", get(get_pii_policy).post(update_pii_policy))
        .route("/projects/:id/sla-policy", get(get_sla_policy).post(update_sla_policy))
        .route("/projects/:id/sla-report", get(get_sla_report))
        .route("/projects/:id/slo", get(get_slo_policy).post(update_slo_policy))
        .route("/projects/:id/slo/report", get(get_slo_report))
        .route("/projects/:id/storage-policy", get(get_storage_policy).post(update_storage_policy))
        .route("/projects/:id/storage-tier/run", post(run_storage_tiering))
        .route("/projects/:id/webhooks", get(list_webhook_endpoints).post(create_webhook_endpoint))
        .route("/projects/:id/webhooks/:webhook_id", post(delete_webhook_endpoint))
        .route("/projects/:id/webhooks/:webhook_id/deliveries", get(list_webhook_deliveries))
        .route("/projects/:id/releases", get(list_releases).post(create_release))
        .route("/projects/:id/releases/:version", get(get_release_detail))
        .route("/projects/:id/releases/:version/regressions", get(list_release_regressions))
        .route("/projects/:id/releases/:version/suspect-commits", get(list_release_suspect_commits))
        .route("/projects/:id/releases/:version/commits", post(add_release_commits))
        .route("/projects/:id/grouping-rules", get(list_grouping_rules).post(create_grouping_rule))
        .route("/projects/:id/grouping-overrides", get(list_grouping_overrides).post(create_grouping_override))
        .route("/projects/:id/grouping-overrides/:override_id", post(delete_grouping_override))
        .route("/projects/:id/grouping/decisions/stats", get(get_grouping_decision_stats))
        .route("/projects/:id/grouping/decisions", get(list_grouping_decisions))
        .route("/projects/:id/grouping/decisions/:decision_id/rules", get(list_grouping_rules_applied))
        .route("/projects/:id/alert-rules", get(list_alert_rules).post(create_alert_rule))
        .route("/projects/:id/alert-silences", get(list_alert_silences).post(create_alert_silence))
        .route("/projects/:id/alert-silences/:silence_id", post(delete_alert_silence))
        .route("/projects/:id/assignment-rules", get(list_assignment_rules).post(create_assignment_rule))
        .route("/projects/:id/ownership-rules", get(list_ownership_rules).post(create_ownership_rule))
        .route("/projects/:id/saved-queries", get(list_saved_queries).post(create_saved_query))
        .route("/projects/:id/saved-queries/:query_id", get(get_saved_query).delete(delete_saved_query))
        .route("/projects/:id/teams", get(list_project_teams).post(add_project_team))
        .route("/orgs/:id", post(update_org))
        .route("/orgs/:id/sso", get(get_sso_config).post(upsert_sso_config))
        .route("/orgs/:id/sso/validate", post(validate_sso_config))
        .route("/orgs/:id/scim-token", post(create_scim_token))
        .route("/integrations", get(list_integrations))
        .route("/orgs/:id/integrations", get(list_org_integrations).post(upsert_org_integration))
        .route("/orgs/:id/integrations/:key/test", post(test_org_integration))
        .route("/orgs/:id/integrations/:key/oauth/start", get(start_oauth_flow))
        .route("/integrations/oauth/callback", get(handle_oauth_callback))
        .route("/orgs/:id/data-requests", get(list_data_requests).post(create_data_request))
        .route("/data-requests/:id/complete", post(complete_data_request))
        .route("/data-requests/:id/run", post(run_data_request))
        .route("/data-requests/:id/results", get(list_data_request_results))
        .route("/regions", get(list_regions))
        .route("/routing", get(get_project_routing))
        .route("/orgs", get(list_orgs).post(create_org))
        .route("/orgs/:id/teams", get(list_org_teams).post(create_team))
        .route("/teams/:id/users", get(list_team_users).post(add_team_user))
        .route("/teams/:id/tokens", get(list_team_tokens).post(create_team_token))
        .route("/teams/:id/tokens/:token_id/revoke", post(revoke_team_token))
        .route("/scim/v2/Users", get(scim_list_users).post(scim_create_user))
        .route("/scim/v2/Users/:id", get(scim_get_user).put(scim_update_user).delete(scim_delete_user))
        .route("/scim/v2/Groups", get(scim_list_groups).post(scim_create_group))
        .route("/scim/v2/Groups/:id", get(scim_get_group).put(scim_update_group).delete(scim_delete_group))
        .route("/me/projects", get(list_my_projects))
        .route("/audit", get(list_audit_log))
        .route("/sourcemaps", post(upload_sourcemap))
        .route("/ui", get(ui_issue_list))
        .route("/ui/issues/:id", get(ui_issue_detail))
        .route("/app", get_service(ServeDir::new("../static").not_found_service(ServeFile::new("../static/index.html"))))
        .route("/app/*path", get_service(ServeDir::new("../static").not_found_service(ServeFile::new("../static/index.html"))))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state.clone(), metrics_middleware));

    let addr = "0.0.0.0:3002";
    info!("api listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "ok"
}

async fn api_metrics(State(state): State<AppState>) -> Result<String, (StatusCode, String)> {
    Ok(state.metrics.render())
}

async fn metrics_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    let response = next.run(req).await;
    let status = response.status().as_u16();
    if status >= 400 {
        state.metrics.requests_error_total.fetch_add(1, Ordering::Relaxed);
    }
    if status == 401 || status == 403 {
        state.metrics.requests_unauthorized_total.fetch_add(1, Ordering::Relaxed);
    }
    response
}

#[derive(Serialize)]
struct IssueListResponse {
    items: Vec<IssueSummary>,
    next_before: Option<String>,
}

#[derive(Serialize)]
struct IssueStatsRow {
    key: String,
    count: i64,
}

#[derive(Serialize)]
struct IssueStatsResponse {
    by_status: Vec<IssueStatsRow>,
    by_level: Vec<IssueStatsRow>,
    by_assignee: Vec<IssueStatsRow>,
    open_issues: i64,
    sla_breaches: i64,
}

#[derive(Serialize)]
struct IssueSummary {
    id: String,
    title: String,
    level: String,
    status: String,
    last_seen: String,
    count_24h: i64,
    assignee: Option<String>,
    affected_users_24h: i64,
    last_user: Option<String>,
}

#[derive(Deserialize)]
struct IssueListQuery {
    before: Option<String>,
    limit: Option<u32>,
    status: Option<String>,
    level: Option<String>,
    q: Option<String>,
}

#[derive(Deserialize)]
struct IssueStatsQuery {
    window_minutes: Option<i64>,
    sla_minutes: Option<i64>,
}

#[derive(Deserialize)]
struct DiscoverEventsQuery {
    before: Option<String>,
    cursor: Option<String>,
    limit: Option<u32>,
    q: Option<String>,
    saved_query_id: Option<String>,
    level: Option<String>,
    release: Option<String>,
    exception_type: Option<String>,
    user: Option<String>,
    issue_id: Option<String>,
}

#[derive(Deserialize)]
struct DiscoverStatsQuery {
    window_minutes: Option<i64>,
    group_by: Option<String>,
    q: Option<String>,
    saved_query_id: Option<String>,
    level: Option<String>,
    release: Option<String>,
    exception_type: Option<String>,
    user: Option<String>,
    issue_id: Option<String>,
}

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct ScimListQuery {
    #[serde(rename = "startIndex")]
    start_index: Option<usize>,
    count: Option<usize>,
    filter: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ScimUserInput {
    #[serde(rename = "userName")]
    user_name: String,
    active: Option<bool>,
}

#[derive(Deserialize)]
struct ScimGroupInput {
    #[serde(rename = "displayName")]
    display_name: String,
    members: Option<Vec<ScimMemberInput>>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ScimMemberInput {
    value: String,
    display: Option<String>,
}

#[derive(Deserialize)]
struct TransactionListQuery {
    before: Option<String>,
    limit: Option<u32>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct TransactionStatsQuery {
    window_minutes: Option<i64>,
}

#[derive(Deserialize)]
struct ServiceMapQuery {
    window_minutes: Option<i64>,
}

#[derive(Deserialize)]
struct TraceBreakdownQuery {
    window_minutes: Option<i64>,
}

#[derive(Deserialize)]
struct TopRegressionsQuery {
    window_minutes: Option<i64>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct ReleaseStatsQuery {
    window_minutes: Option<i64>,
}

#[derive(Deserialize)]
struct ReleaseIssuesQuery {
    limit: Option<u32>,
}

#[derive(Serialize)]
struct IssueDetailResponse {
    id: String,
    project_id: String,
    fingerprint: String,
    title: String,
    level: String,
    status: String,
    assignee: Option<String>,
    first_release: Option<String>,
    last_release: Option<String>,
    regressed_at: Option<String>,
    last_user: Option<String>,
    github_issue_url: Option<String>,
    first_seen: String,
    last_seen: String,
    count_total: i64,
    last_event: Option<EventSummary>,
}

#[derive(Serialize)]
struct EventSummary {
    occurred_at: String,
    message: Option<String>,
    exception_type: String,
    exception_message: String,
    stacktrace: Option<Value>,
    context: Option<Value>,
}

#[derive(Serialize)]
struct EventListResponse {
    items: Vec<EventSummary>,
}

#[derive(Serialize)]
struct DiscoverEventSummary {
    id: String,
    issue_id: String,
    issue_title: String,
    occurred_at: String,
    level: String,
    message: Option<String>,
    exception_type: String,
    exception_message: String,
    release: Option<String>,
    user_id: Option<String>,
    user_email: Option<String>,
}

#[derive(Serialize)]
struct DiscoverEventsResponse {
    items: Vec<DiscoverEventSummary>,
    next_before: Option<String>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct DiscoverStatRow {
    key: String,
    count: i64,
}

#[derive(Serialize)]
struct ProjectSummary {
    id: String,
    name: String,
    created_at: String,
}

#[derive(Serialize)]
struct ProjectDetail {
    id: String,
    name: String,
    api_key: String,
    webhook_url: Option<String>,
    slack_webhook_url: Option<String>,
    github_repo: Option<String>,
    rate_limit_per_min: Option<i64>,
    quota_soft_limit: Option<i64>,
    quota_hard_limit: Option<i64>,
    api_key_last_used_at: Option<String>,
    api_key_rotated_at: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct SamplingRuleSummary {
    project_id: String,
    target_events_per_min: i32,
    min_rate: f64,
    max_rate: f64,
    updated_at: String,
}

#[derive(Serialize)]
struct SlaPolicySummary {
    project_id: String,
    sla_minutes: i32,
    updated_at: String,
}

#[derive(Serialize)]
struct SlaReportSummary {
    project_id: String,
    sla_minutes: i32,
    open_issues: i64,
    breaches: i64,
    oldest_open_minutes: Option<i64>,
    generated_at: String,
}

#[derive(Serialize)]
struct SloPolicySummary {
    project_id: String,
    target_error_rate: f64,
    window_minutes: i32,
    updated_at: String,
}

#[derive(Serialize)]
struct SloReportSummary {
    project_id: String,
    target_error_rate: f64,
    window_minutes: i32,
    total_transactions: i64,
    error_transactions: i64,
    error_rate: f64,
    budget_remaining_ratio: f64,
    generated_at: String,
}

#[derive(Serialize)]
struct StoragePolicySummary {
    project_id: String,
    hot_days: i32,
    cold_days: i32,
    updated_at: String,
}

#[derive(Serialize)]
struct PiiPolicySummary {
    project_id: String,
    scrub_emails: bool,
    scrub_ips: bool,
    scrub_secrets: bool,
    updated_at: String,
}

#[derive(Serialize)]
struct ReleaseSummary {
    id: String,
    project_id: String,
    version: String,
    commit_count: i32,
    adoption_rate: f64,
    events_24h: i64,
    new_issues_24h: i64,
    regressions_24h: i64,
    created_at: String,
}

#[derive(Serialize)]
struct ReleaseRegressionSummary {
    id: String,
    title: String,
    level: String,
    status: String,
    assignee: Option<String>,
    regressed_at: String,
    last_seen: String,
}

#[derive(Serialize)]
struct ReleaseCommitSuspect {
    commit_sha: String,
    message: Option<String>,
    author: Option<String>,
    timestamp: Option<String>,
    new_issues: i64,
    regressions: i64,
}

#[derive(Serialize)]
struct GroupingRuleSummary {
    id: String,
    project_id: String,
    name: String,
    pattern: String,
    fingerprint: String,
    enabled: bool,
    created_at: String,
}

#[derive(Serialize)]
struct GroupingOverrideSummary {
    id: String,
    project_id: String,
    source_fingerprint: String,
    target_fingerprint: String,
    reason: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct AlertRuleSummary {
    id: String,
    project_id: String,
    name: String,
    kind: String,
    threshold: i32,
    window_minutes: i32,
    cooldown_minutes: i32,
    max_triggers_per_day: i32,
    threshold_multiplier: Option<f64>,
    baseline_minutes: Option<i32>,
    channel: String,
    webhook_url: Option<String>,
    slack_webhook_url: Option<String>,
    email_to: Option<String>,
    enabled: bool,
    last_triggered_at: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct AlertSilenceSummary {
    id: String,
    project_id: String,
    rule_id: Option<String>,
    reason: Option<String>,
    starts_at: String,
    ends_at: String,
    created_at: String,
}

#[derive(Serialize)]
struct AssignmentRuleSummary {
    id: String,
    project_id: String,
    name: String,
    pattern: String,
    assignee: String,
    enabled: bool,
    created_at: String,
}

#[derive(Serialize)]
struct OwnershipRuleSummary {
    id: String,
    project_id: String,
    name: String,
    pattern: String,
    owner: String,
    enabled: bool,
    created_at: String,
}

#[derive(Serialize)]
struct OrgSummary {
    id: String,
    name: String,
    sso_domain: Option<String>,
    data_region: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct SsoConfigSummary {
    id: String,
    org_id: String,
    provider: String,
    saml_metadata: Option<String>,
    oidc_client_id: Option<String>,
    oidc_issuer_url: Option<String>,
    enabled: bool,
    enforce_domain: bool,
    created_at: String,
}

#[derive(Serialize)]
struct ScimTokenSummary {
    id: String,
    org_id: String,
    token: String,
    created_at: String,
}

#[derive(Serialize)]
struct ScimMeta {
    #[serde(rename = "resourceType")]
    resource_type: String,
    created: String,
    #[serde(rename = "lastModified")]
    last_modified: String,
}

#[derive(Serialize)]
struct ScimUserResource {
    schemas: Vec<String>,
    id: String,
    #[serde(rename = "userName")]
    user_name: String,
    active: bool,
    meta: ScimMeta,
}

#[derive(Serialize)]
struct ScimGroupMember {
    value: String,
    display: Option<String>,
}

#[derive(Serialize)]
struct ScimGroupResource {
    schemas: Vec<String>,
    id: String,
    #[serde(rename = "displayName")]
    display_name: String,
    members: Vec<ScimGroupMember>,
    meta: ScimMeta,
}

#[derive(Serialize)]
struct ScimListResponse<T> {
    schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    total_results: usize,
    #[serde(rename = "startIndex")]
    start_index: usize,
    #[serde(rename = "itemsPerPage")]
    items_per_page: usize,
    #[serde(rename = "Resources")]
    resources: Vec<T>,
}

#[derive(Serialize)]
struct IntegrationSummary {
    key: String,
    name: String,
    category: String,
    description: Option<String>,
    auth_type: String,
    oauth_authorize_url: Option<String>,
    oauth_scopes: Option<String>,
    enabled: bool,
}

#[derive(Serialize)]
struct OrgIntegrationSummary {
    id: String,
    org_id: String,
    integration_key: String,
    config: Option<Value>,
    enabled: bool,
    created_at: String,
}

#[derive(Serialize)]
struct OAuthStartResponse {
    authorize_url: String,
}

#[derive(Serialize)]
struct DataRequestSummary {
    id: String,
    org_id: String,
    kind: String,
    subject_email: Option<String>,
    status: String,
    requested_by: Option<String>,
    completed_at: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct DataRequestResultSummary {
    id: String,
    request_id: String,
    payload: Value,
    created_at: String,
}

#[derive(Serialize)]
struct DataRequestRunSummary {
    request_id: String,
    kind: String,
    subject_email: Option<String>,
    status: String,
    payload: Value,
}

#[derive(Serialize)]
struct RegionSummary {
    name: String,
    api_base_url: String,
    ingest_url: String,
    active: bool,
}

#[derive(Serialize)]
struct RoutingSummary {
    project_id: String,
    region: String,
    api_base_url: String,
    ingest_url: String,
}

#[derive(Serialize)]
struct TeamSummary {
    id: String,
    org_id: String,
    name: String,
    created_at: String,
}

#[derive(Serialize)]
struct UserSummary {
    id: String,
    email: String,
    role: String,
    created_at: String,
}

#[derive(Serialize)]
struct TokenSummary {
    id: String,
    team_id: String,
    token: String,
    role: String,
    jwt: Option<String>,
    created_by: Option<String>,
    last_used_at: Option<String>,
    revoked_at: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct ProjectTeamSummary {
    project_id: String,
    team_id: String,
    team_name: String,
    created_at: String,
}

#[derive(Serialize)]
struct AuditLogEntry {
    actor: String,
    action: String,
    entity_type: String,
    entity_id: Option<String>,
    payload: Option<Value>,
    ip: Option<String>,
    user_agent: Option<String>,
    request_id: Option<String>,
    created_at: String,
}

struct AuditMeta {
    ip: Option<String>,
    user_agent: Option<String>,
    request_id: Option<String>,
}

#[derive(Deserialize)]
struct CreateProjectBody {
    id: Option<String>,
    name: String,
    rate_limit_per_min: Option<i64>,
    quota_soft_limit: Option<i64>,
    quota_hard_limit: Option<i64>,
}

#[derive(Deserialize)]
struct CreateReleaseBody {
    version: String,
    commits: Option<Vec<ReleaseCommitInput>>,
}

#[derive(Deserialize)]
struct ReleaseCommitInput {
    commit_sha: String,
    message: Option<String>,
    author: Option<String>,
    timestamp: Option<String>,
}

#[derive(Deserialize)]
struct CreateGroupingRuleBody {
    name: String,
    pattern: String,
    fingerprint: String,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct CreateGroupingOverrideBody {
    source_fingerprint: Option<String>,
    target_fingerprint: Option<String>,
    source_issue_id: Option<String>,
    target_issue_id: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct CreateAlertRuleBody {
    name: String,
    kind: Option<String>,
    threshold: i32,
    window_minutes: Option<i32>,
    cooldown_minutes: Option<i32>,
    max_triggers_per_day: Option<i32>,
    threshold_multiplier: Option<f64>,
    baseline_minutes: Option<i32>,
    channel: String,
    webhook_url: Option<String>,
    slack_webhook_url: Option<String>,
    email_to: Option<String>,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct CreateAlertSilenceBody {
    rule_id: Option<String>,
    reason: Option<String>,
    starts_at: String,
    ends_at: String,
}

#[derive(Deserialize)]
struct CreateAssignmentRuleBody {
    name: String,
    pattern: String,
    assignee: String,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct CreateOwnershipRuleBody {
    name: String,
    pattern: String,
    owner: String,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct CreateOrgBody {
    name: String,
}

#[derive(Deserialize)]
struct UpdateOrgBody {
    sso_domain: Option<String>,
    data_region: Option<String>,
}

#[derive(Deserialize)]
struct CreateTeamBody {
    name: String,
}

#[derive(Deserialize)]
struct CreateDataRequestBody {
    kind: String,
    subject_email: Option<String>,
}

#[derive(Deserialize)]
struct CreateSavedQueryBody {
    name: String,
    query: String,
}

#[derive(Deserialize)]
struct AddTeamUserBody {
    email: String,
    role: Option<String>,
}

#[derive(Deserialize)]
struct CreateTeamTokenBody {
    role: Option<String>,
}

#[derive(Deserialize)]
struct AddProjectTeamBody {
    team_id: String,
}

#[derive(Deserialize)]
struct WebhookUpdateBody {
    url: Option<String>,
}

#[derive(Deserialize)]
struct IntegrationsUpdateBody {
    webhook_url: Option<String>,
    slack_webhook_url: Option<String>,
    github_repo: Option<String>,
    github_token: Option<String>,
}

#[derive(Deserialize)]
struct UpdateSamplingRuleBody {
    target_events_per_min: i32,
    min_rate: Option<f64>,
    max_rate: Option<f64>,
}

#[derive(Deserialize)]
struct UpdateSlaPolicyBody {
    sla_minutes: i32,
}

#[derive(Deserialize)]
struct UpdateSloPolicyBody {
    target_error_rate: f64,
    window_minutes: Option<i32>,
}

#[derive(Deserialize)]
struct UpdatePiiPolicyBody {
    scrub_emails: Option<bool>,
    scrub_ips: Option<bool>,
    scrub_secrets: Option<bool>,
}

#[derive(Deserialize)]
struct UpdateRcaPolicyBody {
    min_confidence: Option<f64>,
}

#[derive(Deserialize)]
struct UpdateStoragePolicyBody {
    hot_days: i32,
    cold_days: i32,
}

#[derive(Deserialize)]
struct StorageTierRunBody {
    dry_run: Option<bool>,
}

#[derive(Deserialize)]
struct CreateWebhookEndpointBody {
    url: String,
    secret: Option<String>,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct WebhookDeliveriesQuery {
    limit: Option<u32>,
}

#[derive(Serialize)]
struct StorageTierRunSummary {
    project_id: String,
    hot_cutoff: String,
    cold_cutoff: String,
    events_cold: i64,
    transactions_cold: i64,
    replays_cold: i64,
    profiles_cold: i64,
    events_deleted: i64,
    transactions_deleted: i64,
    replays_deleted: i64,
    profiles_deleted: i64,
}

#[derive(Deserialize)]
struct ProjectCostQuery {
    limit: Option<u32>,
}

#[derive(Serialize)]
struct ProjectCostDailyRow {
    day: String,
    units: f64,
    storage_bytes: i64,
}

#[derive(Serialize)]
struct RcaStatsResponse {
    window_minutes: i64,
    avg_confidence: f64,
    min_confidence: f64,
    max_confidence: f64,
    count: i64,
}

#[derive(Serialize)]
struct RcaPolicySummary {
    project_id: String,
    min_confidence: f64,
    updated_at: String,
}

#[derive(Serialize)]
struct CostUnitRow {
    id: String,
    entity_id: String,
    kind: String,
    units: f64,
    storage_bytes: i64,
    created_at: String,
}

#[derive(Deserialize)]
struct GroupingDecisionStatsQuery {
    window_minutes: Option<i64>,
}

#[derive(Serialize)]
struct GroupingDecisionStatsRow {
    key: String,
    count: i64,
}

#[derive(Serialize)]
struct GroupingDecisionStatsResponse {
    by_reason: Vec<GroupingDecisionStatsRow>,
    by_version: Vec<GroupingDecisionStatsRow>,
}

#[derive(Deserialize)]
struct GroupingDecisionListQuery {
    limit: Option<u32>,
}

#[derive(Serialize)]
struct GroupingDecisionSummary {
    id: String,
    event_id: String,
    issue_id: String,
    fingerprint: String,
    algorithm_version: String,
    reason: String,
    created_at: String,
}

#[derive(Serialize)]
struct GroupingRuleAppliedSummary {
    id: String,
    decision_id: String,
    rule_id: String,
    rule_name: String,
    matched: bool,
    created_at: String,
}

#[derive(Serialize)]
struct IngestDropRow {
    day: String,
    reason: String,
    count: i64,
}

#[derive(Serialize)]
struct WebhookEndpointSummary {
    id: String,
    project_id: String,
    url: String,
    enabled: bool,
    created_at: String,
}

#[derive(Serialize)]
struct WebhookDeliverySummary {
    id: String,
    status_code: Option<i32>,
    error: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
struct UpsertSsoConfigBody {
    provider: String,
    saml_metadata: Option<String>,
    oidc_client_id: Option<String>,
    oidc_client_secret: Option<String>,
    oidc_issuer_url: Option<String>,
    enabled: Option<bool>,
    enforce_domain: Option<bool>,
}

#[derive(Deserialize)]
struct UpsertOrgIntegrationBody {
    integration_key: String,
    config: Option<Value>,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct UpdateIssueStatusBody {
    status: String,
}

#[derive(Deserialize)]
struct AssignIssueBody {
    assignee: Option<String>,
}

#[derive(Deserialize)]
struct IssueBulkUpdateBody {
    issue_ids: Vec<String>,
    status: Option<String>,
    assignee: Option<String>,
}

#[derive(Serialize)]
struct IssueBulkUpdateResponse {
    updated: i64,
}

#[derive(Deserialize)]
struct SearchIssuesQuery {
    query: String,
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct SearchIssuesV2Query {
    query: String,
    limit: Option<u32>,
    before: Option<String>,
    window_minutes: Option<i64>,
}

#[derive(Serialize)]
struct FacetBucket {
    key: String,
    count: i64,
}

#[derive(Serialize)]
struct SearchFacets {
    release: Vec<FacetBucket>,
    exception_type: Vec<FacetBucket>,
    env: Vec<FacetBucket>,
    tags: Vec<FacetBucket>,
}

#[derive(Serialize)]
struct SearchIssuesV2Response {
    items: Vec<IssueSummary>,
    next_before: Option<String>,
    facets: SearchFacets,
}

#[derive(Deserialize)]
struct AuditLogQuery {
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct UiAuthQuery {
    project: String,
    key: String,
    status: Option<String>,
    level: Option<String>,
    q: Option<String>,
}

#[derive(Deserialize)]
struct SourcemapUploadBody {
    release: String,
    minified_url: String,
    map_text: String,
}

#[derive(Serialize)]
struct EventDetailResponse {
    id: String,
    issue_id: String,
    project_id: String,
    occurred_at: String,
    level: String,
    message: Option<String>,
    exception_type: String,
    exception_message: String,
    stacktrace: Option<Value>,
    context: Option<Value>,
    sdk: Option<Value>,
}

#[derive(Serialize)]
struct ReplaySummary {
    id: String,
    project_id: String,
    session_id: String,
    started_at: String,
    duration_ms: f64,
    url: Option<String>,
    user_id: Option<String>,
    user_email: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct ReplayDetail {
    id: String,
    project_id: String,
    session_id: String,
    started_at: String,
    duration_ms: f64,
    url: Option<String>,
    user_id: Option<String>,
    user_email: Option<String>,
    breadcrumbs: Option<Value>,
    events: Option<Value>,
    payload: Value,
    created_at: String,
}

#[derive(Deserialize)]
struct ReplayLinkBody {
    issue_id: Option<String>,
    trace_id: Option<String>,
}

#[derive(Serialize)]
struct ReplayTimelineItem {
    timestamp: String,
    kind: String,
    message: Option<String>,
    data: Value,
}

#[derive(Serialize)]
struct ReplayTimelineResponse {
    id: String,
    items: Vec<ReplayTimelineItem>,
}

#[derive(Serialize)]
struct ReplayLinkSummary {
    replay_id: String,
    issue_id: Option<String>,
    trace_id: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct IssueInsights {
    issue_id: String,
    summary: String,
    culprit: Option<String>,
    last_release: Option<String>,
    regressed_at: Option<String>,
    causal_chain: Option<Value>,
    regression_map: Option<Value>,
    confidence: Option<f64>,
    published: bool,
    updated_at: String,
}

#[derive(Serialize)]
struct SavedQuerySummary {
    id: String,
    project_id: String,
    name: String,
    query: String,
    created_at: String,
}

#[derive(Serialize)]
struct TransactionSummary {
    id: String,
    trace_id: String,
    span_id: String,
    name: String,
    status: String,
    duration_ms: f64,
    occurred_at: String,
    tags: Option<Value>,
    measurements: Option<Value>,
}

#[derive(Serialize)]
struct SpanSummary {
    trace_id: String,
    span_id: String,
    parent_id: Option<String>,
    op: Option<String>,
    description: Option<String>,
    status: Option<String>,
    start_ts: String,
    duration_ms: f64,
    tags: Option<Value>,
}

#[derive(Serialize)]
struct TraceWaterfallSpan {
    span_id: String,
    parent_id: Option<String>,
    op: Option<String>,
    description: Option<String>,
    status: Option<String>,
    start_ts: String,
    duration_ms: f64,
    self_time_ms: f64,
    depth: i32,
    tags: Option<Value>,
}

#[derive(Serialize)]
struct TraceWaterfallResponse {
    trace_id: String,
    spans: Vec<TraceWaterfallSpan>,
}

#[derive(Serialize)]
struct TraceIssueSummary {
    id: String,
    title: String,
    level: String,
    status: String,
    assignee: Option<String>,
    last_seen: String,
}

#[derive(Serialize)]
struct TraceCorrelationResponse {
    trace_id: String,
    issues: Vec<TraceIssueSummary>,
    replays: Vec<ReplaySummary>,
}

#[derive(Serialize)]
struct TopRegressionSummary {
    id: String,
    title: String,
    level: String,
    status: String,
    assignee: Option<String>,
    regressed_at: String,
    last_seen: String,
    last_release: Option<String>,
    events_24h: i64,
}

#[derive(Serialize)]
struct TransactionStat {
    name: String,
    count: i64,
    avg_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}

#[derive(Serialize)]
struct ServiceMapEdge {
    source: String,
    target: String,
    count: i64,
}

#[derive(Serialize)]
struct TraceBreakdownRow {
    op: String,
    count: i64,
    avg_ms: f64,
    p95_ms: f64,
}

#[derive(Serialize)]
struct ProfileSummary {
    id: String,
    trace_id: String,
    created_at: String,
    profile: Value,
}

#[derive(Deserialize)]
struct ProfileListQuery {
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct ProfileHotPathsQuery {
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct ProfileDiffQuery {
    base_id: Option<String>,
    compare_id: Option<String>,
    limit: Option<u32>,
}

#[derive(Serialize)]
struct ProfileListItem {
    id: String,
    trace_id: String,
    created_at: String,
    size_bytes: usize,
    sample_count: Option<i64>,
}

#[derive(Serialize)]
struct ProfileHotPath {
    frame: String,
    weight: f64,
}

#[derive(Serialize)]
struct ProfileHotPathsResponse {
    trace_id: String,
    items: Vec<ProfileHotPath>,
}

#[derive(Serialize)]
struct ProfileDiffEntry {
    frame: String,
    base_weight: f64,
    compare_weight: f64,
    delta: f64,
}

#[derive(Serialize)]
struct ProfileDiffResponse {
    trace_id: String,
    base_id: String,
    compare_id: String,
    items: Vec<ProfileDiffEntry>,
}

#[derive(Serialize, Deserialize)]
struct AccessClaims {
    sub: String,
    team_id: String,
    token_id: String,
    role: String,
    scopes: Option<Vec<String>>,
    exp: usize,
    iat: usize,
}

async fn list_issues(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IssueListQuery>,
) -> Result<Json<IssueListResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let limit = query.limit.unwrap_or(50).min(200) as i64;
    let before = parse_optional_timestamp(query.before.as_deref())?;
    let status = query.status.as_deref().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    let level = query.level.as_deref().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    let pattern = query.q.as_deref().map(|s| format!("%{}%", s.trim())).filter(|s| !s.is_empty());

    let rows = if let Some(before_ts) = before {
        sqlx::query(
            "SELECT i.id, i.title, i.level, i.status, i.last_seen, i.assignee, i.last_user_email, i.last_user_id, COALESCE(e.count_24h, 0) AS count_24h, COALESCE(u.users_24h, 0) AS users_24h\
            FROM issues i\
            LEFT JOIN (\
                SELECT issue_id, COUNT(*)::bigint AS count_24h\
                FROM events\
                WHERE occurred_at > now() - interval '24 hours'\
                GROUP BY issue_id\
            ) e ON e.issue_id = i.id\
            LEFT JOIN (\
                SELECT issue_id, COUNT(DISTINCT COALESCE(user_id, user_email))::bigint AS users_24h\
                FROM events\
                WHERE occurred_at > now() - interval '24 hours'\
                GROUP BY issue_id\
            ) u ON u.issue_id = i.id\
            WHERE i.project_id = $1 AND i.last_seen < $2\
            AND ($3::text IS NULL OR i.status = $3)\
            AND ($4::text IS NULL OR i.level = $4)\
            AND ($5::text IS NULL OR i.title ILIKE $5 OR i.fingerprint ILIKE $5)\
            ORDER BY i.last_seen DESC\
            LIMIT $6",
        )
        .bind(&project_id)
        .bind(before_ts)
        .bind(&status)
        .bind(&level)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            "SELECT i.id, i.title, i.level, i.status, i.last_seen, i.assignee, i.last_user_email, i.last_user_id, COALESCE(e.count_24h, 0) AS count_24h, COALESCE(u.users_24h, 0) AS users_24h\
            FROM issues i\
            LEFT JOIN (\
                SELECT issue_id, COUNT(*)::bigint AS count_24h\
                FROM events\
                WHERE occurred_at > now() - interval '24 hours'\
                GROUP BY issue_id\
            ) e ON e.issue_id = i.id\
            LEFT JOIN (\
                SELECT issue_id, COUNT(DISTINCT COALESCE(user_id, user_email))::bigint AS users_24h\
                FROM events\
                WHERE occurred_at > now() - interval '24 hours'\
                GROUP BY issue_id\
            ) u ON u.issue_id = i.id\
            WHERE i.project_id = $1\
            AND ($2::text IS NULL OR i.status = $2)\
            AND ($3::text IS NULL OR i.level = $3)\
            AND ($4::text IS NULL OR i.title ILIKE $4 OR i.fingerprint ILIKE $4)\
            ORDER BY i.last_seen DESC\
            LIMIT $5",
        )
        .bind(&project_id)
        .bind(&status)
        .bind(&level)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: uuid::Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let title: String = row
            .try_get("title")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let level: String = row
            .try_get("level")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_seen: DateTime<Utc> = row
            .try_get("last_seen")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let assignee: Option<String> = row
            .try_get("assignee")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_user_email: Option<String> = row
            .try_get("last_user_email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_user_id: Option<String> = row
            .try_get("last_user_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count_24h: i64 = row
            .try_get("count_24h")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let users_24h: i64 = row
            .try_get("users_24h")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let last_user = last_user_email.or(last_user_id);

        items.push(IssueSummary {
            id: id.to_string(),
            title,
            level,
            status,
            last_seen: last_seen.to_rfc3339(),
            count_24h,
            assignee,
            affected_users_24h: users_24h,
            last_user,
        });
    }

    let next_before = items.last().map(|item| item.last_seen.clone());
    Ok(Json(IssueListResponse { items, next_before }))
}

async fn issue_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IssueStatsQuery>,
) -> Result<Json<IssueStatsResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let window_minutes = query.window_minutes.unwrap_or(1440).max(1);
    let sla_minutes = query.sla_minutes.unwrap_or(1440).max(1);

    let by_status_rows = sqlx::query(
        "SELECT status AS key, COUNT(*)::bigint AS count\
        FROM issues\
        WHERE project_id = $1 AND last_seen > now() - make_interval(mins => $2)\
        GROUP BY status\
        ORDER BY count DESC",
    )
    .bind(&project_id)
    .bind(window_minutes)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut by_status = Vec::with_capacity(by_status_rows.len());
    for row in by_status_rows {
        by_status.push(IssueStatsRow {
            key: row.try_get("key").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            count: row.try_get("count").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        });
    }

    let by_level_rows = sqlx::query(
        "SELECT level AS key, COUNT(*)::bigint AS count\
        FROM issues\
        WHERE project_id = $1 AND last_seen > now() - make_interval(mins => $2)\
        GROUP BY level\
        ORDER BY count DESC",
    )
    .bind(&project_id)
    .bind(window_minutes)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut by_level = Vec::with_capacity(by_level_rows.len());
    for row in by_level_rows {
        by_level.push(IssueStatsRow {
            key: row.try_get("key").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            count: row.try_get("count").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        });
    }

    let by_assignee_rows = sqlx::query(
        "SELECT COALESCE(assignee, 'unassigned') AS key, COUNT(*)::bigint AS count\
        FROM issues\
        WHERE project_id = $1 AND last_seen > now() - make_interval(mins => $2)\
        GROUP BY key\
        ORDER BY count DESC",
    )
    .bind(&project_id)
    .bind(window_minutes)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut by_assignee = Vec::with_capacity(by_assignee_rows.len());
    for row in by_assignee_rows {
        by_assignee.push(IssueStatsRow {
            key: row.try_get("key").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            count: row.try_get("count").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        });
    }

    let open_row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count FROM issues WHERE project_id = $1 AND status = 'open'",
    )
    .bind(&project_id)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let open_issues: i64 = open_row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let sla_row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count\
        FROM issues\
        WHERE project_id = $1 AND status = 'open'\
        AND first_seen < now() - make_interval(mins => $2)",
    )
    .bind(&project_id)
    .bind(sla_minutes)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let sla_breaches: i64 = sla_row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(IssueStatsResponse {
        by_status,
        by_level,
        by_assignee,
        open_issues,
        sla_breaches,
    }))
}

async fn bulk_update_issues(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<IssueBulkUpdateBody>,
) -> Result<Json<IssueBulkUpdateResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    require_project_scope(&auth, "project:triage")?;

    if payload.issue_ids.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "issue_ids manquant".to_string()));
    }

    let status = payload
        .status
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty());
    if let Some(status) = status.as_deref() {
        if !matches!(status, "open" | "resolved" | "ignored") {
            return Err((StatusCode::BAD_REQUEST, "status invalide".to_string()));
        }
    }

    let assignee = payload
        .assignee
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if status.is_none() && assignee.is_none() {
        return Err((StatusCode::BAD_REQUEST, "aucune modification".to_string()));
    }

    let mut issue_ids = Vec::with_capacity(payload.issue_ids.len());
    for raw in payload.issue_ids {
        let issue_id = Uuid::parse_str(&raw)
            .map_err(|_| (StatusCode::BAD_REQUEST, "issue_id invalide".to_string()))?;
        issue_ids.push(issue_id);
    }

    let result = sqlx::query(
        "UPDATE issues SET status = COALESCE($1, status), assignee = COALESCE($2, assignee)\
        WHERE project_id = $3 AND id = ANY($4)"
    )
    .bind(&status)
    .bind(&assignee)
    .bind(&auth.project_id)
    .bind(&issue_ids)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let updated = result.rows_affected() as i64;

    insert_audit_log(
        &state.db,
        &auth.actor,
        "issues.bulk_update",
        "issue",
        None,
        Some(json!({
            "count": updated,
            "status": status,
            "assignee": assignee
        })),
        Some(&headers),
    )
    .await?;

    Ok(Json(IssueBulkUpdateResponse { updated }))
}

async fn get_issue(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<IssueDetailResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let issue_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let issue_row = sqlx::query(
        "SELECT id, project_id, fingerprint, title, level, status, assignee, first_release, last_release, regressed_at, last_user_email, last_user_id, github_issue_url, first_seen, last_seen, count_total\
        FROM issues WHERE id = $1 AND project_id = $2",
    )
    .bind(issue_id)
    .bind(&project_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let issue_row = match issue_row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "issue introuvable".to_string())),
    };

    let project_id: String = issue_row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let fingerprint: String = issue_row
        .try_get("fingerprint")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let title: String = issue_row
        .try_get("title")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let level: String = issue_row
        .try_get("level")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let status: String = issue_row
        .try_get("status")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let assignee: Option<String> = issue_row
        .try_get("assignee")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let first_release: Option<String> = issue_row
        .try_get("first_release")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_release: Option<String> = issue_row
        .try_get("last_release")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let regressed_at: Option<DateTime<Utc>> = issue_row
        .try_get("regressed_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_user_email: Option<String> = issue_row
        .try_get("last_user_email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_user_id: Option<String> = issue_row
        .try_get("last_user_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let github_issue_url: Option<String> = issue_row
        .try_get("github_issue_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_user = last_user_email.or(last_user_id);
    let first_seen: DateTime<Utc> = issue_row
        .try_get("first_seen")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_seen: DateTime<Utc> = issue_row
        .try_get("last_seen")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let count_total: i64 = issue_row
        .try_get("count_total")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let event_row = sqlx::query(
        "SELECT occurred_at, message, exception_type, exception_message, stacktrace, context\
        FROM events WHERE issue_id = $1 ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(issue_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let last_event = if let Some(row) = event_row {
        let occurred_at: DateTime<Utc> = row
            .try_get("occurred_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let message: Option<String> = row
            .try_get("message")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let exception_type: String = row
            .try_get("exception_type")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let exception_message: String = row
            .try_get("exception_message")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let stacktrace: Option<Value> = row
            .try_get("stacktrace")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let context: Option<Value> = row
            .try_get("context")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        Some(EventSummary {
            occurred_at: occurred_at.to_rfc3339(),
            message,
            exception_type,
            exception_message,
            stacktrace,
            context,
        })
    } else {
        None
    };

    Ok(Json(IssueDetailResponse {
        id: issue_id.to_string(),
        project_id,
        fingerprint,
        title,
        level,
        status,
        assignee,
        first_release,
        last_release,
        regressed_at: regressed_at.map(|value| value.to_rfc3339()),
        last_user,
        github_issue_url,
        first_seen: first_seen.to_rfc3339(),
        last_seen: last_seen.to_rfc3339(),
        count_total,
        last_event,
    }))
}

async fn list_issue_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<IssueListQuery>,
) -> Result<Json<EventListResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let _project_id = auth.project_id;

    let issue_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let limit = query.limit.unwrap_or(50).min(200) as i64;

    let rows = sqlx::query(
        "SELECT occurred_at, message, exception_type, exception_message, stacktrace\
        FROM events\
        WHERE issue_id = $1\
        ORDER BY occurred_at DESC\
        LIMIT $2",
    )
    .bind(issue_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let occurred_at: DateTime<Utc> = row
            .try_get("occurred_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let message: Option<String> = row
            .try_get("message")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let exception_type: String = row
            .try_get("exception_type")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let exception_message: String = row
            .try_get("exception_message")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let stacktrace: Option<Value> = row
            .try_get("stacktrace")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(EventSummary {
            occurred_at: occurred_at.to_rfc3339(),
            message,
            exception_type,
            exception_message,
            stacktrace,
            context: None,
        });
    }

    Ok(Json(EventListResponse { items }))
}

async fn search_issues(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchIssuesQuery>,
) -> Result<Json<IssueListResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let limit = query.limit.unwrap_or(50).min(200) as i64;
    let pattern = format!("%{}%", query.query.trim());

    let rows = sqlx::query(
        "SELECT i.id, i.title, i.level, i.status, i.last_seen, i.assignee, i.last_user_email, i.last_user_id, COALESCE(e.count_24h, 0) AS count_24h, COALESCE(u.users_24h, 0) AS users_24h\
        FROM issues i\
        LEFT JOIN (\
            SELECT issue_id, COUNT(*)::bigint AS count_24h\
            FROM events\
            WHERE occurred_at > now() - interval '24 hours'\
            GROUP BY issue_id\
        ) e ON e.issue_id = i.id\
        LEFT JOIN (\
            SELECT issue_id, COUNT(DISTINCT COALESCE(user_id, user_email))::bigint AS users_24h\
            FROM events\
            WHERE occurred_at > now() - interval '24 hours'\
            GROUP BY issue_id\
        ) u ON u.issue_id = i.id\
        WHERE i.project_id = $1 AND (i.title ILIKE $2 OR i.fingerprint ILIKE $2)\
        ORDER BY i.last_seen DESC\
        LIMIT $3",
    )
    .bind(&project_id)
    .bind(&pattern)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: uuid::Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let title: String = row
            .try_get("title")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let level: String = row
            .try_get("level")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_seen: DateTime<Utc> = row
            .try_get("last_seen")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let assignee: Option<String> = row
            .try_get("assignee")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_user_email: Option<String> = row
            .try_get("last_user_email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_user_id: Option<String> = row
            .try_get("last_user_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count_24h: i64 = row
            .try_get("count_24h")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let users_24h: i64 = row
            .try_get("users_24h")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let last_user = last_user_email.or(last_user_id);

        items.push(IssueSummary {
            id: id.to_string(),
            title,
            level,
            status,
            last_seen: last_seen.to_rfc3339(),
            count_24h,
            assignee,
            affected_users_24h: users_24h,
            last_user,
        });
    }

    Ok(Json(IssueListResponse {
        items,
        next_before: None,
    }))
}

async fn search_issues_v2(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchIssuesV2Query>,
) -> Result<Json<SearchIssuesV2Response>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let raw_query = query.query.trim();
    if raw_query.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "query manquante".to_string()));
    }

    let limit = query.limit.unwrap_or(50).min(200) as i64;
    let before = parse_optional_timestamp(query.before.as_deref())?;
    let window_minutes = query.window_minutes.unwrap_or(1440).max(1);

    let rows = if let Some(before_ts) = before {
        sqlx::query(
            "SELECT i.id, i.title, i.level, i.status, i.last_seen, i.assignee, i.last_user_email, i.last_user_id,\
            COALESCE(e.count_24h, 0) AS count_24h, COALESCE(u.users_24h, 0) AS users_24h\
            FROM issues i\
            LEFT JOIN (\
                SELECT issue_id, COUNT(*)::bigint AS count_24h\
                FROM events\
                WHERE occurred_at > now() - interval '24 hours'\
                GROUP BY issue_id\
            ) e ON e.issue_id = i.id\
            LEFT JOIN (\
                SELECT issue_id, COUNT(DISTINCT COALESCE(user_id, user_email))::bigint AS users_24h\
                FROM events\
                WHERE occurred_at > now() - interval '24 hours'\
                GROUP BY issue_id\
            ) u ON u.issue_id = i.id\
            WHERE i.project_id = $1 AND i.last_seen < $2\
            AND (\
                to_tsvector('simple', i.title) @@ plainto_tsquery('simple', $3)\
                OR EXISTS (\
                    SELECT 1 FROM events ev\
                    WHERE ev.project_id = $1 AND ev.issue_id = i.id\
                    AND to_tsvector('simple', COALESCE(ev.message, '') || ' ' || ev.exception_message || ' ' || ev.exception_type)\
                        @@ plainto_tsquery('simple', $3)\
                )\
            )\
            ORDER BY i.last_seen DESC\
            LIMIT $4",
        )
        .bind(&project_id)
        .bind(before_ts)
        .bind(raw_query)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            "SELECT i.id, i.title, i.level, i.status, i.last_seen, i.assignee, i.last_user_email, i.last_user_id,\
            COALESCE(e.count_24h, 0) AS count_24h, COALESCE(u.users_24h, 0) AS users_24h\
            FROM issues i\
            LEFT JOIN (\
                SELECT issue_id, COUNT(*)::bigint AS count_24h\
                FROM events\
                WHERE occurred_at > now() - interval '24 hours'\
                GROUP BY issue_id\
            ) e ON e.issue_id = i.id\
            LEFT JOIN (\
                SELECT issue_id, COUNT(DISTINCT COALESCE(user_id, user_email))::bigint AS users_24h\
                FROM events\
                WHERE occurred_at > now() - interval '24 hours'\
                GROUP BY issue_id\
            ) u ON u.issue_id = i.id\
            WHERE i.project_id = $1\
            AND (\
                to_tsvector('simple', i.title) @@ plainto_tsquery('simple', $2)\
                OR EXISTS (\
                    SELECT 1 FROM events ev\
                    WHERE ev.project_id = $1 AND ev.issue_id = i.id\
                    AND to_tsvector('simple', COALESCE(ev.message, '') || ' ' || ev.exception_message || ' ' || ev.exception_type)\
                        @@ plainto_tsquery('simple', $2)\
                )\
            )\
            ORDER BY i.last_seen DESC\
            LIMIT $3",
        )
        .bind(&project_id)
        .bind(raw_query)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    let mut issue_ids = Vec::with_capacity(rows.len());
    for row in rows {
        let id: uuid::Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let title: String = row
            .try_get("title")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let level: String = row
            .try_get("level")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_seen: DateTime<Utc> = row
            .try_get("last_seen")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let assignee: Option<String> = row
            .try_get("assignee")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_user_email: Option<String> = row
            .try_get("last_user_email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_user_id: Option<String> = row
            .try_get("last_user_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count_24h: i64 = row
            .try_get("count_24h")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let users_24h: i64 = row
            .try_get("users_24h")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        issue_ids.push(id);
        items.push(IssueSummary {
            id: id.to_string(),
            title,
            level,
            status,
            last_seen: last_seen.to_rfc3339(),
            count_24h,
            assignee,
            affected_users_24h: users_24h,
            last_user: last_user_email.or(last_user_id),
        });
    }

    let facets = if issue_ids.is_empty() {
        SearchFacets {
            release: Vec::new(),
            exception_type: Vec::new(),
            env: Vec::new(),
            tags: Vec::new(),
        }
    } else {
        let release_rows = sqlx::query(
            "SELECT release AS key, COUNT(*)::bigint AS count\
            FROM events\
            WHERE project_id = $1 AND issue_id = ANY($2)\
            AND release IS NOT NULL\
            AND occurred_at > now() - make_interval(mins => $3)\
            GROUP BY release ORDER BY count DESC LIMIT 50",
        )
        .bind(&project_id)
        .bind(&issue_ids)
        .bind(window_minutes)
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let exception_rows = sqlx::query(
            "SELECT exception_type AS key, COUNT(*)::bigint AS count\
            FROM events\
            WHERE project_id = $1 AND issue_id = ANY($2)\
            AND occurred_at > now() - make_interval(mins => $3)\
            GROUP BY exception_type ORDER BY count DESC LIMIT 50",
        )
        .bind(&project_id)
        .bind(&issue_ids)
        .bind(window_minutes)
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let env_rows = sqlx::query(
            "SELECT context->>'env' AS key, COUNT(*)::bigint AS count\
            FROM events\
            WHERE project_id = $1 AND issue_id = ANY($2)\
            AND context ? 'env'\
            AND occurred_at > now() - make_interval(mins => $3)\
            GROUP BY key ORDER BY count DESC LIMIT 50",
        )
        .bind(&project_id)
        .bind(&issue_ids)
        .bind(window_minutes)
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let tags_rows = sqlx::query(
            "SELECT (t.key || ':' || t.value) AS key, COUNT(*)::bigint AS count\
            FROM events e\
            JOIN LATERAL jsonb_each_text(e.context->'tags') AS t(key, value) ON true\
            WHERE e.project_id = $1 AND e.issue_id = ANY($2)\
            AND e.context ? 'tags'\
            AND e.occurred_at > now() - make_interval(mins => $3)\
            GROUP BY key ORDER BY count DESC LIMIT 100",
        )
        .bind(&project_id)
        .bind(&issue_ids)
        .bind(window_minutes)
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let mut release = Vec::with_capacity(release_rows.len());
        for row in release_rows {
            release.push(FacetBucket {
                key: row.try_get("key").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
                count: row.try_get("count").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            });
        }

        let mut exception_type = Vec::with_capacity(exception_rows.len());
        for row in exception_rows {
            exception_type.push(FacetBucket {
                key: row.try_get("key").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
                count: row.try_get("count").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            });
        }

        let mut env = Vec::with_capacity(env_rows.len());
        for row in env_rows {
            env.push(FacetBucket {
                key: row.try_get("key").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
                count: row.try_get("count").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            });
        }

        let mut tags = Vec::with_capacity(tags_rows.len());
        for row in tags_rows {
            tags.push(FacetBucket {
                key: row.try_get("key").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
                count: row.try_get("count").map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            });
        }

        SearchFacets {
            release,
            exception_type,
            env,
            tags,
        }
    };

    let next_before = items.last().map(|item| item.last_seen.clone());
    Ok(Json(SearchIssuesV2Response { items, next_before, facets }))
}

async fn upload_sourcemap(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SourcemapUploadBody>,
) -> Result<&'static str, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id.clone();
    require_project_scope(&auth, "project:write")?;

    let release = payload.release.trim();
    let minified_url = payload.minified_url.trim();
    if release.is_empty() || minified_url.is_empty() || payload.map_text.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "payload invalide".to_string()));
    }

    sqlx::query(
        "INSERT INTO sourcemaps (project_id, release, minified_url, map_text)\
        VALUES ($1, $2, $3, $4)\
        ON CONFLICT (project_id, release, minified_url) DO UPDATE SET map_text = EXCLUDED.map_text",
    )
    .bind(&project_id)
    .bind(release)
    .bind(minified_url)
    .bind(&payload.map_text)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &auth.actor,
        "sourcemap.upload",
        "project",
        Some(&project_id),
        Some(json!({ "release": release, "minified_url": minified_url })),
        Some(&headers),
    )
    .await?;

    Ok("ok")
}

async fn ui_issue_list(
    State(state): State<AppState>,
    Query(query): Query<UiAuthQuery>,
) -> Result<String, (StatusCode, String)> {
    authorize_project(&state.db, &query.project, &query.key).await?;

    let status = query.status.as_deref().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    let level = query.level.as_deref().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    let pattern = query.q.as_deref().map(|s| format!("%{}%", s.trim())).filter(|s| !s.is_empty());

    let rows = sqlx::query(
        "SELECT id, title, level, last_seen, assignee, count_total, status\
        FROM issues\
        WHERE project_id = $1\
        AND ($2::text IS NULL OR status = $2)\
        AND ($3::text IS NULL OR level = $3)\
        AND ($4::text IS NULL OR title ILIKE $4 OR fingerprint ILIKE $4)\
        ORDER BY last_seen DESC LIMIT 200",
    )
    .bind(&query.project)
    .bind(&status)
    .bind(&level)
    .bind(pattern)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut body = String::new();
    body.push_str("<html><head><meta charset='utf-8'><title>EMBER</title>");
    body.push_str("<style>body{font-family:Inter,Arial,sans-serif;margin:24px;background:#0b0d12;color:#f5f5f5;}table{width:100%;border-collapse:collapse;}th,td{padding:10px;border-bottom:1px solid #222;}a{color:#7dd3fc;text-decoration:none;} .badge{padding:2px 8px;border-radius:999px;background:#222;}</style>");
    body.push_str("</head><body>");
    body.push_str("<h2>Issues</h2>");
    body.push_str("<form method='get' style='margin-bottom:16px'>");
    body.push_str(&format!("<input type='hidden' name='project' value='{}'/>", html_escape(&query.project)));
    body.push_str(&format!("<input type='hidden' name='key' value='{}'/>", html_escape(&query.key)));
    body.push_str("<label>Status <select name='status'>");
    body.push_str("<option value=''>all</option>");
    for value in ["open", "resolved", "ignored"] {
        let selected = status.as_deref() == Some(value);
        body.push_str(&format!("<option value='{}'{}>{}</option>", value, if selected { " selected" } else { "" }, value));
    }
    body.push_str("</select></label> ");
    body.push_str("<label>Niveau <select name='level'>");
    body.push_str("<option value=''>all</option>");
    for value in ["error", "warning", "info", "debug"] {
        let selected = level.as_deref() == Some(value);
        body.push_str(&format!("<option value='{}'{}>{}</option>", value, if selected { " selected" } else { "" }, value));
    }
    body.push_str("</select></label> ");
    body.push_str(&format!("<input type='text' name='q' placeholder='search' value='{}'/> ", html_escape(query.q.as_deref().unwrap_or(""))));
    body.push_str("<button type='submit'>Filtrer</button>");
    body.push_str("</form>");
    body.push_str("<table><thead><tr><th>Titre</th><th>Niveau</th><th>Status</th><th>Assigné</th><th>Dernier</th><th>Total</th></tr></thead><tbody>");

    for row in rows {
        let id: uuid::Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let title: String = row
            .try_get("title")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let level: String = row
            .try_get("level")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let assignee: Option<String> = row
            .try_get("assignee")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_seen: DateTime<Utc> = row
            .try_get("last_seen")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count_total: i64 = row
            .try_get("count_total")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let safe_title = html_escape(&title);
        let url = format!("/ui/issues/{}?project={}&key={}", id, query.project, query.key);
        body.push_str(&format!(
            "<tr><td><a href='{}'>{}</a></td><td><span class='badge'>{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            url,
            safe_title,
            level,
            status,
            assignee.unwrap_or_else(|| "-".to_string()),
            last_seen.to_rfc3339(),
            count_total
        ));
    }

    body.push_str("</tbody></table></body></html>");
    Ok(body)
}

async fn ui_issue_detail(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<UiAuthQuery>,
) -> Result<String, (StatusCode, String)> {
    authorize_project(&state.db, &query.project, &query.key).await?;

    let issue_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let issue_row = sqlx::query(
        "SELECT id, title, level, status, assignee, first_release, last_release, regressed_at, first_seen, last_seen, count_total\
        FROM issues WHERE id = $1 AND project_id = $2",
    )
    .bind(issue_id)
    .bind(&query.project)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let issue_row = match issue_row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "issue introuvable".to_string())),
    };

    let title: String = issue_row
        .try_get("title")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let level: String = issue_row
        .try_get("level")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let status: String = issue_row
        .try_get("status")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let assignee: Option<String> = issue_row
        .try_get("assignee")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let first_release: Option<String> = issue_row
        .try_get("first_release")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_release: Option<String> = issue_row
        .try_get("last_release")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let regressed_at: Option<DateTime<Utc>> = issue_row
        .try_get("regressed_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let first_seen: DateTime<Utc> = issue_row
        .try_get("first_seen")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_seen: DateTime<Utc> = issue_row
        .try_get("last_seen")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let count_total: i64 = issue_row
        .try_get("count_total")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let event_row = sqlx::query(
        "SELECT occurred_at, message, exception_type, exception_message, stacktrace, context\
        FROM events WHERE issue_id = $1 ORDER BY occurred_at DESC LIMIT 1",
    )
    .bind(issue_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut body = String::new();
    body.push_str("<html><head><meta charset='utf-8'><title>EMBER</title>");
    body.push_str("<style>body{font-family:Inter,Arial,sans-serif;margin:24px;background:#0b0d12;color:#f5f5f5;}a{color:#7dd3fc;text-decoration:none;}pre{background:#111;padding:12px;border-radius:8px;overflow:auto;}</style>");
    body.push_str("</head><body>");
    body.push_str(&format!("<a href='/ui?project={}&key={}'>← retour</a>", query.project, query.key));
    body.push_str(&format!("<h2>{}</h2>", html_escape(&title)));
    body.push_str(&format!("<p>Niveau: {} | Status: {} | Assigné: {} | Total: {}</p>", level, status, assignee.unwrap_or_else(|| "-".to_string()), count_total));
    body.push_str(&format!("<p>Release: {} → {} | Régression: {}</p>",
        first_release.clone().unwrap_or_else(|| "-".to_string()),
        last_release.clone().unwrap_or_else(|| "-".to_string()),
        regressed_at.map(|value| value.to_rfc3339()).unwrap_or_else(|| "-".to_string())
    ));
    body.push_str(&format!("<p>First seen: {}<br/>Last seen: {}</p>", first_seen.to_rfc3339(), last_seen.to_rfc3339()));

    if let Some(row) = event_row {
        let occurred_at: DateTime<Utc> = row
            .try_get("occurred_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let message: Option<String> = row
            .try_get("message")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let exception_type: String = row
            .try_get("exception_type")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let exception_message: String = row
            .try_get("exception_message")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let stacktrace: Option<Value> = row
            .try_get("stacktrace")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let context: Option<Value> = row
            .try_get("context")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        body.push_str(&format!("<h3>Dernier event</h3><p>{} — {}: {}</p>", occurred_at.to_rfc3339(), exception_type, html_escape(&exception_message)));
        if let Some(message) = message {
            body.push_str(&format!("<p>Message: {}</p>", html_escape(&message)));
        }
        if let Some(stacktrace) = stacktrace {
            body.push_str("<pre>");
            body.push_str(&html_escape(&stacktrace.to_string()));
            body.push_str("</pre>");
        }
        if let Some(context) = context {
            if let Some(breadcrumbs) = context.get("breadcrumbs") {
                body.push_str("<h4>Breadcrumbs</h4><pre>");
                body.push_str(&html_escape(&breadcrumbs.to_string()));
                body.push_str("</pre>");
            }
        }
    }

    body.push_str("</body></html>");
    Ok(body)
}

async fn get_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<EventDetailResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let event_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT id, issue_id, project_id, occurred_at, level, message, exception_type, exception_message, stacktrace, context, sdk\
        FROM events WHERE id = $1 AND project_id = $2",
    )
    .bind(event_id)
    .bind(&project_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "event introuvable".to_string())),
    };

    let issue_id: uuid::Uuid = row
        .try_get("issue_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let occurred_at: DateTime<Utc> = row
        .try_get("occurred_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let level: String = row
        .try_get("level")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let message: Option<String> = row
        .try_get("message")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let exception_type: String = row
        .try_get("exception_type")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let exception_message: String = row
        .try_get("exception_message")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let stacktrace: Option<Value> = row
        .try_get("stacktrace")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let context: Option<Value> = row
        .try_get("context")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let sdk: Option<Value> = row
        .try_get("sdk")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(EventDetailResponse {
        id: event_id.to_string(),
        issue_id: issue_id.to_string(),
        project_id,
        occurred_at: occurred_at.to_rfc3339(),
        level,
        message,
        exception_type,
        exception_message,
        stacktrace,
        context,
        sdk,
    }))
}

async fn list_transactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TransactionListQuery>,
) -> Result<Json<Vec<TransactionSummary>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let limit = query.limit.unwrap_or(50).min(200) as i64;
    let before = parse_optional_timestamp(query.before.as_deref())?;
    let name = query.name.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());

    let rows = if let Some(before_ts) = before {
        sqlx::query(
            "SELECT id, trace_id, span_id, name, status, duration_ms, occurred_at, tags, measurements\
            FROM transactions\
            WHERE project_id = $1 AND occurred_at < $2\
            AND ($3::text IS NULL OR name = $3)\
            ORDER BY occurred_at DESC\
            LIMIT $4",
        )
        .bind(&project_id)
        .bind(before_ts)
        .bind(&name)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            "SELECT id, trace_id, span_id, name, status, duration_ms, occurred_at, tags, measurements\
            FROM transactions\
            WHERE project_id = $1\
            AND ($2::text IS NULL OR name = $2)\
            ORDER BY occurred_at DESC\
            LIMIT $3",
        )
        .bind(&project_id)
        .bind(&name)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let trace_id: String = row
            .try_get("trace_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let span_id: String = row
            .try_get("span_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let duration_ms: f64 = row
            .try_get("duration_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let occurred_at: DateTime<Utc> = row
            .try_get("occurred_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let tags: Option<Value> = row
            .try_get("tags")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let measurements: Option<Value> = row
            .try_get("measurements")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(TransactionSummary {
            id: id.to_string(),
            trace_id,
            span_id,
            name,
            status,
            duration_ms,
            occurred_at: occurred_at.to_rfc3339(),
            tags,
            measurements,
        });
    }

    Ok(Json(items))
}

async fn list_transaction_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TransactionStatsQuery>,
) -> Result<Json<Vec<TransactionStat>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let window_minutes = query.window_minutes.unwrap_or(60).max(1);

    let rows = sqlx::query(
        "SELECT name, COUNT(*)::bigint AS count, AVG(duration_ms)::float8 AS avg_ms,\
        COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms), 0)::float8 AS p95_ms,\
        MAX(duration_ms)::float8 AS max_ms\
        FROM transactions\
        WHERE project_id = $1 AND occurred_at > now() - make_interval(mins => $2)\
        GROUP BY name\
        ORDER BY count DESC\
        LIMIT 50",
    )
    .bind(&project_id)
    .bind(window_minutes)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let avg_ms: f64 = row
            .try_get("avg_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let p95_ms: f64 = row
            .try_get("p95_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let max_ms: f64 = row
            .try_get("max_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(TransactionStat {
            name,
            count,
            avg_ms,
            p95_ms,
            max_ms,
        });
    }

    Ok(Json(items))
}

async fn get_trace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
) -> Result<Json<Vec<SpanSummary>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let rows = sqlx::query(
        "SELECT trace_id, span_id, parent_id, op, description, status, start_ts, duration_ms, tags\
        FROM spans\
        WHERE project_id = $1 AND trace_id = $2\
        ORDER BY start_ts ASC",
    )
    .bind(&project_id)
    .bind(&trace_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let trace_id: String = row
            .try_get("trace_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let span_id: String = row
            .try_get("span_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let parent_id: Option<String> = row
            .try_get("parent_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let op: Option<String> = row
            .try_get("op")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let description: Option<String> = row
            .try_get("description")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: Option<String> = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let start_ts: DateTime<Utc> = row
            .try_get("start_ts")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let duration_ms: f64 = row
            .try_get("duration_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let tags: Option<Value> = row
            .try_get("tags")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(SpanSummary {
            trace_id,
            span_id,
            parent_id,
            op,
            description,
            status,
            start_ts: start_ts.to_rfc3339(),
            duration_ms,
            tags,
        });
    }

    Ok(Json(items))
}

async fn get_trace_waterfall(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceWaterfallResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let rows = sqlx::query(
        "SELECT span_id, parent_id, op, description, status, start_ts, duration_ms, tags\
        FROM spans\
        WHERE project_id = $1 AND trace_id = $2\
        ORDER BY start_ts ASC",
    )
    .bind(&project_id)
    .bind(&trace_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut spans = Vec::with_capacity(rows.len());
    let mut parent_map: std::collections::HashMap<String, Option<String>> = std::collections::HashMap::new();
    let mut duration_map: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    let mut child_sum: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

    for row in &rows {
        let span_id: String = row
            .try_get("span_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let parent_id: Option<String> = row
            .try_get("parent_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let duration_ms: f64 = row
            .try_get("duration_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        if let Some(parent) = parent_id.as_ref() {
            let entry = child_sum.entry(parent.clone()).or_insert(0.0);
            *entry += duration_ms.max(0.0);
        }
        parent_map.insert(span_id.clone(), parent_id.clone());
        duration_map.insert(span_id, duration_ms);
    }

    for row in rows {
        let span_id: String = row
            .try_get("span_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let parent_id: Option<String> = row
            .try_get("parent_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let op: Option<String> = row
            .try_get("op")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let description: Option<String> = row
            .try_get("description")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: Option<String> = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let start_ts: DateTime<Utc> = row
            .try_get("start_ts")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let duration_ms: f64 = row
            .try_get("duration_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let tags: Option<Value> = row
            .try_get("tags")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let mut depth = 0;
        let mut current = parent_id.clone();
        let mut guard = 0;
        while let Some(parent) = current {
            if guard > 64 {
                break;
            }
            depth += 1;
            current = parent_map.get(&parent).cloned().unwrap_or(None);
            guard += 1;
        }

        let children_total = child_sum.get(&span_id).cloned().unwrap_or(0.0);
        let mut self_time_ms = duration_ms - children_total;
        if self_time_ms < 0.0 {
            self_time_ms = 0.0;
        }

        spans.push(TraceWaterfallSpan {
            span_id,
            parent_id,
            op,
            description,
            status,
            start_ts: start_ts.to_rfc3339(),
            duration_ms,
            self_time_ms,
            depth,
            tags,
        });
    }

    Ok(Json(TraceWaterfallResponse { trace_id, spans }))
}

async fn get_trace_correlations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceCorrelationResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let issue_rows = sqlx::query(
        "SELECT DISTINCT i.id, i.title, i.level, i.status, i.assignee, i.last_seen\
        FROM replay_links rl\
        JOIN issues i ON i.id = rl.issue_id\
        WHERE rl.project_id = $1 AND rl.trace_id = $2\
        ORDER BY i.last_seen DESC",
    )
    .bind(&project_id)
    .bind(&trace_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut issues = Vec::with_capacity(issue_rows.len());
    for row in issue_rows {
        let issue_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let title: String = row
            .try_get("title")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let level: String = row
            .try_get("level")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let assignee: Option<String> = row
            .try_get("assignee")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_seen: DateTime<Utc> = row
            .try_get("last_seen")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        issues.push(TraceIssueSummary {
            id: issue_id.to_string(),
            title,
            level,
            status,
            assignee,
            last_seen: last_seen.to_rfc3339(),
        });
    }

    let replay_rows = sqlx::query(
        "SELECT r.id, r.project_id, r.session_id, r.started_at, r.duration_ms, r.url, r.user_id, r.user_email, r.created_at\
        FROM replay_links rl\
        JOIN replays r ON r.id = rl.replay_id\
        WHERE rl.project_id = $1 AND rl.trace_id = $2\
        ORDER BY r.created_at DESC",
    )
    .bind(&project_id)
    .bind(&trace_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut replays = Vec::with_capacity(replay_rows.len());
    for row in replay_rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let session_id: String = row
            .try_get("session_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let started_at: DateTime<Utc> = row
            .try_get("started_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let duration_ms: f64 = row
            .try_get("duration_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let url: Option<String> = row
            .try_get("url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_id: Option<String> = row
            .try_get("user_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_email: Option<String> = row
            .try_get("user_email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        replays.push(ReplaySummary {
            id: id.to_string(),
            project_id: project_id.clone(),
            session_id,
            started_at: started_at.to_rfc3339(),
            duration_ms,
            url,
            user_id,
            user_email,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(TraceCorrelationResponse {
        trace_id,
        issues,
        replays,
    }))
}

async fn get_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
) -> Result<Json<ProfileSummary>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let row = sqlx::query(
        "SELECT id, trace_id, created_at, profile\
        FROM profiles\
        WHERE project_id = $1 AND trace_id = $2\
        ORDER BY created_at DESC\
        LIMIT 1",
    )
    .bind(&project_id)
    .bind(&trace_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "profile introuvable".to_string())),
    };

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let trace_id: String = row
        .try_get("trace_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let profile: Value = row
        .try_get("profile")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(ProfileSummary {
        id: id.to_string(),
        trace_id,
        created_at: created_at.to_rfc3339(),
        profile,
    }))
}

async fn list_profiles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
    Query(query): Query<ProfileListQuery>,
) -> Result<Json<Vec<ProfileListItem>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let limit = query.limit.unwrap_or(20).min(100) as i64;
    let rows = sqlx::query(
        "SELECT id, trace_id, created_at, profile\
        FROM profiles\
        WHERE project_id = $1 AND trace_id = $2\
        ORDER BY created_at DESC\
        LIMIT $3",
    )
    .bind(&project_id)
    .bind(&trace_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let trace_id: String = row
            .try_get("trace_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let profile: Value = row
            .try_get("profile")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let size_bytes = serde_json::to_vec(&profile)
            .map(|value| value.len())
            .unwrap_or(0);
        let sample_count = profile.get("samples").and_then(|value| value.as_array()).map(|value| value.len() as i64);

        items.push(ProfileListItem {
            id: id.to_string(),
            trace_id,
            created_at: created_at.to_rfc3339(),
            size_bytes,
            sample_count,
        });
    }

    Ok(Json(items))
}

async fn get_profile_hot_paths(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
    Query(query): Query<ProfileHotPathsQuery>,
) -> Result<Json<ProfileHotPathsResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;
    let limit = query.limit.unwrap_or(20).min(200) as usize;

    let row = sqlx::query(
        "SELECT profile\
        FROM profiles\
        WHERE project_id = $1 AND trace_id = $2\
        ORDER BY created_at DESC\
        LIMIT 1",
    )
    .bind(&project_id)
    .bind(&trace_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "profile introuvable".to_string())),
    };

    let profile: Value = row
        .try_get("profile")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items: Vec<ProfileHotPath> = extract_profile_weights(&profile)
        .into_iter()
        .map(|(frame, weight)| ProfileHotPath { frame, weight })
        .collect();

    items.sort_by(|a, b| b.weight.partial_cmp(&a.weight).unwrap_or(std::cmp::Ordering::Equal));
    items.truncate(limit);

    Ok(Json(ProfileHotPathsResponse { trace_id, items }))
}

async fn diff_profiles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
    Query(query): Query<ProfileDiffQuery>,
) -> Result<Json<ProfileDiffResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;
    let limit = query.limit.unwrap_or(20).min(200) as usize;

    let (base_id, compare_id, base_profile, compare_profile) = if let (Some(base_id), Some(compare_id)) = (query.base_id.as_deref(), query.compare_id.as_deref()) {
        let base_uuid = Uuid::parse_str(base_id)
            .map_err(|_| (StatusCode::BAD_REQUEST, "base_id invalide".to_string()))?;
        let compare_uuid = Uuid::parse_str(compare_id)
            .map_err(|_| (StatusCode::BAD_REQUEST, "compare_id invalide".to_string()))?;

        let base_row = sqlx::query(
            "SELECT id, profile FROM profiles WHERE project_id = $1 AND id = $2",
        )
        .bind(&project_id)
        .bind(base_uuid)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let compare_row = sqlx::query(
            "SELECT id, profile FROM profiles WHERE project_id = $1 AND id = $2",
        )
        .bind(&project_id)
        .bind(compare_uuid)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let base_row = base_row.ok_or_else(|| (StatusCode::NOT_FOUND, "profile base introuvable".to_string()))?;
        let compare_row = compare_row.ok_or_else(|| (StatusCode::NOT_FOUND, "profile compare introuvable".to_string()))?;

        let base_profile: Value = base_row
            .try_get("profile")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let compare_profile: Value = compare_row
            .try_get("profile")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        (base_id.to_string(), compare_id.to_string(), base_profile, compare_profile)
    } else {
        let rows = sqlx::query(
            "SELECT id, profile\
            FROM profiles\
            WHERE project_id = $1 AND trace_id = $2\
            ORDER BY created_at DESC\
            LIMIT 2",
        )
        .bind(&project_id)
        .bind(&trace_id)
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        if rows.len() < 2 {
            return Err((StatusCode::NOT_FOUND, "profiles insuffisants".to_string()));
        }

        let compare_id: Uuid = rows[0]
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let base_id: Uuid = rows[1]
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let compare_profile: Value = rows[0]
            .try_get("profile")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let base_profile: Value = rows[1]
            .try_get("profile")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        (base_id.to_string(), compare_id.to_string(), base_profile, compare_profile)
    };

    let base_weights = extract_profile_weights(&base_profile);
    let compare_weights = extract_profile_weights(&compare_profile);

    let mut items = Vec::new();
    for (frame, base_weight) in base_weights.iter() {
        let compare_weight = compare_weights.get(frame).cloned().unwrap_or(0.0);
        let delta = compare_weight - base_weight;
        items.push(ProfileDiffEntry {
            frame: frame.clone(),
            base_weight: *base_weight,
            compare_weight,
            delta,
        });
    }
    for (frame, compare_weight) in compare_weights.iter() {
        if base_weights.contains_key(frame) {
            continue;
        }
        items.push(ProfileDiffEntry {
            frame: frame.clone(),
            base_weight: 0.0,
            compare_weight: *compare_weight,
            delta: *compare_weight,
        });
    }

    items.sort_by(|a, b| b.delta.abs().partial_cmp(&a.delta.abs()).unwrap_or(std::cmp::Ordering::Equal));
    items.truncate(limit);

    Ok(Json(ProfileDiffResponse {
        trace_id,
        base_id,
        compare_id,
        items,
    }))
}

fn extract_profile_weights(profile: &Value) -> std::collections::HashMap<String, f64> {
    let mut weights = std::collections::HashMap::new();

    let frames = profile.get("frames").and_then(|value| value.as_array());
    let stacks = profile.get("stacks").and_then(|value| value.as_array());
    let samples = profile.get("samples").and_then(|value| value.as_array());

    let (frames, stacks, samples) = match (frames, stacks, samples) {
        (Some(frames), Some(stacks), Some(samples)) => (frames, stacks, samples),
        _ => return weights,
    };

    let resolve_frame_name = |frame_value: &Value| -> String {
        if let Some(obj) = frame_value.as_object() {
            if let Some(value) = obj.get("name").and_then(|v| v.as_str()) {
                return value.to_string();
            }
            if let Some(value) = obj.get("function").and_then(|v| v.as_str()) {
                return value.to_string();
            }
            if let Some(value) = obj.get("label").and_then(|v| v.as_str()) {
                return value.to_string();
            }
            if let Some(value) = obj.get("file").and_then(|v| v.as_str()) {
                return value.to_string();
            }
        }
        frame_value.as_str().unwrap_or("unknown").to_string()
    };

    for sample in samples {
        let (stack_id, weight) = match sample {
            Value::Object(map) => {
                let stack_id = map
                    .get("stack_id")
                    .or_else(|| map.get("stack"))
                    .and_then(|v| v.as_u64());
                let weight = map
                    .get("weight")
                    .or_else(|| map.get("value"))
                    .or_else(|| map.get("duration"))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(1.0);
                match stack_id {
                    Some(value) => (value as usize, weight),
                    None => continue,
                }
            }
            Value::Array(items) => {
                let stack_id = items.get(0).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let weight = items.get(1).and_then(|v| v.as_f64()).unwrap_or(1.0);
                (stack_id, weight)
            }
            _ => continue,
        };

        let stack_frames: Vec<usize> = match stacks.get(stack_id) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|value| value.as_u64().map(|v| v as usize))
                .collect(),
            Some(Value::Object(obj)) => obj
                .get("frames")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|value| value.as_u64().map(|v| v as usize))
                        .collect()
                })
                .unwrap_or_default(),
            _ => continue,
        };

        for frame_idx in stack_frames {
            let frame = frames.get(frame_idx).map(resolve_frame_name).unwrap_or_else(|| "unknown".to_string());
            *weights.entry(frame).or_insert(0.0) += weight;
        }
    }

    weights
}

async fn get_service_map(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ServiceMapQuery>,
) -> Result<Json<Vec<ServiceMapEdge>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let window_minutes = query.window_minutes.unwrap_or(60).max(1);

    let rows = sqlx::query(
        "SELECT COALESCE(parent.op, 'root') AS source, COALESCE(child.op, 'unknown') AS target, COUNT(*)::bigint AS count\
        FROM spans child\
        LEFT JOIN spans parent\
        ON parent.project_id = child.project_id AND parent.span_id = child.parent_id\
        WHERE child.project_id = $1 AND child.start_ts > now() - make_interval(mins => $2)\
        GROUP BY source, target\
        ORDER BY count DESC\
        LIMIT 200",
    )
    .bind(&project_id)
    .bind(window_minutes)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let source: String = row
            .try_get("source")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let target: String = row
            .try_get("target")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        items.push(ServiceMapEdge { source, target, count });
    }

    Ok(Json(items))
}

async fn get_trace_breakdown(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TraceBreakdownQuery>,
) -> Result<Json<Vec<TraceBreakdownRow>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let window_minutes = query.window_minutes.unwrap_or(60).max(1);

    let rows = sqlx::query(
        "SELECT COALESCE(op, 'unknown') AS op, COUNT(*)::bigint AS count, AVG(duration_ms)::float8 AS avg_ms,\
        COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms), 0)::float8 AS p95_ms\
        FROM spans\
        WHERE project_id = $1 AND start_ts > now() - make_interval(mins => $2)\
        GROUP BY op\
        ORDER BY count DESC\
        LIMIT 100",
    )
    .bind(&project_id)
    .bind(window_minutes)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let op: String = row
            .try_get("op")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let avg_ms: f64 = row
            .try_get("avg_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let p95_ms: f64 = row
            .try_get("p95_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        items.push(TraceBreakdownRow { op, count, avg_ms, p95_ms });
    }

    Ok(Json(items))
}

async fn get_top_regressions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TopRegressionsQuery>,
) -> Result<Json<Vec<TopRegressionSummary>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let window_minutes = query.window_minutes.unwrap_or(1440).max(1);
    let limit = query.limit.unwrap_or(50).min(200) as i64;

    let rows = sqlx::query(
        "SELECT i.id, i.title, i.level, i.status, i.assignee, i.regressed_at, i.last_seen, i.last_release,\
        COALESCE(e.count_24h, 0) AS events_24h\
        FROM issues i\
        LEFT JOIN (\
            SELECT issue_id, COUNT(*)::bigint AS count_24h\
            FROM events\
            WHERE occurred_at > now() - make_interval(mins => $2)\
            GROUP BY issue_id\
        ) e ON e.issue_id = i.id\
        WHERE i.project_id = $1\
        AND i.regressed_at IS NOT NULL\
        ORDER BY e.count_24h DESC NULLS LAST, i.regressed_at DESC\
        LIMIT $3",
    )
    .bind(&project_id)
    .bind(window_minutes)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let title: String = row
            .try_get("title")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let level: String = row
            .try_get("level")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let assignee: Option<String> = row
            .try_get("assignee")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let regressed_at: DateTime<Utc> = row
            .try_get("regressed_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_seen: DateTime<Utc> = row
            .try_get("last_seen")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_release: Option<String> = row
            .try_get("last_release")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let events_24h: i64 = row
            .try_get("events_24h")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(TopRegressionSummary {
            id: id.to_string(),
            title,
            level,
            status,
            assignee,
            regressed_at: regressed_at.to_rfc3339(),
            last_seen: last_seen.to_rfc3339(),
            last_release,
            events_24h,
        });
    }

    Ok(Json(items))
}

async fn list_replays(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TransactionListQuery>,
) -> Result<Json<Vec<ReplaySummary>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let limit = query.limit.unwrap_or(50).min(200) as i64;
    let before = parse_optional_timestamp(query.before.as_deref())?;
    let session_filter = query.name.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());

    let rows = if let Some(before_ts) = before {
        sqlx::query(
            "SELECT id, project_id, session_id, started_at, duration_ms, url, user_id, user_email, created_at\
            FROM replays\
            WHERE project_id = $1 AND created_at < $2\
            AND ($3::text IS NULL OR session_id = $3)\
            ORDER BY created_at DESC\
            LIMIT $4",
        )
        .bind(&project_id)
        .bind(before_ts)
        .bind(&session_filter)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            "SELECT id, project_id, session_id, started_at, duration_ms, url, user_id, user_email, created_at\
            FROM replays\
            WHERE project_id = $1\
            AND ($2::text IS NULL OR session_id = $2)\
            ORDER BY created_at DESC\
            LIMIT $3",
        )
        .bind(&project_id)
        .bind(&session_filter)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let session_id: String = row
            .try_get("session_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let started_at: DateTime<Utc> = row
            .try_get("started_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let duration_ms: f64 = row
            .try_get("duration_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let url: Option<String> = row
            .try_get("url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_id: Option<String> = row
            .try_get("user_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_email: Option<String> = row
            .try_get("user_email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(ReplaySummary {
            id: id.to_string(),
            project_id: project_id.clone(),
            session_id,
            started_at: started_at.to_rfc3339(),
            duration_ms,
            url,
            user_id,
            user_email,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn get_replay(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ReplayDetail>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let replay_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT id, project_id, session_id, started_at, duration_ms, url, user_id, user_email, breadcrumbs, events, payload, created_at\
        FROM replays\
        WHERE id = $1 AND project_id = $2",
    )
    .bind(replay_id)
    .bind(&project_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "replay introuvable".to_string())),
    };

    let session_id: String = row
        .try_get("session_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let started_at: DateTime<Utc> = row
        .try_get("started_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let duration_ms: f64 = row
        .try_get("duration_ms")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let url: Option<String> = row
        .try_get("url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let user_id: Option<String> = row
        .try_get("user_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let user_email: Option<String> = row
        .try_get("user_email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let breadcrumbs: Option<Value> = row
        .try_get("breadcrumbs")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let events: Option<Value> = row
        .try_get("events")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let payload: Value = row
        .try_get("payload")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(ReplayDetail {
        id: replay_id.to_string(),
        project_id,
        session_id,
        started_at: started_at.to_rfc3339(),
        duration_ms,
        url,
        user_id,
        user_email,
        breadcrumbs,
        events,
        payload,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn get_replay_timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ReplayTimelineResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let replay_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT breadcrumbs, events\
        FROM replays\
        WHERE id = $1 AND project_id = $2",
    )
    .bind(replay_id)
    .bind(&project_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "replay introuvable".to_string())),
    };

    let breadcrumbs: Option<Value> = row
        .try_get("breadcrumbs")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let events: Option<Value> = row
        .try_get("events")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items: Vec<ReplayTimelineItem> = Vec::new();
    if let Some(Value::Array(values)) = breadcrumbs {
        for value in values {
            let timestamp = value.get("timestamp").and_then(|v| v.as_str()).unwrap_or("-").to_string();
            let message = value.get("message").and_then(|v| v.as_str()).map(|v| v.to_string());
            let kind = value.get("category").and_then(|v| v.as_str()).unwrap_or("breadcrumb");
            items.push(ReplayTimelineItem {
                timestamp,
                kind: kind.to_string(),
                message,
                data: value,
            });
        }
    }
    if let Some(Value::Array(values)) = events {
        for value in values {
            let timestamp = value.get("timestamp").and_then(|v| v.as_str()).unwrap_or("-").to_string();
            let message = value.get("message").and_then(|v| v.as_str()).map(|v| v.to_string());
            let kind = value.get("type").and_then(|v| v.as_str()).unwrap_or("event");
            items.push(ReplayTimelineItem {
                timestamp,
                kind: kind.to_string(),
                message,
                data: value,
            });
        }
    }

    items.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    Ok(Json(ReplayTimelineResponse { id, items }))
}

async fn get_replay_scrubbed(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ReplayDetail>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let replay_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT id, project_id, session_id, started_at, duration_ms, url, user_id, user_email, breadcrumbs, events, payload, created_at\
        FROM replays\
        WHERE id = $1 AND project_id = $2",
    )
    .bind(replay_id)
    .bind(&project_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "replay introuvable".to_string())),
    };

    let session_id: String = row
        .try_get("session_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let started_at: DateTime<Utc> = row
        .try_get("started_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let duration_ms: f64 = row
        .try_get("duration_ms")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let url: Option<String> = row
        .try_get("url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let user_id: Option<String> = row
        .try_get("user_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let user_email: Option<String> = row
        .try_get("user_email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let breadcrumbs: Option<Value> = row
        .try_get("breadcrumbs")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let events: Option<Value> = row
        .try_get("events")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let payload: Value = row
        .try_get("payload")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let policy = fetch_pii_policy_settings(&state.db, &project_id).await?;
    let scrubbed = scrub_pii_with_policy(payload, &policy);
    let scrubbed_breadcrumbs = breadcrumbs.map(|value| scrub_pii_with_policy(value, &policy));
    let scrubbed_events = events.map(|value| scrub_pii_with_policy(value, &policy));

    Ok(Json(ReplayDetail {
        id: replay_id.to_string(),
        project_id,
        session_id,
        started_at: started_at.to_rfc3339(),
        duration_ms,
        url,
        user_id,
        user_email,
        breadcrumbs: scrubbed_breadcrumbs,
        events: scrubbed_events,
        payload: scrubbed,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn link_replay_issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<ReplayLinkBody>,
) -> Result<Json<ReplayLinkSummary>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let replay_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let issue_id = match payload.issue_id.as_deref() {
        Some(value) if !value.trim().is_empty() => Some(
            Uuid::parse_str(value)
                .map_err(|_| (StatusCode::BAD_REQUEST, "issue_id invalide".to_string()))?
        ),
        _ => None,
    };
    let trace_id = payload.trace_id.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    if issue_id.is_none() && trace_id.is_none() {
        return Err((StatusCode::BAD_REQUEST, "issue_id ou trace_id requis".to_string()));
    }

    sqlx::query(
        "INSERT INTO replay_links (project_id, replay_id, issue_id, trace_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(&project_id)
    .bind(replay_id)
    .bind(issue_id)
    .bind(trace_id.as_deref())
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let created_at = Utc::now();

    Ok(Json(ReplayLinkSummary {
        replay_id: replay_id.to_string(),
        issue_id: issue_id.map(|value| value.to_string()),
        trace_id,
        created_at: created_at.to_rfc3339(),
    }))
}

#[derive(Clone, Copy)]
struct PiiPolicySettings {
    scrub_emails: bool,
    scrub_ips: bool,
    scrub_secrets: bool,
}

fn scrub_pii_with_policy(value: Value, policy: &PiiPolicySettings) -> Value {
    match value {
        Value::String(text) => Value::String(mask_pii_string(&text, policy)),
        Value::Array(items) => Value::Array(items.into_iter().map(|item| scrub_pii_with_policy(item, policy)).collect()),
        Value::Object(map) => {
            let mut cleaned = serde_json::Map::new();
            for (key, val) in map {
                if policy.scrub_secrets && (key.to_lowercase().contains("password") || key.to_lowercase().contains("token") || key.to_lowercase().contains("secret")) {
                    cleaned.insert(key, Value::String("[redacted]".to_string()));
                } else {
                    cleaned.insert(key, scrub_pii_with_policy(val, policy));
                }
            }
            Value::Object(cleaned)
        }
        other => other,
    }
}

fn mask_pii_string(input: &str, policy: &PiiPolicySettings) -> String {
    let mut out = input.to_string();
    if policy.scrub_emails {
        let email_re = Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap();
        out = email_re.replace_all(&out, "[email]").to_string();
    }
    if policy.scrub_ips {
        let ip_re = Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").unwrap();
        out = ip_re.replace_all(&out, "[ip]").to_string();
    }
    out
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

fn encrypt_secret(plain: &str) -> Result<String, String> {
    let key = load_secrets_key()?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plain.as_bytes())
        .map_err(|_| "chiffrement impossible".to_string())?;
    Ok(format!(
        "v1:{}:{}",
        BASE64.encode(nonce.as_slice()),
        BASE64.encode(&ciphertext)
    ))
}

#[allow(dead_code)]
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

async fn list_replay_links(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<ReplayLinkSummary>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let replay_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let rows = sqlx::query(
        "SELECT rl.replay_id, rl.issue_id, rl.trace_id, rl.created_at\
        FROM replay_links rl\
        JOIN replays r ON r.id = rl.replay_id\
        WHERE rl.replay_id = $1 AND r.project_id = $2\
        ORDER BY rl.created_at DESC",
    )
    .bind(replay_id)
    .bind(&project_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let replay_id: Uuid = row
            .try_get("replay_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let issue_id: Option<Uuid> = row
            .try_get("issue_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let trace_id: Option<String> = row
            .try_get("trace_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(ReplayLinkSummary {
            replay_id: replay_id.to_string(),
            issue_id: issue_id.map(|value| value.to_string()),
            trace_id,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn list_issue_replays(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<ReplaySummary>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let issue_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let rows = sqlx::query(
        "SELECT r.id, r.project_id, r.session_id, r.started_at, r.duration_ms, r.url, r.user_id, r.user_email, r.created_at\
        FROM replay_links rl\
        JOIN replays r ON r.id = rl.replay_id\
        WHERE rl.issue_id = $1 AND r.project_id = $2\
        ORDER BY r.created_at DESC\
        LIMIT 200",
    )
    .bind(issue_id)
    .bind(&project_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let session_id: String = row
            .try_get("session_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let started_at: DateTime<Utc> = row
            .try_get("started_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let duration_ms: f64 = row
            .try_get("duration_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let url: Option<String> = row
            .try_get("url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_id: Option<String> = row
            .try_get("user_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_email: Option<String> = row
            .try_get("user_email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(ReplaySummary {
            id: id.to_string(),
            project_id: project_id.clone(),
            session_id,
            started_at: started_at.to_rfc3339(),
            duration_ms,
            url,
            user_id,
            user_email,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn list_trace_replays(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
) -> Result<Json<Vec<ReplaySummary>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let rows = sqlx::query(
        "SELECT r.id, r.project_id, r.session_id, r.started_at, r.duration_ms, r.url, r.user_id, r.user_email, r.created_at\
        FROM replay_links rl\
        JOIN replays r ON r.id = rl.replay_id\
        WHERE rl.trace_id = $1 AND r.project_id = $2\
        ORDER BY r.created_at DESC\
        LIMIT 200",
    )
    .bind(&trace_id)
    .bind(&project_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let session_id: String = row
            .try_get("session_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let started_at: DateTime<Utc> = row
            .try_get("started_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let duration_ms: f64 = row
            .try_get("duration_ms")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let url: Option<String> = row
            .try_get("url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_id: Option<String> = row
            .try_get("user_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_email: Option<String> = row
            .try_get("user_email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(ReplaySummary {
            id: id.to_string(),
            project_id: project_id.clone(),
            session_id,
            started_at: started_at.to_rfc3339(),
            duration_ms,
            url,
            user_id,
            user_email,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn list_discover_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DiscoverEventsQuery>,
) -> Result<Json<DiscoverEventsResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let limit = query.limit.unwrap_or(50).min(200) as i64;
    let before = parse_optional_timestamp(query.before.as_deref())?;
    let cursor = parse_discover_cursor(query.cursor.as_deref())?;
    let saved_query = resolve_saved_query(&state.db, &project_id, query.saved_query_id.as_deref(), query.q.as_deref()).await?;
    let level = query.level.as_deref().map(|v| v.trim().to_lowercase()).filter(|v| !v.is_empty());
    let release = query.release.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let exception_type = query.exception_type.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let user = query.user.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let issue_id = query.issue_id.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let pattern = saved_query.as_deref().map(|s| format!("%{}%", s.trim())).filter(|s| !s.is_empty());

    let rows = if let Some((cursor_ts, cursor_id)) = cursor {
        sqlx::query(
            "SELECT e.id, e.issue_id, i.title, e.occurred_at, e.level, e.message, e.exception_type, e.exception_message, e.release, e.user_id, e.user_email\
            FROM events e\
            JOIN issues i ON i.id = e.issue_id\
            WHERE e.project_id = $1 AND (e.occurred_at, e.id) < ($2, $3)\
            AND ($4::text IS NULL OR e.level = $4)\
            AND ($5::text IS NULL OR e.release = $5)\
            AND ($6::text IS NULL OR e.exception_type = $6)\
            AND ($7::text IS NULL OR e.user_id = $7 OR e.user_email = $7)\
            AND ($8::text IS NULL OR e.issue_id::text = $8)\
            AND ($9::text IS NULL OR i.title ILIKE $9 OR e.message ILIKE $9 OR e.exception_message ILIKE $9)\
            ORDER BY e.occurred_at DESC, e.id DESC\
            LIMIT $10",
        )
        .bind(&project_id)
        .bind(cursor_ts)
        .bind(cursor_id)
        .bind(&level)
        .bind(&release)
        .bind(&exception_type)
        .bind(&user)
        .bind(&issue_id)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else if let Some(before_ts) = before {
        sqlx::query(
            "SELECT e.id, e.issue_id, i.title, e.occurred_at, e.level, e.message, e.exception_type, e.exception_message, e.release, e.user_id, e.user_email\
            FROM events e\
            JOIN issues i ON i.id = e.issue_id\
            WHERE e.project_id = $1 AND e.occurred_at < $2\
            AND ($3::text IS NULL OR e.level = $3)\
            AND ($4::text IS NULL OR e.release = $4)\
            AND ($5::text IS NULL OR e.exception_type = $5)\
            AND ($6::text IS NULL OR e.user_id = $6 OR e.user_email = $6)\
            AND ($7::text IS NULL OR e.issue_id::text = $7)\
            AND ($8::text IS NULL OR i.title ILIKE $8 OR e.message ILIKE $8 OR e.exception_message ILIKE $8)\
            ORDER BY e.occurred_at DESC, e.id DESC\
            LIMIT $9",
        )
        .bind(&project_id)
        .bind(before_ts)
        .bind(&level)
        .bind(&release)
        .bind(&exception_type)
        .bind(&user)
        .bind(&issue_id)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            "SELECT e.id, e.issue_id, i.title, e.occurred_at, e.level, e.message, e.exception_type, e.exception_message, e.release, e.user_id, e.user_email\
            FROM events e\
            JOIN issues i ON i.id = e.issue_id\
            WHERE e.project_id = $1\
            AND ($2::text IS NULL OR e.level = $2)\
            AND ($3::text IS NULL OR e.release = $3)\
            AND ($4::text IS NULL OR e.exception_type = $4)\
            AND ($5::text IS NULL OR e.user_id = $5 OR e.user_email = $5)\
            AND ($6::text IS NULL OR e.issue_id::text = $6)\
            AND ($7::text IS NULL OR i.title ILIKE $7 OR e.message ILIKE $7 OR e.exception_message ILIKE $7)\
            ORDER BY e.occurred_at DESC, e.id DESC\
            LIMIT $8",
        )
        .bind(&project_id)
        .bind(&level)
        .bind(&release)
        .bind(&exception_type)
        .bind(&user)
        .bind(&issue_id)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let issue_id: Uuid = row
            .try_get("issue_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let issue_title: String = row
            .try_get("title")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let occurred_at: DateTime<Utc> = row
            .try_get("occurred_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let level: String = row
            .try_get("level")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let message: Option<String> = row
            .try_get("message")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let exception_type: String = row
            .try_get("exception_type")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let exception_message: String = row
            .try_get("exception_message")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let release: Option<String> = row
            .try_get("release")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_id: Option<String> = row
            .try_get("user_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_email: Option<String> = row
            .try_get("user_email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(DiscoverEventSummary {
            id: id.to_string(),
            issue_id: issue_id.to_string(),
            issue_title,
            occurred_at: occurred_at.to_rfc3339(),
            level,
            message,
            exception_type,
            exception_message,
            release,
            user_id,
            user_email,
        });
    }

    let next_before = items.last().map(|item| item.occurred_at.clone());
    let next_cursor = items.last().map(|item| format_discover_cursor(&item.occurred_at, &item.id));
    Ok(Json(DiscoverEventsResponse { items, next_before, next_cursor }))
}

async fn list_discover_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DiscoverStatsQuery>,
) -> Result<Json<Vec<DiscoverStatRow>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let window_minutes = query.window_minutes.unwrap_or(60).max(1);
    let group_by = query.group_by.unwrap_or_else(|| "level".to_string());
    let saved_query = resolve_saved_query(&state.db, &project_id, query.saved_query_id.as_deref(), query.q.as_deref()).await?;
    let level = query.level.as_deref().map(|v| v.trim().to_lowercase()).filter(|v| !v.is_empty());
    let release = query.release.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let exception_type = query.exception_type.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let user = query.user.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let issue_id = query.issue_id.as_deref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let pattern = saved_query.as_deref().map(|s| format!("%{}%", s.trim())).filter(|s| !s.is_empty());

    let key_expr = match group_by.as_str() {
        "level" => "COALESCE(e.level, '-')",
        "release" => "COALESCE(e.release, '-')",
        "exception_type" => "COALESCE(e.exception_type, '-')",
        _ => return Err((StatusCode::BAD_REQUEST, "group_by invalide".to_string())),
    };

    let sql = format!(
        "SELECT {key_expr} AS key, COUNT(*)::bigint AS count \
        FROM events e \
        JOIN issues i ON i.id = e.issue_id \
        WHERE e.project_id = $1 AND e.occurred_at > now() - make_interval(mins => $2) \
        AND ($3::text IS NULL OR e.level = $3) \
        AND ($4::text IS NULL OR e.release = $4) \
        AND ($5::text IS NULL OR e.exception_type = $5) \
        AND ($6::text IS NULL OR e.user_id = $6 OR e.user_email = $6) \
        AND ($7::text IS NULL OR e.issue_id::text = $7) \
        AND ($8::text IS NULL OR i.title ILIKE $8 OR e.message ILIKE $8 OR e.exception_message ILIKE $8) \
        GROUP BY key ORDER BY count DESC LIMIT 50"
    );

    let rows = sqlx::query(&sql)
        .bind(&project_id)
        .bind(window_minutes)
        .bind(&level)
        .bind(&release)
        .bind(&exception_type)
        .bind(&user)
        .bind(&issue_id)
        .bind(&pattern)
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let key: String = row
            .try_get("key")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        items.push(DiscoverStatRow { key, count });
    }

    Ok(Json(items))
}

async fn get_issue_insights(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<IssueInsights>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let issue_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT ii.issue_id, ii.summary, ii.culprit, ii.last_release, ii.regressed_at, ii.causal_chain, ii.regression_map, ii.confidence, ii.published, ii.updated_at\
        FROM issue_insights ii\
        JOIN issues i ON i.id = ii.issue_id\
        WHERE ii.issue_id = $1 AND i.project_id = $2",
    )
    .bind(issue_id)
    .bind(&project_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "insight introuvable".to_string())),
    };

    let summary: String = row
        .try_get("summary")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let culprit: Option<String> = row
        .try_get("culprit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_release: Option<String> = row
        .try_get("last_release")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let regressed_at: Option<DateTime<Utc>> = row
        .try_get("regressed_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let causal_chain: Option<Value> = row
        .try_get("causal_chain")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let regression_map: Option<Value> = row
        .try_get("regression_map")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let confidence: Option<f64> = row
        .try_get("confidence")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let published: bool = row
        .try_get("published")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let updated_at: DateTime<Utc> = row
        .try_get("updated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(IssueInsights {
        issue_id: issue_id.to_string(),
        summary,
        culprit,
        last_release,
        regressed_at: regressed_at.map(|value| value.to_rfc3339()),
        causal_chain,
        regression_map,
        confidence,
        published,
        updated_at: updated_at.to_rfc3339(),
    }))
}

async fn list_assignment_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<AssignmentRuleSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT id, project_id, name, pattern, assignee, enabled, created_at\
        FROM assignment_rules\
        WHERE project_id = $1\
        ORDER BY created_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let rule_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let pattern: String = row
            .try_get("pattern")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let assignee: String = row
            .try_get("assignee")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let enabled: bool = row
            .try_get("enabled")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(AssignmentRuleSummary {
            id: rule_id.to_string(),
            project_id,
            name,
            pattern,
            assignee,
            enabled,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn list_ownership_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<OwnershipRuleSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT id, project_id, name, pattern, owner, enabled, created_at\
        FROM ownership_rules\
        WHERE project_id = $1\
        ORDER BY created_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let rule_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let pattern: String = row
            .try_get("pattern")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let owner: String = row
            .try_get("owner")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let enabled: bool = row
            .try_get("enabled")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(OwnershipRuleSummary {
            id: rule_id.to_string(),
            project_id,
            name,
            pattern,
            owner,
            enabled,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn create_ownership_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateOwnershipRuleBody>,
) -> Result<Json<OwnershipRuleSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let name = payload.name.trim();
    let pattern = payload.pattern.trim();
    let owner = payload.owner.trim();
    if name.is_empty() || pattern.is_empty() || owner.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "payload invalide".to_string()));
    }

    let enabled = payload.enabled.unwrap_or(true);

    let row = sqlx::query(
        "INSERT INTO ownership_rules (project_id, name, pattern, owner, enabled)\
        VALUES ($1, $2, $3, $4, $5)\
        RETURNING id, project_id, name, pattern, owner, enabled, created_at",
    )
    .bind(&id)
    .bind(name)
    .bind(pattern)
    .bind(owner)
    .bind(enabled)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let rule_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let enabled: bool = row
        .try_get("enabled")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "ownership_rule.create",
        "ownership_rule",
        Some(&rule_id.to_string()),
        Some(json!({ "project_id": id.clone(), "name": name, "owner": owner })),
        Some(&headers),
    )
    .await?;

    Ok(Json(OwnershipRuleSummary {
        id: rule_id.to_string(),
        project_id,
        name: name.to_string(),
        pattern: pattern.to_string(),
        owner: owner.to_string(),
        enabled,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn create_assignment_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateAssignmentRuleBody>,
) -> Result<Json<AssignmentRuleSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let name = payload.name.trim();
    let pattern = payload.pattern.trim();
    let assignee = payload.assignee.trim();
    if name.is_empty() || pattern.is_empty() || assignee.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "payload invalide".to_string()));
    }

    let enabled = payload.enabled.unwrap_or(true);

    let row = sqlx::query(
        "INSERT INTO assignment_rules (project_id, name, pattern, assignee, enabled)\
        VALUES ($1, $2, $3, $4, $5)\
        RETURNING id, project_id, name, pattern, assignee, enabled, created_at",
    )
    .bind(&id)
    .bind(name)
    .bind(pattern)
    .bind(assignee)
    .bind(enabled)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let rule_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let enabled: bool = row
        .try_get("enabled")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "assignment_rule.create",
        "assignment_rule",
        Some(&rule_id.to_string()),
        Some(json!({ "project_id": id.clone(), "name": name })),
        Some(&headers),
    )
    .await?;

    Ok(Json(AssignmentRuleSummary {
        id: rule_id.to_string(),
        project_id,
        name: name.to_string(),
        pattern: pattern.to_string(),
        assignee: assignee.to_string(),
        enabled,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn get_sso_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SsoConfigSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT id, org_id, provider, saml_metadata, oidc_client_id, oidc_issuer_url, enabled, enforce_domain, created_at\
        FROM sso_configs WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "sso introuvable".to_string())),
    };

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let org_id: Uuid = row
        .try_get("org_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let provider: String = row
        .try_get("provider")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let saml_metadata: Option<String> = row
        .try_get("saml_metadata")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let oidc_client_id: Option<String> = row
        .try_get("oidc_client_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let oidc_issuer_url: Option<String> = row
        .try_get("oidc_issuer_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let enabled: bool = row
        .try_get("enabled")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let enforce_domain: bool = row
        .try_get("enforce_domain")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(SsoConfigSummary {
        id: id.to_string(),
        org_id: org_id.to_string(),
        provider,
        saml_metadata,
        oidc_client_id,
        oidc_issuer_url,
        enabled,
        enforce_domain,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn upsert_sso_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpsertSsoConfigBody>,
) -> Result<Json<SsoConfigSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;
    let provider = payload.provider.trim().to_lowercase();
    if provider.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "provider manquant".to_string()));
    }

    let enabled = payload.enabled.unwrap_or(true);
    let enforce_domain = payload.enforce_domain.unwrap_or(false);
    let mut saml_metadata = payload.saml_metadata.clone();

    validate_sso_payload(&provider, &payload)?;
    if provider == "saml" {
        saml_metadata = normalize_saml_metadata(payload.saml_metadata.as_deref()).await?;
    }

    let row = sqlx::query(
        "INSERT INTO sso_configs (org_id, provider, saml_metadata, oidc_client_id, oidc_client_secret, oidc_issuer_url, enabled, enforce_domain)\
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)\
        ON CONFLICT (org_id) DO UPDATE SET\
            provider = EXCLUDED.provider,\
            saml_metadata = EXCLUDED.saml_metadata,\
            oidc_client_id = EXCLUDED.oidc_client_id,\
            oidc_client_secret = EXCLUDED.oidc_client_secret,\
            oidc_issuer_url = EXCLUDED.oidc_issuer_url,\
            enabled = EXCLUDED.enabled,\
            enforce_domain = EXCLUDED.enforce_domain\
        RETURNING id, org_id, provider, saml_metadata, oidc_client_id, oidc_issuer_url, enabled, enforce_domain, created_at",
    )
    .bind(org_id)
    .bind(&provider)
    .bind(saml_metadata.as_deref())
    .bind(payload.oidc_client_id.as_deref())
    .bind(payload.oidc_client_secret.as_deref())
    .bind(payload.oidc_issuer_url.as_deref())
    .bind(enabled)
    .bind(enforce_domain)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let org_id: Uuid = row
        .try_get("org_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let provider: String = row
        .try_get("provider")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let saml_metadata: Option<String> = row
        .try_get("saml_metadata")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let oidc_client_id: Option<String> = row
        .try_get("oidc_client_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let oidc_issuer_url: Option<String> = row
        .try_get("oidc_issuer_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let enabled: bool = row
        .try_get("enabled")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let enforce_domain: bool = row
        .try_get("enforce_domain")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "sso.upsert",
        "sso_config",
        Some(&id.to_string()),
        Some(json!({ "org_id": org_id.to_string(), "provider": provider.clone() })),
        Some(&headers),
    )
    .await?;

    Ok(Json(SsoConfigSummary {
        id: id.to_string(),
        org_id: org_id.to_string(),
        provider,
        saml_metadata,
        oidc_client_id,
        oidc_issuer_url,
        enabled,
        enforce_domain,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn validate_sso_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT provider, saml_metadata, oidc_client_id, oidc_client_secret, oidc_issuer_url\
        FROM sso_configs WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "sso introuvable".to_string())),
    };

    let provider: String = row
        .try_get("provider")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let saml_metadata: Option<String> = row
        .try_get("saml_metadata")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let oidc_client_id: Option<String> = row
        .try_get("oidc_client_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let oidc_client_secret: Option<String> = row
        .try_get("oidc_client_secret")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let oidc_issuer_url: Option<String> = row
        .try_get("oidc_issuer_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let payload = UpsertSsoConfigBody {
        provider: provider.clone(),
        saml_metadata: saml_metadata.clone(),
        oidc_client_id: oidc_client_id.clone(),
        oidc_client_secret: oidc_client_secret.clone(),
        oidc_issuer_url: oidc_issuer_url.clone(),
        enabled: None,
        enforce_domain: None,
    };

    validate_sso_payload(&provider, &payload)?;
    if provider == "saml" {
        let normalized = normalize_saml_metadata(saml_metadata.as_deref()).await?;
        if normalized.is_none() {
            return Err((StatusCode::BAD_REQUEST, "metadata SAML invalide".to_string()));
        }
    }

    Ok(Json(json!({ "ok": true })))
}

async fn create_scim_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ScimTokenSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;
    let token = Uuid::new_v4().to_string();

    let row = sqlx::query(
        "INSERT INTO scim_tokens (org_id, token) VALUES ($1, $2) RETURNING id, org_id, token, created_at",
    )
    .bind(org_id)
    .bind(&token)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "scim.token.create",
        "scim_token",
        Some(&id.to_string()),
        Some(json!({ "org_id": org_id.to_string() })),
        Some(&headers),
    )
    .await?;

    Ok(Json(ScimTokenSummary {
        id: id.to_string(),
        org_id: org_id.to_string(),
        token,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn scim_list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ScimListQuery>,
) -> Result<Json<ScimListResponse<ScimUserResource>>, (StatusCode, String)> {
    let org_id = authorize_scim(&state.db, &headers).await?;

    let (start_index, count, filter_email) = parse_scim_list_query(&query, "userName");
    let offset = start_index.saturating_sub(1) as i64;
    let limit = count as i64;

    let total_row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count\
        FROM org_users ou\
        JOIN users u ON u.id = ou.user_id\
        WHERE ou.org_id = $1 AND ($2::text IS NULL OR u.email = $2)",
    )
    .bind(org_id)
    .bind(filter_email.as_deref())
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let total: i64 = total_row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let rows = sqlx::query(
        "SELECT u.id, u.email, u.created_at\
        FROM org_users ou\
        JOIN users u ON u.id = ou.user_id\
        WHERE ou.org_id = $1 AND ($2::text IS NULL OR u.email = $2)\
        ORDER BY u.created_at ASC\
        OFFSET $3 LIMIT $4",
    )
    .bind(org_id)
    .bind(filter_email.as_deref())
    .bind(offset)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut resources = Vec::with_capacity(rows.len());
    for row in rows {
        let user_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let email: String = row
            .try_get("email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        resources.push(build_scim_user(&user_id, &email, created_at));
    }

    Ok(Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total as usize,
        start_index: start_index,
        items_per_page: resources.len(),
        resources: resources,
    }))
}

async fn scim_get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ScimUserResource>, (StatusCode, String)> {
    let org_id = authorize_scim(&state.db, &headers).await?;
    let user_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "user id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT u.id, u.email, u.created_at\
        FROM org_users ou\
        JOIN users u ON u.id = ou.user_id\
        WHERE ou.org_id = $1 AND u.id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "user introuvable".to_string())),
    };

    let email: String = row
        .try_get("email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(build_scim_user(&user_id, &email, created_at)))
}

async fn scim_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ScimUserInput>,
) -> Result<Json<ScimUserResource>, (StatusCode, String)> {
    let org_id = authorize_scim(&state.db, &headers).await?;

    let email = payload.user_name.trim();
    if email.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "userName manquant".to_string()));
    }

    let row = sqlx::query(
        "INSERT INTO users (email) VALUES ($1)\
        ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email\
        RETURNING id, email, created_at",
    )
    .bind(email)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let user_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let email: String = row
        .try_get("email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    sqlx::query("INSERT INTO org_users (org_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(org_id)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(build_scim_user(&user_id, &email, created_at)))
}

async fn scim_update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<ScimUserInput>,
) -> Result<Json<ScimUserResource>, (StatusCode, String)> {
    let org_id = authorize_scim(&state.db, &headers).await?;
    let user_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "user id invalide".to_string()))?;

    let email = payload.user_name.trim();
    if email.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "userName manquant".to_string()));
    }

    let row = sqlx::query(
        "UPDATE users SET email = $1 WHERE id = $2 RETURNING id, email, created_at",
    )
    .bind(email)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "user introuvable".to_string())),
    };

    sqlx::query("INSERT INTO org_users (org_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(org_id)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let email: String = row
        .try_get("email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(build_scim_user(&user_id, &email, created_at)))
}

async fn scim_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<&'static str, (StatusCode, String)> {
    let org_id = authorize_scim(&state.db, &headers).await?;
    let user_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "user id invalide".to_string()))?;

    sqlx::query(
        "DELETE FROM team_memberships WHERE user_id = $1 AND team_id IN (SELECT id FROM teams WHERE org_id = $2)",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    sqlx::query("DELETE FROM org_users WHERE org_id = $1 AND user_id = $2")
        .bind(org_id)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let remaining = sqlx::query("SELECT COUNT(*)::bigint AS count FROM org_users WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let count: i64 = remaining
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    if count == 0 {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await;
    }

    Ok("ok")
}

async fn scim_list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ScimListQuery>,
) -> Result<Json<ScimListResponse<ScimGroupResource>>, (StatusCode, String)> {
    let org_id = authorize_scim(&state.db, &headers).await?;

    let (start_index, count, filter_name) = parse_scim_list_query(&query, "displayName");
    let offset = start_index.saturating_sub(1) as i64;
    let limit = count as i64;

    let total_row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count FROM teams WHERE org_id = $1 AND ($2::text IS NULL OR name = $2)",
    )
    .bind(org_id)
    .bind(filter_name.as_deref())
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let total: i64 = total_row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let rows = sqlx::query(
        "SELECT id, name, created_at FROM teams WHERE org_id = $1 AND ($2::text IS NULL OR name = $2)\
        ORDER BY created_at ASC OFFSET $3 LIMIT $4",
    )
    .bind(org_id)
    .bind(filter_name.as_deref())
    .bind(offset)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut resources = Vec::with_capacity(rows.len());
    for row in rows {
        let team_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let members = fetch_team_members(&state.db, team_id).await?;
        resources.push(build_scim_group(&team_id, &name, created_at, members));
    }

    Ok(Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total as usize,
        start_index: start_index,
        items_per_page: resources.len(),
        resources: resources,
    }))
}

async fn scim_get_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ScimGroupResource>, (StatusCode, String)> {
    let org_id = authorize_scim(&state.db, &headers).await?;
    let team_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "group id invalide".to_string()))?;

    let row = sqlx::query("SELECT id, name, created_at FROM teams WHERE id = $1 AND org_id = $2")
        .bind(team_id)
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "group introuvable".to_string())),
    };

    let name: String = row
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let members = fetch_team_members(&state.db, team_id).await?;

    Ok(Json(build_scim_group(&team_id, &name, created_at, members)))
}

async fn scim_create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ScimGroupInput>,
) -> Result<Json<ScimGroupResource>, (StatusCode, String)> {
    let org_id = authorize_scim(&state.db, &headers).await?;
    let name = payload.display_name.trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "displayName manquant".to_string()));
    }

    let row = sqlx::query(
        "INSERT INTO teams (org_id, name) VALUES ($1, $2) RETURNING id, name, created_at",
    )
    .bind(org_id)
    .bind(name)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let team_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let members = if let Some(members) = payload.members {
        replace_team_members(&state.db, org_id, team_id, members).await?
    } else {
        Vec::new()
    };

    Ok(Json(build_scim_group(&team_id, name, created_at, members)))
}

async fn scim_update_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<ScimGroupInput>,
) -> Result<Json<ScimGroupResource>, (StatusCode, String)> {
    let org_id = authorize_scim(&state.db, &headers).await?;
    let team_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "group id invalide".to_string()))?;
    let name = payload.display_name.trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "displayName manquant".to_string()));
    }

    let row = sqlx::query(
        "UPDATE teams SET name = $1 WHERE id = $2 AND org_id = $3 RETURNING id, name, created_at",
    )
    .bind(name)
    .bind(team_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "group introuvable".to_string())),
    };

    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let members = if let Some(members) = payload.members {
        replace_team_members(&state.db, org_id, team_id, members).await?
    } else {
        fetch_team_members(&state.db, team_id).await?
    };

    Ok(Json(build_scim_group(&team_id, name, created_at, members)))
}

async fn scim_delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<&'static str, (StatusCode, String)> {
    let org_id = authorize_scim(&state.db, &headers).await?;
    let team_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "group id invalide".to_string()))?;

    let result = sqlx::query("DELETE FROM teams WHERE id = $1 AND org_id = $2")
        .bind(team_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "group introuvable".to_string()));
    }

    Ok("ok")
}

async fn authorize_scim(db: &PgPool, headers: &HeaderMap) -> Result<Uuid, (StatusCode, String)> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or((StatusCode::UNAUTHORIZED, "scim token manquant".to_string()))?;

    let row = sqlx::query("SELECT org_id FROM scim_tokens WHERE token = $1")
        .bind(&token)
        .fetch_optional(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::UNAUTHORIZED, "scim token invalide".to_string())),
    };

    let org_id: Uuid = row
        .try_get("org_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(org_id)
}

fn parse_scim_list_query(query: &ScimListQuery, field: &str) -> (usize, usize, Option<String>) {
    let start_index = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(100).min(200).max(1);
    let filter = query.filter.as_deref().and_then(|value| parse_scim_filter(value, field));
    (start_index, count, filter)
}

fn parse_scim_filter(raw: &str, field: &str) -> Option<String> {
    let pattern = format!(r#"{}\s+eq\s+\"([^\"]+)\""#, field);
    let re = Regex::new(&pattern).ok()?;
    re.captures(raw)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().trim().to_string())
}

fn build_scim_user(user_id: &Uuid, email: &str, created_at: DateTime<Utc>) -> ScimUserResource {
    ScimUserResource {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
        id: user_id.to_string(),
        user_name: email.to_string(),
        active: true,
        meta: ScimMeta {
            resource_type: "User".to_string(),
            created: created_at.to_rfc3339(),
            last_modified: created_at.to_rfc3339(),
        },
    }
}

fn build_scim_group(team_id: &Uuid, name: &str, created_at: DateTime<Utc>, members: Vec<ScimGroupMember>) -> ScimGroupResource {
    ScimGroupResource {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:Group".to_string()],
        id: team_id.to_string(),
        display_name: name.to_string(),
        members,
        meta: ScimMeta {
            resource_type: "Group".to_string(),
            created: created_at.to_rfc3339(),
            last_modified: created_at.to_rfc3339(),
        },
    }
}

async fn fetch_team_members(db: &PgPool, team_id: Uuid) -> Result<Vec<ScimGroupMember>, (StatusCode, String)> {
    let rows = sqlx::query(
        "SELECT u.id, u.email FROM team_memberships tm JOIN users u ON u.id = tm.user_id WHERE tm.team_id = $1",
    )
    .bind(team_id)
    .fetch_all(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut members = Vec::with_capacity(rows.len());
    for row in rows {
        let user_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let email: String = row
            .try_get("email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        members.push(ScimGroupMember {
            value: user_id.to_string(),
            display: Some(email),
        });
    }
    Ok(members)
}

async fn replace_team_members(
    db: &PgPool,
    org_id: Uuid,
    team_id: Uuid,
    members: Vec<ScimMemberInput>,
) -> Result<Vec<ScimGroupMember>, (StatusCode, String)> {
    sqlx::query("DELETE FROM team_memberships WHERE team_id = $1")
        .bind(team_id)
        .execute(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut results = Vec::new();
    for member in members {
        let user_id = Uuid::parse_str(member.value.trim())
            .map_err(|_| (StatusCode::BAD_REQUEST, "member id invalide".to_string()))?;
        let user_row = sqlx::query("SELECT id, email FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_row = match user_row {
            Some(row) => row,
            None => return Err((StatusCode::BAD_REQUEST, "member introuvable".to_string())),
        };

        let email: String = user_row
            .try_get("email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        sqlx::query("INSERT INTO team_memberships (team_id, user_id, role) VALUES ($1, $2, 'member')")
            .bind(team_id)
            .bind(user_id)
            .execute(db)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        sqlx::query("INSERT INTO org_users (org_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
            .bind(org_id)
            .bind(user_id)
            .execute(db)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        results.push(ScimGroupMember {
            value: user_id.to_string(),
            display: Some(email),
        });
    }
    Ok(results)
}

async fn list_integrations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<IntegrationSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT key, name, category, description, auth_type, oauth_authorize_url, oauth_scopes, enabled FROM integrations_catalog ORDER BY name ASC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let key: String = row
            .try_get("key")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let category: String = row
            .try_get("category")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let description: Option<String> = row
            .try_get("description")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let auth_type: String = row
            .try_get("auth_type")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let oauth_authorize_url: Option<String> = row
            .try_get("oauth_authorize_url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let oauth_scopes: Option<String> = row
            .try_get("oauth_scopes")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let enabled: bool = row
            .try_get("enabled")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(IntegrationSummary {
            key,
            name,
            category,
            description,
            auth_type,
            oauth_authorize_url,
            oauth_scopes,
            enabled,
        });
    }

    Ok(Json(items))
}

async fn list_org_integrations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<OrgIntegrationSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;

    let rows = sqlx::query(
        "SELECT id, org_id, integration_key, config, enabled, created_at\
        FROM org_integrations WHERE org_id = $1 ORDER BY created_at DESC",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let org_id: Uuid = row
            .try_get("org_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let integration_key: String = row
            .try_get("integration_key")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let config: Option<Value> = row
            .try_get("config")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let enabled: bool = row
            .try_get("enabled")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(OrgIntegrationSummary {
            id: id.to_string(),
            org_id: org_id.to_string(),
            integration_key,
            config,
            enabled,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn upsert_org_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpsertOrgIntegrationBody>,
) -> Result<Json<OrgIntegrationSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;
    let integration_key = payload.integration_key.trim().to_string();
    if integration_key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "integration_key manquant".to_string()));
    }
    let enabled = payload.enabled.unwrap_or(true);

    let row = sqlx::query(
        "INSERT INTO org_integrations (org_id, integration_key, config, enabled)\
        VALUES ($1, $2, $3, $4)\
        ON CONFLICT (org_id, integration_key) DO UPDATE SET\
            config = EXCLUDED.config,\
            enabled = EXCLUDED.enabled\
        RETURNING id, org_id, integration_key, config, enabled, created_at",
    )
    .bind(org_id)
    .bind(&integration_key)
    .bind(&payload.config)
    .bind(enabled)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let org_id: Uuid = row
        .try_get("org_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let integration_key: String = row
        .try_get("integration_key")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let config: Option<Value> = row
        .try_get("config")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let enabled: bool = row
        .try_get("enabled")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "org.integration.upsert",
        "org_integration",
        Some(&id.to_string()),
        Some(json!({ "org_id": org_id.to_string(), "integration_key": integration_key.clone() })),
        Some(&headers),
    )
    .await?;

    Ok(Json(OrgIntegrationSummary {
        id: id.to_string(),
        org_id: org_id.to_string(),
        integration_key,
        config,
        enabled,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn test_org_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, key)): Path<(String, String)>,
) -> Result<Json<Value>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT id, config, enabled FROM org_integrations WHERE org_id = $1 AND integration_key = $2",
    )
    .bind(org_id)
    .bind(&key)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "integration introuvable".to_string())),
    };

    let enabled: bool = row
        .try_get("enabled")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    if !enabled {
        return Err((StatusCode::BAD_REQUEST, "integration désactivée".to_string()));
    }

    let config: Option<Value> = row
        .try_get("config")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let url = config.as_ref().and_then(|value| {
        value
            .get("webhook_url")
            .or_else(|| value.get("url"))
            .and_then(|v| v.as_str())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    });

    let url = match url {
        Some(url) => url,
        None => return Err((StatusCode::BAD_REQUEST, "webhook_url manquant".to_string())),
    };

    let client = Client::new();
    let payload = json!({
        "kind": "integration_test",
        "org_id": id,
        "integration_key": key,
        "message": "Test integration from AMBER"
    });

    let response = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let status = response.status().as_u16();

    insert_audit_log(
        &state.db,
        &actor,
        "org.integration.test",
        "org_integration",
        None,
        Some(json!({ "org_id": org_id.to_string(), "integration_key": key, "status": status })),
        Some(&headers),
    )
    .await?;

    Ok(Json(json!({ "ok": status >= 200 && status < 300, "status": status })))
}

async fn start_oauth_flow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, key)): Path<(String, String)>,
) -> Result<Json<OAuthStartResponse>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT oauth_authorize_url, oauth_scopes FROM integrations_catalog WHERE key = $1 AND enabled = true",
    )
    .bind(&key)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "integration introuvable".to_string())),
    };

    let authorize_url: Option<String> = row
        .try_get("oauth_authorize_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let scopes: Option<String> = row
        .try_get("oauth_scopes")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let authorize_url = authorize_url.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "oauth_authorize_url manquant".to_string())
    })?;

    let state_token = format!("{}:{}", org_id, key);
    let scopes = scopes.unwrap_or_default();
    let mut url = format!("{}?state={}", authorize_url, urlencoding::encode(&state_token));
    if !scopes.is_empty() {
        url = format!("{}&scope={}", url, urlencoding::encode(&scopes));
    }

    Ok(Json(OAuthStartResponse { authorize_url: url }))
}

async fn handle_oauth_callback(
    State(state): State<AppState>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let parts: Vec<&str> = query.state.split(':').collect();
    if parts.len() != 2 {
        return Err((StatusCode::BAD_REQUEST, "state invalide".to_string()));
    }

    let org_id = Uuid::parse_str(parts[0])
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;
    let integration_key = parts[1].to_string();

    let row = sqlx::query(
        "SELECT oauth_token_url FROM integrations_catalog WHERE key = $1",
    )
    .bind(&integration_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "integration introuvable".to_string())),
    };

    let token_url: Option<String> = row
        .try_get("oauth_token_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let token_url = token_url.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "oauth_token_url manquant".to_string())
    })?;

    let client = Client::new();
    let token_response = client
        .post(&token_url)
        .json(&json!({ "code": query.code }))
        .send()
        .await
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let token_payload: Value = token_response
        .json()
        .await
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let access_token = token_payload.get("access_token").and_then(|v| v.as_str()).map(|v| v.to_string());
    let refresh_token = token_payload.get("refresh_token").and_then(|v| v.as_str()).map(|v| v.to_string());
    let access_token = if let Some(token) = access_token {
        Some(encrypt_secret(&token).map_err(|err| (StatusCode::BAD_REQUEST, err))?)
    } else {
        None
    };
    let refresh_token = if let Some(token) = refresh_token {
        Some(encrypt_secret(&token).map_err(|err| (StatusCode::BAD_REQUEST, err))?)
    } else {
        None
    };
    let expires_in = token_payload.get("expires_in").and_then(|v| v.as_i64());
    let expires_at = expires_in.map(|value| Utc::now() + chrono::Duration::seconds(value));

    sqlx::query(
        "INSERT INTO oauth_connections (org_id, integration_key, access_token, refresh_token, expires_at)\
        VALUES ($1, $2, $3, $4, $5)\
        ON CONFLICT (org_id, integration_key) DO UPDATE SET\
            access_token = EXCLUDED.access_token,\
            refresh_token = EXCLUDED.refresh_token,\
            expires_at = EXCLUDED.expires_at",
    )
    .bind(org_id)
    .bind(&integration_key)
    .bind(&access_token)
    .bind(&refresh_token)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(json!({ "ok": true })))
}

async fn list_data_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<DataRequestSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;

    let rows = sqlx::query(
        "SELECT id, org_id, kind, subject_email, status, requested_by, completed_at, created_at\
        FROM data_requests WHERE org_id = $1 ORDER BY created_at DESC",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let org_id: Uuid = row
            .try_get("org_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let kind: String = row
            .try_get("kind")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let subject_email: Option<String> = row
            .try_get("subject_email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let requested_by: Option<String> = row
            .try_get("requested_by")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let completed_at: Option<DateTime<Utc>> = row
            .try_get("completed_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(DataRequestSummary {
            id: id.to_string(),
            org_id: org_id.to_string(),
            kind,
            subject_email,
            status,
            requested_by,
            completed_at: completed_at.map(|value| value.to_rfc3339()),
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn create_data_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateDataRequestBody>,
) -> Result<Json<DataRequestSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;
    let kind = payload.kind.trim().to_lowercase();
    if !matches!(kind.as_str(), "export" | "delete") {
        return Err((StatusCode::BAD_REQUEST, "kind invalide".to_string()));
    }

    let subject_email = payload
        .subject_email
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty());

    let row = sqlx::query(
        "INSERT INTO data_requests (org_id, kind, subject_email, requested_by) VALUES ($1, $2, $3, $4)\
        RETURNING id, org_id, kind, subject_email, status, requested_by, completed_at, created_at",
    )
    .bind(org_id)
    .bind(&kind)
    .bind(&subject_email)
    .bind(&actor)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let org_id: Uuid = row
        .try_get("org_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let kind: String = row
        .try_get("kind")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let subject_email: Option<String> = row
        .try_get("subject_email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let status: String = row
        .try_get("status")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let requested_by: Option<String> = row
        .try_get("requested_by")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let completed_at: Option<DateTime<Utc>> = row
        .try_get("completed_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "data_request.create",
        "data_request",
        Some(&id.to_string()),
        Some(json!({ "org_id": org_id.to_string(), "kind": kind })),
        Some(&headers),
    )
    .await?;

    Ok(Json(DataRequestSummary {
        id: id.to_string(),
        org_id: org_id.to_string(),
        kind,
        subject_email,
        status,
        requested_by,
        completed_at: completed_at.map(|value| value.to_rfc3339()),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn complete_data_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DataRequestSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let request_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let row = sqlx::query(
        "UPDATE data_requests SET status = 'completed', completed_at = now() WHERE id = $1\
        RETURNING id, org_id, kind, subject_email, status, requested_by, completed_at, created_at",
    )
    .bind(request_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "request introuvable".to_string())),
    };

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let org_id: Uuid = row
        .try_get("org_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let kind: String = row
        .try_get("kind")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let subject_email: Option<String> = row
        .try_get("subject_email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let status: String = row
        .try_get("status")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let requested_by: Option<String> = row
        .try_get("requested_by")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let completed_at: Option<DateTime<Utc>> = row
        .try_get("completed_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "data_request.complete",
        "data_request",
        Some(&id.to_string()),
        Some(json!({ "org_id": org_id.to_string(), "kind": kind })),
        Some(&headers),
    )
    .await?;

    Ok(Json(DataRequestSummary {
        id: id.to_string(),
        org_id: org_id.to_string(),
        kind,
        subject_email,
        status,
        requested_by,
        completed_at: completed_at.map(|value| value.to_rfc3339()),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn run_data_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DataRequestRunSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let request_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT id, org_id, kind, subject_email, status FROM data_requests WHERE id = $1",
    )
    .bind(request_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "request introuvable".to_string())),
    };

    let org_id: Uuid = row
        .try_get("org_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let kind: String = row
        .try_get("kind")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let subject_email: Option<String> = row
        .try_get("subject_email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let subject = subject_email
        .as_deref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or((StatusCode::BAD_REQUEST, "subject_email manquant".to_string()))?;

    let project_ids = org_project_ids(&state.db, org_id).await?;
    if project_ids.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "aucun projet pour l'org".to_string()));
    }

    let payload = if kind == "export" {
        let events_count = count_user_events(&state.db, &project_ids, &subject).await?;
        let replays_count = count_user_replays(&state.db, &project_ids, &subject).await?;
        let issues_count = count_user_issues(&state.db, &project_ids, &subject).await?;

        let events_sample = sample_user_events(&state.db, &project_ids, &subject).await?;
        let replays_sample = sample_user_replays(&state.db, &project_ids, &subject).await?;
        let issues_sample = sample_user_issues(&state.db, &project_ids, &subject).await?;

        json!({
            "events_count": events_count,
            "replays_count": replays_count,
            "issues_count": issues_count,
            "events_sample": events_sample,
            "replays_sample": replays_sample,
            "issues_sample": issues_sample
        })
    } else if kind == "delete" {
        let events_deleted = delete_user_events(&state.db, &project_ids, &subject).await?;
        let replays_deleted = delete_user_replays(&state.db, &project_ids, &subject).await?;
        let issues_updated = clear_user_issues(&state.db, &project_ids, &subject).await?;

        json!({
            "events_deleted": events_deleted,
            "replays_deleted": replays_deleted,
            "issues_updated": issues_updated
        })
    } else {
        return Err((StatusCode::BAD_REQUEST, "kind invalide".to_string()));
    };

    let result_row = sqlx::query(
        "INSERT INTO data_request_results (request_id, payload) VALUES ($1, $2)\
        RETURNING id, created_at",
    )
    .bind(request_id)
    .bind(&payload)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let result_id: Uuid = result_row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    sqlx::query("UPDATE data_requests SET status = 'completed', completed_at = now() WHERE id = $1")
        .bind(request_id)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "data_request.run",
        "data_request",
        Some(&request_id.to_string()),
        Some(json!({ "org_id": org_id.to_string(), "kind": kind })),
        Some(&headers),
    )
    .await?;

    Ok(Json(DataRequestRunSummary {
        request_id: request_id.to_string(),
        kind,
        subject_email: Some(subject),
        status: "completed".to_string(),
        payload: json!({
            "result_id": result_id.to_string(),
            "data": payload
        }),
    }))
}

async fn list_data_request_results(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<DataRequestResultSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let request_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let rows = sqlx::query(
        "SELECT id, request_id, payload, created_at FROM data_request_results WHERE request_id = $1 ORDER BY created_at DESC",
    )
    .bind(request_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let result_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let request_id: Uuid = row
            .try_get("request_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let payload: Value = row
            .try_get("payload")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(DataRequestResultSummary {
            id: result_id.to_string(),
            request_id: request_id.to_string(),
            payload,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn org_project_ids(db: &PgPool, org_id: Uuid) -> Result<Vec<String>, (StatusCode, String)> {
    let rows = sqlx::query(
        "SELECT DISTINCT pt.project_id\
        FROM project_teams pt\
        JOIN teams t ON t.id = pt.team_id\
        WHERE t.org_id = $1",
    )
    .bind(org_id)
    .fetch_all(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        ids.push(project_id);
    }
    Ok(ids)
}

async fn count_user_events(db: &PgPool, project_ids: &[String], subject: &str) -> Result<i64, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count FROM events\
        WHERE project_id = ANY($1) AND (user_email = $2 OR user_id = $2)",
    )
    .bind(project_ids)
    .bind(subject)
    .fetch_one(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let count: i64 = row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(count)
}

async fn count_user_replays(db: &PgPool, project_ids: &[String], subject: &str) -> Result<i64, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count FROM replays\
        WHERE project_id = ANY($1) AND (user_email = $2 OR user_id = $2)",
    )
    .bind(project_ids)
    .bind(subject)
    .fetch_one(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let count: i64 = row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(count)
}

async fn count_user_issues(db: &PgPool, project_ids: &[String], subject: &str) -> Result<i64, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count FROM issues\
        WHERE project_id = ANY($1) AND (last_user_email = $2 OR last_user_id = $2)",
    )
    .bind(project_ids)
    .bind(subject)
    .fetch_one(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let count: i64 = row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(count)
}

async fn sample_user_events(db: &PgPool, project_ids: &[String], subject: &str) -> Result<Vec<String>, (StatusCode, String)> {
    let rows = sqlx::query(
        "SELECT id FROM events\
        WHERE project_id = ANY($1) AND (user_email = $2 OR user_id = $2)\
        ORDER BY occurred_at DESC LIMIT 20",
    )
    .bind(project_ids)
    .bind(subject)
    .fetch_all(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(rows
        .into_iter()
        .filter_map(|row| row.try_get::<Uuid, _>("id").ok())
        .map(|value| value.to_string())
        .collect())
}

async fn sample_user_replays(db: &PgPool, project_ids: &[String], subject: &str) -> Result<Vec<String>, (StatusCode, String)> {
    let rows = sqlx::query(
        "SELECT id FROM replays\
        WHERE project_id = ANY($1) AND (user_email = $2 OR user_id = $2)\
        ORDER BY created_at DESC LIMIT 20",
    )
    .bind(project_ids)
    .bind(subject)
    .fetch_all(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(rows
        .into_iter()
        .filter_map(|row| row.try_get::<Uuid, _>("id").ok())
        .map(|value| value.to_string())
        .collect())
}

async fn sample_user_issues(db: &PgPool, project_ids: &[String], subject: &str) -> Result<Vec<String>, (StatusCode, String)> {
    let rows = sqlx::query(
        "SELECT id FROM issues\
        WHERE project_id = ANY($1) AND (last_user_email = $2 OR last_user_id = $2)\
        ORDER BY last_seen DESC LIMIT 20",
    )
    .bind(project_ids)
    .bind(subject)
    .fetch_all(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(rows
        .into_iter()
        .filter_map(|row| row.try_get::<Uuid, _>("id").ok())
        .map(|value| value.to_string())
        .collect())
}

async fn delete_user_events(db: &PgPool, project_ids: &[String], subject: &str) -> Result<i64, (StatusCode, String)> {
    let result = sqlx::query(
        "DELETE FROM events WHERE project_id = ANY($1) AND (user_email = $2 OR user_id = $2)",
    )
    .bind(project_ids)
    .bind(subject)
    .execute(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(result.rows_affected() as i64)
}

async fn delete_user_replays(db: &PgPool, project_ids: &[String], subject: &str) -> Result<i64, (StatusCode, String)> {
    let result = sqlx::query(
        "DELETE FROM replays WHERE project_id = ANY($1) AND (user_email = $2 OR user_id = $2)",
    )
    .bind(project_ids)
    .bind(subject)
    .execute(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(result.rows_affected() as i64)
}

async fn clear_user_issues(db: &PgPool, project_ids: &[String], subject: &str) -> Result<i64, (StatusCode, String)> {
    let result = sqlx::query(
        "UPDATE issues SET last_user_email = NULL, last_user_id = NULL\
        WHERE project_id = ANY($1) AND (last_user_email = $2 OR last_user_id = $2)",
    )
    .bind(project_ids)
    .bind(subject)
    .execute(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(result.rows_affected() as i64)
}

async fn list_regions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<RegionSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT name, api_base_url, ingest_url, active FROM regions ORDER BY name ASC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let api_base_url: String = row
            .try_get("api_base_url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let ingest_url: String = row
            .try_get("ingest_url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let active: bool = row
            .try_get("active")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(RegionSummary {
            name,
            api_base_url,
            ingest_url,
            active,
        });
    }

    Ok(Json(items))
}

async fn get_project_routing(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RoutingSummary>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    let row = sqlx::query(
        "SELECT o.data_region AS data_region\
        FROM organizations o\
        JOIN teams t ON t.org_id = o.id\
        JOIN project_teams pt ON pt.team_id = t.id\
        WHERE pt.project_id = $1\
        LIMIT 1",
    )
    .bind(&project_id)
    .fetch_optional(&state.db)
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
        .fetch_optional(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        sqlx::query(
            "SELECT name, api_base_url, ingest_url FROM regions WHERE active = true ORDER BY name ASC LIMIT 1",
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    };

    let region_row = match region_row {
        Some(row) => row,
        None => return Err((StatusCode::BAD_REQUEST, "region indisponible".to_string())),
    };

    let name: String = region_row
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_base_url: String = region_row
        .try_get("api_base_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let ingest_url: String = region_row
        .try_get("ingest_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(RoutingSummary {
        project_id,
        region: name,
        api_base_url,
        ingest_url,
    }))
}

async fn update_issue_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<UpdateIssueStatusBody>,
) -> Result<Json<IssueDetailResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id.clone();
    require_project_scope(&auth, "project:triage")?;

    let status = payload.status.to_lowercase();
    if !matches!(status.as_str(), "open" | "resolved" | "ignored") {
        return Err((StatusCode::BAD_REQUEST, "status invalide".to_string()));
    }

    let issue_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let row = sqlx::query(
        "UPDATE issues SET status = $1 WHERE id = $2 AND project_id = $3\
        RETURNING id, project_id, fingerprint, title, level, status, assignee, first_release, last_release, regressed_at, last_user_email, last_user_id, github_issue_url, first_seen, last_seen, count_total",
    )
    .bind(&status)
    .bind(issue_id)
    .bind(&project_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "issue introuvable".to_string())),
    };

    let fingerprint: String = row
        .try_get("fingerprint")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let title: String = row
        .try_get("title")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let level: String = row
        .try_get("level")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let status: String = row
        .try_get("status")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let assignee: Option<String> = row
        .try_get("assignee")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let first_release: Option<String> = row
        .try_get("first_release")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_release: Option<String> = row
        .try_get("last_release")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let regressed_at: Option<DateTime<Utc>> = row
        .try_get("regressed_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_user_email: Option<String> = row
        .try_get("last_user_email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_user_id: Option<String> = row
        .try_get("last_user_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let github_issue_url: Option<String> = row
        .try_get("github_issue_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_user = last_user_email.or(last_user_id);
    let first_seen: DateTime<Utc> = row
        .try_get("first_seen")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_seen: DateTime<Utc> = row
        .try_get("last_seen")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let count_total: i64 = row
        .try_get("count_total")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &auth.actor,
        "issue.assign",
        "issue",
        Some(&issue_id.to_string()),
        Some(json!({ "assignee": assignee.clone() })),
        Some(&headers),
    )
    .await?;

    insert_audit_log(
        &state.db,
        &auth.actor,
        "issue.status.update",
        "issue",
        Some(&issue_id.to_string()),
        Some(json!({ "status": status.clone() })),
        Some(&headers),
    )
    .await?;

    Ok(Json(IssueDetailResponse {
        id: issue_id.to_string(),
        project_id,
        fingerprint,
        title,
        level,
        status,
        assignee,
        first_release,
        last_release,
        regressed_at: regressed_at.map(|value| value.to_rfc3339()),
        last_user,
        github_issue_url,
        first_seen: first_seen.to_rfc3339(),
        last_seen: last_seen.to_rfc3339(),
        count_total,
        last_event: None,
    }))
}

async fn assign_issue(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<AssignIssueBody>,
) -> Result<Json<IssueDetailResponse>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id.clone();
    require_project_scope(&auth, "project:triage")?;

    let issue_id = uuid::Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "id invalide".to_string()))?;

    let assignee = payload
        .assignee
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let row = sqlx::query(
        "UPDATE issues SET assignee = $1 WHERE id = $2 AND project_id = $3\
        RETURNING id, project_id, fingerprint, title, level, status, assignee, first_release, last_release, regressed_at, last_user_email, last_user_id, github_issue_url, first_seen, last_seen, count_total",
    )
    .bind(&assignee)
    .bind(issue_id)
    .bind(&project_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "issue introuvable".to_string())),
    };

    let fingerprint: String = row
        .try_get("fingerprint")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let title: String = row
        .try_get("title")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let level: String = row
        .try_get("level")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let status: String = row
        .try_get("status")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let assignee: Option<String> = row
        .try_get("assignee")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let first_release: Option<String> = row
        .try_get("first_release")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_release: Option<String> = row
        .try_get("last_release")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let regressed_at: Option<DateTime<Utc>> = row
        .try_get("regressed_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_user_email: Option<String> = row
        .try_get("last_user_email")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_user_id: Option<String> = row
        .try_get("last_user_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let github_issue_url: Option<String> = row
        .try_get("github_issue_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_user = last_user_email.or(last_user_id);
    let first_seen: DateTime<Utc> = row
        .try_get("first_seen")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_seen: DateTime<Utc> = row
        .try_get("last_seen")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let count_total: i64 = row
        .try_get("count_total")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(IssueDetailResponse {
        id: issue_id.to_string(),
        project_id,
        fingerprint,
        title,
        level,
        status,
        assignee,
        first_release,
        last_release,
        regressed_at: regressed_at.map(|value| value.to_rfc3339()),
        last_user,
        github_issue_url,
        first_seen: first_seen.to_rfc3339(),
        last_seen: last_seen.to_rfc3339(),
        count_total,
        last_event: None,
    }))
}

async fn get_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ProjectDetail>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let row = sqlx::query("SELECT id, name, api_key, webhook_url, slack_webhook_url, github_repo, rate_limit_per_min, quota_soft_limit, quota_hard_limit, api_key_last_used_at, api_key_rotated_at, created_at FROM projects WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "project introuvable".to_string())),
    };

    let name: String = row
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key: String = row
        .try_get("api_key")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let webhook_url: Option<String> = row
        .try_get("webhook_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let slack_webhook_url: Option<String> = row
        .try_get("slack_webhook_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let github_repo: Option<String> = row
        .try_get("github_repo")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let rate_limit_per_min: Option<i64> = row
        .try_get("rate_limit_per_min")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let quota_soft_limit: Option<i64> = row
        .try_get("quota_soft_limit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let quota_hard_limit: Option<i64> = row
        .try_get("quota_hard_limit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key_last_used_at: Option<DateTime<Utc>> = row
        .try_get("api_key_last_used_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key_rotated_at: Option<DateTime<Utc>> = row
        .try_get("api_key_rotated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(ProjectDetail {
        id,
        name,
        api_key,
        webhook_url,
        slack_webhook_url,
        github_repo,
        rate_limit_per_min,
        quota_soft_limit,
        quota_hard_limit,
        api_key_last_used_at: api_key_last_used_at.map(|value| value.to_rfc3339()),
        api_key_rotated_at: api_key_rotated_at.map(|value| value.to_rfc3339()),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn list_projects(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProjectSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query("SELECT id, name, created_at FROM projects ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(ProjectSummary {
            id,
            name,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn create_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateProjectBody>,
) -> Result<Json<ProjectDetail>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let project_id = payload.id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let api_key = Uuid::new_v4().to_string();

    let row = sqlx::query(
        "INSERT INTO projects (id, name, api_key, rate_limit_per_min, quota_soft_limit, quota_hard_limit) VALUES ($1, $2, $3, $4, $5, $6)\
        RETURNING id, name, api_key, webhook_url, slack_webhook_url, github_repo, rate_limit_per_min, quota_soft_limit, quota_hard_limit, api_key_last_used_at, api_key_rotated_at, created_at",
    )
    .bind(&project_id)
    .bind(&payload.name)
    .bind(&api_key)
    .bind(payload.rate_limit_per_min)
    .bind(payload.quota_soft_limit)
    .bind(payload.quota_hard_limit)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let rate_limit_per_min: Option<i64> = row
        .try_get("rate_limit_per_min")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let quota_soft_limit: Option<i64> = row
        .try_get("quota_soft_limit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let quota_hard_limit: Option<i64> = row
        .try_get("quota_hard_limit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key_last_used_at: Option<DateTime<Utc>> = row
        .try_get("api_key_last_used_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key_rotated_at: Option<DateTime<Utc>> = row
        .try_get("api_key_rotated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.create",
        "project",
        Some(&project_id),
        Some(json!({ "name": payload.name.clone() })),
        Some(&headers),
    )
    .await?;

    Ok(Json(ProjectDetail {
        id: project_id,
        name: payload.name,
        api_key,
        webhook_url: None,
        slack_webhook_url: None,
        github_repo: None,
        rate_limit_per_min,
        quota_soft_limit,
        quota_hard_limit,
        api_key_last_used_at: api_key_last_used_at.map(|value| value.to_rfc3339()),
        api_key_rotated_at: api_key_rotated_at.map(|value| value.to_rfc3339()),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn rotate_project_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ProjectDetail>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let api_key = Uuid::new_v4().to_string();
    let row = sqlx::query(
        "UPDATE projects SET api_key = $1, api_key_rotated_at = now() WHERE id = $2\
        RETURNING id, name, api_key, webhook_url, slack_webhook_url, github_repo, rate_limit_per_min, quota_soft_limit, quota_hard_limit, api_key_last_used_at, api_key_rotated_at, created_at",
    )
    .bind(&api_key)
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "project introuvable".to_string())),
    };

    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let name: String = row
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let webhook_url: Option<String> = row
        .try_get("webhook_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let slack_webhook_url: Option<String> = row
        .try_get("slack_webhook_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let github_repo: Option<String> = row
        .try_get("github_repo")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let rate_limit_per_min: Option<i64> = row
        .try_get("rate_limit_per_min")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let quota_soft_limit: Option<i64> = row
        .try_get("quota_soft_limit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let quota_hard_limit: Option<i64> = row
        .try_get("quota_hard_limit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key_last_used_at: Option<DateTime<Utc>> = row
        .try_get("api_key_last_used_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key_rotated_at: Option<DateTime<Utc>> = row
        .try_get("api_key_rotated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.rotate_key",
        "project",
        Some(&id),
        None,
        Some(&headers),
    )
    .await?;

    Ok(Json(ProjectDetail {
        id,
        name,
        api_key,
        webhook_url,
        slack_webhook_url,
        github_repo,
        rate_limit_per_min,
        quota_soft_limit,
        quota_hard_limit,
        api_key_last_used_at: api_key_last_used_at.map(|value| value.to_rfc3339()),
        api_key_rotated_at: api_key_rotated_at.map(|value| value.to_rfc3339()),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn update_project_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<WebhookUpdateBody>,
) -> Result<Json<ProjectDetail>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let url = payload
        .url
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let row = sqlx::query(
        "UPDATE projects SET webhook_url = $1 WHERE id = $2\
        RETURNING id, name, api_key, webhook_url, slack_webhook_url, github_repo, rate_limit_per_min, quota_soft_limit, quota_hard_limit, api_key_last_used_at, api_key_rotated_at, created_at",
    )
    .bind(&url)
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "project introuvable".to_string())),
    };

    let name: String = row
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key: String = row
        .try_get("api_key")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let webhook_url: Option<String> = row
        .try_get("webhook_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let slack_webhook_url: Option<String> = row
        .try_get("slack_webhook_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let github_repo: Option<String> = row
        .try_get("github_repo")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let rate_limit_per_min: Option<i64> = row
        .try_get("rate_limit_per_min")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let quota_soft_limit: Option<i64> = row
        .try_get("quota_soft_limit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let quota_hard_limit: Option<i64> = row
        .try_get("quota_hard_limit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key_last_used_at: Option<DateTime<Utc>> = row
        .try_get("api_key_last_used_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key_rotated_at: Option<DateTime<Utc>> = row
        .try_get("api_key_rotated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.webhook.update",
        "project",
        Some(&id),
        Some(json!({ "webhook_url": url })),
        Some(&headers),
    )
    .await?;

    Ok(Json(ProjectDetail {
        id,
        name,
        api_key,
        webhook_url,
        slack_webhook_url,
        github_repo,
        rate_limit_per_min,
        quota_soft_limit,
        quota_hard_limit,
        api_key_last_used_at: api_key_last_used_at.map(|value| value.to_rfc3339()),
        api_key_rotated_at: api_key_rotated_at.map(|value| value.to_rfc3339()),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn update_project_integrations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<IntegrationsUpdateBody>,
) -> Result<Json<ProjectDetail>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let webhook_url = payload.webhook_url.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let slack_webhook_url = payload.slack_webhook_url.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let github_repo = payload.github_repo.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let github_token = payload.github_token.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let github_token = if let Some(token) = github_token {
        Some(encrypt_secret(&token).map_err(|err| (StatusCode::BAD_REQUEST, err))?)
    } else {
        None
    };

    let row = sqlx::query(
        "UPDATE projects SET webhook_url = $1, slack_webhook_url = $2, github_repo = $3, github_token = $4 WHERE id = $5\
        RETURNING id, name, api_key, webhook_url, slack_webhook_url, github_repo, rate_limit_per_min, quota_soft_limit, quota_hard_limit, api_key_last_used_at, api_key_rotated_at, created_at",
    )
    .bind(&webhook_url)
    .bind(&slack_webhook_url)
    .bind(&github_repo)
    .bind(&github_token)
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "project introuvable".to_string())),
    };

    let name: String = row
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key: String = row
        .try_get("api_key")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let webhook_url: Option<String> = row
        .try_get("webhook_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let slack_webhook_url: Option<String> = row
        .try_get("slack_webhook_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let github_repo: Option<String> = row
        .try_get("github_repo")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let rate_limit_per_min: Option<i64> = row
        .try_get("rate_limit_per_min")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let quota_soft_limit: Option<i64> = row
        .try_get("quota_soft_limit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let quota_hard_limit: Option<i64> = row
        .try_get("quota_hard_limit")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key_last_used_at: Option<DateTime<Utc>> = row
        .try_get("api_key_last_used_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let api_key_rotated_at: Option<DateTime<Utc>> = row
        .try_get("api_key_rotated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.integrations.update",
        "project",
        Some(&id),
        Some(json!({
            "webhook_url": webhook_url.clone(),
            "slack_webhook_url": slack_webhook_url.clone(),
            "github_repo": github_repo.clone()
        })),
        Some(&headers),
    )
    .await?;

    Ok(Json(ProjectDetail {
        id,
        name,
        api_key,
        webhook_url,
        slack_webhook_url,
        github_repo,
        rate_limit_per_min,
        quota_soft_limit,
        quota_hard_limit,
        api_key_last_used_at: api_key_last_used_at.map(|value| value.to_rfc3339()),
        api_key_rotated_at: api_key_rotated_at.map(|value| value.to_rfc3339()),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn get_sampling_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SamplingRuleSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let row = sqlx::query(
        "SELECT project_id, target_events_per_min, min_rate, max_rate, updated_at\
        FROM sampling_rules WHERE project_id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => {
            let now = Utc::now();
            return Ok(Json(SamplingRuleSummary {
                project_id: id,
                target_events_per_min: 0,
                min_rate: 0.1,
                max_rate: 1.0,
                updated_at: now.to_rfc3339(),
            }));
        }
    };

    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let target_events_per_min: i32 = row
        .try_get("target_events_per_min")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let min_rate: f64 = row
        .try_get("min_rate")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let max_rate: f64 = row
        .try_get("max_rate")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let updated_at: DateTime<Utc> = row
        .try_get("updated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(SamplingRuleSummary {
        project_id,
        target_events_per_min,
        min_rate,
        max_rate,
        updated_at: updated_at.to_rfc3339(),
    }))
}

async fn list_project_cost_units(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ProjectCostQuery>,
) -> Result<Json<Vec<CostUnitRow>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let limit = query.limit.unwrap_or(200).min(500) as i64;
    let rows = sqlx::query(
        "SELECT id, entity_id, kind, units, storage_bytes, created_at\
        FROM cost_units WHERE project_id = $1\
        ORDER BY created_at DESC LIMIT $2",
    )
    .bind(&id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let entity_id: Uuid = row
            .try_get("entity_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let kind: String = row
            .try_get("kind")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let units: f64 = row
            .try_get("units")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let storage_bytes: i64 = row
            .try_get("storage_bytes")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(CostUnitRow {
            id: id.to_string(),
            entity_id: entity_id.to_string(),
            kind,
            units,
            storage_bytes,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn list_project_cost_daily(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ProjectCostQuery>,
) -> Result<Json<Vec<ProjectCostDailyRow>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let limit = query.limit.unwrap_or(30).min(365) as i64;
    let rows = sqlx::query(
        "SELECT day, units, storage_bytes\
        FROM project_cost_daily WHERE project_id = $1\
        ORDER BY day DESC LIMIT $2",
    )
    .bind(&id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let day: chrono::NaiveDate = row
            .try_get("day")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let units: f64 = row
            .try_get("units")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let storage_bytes: i64 = row
            .try_get("storage_bytes")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(ProjectCostDailyRow {
            day: day.to_string(),
            units,
            storage_bytes,
        });
    }

    Ok(Json(items))
}

async fn get_rca_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<GroupingDecisionStatsQuery>,
) -> Result<Json<RcaStatsResponse>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let window_minutes = query.window_minutes.unwrap_or(1440).max(1);
    let row = sqlx::query(
        "SELECT COALESCE(AVG(ii.confidence), 0)::float8 AS avg_confidence,\
            COALESCE(MIN(ii.confidence), 0)::float8 AS min_confidence,\
            COALESCE(MAX(ii.confidence), 0)::float8 AS max_confidence,\
            COUNT(*)::bigint AS count\
        FROM issue_insights ii\
        JOIN issues i ON i.id = ii.issue_id\
        WHERE i.project_id = $1 AND ii.updated_at > now() - make_interval(mins => $2)",
    )
    .bind(&id)
    .bind(window_minutes)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let avg_confidence: f64 = row
        .try_get("avg_confidence")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let min_confidence: f64 = row
        .try_get("min_confidence")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let max_confidence: f64 = row
        .try_get("max_confidence")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let count: i64 = row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(RcaStatsResponse {
        window_minutes,
        avg_confidence,
        min_confidence,
        max_confidence,
        count,
    }))
}

async fn get_rca_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<RcaPolicySummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let row = sqlx::query(
        "SELECT project_id, min_confidence, updated_at FROM rca_policies WHERE project_id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => {
            let now = Utc::now();
            return Ok(Json(RcaPolicySummary {
                project_id: id,
                min_confidence: 0.5,
                updated_at: now.to_rfc3339(),
            }));
        }
    };

    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let min_confidence: f64 = row
        .try_get("min_confidence")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let updated_at: DateTime<Utc> = row
        .try_get("updated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(RcaPolicySummary {
        project_id,
        min_confidence,
        updated_at: updated_at.to_rfc3339(),
    }))
}

async fn update_rca_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateRcaPolicyBody>,
) -> Result<Json<RcaPolicySummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let min_confidence = payload.min_confidence.unwrap_or(0.5).clamp(0.0, 1.0);

    let row = sqlx::query(
        "INSERT INTO rca_policies (project_id, min_confidence) VALUES ($1, $2)\
        ON CONFLICT (project_id) DO UPDATE SET\
            min_confidence = EXCLUDED.min_confidence,\
            updated_at = now()\
        RETURNING project_id, min_confidence, updated_at",
    )
    .bind(&id)
    .bind(min_confidence)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let updated_at: DateTime<Utc> = row
        .try_get("updated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.rca_policy.update",
        "project",
        Some(&id),
        Some(json!({ "min_confidence": min_confidence })),
        Some(&headers),
    )
    .await?;

    Ok(Json(RcaPolicySummary {
        project_id: id,
        min_confidence,
        updated_at: updated_at.to_rfc3339(),
    }))
}

async fn get_grouping_decision_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<GroupingDecisionStatsQuery>,
) -> Result<Json<GroupingDecisionStatsResponse>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let window_minutes = query.window_minutes.unwrap_or(1440).max(1);

    let reason_rows = sqlx::query(
        "SELECT reason AS key, COUNT(*)::bigint AS count\
        FROM grouping_decisions\
        WHERE project_id = $1 AND created_at > now() - make_interval(mins => $2)\
        GROUP BY reason ORDER BY count DESC",
    )
    .bind(&id)
    .bind(window_minutes)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut by_reason = Vec::with_capacity(reason_rows.len());
    for row in reason_rows {
        let key: String = row
            .try_get("key")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        by_reason.push(GroupingDecisionStatsRow { key, count });
    }

    let version_rows = sqlx::query(
        "SELECT algorithm_version AS key, COUNT(*)::bigint AS count\
        FROM grouping_decisions\
        WHERE project_id = $1 AND created_at > now() - make_interval(mins => $2)\
        GROUP BY algorithm_version ORDER BY count DESC",
    )
    .bind(&id)
    .bind(window_minutes)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut by_version = Vec::with_capacity(version_rows.len());
    for row in version_rows {
        let key: String = row
            .try_get("key")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        by_version.push(GroupingDecisionStatsRow { key, count });
    }

    Ok(Json(GroupingDecisionStatsResponse { by_reason, by_version }))
}

async fn list_grouping_decisions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<GroupingDecisionListQuery>,
) -> Result<Json<Vec<GroupingDecisionSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let limit = query.limit.unwrap_or(200).min(500) as i64;
    let rows = sqlx::query(
        "SELECT id, event_id, issue_id, fingerprint, algorithm_version, reason, created_at\
        FROM grouping_decisions WHERE project_id = $1\
        ORDER BY created_at DESC LIMIT $2",
    )
    .bind(&id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let decision_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let event_id: Uuid = row
            .try_get("event_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let issue_id: Uuid = row
            .try_get("issue_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let fingerprint: String = row
            .try_get("fingerprint")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let algorithm_version: String = row
            .try_get("algorithm_version")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let reason: String = row
            .try_get("reason")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(GroupingDecisionSummary {
            id: decision_id.to_string(),
            event_id: event_id.to_string(),
            issue_id: issue_id.to_string(),
            fingerprint,
            algorithm_version,
            reason,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn list_grouping_rules_applied(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, decision_id)): Path<(String, String)>,
) -> Result<Json<Vec<GroupingRuleAppliedSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let decision_uuid = Uuid::parse_str(&decision_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "decision_id invalide".to_string()))?;

    let rows = sqlx::query(
        "SELECT gra.id, gra.decision_id, gra.rule_id, gra.rule_name, gra.matched, gra.created_at\
        FROM grouping_rules_applied gra\
        JOIN grouping_decisions gd ON gd.id = gra.decision_id\
        WHERE gra.decision_id = $1 AND gd.project_id = $2\
        ORDER BY gra.created_at DESC",
    )
    .bind(decision_uuid)
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let decision_id: Uuid = row
            .try_get("decision_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let rule_id: Uuid = row
            .try_get("rule_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let rule_name: String = row
            .try_get("rule_name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let matched: bool = row
            .try_get("matched")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(GroupingRuleAppliedSummary {
            id: id.to_string(),
            decision_id: decision_id.to_string(),
            rule_id: rule_id.to_string(),
            rule_name,
            matched,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn list_ingest_drops(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ProjectCostQuery>,
) -> Result<Json<Vec<IngestDropRow>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let limit = query.limit.unwrap_or(30).min(365) as i64;
    let rows = sqlx::query(
        "SELECT day, reason, count\
        FROM ingest_drops_daily WHERE project_id = $1\
        ORDER BY day DESC, reason ASC LIMIT $2",
    )
    .bind(&id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let day: chrono::NaiveDate = row
            .try_get("day")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let reason: String = row
            .try_get("reason")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        items.push(IngestDropRow {
            day: day.to_string(),
            reason,
            count,
        });
    }

    Ok(Json(items))
}

async fn get_pii_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<PiiPolicySummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let policy = fetch_pii_policy_summary(&state.db, &id).await?;
    Ok(Json(policy))
}

async fn update_pii_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdatePiiPolicyBody>,
) -> Result<Json<PiiPolicySummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let current = fetch_pii_policy_summary(&state.db, &id).await?;
    let scrub_emails = payload.scrub_emails.unwrap_or(current.scrub_emails);
    let scrub_ips = payload.scrub_ips.unwrap_or(current.scrub_ips);
    let scrub_secrets = payload.scrub_secrets.unwrap_or(current.scrub_secrets);

    let row = sqlx::query(
        "INSERT INTO pii_policies (project_id, scrub_emails, scrub_ips, scrub_secrets)\
        VALUES ($1, $2, $3, $4)\
        ON CONFLICT (project_id) DO UPDATE SET\
            scrub_emails = EXCLUDED.scrub_emails,\
            scrub_ips = EXCLUDED.scrub_ips,\
            scrub_secrets = EXCLUDED.scrub_secrets,\
            updated_at = now()\
        RETURNING project_id, scrub_emails, scrub_ips, scrub_secrets, updated_at",
    )
    .bind(&id)
    .bind(scrub_emails)
    .bind(scrub_ips)
    .bind(scrub_secrets)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let updated_at: DateTime<Utc> = row
        .try_get("updated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.pii_policy.update",
        "project",
        Some(&id),
        Some(json!({
            "scrub_emails": scrub_emails,
            "scrub_ips": scrub_ips,
            "scrub_secrets": scrub_secrets
        })),
        Some(&headers),
    )
    .await?;

    Ok(Json(PiiPolicySummary {
        project_id: id,
        scrub_emails,
        scrub_ips,
        scrub_secrets,
        updated_at: updated_at.to_rfc3339(),
    }))
}

async fn fetch_pii_policy_summary(db: &PgPool, project_id: &str) -> Result<PiiPolicySummary, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT project_id, scrub_emails, scrub_ips, scrub_secrets, updated_at FROM pii_policies WHERE project_id = $1",
    )
    .bind(project_id)
    .fetch_optional(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    match row {
        Some(row) => {
            let project_id: String = row
                .try_get("project_id")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            let scrub_emails: bool = row
                .try_get("scrub_emails")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            let scrub_ips: bool = row
                .try_get("scrub_ips")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            let scrub_secrets: bool = row
                .try_get("scrub_secrets")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            let updated_at: DateTime<Utc> = row
                .try_get("updated_at")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

            Ok(PiiPolicySummary {
                project_id,
                scrub_emails,
                scrub_ips,
                scrub_secrets,
                updated_at: updated_at.to_rfc3339(),
            })
        }
        None => {
            let now = Utc::now();
            Ok(PiiPolicySummary {
                project_id: project_id.to_string(),
                scrub_emails: true,
                scrub_ips: true,
                scrub_secrets: true,
                updated_at: now.to_rfc3339(),
            })
        }
    }
}

async fn fetch_pii_policy_settings(db: &PgPool, project_id: &str) -> Result<PiiPolicySettings, (StatusCode, String)> {
    let summary = fetch_pii_policy_summary(db, project_id).await?;
    Ok(PiiPolicySettings {
        scrub_emails: summary.scrub_emails,
        scrub_ips: summary.scrub_ips,
        scrub_secrets: summary.scrub_secrets,
    })
}

async fn update_sampling_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateSamplingRuleBody>,
) -> Result<Json<SamplingRuleSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let target_events_per_min = payload.target_events_per_min.max(0);
    let min_rate = payload.min_rate.unwrap_or(0.1).clamp(0.0, 1.0);
    let max_rate = payload.max_rate.unwrap_or(1.0).clamp(0.0, 1.0);
    let (min_rate, max_rate) = if min_rate > max_rate { (max_rate, min_rate) } else { (min_rate, max_rate) };

    let row = sqlx::query(
        "INSERT INTO sampling_rules (project_id, target_events_per_min, min_rate, max_rate)\
        VALUES ($1, $2, $3, $4)\
        ON CONFLICT (project_id) DO UPDATE SET\
            target_events_per_min = EXCLUDED.target_events_per_min,\
            min_rate = EXCLUDED.min_rate,\
            max_rate = EXCLUDED.max_rate,\
            updated_at = now()\
        RETURNING project_id, target_events_per_min, min_rate, max_rate, updated_at",
    )
    .bind(&id)
    .bind(target_events_per_min)
    .bind(min_rate)
    .bind(max_rate)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let updated_at: DateTime<Utc> = row
        .try_get("updated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.sampling.update",
        "project",
        Some(&id),
        Some(json!({
            "target_events_per_min": target_events_per_min,
            "min_rate": min_rate,
            "max_rate": max_rate,
        })),
        Some(&headers),
    )
    .await?;

    Ok(Json(SamplingRuleSummary {
        project_id: id,
        target_events_per_min,
        min_rate,
        max_rate,
        updated_at: updated_at.to_rfc3339(),
    }))
}

async fn get_sla_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SlaPolicySummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let policy = fetch_sla_policy(&state.db, &id).await?;
    Ok(Json(policy))
}

async fn update_sla_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateSlaPolicyBody>,
) -> Result<Json<SlaPolicySummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let sla_minutes = payload.sla_minutes.max(1);

    let row = sqlx::query(
        "INSERT INTO sla_policies (project_id, sla_minutes) VALUES ($1, $2)\
        ON CONFLICT (project_id) DO UPDATE SET sla_minutes = EXCLUDED.sla_minutes, updated_at = now()\
        RETURNING project_id, sla_minutes, updated_at",
    )
    .bind(&id)
    .bind(sla_minutes)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let updated_at: DateTime<Utc> = row
        .try_get("updated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.sla_policy.update",
        "project",
        Some(&id),
        Some(json!({ "sla_minutes": sla_minutes })),
        Some(&headers),
    )
    .await?;

    Ok(Json(SlaPolicySummary {
        project_id: id,
        sla_minutes,
        updated_at: updated_at.to_rfc3339(),
    }))
}

async fn get_sla_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SlaReportSummary>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    if project_id != id {
        return Err((StatusCode::FORBIDDEN, "accès refusé".to_string()));
    }

    let policy = fetch_sla_policy(&state.db, &project_id).await?;
    let sla_minutes = policy.sla_minutes.max(1) as i64;

    let open_row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count FROM issues WHERE project_id = $1 AND status = 'open'",
    )
    .bind(&project_id)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let open_issues: i64 = open_row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let breach_row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count\
        FROM issues\
        WHERE project_id = $1 AND status = 'open'\
        AND first_seen < now() - make_interval(mins => $2)",
    )
    .bind(&project_id)
    .bind(sla_minutes)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let breaches: i64 = breach_row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let oldest_row = sqlx::query(
        "SELECT MIN(first_seen) AS oldest FROM issues WHERE project_id = $1 AND status = 'open'",
    )
    .bind(&project_id)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let oldest: Option<DateTime<Utc>> = oldest_row
        .try_get("oldest")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let oldest_open_minutes = oldest.map(|value| (Utc::now() - value).num_minutes().max(0));

    Ok(Json(SlaReportSummary {
        project_id,
        sla_minutes: sla_minutes as i32,
        open_issues,
        breaches,
        oldest_open_minutes,
        generated_at: Utc::now().to_rfc3339(),
    }))
}

async fn get_slo_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SloPolicySummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let policy = fetch_slo_policy(&state.db, &id).await?;
    Ok(Json(policy))
}

async fn update_slo_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateSloPolicyBody>,
) -> Result<Json<SloPolicySummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let target_error_rate = payload.target_error_rate.clamp(0.0, 1.0);
    let window_minutes = payload.window_minutes.unwrap_or(1440).max(1);

    let row = sqlx::query(
        "INSERT INTO slo_policies (project_id, target_error_rate, window_minutes) VALUES ($1, $2, $3)\
        ON CONFLICT (project_id) DO UPDATE SET target_error_rate = EXCLUDED.target_error_rate, window_minutes = EXCLUDED.window_minutes, updated_at = now()\
        RETURNING project_id, target_error_rate, window_minutes, updated_at",
    )
    .bind(&id)
    .bind(target_error_rate)
    .bind(window_minutes)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let updated_at: DateTime<Utc> = row
        .try_get("updated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.slo_policy.update",
        "project",
        Some(&id),
        Some(json!({ "target_error_rate": target_error_rate, "window_minutes": window_minutes })),
        Some(&headers),
    )
    .await?;

    Ok(Json(SloPolicySummary {
        project_id: id,
        target_error_rate,
        window_minutes,
        updated_at: updated_at.to_rfc3339(),
    }))
}

async fn get_slo_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SloReportSummary>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    let project_id = auth.project_id;

    if project_id != id {
        return Err((StatusCode::FORBIDDEN, "accès refusé".to_string()));
    }

    let policy = fetch_slo_policy(&state.db, &project_id).await?;
    let window_minutes = policy.window_minutes.max(1) as i64;

    let total_row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count\
        FROM transactions\
        WHERE project_id = $1 AND occurred_at > now() - make_interval(mins => $2)",
    )
    .bind(&project_id)
    .bind(window_minutes)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let total: i64 = total_row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let error_row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count\
        FROM transactions\
        WHERE project_id = $1 AND occurred_at > now() - make_interval(mins => $2) AND status <> 'ok'",
    )
    .bind(&project_id)
    .bind(window_minutes)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let errors: i64 = error_row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let error_rate = if total > 0 { errors as f64 / total as f64 } else { 0.0 };
    let budget_remaining_ratio = if policy.target_error_rate <= 0.0 {
        0.0
    } else {
        ((policy.target_error_rate - error_rate) / policy.target_error_rate).clamp(0.0, 1.0)
    };

    Ok(Json(SloReportSummary {
        project_id,
        target_error_rate: policy.target_error_rate,
        window_minutes: policy.window_minutes,
        total_transactions: total,
        error_transactions: errors,
        error_rate,
        budget_remaining_ratio,
        generated_at: Utc::now().to_rfc3339(),
    }))
}

async fn fetch_sla_policy(db: &PgPool, project_id: &str) -> Result<SlaPolicySummary, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT project_id, sla_minutes, updated_at FROM sla_policies WHERE project_id = $1",
    )
    .bind(project_id)
    .fetch_optional(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    match row {
        Some(row) => {
            let project_id: String = row
                .try_get("project_id")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            let sla_minutes: i32 = row
                .try_get("sla_minutes")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            let updated_at: DateTime<Utc> = row
                .try_get("updated_at")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            Ok(SlaPolicySummary {
                project_id,
                sla_minutes,
                updated_at: updated_at.to_rfc3339(),
            })
        }
        None => {
            let now = Utc::now();
            Ok(SlaPolicySummary {
                project_id: project_id.to_string(),
                sla_minutes: 1440,
                updated_at: now.to_rfc3339(),
            })
        }
    }
}

async fn fetch_slo_policy(db: &PgPool, project_id: &str) -> Result<SloPolicySummary, (StatusCode, String)> {
    let row = sqlx::query(
        "SELECT project_id, target_error_rate, window_minutes, updated_at FROM slo_policies WHERE project_id = $1",
    )
    .bind(project_id)
    .fetch_optional(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    match row {
        Some(row) => {
            let project_id: String = row
                .try_get("project_id")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            let target_error_rate: f64 = row
                .try_get("target_error_rate")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            let window_minutes: i32 = row
                .try_get("window_minutes")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            let updated_at: DateTime<Utc> = row
                .try_get("updated_at")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            Ok(SloPolicySummary {
                project_id,
                target_error_rate,
                window_minutes,
                updated_at: updated_at.to_rfc3339(),
            })
        }
        None => {
            let now = Utc::now();
            Ok(SloPolicySummary {
                project_id: project_id.to_string(),
                target_error_rate: 0.01,
                window_minutes: 1440,
                updated_at: now.to_rfc3339(),
            })
        }
    }
}

async fn get_storage_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<StoragePolicySummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let row = sqlx::query(
        "SELECT project_id, hot_days, cold_days, updated_at FROM storage_policies WHERE project_id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => {
            let now = Utc::now();
            return Ok(Json(StoragePolicySummary {
                project_id: id,
                hot_days: 30,
                cold_days: 365,
                updated_at: now.to_rfc3339(),
            }));
        }
    };

    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let hot_days: i32 = row
        .try_get("hot_days")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let cold_days: i32 = row
        .try_get("cold_days")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let updated_at: DateTime<Utc> = row
        .try_get("updated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(StoragePolicySummary {
        project_id,
        hot_days,
        cold_days,
        updated_at: updated_at.to_rfc3339(),
    }))
}

async fn update_storage_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateStoragePolicyBody>,
) -> Result<Json<StoragePolicySummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let hot_days = payload.hot_days.max(1);
    let cold_days = payload.cold_days.max(hot_days + 1);

    let row = sqlx::query(
        "INSERT INTO storage_policies (project_id, hot_days, cold_days)\
        VALUES ($1, $2, $3)\
        ON CONFLICT (project_id) DO UPDATE SET\
            hot_days = EXCLUDED.hot_days,\
            cold_days = EXCLUDED.cold_days,\
            updated_at = now()\
        RETURNING project_id, hot_days, cold_days, updated_at",
    )
    .bind(&id)
    .bind(hot_days)
    .bind(cold_days)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let updated_at: DateTime<Utc> = row
        .try_get("updated_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.storage_policy.update",
        "project",
        Some(&id),
        Some(json!({ "hot_days": hot_days, "cold_days": cold_days })),
        Some(&headers),
    )
    .await?;

    Ok(Json(StoragePolicySummary {
        project_id: id,
        hot_days,
        cold_days,
        updated_at: updated_at.to_rfc3339(),
    }))
}

async fn run_storage_tiering(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<StorageTierRunBody>,
) -> Result<Json<StorageTierRunSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let row = sqlx::query(
        "SELECT hot_days, cold_days FROM storage_policies WHERE project_id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let (hot_days, cold_days) = match row {
        Some(row) => (
            row.try_get::<i32, _>("hot_days")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
            row.try_get::<i32, _>("cold_days")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        ),
        None => (30, 365),
    };

    let hot_cutoff = Utc::now() - chrono::Duration::days(hot_days as i64);
    let cold_cutoff = Utc::now() - chrono::Duration::days(cold_days as i64);
    let dry_run = payload.dry_run.unwrap_or(false);

    let events_cold = count_tier_candidates(&state.db, "events", "occurred_at", &id, &hot_cutoff).await?;
    let transactions_cold = count_tier_candidates(&state.db, "transactions", "occurred_at", &id, &hot_cutoff).await?;
    let replays_cold = count_tier_candidates(&state.db, "replays", "created_at", &id, &hot_cutoff).await?;
    let profiles_cold = count_tier_candidates(&state.db, "profiles", "created_at", &id, &hot_cutoff).await?;

    let (mut events_deleted, mut transactions_deleted, mut replays_deleted, mut profiles_deleted) = (0, 0, 0, 0);

    if !dry_run {
        mark_cold(&state.db, "events", "occurred_at", &id, &hot_cutoff).await?;
        mark_cold(&state.db, "transactions", "occurred_at", &id, &hot_cutoff).await?;
        mark_cold(&state.db, "replays", "created_at", &id, &hot_cutoff).await?;
        mark_cold(&state.db, "profiles", "created_at", &id, &hot_cutoff).await?;

        events_deleted = delete_cold(&state.db, "events", "occurred_at", &id, &cold_cutoff).await?;
        transactions_deleted = delete_cold(&state.db, "transactions", "occurred_at", &id, &cold_cutoff).await?;
        replays_deleted = delete_cold(&state.db, "replays", "created_at", &id, &cold_cutoff).await?;
        profiles_deleted = delete_cold(&state.db, "profiles", "created_at", &id, &cold_cutoff).await?;
    }

    Ok(Json(StorageTierRunSummary {
        project_id: id,
        hot_cutoff: hot_cutoff.to_rfc3339(),
        cold_cutoff: cold_cutoff.to_rfc3339(),
        events_cold,
        transactions_cold,
        replays_cold,
        profiles_cold,
        events_deleted,
        transactions_deleted,
        replays_deleted,
        profiles_deleted,
    }))
}

async fn list_webhook_endpoints(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<WebhookEndpointSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT id, project_id, url, enabled, created_at FROM webhook_endpoints WHERE project_id = $1 ORDER BY created_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let endpoint_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let url: String = row
            .try_get("url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let enabled: bool = row
            .try_get("enabled")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(WebhookEndpointSummary {
            id: endpoint_id.to_string(),
            project_id,
            url,
            enabled,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn create_webhook_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateWebhookEndpointBody>,
) -> Result<Json<WebhookEndpointSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let url = payload.url.trim();
    if url.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "url manquante".to_string()));
    }
    let enabled = payload.enabled.unwrap_or(true);
    let secret = payload.secret.map(|value| value.trim().to_string()).filter(|value| !value.is_empty());

    let row = sqlx::query(
        "INSERT INTO webhook_endpoints (project_id, url, secret, enabled)\
        VALUES ($1, $2, $3, $4)\
        RETURNING id, project_id, url, enabled, created_at",
    )
    .bind(&id)
    .bind(url)
    .bind(&secret)
    .bind(enabled)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let endpoint_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let url: String = row
        .try_get("url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let enabled: bool = row
        .try_get("enabled")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "webhook_endpoint.create",
        "webhook_endpoint",
        Some(&endpoint_id.to_string()),
        Some(json!({ "project_id": id, "url": url })),
        Some(&headers),
    )
    .await?;

    Ok(Json(WebhookEndpointSummary {
        id: endpoint_id.to_string(),
        project_id,
        url,
        enabled,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn delete_webhook_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, webhook_id)): Path<(String, String)>,
) -> Result<&'static str, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let endpoint_id = Uuid::parse_str(&webhook_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "webhook_id invalide".to_string()))?;

    let result = sqlx::query(
        "DELETE FROM webhook_endpoints WHERE id = $1 AND project_id = $2",
    )
    .bind(endpoint_id)
    .bind(&project_id)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "webhook introuvable".to_string()));
    }

    insert_audit_log(
        &state.db,
        &actor,
        "webhook_endpoint.delete",
        "webhook_endpoint",
        Some(&webhook_id),
        Some(json!({ "project_id": project_id })),
        Some(&headers),
    )
    .await?;

    Ok("ok")
}

async fn list_webhook_deliveries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, webhook_id)): Path<(String, String)>,
    Query(query): Query<WebhookDeliveriesQuery>,
) -> Result<Json<Vec<WebhookDeliverySummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let endpoint_id = Uuid::parse_str(&webhook_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "webhook_id invalide".to_string()))?;
    let limit = query.limit.unwrap_or(50).min(200) as i64;

    let rows = sqlx::query(
        "SELECT d.id, d.status_code, d.error, d.created_at\
        FROM webhook_deliveries d\
        JOIN webhook_endpoints e ON e.id = d.endpoint_id\
        WHERE d.endpoint_id = $1 AND e.project_id = $2\
        ORDER BY d.created_at DESC\
        LIMIT $3",
    )
    .bind(endpoint_id)
    .bind(&project_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let delivery_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status_code: Option<i32> = row
            .try_get("status_code")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let error: Option<String> = row
            .try_get("error")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(WebhookDeliverySummary {
            id: delivery_id.to_string(),
            status_code,
            error,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn count_tier_candidates(
    db: &PgPool,
    table: &str,
    time_column: &str,
    project_id: &str,
    cutoff: &DateTime<Utc>,
) -> Result<i64, (StatusCode, String)> {
    let sql = format!(
        "SELECT COUNT(*)::bigint AS count FROM {table} WHERE project_id = $1 AND {time_column} < $2 AND storage_tier = 'hot'"
    );
    let row = sqlx::query(&sql)
        .bind(project_id)
        .bind(cutoff)
        .fetch_one(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let count: i64 = row
        .try_get("count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(count)
}

async fn mark_cold(
    db: &PgPool,
    table: &str,
    time_column: &str,
    project_id: &str,
    cutoff: &DateTime<Utc>,
) -> Result<(), (StatusCode, String)> {
    let sql = format!(
        "UPDATE {table} SET storage_tier = 'cold' WHERE project_id = $1 AND {time_column} < $2"
    );
    sqlx::query(&sql)
        .bind(project_id)
        .bind(cutoff)
        .execute(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(())
}

async fn delete_cold(
    db: &PgPool,
    table: &str,
    time_column: &str,
    project_id: &str,
    cutoff: &DateTime<Utc>,
) -> Result<i64, (StatusCode, String)> {
    let sql = format!(
        "DELETE FROM {table} WHERE project_id = $1 AND {time_column} < $2 AND storage_tier = 'cold'"
    );
    let result = sqlx::query(&sql)
        .bind(project_id)
        .bind(cutoff)
        .execute(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(result.rows_affected() as i64)
}

async fn list_releases(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ReleaseStatsQuery>,
) -> Result<Json<Vec<ReleaseSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let window_minutes = query.window_minutes.unwrap_or(1440).max(1);
    let total_events: i64 = sqlx::query(
        "SELECT COUNT(*)::bigint AS count\
        FROM events\
        WHERE project_id = $1\
        AND occurred_at > now() - make_interval(mins => $2)",
    )
    .bind(&id)
    .bind(window_minutes)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    .try_get("count")
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let rows = sqlx::query(
        "SELECT id, project_id, version, commit_count, created_at,\
        (SELECT COUNT(*)::bigint FROM events e WHERE e.project_id = $1 AND e.release = releases.version AND e.occurred_at > now() - make_interval(mins => $2)) AS events_24h,\
        (SELECT COUNT(*)::bigint FROM issues i WHERE i.project_id = $1 AND i.first_release = releases.version AND i.first_seen > now() - make_interval(mins => $2)) AS new_issues_24h,\
        (SELECT COUNT(*)::bigint FROM issues i WHERE i.project_id = $1 AND i.last_release = releases.version AND i.regressed_at > now() - make_interval(mins => $2)) AS regressions_24h\
        FROM releases\
        WHERE project_id = $1\
        ORDER BY created_at DESC",
    )
    .bind(&id)
    .bind(window_minutes)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let release_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let version: String = row
            .try_get("version")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let commit_count: i32 = row
            .try_get("commit_count")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let events_24h: i64 = row
            .try_get("events_24h")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let new_issues_24h: i64 = row
            .try_get("new_issues_24h")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let regressions_24h: i64 = row
            .try_get("regressions_24h")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let adoption_rate = if total_events > 0 {
            events_24h as f64 / total_events as f64
        } else {
            0.0
        };

        items.push(ReleaseSummary {
            id: release_id.to_string(),
            project_id,
            version,
            commit_count,
            adoption_rate,
            events_24h,
            new_issues_24h,
            regressions_24h,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn get_release_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, version)): Path<(String, String)>,
    Query(query): Query<ReleaseStatsQuery>,
) -> Result<Json<ReleaseSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let window_minutes = query.window_minutes.unwrap_or(1440).max(1);
    let total_events: i64 = sqlx::query(
        "SELECT COUNT(*)::bigint AS count\
        FROM events\
        WHERE project_id = $1\
        AND occurred_at > now() - make_interval(mins => $2)",
    )
    .bind(&id)
    .bind(window_minutes)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    .try_get("count")
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = sqlx::query(
        "SELECT id, project_id, version, commit_count, created_at,\
        (SELECT COUNT(*)::bigint FROM events e WHERE e.project_id = $1 AND e.release = $2 AND e.occurred_at > now() - make_interval(mins => $3)) AS events_24h,\
        (SELECT COUNT(*)::bigint FROM issues i WHERE i.project_id = $1 AND i.first_release = $2 AND i.first_seen > now() - make_interval(mins => $3)) AS new_issues_24h,\
        (SELECT COUNT(*)::bigint FROM issues i WHERE i.project_id = $1 AND i.last_release = $2 AND i.regressed_at > now() - make_interval(mins => $3)) AS regressions_24h\
        FROM releases\
        WHERE project_id = $1 AND version = $2",
    )
    .bind(&id)
    .bind(&version)
    .bind(window_minutes)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "release introuvable".to_string())),
    };

    let release_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let version: String = row
        .try_get("version")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let commit_count: i32 = row
        .try_get("commit_count")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let events_24h: i64 = row
        .try_get("events_24h")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let new_issues_24h: i64 = row
        .try_get("new_issues_24h")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let regressions_24h: i64 = row
        .try_get("regressions_24h")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let adoption_rate = if total_events > 0 {
        events_24h as f64 / total_events as f64
    } else {
        0.0
    };

    Ok(Json(ReleaseSummary {
        id: release_id.to_string(),
        project_id,
        version,
        commit_count,
        adoption_rate,
        events_24h,
        new_issues_24h,
        regressions_24h,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn list_release_regressions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, version)): Path<(String, String)>,
    Query(query): Query<ReleaseIssuesQuery>,
) -> Result<Json<Vec<ReleaseRegressionSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let limit = query.limit.unwrap_or(50).min(200) as i64;

    let rows = sqlx::query(
        "SELECT id, title, level, status, assignee, regressed_at, last_seen\
        FROM issues\
        WHERE project_id = $1\
        AND last_release = $2\
        AND regressed_at IS NOT NULL\
        ORDER BY regressed_at DESC\
        LIMIT $3",
    )
    .bind(&id)
    .bind(&version)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let issue_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let title: String = row
            .try_get("title")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let level: String = row
            .try_get("level")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let status: String = row
            .try_get("status")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let assignee: Option<String> = row
            .try_get("assignee")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let regressed_at: DateTime<Utc> = row
            .try_get("regressed_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_seen: DateTime<Utc> = row
            .try_get("last_seen")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(ReleaseRegressionSummary {
            id: issue_id.to_string(),
            title,
            level,
            status,
            assignee,
            regressed_at: regressed_at.to_rfc3339(),
            last_seen: last_seen.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn list_release_suspect_commits(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, version)): Path<(String, String)>,
) -> Result<Json<Vec<ReleaseCommitSuspect>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT rc.commit_sha, rc.message, rc.author, rc.timestamp,\
        COALESCE(stats.new_issues, 0) AS new_issues,\
        COALESCE(stats.regressions, 0) AS regressions\
        FROM release_commits rc\
        LEFT JOIN (\
            SELECT commit_sha,\
                SUM(CASE WHEN kind = 'new' THEN 1 ELSE 0 END)::bigint AS new_issues,\
                SUM(CASE WHEN kind = 'regression' THEN 1 ELSE 0 END)::bigint AS regressions\
            FROM (\
                SELECT rc_map.commit_sha, 'new' AS kind\
                FROM issues i\
                JOIN LATERAL (\
                    SELECT commit_sha\
                    FROM release_commits\
                    WHERE project_id = $1 AND release = $2\
                    AND timestamp IS NOT NULL\
                    AND timestamp <= i.first_seen\
                    ORDER BY timestamp DESC\
                    LIMIT 1\
                ) rc_map ON true\
                WHERE i.project_id = $1 AND i.first_release = $2\
                UNION ALL\
                SELECT rc_map.commit_sha, 'regression' AS kind\
                FROM issues i\
                JOIN LATERAL (\
                    SELECT commit_sha\
                    FROM release_commits\
                    WHERE project_id = $1 AND release = $2\
                    AND timestamp IS NOT NULL\
                    AND timestamp <= i.regressed_at\
                    ORDER BY timestamp DESC\
                    LIMIT 1\
                ) rc_map ON true\
                WHERE i.project_id = $1 AND i.last_release = $2 AND i.regressed_at IS NOT NULL\
            ) mapped\
            GROUP BY commit_sha\
        ) stats ON stats.commit_sha = rc.commit_sha\
        WHERE rc.project_id = $1 AND rc.release = $2\
        ORDER BY (COALESCE(stats.new_issues, 0) + COALESCE(stats.regressions, 0)) DESC, rc.timestamp DESC NULLS LAST",
    )
    .bind(&id)
    .bind(&version)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let commit_sha: String = row
            .try_get("commit_sha")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let message: Option<String> = row
            .try_get("message")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let author: Option<String> = row
            .try_get("author")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let timestamp: Option<DateTime<Utc>> = row
            .try_get("timestamp")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let new_issues: i64 = row
            .try_get("new_issues")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let regressions: i64 = row
            .try_get("regressions")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(ReleaseCommitSuspect {
            commit_sha,
            message,
            author,
            timestamp: timestamp.map(|value| value.to_rfc3339()),
            new_issues,
            regressions,
        });
    }

    Ok(Json(items))
}

async fn create_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateReleaseBody>,
) -> Result<Json<ReleaseSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let version = payload.version.trim();
    if version.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "version manquante".to_string()));
    }

    let row = sqlx::query(
        "INSERT INTO releases (project_id, version) VALUES ($1, $2)\
        ON CONFLICT (project_id, version) DO UPDATE SET version = EXCLUDED.version\
        RETURNING id, project_id, version, commit_count, created_at",
    )
    .bind(&id)
    .bind(version)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    if let Some(commits) = payload.commits {
        insert_release_commits(&state.db, &id, version, &commits).await?;
    }

    let release_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let commit_count: i32 = sqlx::query(
        "SELECT COUNT(*)::int AS count FROM release_commits WHERE project_id = $1 AND release = $2",
    )
    .bind(&id)
    .bind(version)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    .try_get("count")
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    sqlx::query("UPDATE releases SET commit_count = $1 WHERE project_id = $2 AND version = $3")
        .bind(commit_count)
        .bind(&id)
        .bind(version)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "release.create",
        "release",
        Some(version),
        Some(json!({ "project_id": id.clone(), "version": version })),
        Some(&headers),
    )
    .await?;

    Ok(Json(ReleaseSummary {
        id: release_id.to_string(),
        project_id: id,
        version: version.to_string(),
        commit_count,
        adoption_rate: 0.0,
        events_24h: 0,
        new_issues_24h: 0,
        regressions_24h: 0,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn add_release_commits(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, version)): Path<(String, String)>,
    Json(payload): Json<Vec<ReleaseCommitInput>>,
) -> Result<&'static str, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    if payload.is_empty() {
        return Ok("ok");
    }

    insert_release_commits(&state.db, &id, &version, &payload).await?;

    let commit_count: i32 = sqlx::query(
        "SELECT COUNT(*)::int AS count FROM release_commits WHERE project_id = $1 AND release = $2",
    )
    .bind(&id)
    .bind(&version)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    .try_get("count")
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    sqlx::query("UPDATE releases SET commit_count = $1 WHERE project_id = $2 AND version = $3")
        .bind(commit_count)
        .bind(&id)
        .bind(&version)
        .execute(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "release.commits.add",
        "release",
        Some(&version),
        Some(json!({ "project_id": id, "count": payload.len() })),
        Some(&headers),
    )
    .await?;

    Ok("ok")
}

async fn list_grouping_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<GroupingRuleSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT id, project_id, name, pattern, fingerprint, enabled, created_at\
        FROM grouping_rules\
        WHERE project_id = $1\
        ORDER BY created_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let rule_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let pattern: String = row
            .try_get("pattern")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let fingerprint: String = row
            .try_get("fingerprint")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let enabled: bool = row
            .try_get("enabled")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(GroupingRuleSummary {
            id: rule_id.to_string(),
            project_id,
            name,
            pattern,
            fingerprint,
            enabled,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn create_grouping_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateGroupingRuleBody>,
) -> Result<Json<GroupingRuleSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let name = payload.name.trim();
    let pattern = payload.pattern.trim();
    let fingerprint = payload.fingerprint.trim();
    if name.is_empty() || pattern.is_empty() || fingerprint.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "payload invalide".to_string()));
    }
    let enabled = payload.enabled.unwrap_or(true);

    let row = sqlx::query(
        "INSERT INTO grouping_rules (project_id, name, pattern, fingerprint, enabled)\
        VALUES ($1, $2, $3, $4, $5)\
        RETURNING id, project_id, name, pattern, fingerprint, enabled, created_at",
    )
    .bind(&id)
    .bind(name)
    .bind(pattern)
    .bind(fingerprint)
    .bind(enabled)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let rule_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "grouping_rule.create",
        "grouping_rule",
        Some(&rule_id.to_string()),
        Some(json!({ "project_id": id.clone(), "name": name })),
        Some(&headers),
    )
    .await?;

    Ok(Json(GroupingRuleSummary {
        id: rule_id.to_string(),
        project_id,
        name: name.to_string(),
        pattern: pattern.to_string(),
        fingerprint: fingerprint.to_string(),
        enabled,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn list_grouping_overrides(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<GroupingOverrideSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT id, project_id, source_fingerprint, target_fingerprint, reason, created_at\
        FROM grouping_overrides WHERE project_id = $1 ORDER BY created_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let override_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let source_fingerprint: String = row
            .try_get("source_fingerprint")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let target_fingerprint: String = row
            .try_get("target_fingerprint")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let reason: Option<String> = row
            .try_get("reason")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(GroupingOverrideSummary {
            id: override_id.to_string(),
            project_id,
            source_fingerprint,
            target_fingerprint,
            reason,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn create_grouping_override(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateGroupingOverrideBody>,
) -> Result<Json<GroupingOverrideSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let (source_fingerprint, target_fingerprint) = resolve_override_fingerprints(&state.db, &id, &payload).await?;
    if source_fingerprint == target_fingerprint {
        return Err((StatusCode::BAD_REQUEST, "override invalide".to_string()));
    }

    let reason = payload
        .reason
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let row = sqlx::query(
        "INSERT INTO grouping_overrides (project_id, source_fingerprint, target_fingerprint, reason)\
        VALUES ($1, $2, $3, $4)\
        ON CONFLICT (project_id, source_fingerprint) DO UPDATE SET\
            target_fingerprint = EXCLUDED.target_fingerprint,\
            reason = EXCLUDED.reason\
        RETURNING id, project_id, source_fingerprint, target_fingerprint, reason, created_at",
    )
    .bind(&id)
    .bind(&source_fingerprint)
    .bind(&target_fingerprint)
    .bind(&reason)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let override_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "grouping_override.upsert",
        "grouping_override",
        Some(&override_id.to_string()),
        Some(json!({
            "project_id": id,
            "source_fingerprint": source_fingerprint,
            "target_fingerprint": target_fingerprint,
            "reason": reason,
        })),
        Some(&headers),
    )
    .await?;

    Ok(Json(GroupingOverrideSummary {
        id: override_id.to_string(),
        project_id,
        source_fingerprint,
        target_fingerprint,
        reason,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn delete_grouping_override(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, override_id)): Path<(String, String)>,
) -> Result<&'static str, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let override_uuid = Uuid::parse_str(&override_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "override_id invalide".to_string()))?;

    let result = sqlx::query(
        "DELETE FROM grouping_overrides WHERE id = $1 AND project_id = $2",
    )
    .bind(override_uuid)
    .bind(&project_id)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "override introuvable".to_string()));
    }

    insert_audit_log(
        &state.db,
        &actor,
        "grouping_override.delete",
        "grouping_override",
        Some(&override_id),
        Some(json!({ "project_id": project_id })),
        Some(&headers),
    )
    .await?;

    Ok("ok")
}

async fn list_alert_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<AlertRuleSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT id, project_id, name, kind, threshold, window_minutes, cooldown_minutes, max_triggers_per_day, threshold_multiplier, baseline_minutes, channel, webhook_url, slack_webhook_url, email_to, enabled, last_triggered_at, created_at\
        FROM alert_rules\
        WHERE project_id = $1\
        ORDER BY created_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let rule_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let kind: String = row
            .try_get("kind")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let threshold: i32 = row
            .try_get("threshold")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let window_minutes: i32 = row
            .try_get("window_minutes")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let cooldown_minutes: i32 = row
            .try_get("cooldown_minutes")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let max_triggers_per_day: i32 = row
            .try_get("max_triggers_per_day")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let threshold_multiplier: Option<f64> = row
            .try_get("threshold_multiplier")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let baseline_minutes: Option<i32> = row
            .try_get("baseline_minutes")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let channel: String = row
            .try_get("channel")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let webhook_url: Option<String> = row
            .try_get("webhook_url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let slack_webhook_url: Option<String> = row
            .try_get("slack_webhook_url")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let email_to: Option<String> = row
            .try_get("email_to")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let enabled: bool = row
            .try_get("enabled")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_triggered_at: Option<DateTime<Utc>> = row
            .try_get("last_triggered_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(AlertRuleSummary {
            id: rule_id.to_string(),
            project_id,
            name,
            kind,
            threshold,
            window_minutes,
            cooldown_minutes,
            max_triggers_per_day,
            threshold_multiplier,
            baseline_minutes,
            channel,
            webhook_url,
            slack_webhook_url,
            email_to,
            enabled,
            last_triggered_at: last_triggered_at.map(|value| value.to_rfc3339()),
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn create_alert_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateAlertRuleBody>,
) -> Result<Json<AlertRuleSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let name = payload.name.trim();
    let channel = payload.channel.trim().to_lowercase();
    if name.is_empty() || channel.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "payload invalide".to_string()));
    }

    let kind = payload.kind.unwrap_or_else(|| "event_rate".to_string());
    let window_minutes = payload.window_minutes.unwrap_or(5).max(1);
    let enabled = payload.enabled.unwrap_or(true);

    let cooldown_minutes = payload.cooldown_minutes.unwrap_or(0).max(0);
    let max_triggers_per_day = payload.max_triggers_per_day.unwrap_or(0).max(0);
    let baseline_minutes = payload.baseline_minutes.filter(|value| *value > 0);
    let threshold_multiplier = payload.threshold_multiplier.filter(|value| *value > 1.0);

    let row = sqlx::query(
        "INSERT INTO alert_rules (project_id, name, kind, threshold, window_minutes, cooldown_minutes, max_triggers_per_day, threshold_multiplier, baseline_minutes, channel, webhook_url, slack_webhook_url, email_to, enabled)\
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)\
        RETURNING id, project_id, name, kind, threshold, window_minutes, cooldown_minutes, max_triggers_per_day, threshold_multiplier, baseline_minutes, channel, webhook_url, slack_webhook_url, email_to, enabled, last_triggered_at, created_at",
    )
    .bind(&id)
    .bind(name)
    .bind(&kind)
    .bind(payload.threshold)
    .bind(window_minutes)
    .bind(cooldown_minutes)
    .bind(max_triggers_per_day)
    .bind(threshold_multiplier)
    .bind(baseline_minutes)
    .bind(&channel)
    .bind(payload.webhook_url.as_deref())
    .bind(payload.slack_webhook_url.as_deref())
    .bind(payload.email_to.as_deref())
    .bind(enabled)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let rule_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let cooldown_minutes: i32 = row
        .try_get("cooldown_minutes")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let max_triggers_per_day: i32 = row
        .try_get("max_triggers_per_day")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let threshold_multiplier: Option<f64> = row
        .try_get("threshold_multiplier")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let baseline_minutes: Option<i32> = row
        .try_get("baseline_minutes")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let webhook_url: Option<String> = row
        .try_get("webhook_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let slack_webhook_url: Option<String> = row
        .try_get("slack_webhook_url")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let email_to: Option<String> = row
        .try_get("email_to")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_triggered_at: Option<DateTime<Utc>> = row
        .try_get("last_triggered_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "alert_rule.create",
        "alert_rule",
        Some(&rule_id.to_string()),
        Some(json!({ "project_id": id.clone(), "name": name })),
        Some(&headers),
    )
    .await?;

    Ok(Json(AlertRuleSummary {
        id: rule_id.to_string(),
        project_id,
        name: name.to_string(),
        kind,
        threshold: payload.threshold,
        window_minutes,
        cooldown_minutes,
        max_triggers_per_day,
        threshold_multiplier,
        baseline_minutes,
        channel,
        webhook_url,
        slack_webhook_url,
        email_to,
        enabled,
        last_triggered_at: last_triggered_at.map(|value| value.to_rfc3339()),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn list_alert_silences(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<AlertSilenceSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT id, project_id, rule_id, reason, starts_at, ends_at, created_at\
        FROM alert_silences WHERE project_id = $1 ORDER BY created_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let silence_id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let rule_id: Option<Uuid> = row
            .try_get("rule_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let reason: Option<String> = row
            .try_get("reason")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let starts_at: DateTime<Utc> = row
            .try_get("starts_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let ends_at: DateTime<Utc> = row
            .try_get("ends_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(AlertSilenceSummary {
            id: silence_id.to_string(),
            project_id,
            rule_id: rule_id.map(|value| value.to_string()),
            reason,
            starts_at: starts_at.to_rfc3339(),
            ends_at: ends_at.to_rfc3339(),
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn create_alert_silence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateAlertSilenceBody>,
) -> Result<Json<AlertSilenceSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let starts_at = DateTime::parse_from_rfc3339(payload.starts_at.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "starts_at invalide".to_string()))?
        .with_timezone(&Utc);
    let ends_at = DateTime::parse_from_rfc3339(payload.ends_at.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "ends_at invalide".to_string()))?
        .with_timezone(&Utc);
    if ends_at <= starts_at {
        return Err((StatusCode::BAD_REQUEST, "ends_at invalide".to_string()));
    }

    let rule_id = match payload.rule_id.as_deref() {
        Some(value) if !value.trim().is_empty() => Some(
            Uuid::parse_str(value)
                .map_err(|_| (StatusCode::BAD_REQUEST, "rule_id invalide".to_string()))?
        ),
        _ => None,
    };

    let reason = payload
        .reason
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let row = sqlx::query(
        "INSERT INTO alert_silences (project_id, rule_id, reason, starts_at, ends_at)\
        VALUES ($1, $2, $3, $4, $5)\
        RETURNING id, project_id, rule_id, reason, starts_at, ends_at, created_at",
    )
    .bind(&id)
    .bind(rule_id)
    .bind(&reason)
    .bind(starts_at)
    .bind(ends_at)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let silence_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let rule_id: Option<Uuid> = row
        .try_get("rule_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "alert_silence.create",
        "alert_silence",
        Some(&silence_id.to_string()),
        Some(json!({
            "project_id": id,
            "rule_id": rule_id.map(|value| value.to_string()),
            "starts_at": starts_at.to_rfc3339(),
            "ends_at": ends_at.to_rfc3339(),
            "reason": reason,
        })),
        Some(&headers),
    )
    .await?;

    Ok(Json(AlertSilenceSummary {
        id: silence_id.to_string(),
        project_id,
        rule_id: rule_id.map(|value| value.to_string()),
        reason,
        starts_at: starts_at.to_rfc3339(),
        ends_at: ends_at.to_rfc3339(),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn delete_alert_silence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, silence_id)): Path<(String, String)>,
) -> Result<&'static str, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let silence_uuid = Uuid::parse_str(&silence_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "silence_id invalide".to_string()))?;

    let result = sqlx::query(
        "DELETE FROM alert_silences WHERE id = $1 AND project_id = $2",
    )
    .bind(silence_uuid)
    .bind(&project_id)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "silence introuvable".to_string()));
    }

    insert_audit_log(
        &state.db,
        &actor,
        "alert_silence.delete",
        "alert_silence",
        Some(&silence_id),
        Some(json!({ "project_id": project_id })),
        Some(&headers),
    )
    .await?;

    Ok("ok")
}

async fn list_project_teams(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<ProjectTeamSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT pt.project_id, pt.team_id, t.name AS team_name, pt.created_at\
        FROM project_teams pt\
        JOIN teams t ON t.id = pt.team_id\
        WHERE pt.project_id = $1\
        ORDER BY pt.created_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let team_id: Uuid = row
            .try_get("team_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let team_name: String = row
            .try_get("team_name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(ProjectTeamSummary {
            project_id,
            team_id: team_id.to_string(),
            team_name,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn add_project_team(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<AddProjectTeamBody>,
) -> Result<Json<ProjectTeamSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let team_id = Uuid::parse_str(&payload.team_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "team_id invalide".to_string()))?;

    let row = sqlx::query(
        "INSERT INTO project_teams (project_id, team_id) VALUES ($1, $2)\
        ON CONFLICT (project_id, team_id) DO UPDATE SET created_at = EXCLUDED.created_at\
        RETURNING project_id, team_id, created_at",
    )
    .bind(&id)
    .bind(team_id)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let team_id: Uuid = row
        .try_get("team_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let team_name: String = sqlx::query("SELECT name FROM teams WHERE id = $1")
        .bind(team_id)
        .fetch_one(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "project.team.add",
        "project",
        Some(&project_id),
        Some(json!({ "team_id": team_id.to_string(), "team_name": team_name.clone() })),
        Some(&headers),
    )
    .await?;

    Ok(Json(ProjectTeamSummary {
        project_id,
        team_id: team_id.to_string(),
        team_name,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn list_orgs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OrgSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let rows = sqlx::query("SELECT id, name, sso_domain, data_region, created_at FROM organizations ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let sso_domain: Option<String> = row
            .try_get("sso_domain")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let data_region: Option<String> = row
            .try_get("data_region")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        items.push(OrgSummary {
            id: id.to_string(),
            name,
            sso_domain,
            data_region,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn create_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateOrgBody>,
) -> Result<Json<OrgSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let name = payload.name.trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name manquant".to_string()));
    }

    let row = sqlx::query("INSERT INTO organizations (name) VALUES ($1) RETURNING id, name, created_at")
        .bind(name)
        .fetch_one(&state.db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "org.create",
        "organization",
        Some(&id.to_string()),
        Some(json!({ "name": name })),
        Some(&headers),
    )
    .await?;

    Ok(Json(OrgSummary {
        id: id.to_string(),
        name: name.to_string(),
        sso_domain: None,
        data_region: None,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn update_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateOrgBody>,
) -> Result<Json<OrgSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let sso_domain = payload.sso_domain.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let data_region = payload.data_region.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());

    if let Some(region) = data_region.as_deref() {
        let exists = sqlx::query("SELECT 1 FROM regions WHERE name = $1 AND active = true")
            .bind(region)
            .fetch_optional(&state.db)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        if exists.is_none() {
            return Err((StatusCode::BAD_REQUEST, "data_region invalide".to_string()));
        }
    }

    let row = sqlx::query(
        "UPDATE organizations SET sso_domain = $1, data_region = $2 WHERE id = $3\
        RETURNING id, name, sso_domain, data_region, created_at",
    )
    .bind(&sso_domain)
    .bind(&data_region)
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "org introuvable".to_string())),
    };

    let name: String = row
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let sso_domain: Option<String> = row
        .try_get("sso_domain")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let data_region: Option<String> = row
        .try_get("data_region")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "org.update",
        "organization",
        Some(&id),
        Some(json!({ "sso_domain": sso_domain.clone(), "data_region": data_region.clone() })),
        Some(&headers),
    )
    .await?;

    Ok(Json(OrgSummary {
        id,
        name,
        sso_domain,
        data_region,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn list_org_teams(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<TeamSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;

    let rows = sqlx::query(
        "SELECT id, org_id, name, created_at FROM teams WHERE org_id = $1 ORDER BY created_at DESC",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let org_id: Uuid = row
            .try_get("org_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        items.push(TeamSummary {
            id: id.to_string(),
            org_id: org_id.to_string(),
            name,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn create_team(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateTeamBody>,
) -> Result<Json<TeamSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let org_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "org id invalide".to_string()))?;
    let name = payload.name.trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name manquant".to_string()));
    }

    let row = sqlx::query(
        "INSERT INTO teams (org_id, name) VALUES ($1, $2) RETURNING id, org_id, name, created_at",
    )
    .bind(org_id)
    .bind(name)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "team.create",
        "team",
        Some(&id.to_string()),
        Some(json!({ "org_id": org_id.to_string(), "name": name })),
        Some(&headers),
    )
    .await?;

    Ok(Json(TeamSummary {
        id: id.to_string(),
        org_id: org_id.to_string(),
        name: name.to_string(),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn list_team_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<UserSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let team_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "team id invalide".to_string()))?;

    let rows = sqlx::query(
        "SELECT u.id, u.email, tm.role, tm.created_at\
        FROM team_memberships tm\
        JOIN users u ON u.id = tm.user_id\
        WHERE tm.team_id = $1\
        ORDER BY tm.created_at DESC",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let email: String = row
            .try_get("email")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let role: String = row
            .try_get("role")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        items.push(UserSummary {
            id: id.to_string(),
            email,
            role,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn add_team_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<AddTeamUserBody>,
) -> Result<Json<UserSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let team_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "team id invalide".to_string()))?;
    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "email manquant".to_string()));
    }
    let role = payload
        .role
        .unwrap_or_else(|| "member".to_string())
        .to_lowercase();

    let user_row = sqlx::query(
        "INSERT INTO users (email) VALUES ($1)\
        ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email\
        RETURNING id, email, created_at",
    )
    .bind(&email)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let user_id: Uuid = user_row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = user_row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    sqlx::query(
        "INSERT INTO team_memberships (team_id, user_id, role) VALUES ($1, $2, $3)\
        ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role",
    )
    .bind(team_id)
    .bind(user_id)
    .bind(&role)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "team.user.add",
        "team",
        Some(&team_id.to_string()),
        Some(json!({ "user_id": user_id.to_string(), "email": email.clone(), "role": role.clone() })),
        Some(&headers),
    )
    .await?;

    Ok(Json(UserSummary {
        id: user_id.to_string(),
        email,
        role,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn list_team_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<TokenSummary>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let team_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "team id invalide".to_string()))?;

    let rows = sqlx::query(
        "SELECT id, team_id, token, role, created_by, last_used_at, revoked_at, created_at FROM api_tokens WHERE team_id = $1 ORDER BY created_at DESC",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let team_id: Uuid = row
            .try_get("team_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let token: String = row
            .try_get("token")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let role: String = row
            .try_get("role")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_by: Option<String> = row
            .try_get("created_by")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let last_used_at: Option<DateTime<Utc>> = row
            .try_get("last_used_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let revoked_at: Option<DateTime<Utc>> = row
            .try_get("revoked_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(TokenSummary {
            id: id.to_string(),
            team_id: team_id.to_string(),
            token,
            role,
            jwt: None,
            created_by,
            last_used_at: last_used_at.map(|value| value.to_rfc3339()),
            revoked_at: revoked_at.map(|value| value.to_rfc3339()),
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn list_saved_queries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<SavedQuerySummary>>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    if auth.project_id != id {
        return Err((StatusCode::UNAUTHORIZED, "accès refusé".to_string()));
    }

    let rows = sqlx::query(
        "SELECT id, project_id, name, query, created_at FROM saved_queries WHERE project_id = $1 ORDER BY created_at DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let project_id: String = row
            .try_get("project_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let query: String = row
            .try_get("query")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(SavedQuerySummary {
            id: id.to_string(),
            project_id,
            name,
            query,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn get_saved_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, query_id)): Path<(String, String)>,
) -> Result<Json<SavedQuerySummary>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    if auth.project_id != project_id {
        return Err((StatusCode::UNAUTHORIZED, "accès refusé".to_string()));
    }

    let query_uuid = Uuid::parse_str(&query_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "query_id invalide".to_string()))?;

    let row = sqlx::query(
        "SELECT id, project_id, name, query, created_at FROM saved_queries WHERE id = $1 AND project_id = $2",
    )
    .bind(query_uuid)
    .bind(&project_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "saved query introuvable".to_string())),
    };

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let name: String = row
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let query: String = row
        .try_get("query")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Json(SavedQuerySummary {
        id: id.to_string(),
        project_id,
        name,
        query,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn delete_saved_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, query_id)): Path<(String, String)>,
) -> Result<&'static str, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    if auth.project_id != project_id {
        return Err((StatusCode::UNAUTHORIZED, "accès refusé".to_string()));
    }
    require_project_scope(&auth, "project:write")?;

    let query_uuid = Uuid::parse_str(&query_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "query_id invalide".to_string()))?;

    let result = sqlx::query(
        "DELETE FROM saved_queries WHERE id = $1 AND project_id = $2",
    )
    .bind(query_uuid)
    .bind(&project_id)
    .execute(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "saved query introuvable".to_string()));
    }

    insert_audit_log(
        &state.db,
        &auth.actor,
        "saved_query.delete",
        "saved_query",
        Some(&query_id),
        Some(json!({ "project_id": project_id })),
        Some(&headers),
    )
    .await?;

    Ok("ok")
}

async fn create_saved_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<CreateSavedQueryBody>,
) -> Result<Json<SavedQuerySummary>, (StatusCode, String)> {
    let auth = authorize_project_access(&state.db, &headers).await?;
    if auth.project_id != id {
        return Err((StatusCode::UNAUTHORIZED, "accès refusé".to_string()));
    }
    require_project_scope(&auth, "project:write")?;

    let name = payload.name.trim();
    let query = payload.query.trim();
    if name.is_empty() || query.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "payload invalide".to_string()));
    }

    let row = sqlx::query(
        "INSERT INTO saved_queries (project_id, name, query) VALUES ($1, $2, $3) RETURNING id, project_id, name, query, created_at",
    )
    .bind(&id)
    .bind(name)
    .bind(query)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let project_id: String = row
        .try_get("project_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let name: String = row
        .try_get("name")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let query: String = row
        .try_get("query")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &auth.actor,
        "saved_query.create",
        "saved_query",
        Some(&id.to_string()),
        Some(json!({ "project_id": project_id.clone(), "name": name })),
        Some(&headers),
    )
    .await?;

    Ok(Json(SavedQuerySummary {
        id: id.to_string(),
        project_id,
        name,
        query,
        created_at: created_at.to_rfc3339(),
    }))
}

async fn create_team_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Option<Json<CreateTeamTokenBody>>,
) -> Result<Json<TokenSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let team_id = Uuid::parse_str(&id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "team id invalide".to_string()))?;
    let token = Uuid::new_v4().to_string();
    let role = payload
        .and_then(|value| value.0.role)
        .unwrap_or_else(|| "member".to_string())
        .to_lowercase();
    let role = normalize_role(&role)?;

    let row = sqlx::query(
        "INSERT INTO api_tokens (team_id, token, role, created_by) VALUES ($1, $2, $3, $4) RETURNING id, team_id, token, role, created_by, last_used_at, revoked_at, created_at",
    )
    .bind(team_id)
    .bind(&token)
    .bind(&role)
    .bind(&actor)
    .fetch_one(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let role: String = row
        .try_get("role")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_by: Option<String> = row
        .try_get("created_by")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_used_at: Option<DateTime<Utc>> = row
        .try_get("last_used_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let revoked_at: Option<DateTime<Utc>> = row
        .try_get("revoked_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let jwt = sign_jwt_token(&team_id, &id, &role)?;

    insert_audit_log(
        &state.db,
        &actor,
        "team.token.create",
        "team",
        Some(&team_id.to_string()),
        Some(json!({ "token_id": id.to_string() })),
        Some(&headers),
    )
    .await?;

    Ok(Json(TokenSummary {
        id: id.to_string(),
        team_id: team_id.to_string(),
        token,
        role,
        jwt: Some(jwt),
        created_by,
        last_used_at: last_used_at.map(|value| value.to_rfc3339()),
        revoked_at: revoked_at.map(|value| value.to_rfc3339()),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn revoke_team_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((team_id, token_id)): Path<(String, String)>,
) -> Result<Json<TokenSummary>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;
    let actor = get_admin_actor(&headers);

    let team_id = Uuid::parse_str(&team_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "team id invalide".to_string()))?;
    let token_id = Uuid::parse_str(&token_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "token id invalide".to_string()))?;

    let row = sqlx::query(
        "UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, now())\
        WHERE id = $1 AND team_id = $2\
        RETURNING id, team_id, token, role, created_by, last_used_at, revoked_at, created_at",
    )
    .bind(token_id)
    .bind(team_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "token introuvable".to_string())),
    };

    let id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let team_id: Uuid = row
        .try_get("team_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let token: String = row
        .try_get("token")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let role: String = row
        .try_get("role")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_by: Option<String> = row
        .try_get("created_by")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let last_used_at: Option<DateTime<Utc>> = row
        .try_get("last_used_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let revoked_at: Option<DateTime<Utc>> = row
        .try_get("revoked_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get("created_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    insert_audit_log(
        &state.db,
        &actor,
        "team.token.revoke",
        "team",
        Some(&team_id.to_string()),
        Some(json!({ "token_id": id.to_string() })),
        Some(&headers),
    )
    .await?;

    Ok(Json(TokenSummary {
        id: id.to_string(),
        team_id: team_id.to_string(),
        token,
        role,
        jwt: None,
        created_by,
        last_used_at: last_used_at.map(|value| value.to_rfc3339()),
        revoked_at: revoked_at.map(|value| value.to_rfc3339()),
        created_at: created_at.to_rfc3339(),
    }))
}

async fn list_my_projects(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProjectSummary>>, (StatusCode, String)> {
    let token_ctx = authorize_team_token(&state.db, &headers).await?;

    let rows = sqlx::query(
        "SELECT p.id, p.name, p.created_at\
        FROM project_teams pt\
        JOIN projects p ON p.id = pt.project_id\
        WHERE pt.team_id = $1\
        ORDER BY p.created_at DESC",
    )
    .bind(token_ctx.team_id)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row
            .try_get("id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let name: String = row
            .try_get("name")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(ProjectSummary {
            id,
            name,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
}

async fn list_audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<Vec<AuditLogEntry>>, (StatusCode, String)> {
    authorize_admin(&state.db, &headers).await?;

    let limit = query.limit.unwrap_or(100).min(500) as i64;
    let rows = sqlx::query(
        "SELECT actor, action, entity_type, entity_id, payload, ip, user_agent, request_id, created_at\
        FROM audit_log\
        ORDER BY created_at DESC\
        LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let actor: String = row
            .try_get("actor")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let action: String = row
            .try_get("action")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let entity_type: String = row
            .try_get("entity_type")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let entity_id: Option<String> = row
            .try_get("entity_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let payload: Option<Value> = row
            .try_get("payload")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let ip: Option<String> = row
            .try_get("ip")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let user_agent: Option<String> = row
            .try_get("user_agent")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let request_id: Option<String> = row
            .try_get("request_id")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        items.push(AuditLogEntry {
            actor,
            action,
            entity_type,
            entity_id,
            payload,
            ip,
            user_agent,
            request_id,
            created_at: created_at.to_rfc3339(),
        });
    }

    Ok(Json(items))
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

fn get_project_id(headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    let project_id = headers
        .get("x-ember-project")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string());

    match project_id {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err((StatusCode::UNAUTHORIZED, "project id manquant".to_string())),
    }
}

fn get_team_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-ember-token")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn get_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_role(role: &str) -> Result<String, (StatusCode, String)> {
    let normalized = role.trim().to_lowercase();
    if matches!(normalized.as_str(), "member" | "admin" | "owner") {
        Ok(normalized)
    } else {
        Err((StatusCode::BAD_REQUEST, "role invalide".to_string()))
    }
}

fn is_admin_role(role: &str) -> bool {
    matches!(role, "admin" | "owner")
}

fn role_scopes(role: &str) -> Vec<&'static str> {
    match role {
        "owner" => vec!["project:read", "project:triage", "project:write", "project:admin", "org:admin"],
        "admin" => vec!["project:read", "project:triage", "project:write", "project:admin"],
        _ => vec!["project:read", "project:triage"],
    }
}

fn role_has_scope(role: &str, scope: &str) -> bool {
    role_scopes(role).iter().any(|value| value == &scope)
}

fn require_project_scope(auth: &AuthContext, scope: &str) -> Result<(), (StatusCode, String)> {
    match auth.role.as_deref() {
        None => Ok(()),
        Some(role) => {
            if role_has_scope(role, scope) {
                Ok(())
            } else {
                Err((StatusCode::UNAUTHORIZED, "accès refusé".to_string()))
            }
        }
    }
}

fn looks_like_jwt(value: &str) -> bool {
    value.matches('.').count() == 2
}

fn get_admin_actor(headers: &HeaderMap) -> String {
    headers
        .get("x-ember-actor")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "admin".to_string())
}

fn extract_audit_meta(headers: Option<&HeaderMap>) -> AuditMeta {
    let headers = match headers {
        Some(value) => value,
        None => {
            return AuditMeta {
                ip: None,
                user_agent: None,
                request_id: None,
            }
        }
    };

    let forwarded_for = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').next().unwrap_or("").trim().to_string())
        .filter(|value| !value.is_empty());

    let real_ip = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let user_agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    AuditMeta {
        ip: forwarded_for.or(real_ip),
        user_agent,
        request_id,
    }
}

fn extract_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let forwarded_for = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let real_ip = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    forwarded_for
        .or(real_ip)
        .and_then(|value| value.parse::<IpAddr>().ok())
}

fn parse_admin_allowlist(value: &str) -> Result<Vec<IpNet>, (StatusCode, String)> {
    let mut entries = Vec::new();
    for raw in value.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        let entry = trimmed.parse::<IpNet>()
            .or_else(|_| trimmed.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "ADMIN_ALLOWED_IPS invalide".to_string()))?;
        entries.push(entry);
    }

    Ok(entries)
}

fn verify_admin_totp(secret: &str, code: &str) -> Result<bool, (StatusCode, String)> {
    let cleaned = secret
        .trim()
        .replace(' ', "")
        .replace('-', "")
        .to_uppercase();
    if cleaned.is_empty() {
        return Ok(false);
    }

    let secret_bytes = BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "ADMIN_TOTP_SECRET invalide".to_string()))?;

    let trimmed = code.trim();
    if trimmed.len() < 6 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }

    let now = Utc::now().timestamp().max(0) as u64;
    let step = 30u64;
    for offset in [-30i64, 0, 30] {
        let ts = if offset.is_negative() {
            now.saturating_sub(offset.wrapping_abs() as u64)
        } else {
            now.saturating_add(offset as u64)
        };
        let candidate = totp_at(&secret_bytes, ts, step, 6)?;
        if candidate == trimmed {
            return Ok(true);
        }
    }

    Ok(false)
}

fn totp_at(secret: &[u8], timestamp: u64, step: u64, digits: u32) -> Result<String, (StatusCode, String)> {
    let counter = timestamp / step;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "TOTP init failed".to_string()))?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let binary = ((result[offset] & 0x7f) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);
    let modulo = 10u32.pow(digits);
    let otp = binary % modulo;
    Ok(format!("{:0width$}", otp, width = digits as usize))
}

fn enforce_admin_security(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    if let Ok(value) = env::var("ADMIN_ALLOWED_IPS") {
        let value = value.trim();
        if !value.is_empty() {
            let client_ip = extract_client_ip(headers)
                .ok_or((StatusCode::UNAUTHORIZED, "admin ip introuvable".to_string()))?;
            let allowlist = parse_admin_allowlist(value)?;
            if !allowlist.iter().any(|net| net.contains(&client_ip)) {
                return Err((StatusCode::UNAUTHORIZED, "admin ip refusée".to_string()));
            }
        }
    }

    if let Ok(secret) = env::var("ADMIN_TOTP_SECRET") {
        if !secret.trim().is_empty() {
            let otp = headers
                .get("x-ember-otp")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.trim().to_string());
            let otp = otp.ok_or((StatusCode::UNAUTHORIZED, "admin otp manquant".to_string()))?;
            if !verify_admin_totp(&secret, &otp)? {
                return Err((StatusCode::UNAUTHORIZED, "admin otp invalide".to_string()));
            }
        }
    }

    Ok(())
}

async fn authorize_admin(db: &PgPool, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let admin_key = headers
        .get("x-ember-admin")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string());

    let secret = env::var("EMBER_SECRET").unwrap_or_default();
    if secret.is_empty() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "EMBER_SECRET manquant".to_string()));
    }

    if matches!(admin_key, Some(value) if value == secret) {
        enforce_admin_security(headers)?;
        return Ok(());
    }

    if let Some(bearer) = get_bearer_token(headers) {
        if looks_like_jwt(&bearer) {
            let claims = decode_jwt_claims(&bearer)?;
            if !is_admin_role(&claims.role) {
                return Err((StatusCode::UNAUTHORIZED, "admin key invalide".to_string()));
            }

            let token_id = Uuid::parse_str(&claims.token_id)
                .map_err(|_| (StatusCode::UNAUTHORIZED, "token invalide".to_string()))?;
            let team_id = Uuid::parse_str(&claims.team_id)
                .map_err(|_| (StatusCode::UNAUTHORIZED, "token invalide".to_string()))?;

            let row = sqlx::query("SELECT role FROM api_tokens WHERE id = $1 AND team_id = $2")
                .bind(token_id)
                .bind(team_id)
                .fetch_optional(db)
                .await
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

            let row = match row {
                Some(row) => row,
                None => return Err((StatusCode::UNAUTHORIZED, "token invalide".to_string())),
            };

            let role: String = row
                .try_get("role")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

            if !is_admin_role(&role) {
                return Err((StatusCode::UNAUTHORIZED, "admin key invalide".to_string()));
            }

            enforce_admin_security(headers)?;
            return Ok(());
        }
    }

    Err((StatusCode::UNAUTHORIZED, "admin key invalide".to_string()))
}

fn decode_jwt_claims(token: &str) -> Result<AccessClaims, (StatusCode, String)> {
    let secret = env::var("EMBER_JWT_SECRET").unwrap_or_default();
    if secret.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMBER_JWT_SECRET manquant".to_string(),
        ));
    }

    let validation = Validation::default();
    decode::<AccessClaims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation)
        .map(|data| data.claims)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "token invalide".to_string()))
}

fn sign_jwt_token(
    team_id: &Uuid,
    token_id: &Uuid,
    role: &str,
) -> Result<String, (StatusCode, String)> {
    let secret = env::var("EMBER_JWT_SECRET").unwrap_or_default();
    if secret.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMBER_JWT_SECRET manquant".to_string(),
        ));
    }

    let now = Utc::now().timestamp();
    let exp = now + 60 * 60 * 24 * 30;
    let claims = AccessClaims {
        sub: token_id.to_string(),
        team_id: team_id.to_string(),
        token_id: token_id.to_string(),
        role: role.to_string(),
        scopes: Some(role_scopes(role).into_iter().map(|value| value.to_string()).collect()),
        iat: now.max(0) as usize,
        exp: exp.max(0) as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
}

async fn authorize_project(
    db: &PgPool,
    project_id: &str,
    api_key: &str,
) -> Result<(), (StatusCode, String)> {
    let row = sqlx::query("SELECT api_key FROM projects WHERE id = $1")
        .bind(project_id)
        .fetch_optional(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::UNAUTHORIZED, "project inconnu".to_string())),
    };

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

    Ok(())
}

async fn authorize_team_token(
    db: &PgPool,
    headers: &HeaderMap,
) -> Result<TeamTokenContext, (StatusCode, String)> {
    if let Some(bearer) = get_bearer_token(headers) {
        if looks_like_jwt(&bearer) {
            let claims = decode_jwt_claims(&bearer)?;
            let token_id = Uuid::parse_str(&claims.token_id)
                .map_err(|_| (StatusCode::UNAUTHORIZED, "token invalide".to_string()))?;
            let team_id = Uuid::parse_str(&claims.team_id)
                .map_err(|_| (StatusCode::UNAUTHORIZED, "token invalide".to_string()))?;

            let row = sqlx::query("SELECT id, team_id, role, revoked_at FROM api_tokens WHERE id = $1 AND team_id = $2")
                .bind(token_id)
                .bind(team_id)
                .fetch_optional(db)
                .await
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

            let row = match row {
                Some(row) => row,
                None => return Err((StatusCode::UNAUTHORIZED, "token invalide".to_string())),
            };

            let role: String = row
                .try_get("role")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
            let revoked_at: Option<DateTime<Utc>> = row
                .try_get("revoked_at")
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

            if revoked_at.is_some() {
                return Err((StatusCode::UNAUTHORIZED, "token révoqué".to_string()));
            }

            sqlx::query("UPDATE api_tokens SET last_used_at = now() WHERE id = $1")
                .bind(token_id)
                .execute(db)
                .await
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

            return Ok(TeamTokenContext {
                team_id,
                token_id,
                actor: format!("team:{} token:{}", team_id, token_id),
                role,
            });
        }

        return resolve_team_token_from_value(db, &bearer).await;
    }

    let token = get_team_token(headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, "token manquant".to_string())
    })?;

    resolve_team_token_from_value(db, &token).await
}

async fn resolve_team_token_from_value(
    db: &PgPool,
    token: &str,
) -> Result<TeamTokenContext, (StatusCode, String)> {
    let row = sqlx::query("SELECT id, team_id, role, revoked_at FROM api_tokens WHERE token = $1")
        .bind(token)
        .fetch_optional(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::UNAUTHORIZED, "token invalide".to_string())),
    };

    let token_id: Uuid = row
        .try_get("id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let team_id: Uuid = row
        .try_get("team_id")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let role: String = row
        .try_get("role")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let revoked_at: Option<DateTime<Utc>> = row
        .try_get("revoked_at")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    if revoked_at.is_some() {
        return Err((StatusCode::UNAUTHORIZED, "token révoqué".to_string()));
    }

    sqlx::query("UPDATE api_tokens SET last_used_at = now() WHERE id = $1")
        .bind(token_id)
        .execute(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(TeamTokenContext {
        team_id,
        token_id,
        actor: format!("team:{} token:{}", team_id, token_id),
        role,
    })
}

async fn authorize_project_access(
    db: &PgPool,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    let project_id = get_project_id(headers)?;
    if get_team_token(headers).is_some() || get_bearer_token(headers).is_some() {
        let token_ctx = authorize_team_token(db, headers).await?;

        let access = sqlx::query("SELECT 1 FROM project_teams WHERE project_id = $1 AND team_id = $2")
            .bind(&project_id)
            .bind(token_ctx.team_id)
            .fetch_optional(db)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        if access.is_none() {
            return Err((StatusCode::UNAUTHORIZED, "accès refusé".to_string()));
        }

        return Ok(AuthContext {
            project_id,
            actor: token_ctx.actor.clone(),
            team_id: Some(token_ctx.team_id),
            token_id: Some(token_ctx.token_id),
            role: Some(token_ctx.role),
        });
    }

    let api_key = get_api_key(headers)?;
    authorize_project(db, &project_id, &api_key).await?;

    Ok(AuthContext {
        project_id: project_id.clone(),
        actor: format!("project:{}", project_id),
        team_id: None,
        token_id: None,
        role: None,
    })
}

async fn insert_audit_log(
    db: &PgPool,
    actor: &str,
    action: &str,
    entity_type: &str,
    entity_id: Option<&str>,
    payload: Option<Value>,
    headers: Option<&HeaderMap>,
) -> Result<(), (StatusCode, String)> {
    let meta = extract_audit_meta(headers);
    sqlx::query(
        "INSERT INTO audit_log (actor, action, entity_type, entity_id, payload, ip, user_agent, request_id)\
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(actor)
    .bind(action)
    .bind(entity_type)
    .bind(entity_id)
    .bind(payload)
    .bind(meta.ip)
    .bind(meta.user_agent)
    .bind(meta.request_id)
    .execute(db)
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(())
}

fn parse_optional_timestamp(value: Option<&str>) -> Result<Option<DateTime<Utc>>, (StatusCode, String)> {
    if let Some(raw) = value {
        let parsed = DateTime::parse_from_rfc3339(raw)
            .map_err(|_| (StatusCode::BAD_REQUEST, "timestamp invalide".to_string()))?
            .with_timezone(&Utc);
        Ok(Some(parsed))
    } else {
        Ok(None)
    }
}

fn parse_discover_cursor(value: Option<&str>) -> Result<Option<(DateTime<Utc>, Uuid)>, (StatusCode, String)> {
    let raw = match value {
        Some(raw) if !raw.trim().is_empty() => raw.trim(),
        _ => return Ok(None),
    };

    let parts: Vec<&str> = raw.split('|').collect();
    if parts.len() != 2 {
        return Err((StatusCode::BAD_REQUEST, "cursor invalide".to_string()));
    }

    let ts = DateTime::parse_from_rfc3339(parts[0])
        .map_err(|_| (StatusCode::BAD_REQUEST, "cursor invalide".to_string()))?
        .with_timezone(&Utc);
    let id = Uuid::parse_str(parts[1])
        .map_err(|_| (StatusCode::BAD_REQUEST, "cursor invalide".to_string()))?;

    Ok(Some((ts, id)))
}

fn format_discover_cursor(occurred_at: &str, event_id: &str) -> String {
    format!("{}|{}", occurred_at, event_id)
}

async fn resolve_saved_query(
    db: &PgPool,
    project_id: &str,
    saved_query_id: Option<&str>,
    q: Option<&str>,
) -> Result<Option<String>, (StatusCode, String)> {
    if let Some(raw) = q.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()) {
        return Ok(Some(raw));
    }

    let saved_query_id = match saved_query_id {
        Some(value) if !value.trim().is_empty() => value.trim(),
        _ => return Ok(None),
    };

    let query_uuid = Uuid::parse_str(saved_query_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "saved_query_id invalide".to_string()))?;

    let row = sqlx::query("SELECT query FROM saved_queries WHERE id = $1 AND project_id = $2")
        .bind(query_uuid)
        .bind(project_id)
        .fetch_optional(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    let row = match row {
        Some(row) => row,
        None => return Err((StatusCode::NOT_FOUND, "saved query introuvable".to_string())),
    };

    let query: String = row
        .try_get("query")
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

    Ok(Some(query))
}

async fn resolve_override_fingerprints(
    db: &PgPool,
    project_id: &str,
    payload: &CreateGroupingOverrideBody,
) -> Result<(String, String), (StatusCode, String)> {
    if let (Some(source_id), Some(target_id)) = (payload.source_issue_id.as_deref(), payload.target_issue_id.as_deref()) {
        let source_uuid = Uuid::parse_str(source_id)
            .map_err(|_| (StatusCode::BAD_REQUEST, "source_issue_id invalide".to_string()))?;
        let target_uuid = Uuid::parse_str(target_id)
            .map_err(|_| (StatusCode::BAD_REQUEST, "target_issue_id invalide".to_string()))?;

        let source_row = sqlx::query("SELECT fingerprint FROM issues WHERE id = $1 AND project_id = $2")
            .bind(source_uuid)
            .bind(project_id)
            .fetch_optional(db)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let target_row = sqlx::query("SELECT fingerprint FROM issues WHERE id = $1 AND project_id = $2")
            .bind(target_uuid)
            .bind(project_id)
            .fetch_optional(db)
            .await
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;

        let source_row = source_row.ok_or((StatusCode::NOT_FOUND, "source issue introuvable".to_string()))?;
        let target_row = target_row.ok_or((StatusCode::NOT_FOUND, "target issue introuvable".to_string()))?;

        let source_fp: String = source_row
            .try_get("fingerprint")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let target_fp: String = target_row
            .try_get("fingerprint")
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        return Ok((source_fp, target_fp));
    }

    let source_fp = payload
        .source_fingerprint
        .as_deref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or((StatusCode::BAD_REQUEST, "source_fingerprint manquant".to_string()))?;
    let target_fp = payload
        .target_fingerprint
        .as_deref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or((StatusCode::BAD_REQUEST, "target_fingerprint manquant".to_string()))?;

    Ok((source_fp, target_fp))
}

async fn insert_release_commits(
    db: &PgPool,
    project_id: &str,
    version: &str,
    commits: &[ReleaseCommitInput],
) -> Result<(), (StatusCode, String)> {
    for commit in commits {
        let sha = commit.commit_sha.trim();
        if sha.is_empty() {
            continue;
        }
        let timestamp = parse_optional_timestamp(commit.timestamp.as_deref())?;
        sqlx::query(
            "INSERT INTO release_commits (project_id, release, commit_sha, message, author, timestamp)\
            VALUES ($1, $2, $3, $4, $5, $6)\
            ON CONFLICT (project_id, release, commit_sha) DO NOTHING",
        )
        .bind(project_id)
        .bind(version)
        .bind(sha)
        .bind(commit.message.as_deref())
        .bind(commit.author.as_deref())
        .bind(timestamp)
        .execute(db)
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    }

    Ok(())
}

fn html_escape(value: &str) -> String {
    let re = Regex::new(r#"[&<>"]"#).unwrap();
    re.replace_all(value, |caps: &regex::Captures| match &caps[0] {
        "&" => "&amp;",
        "<" => "&lt;",
        ">" => "&gt;",
        "\"" => "&quot;",
        _ => "",
    })
    .into_owned()
}

fn validate_sso_payload(
    provider: &str,
    payload: &UpsertSsoConfigBody,
) -> Result<(), (StatusCode, String)> {
    match provider {
        "saml" => {
            if payload.saml_metadata.as_deref().unwrap_or("").trim().is_empty() {
                return Err((StatusCode::BAD_REQUEST, "saml_metadata manquant".to_string()));
            }
        }
        "oidc" => {
            if payload.oidc_client_id.as_deref().unwrap_or("").trim().is_empty()
                || payload.oidc_issuer_url.as_deref().unwrap_or("").trim().is_empty()
                || payload.oidc_client_secret.as_deref().unwrap_or("").trim().is_empty()
            {
                return Err((StatusCode::BAD_REQUEST, "oidc fields manquants".to_string()));
            }
        }
        _ => {
            return Err((StatusCode::BAD_REQUEST, "provider invalide".to_string()));
        }
    }

    Ok(())
}

async fn normalize_saml_metadata(
    saml_metadata: Option<&str>,
) -> Result<Option<String>, (StatusCode, String)> {
    let raw = saml_metadata.unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(None);
    }

    if raw.starts_with("http://") || raw.starts_with("https://") {
        let client = Client::new();
        let response = client
            .get(raw)
            .send()
            .await
            .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
        let text = response
            .text()
            .await
            .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
        if !text.contains("EntityDescriptor") {
            return Err((StatusCode::BAD_REQUEST, "metadata SAML invalide".to_string()));
        }
        return Ok(Some(text));
    }

    if !raw.contains("EntityDescriptor") {
        return Err((StatusCode::BAD_REQUEST, "metadata SAML invalide".to_string()));
    }

    Ok(Some(raw.to_string()))
}
