use clap::{Parser, Subcommand, ValueEnum};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{PgPool, Postgres, QueryBuilder, Row};
use std::env;
use std::fs::File;
use std::io::{self, Write};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "ember-admin", version, about = "EMBER admin CLI")]
struct Cli {
    #[arg(long)]
    database_url: Option<String>,

    #[arg(long, default_value_t = false)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Rotate a project's API key
    RotateProjectKey {
        #[arg(long)]
        project_id: String,
        #[arg(long)]
        actor: Option<String>,
    },

    /// Export audit log entries
    AuditExport {
        #[arg(long, value_enum, default_value = "json")]
        format: ExportFormat,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        limit: Option<i64>,
    },

    /// Replay jobs from the DLQ
    ReplayDlq {
        #[arg(long)]
        limit: Option<i64>,
        #[arg(long)]
        project_id: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = true)]
        reset_attempts: bool,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long)]
        actor: Option<String>,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum ExportFormat {
    Json,
    Csv,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    let database_url = cli
        .database_url
        .or_else(|| env::var("DATABASE_URL").ok())
        .ok_or("DATABASE_URL is required")?;

    let pool = PgPool::connect(&database_url).await?;

    match cli.command {
        Commands::RotateProjectKey { project_id, actor } => {
            let new_key = rotate_project_key(&pool, &project_id, actor).await?;
            if !cli.quiet {
                println!("rotated api key for project {project_id}: {new_key}");
            }
        }
        Commands::AuditExport {
            format,
            output,
            since,
            limit,
        } => {
            export_audit_log(&pool, format, output, since, limit, cli.quiet).await?;
        }
        Commands::ReplayDlq {
            limit,
            project_id,
            kind,
            reset_attempts,
            dry_run,
            actor,
        } => {
            let count = replay_dlq(&pool, limit, project_id, kind, reset_attempts, dry_run, actor).await?;
            if !cli.quiet {
                if dry_run {
                    println!("{count} dead jobs would be replayed");
                } else {
                    println!("{count} dead jobs replayed");
                }
            }
        }
    }

    Ok(())
}

async fn rotate_project_key(
    pool: &PgPool,
    project_id: &str,
    actor: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let api_key = Uuid::new_v4().to_string();
    let row = sqlx::query(
        "UPDATE projects SET api_key = $1, api_key_rotated_at = now() WHERE id = $2 RETURNING api_key",
    )
    .bind(&api_key)
    .bind(project_id)
    .fetch_one(pool)
    .await?;

    let actor = resolve_actor(actor);
    let payload = json!({"project_id": project_id});
    insert_audit_log(pool, &actor, "project.rotate_key", "project", Some(project_id), Some(payload)).await?;

    Ok(row.try_get("api_key")?)
}

async fn export_audit_log(
    pool: &PgPool,
    format: ExportFormat,
    output: Option<String>,
    since: Option<String>,
    limit: Option<i64>,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let since_dt = match since {
        Some(value) => Some(parse_datetime(&value)?),
        None => None,
    };

    let mut builder: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT id, actor, action, entity_type, entity_id, payload, ip, user_agent, request_id, created_at FROM audit_log",
    );

    if let Some(since_dt) = since_dt {
        builder.push(" WHERE created_at >= ").push_bind(since_dt);
    }

    builder.push(" ORDER BY created_at DESC");
    if let Some(limit) = limit {
        builder.push(" LIMIT ").push_bind(limit);
    }

    let rows = builder.build().fetch_all(pool).await?;
    let row_count = rows.len();

    match format {
        ExportFormat::Json => {
            let mut entries = Vec::with_capacity(rows.len());
            for row in rows.iter() {
                let payload: Option<serde_json::Value> = row.try_get("payload")?;
                entries.push(json!({
                    "id": row.try_get::<Uuid, _>("id")?.to_string(),
                    "actor": row.try_get::<String, _>("actor")?,
                    "action": row.try_get::<String, _>("action")?,
                    "entity_type": row.try_get::<String, _>("entity_type")?,
                    "entity_id": row.try_get::<Option<String>, _>("entity_id")?,
                    "payload": payload,
                    "ip": row.try_get::<Option<String>, _>("ip")?,
                    "user_agent": row.try_get::<Option<String>, _>("user_agent")?,
                    "request_id": row.try_get::<Option<String>, _>("request_id")?,
                    "created_at": row.try_get::<DateTime<Utc>, _>("created_at")?.to_rfc3339(),
                }));
            }
            let json_out = serde_json::to_string_pretty(&entries)?;
            write_output(output, json_out.as_bytes())?;
        }
        ExportFormat::Csv => {
            let writer: Box<dyn Write> = match output {
                Some(path) => Box::new(File::create(path)?),
                None => Box::new(io::stdout()),
            };
            let mut csv = csv::Writer::from_writer(writer);
            csv.write_record([
                "id",
                "actor",
                "action",
                "entity_type",
                "entity_id",
                "payload",
                "ip",
                "user_agent",
                "request_id",
                "created_at",
            ])?;

            for row in rows.iter() {
                let payload: Option<serde_json::Value> = row.try_get("payload")?;
                csv.write_record([
                    row.try_get::<Uuid, _>("id")?.to_string(),
                    row.try_get::<String, _>("actor")?,
                    row.try_get::<String, _>("action")?,
                    row.try_get::<String, _>("entity_type")?,
                    row.try_get::<Option<String>, _>("entity_id")?.unwrap_or_default(),
                    payload.map(|p| p.to_string()).unwrap_or_default(),
                    row.try_get::<Option<String>, _>("ip")?.unwrap_or_default(),
                    row.try_get::<Option<String>, _>("user_agent")?.unwrap_or_default(),
                    row.try_get::<Option<String>, _>("request_id")?.unwrap_or_default(),
                    row.try_get::<DateTime<Utc>, _>("created_at")?.to_rfc3339(),
                ])?;
            }
            csv.flush()?;
        }
    }

    if !quiet {
        println!("exported {} audit log entries", row_count);
    }

    Ok(())
}

async fn replay_dlq(
    pool: &PgPool,
    limit: Option<i64>,
    project_id: Option<String>,
    kind: Option<String>,
    reset_attempts: bool,
    dry_run: bool,
    actor: Option<String>,
) -> Result<u64, Box<dyn std::error::Error>> {
    if dry_run {
        let mut builder: QueryBuilder<Postgres> = QueryBuilder::new("SELECT count(*)::bigint as total FROM jobs WHERE status = 'dead'");
        if let Some(project_id) = &project_id {
            builder.push(" AND project_id = ").push_bind(project_id);
        }
        if let Some(kind) = &kind {
            builder.push(" AND kind = ").push_bind(kind);
        }
        let row = builder.build().fetch_one(pool).await?;
        let total: i64 = row.try_get("total")?;
        return Ok(total as u64);
    }

    let mut builder: QueryBuilder<Postgres> = QueryBuilder::new(
        "UPDATE jobs SET status = 'pending', run_at = now(), dead_at = NULL, last_error = NULL",
    );
    if reset_attempts {
        builder.push(", attempts = 0");
    }
    builder.push(" WHERE status = 'dead'");
    if let Some(project_id) = &project_id {
        builder.push(" AND project_id = ").push_bind(project_id);
    }
    if let Some(kind) = &kind {
        builder.push(" AND kind = ").push_bind(kind);
    }
    if let Some(limit) = limit {
        builder.push(" AND id IN (SELECT id FROM jobs WHERE status = 'dead'");
        if let Some(project_id) = &project_id {
            builder.push(" AND project_id = ").push_bind(project_id);
        }
        if let Some(kind) = &kind {
            builder.push(" AND kind = ").push_bind(kind);
        }
        builder.push(" ORDER BY dead_at DESC NULLS LAST LIMIT ").push_bind(limit);
        builder.push(")");
    }

    let result = builder.build().execute(pool).await?;
    let affected = result.rows_affected();

    let actor = resolve_actor(actor);
    let payload = json!({
        "project_id": project_id,
        "kind": kind,
        "limit": limit,
        "reset_attempts": reset_attempts,
        "replayed": affected
    });
    insert_audit_log(pool, &actor, "jobs.replay_dlq", "jobs", None, Some(payload)).await?;

    Ok(affected)
}

async fn insert_audit_log(
    pool: &PgPool,
    actor: &str,
    action: &str,
    entity_type: &str,
    entity_id: Option<&str>,
    payload: Option<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        "INSERT INTO audit_log (actor, action, entity_type, entity_id, payload) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(actor)
    .bind(action)
    .bind(entity_type)
    .bind(entity_id)
    .bind(payload)
    .execute(pool)
    .await?;
    Ok(())
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    let parsed = DateTime::parse_from_rfc3339(value)?;
    Ok(parsed.with_timezone(&Utc))
}

fn resolve_actor(actor: Option<String>) -> String {
    actor
        .filter(|value| !value.trim().is_empty())
        .or_else(|| env::var("ADMIN_ACTOR").ok())
        .unwrap_or_else(|| "admin-cli".to_string())
}

fn write_output(path: Option<String>, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    match path {
        Some(path) => {
            let mut file = File::create(path)?;
            file.write_all(data)?;
        }
        None => {
            let mut stdout = io::stdout();
            stdout.write_all(data)?;
        }
    }
    Ok(())
}
