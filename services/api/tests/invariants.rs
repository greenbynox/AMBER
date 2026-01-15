use chrono::{Duration, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

async fn connect_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run invariant tests");
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("connect to database");
    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
    pool
}

async fn insert_project(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, project_id: &str) {
    sqlx::query("INSERT INTO projects (id, name, api_key) VALUES ($1, $2, $3)")
        .bind(project_id)
        .bind(project_id)
        .bind("test-key")
        .execute(&mut **tx)
        .await
        .expect("insert project");
}

#[tokio::test]
#[ignore]
async fn invariant_no_ghost_data_violation_detected() {
    let pool = connect_db().await;
    let mut tx = pool.begin().await.expect("begin tx");

    let project_id = "inv-ghost";
    insert_project(&mut tx, project_id).await;

    let issue_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO issues (id, project_id, fingerprint, title, level, first_seen, last_seen, count_total) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1)",
    )
    .bind(issue_id)
    .bind(project_id)
    .bind("fp-ghost")
    .bind("ghost issue")
    .bind("error")
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("insert issue");

    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count \
         FROM issues i \
         LEFT JOIN events e ON e.issue_id = i.id \
         WHERE i.project_id = $1 AND e.id IS NULL",
    )
    .bind(project_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count ghost issues");

    let count: i64 = row.try_get("count").expect("count column");
    assert!(count >= 1, "expected ghost issue violation to be detected");

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
#[ignore]
async fn invariant_monotonic_counters_violation_detected() {
    let pool = connect_db().await;
    let mut tx = pool.begin().await.expect("begin tx");

    let project_id = "inv-monotonic";
    insert_project(&mut tx, project_id).await;

    let issue_id = Uuid::new_v4();
    let now = Utc::now();
    let earlier = now - Duration::days(1);

    sqlx::query(
        "INSERT INTO issues (id, project_id, fingerprint, title, level, first_seen, last_seen, count_total) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1)",
    )
    .bind(issue_id)
    .bind(project_id)
    .bind("fp-monotonic")
    .bind("monotonic issue")
    .bind("error")
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("insert issue");

    sqlx::query("UPDATE issues SET last_seen = $1 WHERE id = $2")
        .bind(earlier)
        .bind(issue_id)
        .execute(&mut *tx)
        .await
        .expect("regress last_seen");

    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count \
         FROM issues \
         WHERE project_id = $1 AND last_seen < first_seen",
    )
    .bind(project_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count regressions");

    let count: i64 = row.try_get("count").expect("count column");
    assert!(count >= 1, "expected monotonic violation to be detected");

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
#[ignore]
async fn invariant_write_once_fields_violation_detected() {
    let pool = connect_db().await;
    let mut tx = pool.begin().await.expect("begin tx");

    let project_id = "inv-write-once";
    insert_project(&mut tx, project_id).await;

    let issue_id = Uuid::new_v4();
    let now = Utc::now();
    let future = now + Duration::days(1);

    sqlx::query(
        "INSERT INTO issues (id, project_id, fingerprint, title, level, first_seen, last_seen, count_total) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1)",
    )
    .bind(issue_id)
    .bind(project_id)
    .bind("fp-write-once")
    .bind("write-once issue")
    .bind("error")
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("insert issue");

    sqlx::query("UPDATE issues SET first_seen = $1 WHERE id = $2")
        .bind(future)
        .bind(issue_id)
        .execute(&mut *tx)
        .await
        .expect("mutate first_seen");

    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS count \
         FROM issues \
         WHERE project_id = $1 AND first_seen > last_seen",
    )
    .bind(project_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count write-once violations");

    let count: i64 = row.try_get("count").expect("count column");
    assert!(count >= 1, "expected write-once violation to be detected");

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
#[ignore]
async fn invariant_no_dangling_signal_links_scaffold() {
    let pool = connect_db().await;
    let mut tx = pool.begin().await.expect("begin tx");

    let row = sqlx::query(
        "SELECT EXISTS (\
            SELECT 1 FROM information_schema.tables \
            WHERE table_name = 'signal_links'\
        ) AS exists",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("check signal_links existence");

    let exists: bool = row.try_get("exists").expect("exists column");
    if !exists {
        tx.rollback().await.expect("rollback");
        return;
    }

    // TODO: insert a dangling signal_links row and assert detection query > 0.
    tx.rollback().await.expect("rollback");
}
