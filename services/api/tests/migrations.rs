use sqlx::Executor;

#[tokio::test]
#[ignore]
async fn migrations_apply_on_clean_db() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run migration tests");

    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("connect to database");

    // Reset schema to ensure migrations apply from a clean slate.
    pool.execute("DROP SCHEMA public CASCADE;")
        .await
        .expect("drop public schema");
    pool.execute("CREATE SCHEMA public;")
        .await
        .expect("recreate public schema");

    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .expect("apply migrations");
}
