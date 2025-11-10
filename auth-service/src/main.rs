use std::sync::Arc;
use sqlx::PgPool;
use tokio::sync::RwLock;
use auth_service::{Application, app_state::AppState, get_postgres_pool, get_redis_client, 
    services::data_stores::{MockEmailClient, PostgresUserStore, RedisBannedTokenStore, RedisTwoFACodeStore}, 
    utils::{constants::{DATABASE_URL, REDIS_HOST_NAME, prod}, 
    tracing::init_tracing
}};

#[tokio::main]
async fn main() {
    init_tracing().expect("Failed to initialize tracing"); // Updated!
    color_eyre::install().expect("Failed to install color_eyre"); // New!
    let pg_pool = configure_postgresql().await;
    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(Arc::new(RwLock::new(configure_redis())))));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(Arc::new(RwLock::new(configure_redis())))));
    let email_client = Arc::new(RwLock::new(MockEmailClient));
    let app_state = AppState { user_store, banned_token_store, two_fa_code_store, email_client };

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database! 
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}