use anyhow::Result;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod auth;
mod config;
mod domain;
mod error;
mod protocols;
mod storage;
mod storage;
mod tls;

use api::ApiServer;
use config::Config;
use protocols::{imap::ImapServer, pop3::Pop3Server, smtp::SmtpServer};
use storage::Database;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_mail_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Rust Mail Server");

    // Load configuration
    let config = Config::load().await?;
    info!("Configuration loaded successfully");

    let database = Database::new(&config.database.url).await?;
    info!("Database connection established");

    let db_pool = database.pool().clone();

    // Run database migrations
    storage::run_migrations(&db_pool).await?;
    info!("Database migrations completed");

    database.health_check().await?;
    info!("Database health check passed");

    // Initialize TLS configuration
    let tls_config = tls::load_tls_config(&config.tls).await?;
    info!("TLS configuration loaded");

    // Start protocol servers concurrently
    let smtp_server = SmtpServer::new(config.smtp.clone(), db_pool.clone(), tls_config.clone());
    let imap_server = ImapServer::new(config.imap.clone(), db_pool.clone(), tls_config.clone());
    let pop3_server = Pop3Server::new(config.pop3.clone(), db_pool.clone(), tls_config.clone());
    let api_server = ApiServer::new(config.api.clone(), db_pool.clone(), tls_config.clone());

    info!("Starting protocol servers and HTTP API...");

    tokio::try_join!(
        smtp_server.start(),
        imap_server.start(),
        pop3_server.start(),
        api_server.start(),
    )?;

    Ok(())
}
