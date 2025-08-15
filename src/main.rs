use anyhow::Result;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod auth;
mod storage;
mod protocols;
mod domain;
mod tls;
mod api;

use config::Config;
use protocols::{smtp::SmtpServer, imap::ImapServer, pop3::Pop3Server};
use api::ApiServer;

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

    // Initialize database connection pool
    let db_pool = storage::init_database(&config.database).await?;
    info!("Database connection established");

    // Run database migrations
    storage::run_migrations(&db_pool).await?;
    info!("Database migrations completed");

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
