use axum::{
    extract::State,
    http::{HeaderValue, Method},
    middleware,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, error};

use crate::{config::ApiConfig, error::MailServerError, tls::TlsConfig};

pub mod auth;
pub mod mailboxes;
pub mod messages;
pub mod users;
pub mod domains;
pub mod admin;
pub mod middleware as api_middleware;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: ApiConfig,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
}

pub struct ApiServer {
    config: ApiConfig,
    db_pool: PgPool,
    tls_config: Option<Arc<rustls::ServerConfig>>,
}

impl ApiServer {
    pub fn new(
        config: ApiConfig,
        db_pool: PgPool,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> Self {
        Self {
            config,
            db_pool,
            tls_config,
        }
    }

    pub async fn start(self) -> Result<(), MailServerError> {
        let state = AppState {
            db: self.db_pool,
            config: self.config.clone(),
            tls_config: self.tls_config,
        };

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers(Any)
            .allow_origin(
                self.config
                    .cors_origins
                    .iter()
                    .map(|origin| origin.parse::<HeaderValue>().unwrap())
                    .collect::<Vec<_>>(),
            );

        let app = Router::new()
            // Health check
            .route("/health", get(health_check))
            
            // Authentication routes
            .route("/api/v1/auth/login", post(auth::login))
            .route("/api/v1/auth/logout", post(auth::logout))
            .route("/api/v1/auth/refresh", post(auth::refresh_token))
            .route("/api/v1/auth/me", get(auth::get_current_user))
            
            // User management routes
            .route("/api/v1/users", get(users::list_users))
            .route("/api/v1/users", post(users::create_user))
            .route("/api/v1/users/:id", get(users::get_user))
            .route("/api/v1/users/:id", put(users::update_user))
            .route("/api/v1/users/:id", delete(users::delete_user))
            .route("/api/v1/users/:id/password", put(users::change_password))
            
            // Mailbox routes
            .route("/api/v1/mailboxes", get(mailboxes::list_mailboxes))
            .route("/api/v1/mailboxes", post(mailboxes::create_mailbox))
            .route("/api/v1/mailboxes/:id", get(mailboxes::get_mailbox))
            .route("/api/v1/mailboxes/:id", put(mailboxes::update_mailbox))
            .route("/api/v1/mailboxes/:id", delete(mailboxes::delete_mailbox))
            .route("/api/v1/mailboxes/:id/messages", get(mailboxes::list_messages))
            
            // Message routes
            .route("/api/v1/messages", post(messages::send_message))
            .route("/api/v1/messages/:id", get(messages::get_message))
            .route("/api/v1/messages/:id", put(messages::update_message))
            .route("/api/v1/messages/:id", delete(messages::delete_message))
            .route("/api/v1/messages/:id/attachments", get(messages::get_attachments))
            .route("/api/v1/messages/search", post(messages::search_messages))
            
            // Domain routes
            .route("/api/v1/domains", get(domains::list_domains))
            .route("/api/v1/domains", post(domains::create_domain))
            .route("/api/v1/domains/:id", get(domains::get_domain))
            .route("/api/v1/domains/:id", put(domains::update_domain))
            .route("/api/v1/domains/:id", delete(domains::delete_domain))
            .route("/api/v1/domains/:id/verify", post(domains::verify_domain))
            
            // Admin routes
            .route("/api/v1/admin/stats", get(admin::get_server_stats))
            .route("/api/v1/admin/logs", get(admin::get_logs))
            .route("/api/v1/admin/config", get(admin::get_config))
            .route("/api/v1/admin/config", put(admin::update_config))
            
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(cors)
                    .layer(middleware::from_fn_with_state(
                        state.clone(),
                        api_middleware::auth_middleware,
                    ))
                    .layer(middleware::from_fn_with_state(
                        state.clone(),
                        api_middleware::rate_limit_middleware,
                    )),
            )
            .with_state(state);

        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            MailServerError::Io(format!("Failed to bind to {}: {}", addr, e))
        })?;

        info!("HTTP API server listening on {}", addr);

        axum::serve(listener, app).await.map_err(|e| {
            MailServerError::Io(format!("HTTP API server error: {}", e))
        })?;

        Ok(())
    }
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "rust-mail-server"
    }))
}
