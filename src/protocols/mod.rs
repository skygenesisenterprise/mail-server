pub mod imap;
pub mod pop3;
pub mod smtp;

use crate::error::Result;
use crate::protocols::ProtocolServer;
use sqlx::PgPool;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

#[async_trait::async_trait]
pub trait ProtocolServer {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
}

#[derive(Clone)]
pub struct ServerContext {
    pub db_pool: PgPool,
    pub tls_acceptor: Arc<TlsAcceptor>,
}

impl ServerContext {
    pub fn new(db_pool: PgPool, tls_acceptor: Arc<TlsAcceptor>) -> Self {
        Self {
            db_pool,
            tls_acceptor,
        }
    }
}
