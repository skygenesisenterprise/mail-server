use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub tls: TlsConfig,
    pub smtp: SmtpConfig,
    pub imap: ImapConfig,
    pub pop3: Pop3Config,
    pub api: ApiConfig, // Added API configuration
    pub powerdns: PowerDnsConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub hostname: String,
    pub max_connections: usize,
    pub connection_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_cert_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub bind_address: String,
    pub port: u16,
    pub tls_port: u16,
    pub max_message_size: usize,
    pub require_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapConfig {
    pub bind_address: String,
    pub port: u16,
    pub tls_port: u16,
    pub idle_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pop3Config {
    pub bind_address: String,
    pub port: u16,
    pub tls_port: u16,
    pub session_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
    pub jwt_secret: String,
    pub cors_origins: Vec<String>,
    pub rate_limit_requests: u32,
    pub rate_limit_window: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerDnsConfig {
    pub api_url: String,
    pub api_key: String,
    pub default_ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub password_hash_cost: u32,
    pub session_timeout: u64,
    pub max_login_attempts: u32,
    pub lockout_duration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub mail_storage_path: String,
    pub max_mailbox_size: u64,
    pub cleanup_interval: u64,
}

impl Config {
    pub async fn load() -> Result<Self> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());

        if !Path::new(&config_path).exists() {
            Self::create_default_config(&config_path).await?;
        }

        let config_content = fs::read_to_string(&config_path).await?;
        let config: Config = toml::from_str(&config_content)?;

        Ok(config)
    }

    async fn create_default_config(path: &str) -> Result<()> {
        let default_config = Config {
            server: ServerConfig {
                hostname: "localhost".to_string(),
                max_connections: 1000,
                connection_timeout: 300,
            },
            database: DatabaseConfig {
                url: "postgresql://mailserver:password@localhost/mailserver".to_string(),
                max_connections: 20,
                min_connections: 5,
                connection_timeout: 30,
            },
            tls: TlsConfig {
                cert_path: "certs/server.crt".to_string(),
                key_path: "certs/server.key".to_string(),
                ca_cert_path: None,
            },
            smtp: SmtpConfig {
                bind_address: "0.0.0.0".to_string(),
                port: 25,
                tls_port: 465,
                max_message_size: 25 * 1024 * 1024, // 25MB
                require_tls: true,
            },
            imap: ImapConfig {
                bind_address: "0.0.0.0".to_string(),
                port: 143,
                tls_port: 993,
                idle_timeout: 1800, // 30 minutes
            },
            pop3: Pop3Config {
                bind_address: "0.0.0.0".to_string(),
                port: 110,
                tls_port: 995,
                session_timeout: 600, // 10 minutes
            },
            api: ApiConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                jwt_secret: "your-super-secret-jwt-key-change-this-in-production".to_string(),
                cors_origins: vec![
                    "http://localhost:3000".to_string(),
                    "https://yourdomain.com".to_string(),
                ],
                rate_limit_requests: 100,
                rate_limit_window: 60, // 1 minute
            },
            powerdns: PowerDnsConfig {
                api_url: "http://localhost:8081".to_string(),
                api_key: "your-powerdns-api-key".to_string(),
                default_ttl: 3600,
            },
            auth: AuthConfig {
                password_hash_cost: 12,
                session_timeout: 3600,
                max_login_attempts: 5,
                lockout_duration: 900, // 15 minutes
            },
            storage: StorageConfig {
                mail_storage_path: "/var/mail".to_string(),
                max_mailbox_size: 1024 * 1024 * 1024, // 1GB
                cleanup_interval: 86400,              // 24 hours
            },
        };

        let config_content = toml::to_string_pretty(&default_config)?;
        fs::write(path, config_content).await?;

        Ok(())
    }
}
