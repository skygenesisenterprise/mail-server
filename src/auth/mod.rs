pub mod password;
pub mod session;
pub mod rate_limit;
pub mod security;
pub mod totp;

use crate::error::{MailServerError, Result};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use tracing::{info, warn, error};

// Re-export commonly used types
pub use password::PasswordManager;
pub use session::{Session, SessionManager};
pub use rate_limit::{RateLimiter, RateLimitEntry};
pub use security::{SecurityLogger, SecurityEvent, SecurityEventType};

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub domain_id: Uuid,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub active: bool,
    pub two_factor_enabled: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
}

pub struct AuthService {
    db_pool: PgPool,
    password_manager: PasswordManager,
    rate_limiter: RateLimiter,
    session_manager: SessionManager,
    security_logger: SecurityLogger,
}

impl AuthService {
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            password_manager: PasswordManager::new(db_pool.clone()),
            rate_limiter: RateLimiter::new(),
            session_manager: SessionManager::new(db_pool.clone()),
            security_logger: SecurityLogger::new(db_pool.clone()),
            db_pool,
        }
    }
    
    pub async fn authenticate(&self, email: &str, password: &str, ip_address: Option<String>) -> Result<Option<User>> {
        // Check rate limiting
        if self.rate_limiter.is_rate_limited(email, &ip_address).await? {
            self.security_logger.log_event(
                None,
                SecurityEventType::LoginFailure,
                ip_address.clone(),
                None,
                Some("Rate limited".to_string()),
            ).await?;
            return Err(MailServerError::RateLimitExceeded);
        }

        let row = sqlx::query!(
            "SELECT id, email, password_hash, domain_id, quota_bytes, used_bytes, active, 
             two_factor_enabled, last_login, failed_login_attempts, locked_until
             FROM users WHERE email = $1",
            email
        )
        .fetch_optional(&self.db_pool)
        .await?;
        
        if let Some(row) = row {
            // Check if account is locked
            if let Some(locked_until) = row.locked_until {
                if locked_until > Utc::now() {
                    self.security_logger.log_event(
                        Some(row.id),
                        SecurityEventType::LoginFailure,
                        ip_address,
                        None,
                        Some("Account locked".to_string()),
                    ).await?;
                    return Ok(None);
                }
            }

            // Check if account is active
            if !row.active {
                self.security_logger.log_event(
                    Some(row.id),
                    SecurityEventType::LoginFailure,
                    ip_address,
                    None,
                    Some("Account inactive".to_string()),
                ).await?;
                return Ok(None);
            }

            if self.password_manager.verify_password(password, &row.password_hash)? {
                // Successful authentication
                self.rate_limiter.reset_attempts(email, &ip_address).await?;
                self.update_last_login(row.id).await?;
                
                let user = User {
                    id: row.id,
                    email: row.email.clone(),
                    domain_id: row.domain_id,
                    quota_bytes: row.quota_bytes,
                    used_bytes: row.used_bytes,
                    active: row.active,
                    two_factor_enabled: row.two_factor_enabled,
                    last_login: row.last_login,
                    failed_login_attempts: row.failed_login_attempts,
                    locked_until: row.locked_until,
                };

                self.security_logger.log_event(
                    Some(row.id),
                    SecurityEventType::LoginSuccess,
                    ip_address,
                    None,
                    None,
                ).await?;

                return Ok(Some(user));
            } else {
                // Failed authentication
                self.increment_failed_attempts(email, row.id).await?;
                self.rate_limiter.record_failed_attempt(email, &ip_address).await?;
                
                self.security_logger.log_event(
                    Some(row.id),
                    SecurityEventType::LoginFailure,
                    ip_address,
                    None,
                    Some("Invalid password".to_string()),
                ).await?;
            }
        } else {
            // User not found - still record the attempt to prevent enumeration
            self.rate_limiter.record_failed_attempt(email, &ip_address).await?;
            
            self.security_logger.log_event(
                None,
                SecurityEventType::LoginFailure,
                ip_address,
                None,
                Some("User not found".to_string()),
            ).await?;
        }
        
        Ok(None)
    }
    
    pub async fn create_user(&self, email: &str, password: &str, domain_id: Uuid) -> Result<Uuid> {
        // Validate password strength
        self.password_manager.validate_password_strength(password)?;

        let password_hash = self.password_manager.hash_password(password)?;
        
        let user_id = sqlx::query_scalar!(
            "INSERT INTO users (email, password_hash, domain_id) VALUES ($1, $2, $3) RETURNING id",
            email,
            password_hash,
            domain_id
        )
        .fetch_one(&self.db_pool)
        .await?;
        
        // Create default mailboxes
        self.create_default_mailboxes(user_id).await?;
        
        // Log user creation
        self.security_logger.log_event(
            Some(user_id),
            SecurityEventType::AccountCreated,
            None,
            None,
            Some("User account created".to_string()),
        ).await?;
        
        Ok(user_id)
    }

    pub async fn change_password(&self, user_id: Uuid, old_password: &str, new_password: &str) -> Result<()> {
        self.password_manager.change_password(user_id, old_password, new_password).await?;

        // Invalidate all sessions for this user
        self.session_manager.invalidate_user_sessions(user_id).await?;

        // Log password change
        self.security_logger.log_event(
            Some(user_id),
            SecurityEventType::PasswordChanged,
            None,
            None,
            None,
        ).await?;

        Ok(())
    }

    pub async fn create_session(&self, user_id: Uuid, ip_address: Option<String>, user_agent: Option<String>) -> Result<Session> {
        let session = self.session_manager.create_session(user_id, ip_address.clone(), user_agent.clone()).await?;
        
        self.security_logger.log_event(
            Some(user_id),
            SecurityEventType::SessionCreated,
            ip_address,
            user_agent,
            None,
        ).await?;

        Ok(session)
    }

    pub async fn validate_session(&self, token: &str) -> Result<Option<Session>> {
        self.session_manager.validate_session(token).await
    }

    pub async fn invalidate_session(&self, token: &str) -> Result<()> {
        self.session_manager.invalidate_session(token).await
    }

    pub async fn enable_two_factor(&self, user_id: Uuid) -> Result<String> {
        // Generate TOTP secret
        let secret = totp::generate_secret();
        
        // Store secret in database
        sqlx::query!(
            "UPDATE users SET two_factor_enabled = true, totp_secret = $1 WHERE id = $2",
            secret,
            user_id
        )
        .execute(&self.db_pool)
        .await?;

        // Log 2FA enablement
        self.security_logger.log_event(
            Some(user_id),
            SecurityEventType::TwoFactorEnabled,
            None,
            None,
            None,
        ).await?;

        Ok(secret)
    }

    pub async fn verify_totp(&self, user_id: Uuid, code: &str) -> Result<bool> {
        let row = sqlx::query!(
            "SELECT totp_secret FROM users WHERE id = $1 AND two_factor_enabled = true",
            user_id
        )
        .fetch_optional(&self.db_pool)
        .await?;

        if let Some(row) = row {
            if let Some(secret) = row.totp_secret {
                return Ok(totp::verify_code(&secret, code));
            }
        }

        Ok(false)
    }

    // Private helper methods

    async fn increment_failed_attempts(&self, email: &str, user_id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1 RETURNING failed_login_attempts",
            user_id
        )
        .fetch_one(&self.db_pool)
        .await?;

        // Lock account after 5 failed attempts
        if result.failed_login_attempts >= 5 {
            sqlx::query!(
                "UPDATE users SET locked_until = $1 WHERE id = $2",
                Utc::now() + Duration::minutes(30),
                user_id
            )
            .execute(&self.db_pool)
            .await?;

            self.security_logger.log_event(
                Some(user_id),
                SecurityEventType::AccountLocked,
                None,
                None,
                Some(format!("Account locked after {} failed attempts", result.failed_login_attempts)),
            ).await?;
        }

        Ok(())
    }

    async fn update_last_login(&self, user_id: Uuid) -> Result<()> {
        sqlx::query!(
            "UPDATE users SET last_login = $1, failed_login_attempts = 0, locked_until = NULL WHERE id = $2",
            Utc::now(),
            user_id
        )
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    async fn create_default_mailboxes(&self, user_id: Uuid) -> Result<()> {
        let default_mailboxes = ["INBOX", "Sent", "Drafts", "Trash"];
        
        for mailbox_name in &default_mailboxes {
            sqlx::query!(
                "INSERT INTO mailboxes (user_id, name) VALUES ($1, $2)",
                user_id,
                mailbox_name
            )
            .execute(&self.db_pool)
            .await?;
        }
        
        Ok(())
    }
}
