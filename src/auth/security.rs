use crate::error::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub event_type: SecurityEventType,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum SecurityEventType {
    LoginSuccess,
    LoginFailure,
    AccountLocked,
    AccountUnlocked,
    PasswordChanged,
    TwoFactorEnabled,
    TwoFactorDisabled,
    SessionCreated,
    SessionExpired,
    SuspiciousActivity,
    AccountCreated,
    AccountDeleted,
    PermissionChanged,
    DataExport,
    DataImport,
}

pub struct SecurityLogger {
    db_pool: PgPool,
}

impl SecurityLogger {
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    pub async fn log_event(
        &self,
        user_id: Option<Uuid>,
        event_type: SecurityEventType,
        ip_address: Option<String>,
        user_agent: Option<String>,
        details: Option<String>,
    ) -> Result<()> {
        let event_type_str = self.event_type_to_string(&event_type);

        sqlx::query!(
            "INSERT INTO security_events (user_id, event_type, ip_address, user_agent, details) 
             VALUES ($1, $2, $3, $4, $5)",
            user_id,
            event_type_str,
            ip_address,
            user_agent,
            details
        )
        .execute(&self.db_pool)
        .await?;

        // Also log to application logs for monitoring
        match event_type {
            SecurityEventType::LoginFailure | 
            SecurityEventType::AccountLocked | 
            SecurityEventType::SuspiciousActivity => {
                warn!("Security event: {:?} for user {:?} from IP {:?}", event_type, user_id, ip_address);
            }
            _ => {
                info!("Security event: {:?} for user {:?}", event_type, user_id);
            }
        }

        Ok(())
    }

    pub async fn get_security_events(&self, user_id: Option<Uuid>, limit: i64) -> Result<Vec<SecurityEvent>> {
        let rows = if let Some(user_id) = user_id {
            sqlx::query!(
                "SELECT id, user_id, event_type, ip_address, user_agent, details, created_at
                 FROM security_events WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
                user_id,
                limit
            )
            .fetch_all(&self.db_pool)
            .await?
        } else {
            sqlx::query!(
                "SELECT id, user_id, event_type, ip_address, user_agent, details, created_at
                 FROM security_events ORDER BY created_at DESC LIMIT $1",
                limit
            )
            .fetch_all(&self.db_pool)
            .await?
        };

        let mut events = Vec::new();
        for row in rows {
            let event_type = self.string_to_event_type(&row.event_type);

            events.push(SecurityEvent {
                id: row.id,
                user_id: row.user_id,
                event_type,
                ip_address: row.ip_address,
                user_agent: row.user_agent,
                details: row.details,
                timestamp: row.created_at,
            });
        }

        Ok(events)
    }

    pub async fn get_failed_login_attempts(&self, user_id: Option<Uuid>, since: DateTime<Utc>) -> Result<i64> {
        let count = if let Some(user_id) = user_id {
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM security_events 
                 WHERE user_id = $1 AND event_type = 'login_failure' AND created_at > $2",
                user_id,
                since
            )
            .fetch_one(&self.db_pool)
            .await?
        } else {
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM security_events 
                 WHERE event_type = 'login_failure' AND created_at > $2",
                since
            )
            .fetch_one(&self.db_pool)
            .await?
        };

        Ok(count.unwrap_or(0))
    }

    pub async fn detect_suspicious_activity(&self, user_id: Uuid) -> Result<Vec<String>> {
        let mut suspicious_patterns = Vec::new();

        // Check for multiple failed logins from different IPs
        let failed_logins = sqlx::query!(
            "SELECT DISTINCT ip_address FROM security_events 
             WHERE user_id = $1 AND event_type = 'login_failure' 
             AND created_at > $2",
            user_id,
            Utc::now() - chrono::Duration::hours(1)
        )
        .fetch_all(&self.db_pool)
        .await?;

        if failed_logins.len() > 3 {
            suspicious_patterns.push("Multiple failed login attempts from different IP addresses".to_string());
        }

        // Check for login from unusual locations (simplified - would need GeoIP in production)
        let recent_ips = sqlx::query!(
            "SELECT DISTINCT ip_address FROM security_events 
             WHERE user_id = $1 AND event_type = 'login_success' 
             AND created_at > $2",
            user_id,
            Utc::now() - chrono::Duration::days(7)
        )
        .fetch_all(&self.db_pool)
        .await?;

        let current_ips = sqlx::query!(
            "SELECT DISTINCT ip_address FROM security_events 
             WHERE user_id = $1 AND event_type = 'login_success' 
             AND created_at > $2",
            user_id,
            Utc::now() - chrono::Duration::hours(1)
        )
        .fetch_all(&self.db_pool)
        .await?;

        // Simple check for new IP addresses
        for current_ip in &current_ips {
            if let Some(current_ip) = &current_ip.ip_address {
                let is_known = recent_ips.iter().any(|row| {
                    row.ip_address.as_ref() == Some(current_ip)
                });
                
                if !is_known {
                    suspicious_patterns.push(format!("Login from new IP address: {}", current_ip));
                }
            }
        }

        // Check for rapid successive logins
        let rapid_logins = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM security_events 
             WHERE user_id = $1 AND event_type = 'login_success' 
             AND created_at > $2",
            user_id,
            Utc::now() - chrono::Duration::minutes(5)
        )
        .fetch_one(&self.db_pool)
        .await?;

        if rapid_logins.unwrap_or(0) > 5 {
            suspicious_patterns.push("Rapid successive login attempts".to_string());
        }

        Ok(suspicious_patterns)
    }

    pub async fn cleanup_old_events(&self, older_than: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query!(
            "DELETE FROM security_events WHERE created_at < $1",
            older_than
        )
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    fn event_type_to_string(&self, event_type: &SecurityEventType) -> &'static str {
        match event_type {
            SecurityEventType::LoginSuccess => "login_success",
            SecurityEventType::LoginFailure => "login_failure",
            SecurityEventType::AccountLocked => "account_locked",
            SecurityEventType::AccountUnlocked => "account_unlocked",
            SecurityEventType::PasswordChanged => "password_changed",
            SecurityEventType::TwoFactorEnabled => "two_factor_enabled",
            SecurityEventType::TwoFactorDisabled => "two_factor_disabled",
            SecurityEventType::SessionCreated => "session_created",
            SecurityEventType::SessionExpired => "session_expired",
            SecurityEventType::SuspiciousActivity => "suspicious_activity",
            SecurityEventType::AccountCreated => "account_created",
            SecurityEventType::AccountDeleted => "account_deleted",
            SecurityEventType::PermissionChanged => "permission_changed",
            SecurityEventType::DataExport => "data_export",
            SecurityEventType::DataImport => "data_import",
        }
    }

    fn string_to_event_type(&self, event_type_str: &str) -> SecurityEventType {
        match event_type_str {
            "login_success" => SecurityEventType::LoginSuccess,
            "login_failure" => SecurityEventType::LoginFailure,
            "account_locked" => SecurityEventType::AccountLocked,
            "account_unlocked" => SecurityEventType::AccountUnlocked,
            "password_changed" => SecurityEventType::PasswordChanged,
            "two_factor_enabled" => SecurityEventType::TwoFactorEnabled,
            "two_factor_disabled" => SecurityEventType::TwoFactorDisabled,
            "session_created" => SecurityEventType::SessionCreated,
            "session_expired" => SecurityEventType::SessionExpired,
            "account_created" => SecurityEventType::AccountCreated,
            "account_deleted" => SecurityEventType::AccountDeleted,
            "permission_changed" => SecurityEventType::PermissionChanged,
            "data_export" => SecurityEventType::DataExport,
            "data_import" => SecurityEventType::DataImport,
            _ => SecurityEventType::SuspiciousActivity,
        }
    }
}
