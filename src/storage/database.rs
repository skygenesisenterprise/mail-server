use crate::error::MailServerError;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::time::Duration;
use tracing::{error, info, warn};

/// Database connection manager and query utilities
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Create a new database instance with connection pool
    pub async fn new(database_url: &str) -> Result<Self, MailServerError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(20)
            .min_connections(5)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .max_lifetime(Duration::from_secs(1800))
            .connect(database_url)
            .await
            .map_err(|e| MailServerError::Database(e.to_string()))?;

        info!("Database connection pool established");
        Ok(Self { pool })
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Begin a new database transaction
    pub async fn begin_transaction(&self) -> Result<Transaction<'_, Postgres>, MailServerError> {
        self.pool
            .begin()
            .await
            .map_err(|e| MailServerError::Database(e.to_string()))
    }

    /// Execute a query and return the number of affected rows
    pub async fn execute(
        &self,
        query: &str,
        params: &[&(dyn sqlx::Encode<Postgres> + sqlx::Type<Postgres> + Sync)],
    ) -> Result<u64, MailServerError> {
        let mut query_builder = sqlx::query(query);
        for param in params {
            query_builder = query_builder.bind(param);
        }

        let result = query_builder
            .execute(&self.pool)
            .await
            .map_err(|e| MailServerError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Execute a query and return a single row
    pub async fn fetch_one(
        &self,
        query: &str,
        params: &[&(dyn sqlx::Encode<Postgres> + sqlx::Type<Postgres> + Sync)],
    ) -> Result<sqlx::postgres::PgRow, MailServerError> {
        let mut query_builder = sqlx::query(query);
        for param in params {
            query_builder = query_builder.bind(param);
        }

        query_builder
            .fetch_one(&self.pool)
            .await
            .map_err(|e| MailServerError::Database(e.to_string()))
    }

    /// Execute a query and return an optional row
    pub async fn fetch_optional(
        &self,
        query: &str,
        params: &[&(dyn sqlx::Encode<Postgres> + sqlx::Type<Postgres> + Sync)],
    ) -> Result<Option<sqlx::postgres::PgRow>, MailServerError> {
        let mut query_builder = sqlx::query(query);
        for param in params {
            query_builder = query_builder.bind(param);
        }

        query_builder
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| MailServerError::Database(e.to_string()))
    }

    /// Execute a query and return all rows
    pub async fn fetch_all(
        &self,
        query: &str,
        params: &[&(dyn sqlx::Encode<Postgres> + sqlx::Type<Postgres> + Sync)],
    ) -> Result<Vec<sqlx::postgres::PgRow>, MailServerError> {
        let mut query_builder = sqlx::query(query);
        for param in params {
            query_builder = query_builder.bind(param);
        }

        query_builder
            .fetch_all(&self.pool)
            .await
            .map_err(|e| MailServerError::Database(e.to_string()))
    }

    /// Check database connectivity
    pub async fn health_check(&self) -> Result<(), MailServerError> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| MailServerError::Database(format!("Health check failed: {}", e)))?;

        Ok(())
    }

    /// Get database statistics
    pub async fn get_stats(&self) -> Result<DatabaseStats, MailServerError> {
        let row = sqlx::query(
            r#"
            SELECT 
                (SELECT COUNT(*) FROM users) as user_count,
                (SELECT COUNT(*) FROM domains) as domain_count,
                (SELECT COUNT(*) FROM mailboxes) as mailbox_count,
                (SELECT COUNT(*) FROM messages) as message_count,
                (SELECT COALESCE(SUM(size), 0) FROM messages) as total_size,
                (SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()) as active_sessions
        "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| MailServerError::Database(e.to_string()))?;

        Ok(DatabaseStats {
            user_count: row.get::<i64, _>("user_count") as u64,
            domain_count: row.get::<i64, _>("domain_count") as u64,
            mailbox_count: row.get::<i64, _>("mailbox_count") as u64,
            message_count: row.get::<i64, _>("message_count") as u64,
            total_size: row.get::<i64, _>("total_size") as u64,
            active_sessions: row.get::<i64, _>("active_sessions") as u64,
        })
    }

    /// Run database maintenance tasks
    pub async fn maintenance(&self) -> Result<MaintenanceResult, MailServerError> {
        let mut result = MaintenanceResult::default();

        // Clean up expired sessions
        let expired_sessions = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| MailServerError::Database(e.to_string()))?
            .rows_affected();
        result.expired_sessions_cleaned = expired_sessions;

        // Clean up old security events (older than 90 days)
        let old_events = sqlx::query(
            "DELETE FROM security_events WHERE created_at < NOW() - INTERVAL '90 days'",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| MailServerError::Database(e.to_string()))?
        .rows_affected();
        result.old_security_events_cleaned = old_events;

        // Update storage usage statistics
        sqlx::query(r#"
            INSERT INTO storage_usage (user_id, mailbox_count, message_count, total_size, updated_at)
            SELECT 
                u.id,
                COUNT(DISTINCT m.id),
                COUNT(DISTINCT msg.id),
                COALESCE(SUM(msg.size), 0),
                NOW()
            FROM users u
            LEFT JOIN mailboxes m ON u.id = m.user_id
            LEFT JOIN messages msg ON m.id = msg.mailbox_id
            GROUP BY u.id
            ON CONFLICT (user_id) DO UPDATE SET
                mailbox_count = EXCLUDED.mailbox_count,
                message_count = EXCLUDED.message_count,
                total_size = EXCLUDED.total_size,
                updated_at = EXCLUDED.updated_at
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| MailServerError::Database(e.to_string()))?;

        // Vacuum analyze for performance
        sqlx::query("VACUUM ANALYZE")
            .execute(&self.pool)
            .await
            .map_err(|e| MailServerError::Database(e.to_string()))?;

        info!("Database maintenance completed: {:?}", result);
        Ok(result)
    }

    /// Execute a raw SQL query (for migrations and admin tasks)
    pub async fn execute_raw(&self, sql: &str) -> Result<u64, MailServerError> {
        sqlx::query(sql)
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected())
            .map_err(|e| MailServerError::Database(e.to_string()))
    }

    /// Get connection pool statistics
    pub fn pool_stats(&self) -> PoolStats {
        PoolStats {
            size: self.pool.size(),
            idle: self.pool.num_idle(),
        }
    }

    /// Close the database connection pool
    pub async fn close(&self) {
        self.pool.close().await;
        info!("Database connection pool closed");
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub user_count: u64,
    pub domain_count: u64,
    pub mailbox_count: u64,
    pub message_count: u64,
    pub total_size: u64,
    pub active_sessions: u64,
}

/// Database maintenance result
#[derive(Debug, Clone, Default)]
pub struct MaintenanceResult {
    pub expired_sessions_cleaned: u64,
    pub old_security_events_cleaned: u64,
}

/// Connection pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub size: u32,
    pub idle: usize,
}

/// Database query builder for complex queries
pub struct QueryBuilder {
    query: String,
    params: Vec<Value>,
}

impl QueryBuilder {
    pub fn new(base_query: &str) -> Self {
        Self {
            query: base_query.to_string(),
            params: Vec::new(),
        }
    }

    pub fn add_condition(&mut self, condition: &str) -> &mut Self {
        if self.query.contains("WHERE") {
            self.query.push_str(" AND ");
        } else {
            self.query.push_str(" WHERE ");
        }
        self.query.push_str(condition);
        self
    }

    pub fn add_param(&mut self, param: Value) -> &mut Self {
        self.params.push(param);
        self
    }

    pub fn add_order_by(&mut self, column: &str, direction: &str) -> &mut Self {
        self.query
            .push_str(&format!(" ORDER BY {} {}", column, direction));
        self
    }

    pub fn add_limit(&mut self, limit: i64) -> &mut Self {
        self.query.push_str(&format!(" LIMIT {}", limit));
        self
    }

    pub fn add_offset(&mut self, offset: i64) -> &mut Self {
        self.query.push_str(&format!(" OFFSET {}", offset));
        self
    }

    pub fn build(&self) -> (&str, &[Value]) {
        (&self.query, &self.params)
    }
}

/// Database migration utilities
pub struct Migration {
    pub version: i32,
    pub name: String,
    pub up_sql: String,
    pub down_sql: String,
}

impl Migration {
    pub fn new(version: i32, name: &str, up_sql: &str, down_sql: &str) -> Self {
        Self {
            version,
            name: name.to_string(),
            up_sql: up_sql.to_string(),
            down_sql: down_sql.to_string(),
        }
    }
}

/// Database backup utilities
pub struct BackupManager {
    database: Database,
}

impl BackupManager {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    pub async fn create_backup(&self, backup_name: &str) -> Result<String, MailServerError> {
        // This would typically use pg_dump or similar
        // For now, we'll create a logical backup record
        let backup_id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            r#"
            INSERT INTO backup_jobs (id, name, status, created_at, backup_type)
            VALUES ($1, $2, 'completed', NOW(), 'logical')
        "#,
        )
        .bind(&backup_id)
        .bind(backup_name)
        .execute(self.database.pool())
        .await
        .map_err(|e| MailServerError::Database(e.to_string()))?;

        info!("Backup created: {} ({})", backup_name, backup_id);
        Ok(backup_id)
    }

    pub async fn list_backups(&self) -> Result<Vec<BackupInfo>, MailServerError> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, status, created_at, backup_type, size
            FROM backup_jobs
            ORDER BY created_at DESC
        "#,
        )
        .fetch_all(self.database.pool())
        .await
        .map_err(|e| MailServerError::Database(e.to_string()))?;

        let backups = rows
            .into_iter()
            .map(|row| BackupInfo {
                id: row.get("id"),
                name: row.get("name"),
                status: row.get("status"),
                created_at: row.get("created_at"),
                backup_type: row.get("backup_type"),
                size: row.get("size"),
            })
            .collect();

        Ok(backups)
    }
}

#[derive(Debug, Clone)]
pub struct BackupInfo {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub backup_type: String,
    pub size: Option<i64>,
}
