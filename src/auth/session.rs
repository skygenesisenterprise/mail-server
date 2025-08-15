use crate::error::Result;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

pub struct SessionManager {
    db_pool: PgPool,
}

impl SessionManager {
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    pub async fn create_session(
        &self,
        user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Session> {
        let token = self.generate_session_token();
        let expires_at = Utc::now() + Duration::hours(24); // 24 hour sessions

        let session_id = sqlx::query_scalar!(
            "INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent) 
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
            user_id,
            token,
            expires_at,
            ip_address,
            user_agent
        )
        .fetch_one(&self.db_pool)
        .await?;

        Ok(Session {
            id: session_id,
            user_id,
            token,
            expires_at,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            ip_address,
            user_agent,
        })
    }

    pub async fn validate_session(&self, token: &str) -> Result<Option<Session>> {
        let row = sqlx::query!(
            "SELECT id, user_id, token, expires_at, created_at, last_activity, ip_address, user_agent
             FROM sessions WHERE token = $1 AND expires_at > $2",
            token,
            Utc::now()
        )
        .fetch_optional(&self.db_pool)
        .await?;

        if let Some(row) = row {
            // Update last activity
            sqlx::query!(
                "UPDATE sessions SET last_activity = $1 WHERE id = $2",
                Utc::now(),
                row.id
            )
            .execute(&self.db_pool)
            .await?;

            Ok(Some(Session {
                id: row.id,
                user_id: row.user_id,
                token: row.token,
                expires_at: row.expires_at,
                created_at: row.created_at,
                last_activity: Utc::now(),
                ip_address: row.ip_address,
                user_agent: row.user_agent,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn invalidate_session(&self, token: &str) -> Result<()> {
        sqlx::query!("DELETE FROM sessions WHERE token = $1", token)
            .execute(&self.db_pool)
            .await?;

        Ok(())
    }

    pub async fn invalidate_user_sessions(&self, user_id: Uuid) -> Result<()> {
        sqlx::query!("DELETE FROM sessions WHERE user_id = $1", user_id)
            .execute(&self.db_pool)
            .await?;

        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<()> {
        sqlx::query!("DELETE FROM sessions WHERE expires_at < $1", Utc::now())
            .execute(&self.db_pool)
            .await?;

        Ok(())
    }

    pub async fn extend_session(&self, token: &str, duration: Duration) -> Result<bool> {
        let rows_affected = sqlx::query!(
            "UPDATE sessions SET expires_at = $1 WHERE token = $2 AND expires_at > $3",
            Utc::now() + duration,
            token,
            Utc::now()
        )
        .execute(&self.db_pool)
        .await?
        .rows_affected();

        Ok(rows_affected > 0)
    }

    pub async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>> {
        let rows = sqlx::query!(
            "SELECT id, user_id, token, expires_at, created_at, last_activity, ip_address, user_agent
             FROM sessions WHERE user_id = $1 AND expires_at > $2 ORDER BY last_activity DESC",
            user_id,
            Utc::now()
        )
        .fetch_all(&self.db_pool)
        .await?;

        let sessions = rows
            .into_iter()
            .map(|row| Session {
                id: row.id,
                user_id: row.user_id,
                token: row.token,
                expires_at: row.expires_at,
                created_at: row.created_at,
                last_activity: row.last_activity,
                ip_address: row.ip_address,
                user_agent: row.user_agent,
            })
            .collect();

        Ok(sessions)
    }

    fn generate_session_token(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let token: String = (0..64)
            .map(|_| {
                let idx = rng.gen_range(0..62);
                match idx {
                    0..=25 => (b'A' + idx) as char,
                    26..=51 => (b'a' + (idx - 26)) as char,
                    _ => (b'0' + (idx - 52)) as char,
                }
            })
            .collect();
        token
    }
}
