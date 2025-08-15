use crate::error::Result;
use sqlx::{PgPool, Row};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use tracing::{info, warn, error, debug};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mailbox {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub uidvalidity: i32,
    pub uidnext: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxStats {
    pub mailbox_id: Uuid,
    pub message_count: i32,
    pub unseen_count: i32,
    pub recent_count: i32,
    pub size_bytes: i64,
    pub first_unseen_uid: Option<i32>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxInfo {
    pub mailbox: Mailbox,
    pub stats: MailboxStats,
    pub flags: Vec<String>,
    pub permanent_flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MailboxManager {
    pool: PgPool,
}

impl MailboxManager {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new mailbox for a user
    pub async fn create_mailbox(&self, user_id: Uuid, name: &str) -> Result<Mailbox> {
        debug!("Creating mailbox '{}' for user {}", name, user_id);
        
        // Generate UIDVALIDITY as current timestamp
        let uidvalidity = chrono::Utc::now().timestamp() as i32;
        
        let mailbox = sqlx::query_as!(
            Mailbox,
            r#"
            INSERT INTO mailboxes (user_id, name, uidvalidity, uidnext)
            VALUES ($1, $2, $3, 1)
            RETURNING id, user_id, name, uidvalidity, uidnext, created_at
            "#,
            user_id,
            name,
            uidvalidity
        )
        .fetch_one(&self.pool)
        .await?;
        
        info!("Created mailbox '{}' with ID {} for user {}", name, mailbox.id, user_id);
        Ok(mailbox)
    }

    /// Get a mailbox by ID
    pub async fn get_mailbox(&self, mailbox_id: Uuid) -> Result<Option<Mailbox>> {
        let mailbox = sqlx::query_as!(
            Mailbox,
            "SELECT id, user_id, name, uidvalidity, uidnext, created_at FROM mailboxes WHERE id = $1",
            mailbox_id
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(mailbox)
    }

    /// Get a mailbox by user ID and name
    pub async fn get_mailbox_by_name(&self, user_id: Uuid, name: &str) -> Result<Option<Mailbox>> {
        let mailbox = sqlx::query_as!(
            Mailbox,
            "SELECT id, user_id, name, uidvalidity, uidnext, created_at FROM mailboxes WHERE user_id = $1 AND name = $2",
            user_id,
            name
        )
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(mailbox)
    }

    /// List all mailboxes for a user
    pub async fn list_mailboxes(&self, user_id: Uuid) -> Result<Vec<Mailbox>> {
        let mailboxes = sqlx::query_as!(
            Mailbox,
            "SELECT id, user_id, name, uidvalidity, uidnext, created_at FROM mailboxes WHERE user_id = $1 ORDER BY name",
            user_id
        )
        .fetch_all(&self.pool)
        .await?;
        
        Ok(mailboxes)
    }

    /// Delete a mailbox and all its messages
    pub async fn delete_mailbox(&self, mailbox_id: Uuid) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        
        // Delete all messages in the mailbox (cascading will handle attachments and headers)
        let message_count = sqlx::query_scalar::<_, i64>(
            "DELETE FROM messages WHERE mailbox_id = $1 RETURNING COUNT(*)"
        )
        .bind(mailbox_id)
        .fetch_one(&mut *tx)
        .await?;
        
        // Delete the mailbox
        let deleted_rows = sqlx::query!(
            "DELETE FROM mailboxes WHERE id = $1",
            mailbox_id
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        
        tx.commit().await?;
        
        if deleted_rows > 0 {
            info!("Deleted mailbox {} with {} messages", mailbox_id, message_count);
            Ok(true)
        } else {
            warn!("Attempted to delete non-existent mailbox {}", mailbox_id);
            Ok(false)
        }
    }

    /// Rename a mailbox
    pub async fn rename_mailbox(&self, mailbox_id: Uuid, new_name: &str) -> Result<bool> {
        let updated_rows = sqlx::query!(
            "UPDATE mailboxes SET name = $1, updated_at = NOW() WHERE id = $2",
            new_name,
            mailbox_id
        )
        .execute(&self.pool)
        .await?
        .rows_affected();
        
        if updated_rows > 0 {
            info!("Renamed mailbox {} to '{}'", mailbox_id, new_name);
            Ok(true)
        } else {
            warn!("Attempted to rename non-existent mailbox {}", mailbox_id);
            Ok(false)
        }
    }

    /// Get mailbox statistics
    pub async fn get_mailbox_stats(&self, mailbox_id: Uuid) -> Result<MailboxStats> {
        let stats = sqlx::query!(
            r#"
            SELECT 
                COUNT(m.id) as message_count,
                COUNT(CASE WHEN NOT ('\\Seen' = ANY(m.flags)) THEN 1 END) as unseen_count,
                COUNT(CASE WHEN '\\Recent' = ANY(m.flags) THEN 1 END) as recent_count,
                COALESCE(SUM(m.size_bytes), 0) as size_bytes,
                MIN(CASE WHEN NOT ('\\Seen' = ANY(m.flags)) THEN m.uid END) as first_unseen_uid
            FROM messages m
            WHERE m.mailbox_id = $1 AND m.archived_at IS NULL
            "#,
            mailbox_id
        )
        .fetch_one(&self.pool)
        .await?;
        
        Ok(MailboxStats {
            mailbox_id,
            message_count: stats.message_count.unwrap_or(0) as i32,
            unseen_count: stats.unseen_count.unwrap_or(0) as i32,
            recent_count: stats.recent_count.unwrap_or(0) as i32,
            size_bytes: stats.size_bytes.unwrap_or(0),
            first_unseen_uid: stats.first_unseen_uid,
            last_updated: Utc::now(),
        })
    }

    /// Get complete mailbox information including stats
    pub async fn get_mailbox_info(&self, mailbox_id: Uuid) -> Result<Option<MailboxInfo>> {
        let mailbox = match self.get_mailbox(mailbox_id).await? {
            Some(mb) => mb,
            None => return Ok(None),
        };
        
        let stats = self.get_mailbox_stats(mailbox_id).await?;
        
        // Get available flags from messages in this mailbox
        let flags_result = sqlx::query!(
            "SELECT DISTINCT unnest(flags) as flag FROM messages WHERE mailbox_id = $1",
            mailbox_id
        )
        .fetch_all(&self.pool)
        .await?;
        
        let mut flags: Vec<String> = flags_result
            .into_iter()
            .filter_map(|row| row.flag)
            .collect();
        
        // Add standard IMAP flags if not present
        let standard_flags = vec![
            "\\Seen".to_string(),
            "\\Answered".to_string(),
            "\\Flagged".to_string(),
            "\\Deleted".to_string(),
            "\\Draft".to_string(),
            "\\Recent".to_string(),
        ];
        
        for flag in standard_flags {
            if !flags.contains(&flag) {
                flags.push(flag);
            }
        }
        
        let permanent_flags = vec![
            "\\Seen".to_string(),
            "\\Answered".to_string(),
            "\\Flagged".to_string(),
            "\\Deleted".to_string(),
            "\\Draft".to_string(),
            "\\*".to_string(), // Indicates custom flags are allowed
        ];
        
        Ok(Some(MailboxInfo {
            mailbox,
            stats,
            flags,
            permanent_flags,
        }))
    }

    /// Get next UID for a mailbox and increment UIDNEXT
    pub async fn get_next_uid(&self, mailbox_id: Uuid) -> Result<i32> {
        let mut tx = self.pool.begin().await?;
        
        let current_uidnext = sqlx::query_scalar::<_, i32>(
            "SELECT uidnext FROM mailboxes WHERE id = $1 FOR UPDATE",
            mailbox_id
        )
        .fetch_one(&mut *tx)
        .await?;
        
        // Increment UIDNEXT
        sqlx::query!(
            "UPDATE mailboxes SET uidnext = uidnext + 1 WHERE id = $1",
            mailbox_id
        )
        .execute(&mut *tx)
        .await?;
        
        tx.commit().await?;
        
        Ok(current_uidnext)
    }

    /// Update UIDVALIDITY (used when mailbox structure changes significantly)
    pub async fn update_uidvalidity(&self, mailbox_id: Uuid) -> Result<i32> {
        let new_uidvalidity = chrono::Utc::now().timestamp() as i32;
        
        sqlx::query!(
            "UPDATE mailboxes SET uidvalidity = $1, uidnext = 1 WHERE id = $2",
            new_uidvalidity,
            mailbox_id
        )
        .execute(&self.pool)
        .await?;
        
        info!("Updated UIDVALIDITY for mailbox {} to {}", mailbox_id, new_uidvalidity);
        Ok(new_uidvalidity)
    }

    /// Get mailbox quota usage
    pub async fn get_mailbox_quota(&self, mailbox_id: Uuid) -> Result<(i64, i32)> {
        let result = sqlx::query!(
            r#"
            SELECT 
                COALESCE(SUM(size_bytes), 0) as total_bytes,
                COUNT(id) as message_count
            FROM messages 
            WHERE mailbox_id = $1 AND archived_at IS NULL
            "#,
            mailbox_id
        )
        .fetch_one(&self.pool)
        .await?;
        
        Ok((
            result.total_bytes.unwrap_or(0),
            result.message_count.unwrap_or(0) as i32,
        ))
    }

    /// Check if a mailbox exists and belongs to the user
    pub async fn verify_mailbox_access(&self, mailbox_id: Uuid, user_id: Uuid) -> Result<bool> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE id = $1 AND user_id = $2)",
            mailbox_id,
            user_id
        )
        .fetch_one(&self.pool)
        .await?;
        
        Ok(exists)
    }

    /// Get mailboxes with their message counts for a user
    pub async fn get_mailbox_summary(&self, user_id: Uuid) -> Result<HashMap<String, (Uuid, i32, i32)>> {
        let results = sqlx::query!(
            r#"
            SELECT 
                mb.id,
                mb.name,
                COUNT(m.id) as message_count,
                COUNT(CASE WHEN NOT ('\\Seen' = ANY(m.flags)) THEN 1 END) as unseen_count
            FROM mailboxes mb
            LEFT JOIN messages m ON mb.id = m.mailbox_id AND m.archived_at IS NULL
            WHERE mb.user_id = $1
            GROUP BY mb.id, mb.name
            ORDER BY mb.name
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;
        
        let mut summary = HashMap::new();
        for row in results {
            summary.insert(
                row.name,
                (
                    row.id,
                    row.message_count.unwrap_or(0) as i32,
                    row.unseen_count.unwrap_or(0) as i32,
                ),
            );
        }
        
        Ok(summary)
    }

    /// Create default mailboxes for a new user
    pub async fn create_default_mailboxes(&self, user_id: Uuid) -> Result<Vec<Mailbox>> {
        let default_mailboxes = vec![
            "INBOX",
            "Sent",
            "Drafts",
            "Trash",
            "Junk",
        ];
        
        let mut created_mailboxes = Vec::new();
        
        for name in default_mailboxes {
            match self.create_mailbox(user_id, name).await {
                Ok(mailbox) => {
                    created_mailboxes.push(mailbox);
                    info!("Created default mailbox '{}' for user {}", name, user_id);
                }
                Err(e) => {
                    error!("Failed to create default mailbox '{}' for user {}: {}", name, user_id, e);
                }
            }
        }
        
        Ok(created_mailboxes)
    }

    /// Archive old messages in a mailbox
    pub async fn archive_mailbox_messages(&self, mailbox_id: Uuid, days_old: i32) -> Result<i32> {
        let archived_count = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE messages 
            SET archived_at = NOW()
            WHERE mailbox_id = $1 
            AND archived_at IS NULL 
            AND internal_date < NOW() - INTERVAL '%d days'
            AND NOT ('\\Important' = ANY(flags))
            "#,
            mailbox_id,
            days_old
        )
        .fetch_one(&self.pool)
        .await?;
        
        info!("Archived {} messages in mailbox {}", archived_count, mailbox_id);
        Ok(archived_count as i32)
    }

    /// Expunge deleted messages from a mailbox
    pub async fn expunge_mailbox(&self, mailbox_id: Uuid) -> Result<Vec<i32>> {
        let mut tx = self.pool.begin().await?;
        
        // Get UIDs of messages marked for deletion
        let deleted_uids = sqlx::query_scalar::<_, i32>(
            "SELECT uid FROM messages WHERE mailbox_id = $1 AND '\\Deleted' = ANY(flags) ORDER BY uid",
            mailbox_id
        )
        .fetch_all(&mut *tx)
        .await?;
        
        if !deleted_uids.is_empty() {
            // Delete the messages
            sqlx::query!(
                "DELETE FROM messages WHERE mailbox_id = $1 AND '\\Deleted' = ANY(flags)",
                mailbox_id
            )
            .execute(&mut *tx)
            .await?;
            
            info!("Expunged {} messages from mailbox {}", deleted_uids.len(), mailbox_id);
        }
        
        tx.commit().await?;
        Ok(deleted_uids)
    }
}
