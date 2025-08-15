pub mod database;
pub mod email_parser;
pub mod mailbox;

use crate::config::DatabaseConfig;
use crate::error::Result;
use chrono::{DateTime, Utc};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::io::Write;
use std::time::Duration;
use tracing::{error, info, warn};
use uuid::Uuid;

pub use mailbox::{Mailbox, MailboxInfo, MailboxManager, MailboxStats};

pub async fn init_database(config: &DatabaseConfig) -> Result<PgPool> {
    info!("Initializing database connection pool");

    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.connection_timeout))
        .connect(&config.url)
        .await?;

    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    info!("Running database migrations");

    // Create tables if they don't exist
    sqlx::query(
        r#"
        -- Enable required extensions
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        CREATE EXTENSION IF NOT EXISTS "pg_trgm";
        CREATE EXTENSION IF NOT EXISTS "btree_gin";
        
        CREATE TABLE IF NOT EXISTS domains (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) UNIQUE NOT NULL,
            status VARCHAR(50) DEFAULT 'pending',
            verification_token VARCHAR(255),
            verified_at TIMESTAMPTZ,
            ssl_enabled BOOLEAN DEFAULT FALSE,
            ssl_cert_path VARCHAR(500),
            ssl_key_path VARCHAR(500),
            ssl_expires_at TIMESTAMPTZ,
            dkim_private_key TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS dns_records (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            domain_id UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            record_type VARCHAR(10) NOT NULL,
            content TEXT NOT NULL,
            ttl INTEGER DEFAULT 3600,
            priority INTEGER,
            disabled BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS domain_health_checks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            domain_id UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            check_type VARCHAR(50) NOT NULL,
            status VARCHAR(20) NOT NULL,
            response_time_ms INTEGER,
            error_message TEXT,
            checked_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            domain_id UUID NOT NULL REFERENCES domains(id),
            quota_bytes BIGINT DEFAULT 1073741824, -- 1GB default
            used_bytes BIGINT DEFAULT 0,
            active BOOLEAN DEFAULT TRUE,
            two_factor_enabled BOOLEAN DEFAULT FALSE,
            totp_secret VARCHAR(255),
            last_login TIMESTAMPTZ,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token VARCHAR(255) UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_activity TIMESTAMPTZ DEFAULT NOW(),
            ip_address INET,
            user_agent TEXT
        );
        
        CREATE TABLE IF NOT EXISTS security_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            event_type VARCHAR(50) NOT NULL,
            ip_address INET,
            user_agent TEXT,
            details TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS mailboxes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            uidvalidity INTEGER NOT NULL DEFAULT extract(epoch from now())::integer,
            uidnext INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(user_id, name)
        );
        
        CREATE TABLE IF NOT EXISTS messages (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            mailbox_id UUID NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
            uid INTEGER NOT NULL,
            message_id VARCHAR(255),
            thread_id VARCHAR(255),
            subject TEXT,
            sender VARCHAR(255),
            recipients TEXT[],
            cc TEXT[],
            bcc TEXT[],
            reply_to VARCHAR(255),
            body_text TEXT,
            body_html TEXT,
            raw_message BYTEA,
            compressed_message BYTEA,
            size_bytes INTEGER NOT NULL,
            compressed_size_bytes INTEGER,
            flags TEXT[] DEFAULT '{}',
            labels TEXT[] DEFAULT '{}',
            priority INTEGER DEFAULT 3,
            spam_score REAL DEFAULT 0.0,
            virus_scan_status VARCHAR(20) DEFAULT 'pending',
            content_hash VARCHAR(64),
            search_vector tsvector,
            has_attachments BOOLEAN DEFAULT FALSE,
            attachment_count INTEGER DEFAULT 0,
            internal_date TIMESTAMPTZ DEFAULT NOW(),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            archived_at TIMESTAMPTZ,
            UNIQUE(mailbox_id, uid)
        );
        
        CREATE TABLE IF NOT EXISTS message_attachments (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            filename VARCHAR(255) NOT NULL,
            content_type VARCHAR(100),
            content_disposition VARCHAR(50),
            content_id VARCHAR(255),
            size_bytes INTEGER NOT NULL,
            content_hash VARCHAR(64),
            storage_path VARCHAR(500),
            compressed BOOLEAN DEFAULT FALSE,
            virus_scan_status VARCHAR(20) DEFAULT 'pending',
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS message_headers (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            value TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS storage_usage (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            mailbox_id UUID REFERENCES mailboxes(id) ON DELETE CASCADE,
            usage_type VARCHAR(50) NOT NULL, -- 'messages', 'attachments', 'total'
            bytes_used BIGINT NOT NULL DEFAULT 0,
            message_count INTEGER NOT NULL DEFAULT 0,
            last_calculated TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(user_id, mailbox_id, usage_type)
        );
        
        CREATE TABLE IF NOT EXISTS archive_policies (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            domain_id UUID REFERENCES domains(id) ON DELETE CASCADE,
            policy_name VARCHAR(100) NOT NULL,
            archive_after_days INTEGER NOT NULL DEFAULT 365,
            compress_after_days INTEGER NOT NULL DEFAULT 30,
            delete_after_days INTEGER, -- NULL means never delete
            enabled BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS message_deduplication (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            content_hash VARCHAR(64) NOT NULL,
            first_message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            duplicate_count INTEGER DEFAULT 1,
            last_seen TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(content_hash)
        );
        
        CREATE TABLE IF NOT EXISTS backup_jobs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            job_type VARCHAR(50) NOT NULL, -- 'full', 'incremental', 'differential'
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            backup_path VARCHAR(500),
            size_bytes BIGINT,
            message_count INTEGER,
            error_message TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS storage_metrics (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            metric_type VARCHAR(50) NOT NULL,
            metric_value REAL NOT NULL,
            labels JSONB,
            recorded_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        -- Enhanced indexes for performance
        CREATE INDEX IF NOT EXISTS idx_messages_search_vector ON messages USING GIN(search_vector);
        CREATE INDEX IF NOT EXISTS idx_messages_content_hash ON messages(content_hash);
        CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id);
        CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
        CREATE INDEX IF NOT EXISTS idx_messages_subject ON messages USING GIN(to_tsvector('english', subject));
        CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(internal_date DESC);
        CREATE INDEX IF NOT EXISTS idx_messages_flags_gin ON messages USING GIN(flags);
        CREATE INDEX IF NOT EXISTS idx_messages_labels_gin ON messages USING GIN(labels);
        CREATE INDEX IF NOT EXISTS idx_messages_spam_score ON messages(spam_score);
        CREATE INDEX IF NOT EXISTS idx_messages_archived ON messages(archived_at) WHERE archived_at IS NOT NULL;
        
        CREATE INDEX IF NOT EXISTS idx_attachments_message ON message_attachments(message_id);
        CREATE INDEX IF NOT EXISTS idx_attachments_hash ON message_attachments(content_hash);
        CREATE INDEX IF NOT EXISTS idx_attachments_filename ON message_attachments USING GIN(to_tsvector('english', filename));
        
        CREATE INDEX IF NOT EXISTS idx_headers_message ON message_headers(message_id);
        CREATE INDEX IF NOT EXISTS idx_headers_name ON message_headers(name);
        CREATE INDEX IF NOT EXISTS idx_headers_value_gin ON message_headers USING GIN(to_tsvector('english', value));
        
        CREATE INDEX IF NOT EXISTS idx_storage_usage_user ON storage_usage(user_id);
        CREATE INDEX IF NOT EXISTS idx_storage_usage_mailbox ON storage_usage(mailbox_id);
        CREATE INDEX IF NOT EXISTS idx_storage_usage_type ON storage_usage(usage_type);
        
        CREATE INDEX IF NOT EXISTS idx_dedup_hash ON message_deduplication(content_hash);
        CREATE INDEX IF NOT EXISTS idx_dedup_count ON message_deduplication(duplicate_count DESC);
        
        -- Triggers for automatic search vector updates
        CREATE OR REPLACE FUNCTION update_message_search_vector() RETURNS trigger AS $$
        BEGIN
            NEW.search_vector := 
                setweight(to_tsvector('english', COALESCE(NEW.subject, '')), 'A') ||
                setweight(to_tsvector('english', COALESCE(NEW.sender, '')), 'B') ||
                setweight(to_tsvector('english', COALESCE(NEW.body_text, '')), 'C') ||
                setweight(to_tsvector('english', array_to_string(NEW.recipients, ' ')), 'D');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        
        DROP TRIGGER IF EXISTS trigger_update_message_search_vector ON messages;
        CREATE TRIGGER trigger_update_message_search_vector
            BEFORE INSERT OR UPDATE ON messages
            FOR EACH ROW EXECUTE FUNCTION update_message_search_vector();
        
        -- Function for storage usage calculation
        CREATE OR REPLACE FUNCTION calculate_storage_usage(user_uuid UUID) RETURNS void AS $$
        BEGIN
            -- Update message storage usage
            INSERT INTO storage_usage (user_id, usage_type, bytes_used, message_count, last_calculated)
            SELECT 
                user_uuid,
                'messages',
                COALESCE(SUM(m.size_bytes), 0),
                COUNT(m.id),
                NOW()
            FROM mailboxes mb
            LEFT JOIN messages m ON mb.id = m.mailbox_id
            WHERE mb.user_id = user_uuid
            ON CONFLICT (user_id, mailbox_id, usage_type) 
            DO UPDATE SET 
                bytes_used = EXCLUDED.bytes_used,
                message_count = EXCLUDED.message_count,
                last_calculated = EXCLUDED.last_calculated;
            
            -- Update attachment storage usage
            INSERT INTO storage_usage (user_id, usage_type, bytes_used, message_count, last_calculated)
            SELECT 
                user_uuid,
                'attachments',
                COALESCE(SUM(ma.size_bytes), 0),
                COUNT(ma.id),
                NOW()
            FROM mailboxes mb
            LEFT JOIN messages m ON mb.id = m.mailbox_id
            LEFT JOIN message_attachments ma ON m.id = ma.message_id
            WHERE mb.user_id = user_uuid
            ON CONFLICT (user_id, mailbox_id, usage_type) 
            DO UPDATE SET 
                bytes_used = EXCLUDED.bytes_used,
                message_count = EXCLUDED.message_count,
                last_calculated = EXCLUDED.last_calculated;
        END;
        $$ LANGUAGE plpgsql;
        "#
    )
    .execute(pool)
    .await?;

    info!("Database migrations completed successfully");
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageManager {
    pool: PgPool,
    compression_enabled: bool,
    deduplication_enabled: bool,
    archive_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageStorage {
    pub id: Uuid,
    pub mailbox_id: Uuid,
    pub uid: i32,
    pub message_id: Option<String>,
    pub thread_id: Option<String>,
    pub subject: Option<String>,
    pub sender: Option<String>,
    pub recipients: Vec<String>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub size_bytes: i32,
    pub flags: Vec<String>,
    pub labels: Vec<String>,
    pub has_attachments: bool,
    pub attachment_count: i32,
    pub spam_score: f32,
    pub content_hash: Option<String>,
    pub internal_date: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentStorage {
    pub id: Uuid,
    pub message_id: Uuid,
    pub filename: String,
    pub content_type: Option<String>,
    pub size_bytes: i32,
    pub content_hash: Option<String>,
    pub storage_path: Option<String>,
    pub compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageQuota {
    pub user_id: Uuid,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub message_count: i32,
    pub attachment_bytes: i64,
    pub last_calculated: DateTime<Utc>,
}

impl StorageManager {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            compression_enabled: true,
            deduplication_enabled: true,
            archive_enabled: true,
        }
    }

    pub async fn store_message(
        &self,
        message: &MessageStorage,
        raw_content: &[u8],
    ) -> Result<Uuid> {
        let mut tx = self.pool.begin().await?;

        // Calculate content hash for deduplication
        let content_hash = sha256::digest(raw_content);

        // Check for duplicates if deduplication is enabled
        if self.deduplication_enabled {
            if let Some(existing_id) = self.check_duplicate(&content_hash).await? {
                // Update duplicate count
                sqlx::query(
                    "UPDATE message_deduplication SET duplicate_count = duplicate_count + 1, last_seen = NOW() WHERE content_hash = $1"
                )
                .bind(&content_hash)
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
                return Ok(existing_id);
            }
        }

        // Compress message if enabled and size is above threshold
        let (raw_message, compressed_message, compressed_size) =
            if self.compression_enabled && raw_content.len() > 1024 {
                let compressed = self.compress_content(raw_content)?;
                (
                    None,
                    Some(compressed.clone()),
                    Some(compressed.len() as i32),
                )
            } else {
                (Some(raw_content.to_vec()), None, None)
            };

        // Insert message
        let message_id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO messages (
                mailbox_id, uid, message_id, thread_id, subject, sender, recipients, cc, bcc,
                body_text, body_html, raw_message, compressed_message, size_bytes, compressed_size_bytes,
                flags, labels, spam_score, content_hash, has_attachments, attachment_count, internal_date
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
            RETURNING id
            "#
        )
        .bind(message.mailbox_id)
        .bind(message.uid)
        .bind(&message.message_id)
        .bind(&message.thread_id)
        .bind(&message.subject)
        .bind(&message.sender)
        .bind(&message.recipients)
        .bind(&Vec::<String>::new()) // cc
        .bind(&Vec::<String>::new()) // bcc
        .bind(&message.body_text)
        .bind(&message.body_html)
        .bind(raw_message)
        .bind(compressed_message)
        .bind(message.size_bytes)
        .bind(compressed_size)
        .bind(&message.flags)
        .bind(&message.labels)
        .bind(message.spam_score)
        .bind(&content_hash)
        .bind(message.has_attachments)
        .bind(message.attachment_count)
        .bind(message.internal_date)
        .fetch_one(&mut *tx)
        .await?;

        // Record for deduplication
        if self.deduplication_enabled {
            sqlx::query(
                "INSERT INTO message_deduplication (content_hash, first_message_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            )
            .bind(&content_hash)
            .bind(message_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        // Update storage usage asynchronously
        self.update_storage_usage(message.mailbox_id).await?;

        Ok(message_id)
    }

    pub async fn search_messages(
        &self,
        mailbox_id: Uuid,
        query: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<MessageStorage>> {
        let messages = sqlx::query_as::<_, MessageStorage>(
            r#"
            SELECT id, mailbox_id, uid, message_id, thread_id, subject, sender, recipients,
                   body_text, body_html, size_bytes, flags, labels, has_attachments, attachment_count,
                   spam_score, content_hash, internal_date, archived_at
            FROM messages 
            WHERE mailbox_id = $1 AND search_vector @@ plainto_tsquery('english', $2)
            ORDER BY ts_rank(search_vector, plainto_tsquery('english', $2)) DESC, internal_date DESC
            LIMIT $3 OFFSET $4
            "#
        )
        .bind(mailbox_id)
        .bind(query)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(messages)
    }

    pub async fn get_storage_quota(&self, user_id: Uuid) -> Result<StorageQuota> {
        let quota = sqlx::query_as::<_, StorageQuota>(
            r#"
            SELECT u.id as user_id, u.quota_bytes, u.used_bytes,
                   COALESCE(su_msg.message_count, 0) as message_count,
                   COALESCE(su_att.bytes_used, 0) as attachment_bytes,
                   COALESCE(su_msg.last_calculated, NOW()) as last_calculated
            FROM users u
            LEFT JOIN storage_usage su_msg ON u.id = su_msg.user_id AND su_msg.usage_type = 'messages'
            LEFT JOIN storage_usage su_att ON u.id = su_att.user_id AND su_att.usage_type = 'attachments'
            WHERE u.id = $1
            "#
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(quota)
    }

    pub async fn archive_old_messages(&self, days_old: i32) -> Result<i32> {
        if !self.archive_enabled {
            return Ok(0);
        }

        let archived_count = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE messages SET archived_at = NOW()
            WHERE archived_at IS NULL 
            AND internal_date < NOW() - INTERVAL '%d days'
            AND NOT ('\\Important' = ANY(flags))
            "#,
        )
        .bind(days_old)
        .fetch_one(&self.pool)
        .await?;

        info!("Archived {} old messages", archived_count);
        Ok(archived_count as i32)
    }

    pub async fn compress_old_messages(&self, days_old: i32) -> Result<i32> {
        if !self.compression_enabled {
            return Ok(0);
        }

        let messages = sqlx::query!(
            "SELECT id, raw_message FROM messages WHERE compressed_message IS NULL AND internal_date < NOW() - INTERVAL '%d days'",
            days_old
        )
        .fetch_all(&self.pool)
        .await?;

        let mut compressed_count = 0;

        for message in messages {
            if let Some(raw_content) = message.raw_message {
                let compressed = self.compress_content(&raw_content)?;

                sqlx::query(
                    "UPDATE messages SET compressed_message = $1, compressed_size_bytes = $2, raw_message = NULL WHERE id = $3"
                )
                .bind(&compressed)
                .bind(compressed.len() as i32)
                .bind(message.id)
                .execute(&self.pool)
                .await?;

                compressed_count += 1;
            }
        }

        info!("Compressed {} old messages", compressed_count);
        Ok(compressed_count)
    }

    async fn check_duplicate(&self, content_hash: &str) -> Result<Option<Uuid>> {
        let result = sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT first_message_id FROM message_deduplication WHERE content_hash = $1",
        )
        .bind(content_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.flatten())
    }

    async fn update_storage_usage(&self, mailbox_id: Uuid) -> Result<()> {
        // Get user_id from mailbox
        let user_id = sqlx::query_scalar::<_, Uuid>("SELECT user_id FROM mailboxes WHERE id = $1")
            .bind(mailbox_id)
            .fetch_one(&self.pool)
            .await?;

        // Call the stored procedure to calculate usage
        sqlx::query("SELECT calculate_storage_usage($1)")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    fn compress_content(&self, content: &[u8]) -> Result<Vec<u8>> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content)?;
        Ok(encoder.finish()?)
    }

    pub async fn create_backup(&self, backup_type: &str) -> Result<Uuid> {
        let backup_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO backup_jobs (job_type, status, started_at) VALUES ($1, 'running', NOW()) RETURNING id"
        )
        .bind(backup_type)
        .fetch_one(&self.pool)
        .await?;

        // Backup logic would go here - this is a placeholder
        info!("Starting {} backup with ID: {}", backup_type, backup_id);

        Ok(backup_id)
    }
}
