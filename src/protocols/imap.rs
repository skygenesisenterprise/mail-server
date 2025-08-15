use crate::config::ImapConfig;
use crate::error::{MailServerError, Result};
use crate::protocols::{ProtocolServer, ServerContext};
use crate::auth::{AuthService, User};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{info, error, debug, warn};
use uuid::Uuid;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use base64;

pub struct ImapServer {
    config: ImapConfig,
    context: ServerContext,
}

impl ImapServer {
    pub fn new(config: ImapConfig, db_pool: PgPool, tls_acceptor: Arc<TlsAcceptor>) -> Self {
        Self {
            config,
            context: ServerContext::new(db_pool, tls_acceptor),
        }
    }
}

#[async_trait::async_trait]
impl ProtocolServer for ImapServer {
    async fn start(&self) -> Result<()> {
        let bind_addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let tls_bind_addr = format!("{}:{}", self.config.bind_address, self.config.tls_port);
        
        info!("Starting IMAP server on {} (plain) and {} (TLS)", bind_addr, tls_bind_addr);
        
        // Start both plain and TLS listeners
        let plain_listener = TcpListener::bind(&bind_addr).await?;
        let tls_listener = TcpListener::bind(&tls_bind_addr).await?;
        
        let context = Arc::new(self.context.clone());
        let config = Arc::new(self.config.clone());
        
        // Handle plain IMAP connections
        let plain_context = context.clone();
        let plain_config = config.clone();
        tokio::spawn(async move {
            loop {
                match plain_listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New IMAP connection from {}", addr);
                        let ctx = plain_context.clone();
                        let cfg = plain_config.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_imap_connection(stream, ctx, cfg, false).await {
                                error!("IMAP connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => error!("Failed to accept IMAP connection: {}", e),
                }
            }
        });
        
        // Handle TLS IMAP connections
        let tls_context = context.clone();
        let tls_config = config.clone();
        tokio::spawn(async move {
            loop {
                match tls_listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New IMAP TLS connection from {}", addr);
                        let ctx = tls_context.clone();
                        let cfg = tls_config.clone();
                        let tls_acceptor = ctx.tls_acceptor.clone();
                        tokio::spawn(async move {
                            match tls_acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    if let Err(e) = handle_imap_tls_connection(tls_stream, ctx, cfg).await {
                                        error!("IMAP TLS connection error: {}", e);
                                    }
                                }
                                Err(e) => error!("TLS handshake failed: {}", e),
                            }
                        });
                    }
                    Err(e) => error!("Failed to accept IMAP TLS connection: {}", e),
                }
            }
        });
        
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        info!("Stopping IMAP server");
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum ImapState {
    NotAuthenticated,
    Authenticated(User),
    Selected(User, Mailbox),
    Logout,
}

#[derive(Debug, Clone)]
struct Mailbox {
    id: Uuid,
    name: String,
    uidvalidity: i32,
    uidnext: i32,
    exists: i32,
    recent: i32,
    unseen: i32,
}

#[derive(Debug, Clone)]
struct ImapMessage {
    id: Uuid,
    uid: i32,
    sequence: i32,
    message_id: Option<String>,
    subject: Option<String>,
    sender: Option<String>,
    recipients: Vec<String>,
    body_text: Option<String>,
    body_html: Option<String>,
    raw_message: Vec<u8>,
    size_bytes: i32,
    flags: Vec<String>,
    internal_date: DateTime<Utc>,
}

struct ImapSession {
    state: ImapState,
    auth_service: AuthService,
    db_pool: PgPool,
    config: Arc<ImapConfig>,
    sequence_map: HashMap<i32, i32>, // sequence number -> UID mapping
}

impl ImapSession {
    fn new(db_pool: PgPool, config: Arc<ImapConfig>) -> Self {
        Self {
            state: ImapState::NotAuthenticated,
            auth_service: AuthService::new(db_pool.clone()),
            db_pool,
            config,
            sequence_map: HashMap::new(),
        }
    }

    async fn handle_command(&mut self, tag: &str, command: &str) -> Result<String> {
        let parts: Vec<&str> = command.trim().split_whitespace().collect();
        if parts.is_empty() {
            return Ok(format!("{} BAD Command unrecognized\r\n", tag));
        }

        let cmd = parts[0].to_uppercase();
        debug!("Processing IMAP command: {} {}", tag, cmd);

        match cmd.as_str() {
            "CAPABILITY" => self.handle_capability(tag).await,
            "LOGIN" => self.handle_login(tag, &parts).await,
            "AUTHENTICATE" => self.handle_authenticate(tag, &parts).await,
            "SELECT" => self.handle_select(tag, &parts).await,
            "EXAMINE" => self.handle_examine(tag, &parts).await,
            "CREATE" => self.handle_create(tag, &parts).await,
            "DELETE" => self.handle_delete(tag, &parts).await,
            "RENAME" => self.handle_rename(tag, &parts).await,
            "LIST" => self.handle_list(tag, &parts).await,
            "LSUB" => self.handle_lsub(tag, &parts).await,
            "STATUS" => self.handle_status(tag, &parts).await,
            "APPEND" => self.handle_append(tag, &parts).await,
            "CHECK" => self.handle_check(tag).await,
            "CLOSE" => self.handle_close(tag).await,
            "EXPUNGE" => self.handle_expunge(tag).await,
            "SEARCH" => self.handle_search(tag, &parts).await,
            "FETCH" => self.handle_fetch(tag, &parts).await,
            "STORE" => self.handle_store(tag, &parts).await,
            "COPY" => self.handle_copy(tag, &parts).await,
            "UID" => self.handle_uid(tag, &parts).await,
            "IDLE" => self.handle_idle(tag).await,
            "LOGOUT" => self.handle_logout(tag).await,
            "NOOP" => Ok(format!("{} OK NOOP completed\r\n", tag)),
            "STARTTLS" => Ok(format!("{} OK Begin TLS negotiation now\r\n", tag)),
            _ => Ok(format!("{} BAD Command unrecognized\r\n", tag)),
        }
    }

    async fn handle_capability(&self, tag: &str) -> Result<String> {
        Ok(format!(
            "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN IDLE UIDPLUS\r\n{} OK CAPABILITY completed\r\n",
            tag
        ))
    }

    async fn handle_login(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        if !matches!(self.state, ImapState::NotAuthenticated) {
            return Ok(format!("{} BAD Already authenticated\r\n", tag));
        }

        if parts.len() < 3 {
            return Ok(format!("{} BAD LOGIN requires username and password\r\n", tag));
        }

        let username = parts[1].trim_matches('"');
        let password = parts[2].trim_matches('"');

        match self.auth_service.authenticate(username, password).await? {
            Some(user) => {
                self.state = ImapState::Authenticated(user);
                Ok(format!("{} OK LOGIN completed\r\n", tag))
            }
            None => Ok(format!("{} NO LOGIN failed\r\n", tag)),
        }
    }

    async fn handle_authenticate(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        if !matches!(self.state, ImapState::NotAuthenticated) {
            return Ok(format!("{} BAD Already authenticated\r\n", tag));
        }

        if parts.len() < 2 {
            return Ok(format!("{} BAD AUTHENTICATE requires mechanism\r\n", tag));
        }

        match parts[1].to_uppercase().as_str() {
            "PLAIN" => {
                Ok("+ \r\n".to_string()) // Request credentials
            }
            _ => Ok(format!("{} NO Authentication mechanism not supported\r\n", tag)),
        }
    }

    async fn handle_select(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        let user = match &self.state {
            ImapState::Authenticated(user) | ImapState::Selected(user, _) => user.clone(),
            _ => return Ok(format!("{} NO Not authenticated\r\n", tag)),
        };

        if parts.len() < 2 {
            return Ok(format!("{} BAD SELECT requires mailbox name\r\n", tag));
        }

        let mailbox_name = parts[1].trim_matches('"');
        
        match self.get_mailbox(&user, mailbox_name).await? {
            Some(mailbox) => {
                // Build sequence number mapping
                self.build_sequence_map(&mailbox).await?;
                
                let response = format!(
                    "* {} EXISTS\r\n* {} RECENT\r\n* OK [UNSEEN {}] Message {} is first unseen\r\n* OK [UIDVALIDITY {}] UIDs valid\r\n* OK [UIDNEXT {}] Predicted next UID\r\n* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Limited\r\n{} OK [READ-WRITE] SELECT completed\r\n",
                    mailbox.exists,
                    mailbox.recent,
                    mailbox.unseen,
                    mailbox.unseen,
                    mailbox.uidvalidity,
                    mailbox.uidnext,
                    tag
                );
                
                self.state = ImapState::Selected(user, mailbox);
                Ok(response)
            }
            None => Ok(format!("{} NO Mailbox does not exist\r\n", tag)),
        }
    }

    async fn handle_examine(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        // Similar to SELECT but read-only
        let user = match &self.state {
            ImapState::Authenticated(user) | ImapState::Selected(user, _) => user.clone(),
            _ => return Ok(format!("{} NO Not authenticated\r\n", tag)),
        };

        if parts.len() < 2 {
            return Ok(format!("{} BAD EXAMINE requires mailbox name\r\n", tag));
        }

        let mailbox_name = parts[1].trim_matches('"');
        
        match self.get_mailbox(&user, mailbox_name).await? {
            Some(mailbox) => {
                self.build_sequence_map(&mailbox).await?;
                
                let response = format!(
                    "* {} EXISTS\r\n* {} RECENT\r\n* OK [UNSEEN {}] Message {} is first unseen\r\n* OK [UIDVALIDITY {}] UIDs valid\r\n* OK [UIDNEXT {}] Predicted next UID\r\n* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n* OK [PERMANENTFLAGS ()] No permanent flags permitted\r\n{} OK [READ-ONLY] EXAMINE completed\r\n",
                    mailbox.exists,
                    mailbox.recent,
                    mailbox.unseen,
                    mailbox.unseen,
                    mailbox.uidvalidity,
                    mailbox.uidnext,
                    tag
                );
                
                self.state = ImapState::Selected(user, mailbox);
                Ok(response)
            }
            None => Ok(format!("{} NO Mailbox does not exist\r\n", tag)),
        }
    }

    async fn handle_create(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        let user = match &self.state {
            ImapState::Authenticated(user) | ImapState::Selected(user, _) => user.clone(),
            _ => return Ok(format!("{} NO Not authenticated\r\n", tag)),
        };

        if parts.len() < 2 {
            return Ok(format!("{} BAD CREATE requires mailbox name\r\n", tag));
        }

        let mailbox_name = parts[1].trim_matches('"');
        
        // Check if mailbox already exists
        if self.get_mailbox(&user, mailbox_name).await?.is_some() {
            return Ok(format!("{} NO Mailbox already exists\r\n", tag));
        }

        // Create the mailbox
        sqlx::query!(
            "INSERT INTO mailboxes (user_id, name) VALUES ($1, $2)",
            user.id,
            mailbox_name
        )
        .execute(&self.db_pool)
        .await?;

        Ok(format!("{} OK CREATE completed\r\n", tag))
    }

    async fn handle_delete(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        let user = match &self.state {
            ImapState::Authenticated(user) | ImapState::Selected(user, _) => user.clone(),
            _ => return Ok(format!("{} NO Not authenticated\r\n", tag)),
        };

        if parts.len() < 2 {
            return Ok(format!("{} BAD DELETE requires mailbox name\r\n", tag));
        }

        let mailbox_name = parts[1].trim_matches('"');
        
        // Don't allow deleting INBOX
        if mailbox_name.to_uppercase() == "INBOX" {
            return Ok(format!("{} NO Cannot delete INBOX\r\n", tag));
        }

        // Delete the mailbox and all its messages
        let result = sqlx::query!(
            "DELETE FROM mailboxes WHERE user_id = $1 AND name = $2",
            user.id,
            mailbox_name
        )
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() > 0 {
            Ok(format!("{} OK DELETE completed\r\n", tag))
        } else {
            Ok(format!("{} NO Mailbox does not exist\r\n", tag))
        }
    }

    async fn handle_rename(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        let user = match &self.state {
            ImapState::Authenticated(user) | ImapState::Selected(user, _) => user.clone(),
            _ => return Ok(format!("{} NO Not authenticated\r\n", tag)),
        };

        if parts.len() < 3 {
            return Ok(format!("{} BAD RENAME requires old and new mailbox names\r\n", tag));
        }

        let old_name = parts[1].trim_matches('"');
        let new_name = parts[2].trim_matches('"');
        
        // Don't allow renaming INBOX
        if old_name.to_uppercase() == "INBOX" {
            return Ok(format!("{} NO Cannot rename INBOX\r\n", tag));
        }

        let result = sqlx::query!(
            "UPDATE mailboxes SET name = $1 WHERE user_id = $2 AND name = $3",
            new_name,
            user.id,
            old_name
        )
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() > 0 {
            Ok(format!("{} OK RENAME completed\r\n", tag))
        } else {
            Ok(format!("{} NO Mailbox does not exist\r\n", tag))
        }
    }

    async fn handle_list(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        let user = match &self.state {
            ImapState::Authenticated(user) | ImapState::Selected(user, _) => user.clone(),
            _ => return Ok(format!("{} NO Not authenticated\r\n", tag)),
        };

        if parts.len() < 3 {
            return Ok(format!("{} BAD LIST requires reference and mailbox pattern\r\n", tag));
        }

        let _reference = parts[1].trim_matches('"');
        let pattern = parts[2].trim_matches('"');
        
        let mailboxes = if pattern == "*" || pattern == "%" {
            // List all mailboxes
            sqlx::query!(
                "SELECT name FROM mailboxes WHERE user_id = $1 ORDER BY name",
                user.id
            )
            .fetch_all(&self.db_pool)
            .await?
        } else {
            // Pattern matching - simplified implementation
            sqlx::query!(
                "SELECT name FROM mailboxes WHERE user_id = $1 AND name ILIKE $2 ORDER BY name",
                user.id,
                pattern.replace('*', "%")
            )
            .fetch_all(&self.db_pool)
            .await?
        };

        let mut response = String::new();
        for mailbox in mailboxes {
            response.push_str(&format!("* LIST () \"/\" \"{}\"\r\n", mailbox.name));
        }
        response.push_str(&format!("{} OK LIST completed\r\n", tag));

        Ok(response)
    }

    async fn handle_lsub(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        // For simplicity, LSUB returns the same as LIST
        self.handle_list(tag, parts).await
    }

    async fn handle_status(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        let user = match &self.state {
            ImapState::Authenticated(user) | ImapState::Selected(user, _) => user.clone(),
            _ => return Ok(format!("{} NO Not authenticated\r\n", tag)),
        };

        if parts.len() < 3 {
            return Ok(format!("{} BAD STATUS requires mailbox name and status items\r\n", tag));
        }

        let mailbox_name = parts[1].trim_matches('"');
        
        match self.get_mailbox(&user, mailbox_name).await? {
            Some(mailbox) => {
                let response = format!(
                    "* STATUS \"{}\" (MESSAGES {} RECENT {} UIDNEXT {} UIDVALIDITY {} UNSEEN {})\r\n{} OK STATUS completed\r\n",
                    mailbox_name,
                    mailbox.exists,
                    mailbox.recent,
                    mailbox.uidnext,
                    mailbox.uidvalidity,
                    mailbox.unseen,
                    tag
                );
                Ok(response)
            }
            None => Ok(format!("{} NO Mailbox does not exist\r\n", tag)),
        }
    }

    async fn handle_append(&mut self, tag: &str, _parts: &[&str]) -> Result<String> {
        // APPEND implementation would be complex - simplified for now
        Ok(format!("{} NO APPEND not implemented\r\n", tag))
    }

    async fn handle_check(&mut self, tag: &str) -> Result<String> {
        match &self.state {
            ImapState::Selected(_, _) => Ok(format!("{} OK CHECK completed\r\n", tag)),
            _ => Ok(format!("{} NO No mailbox selected\r\n", tag)),
        }
    }

    async fn handle_close(&mut self, tag: &str) -> Result<String> {
        match &self.state {
            ImapState::Selected(user, _) => {
                self.state = ImapState::Authenticated(user.clone());
                self.sequence_map.clear();
                Ok(format!("{} OK CLOSE completed\r\n", tag))
            }
            _ => Ok(format!("{} NO No mailbox selected\r\n", tag)),
        }
    }

    async fn handle_expunge(&mut self, tag: &str) -> Result<String> {
        let (user, mailbox) = match &self.state {
            ImapState::Selected(user, mailbox) => (user.clone(), mailbox.clone()),
            _ => return Ok(format!("{} NO No mailbox selected\r\n", tag)),
        };

        // Delete messages marked with \Deleted flag
        let deleted_messages = sqlx::query!(
            "DELETE FROM messages WHERE mailbox_id = $1 AND '\\Deleted' = ANY(flags) RETURNING uid",
            mailbox.id
        )
        .fetch_all(&self.db_pool)
        .await?;

        let mut response = String::new();
        for msg in deleted_messages {
            // Find sequence number for this UID
            if let Some(seq) = self.sequence_map.iter().find(|(_, &uid)| uid == msg.uid).map(|(&seq, _)| seq) {
                response.push_str(&format!("* {} EXPUNGE\r\n", seq));
            }
        }

        // Rebuild sequence map
        self.build_sequence_map(&mailbox).await?;
        
        response.push_str(&format!("{} OK EXPUNGE completed\r\n", tag));
        Ok(response)
    }

    async fn handle_search(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        let (_user, mailbox) = match &self.state {
            ImapState::Selected(user, mailbox) => (user.clone(), mailbox.clone()),
            _ => return Ok(format!("{} NO No mailbox selected\r\n", tag)),
        };

        if parts.len() < 2 {
            return Ok(format!("{} BAD SEARCH requires search criteria\r\n", tag));
        }

        // Simplified search - just return all messages for now
        let messages = sqlx::query!(
            "SELECT uid FROM messages WHERE mailbox_id = $1 ORDER BY uid",
            mailbox.id
        )
        .fetch_all(&self.db_pool)
        .await?;

        let mut response = String::from("* SEARCH");
        for msg in messages {
            response.push_str(&format!(" {}", msg.uid));
        }
        response.push_str(&format!("\r\n{} OK SEARCH completed\r\n", tag));

        Ok(response)
    }

    async fn handle_fetch(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        let (_user, mailbox) = match &self.state {
            ImapState::Selected(user, mailbox) => (user.clone(), mailbox.clone()),
            _ => return Ok(format!("{} NO No mailbox selected\r\n", tag)),
        };

        if parts.len() < 3 {
            return Ok(format!("{} BAD FETCH requires sequence set and message data item names\r\n", tag));
        }

        let sequence_set = parts[1];
        let data_items = parts[2..].join(" ");

        // Parse sequence set (simplified - just handle single numbers and ranges)
        let sequences = self.parse_sequence_set(sequence_set);
        
        let mut response = String::new();
        for seq in sequences {
            if let Some(&uid) = self.sequence_map.get(&seq) {
                if let Some(message) = self.get_message_by_uid(&mailbox, uid).await? {
                    response.push_str(&self.format_fetch_response(seq, &message, &data_items));
                }
            }
        }
        
        response.push_str(&format!("{} OK FETCH completed\r\n", tag));
        Ok(response)
    }

    async fn handle_store(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        let (_user, mailbox) = match &self.state {
            ImapState::Selected(user, mailbox) => (user.clone(), mailbox.clone()),
            _ => return Ok(format!("{} NO No mailbox selected\r\n", tag)),
        };

        if parts.len() < 4 {
            return Ok(format!("{} BAD STORE requires sequence set, message data item name, and value\r\n", tag));
        }

        let sequence_set = parts[1];
        let data_item = parts[2];
        let flags = parts[3..].join(" ");

        // Parse sequence set
        let sequences = self.parse_sequence_set(sequence_set);
        
        let mut response = String::new();
        for seq in sequences {
            if let Some(&uid) = self.sequence_map.get(&seq) {
                // Update flags in database
                if data_item.to_uppercase().contains("FLAGS") {
                    let flag_list: Vec<String> = flags
                        .trim_matches(['(', ')'])
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    
                    sqlx::query!(
                        "UPDATE messages SET flags = $1 WHERE mailbox_id = $2 AND uid = $3",
                        &flag_list,
                        mailbox.id,
                        uid
                    )
                    .execute(&self.db_pool)
                    .await?;
                    
                    response.push_str(&format!("* {} FETCH (FLAGS ({}))\r\n", seq, flags));
                }
            }
        }
        
        response.push_str(&format!("{} OK STORE completed\r\n", tag));
        Ok(response)
    }

    async fn handle_copy(&mut self, tag: &str, _parts: &[&str]) -> Result<String> {
        // COPY implementation would be complex - simplified for now
        Ok(format!("{} NO COPY not implemented\r\n", tag))
    }

    async fn handle_uid(&mut self, tag: &str, parts: &[&str]) -> Result<String> {
        if parts.len() < 2 {
            return Ok(format!("{} BAD UID requires command\r\n", tag));
        }

        let uid_command = parts[1].to_uppercase();
        match uid_command.as_str() {
            "FETCH" => {
                // Handle UID FETCH - similar to FETCH but with UIDs instead of sequence numbers
                Ok(format!("{} NO UID FETCH not fully implemented\r\n", tag))
            }
            "SEARCH" => {
                // Handle UID SEARCH
                Ok(format!("{} NO UID SEARCH not fully implemented\r\n", tag))
            }
            "STORE" => {
                // Handle UID STORE
                Ok(format!("{} NO UID STORE not fully implemented\r\n", tag))
            }
            "COPY" => {
                // Handle UID COPY
                Ok(format!("{} NO UID COPY not fully implemented\r\n", tag))
            }
            _ => Ok(format!("{} BAD Unknown UID command\r\n", tag)),
        }
    }

    async fn handle_idle(&mut self, tag: &str) -> Result<String> {
        match &self.state {
            ImapState::Selected(_, _) => {
                // IDLE implementation would require async notification system
                Ok(format!("+ idling\r\n{} OK IDLE terminated\r\n", tag))
            }
            _ => Ok(format!("{} NO No mailbox selected\r\n", tag)),
        }
    }

    async fn handle_logout(&mut self, tag: &str) -> Result<String> {
        self.state = ImapState::Logout;
        Ok(format!("* BYE IMAP4rev1 Server logging out\r\n{} OK LOGOUT completed\r\n", tag))
    }

    // Helper methods

    async fn get_mailbox(&self, user: &User, name: &str) -> Result<Option<Mailbox>> {
        let row = sqlx::query!(
            "SELECT id, name, uidvalidity, uidnext FROM mailboxes WHERE user_id = $1 AND name = $2",
            user.id,
            name
        )
        .fetch_optional(&self.db_pool)
        .await?;

        if let Some(row) = row {
            // Get message counts
            let exists = sqlx::query_scalar!(
                "SELECT COUNT(*) FROM messages WHERE mailbox_id = $1",
                row.id
            )
            .fetch_one(&self.db_pool)
            .await?
            .unwrap_or(0) as i32;

            let recent = sqlx::query_scalar!(
                "SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND '\\Recent' = ANY(flags)",
                row.id
            )
            .fetch_one(&self.db_pool)
            .await?
            .unwrap_or(0) as i32;

            let unseen = sqlx::query_scalar!(
                "SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND NOT ('\\Seen' = ANY(flags))",
                row.id
            )
            .fetch_one(&self.db_pool)
            .await?
            .unwrap_or(0) as i32;

            Ok(Some(Mailbox {
                id: row.id,
                name: row.name,
                uidvalidity: row.uidvalidity,
                uidnext: row.uidnext,
                exists,
                recent,
                unseen: if unseen > 0 { 1 } else { 0 }, // First unseen message sequence number
            }))
        } else {
            Ok(None)
        }
    }

    async fn build_sequence_map(&mut self, mailbox: &Mailbox) -> Result<()> {
        self.sequence_map.clear();
        
        let messages = sqlx::query!(
            "SELECT uid FROM messages WHERE mailbox_id = $1 ORDER BY uid",
            mailbox.id
        )
        .fetch_all(&self.db_pool)
        .await?;

        for (seq, msg) in messages.iter().enumerate() {
            self.sequence_map.insert((seq + 1) as i32, msg.uid);
        }

        Ok(())
    }

    async fn get_message_by_uid(&self, mailbox: &Mailbox, uid: i32) -> Result<Option<ImapMessage>> {
        let row = sqlx::query!(
            "SELECT id, uid, message_id, subject, sender, recipients, body_text, body_html, 
             raw_message, size_bytes, flags, internal_date 
             FROM messages WHERE mailbox_id = $1 AND uid = $2",
            mailbox.id,
            uid
        )
        .fetch_optional(&self.db_pool)
        .await?;

        if let Some(row) = row {
            // Find sequence number for this UID
            let sequence = self.sequence_map.iter()
                .find(|(_, &u)| u == uid)
                .map(|(&seq, _)| seq)
                .unwrap_or(0);

            Ok(Some(ImapMessage {
                id: row.id,
                uid: row.uid,
                sequence,
                message_id: row.message_id,
                subject: row.subject,
                sender: row.sender,
                recipients: row.recipients,
                body_text: row.body_text,
                body_html: row.body_html,
                raw_message: row.raw_message,
                size_bytes: row.size_bytes,
                flags: row.flags,
                internal_date: row.internal_date,
            }))
        } else {
            Ok(None)
        }
    }

    fn parse_sequence_set(&self, sequence_set: &str) -> Vec<i32> {
        let mut sequences = Vec::new();
        
        for part in sequence_set.split(',') {
            if part.contains(':') {
                // Range
                let range_parts: Vec<&str> = part.split(':').collect();
                if range_parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (range_parts[0].parse::<i32>(), range_parts[1].parse::<i32>()) {
                        for seq in start..=end {
                            sequences.push(seq);
                        }
                    }
                }
            } else {
                // Single number
                if let Ok(seq) = part.parse::<i32>() {
                    sequences.push(seq);
                }
            }
        }
        
        sequences
    }

    fn format_fetch_response(&self, sequence: i32, message: &ImapMessage, data_items: &str) -> String {
        let mut response = format!("* {} FETCH (", sequence);
        let mut items = Vec::new();

        if data_items.to_uppercase().contains("UID") {
            items.push(format!("UID {}", message.uid));
        }
        
        if data_items.to_uppercase().contains("FLAGS") {
            let flags_str = message.flags.join(" ");
            items.push(format!("FLAGS ({})", flags_str));
        }
        
        if data_items.to_uppercase().contains("INTERNALDATE") {
            items.push(format!("INTERNALDATE \"{}\"", message.internal_date.format("%d-%b-%Y %H:%M:%S %z")));
        }
        
        if data_items.to_uppercase().contains("RFC822.SIZE") {
            items.push(format!("RFC822.SIZE {}", message.size_bytes));
        }
        
        if data_items.to_uppercase().contains("ENVELOPE") {
            let subject = message.subject.as_deref().unwrap_or("NIL");
            let sender = message.sender.as_deref().unwrap_or("NIL");
            items.push(format!("ENVELOPE (NIL \"{}\" ((\"{}\" NIL \"user\" \"domain.com\")) NIL NIL NIL NIL NIL NIL NIL)", subject, sender));
        }
        
        if data_items.to_uppercase().contains("BODY") && !data_items.to_uppercase().contains("BODY.PEEK") {
            // Mark as seen when fetching body
            items.push("BODY (\"text\" \"plain\" NIL NIL NIL \"7bit\" {} NIL)".to_string());
        }

        response.push_str(&items.join(" "));
        response.push_str(")\r\n");
        response
    }
}

async fn handle_imap_connection(
    stream: TcpStream,
    context: Arc<ServerContext>,
    config: Arc<ImapConfig>,
    _use_tls: bool,
) -> Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    
    let mut session = ImapSession::new(context.db_pool.clone(), config.clone());

    // Send greeting
    writer.write_all(b"* OK IMAP4rev1 Service Ready\r\n").await?;
    writer.flush().await?;

    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // Connection closed
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Parse tag and command
                let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
                if parts.len() < 2 {
                    writer.write_all(b"* BAD Invalid command format\r\n").await?;
                    writer.flush().await?;
                    continue;
                }

                let tag = parts[0];
                let command = parts[1];

                let response = session.handle_command(tag, command).await?;
                writer.write_all(response.as_bytes()).await?;
                writer.flush().await?;

                // Check for logout
                if matches!(session.state, ImapState::Logout) {
                    break;
                }
            }
            Err(e) => {
                error!("Error reading from IMAP connection: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_imap_tls_connection(
    stream: TlsStream<TcpStream>,
    context: Arc<ServerContext>,
    config: Arc<ImapConfig>,
) -> Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    
    let mut session = ImapSession::new(context.db_pool.clone(), config.clone());

    // Send greeting
    writer.write_all(b"* OK IMAP4rev1 Service Ready (TLS)\r\n").await?;
    writer.flush().await?;

    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // Connection closed
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Parse tag and command
                let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
                if parts.len() < 2 {
                    writer.write_all(b"* BAD Invalid command format\r\n").await?;
                    writer.flush().await?;
                    continue;
                }

                let tag = parts[0];
                let command = parts[1];

                let response = session.handle_command(tag, command).await?;
                writer.write_all(response.as_bytes()).await?;
                writer.flush().await?;

                // Check for logout
                if matches!(session.state, ImapState::Logout) {
                    break;
                }
            }
            Err(e) => {
                error!("Error reading from IMAP TLS connection: {}", e);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_parsing() {
        // This would test the sequence set parsing logic
        // Implementation would go here
    }
}
