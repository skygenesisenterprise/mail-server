use crate::config::Pop3Config;
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
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};

pub struct Pop3Server {
    config: Pop3Config,
    context: ServerContext,
}

impl Pop3Server {
    pub fn new(config: Pop3Config, db_pool: PgPool, tls_acceptor: Arc<TlsAcceptor>) -> Self {
        Self {
            config,
            context: ServerContext::new(db_pool, tls_acceptor),
        }
    }
}

#[async_trait::async_trait]
impl ProtocolServer for Pop3Server {
    async fn start(&self) -> Result<()> {
        let bind_addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let tls_bind_addr = format!("{}:{}", self.config.bind_address, self.config.tls_port);
        
        info!("Starting POP3 server on {} (plain) and {} (TLS)", bind_addr, tls_bind_addr);
        
        // Start both plain and TLS listeners
        let plain_listener = TcpListener::bind(&bind_addr).await?;
        let tls_listener = TcpListener::bind(&tls_bind_addr).await?;
        
        let context = Arc::new(self.context.clone());
        let config = Arc::new(self.config.clone());
        
        // Handle plain POP3 connections
        let plain_context = context.clone();
        let plain_config = config.clone();
        tokio::spawn(async move {
            loop {
                match plain_listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New POP3 connection from {}", addr);
                        let ctx = plain_context.clone();
                        let cfg = plain_config.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_pop3_connection(stream, ctx, cfg, false).await {
                                error!("POP3 connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => error!("Failed to accept POP3 connection: {}", e),
                }
            }
        });
        
        // Handle TLS POP3 connections
        let tls_context = context.clone();
        let tls_config = config.clone();
        tokio::spawn(async move {
            loop {
                match tls_listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New POP3 TLS connection from {}", addr);
                        let ctx = tls_context.clone();
                        let cfg = tls_config.clone();
                        let tls_acceptor = ctx.tls_acceptor.clone();
                        tokio::spawn(async move {
                            match tls_acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    if let Err(e) = handle_pop3_tls_connection(tls_stream, ctx, cfg).await {
                                        error!("POP3 TLS connection error: {}", e);
                                    }
                                }
                                Err(e) => error!("TLS handshake failed: {}", e),
                            }
                        });
                    }
                    Err(e) => error!("Failed to accept POP3 TLS connection: {}", e),
                }
            }
        });
        
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        info!("Stopping POP3 server");
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum Pop3State {
    Authorization,
    Transaction(User, Vec<Pop3Message>),
    Update(User, Vec<Pop3Message>),
}

#[derive(Debug, Clone)]
struct Pop3Message {
    id: Uuid,
    uid: i32,
    message_number: i32,
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
    marked_for_deletion: bool,
}

struct Pop3Session {
    state: Pop3State,
    auth_service: AuthService,
    db_pool: PgPool,
    config: Arc<Pop3Config>,
    username: Option<String>,
    deleted_messages: HashSet<i32>, // Message numbers marked for deletion
}

impl Pop3Session {
    fn new(db_pool: PgPool, config: Arc<Pop3Config>) -> Self {
        Self {
            state: Pop3State::Authorization,
            auth_service: AuthService::new(db_pool.clone()),
            db_pool,
            config,
            username: None,
            deleted_messages: HashSet::new(),
        }
    }

    async fn handle_command(&mut self, command: &str) -> Result<String> {
        let parts: Vec<&str> = command.trim().split_whitespace().collect();
        if parts.is_empty() {
            return Ok("-ERR Command unrecognized\r\n".to_string());
        }

        let cmd = parts[0].to_uppercase();
        debug!("Processing POP3 command: {}", cmd);

        match cmd.as_str() {
            "CAPA" => self.handle_capa().await,
            "USER" => self.handle_user(&parts).await,
            "PASS" => self.handle_pass(&parts).await,
            "STAT" => self.handle_stat().await,
            "LIST" => self.handle_list(&parts).await,
            "RETR" => self.handle_retr(&parts).await,
            "DELE" => self.handle_dele(&parts).await,
            "NOOP" => Ok("+OK\r\n".to_string()),
            "RSET" => self.handle_rset().await,
            "TOP" => self.handle_top(&parts).await,
            "UIDL" => self.handle_uidl(&parts).await,
            "QUIT" => self.handle_quit().await,
            "STLS" => Ok("+OK Begin TLS negotiation\r\n".to_string()),
            _ => Ok("-ERR Command not recognized\r\n".to_string()),
        }
    }

    async fn handle_capa(&self) -> Result<String> {
        Ok("+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nSTLS\r\n.\r\n".to_string())
    }

    async fn handle_user(&mut self, parts: &[&str]) -> Result<String> {
        if !matches!(self.state, Pop3State::Authorization) {
            return Ok("-ERR Command not permitted when not in AUTHORIZATION state\r\n".to_string());
        }

        if parts.len() < 2 {
            return Ok("-ERR USER requires username\r\n".to_string());
        }

        let username = parts[1];
        self.username = Some(username.to_string());
        
        Ok(format!("+OK User {} accepted\r\n", username))
    }

    async fn handle_pass(&mut self, parts: &[&str]) -> Result<String> {
        if !matches!(self.state, Pop3State::Authorization) {
            return Ok("-ERR Command not permitted when not in AUTHORIZATION state\r\n".to_string());
        }

        if parts.len() < 2 {
            return Ok("-ERR PASS requires password\r\n".to_string());
        }

        let username = match &self.username {
            Some(u) => u,
            None => return Ok("-ERR USER command must be given first\r\n".to_string()),
        };

        let password = parts[1];

        match self.auth_service.authenticate(username, password).await? {
            Some(user) => {
                // Load messages from INBOX
                let messages = self.load_messages(&user).await?;
                self.state = Pop3State::Transaction(user, messages);
                Ok("+OK Mailbox locked and ready\r\n".to_string())
            }
            None => {
                self.username = None;
                Ok("-ERR Authentication failed\r\n".to_string())
            }
        }
    }

    async fn handle_stat(&self) -> Result<String> {
        match &self.state {
            Pop3State::Transaction(_, messages) => {
                let active_messages: Vec<_> = messages.iter()
                    .filter(|msg| !self.deleted_messages.contains(&msg.message_number))
                    .collect();
                
                let total_size: i32 = active_messages.iter()
                    .map(|msg| msg.size_bytes)
                    .sum();
                
                Ok(format!("+OK {} {}\r\n", active_messages.len(), total_size))
            }
            _ => Ok("-ERR Command not permitted when not in TRANSACTION state\r\n".to_string()),
        }
    }

    async fn handle_list(&self, parts: &[&str]) -> Result<String> {
        match &self.state {
            Pop3State::Transaction(_, messages) => {
                if parts.len() > 1 {
                    // LIST specific message
                    if let Ok(msg_num) = parts[1].parse::<i32>() {
                        if let Some(message) = messages.iter().find(|msg| msg.message_number == msg_num) {
                            if !self.deleted_messages.contains(&msg_num) {
                                return Ok(format!("+OK {} {}\r\n", msg_num, message.size_bytes));
                            }
                        }
                        return Ok("-ERR No such message\r\n".to_string());
                    }
                    return Ok("-ERR Invalid message number\r\n".to_string());
                } else {
                    // LIST all messages
                    let active_messages: Vec<_> = messages.iter()
                        .filter(|msg| !self.deleted_messages.contains(&msg.message_number))
                        .collect();
                    
                    let mut response = format!("+OK {} messages ({} octets)\r\n", 
                        active_messages.len(),
                        active_messages.iter().map(|msg| msg.size_bytes).sum::<i32>()
                    );
                    
                    for message in active_messages {
                        response.push_str(&format!("{} {}\r\n", message.message_number, message.size_bytes));
                    }
                    response.push_str(".\r\n");
                    
                    Ok(response)
                }
            }
            _ => Ok("-ERR Command not permitted when not in TRANSACTION state\r\n".to_string()),
        }
    }

    async fn handle_retr(&self, parts: &[&str]) -> Result<String> {
        match &self.state {
            Pop3State::Transaction(_, messages) => {
                if parts.len() < 2 {
                    return Ok("-ERR RETR requires message number\r\n".to_string());
                }

                if let Ok(msg_num) = parts[1].parse::<i32>() {
                    if let Some(message) = messages.iter().find(|msg| msg.message_number == msg_num) {
                        if !self.deleted_messages.contains(&msg_num) {
                            let raw_message = String::from_utf8_lossy(&message.raw_message);
                            return Ok(format!("+OK {} octets\r\n{}\r\n.\r\n", 
                                message.size_bytes, raw_message));
                        }
                    }
                    return Ok("-ERR No such message\r\n".to_string());
                }
                Ok("-ERR Invalid message number\r\n".to_string())
            }
            _ => Ok("-ERR Command not permitted when not in TRANSACTION state\r\n".to_string()),
        }
    }

    async fn handle_dele(&mut self, parts: &[&str]) -> Result<String> {
        match &self.state {
            Pop3State::Transaction(_, messages) => {
                if parts.len() < 2 {
                    return Ok("-ERR DELE requires message number\r\n".to_string());
                }

                if let Ok(msg_num) = parts[1].parse::<i32>() {
                    if messages.iter().any(|msg| msg.message_number == msg_num) {
                        if self.deleted_messages.contains(&msg_num) {
                            return Ok("-ERR Message already deleted\r\n".to_string());
                        }
                        
                        self.deleted_messages.insert(msg_num);
                        return Ok(format!("+OK Message {} deleted\r\n", msg_num));
                    }
                    return Ok("-ERR No such message\r\n".to_string());
                }
                Ok("-ERR Invalid message number\r\n".to_string())
            }
            _ => Ok("-ERR Command not permitted when not in TRANSACTION state\r\n".to_string()),
        }
    }

    async fn handle_rset(&mut self) -> Result<String> {
        match &self.state {
            Pop3State::Transaction(_, _) => {
                self.deleted_messages.clear();
                Ok("+OK Reset completed\r\n".to_string())
            }
            _ => Ok("-ERR Command not permitted when not in TRANSACTION state\r\n".to_string()),
        }
    }

    async fn handle_top(&self, parts: &[&str]) -> Result<String> {
        match &self.state {
            Pop3State::Transaction(_, messages) => {
                if parts.len() < 3 {
                    return Ok("-ERR TOP requires message number and line count\r\n".to_string());
                }

                if let (Ok(msg_num), Ok(line_count)) = (parts[1].parse::<i32>(), parts[2].parse::<i32>()) {
                    if let Some(message) = messages.iter().find(|msg| msg.message_number == msg_num) {
                        if !self.deleted_messages.contains(&msg_num) {
                            let raw_message = String::from_utf8_lossy(&message.raw_message);
                            let lines: Vec<&str> = raw_message.lines().collect();
                            
                            // Find the end of headers (empty line)
                            let mut header_end = lines.len();
                            for (i, line) in lines.iter().enumerate() {
                                if line.is_empty() {
                                    header_end = i;
                                    break;
                                }
                            }
                            
                            // Include headers + requested body lines
                            let end_line = std::cmp::min(header_end + 1 + line_count as usize, lines.len());
                            let top_content = lines[..end_line].join("\r\n");
                            
                            return Ok(format!("+OK Top of message follows\r\n{}\r\n.\r\n", top_content));
                        }
                    }
                    return Ok("-ERR No such message\r\n".to_string());
                }
                Ok("-ERR Invalid parameters\r\n".to_string())
            }
            _ => Ok("-ERR Command not permitted when not in TRANSACTION state\r\n".to_string()),
        }
    }

    async fn handle_uidl(&self, parts: &[&str]) -> Result<String> {
        match &self.state {
            Pop3State::Transaction(_, messages) => {
                if parts.len() > 1 {
                    // UIDL specific message
                    if let Ok(msg_num) = parts[1].parse::<i32>() {
                        if let Some(message) = messages.iter().find(|msg| msg.message_number == msg_num) {
                            if !self.deleted_messages.contains(&msg_num) {
                                let unique_id = message.message_id.as_deref()
                                    .unwrap_or(&format!("msg-{}", message.uid));
                                return Ok(format!("+OK {} {}\r\n", msg_num, unique_id));
                            }
                        }
                        return Ok("-ERR No such message\r\n".to_string());
                    }
                    return Ok("-ERR Invalid message number\r\n".to_string());
                } else {
                    // UIDL all messages
                    let active_messages: Vec<_> = messages.iter()
                        .filter(|msg| !self.deleted_messages.contains(&msg.message_number))
                        .collect();
                    
                    let mut response = "+OK Unique-ID listing follows\r\n".to_string();
                    
                    for message in active_messages {
                        let unique_id = message.message_id.as_deref()
                            .unwrap_or(&format!("msg-{}", message.uid));
                        response.push_str(&format!("{} {}\r\n", message.message_number, unique_id));
                    }
                    response.push_str(".\r\n");
                    
                    Ok(response)
                }
            }
            _ => Ok("-ERR Command not permitted when not in TRANSACTION state\r\n".to_string()),
        }
    }

    async fn handle_quit(&mut self) -> Result<String> {
        match &self.state {
            Pop3State::Transaction(user, messages) => {
                // Enter UPDATE state and delete marked messages
                self.state = Pop3State::Update(user.clone(), messages.clone());
                
                // Actually delete the messages from the database
                let mut deleted_count = 0;
                for msg_num in &self.deleted_messages {
                    if let Some(message) = messages.iter().find(|msg| msg.message_number == *msg_num) {
                        if let Err(e) = self.delete_message_from_db(&message).await {
                            error!("Failed to delete message {}: {}", msg_num, e);
                        } else {
                            deleted_count += 1;
                        }
                    }
                }
                
                Ok(format!("+OK POP3 server signing off ({} messages deleted)\r\n", deleted_count))
            }
            Pop3State::Authorization => {
                Ok("+OK POP3 server signing off\r\n".to_string())
            }
            Pop3State::Update(_, _) => {
                Ok("+OK POP3 server signing off\r\n".to_string())
            }
        }
    }

    // Helper methods

    async fn load_messages(&self, user: &User) -> Result<Vec<Pop3Message>> {
        // Get INBOX mailbox
        let mailbox_row = sqlx::query!(
            "SELECT id FROM mailboxes WHERE user_id = $1 AND name = 'INBOX'",
            user.id
        )
        .fetch_optional(&self.db_pool)
        .await?;

        let mailbox_id = match mailbox_row {
            Some(row) => row.id,
            None => return Ok(Vec::new()), // No INBOX found
        };

        // Load all messages from INBOX
        let messages = sqlx::query!(
            "SELECT id, uid, message_id, subject, sender, recipients, body_text, body_html, 
             raw_message, size_bytes, flags, internal_date 
             FROM messages WHERE mailbox_id = $1 ORDER BY uid",
            mailbox_id
        )
        .fetch_all(&self.db_pool)
        .await?;

        let mut pop3_messages = Vec::new();
        for (index, msg) in messages.iter().enumerate() {
            pop3_messages.push(Pop3Message {
                id: msg.id,
                uid: msg.uid,
                message_number: (index + 1) as i32, // POP3 uses 1-based indexing
                message_id: msg.message_id.clone(),
                subject: msg.subject.clone(),
                sender: msg.sender.clone(),
                recipients: msg.recipients.clone(),
                body_text: msg.body_text.clone(),
                body_html: msg.body_html.clone(),
                raw_message: msg.raw_message.clone(),
                size_bytes: msg.size_bytes,
                flags: msg.flags.clone(),
                internal_date: msg.internal_date,
                marked_for_deletion: false,
            });
        }

        Ok(pop3_messages)
    }

    async fn delete_message_from_db(&self, message: &Pop3Message) -> Result<()> {
        sqlx::query!(
            "DELETE FROM messages WHERE id = $1",
            message.id
        )
        .execute(&self.db_pool)
        .await?;

        // Update user's used bytes
        if let Pop3State::Transaction(user, _) | Pop3State::Update(user, _) = &self.state {
            sqlx::query!(
                "UPDATE users SET used_bytes = used_bytes - $1 WHERE id = $2",
                message.size_bytes as i64,
                user.id
            )
            .execute(&self.db_pool)
            .await?;
        }

        Ok(())
    }
}

async fn handle_pop3_connection(
    stream: TcpStream,
    context: Arc<ServerContext>,
    config: Arc<Pop3Config>,
    _use_tls: bool,
) -> Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    
    let mut session = Pop3Session::new(context.db_pool.clone(), config.clone());

    // Send greeting
    writer.write_all(b"+OK POP3 server ready\r\n").await?;
    writer.flush().await?;

    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // Connection closed
            Ok(_) => {
                let response = session.handle_command(&line).await?;
                writer.write_all(response.as_bytes()).await?;
                writer.flush().await?;

                // Check for QUIT command
                if line.trim().to_uppercase() == "QUIT" {
                    break;
                }
            }
            Err(e) => {
                error!("Error reading from POP3 connection: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_pop3_tls_connection(
    stream: TlsStream<TcpStream>,
    context: Arc<ServerContext>,
    config: Arc<Pop3Config>,
) -> Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    
    let mut session = Pop3Session::new(context.db_pool.clone(), config.clone());

    // Send greeting
    writer.write_all(b"+OK POP3 server ready (TLS)\r\n").await?;
    writer.flush().await?;

    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // Connection closed
            Ok(_) => {
                let response = session.handle_command(&line).await?;
                writer.write_all(response.as_bytes()).await?;
                writer.flush().await?;

                // Check for QUIT command
                if line.trim().to_uppercase() == "QUIT" {
                    break;
                }
            }
            Err(e) => {
                error!("Error reading from POP3 TLS connection: {}", e);
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
    fn test_pop3_message_numbering() {
        // Test that POP3 uses 1-based message numbering
        // Implementation would go here
    }

    #[test]
    fn test_pop3_deletion_marking() {
        // Test that messages are properly marked for deletion
        // Implementation would go here
    }
}
