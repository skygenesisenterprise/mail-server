use crate::config::SmtpConfig;
use crate::error::{MailServerError, Result};
use crate::protocols::{ProtocolServer, ServerContext};
use crate::auth::{AuthService, User};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{info, error, debug, warn};
use mail_parser::Message;
use uuid::Uuid;
use std::collections::HashMap;
use chrono::Utc;

pub struct SmtpServer {
    config: SmtpConfig,
    context: ServerContext,
}

impl SmtpServer {
    pub fn new(config: SmtpConfig, db_pool: PgPool, tls_acceptor: Arc<TlsAcceptor>) -> Self {
        Self {
            config,
            context: ServerContext::new(db_pool, tls_acceptor),
        }
    }
}

#[async_trait::async_trait]
impl ProtocolServer for SmtpServer {
    async fn start(&self) -> Result<()> {
        let bind_addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let tls_bind_addr = format!("{}:{}", self.config.bind_address, self.config.tls_port);
        
        info!("Starting SMTP server on {} (plain) and {} (TLS)", bind_addr, tls_bind_addr);
        
        // Start both plain and TLS listeners
        let plain_listener = TcpListener::bind(&bind_addr).await?;
        let tls_listener = TcpListener::bind(&tls_bind_addr).await?;
        
        let context = Arc::new(self.context.clone());
        let config = Arc::new(self.config.clone());
        
        // Handle plain SMTP connections
        let plain_context = context.clone();
        let plain_config = config.clone();
        tokio::spawn(async move {
            loop {
                match plain_listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New SMTP connection from {}", addr);
                        let ctx = plain_context.clone();
                        let cfg = plain_config.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_smtp_connection(stream, ctx, cfg, false).await {
                                error!("SMTP connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => error!("Failed to accept SMTP connection: {}", e),
                }
            }
        });
        
        // Handle TLS SMTP connections
        let tls_context = context.clone();
        let tls_config = config.clone();
        tokio::spawn(async move {
            loop {
                match tls_listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New SMTP TLS connection from {}", addr);
                        let ctx = tls_context.clone();
                        let cfg = tls_config.clone();
                        let tls_acceptor = ctx.tls_acceptor.clone();
                        tokio::spawn(async move {
                            match tls_acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    if let Err(e) = handle_smtp_tls_connection(tls_stream, ctx, cfg).await {
                                        error!("SMTP TLS connection error: {}", e);
                                    }
                                }
                                Err(e) => error!("TLS handshake failed: {}", e),
                            }
                        });
                    }
                    Err(e) => error!("Failed to accept SMTP TLS connection: {}", e),
                }
            }
        });
        
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        info!("Stopping SMTP server");
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum SmtpState {
    Connected,
    Greeted,
    Authenticated(User),
    MailFrom(String, Option<User>),
    RcptTo(String, Vec<String>, Option<User>),
    Data(String, Vec<String>, Option<User>),
}

struct SmtpSession {
    state: SmtpState,
    hostname: String,
    auth_service: AuthService,
    db_pool: PgPool,
    config: Arc<SmtpConfig>,
}

impl SmtpSession {
    fn new(hostname: String, db_pool: PgPool, config: Arc<SmtpConfig>) -> Self {
        Self {
            state: SmtpState::Connected,
            hostname,
            auth_service: AuthService::new(db_pool.clone()),
            db_pool,
            config,
        }
    }

    async fn handle_command(&mut self, command: &str) -> Result<String> {
        let parts: Vec<&str> = command.trim().split_whitespace().collect();
        if parts.is_empty() {
            return Ok("500 Syntax error, command unrecognized\r\n".to_string());
        }

        let cmd = parts[0].to_uppercase();
        debug!("Processing SMTP command: {}", cmd);

        match cmd.as_str() {
            "HELO" | "EHLO" => self.handle_helo(&parts).await,
            "AUTH" => self.handle_auth(&parts).await,
            "MAIL" => self.handle_mail(&parts).await,
            "RCPT" => self.handle_rcpt(&parts).await,
            "DATA" => self.handle_data().await,
            "RSET" => self.handle_rset().await,
            "NOOP" => Ok("250 OK\r\n".to_string()),
            "QUIT" => Ok("221 Bye\r\n".to_string()),
            "STARTTLS" => Ok("220 Ready to start TLS\r\n".to_string()),
            _ => Ok("502 Command not implemented\r\n".to_string()),
        }
    }

    async fn handle_helo(&mut self, parts: &[&str]) -> Result<String> {
        if parts.len() < 2 {
            return Ok("501 Syntax: HELO hostname\r\n".to_string());
        }

        self.state = SmtpState::Greeted;
        
        if parts[0] == "EHLO" {
            Ok(format!(
                "250-{} Hello {}\r\n250-AUTH PLAIN LOGIN\r\n250-STARTTLS\r\n250 SIZE {}\r\n",
                self.hostname, parts[1], self.config.max_message_size
            ))
        } else {
            Ok(format!("250 {} Hello {}\r\n", self.hostname, parts[1]))
        }
    }

    async fn handle_auth(&mut self, parts: &[&str]) -> Result<String> {
        if parts.len() < 2 {
            return Ok("501 Syntax: AUTH mechanism\r\n".to_string());
        }

        match parts[1].to_uppercase().as_str() {
            "PLAIN" => {
                if parts.len() >= 3 {
                    // AUTH PLAIN with credentials in same line
                    self.handle_auth_plain(parts[2]).await
                } else {
                    // AUTH PLAIN without credentials - request them
                    Ok("334 \r\n".to_string())
                }
            }
            "LOGIN" => {
                Ok("334 VXNlcm5hbWU6\r\n".to_string()) // "Username:" in base64
            }
            _ => Ok("504 Authentication mechanism not supported\r\n".to_string()),
        }
    }

    async fn handle_auth_plain(&mut self, credentials: &str) -> Result<String> {
        let decoded = match base64::decode(credentials) {
            Ok(data) => String::from_utf8_lossy(&data).to_string(),
            Err(_) => return Ok("535 Authentication failed\r\n".to_string()),
        };

        let parts: Vec<&str> = decoded.split('\0').collect();
        if parts.len() != 3 {
            return Ok("535 Authentication failed\r\n".to_string());
        }

        let username = parts[1];
        let password = parts[2];

        match self.auth_service.authenticate(username, password).await? {
            Some(user) => {
                self.state = SmtpState::Authenticated(user);
                Ok("235 Authentication successful\r\n".to_string())
            }
            None => Ok("535 Authentication failed\r\n".to_string()),
        }
    }

    async fn handle_mail(&mut self, parts: &[&str]) -> Result<String> {
        if !matches!(self.state, SmtpState::Greeted | SmtpState::Authenticated(_)) {
            return Ok("503 Bad sequence of commands\r\n".to_string());
        }

        if parts.len() < 2 || !parts[1].to_uppercase().starts_with("FROM:") {
            return Ok("501 Syntax: MAIL FROM:<address>\r\n".to_string());
        }

        let from_addr = parts[1][5..].trim_matches(['<', '>', ' ']);
        
        // Validate sender address format
        if !is_valid_email(from_addr) {
            return Ok("553 Invalid sender address\r\n".to_string());
        }

        let user = match &self.state {
            SmtpState::Authenticated(user) => Some(user.clone()),
            _ => None,
        };

        self.state = SmtpState::MailFrom(from_addr.to_string(), user);
        Ok("250 OK\r\n".to_string())
    }

    async fn handle_rcpt(&mut self, parts: &[&str]) -> Result<String> {
        let (from_addr, user) = match &self.state {
            SmtpState::MailFrom(addr, user) => (addr.clone(), user.clone()),
            SmtpState::RcptTo(addr, _, user) => (addr.clone(), user.clone()),
            _ => return Ok("503 Bad sequence of commands\r\n".to_string()),
        };

        if parts.len() < 2 || !parts[1].to_uppercase().starts_with("TO:") {
            return Ok("501 Syntax: RCPT TO:<address>\r\n".to_string());
        }

        let to_addr = parts[1][3..].trim_matches(['<', '>', ' ']);
        
        // Validate recipient address format
        if !is_valid_email(to_addr) {
            return Ok("553 Invalid recipient address\r\n".to_string());
        }

        // Check if recipient exists in our system
        if !self.recipient_exists(to_addr).await? {
            return Ok("550 No such user here\r\n".to_string());
        }

        let mut recipients = match &self.state {
            SmtpState::RcptTo(_, rcpts, _) => rcpts.clone(),
            _ => Vec::new(),
        };
        recipients.push(to_addr.to_string());

        self.state = SmtpState::RcptTo(from_addr, recipients, user);
        Ok("250 OK\r\n".to_string())
    }

    async fn handle_data(&mut self) -> Result<String> {
        match &self.state {
            SmtpState::RcptTo(from_addr, recipients, user) => {
                self.state = SmtpState::Data(from_addr.clone(), recipients.clone(), user.clone());
                Ok("354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string())
            }
            _ => Ok("503 Bad sequence of commands\r\n".to_string()),
        }
    }

    async fn handle_rset(&mut self) -> Result<String> {
        self.state = SmtpState::Greeted;
        Ok("250 OK\r\n".to_string())
    }

    async fn store_message(&mut self, message_data: &str) -> Result<String> {
        let (from_addr, recipients, _user) = match &self.state {
            SmtpState::Data(from, rcpts, user) => (from.clone(), rcpts.clone(), user.clone()),
            _ => return Ok("503 Bad sequence of commands\r\n".to_string()),
        };

        // Parse the message
        let message = match Message::parse(message_data.as_bytes()) {
            Some(msg) => msg,
            None => return Ok("554 Message parsing failed\r\n".to_string()),
        };

        // Store message for each recipient
        for recipient in &recipients {
            if let Err(e) = self.store_message_for_recipient(&message, &from_addr, recipient, message_data).await {
                error!("Failed to store message for {}: {}", recipient, e);
                return Ok("451 Temporary failure in message storage\r\n".to_string());
            }
        }

        self.state = SmtpState::Greeted;
        Ok("250 OK: Message accepted for delivery\r\n".to_string())
    }

    async fn store_message_for_recipient(
        &self,
        message: &Message,
        from_addr: &str,
        recipient: &str,
        raw_message: &str,
    ) -> Result<()> {
        // Get recipient's INBOX mailbox
        let mailbox_row = sqlx::query!(
            "SELECT m.id, m.uidnext FROM mailboxes m 
             JOIN users u ON m.user_id = u.id 
             WHERE u.email = $1 AND m.name = 'INBOX'",
            recipient
        )
        .fetch_one(&self.db_pool)
        .await?;

        let mailbox_id = mailbox_row.id;
        let uid = mailbox_row.uidnext;

        // Extract message details
        let subject = message.subject().unwrap_or("").to_string();
        let message_id = message.message_id().map(|id| id.to_string());
        let body_text = message.body_text(0).map(|body| body.to_string());
        let body_html = message.body_html(0).map(|body| body.to_string());
        let size_bytes = raw_message.len() as i32;

        // Store the message
        sqlx::query!(
            "INSERT INTO messages (mailbox_id, uid, message_id, subject, sender, recipients, 
             body_text, body_html, raw_message, size_bytes, internal_date)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            mailbox_id,
            uid,
            message_id,
            subject,
            from_addr,
            &vec![recipient.to_string()],
            body_text,
            body_html,
            raw_message.as_bytes(),
            size_bytes,
            Utc::now()
        )
        .execute(&self.db_pool)
        .await?;

        // Update mailbox uidnext
        sqlx::query!(
            "UPDATE mailboxes SET uidnext = uidnext + 1 WHERE id = $1",
            mailbox_id
        )
        .execute(&self.db_pool)
        .await?;

        // Update user's used bytes
        sqlx::query!(
            "UPDATE users SET used_bytes = used_bytes + $1 
             WHERE email = $2",
            size_bytes as i64,
            recipient
        )
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    async fn recipient_exists(&self, email: &str) -> Result<bool> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM users WHERE email = $1 AND active = true",
            email
        )
        .fetch_one(&self.db_pool)
        .await?;

        Ok(count.unwrap_or(0) > 0)
    }
}

async fn handle_smtp_connection(
    stream: TcpStream,
    context: Arc<ServerContext>,
    config: Arc<SmtpConfig>,
    _use_tls: bool,
) -> Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    
    let mut session = SmtpSession::new(
        "mail.example.com".to_string(), // This should come from config
        context.db_pool.clone(),
        config.clone(),
    );

    // Send greeting
    writer.write_all(b"220 mail.example.com ESMTP Rust Mail Server\r\n").await?;
    writer.flush().await?;

    let mut line = String::new();
    let mut message_data = String::new();
    let mut in_data_mode = false;

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // Connection closed
            Ok(_) => {
                if in_data_mode {
                    if line.trim() == "." {
                        // End of message data
                        let response = session.store_message(&message_data).await?;
                        writer.write_all(response.as_bytes()).await?;
                        writer.flush().await?;
                        in_data_mode = false;
                        message_data.clear();
                    } else {
                        // Accumulate message data
                        message_data.push_str(&line);
                    }
                } else {
                    let response = session.handle_command(&line).await?;
                    writer.write_all(response.as_bytes()).await?;
                    writer.flush().await?;

                    // Check if we're entering data mode
                    if response.starts_with("354") {
                        in_data_mode = true;
                    }

                    // Check for QUIT command
                    if line.trim().to_uppercase() == "QUIT" {
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Error reading from SMTP connection: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_smtp_tls_connection(
    stream: TlsStream<TcpStream>,
    context: Arc<ServerContext>,
    config: Arc<SmtpConfig>,
) -> Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);
    
    let mut session = SmtpSession::new(
        "mail.example.com".to_string(), // This should come from config
        context.db_pool.clone(),
        config.clone(),
    );

    // Send greeting
    writer.write_all(b"220 mail.example.com ESMTP Rust Mail Server (TLS)\r\n").await?;
    writer.flush().await?;

    let mut line = String::new();
    let mut message_data = String::new();
    let mut in_data_mode = false;

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // Connection closed
            Ok(_) => {
                if in_data_mode {
                    if line.trim() == "." {
                        // End of message data
                        let response = session.store_message(&message_data).await?;
                        writer.write_all(response.as_bytes()).await?;
                        writer.flush().await?;
                        in_data_mode = false;
                        message_data.clear();
                    } else {
                        // Accumulate message data
                        message_data.push_str(&line);
                    }
                } else {
                    let response = session.handle_command(&line).await?;
                    writer.write_all(response.as_bytes()).await?;
                    writer.flush().await?;

                    // Check if we're entering data mode
                    if response.starts_with("354") {
                        in_data_mode = true;
                    }

                    // Check for QUIT command
                    if line.trim().to_uppercase() == "QUIT" {
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Error reading from SMTP TLS connection: {}", e);
                break;
            }
        }
    }

    Ok(())
}

fn is_valid_email(email: &str) -> bool {
    // Basic email validation - in production, use a proper email validation library
    email.contains('@') && email.len() > 3 && !email.starts_with('@') && !email.ends_with('@')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("test.email+tag@domain.co.uk"));
        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@domain.com"));
        assert!(!is_valid_email("user@"));
        assert!(!is_valid_email(""));
    }
}
