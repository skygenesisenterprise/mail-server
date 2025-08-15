use crate::error::Result;
use crate::storage::MessageStorage;
use chrono::{DateTime, Utc};
use mail_parser::{Message, MessageParser};
use std::collections::HashMap;
use uuid::Uuid;

pub struct EmailParser {
    parser: MessageParser,
}

impl EmailParser {
    pub fn new() -> Self {
        Self {
            parser: MessageParser::default(),
        }
    }

    pub fn parse_message(
        &self,
        raw_content: &[u8],
        mailbox_id: Uuid,
        uid: i32,
    ) -> Result<MessageStorage> {
        let message = self.parser.parse(raw_content).ok_or_else(|| {
            crate::error::MailError::InvalidMessage("Failed to parse email message".to_string())
        })?;

        let subject = message.subject().map(|s| s.to_string());
        let sender = message
            .from()
            .and_then(|from| from.first())
            .map(|addr| addr.to_string());

        let recipients: Vec<String> = message
            .to()
            .iter()
            .flat_map(|to| to.iter())
            .map(|addr| addr.to_string())
            .collect();

        let body_text = message.body_text(0).map(|body| body.to_string());
        let body_html = message.body_html(0).map(|body| body.to_string());

        let attachments = message.attachments().collect::<Vec<_>>();
        let has_attachments = !attachments.is_empty();
        let attachment_count = attachments.len() as i32;

        let internal_date = message
            .date()
            .and_then(|date| DateTime::parse_from_rfc2822(&date.to_rfc2822()).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let size_bytes = raw_content.len() as i32;

        // Calculate spam score (placeholder - would integrate with SpamAssassin or similar)
        let spam_score = self.calculate_spam_score(&message);

        // Extract thread ID from headers
        let thread_id = message
            .header("Message-ID")
            .or_else(|| message.header("In-Reply-To"))
            .or_else(|| message.header("References"))
            .map(|h| h.to_string());

        Ok(MessageStorage {
            id: Uuid::new_v4(), // Will be overwritten by database
            mailbox_id,
            uid,
            message_id: message.header("Message-ID").map(|s| s.to_string()),
            thread_id,
            subject,
            sender,
            recipients,
            body_text,
            body_html,
            size_bytes,
            flags: vec!["\\Recent".to_string()], // Default flags
            labels: Vec::new(),
            has_attachments,
            attachment_count,
            spam_score,
            content_hash: None, // Will be calculated by StorageManager
            internal_date,
            archived_at: None,
        })
    }

    fn calculate_spam_score(&self, message: &Message) -> f32 {
        let mut score = 0.0;

        // Simple spam scoring - in production, integrate with SpamAssassin
        if let Some(subject) = message.subject() {
            let subject_lower = subject.to_lowercase();
            if subject_lower.contains("urgent") || subject_lower.contains("act now") {
                score += 2.0;
            }
            if subject_lower.chars().filter(|c| c.is_uppercase()).count() > subject.len() / 2 {
                score += 1.5;
            }
        }

        // Check for suspicious headers
        if message.header("X-Spam-Flag").is_some() {
            score += 5.0;
        }

        score.min(10.0) // Cap at 10.0
    }

    pub fn extract_attachments(&self, message: &Message) -> Vec<AttachmentInfo> {
        message
            .attachments()
            .map(|attachment| AttachmentInfo {
                filename: attachment
                    .attachment_name()
                    .unwrap_or("unknown")
                    .to_string(),
                content_type: attachment.content_type().map(|ct| ct.to_string()),
                content_disposition: attachment.content_disposition().map(|cd| cd.to_string()),
                content_id: attachment.content_id().map(|cid| cid.to_string()),
                size_bytes: attachment.contents().len() as i32,
                content: attachment.contents().to_vec(),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct AttachmentInfo {
    pub filename: String,
    pub content_type: Option<String>,
    pub content_disposition: Option<String>,
    pub content_id: Option<String>,
    pub size_bytes: i32,
    pub content: Vec<u8>,
}
