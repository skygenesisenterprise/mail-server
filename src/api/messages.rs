use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    api::AppState,
    auth::Claims,
    error::MailServerError,
    storage::email_parser::EmailParser,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub to: Vec<String>,
    pub cc: Option<Vec<String>>,
    pub bcc: Option<Vec<String>>,
    pub subject: String,
    pub body: String,
    pub html_body: Option<String>,
    pub attachments: Option<Vec<AttachmentData>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttachmentData {
    pub filename: String,
    pub content_type: String,
    pub data: String, // Base64 encoded
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageResponse {
    pub id: Uuid,
    pub from_address: String,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Option<Vec<String>>,
    pub bcc_addresses: Option<Vec<String>>,
    pub subject: String,
    pub body: String,
    pub html_body: Option<String>,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub flags: Vec<String>,
    pub size: i64,
    pub has_attachments: bool,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub query: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub before: Option<chrono::DateTime<chrono::Utc>>,
    pub has_attachments: Option<bool>,
    pub flags: Option<Vec<String>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMessageRequest {
    pub flags: Option<Vec<String>>,
    pub mailbox_id: Option<Uuid>,
}

pub async fn send_message(
    State(state): State<AppState>,
    claims: Claims,
    Json(request): Json<SendMessageRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Validate recipients
    if request.to.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "At least one recipient is required"})),
        ));
    }

    // Create message ID
    let message_id = Uuid::new_v4();
    
    // Get user's email address
    let user_row = sqlx::query("SELECT email FROM users WHERE id = $1")
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to get user information"})),
            )
        })?;
    
    let from_address: String = user_row.get("email");

    // Store message in database
    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database transaction failed"})),
        )
    })?;

    // Insert message
    sqlx::query(
        r#"
        INSERT INTO messages (id, from_address, to_addresses, cc_addresses, bcc_addresses, 
                            subject, body, html_body, size, user_id, received_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
        "#,
    )
    .bind(message_id)
    .bind(&from_address)
    .bind(&request.to)
    .bind(&request.cc)
    .bind(&request.bcc)
    .bind(&request.subject)
    .bind(&request.body)
    .bind(&request.html_body)
    .bind(request.body.len() as i64)
    .bind(claims.user_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to store message"})),
        )
    })?;

    // Handle attachments if present
    if let Some(attachments) = &request.attachments {
        for attachment in attachments {
            let attachment_id = Uuid::new_v4();
            let decoded_data = base64::decode(&attachment.data).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Invalid attachment data"})),
                )
            })?;

            sqlx::query(
                r#"
                INSERT INTO attachments (id, message_id, filename, content_type, size, data)
                VALUES ($1, $2, $3, $4, $5, $6)
                "#,
            )
            .bind(attachment_id)
            .bind(message_id)
            .bind(&attachment.filename)
            .bind(&attachment.content_type)
            .bind(decoded_data.len() as i64)
            .bind(decoded_data)
            .execute(&mut *tx)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to store attachment"})),
                )
            })?;
        }
    }

    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to commit transaction"})),
        )
    })?;

    Ok(Json(json!({
        "message_id": message_id,
        "status": "sent",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn get_message(
    State(state): State<AppState>,
    claims: Claims,
    Path(message_id): Path<Uuid>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Value>)> {
    let row = sqlx::query(
        r#"
        SELECT m.*, COALESCE(array_agg(mf.flag) FILTER (WHERE mf.flag IS NOT NULL), '{}') as flags,
               EXISTS(SELECT 1 FROM attachments WHERE message_id = m.id) as has_attachments
        FROM messages m
        LEFT JOIN message_flags mf ON m.id = mf.message_id
        WHERE m.id = $1 AND m.user_id = $2
        GROUP BY m.id
        "#,
    )
    .bind(message_id)
    .bind(claims.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database query failed"})),
        )
    })?;

    let row = row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Message not found"})),
        )
    })?;

    let message = MessageResponse {
        id: row.get("id"),
        from_address: row.get("from_address"),
        to_addresses: row.get("to_addresses"),
        cc_addresses: row.get("cc_addresses"),
        bcc_addresses: row.get("bcc_addresses"),
        subject: row.get("subject"),
        body: row.get("body"),
        html_body: row.get("html_body"),
        received_at: row.get("received_at"),
        flags: row.get("flags"),
        size: row.get("size"),
        has_attachments: row.get("has_attachments"),
    };

    Ok(Json(message))
}

pub async fn update_message(
    State(state): State<AppState>,
    claims: Claims,
    Path(message_id): Path<Uuid>,
    Json(request): Json<UpdateMessageRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database transaction failed"})),
        )
    })?;

    // Verify message ownership
    let exists = sqlx::query("SELECT 1 FROM messages WHERE id = $1 AND user_id = $2")
        .bind(message_id)
        .bind(claims.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database query failed"})),
            )
        })?
        .is_some();

    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Message not found"})),
        ));
    }

    // Update flags if provided
    if let Some(flags) = &request.flags {
        // Remove existing flags
        sqlx::query("DELETE FROM message_flags WHERE message_id = $1")
            .bind(message_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to update flags"})),
                )
            })?;

        // Add new flags
        for flag in flags {
            sqlx::query("INSERT INTO message_flags (message_id, flag) VALUES ($1, $2)")
                .bind(message_id)
                .bind(flag)
                .execute(&mut *tx)
                .await
                .map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Failed to update flags"})),
                    )
                })?;
        }
    }

    // Move to different mailbox if provided
    if let Some(mailbox_id) = request.mailbox_id {
        sqlx::query("UPDATE messages SET mailbox_id = $1 WHERE id = $2")
            .bind(mailbox_id)
            .bind(message_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to move message"})),
                )
            })?;
    }

    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to commit transaction"})),
        )
    })?;

    Ok(Json(json!({
        "message_id": message_id,
        "status": "updated",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn delete_message(
    State(state): State<AppState>,
    claims: Claims,
    Path(message_id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = sqlx::query("DELETE FROM messages WHERE id = $1 AND user_id = $2")
        .bind(message_id)
        .bind(claims.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database query failed"})),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Message not found"})),
        ));
    }

    Ok(Json(json!({
        "message_id": message_id,
        "status": "deleted",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn get_attachments(
    State(state): State<AppState>,
    claims: Claims,
    Path(message_id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Verify message ownership
    let exists = sqlx::query("SELECT 1 FROM messages WHERE id = $1 AND user_id = $2")
        .bind(message_id)
        .bind(claims.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database query failed"})),
            )
        })?
        .is_some();

    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Message not found"})),
        ));
    }

    let rows = sqlx::query(
        "SELECT id, filename, content_type, size FROM attachments WHERE message_id = $1",
    )
    .bind(message_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database query failed"})),
        )
    })?;

    let attachments: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<Uuid, _>("id"),
                "filename": row.get::<String, _>("filename"),
                "content_type": row.get::<String, _>("content_type"),
                "size": row.get::<i64, _>("size")
            })
        })
        .collect();

    Ok(Json(json!({
        "message_id": message_id,
        "attachments": attachments
    })))
}

pub async fn search_messages(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<HashMap<String, String>>,
    Json(search): Json<SearchQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let limit = search.limit.unwrap_or(50).min(100);
    let offset = search.offset.unwrap_or(0);

    let mut query_builder = sqlx::QueryBuilder::new(
        r#"
        SELECT m.*, COALESCE(array_agg(mf.flag) FILTER (WHERE mf.flag IS NOT NULL), '{}') as flags,
               EXISTS(SELECT 1 FROM attachments WHERE message_id = m.id) as has_attachments
        FROM messages m
        LEFT JOIN message_flags mf ON m.id = mf.message_id
        WHERE m.user_id = 
        "#,
    );
    
    query_builder.push_bind(claims.user_id);

    // Add search filters
    if let Some(query_text) = &search.query {
        query_builder.push(" AND (m.subject ILIKE ");
        query_builder.push_bind(format!("%{}%", query_text));
        query_builder.push(" OR m.body ILIKE ");
        query_builder.push_bind(format!("%{}%", query_text));
        query_builder.push(")");
    }

    if let Some(from) = &search.from {
        query_builder.push(" AND m.from_address ILIKE ");
        query_builder.push_bind(format!("%{}%", from));
    }

    if let Some(subject) = &search.subject {
        query_builder.push(" AND m.subject ILIKE ");
        query_builder.push_bind(format!("%{}%", subject));
    }

    if let Some(since) = search.since {
        query_builder.push(" AND m.received_at >= ");
        query_builder.push_bind(since);
    }

    if let Some(before) = search.before {
        query_builder.push(" AND m.received_at <= ");
        query_builder.push_bind(before);
    }

    if let Some(has_attachments) = search.has_attachments {
        if has_attachments {
            query_builder.push(" AND EXISTS(SELECT 1 FROM attachments WHERE message_id = m.id)");
        } else {
            query_builder.push(" AND NOT EXISTS(SELECT 1 FROM attachments WHERE message_id = m.id)");
        }
    }

    query_builder.push(" GROUP BY m.id ORDER BY m.received_at DESC LIMIT ");
    query_builder.push_bind(limit);
    query_builder.push(" OFFSET ");
    query_builder.push_bind(offset);

    let query = query_builder.build();
    let rows = query.fetch_all(&state.db).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Search query failed"})),
        )
    })?;

    let messages: Vec<MessageResponse> = rows
        .iter()
        .map(|row| MessageResponse {
            id: row.get("id"),
            from_address: row.get("from_address"),
            to_addresses: row.get("to_addresses"),
            cc_addresses: row.get("cc_addresses"),
            bcc_addresses: row.get("bcc_addresses"),
            subject: row.get("subject"),
            body: row.get("body"),
            html_body: row.get("html_body"),
            received_at: row.get("received_at"),
            flags: row.get("flags"),
            size: row.get("size"),
            has_attachments: row.get("has_attachments"),
        })
        .collect();

    Ok(Json(json!({
        "messages": messages,
        "total": messages.len(),
        "limit": limit,
        "offset": offset
    })))
}
