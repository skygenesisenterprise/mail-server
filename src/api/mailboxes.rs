use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    Extension,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::{
    api::AppState,
    auth::User,
    storage::mailbox::MailboxManager,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateMailboxRequest {
    pub name: String,
    pub parent_id: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMailboxRequest {
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MailboxResponse {
    pub id: i32,
    pub name: String,
    pub parent_id: Option<i32>,
    pub uidvalidity: u32,
    pub uidnext: u32,
    pub message_count: i64,
    pub unseen_count: i64,
    pub total_size: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list_mailboxes(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
) -> Result<Json<Vec<MailboxResponse>>, (StatusCode, Json<Value>)> {
    let mailbox_manager = MailboxManager::new(state.db.clone());
    
    let mailboxes = mailbox_manager.list_user_mailboxes(user.id).await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to fetch mailboxes"})),
            )
        })?;

    let response: Vec<MailboxResponse> = mailboxes
        .into_iter()
        .map(|mb| MailboxResponse {
            id: mb.id,
            name: mb.name,
            parent_id: mb.parent_id,
            uidvalidity: mb.uidvalidity,
            uidnext: mb.uidnext,
            message_count: mb.message_count.unwrap_or(0),
            unseen_count: mb.unseen_count.unwrap_or(0),
            total_size: mb.total_size.unwrap_or(0),
            created_at: mb.created_at,
        })
        .collect();

    Ok(Json(response))
}

pub async fn create_mailbox(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Json(payload): Json<CreateMailboxRequest>,
) -> Result<Json<MailboxResponse>, (StatusCode, Json<Value>)> {
    let mailbox_manager = MailboxManager::new(state.db.clone());
    
    let mailbox = mailbox_manager.create_mailbox(user.id, &payload.name, payload.parent_id).await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create mailbox"})),
            )
        })?;

    let response = MailboxResponse {
        id: mailbox.id,
        name: mailbox.name,
        parent_id: mailbox.parent_id,
        uidvalidity: mailbox.uidvalidity,
        uidnext: mailbox.uidnext,
        message_count: 0,
        unseen_count: 0,
        total_size: 0,
        created_at: mailbox.created_at,
    };

    Ok(Json(response))
}

pub async fn get_mailbox(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<i32>,
) -> Result<Json<MailboxResponse>, (StatusCode, Json<Value>)> {
    let mailbox_manager = MailboxManager::new(state.db.clone());
    
    let mailbox = mailbox_manager.get_mailbox_with_stats(id, user.id).await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Mailbox not found"})),
            )
        })?;

    let response = MailboxResponse {
        id: mailbox.id,
        name: mailbox.name,
        parent_id: mailbox.parent_id,
        uidvalidity: mailbox.uidvalidity,
        uidnext: mailbox.uidnext,
        message_count: mailbox.message_count.unwrap_or(0),
        unseen_count: mailbox.unseen_count.unwrap_or(0),
        total_size: mailbox.total_size.unwrap_or(0),
        created_at: mailbox.created_at,
    };

    Ok(Json(response))
}

pub async fn update_mailbox(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<i32>,
    Json(payload): Json<UpdateMailboxRequest>,
) -> Result<Json<MailboxResponse>, (StatusCode, Json<Value>)> {
    let mailbox_manager = MailboxManager::new(state.db.clone());
    
    if let Some(name) = payload.name {
        mailbox_manager.rename_mailbox(id, user.id, &name).await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to update mailbox"})),
                )
            })?;
    }

    let mailbox = mailbox_manager.get_mailbox_with_stats(id, user.id).await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Mailbox not found"})),
            )
        })?;

    let response = MailboxResponse {
        id: mailbox.id,
        name: mailbox.name,
        parent_id: mailbox.parent_id,
        uidvalidity: mailbox.uidvalidity,
        uidnext: mailbox.uidnext,
        message_count: mailbox.message_count.unwrap_or(0),
        unseen_count: mailbox.unseen_count.unwrap_or(0),
        total_size: mailbox.total_size.unwrap_or(0),
        created_at: mailbox.created_at,
    };

    Ok(Json(response))
}

pub async fn delete_mailbox(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<i32>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mailbox_manager = MailboxManager::new(state.db.clone());
    
    mailbox_manager.delete_mailbox(id, user.id).await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to delete mailbox"})),
            )
        })?;

    Ok(Json(json!({"message": "Mailbox deleted successfully"})))
}

pub async fn list_messages(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(mailbox_id): Path<i32>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let limit: i64 = params.get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let offset: i64 = params.get("offset")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // This would integrate with the message storage system
    // For now, return a placeholder response
    Ok(Json(json!({
        "messages": [],
        "total": 0,
        "limit": limit,
        "offset": offset
    })))
}
