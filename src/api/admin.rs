use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::HashMap;

use crate::{
    api::AppState,
    auth::Claims,
    error::MailServerError,
};

#[derive(Debug, Serialize)]
pub struct ServerStats {
    pub total_users: i64,
    pub active_users: i64,
    pub total_domains: i64,
    pub verified_domains: i64,
    pub total_messages: i64,
    pub messages_today: i64,
    pub storage_used_mb: i64,
    pub uptime_seconds: u64,
    pub system_info: SystemInfo,
}

#[derive(Debug, Serialize)]
pub struct SystemInfo {
    pub version: String,
    pub rust_version: String,
    pub build_date: String,
    pub features: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct LogQuery {
    pub level: Option<String>,
    pub component: Option<String>,
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigUpdate {
    pub smtp_max_connections: Option<u32>,
    pub imap_max_connections: Option<u32>,
    pub pop3_max_connections: Option<u32>,
    pub rate_limit_per_minute: Option<u32>,
    pub max_message_size_mb: Option<u32>,
    pub session_timeout_minutes: Option<u32>,
}

pub async fn get_server_stats(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<ServerStats>, (StatusCode, Json<Value>)> {
    // Check if user is admin
    let user_row = sqlx::query("SELECT is_admin FROM users WHERE id = $1")
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify user permissions"})),
            )
        })?;

    let is_admin: bool = user_row.get("is_admin");
    if !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin access required"})),
        ));
    }

    // Gather statistics from database
    let stats_query = sqlx::query(
        r#"
        SELECT 
            (SELECT COUNT(*) FROM users) as total_users,
            (SELECT COUNT(*) FROM users WHERE is_active = true) as active_users,
            (SELECT COUNT(*) FROM domains) as total_domains,
            (SELECT COUNT(*) FROM domains WHERE is_verified = true) as verified_domains,
            (SELECT COUNT(*) FROM messages) as total_messages,
            (SELECT COUNT(*) FROM messages WHERE received_at >= CURRENT_DATE) as messages_today,
            (SELECT COALESCE(SUM(size), 0) / (1024 * 1024) FROM messages) as storage_used_mb
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to gather statistics"})),
        )
    })?;

    let stats = ServerStats {
        total_users: stats_query.get("total_users"),
        active_users: stats_query.get("active_users"),
        total_domains: stats_query.get("total_domains"),
        verified_domains: stats_query.get("verified_domains"),
        total_messages: stats_query.get("total_messages"),
        messages_today: stats_query.get("messages_today"),
        storage_used_mb: stats_query.get("storage_used_mb"),
        uptime_seconds: get_uptime_seconds(),
        system_info: SystemInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            rust_version: get_rust_version(),
            build_date: get_build_date(),
            features: get_enabled_features(),
        },
    };

    Ok(Json(stats))
}

pub async fn get_logs(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<LogQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check if user is admin
    let user_row = sqlx::query("SELECT is_admin FROM users WHERE id = $1")
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify user permissions"})),
            )
        })?;

    let is_admin: bool = user_row.get("is_admin");
    if !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin access required"})),
        ));
    }

    let limit = params.limit.unwrap_or(100).min(1000);

    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT * FROM security_events WHERE 1=1"
    );

    // Add filters
    if let Some(level) = &params.level {
        query_builder.push(" AND event_type = ");
        query_builder.push_bind(level);
    }

    if let Some(component) = &params.component {
        query_builder.push(" AND details->>'component' = ");
        query_builder.push_bind(component);
    }

    if let Some(since) = params.since {
        query_builder.push(" AND created_at >= ");
        query_builder.push_bind(since);
    }

    query_builder.push(" ORDER BY created_at DESC LIMIT ");
    query_builder.push_bind(limit);

    let query = query_builder.build();
    let rows = query.fetch_all(&state.db).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to fetch logs"})),
        )
    })?;

    let logs: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<uuid::Uuid, _>("id"),
                "event_type": row.get::<String, _>("event_type"),
                "user_id": row.get::<Option<uuid::Uuid>, _>("user_id"),
                "ip_address": row.get::<Option<String>, _>("ip_address"),
                "details": row.get::<serde_json::Value, _>("details"),
                "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            })
        })
        .collect();

    Ok(Json(json!({
        "logs": logs,
        "total": logs.len(),
        "limit": limit
    })))
}

pub async fn get_config(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check if user is admin
    let user_row = sqlx::query("SELECT is_admin FROM users WHERE id = $1")
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify user permissions"})),
            )
        })?;

    let is_admin: bool = user_row.get("is_admin");
    if !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin access required"})),
        ));
    }

    // Return sanitized configuration (no sensitive data)
    let config = json!({
        "api": {
            "host": state.config.host,
            "port": state.config.port,
            "cors_origins": state.config.cors_origins
        },
        "rate_limiting": {
            "requests_per_minute": state.config.rate_limit_requests_per_minute,
            "burst_size": state.config.rate_limit_burst_size
        },
        "features": {
            "tls_enabled": state.tls_config.is_some(),
            "jwt_auth": true,
            "rate_limiting": true,
            "cors": true
        }
    });

    Ok(Json(config))
}

pub async fn update_config(
    State(state): State<AppState>,
    claims: Claims,
    Json(request): Json<ConfigUpdate>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check if user is admin
    let user_row = sqlx::query("SELECT is_admin FROM users WHERE id = $1")
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify user permissions"})),
            )
        })?;

    let is_admin: bool = user_row.get("is_admin");
    if !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin access required"})),
        ));
    }

    // Store configuration updates in database
    let config_id = uuid::Uuid::new_v4();
    let config_json = serde_json::to_value(&request).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to serialize configuration"})),
        )
    })?;

    sqlx::query(
        r#"
        INSERT INTO server_config (id, config_data, updated_by, created_at)
        VALUES ($1, $2, $3, NOW())
        "#,
    )
    .bind(config_id)
    .bind(&config_json)
    .bind(claims.user_id)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to save configuration"})),
        )
    })?;

    // Log configuration change
    sqlx::query(
        r#"
        INSERT INTO security_events (id, event_type, user_id, details, created_at)
        VALUES ($1, 'config_update', $2, $3, NOW())
        "#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(claims.user_id)
    .bind(json!({
        "action": "configuration_updated",
        "config_id": config_id,
        "changes": config_json
    }))
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to log configuration change"})),
        )
    })?;

    Ok(Json(json!({
        "config_id": config_id,
        "status": "updated",
        "message": "Configuration updated successfully. Restart required for some changes to take effect.",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

fn get_uptime_seconds() -> u64 {
    // This would typically track server start time
    // For now, return a placeholder
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() % 86400 // Simulate daily restart
}

fn get_rust_version() -> String {
    env!("RUSTC_VERSION").to_string()
}

fn get_build_date() -> String {
    env!("BUILD_DATE").unwrap_or("unknown").to_string()
}

fn get_enabled_features() -> Vec<String> {
    let mut features = vec![
        "smtp".to_string(),
        "imap".to_string(),
        "pop3".to_string(),
        "http-api".to_string(),
        "tls".to_string(),
        "postgresql".to_string(),
    ];

    #[cfg(feature = "powerdns")]
    features.push("powerdns".to_string());

    #[cfg(feature = "redis")]
    features.push("redis".to_string());

    features
}
