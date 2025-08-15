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
    auth::{password::PasswordManager, Claims},
    error::MailServerError,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
    pub domain_id: Uuid,
    pub is_admin: Option<bool>,
    pub quota_mb: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub full_name: Option<String>,
    pub is_admin: Option<bool>,
    pub quota_mb: Option<i64>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub full_name: Option<String>,
    pub domain_id: Uuid,
    pub domain_name: String,
    pub is_admin: bool,
    pub is_active: bool,
    pub quota_mb: Option<i64>,
    pub used_mb: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub domain_id: Option<Uuid>,
    pub is_admin: Option<bool>,
    pub is_active: Option<bool>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_users(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<ListUsersQuery>,
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

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let mut query_builder = sqlx::QueryBuilder::new(
        r#"
        SELECT u.*, d.name as domain_name,
               COALESCE(SUM(m.size), 0) / (1024 * 1024) as used_mb
        FROM users u
        JOIN domains d ON u.domain_id = d.id
        LEFT JOIN messages m ON u.id = m.user_id
        WHERE 1=1
        "#,
    );

    // Add filters
    if let Some(domain_id) = params.domain_id {
        query_builder.push(" AND u.domain_id = ");
        query_builder.push_bind(domain_id);
    }

    if let Some(is_admin) = params.is_admin {
        query_builder.push(" AND u.is_admin = ");
        query_builder.push_bind(is_admin);
    }

    if let Some(is_active) = params.is_active {
        query_builder.push(" AND u.is_active = ");
        query_builder.push_bind(is_active);
    }

    if let Some(search) = &params.search {
        query_builder.push(" AND (u.email ILIKE ");
        query_builder.push_bind(format!("%{}%", search));
        query_builder.push(" OR u.full_name ILIKE ");
        query_builder.push_bind(format!("%{}%", search));
        query_builder.push(")");
    }

    query_builder.push(" GROUP BY u.id, d.name ORDER BY u.created_at DESC LIMIT ");
    query_builder.push_bind(limit);
    query_builder.push(" OFFSET ");
    query_builder.push_bind(offset);

    let query = query_builder.build();
    let rows = query.fetch_all(&state.db).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database query failed"})),
        )
    })?;

    let users: Vec<UserResponse> = rows
        .iter()
        .map(|row| UserResponse {
            id: row.get("id"),
            email: row.get("email"),
            full_name: row.get("full_name"),
            domain_id: row.get("domain_id"),
            domain_name: row.get("domain_name"),
            is_admin: row.get("is_admin"),
            is_active: row.get("is_active"),
            quota_mb: row.get("quota_mb"),
            used_mb: row.get("used_mb"),
            created_at: row.get("created_at"),
            last_login: row.get("last_login"),
        })
        .collect();

    Ok(Json(json!({
        "users": users,
        "total": users.len(),
        "limit": limit,
        "offset": offset
    })))
}

pub async fn create_user(
    State(state): State<AppState>,
    claims: Claims,
    Json(request): Json<CreateUserRequest>,
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

    // Validate email format
    if !request.email.contains('@') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid email format"})),
        ));
    }

    // Check if user already exists
    let existing = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&request.email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database query failed"})),
            )
        })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "User already exists"})),
        ));
    }

    // Verify domain exists
    let domain_exists = sqlx::query("SELECT id FROM domains WHERE id = $1")
        .bind(request.domain_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database query failed"})),
            )
        })?
        .is_some();

    if !domain_exists {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Domain not found"})),
        ));
    }

    // Hash password
    let password_manager = PasswordManager::new();
    let password_hash = password_manager
        .hash_password(&request.password)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to hash password"})),
            )
        })?;

    let user_id = Uuid::new_v4();

    // Create user
    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, full_name, domain_id, is_admin, quota_mb, is_active, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, true, NOW())
        "#,
    )
    .bind(user_id)
    .bind(&request.email)
    .bind(&password_hash)
    .bind(&request.full_name)
    .bind(request.domain_id)
    .bind(request.is_admin.unwrap_or(false))
    .bind(request.quota_mb)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create user"})),
        )
    })?;

    Ok(Json(json!({
        "user_id": user_id,
        "email": request.email,
        "status": "created",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn get_user(
    State(state): State<AppState>,
    claims: Claims,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserResponse>, (StatusCode, Json<Value>)> {
    // Check if user is admin or requesting their own info
    let requesting_user_row = sqlx::query("SELECT is_admin FROM users WHERE id = $1")
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify user permissions"})),
            )
        })?;

    let is_admin: bool = requesting_user_row.get("is_admin");
    if !is_admin && claims.user_id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Access denied"})),
        ));
    }

    let row = sqlx::query(
        r#"
        SELECT u.*, d.name as domain_name,
               COALESCE(SUM(m.size), 0) / (1024 * 1024) as used_mb
        FROM users u
        JOIN domains d ON u.domain_id = d.id
        LEFT JOIN messages m ON u.id = m.user_id
        WHERE u.id = $1
        GROUP BY u.id, d.name
        "#,
    )
    .bind(user_id)
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
            Json(json!({"error": "User not found"})),
        )
    })?;

    let user = UserResponse {
        id: row.get("id"),
        email: row.get("email"),
        full_name: row.get("full_name"),
        domain_id: row.get("domain_id"),
        domain_name: row.get("domain_name"),
        is_admin: row.get("is_admin"),
        is_active: row.get("is_active"),
        quota_mb: row.get("quota_mb"),
        used_mb: row.get("used_mb"),
        created_at: row.get("created_at"),
        last_login: row.get("last_login"),
    };

    Ok(Json(user))
}

pub async fn update_user(
    State(state): State<AppState>,
    claims: Claims,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check if user is admin
    let requesting_user_row = sqlx::query("SELECT is_admin FROM users WHERE id = $1")
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify user permissions"})),
            )
        })?;

    let is_admin: bool = requesting_user_row.get("is_admin");
    if !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin access required"})),
        ));
    }

    // Build dynamic update query
    let mut query_builder = sqlx::QueryBuilder::new("UPDATE users SET ");
    let mut has_updates = false;

    if let Some(full_name) = &request.full_name {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("full_name = ");
        query_builder.push_bind(full_name);
        has_updates = true;
    }

    if let Some(is_admin) = request.is_admin {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("is_admin = ");
        query_builder.push_bind(is_admin);
        has_updates = true;
    }

    if let Some(quota_mb) = request.quota_mb {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("quota_mb = ");
        query_builder.push_bind(quota_mb);
        has_updates = true;
    }

    if let Some(is_active) = request.is_active {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("is_active = ");
        query_builder.push_bind(is_active);
        has_updates = true;
    }

    if !has_updates {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "No updates provided"})),
        ));
    }

    query_builder.push(" WHERE id = ");
    query_builder.push_bind(user_id);

    let query = query_builder.build();
    let result = query.execute(&state.db).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to update user"})),
        )
    })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User not found"})),
        ));
    }

    Ok(Json(json!({
        "user_id": user_id,
        "status": "updated",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn delete_user(
    State(state): State<AppState>,
    claims: Claims,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check if user is admin
    let requesting_user_row = sqlx::query("SELECT is_admin FROM users WHERE id = $1")
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify user permissions"})),
            )
        })?;

    let is_admin: bool = requesting_user_row.get("is_admin");
    if !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin access required"})),
        ));
    }

    // Prevent self-deletion
    if claims.user_id == user_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Cannot delete your own account"})),
        ));
    }

    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to delete user"})),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User not found"})),
        ));
    }

    Ok(Json(json!({
        "user_id": user_id,
        "status": "deleted",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn change_password(
    State(state): State<AppState>,
    claims: Claims,
    Path(user_id): Path<Uuid>,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Users can only change their own password unless they're admin
    let requesting_user_row = sqlx::query("SELECT is_admin FROM users WHERE id = $1")
        .bind(claims.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to verify user permissions"})),
            )
        })?;

    let is_admin: bool = requesting_user_row.get("is_admin");
    if !is_admin && claims.user_id != user_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Access denied"})),
        ));
    }

    // Get current password hash
    let user_row = sqlx::query("SELECT password_hash FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database query failed"})),
            )
        })?;

    let user_row = user_row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User not found"})),
        )
    })?;

    let current_hash: String = user_row.get("password_hash");

    // Verify current password (only if not admin changing someone else's password)
    if claims.user_id == user_id {
        let password_manager = PasswordManager::new();
        if !password_manager
            .verify_password(&request.current_password, &current_hash)
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Password verification failed"})),
                )
            })?
        {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Current password is incorrect"})),
            ));
        }
    }

    // Hash new password
    let password_manager = PasswordManager::new();
    let new_hash = password_manager
        .hash_password(&request.new_password)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to hash new password"})),
            )
        })?;

    // Update password
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to update password"})),
            )
        })?;

    Ok(Json(json!({
        "user_id": user_id,
        "status": "password_changed",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}
