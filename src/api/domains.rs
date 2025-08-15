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

use crate::{api::AppState, auth::Claims, domain::DomainManager, error::MailServerError};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDomainRequest {
    pub name: String,
    pub description: Option<String>,
    pub mx_priority: Option<i32>,
    pub spf_record: Option<String>,
    pub dkim_enabled: Option<bool>,
    pub dmarc_policy: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateDomainRequest {
    pub description: Option<String>,
    pub mx_priority: Option<i32>,
    pub spf_record: Option<String>,
    pub dkim_enabled: Option<bool>,
    pub dmarc_policy: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DomainResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub is_verified: bool,
    pub mx_priority: i32,
    pub spf_record: Option<String>,
    pub dkim_enabled: bool,
    pub dmarc_policy: Option<String>,
    pub user_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ListDomainsQuery {
    pub is_active: Option<bool>,
    pub is_verified: Option<bool>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_domains(
    State(state): State<AppState>,
    claims: Claims,
    Query(params): Query<ListDomainsQuery>,
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
        SELECT d.*, COUNT(u.id) as user_count
        FROM domains d
        LEFT JOIN users u ON d.id = u.domain_id
        WHERE 1=1
        "#,
    );

    // Add filters
    if let Some(is_active) = params.is_active {
        query_builder.push(" AND d.is_active = ");
        query_builder.push_bind(is_active);
    }

    if let Some(is_verified) = params.is_verified {
        query_builder.push(" AND d.is_verified = ");
        query_builder.push_bind(is_verified);
    }

    if let Some(search) = &params.search {
        query_builder.push(" AND (d.name ILIKE ");
        query_builder.push_bind(format!("%{}%", search));
        query_builder.push(" OR d.description ILIKE ");
        query_builder.push_bind(format!("%{}%", search));
        query_builder.push(")");
    }

    query_builder.push(" GROUP BY d.id ORDER BY d.created_at DESC LIMIT ");
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

    let domains: Vec<DomainResponse> = rows
        .iter()
        .map(|row| DomainResponse {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            is_active: row.get("is_active"),
            is_verified: row.get("is_verified"),
            mx_priority: row.get("mx_priority"),
            spf_record: row.get("spf_record"),
            dkim_enabled: row.get("dkim_enabled"),
            dmarc_policy: row.get("dmarc_policy"),
            user_count: row.get("user_count"),
            created_at: row.get("created_at"),
            verified_at: row.get("verified_at"),
        })
        .collect();

    Ok(Json(json!({
        "domains": domains,
        "total": domains.len(),
        "limit": limit,
        "offset": offset
    })))
}

pub async fn create_domain(
    State(state): State<AppState>,
    claims: Claims,
    Json(request): Json<CreateDomainRequest>,
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

    // Validate domain name
    if request.name.is_empty() || !request.name.contains('.') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid domain name"})),
        ));
    }

    // Check if domain already exists
    let existing = sqlx::query("SELECT id FROM domains WHERE name = $1")
        .bind(&request.name)
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
            Json(json!({"error": "Domain already exists"})),
        ));
    }

    let domain_id = Uuid::new_v4();

    // Create domain in database
    sqlx::query(
        r#"
        INSERT INTO domains (id, name, description, mx_priority, spf_record, dkim_enabled, dmarc_policy, is_active, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, true, NOW())
        "#,
    )
    .bind(domain_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(request.mx_priority.unwrap_or(10))
    .bind(&request.spf_record)
    .bind(request.dkim_enabled.unwrap_or(false))
    .bind(&request.dmarc_policy)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create domain"})),
        )
    })?;

    // Set up DNS records via PowerDNS (if configured)
    // This would typically be done asynchronously
    tokio::spawn(async move {
        // Domain setup logic would go here
        // For now, we'll just log the action
        tracing::info!("Domain {} created, DNS setup pending", request.name);
    });

    Ok(Json(json!({
        "domain_id": domain_id,
        "name": request.name,
        "status": "created",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn get_domain(
    State(state): State<AppState>,
    claims: Claims,
    Path(domain_id): Path<Uuid>,
) -> Result<Json<DomainResponse>, (StatusCode, Json<Value>)> {
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

    let row = sqlx::query(
        r#"
        SELECT d.*, COUNT(u.id) as user_count
        FROM domains d
        LEFT JOIN users u ON d.id = u.domain_id
        WHERE d.id = $1
        GROUP BY d.id
        "#,
    )
    .bind(domain_id)
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
            Json(json!({"error": "Domain not found"})),
        )
    })?;

    let domain = DomainResponse {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        is_active: row.get("is_active"),
        is_verified: row.get("is_verified"),
        mx_priority: row.get("mx_priority"),
        spf_record: row.get("spf_record"),
        dkim_enabled: row.get("dkim_enabled"),
        dmarc_policy: row.get("dmarc_policy"),
        user_count: row.get("user_count"),
        created_at: row.get("created_at"),
        verified_at: row.get("verified_at"),
    };

    Ok(Json(domain))
}

pub async fn update_domain(
    State(state): State<AppState>,
    claims: Claims,
    Path(domain_id): Path<Uuid>,
    Json(request): Json<UpdateDomainRequest>,
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

    // Build dynamic update query
    let mut query_builder = sqlx::QueryBuilder::new("UPDATE domains SET ");
    let mut has_updates = false;

    if let Some(description) = &request.description {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("description = ");
        query_builder.push_bind(description);
        has_updates = true;
    }

    if let Some(mx_priority) = request.mx_priority {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("mx_priority = ");
        query_builder.push_bind(mx_priority);
        has_updates = true;
    }

    if let Some(spf_record) = &request.spf_record {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("spf_record = ");
        query_builder.push_bind(spf_record);
        has_updates = true;
    }

    if let Some(dkim_enabled) = request.dkim_enabled {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("dkim_enabled = ");
        query_builder.push_bind(dkim_enabled);
        has_updates = true;
    }

    if let Some(dmarc_policy) = &request.dmarc_policy {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("dmarc_policy = ");
        query_builder.push_bind(dmarc_policy);
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
    query_builder.push_bind(domain_id);

    let query = query_builder.build();
    let result = query.execute(&state.db).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to update domain"})),
        )
    })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Domain not found"})),
        ));
    }

    Ok(Json(json!({
        "domain_id": domain_id,
        "status": "updated",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn delete_domain(
    State(state): State<AppState>,
    claims: Claims,
    Path(domain_id): Path<Uuid>,
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

    // Check if domain has users
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE domain_id = $1")
        .bind(domain_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database query failed"})),
            )
        })?;

    if user_count > 0 {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "Cannot delete domain with existing users"})),
        ));
    }

    let result = sqlx::query("DELETE FROM domains WHERE id = $1")
        .bind(domain_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to delete domain"})),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Domain not found"})),
        ));
    }

    Ok(Json(json!({
        "domain_id": domain_id,
        "status": "deleted",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn verify_domain(
    State(state): State<AppState>,
    claims: Claims,
    Path(domain_id): Path<Uuid>,
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

    // Get domain information
    let domain_row = sqlx::query("SELECT name FROM domains WHERE id = $1")
        .bind(domain_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database query failed"})),
            )
        })?;

    let domain_row = domain_row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Domain not found"})),
        )
    })?;

    let domain_name: String = domain_row.get("name");

    // Perform DNS verification (simplified)
    // In a real implementation, this would check MX, SPF, DKIM, and DMARC records
    let verification_result = perform_dns_verification(&domain_name).await;

    let is_verified = verification_result.is_ok();
    let verification_details = match verification_result {
        Ok(details) => details,
        Err(error) => json!({"error": error}),
    };

    // Update verification status
    if is_verified {
        sqlx::query("UPDATE domains SET is_verified = true, verified_at = NOW() WHERE id = $1")
            .bind(domain_id)
            .execute(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to update verification status"})),
                )
            })?;
    }

    Ok(Json(json!({
        "domain_id": domain_id,
        "domain_name": domain_name,
        "is_verified": is_verified,
        "verification_details": verification_details,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

async fn perform_dns_verification(domain: &str) -> Result<Value, String> {
    // This is a simplified implementation
    // In production, you would use a DNS resolver library to check:
    // - MX records point to your mail server
    // - SPF record is properly configured
    // - DKIM records are present
    // - DMARC policy is set

    // For now, we'll simulate the verification
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    Ok(json!({
        "mx_records": ["mail.example.com"],
        "spf_record": "v=spf1 include:_spf.example.com ~all",
        "dkim_records": ["default._domainkey.example.com"],
        "dmarc_record": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
    }))
}
