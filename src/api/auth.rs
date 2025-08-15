use axum::{extract::State, http::StatusCode, response::Json, Extension};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    api::AppState,
    auth::{AuthService, User},
    error::MailServerError,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub user: UserInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: i32,
    pub email: String,
    pub full_name: String,
    pub is_admin: bool,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user id
    pub email: String,
    pub exp: usize,
    pub iat: usize,
    pub is_admin: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<Value>)> {
    let auth_service = AuthService::new(state.db.clone());

    // Authenticate user
    let user = match auth_service
        .authenticate(&payload.email, &payload.password)
        .await
    {
        Ok(user) => user,
        Err(_) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid credentials"})),
            ));
        }
    };

    // Check TOTP if enabled
    if user.totp_secret.is_some() {
        if let Some(totp_code) = payload.totp_code {
            if !auth_service
                .verify_totp(&user.email, &totp_code)
                .await
                .unwrap_or(false)
            {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid TOTP code"})),
                ));
            }
        } else {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "TOTP code required"})),
            ));
        }
    }

    // Generate JWT tokens
    let now = Utc::now();
    let expires_in = 3600; // 1 hour

    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
        exp: (now + Duration::seconds(expires_in)).timestamp() as usize,
        iat: now.timestamp() as usize,
        is_admin: user.is_admin,
    };

    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_ref()),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to generate token"})),
        )
    })?;

    let refresh_claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
        exp: (now + Duration::days(7)).timestamp() as usize,
        iat: now.timestamp() as usize,
        is_admin: user.is_admin,
    };

    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_ref()),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to generate refresh token"})),
        )
    })?;

    let user_info = UserInfo {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        is_admin: user.is_admin,
        created_at: user.created_at,
    };

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        expires_in,
        user: user_info,
    }))
}

pub async fn logout(
    Extension(user): Extension<User>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // In a production system, you'd invalidate the token in a blacklist
    Ok(Json(json!({"message": "Logged out successfully"})))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<Value>)> {
    let token_data = decode::<Claims>(
        &payload.refresh_token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid refresh token"})),
        )
    })?;

    let auth_service = AuthService::new(state.db.clone());
    let user = auth_service
        .get_user_by_email(&token_data.claims.email)
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "User not found"})),
            )
        })?;

    // Generate new access token
    let now = Utc::now();
    let expires_in = 3600;

    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
        exp: (now + Duration::seconds(expires_in)).timestamp() as usize,
        iat: now.timestamp() as usize,
        is_admin: user.is_admin,
    };

    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_ref()),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to generate token"})),
        )
    })?;

    let user_info = UserInfo {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        is_admin: user.is_admin,
        created_at: user.created_at,
    };

    Ok(Json(LoginResponse {
        access_token,
        refresh_token: payload.refresh_token, // Return the same refresh token
        expires_in,
        user: user_info,
    }))
}

pub async fn get_current_user(
    Extension(user): Extension<User>,
) -> Result<Json<UserInfo>, (StatusCode, Json<Value>)> {
    let user_info = UserInfo {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        is_admin: user.is_admin,
        created_at: user.created_at,
    };

    Ok(Json(user_info))
}
