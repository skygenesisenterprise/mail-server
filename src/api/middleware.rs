use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Extension,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{
    api::{auth::Claims, AppState},
    auth::{AuthService, User},
};

pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for public endpoints
    let path = request.uri().path();
    if path == "/health" 
        || path == "/api/v1/auth/login" 
        || path == "/api/v1/auth/refresh" 
    {
        return Ok(next.run(request).await);
    }

    let auth_header = headers
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "));

    let token = match auth_header {
        Some(token) => token,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_ref()),
        &Validation::default(),
    ).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let auth_service = AuthService::new(state.db.clone());
    let user = auth_service
        .get_user_by_email(&token_data.claims.email)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    request.extensions_mut().insert(user);
    Ok(next.run(request).await)
}

// Simple in-memory rate limiter (in production, use Redis)
lazy_static::lazy_static! {
    static ref RATE_LIMITER: Arc<Mutex<HashMap<String, (Instant, u32)>>> = 
        Arc::new(Mutex::new(HashMap::new()));
}

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let client_ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|header| header.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let mut limiter = RATE_LIMITER.lock().unwrap();
    let now = Instant::now();
    let window_duration = Duration::from_secs(state.config.rate_limit_window);

    let (last_reset, count) = limiter
        .entry(client_ip.clone())
        .or_insert((now, 0));

    if now.duration_since(*last_reset) > window_duration {
        *last_reset = now;
        *count = 0;
    }

    if *count >= state.config.rate_limit_requests {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    *count += 1;
    drop(limiter);

    Ok(next.run(request).await)
}
