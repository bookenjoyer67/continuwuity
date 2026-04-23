use axum::{
    extract::{Query, State},
    response::{IntoResponse, Json},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use conduwuit::{Err, Result, err, Error};
use ruma::{OwnedUserId, OwnedDeviceId, api::client::error::ErrorKind};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
pub(crate) struct BlockIpRequest {
    ip: String,
    reason: String,
    duration_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LockUserRequest {
    user_id: String,
    reason: String,
    duration_seconds: Option<u64>,
}

/// Helper to extract user ID from bearer token and verify admin
async fn authenticate_admin(
    services: &crate::State,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    query_token: Option<&str>,
) -> Result<OwnedUserId> {
    let token = match &bearer {
        | Some(TypedHeader(Authorization(bearer))) => Some(bearer.token()),
        | None => query_token,
    };
    let token = token.ok_or_else(|| err!(Request(MissingToken("Missing access token"))))?;
    
    // Find user from token (returns user_id, device_id)
    let result: Result<(OwnedUserId, OwnedDeviceId), _> = services.users.find_from_token(token).await;
    let (user_id, _device_id) = result.map_err(|_| 
        Error::BadRequest(
            ErrorKind::UnknownToken { soft_logout: false },
            "Invalid access token",
        )
    )?;
    
    // Check if user is admin
    if !services.users.is_admin(&user_id).await {
        return Err!(Request(Forbidden("Only server administrators can use this endpoint")));
    }
    
    Ok(user_id)
}

/// GET /_matrix/client/v1/admin/login_security/blocked_ips
pub(crate) async fn get_blocked_ips(
    State(services): State<crate::State>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    query: Query<Value>,
) -> Result<impl IntoResponse> {
    let _admin_user = authenticate_admin(&services, bearer, query.get("access_token").and_then(|v| v.as_str())).await?;
    
    let blocked_ips = services.login_security.list_blocked_ips().await?;
    Ok(Json(json!({ "blocked_ips": blocked_ips })))
}

/// DELETE /_matrix/client/v1/admin/login_security/blocked_ips/{ip}
#[derive(Debug, Deserialize)]
pub(crate) struct UnblockIpPath {
    ip: String,
}

pub(crate) async fn delete_blocked_ip(
    State(services): State<crate::State>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    query: Query<Value>,
    axum::extract::Path(path): axum::extract::Path<UnblockIpPath>,
) -> Result<impl IntoResponse> {
    let _admin_user = authenticate_admin(&services, bearer, query.get("access_token").and_then(|v| v.as_str())).await?;
    
    services.login_security.unblock_ip(&path.ip).await?;
    Ok(Json(json!({ "success": true })))
}

/// POST /_matrix/client/v1/admin/login_security/blocked_ips
pub(crate) async fn post_block_ip(
    State(services): State<crate::State>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Json(body): Json<BlockIpRequest>,
) -> Result<impl IntoResponse> {
    let _admin_user = authenticate_admin(&services, bearer, None).await?;
    
    // Validate IP format
    if body.ip.is_empty() || body.ip.contains('|') {
        return Err!(Request(InvalidParam("Invalid IP address format")));
    }
    
    services.login_security.manually_block_ip(&body.ip, body.reason, body.duration_seconds).await?;
    Ok(Json(json!({ "success": true })))
}

/// POST /_matrix/client/v1/admin/login_security/locked_users
pub(crate) async fn post_lock_user(
    State(services): State<crate::State>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    Json(body): Json<LockUserRequest>,
) -> Result<impl IntoResponse> {
    let _admin_user = authenticate_admin(&services, bearer, None).await?;
    
    let user_id = OwnedUserId::try_from(body.user_id)
        .map_err(|_| err!(Request(InvalidParam("Invalid user ID"))))?;
    
    services.login_security.manually_lock_user(&user_id, body.reason, body.duration_seconds).await?;
    Ok(Json(json!({ "success": true })))
}

/// GET /_matrix/client/v1/admin/login_security/locked_users
pub(crate) async fn get_locked_users(
    State(services): State<crate::State>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    query: Query<Value>,
) -> Result<impl IntoResponse> {
    let _admin_user = authenticate_admin(&services, bearer, query.get("access_token").and_then(|v| v.as_str())).await?;
    
    let locked_users = services.login_security.list_locked_users().await?;
    Ok(Json(json!({ "locked_users": locked_users })))
}

/// DELETE /_matrix/client/v1/admin/login_security/locked_users/{userId}
#[derive(Debug, Deserialize)]
pub(crate) struct UnlockUserPath {
    user_id: String,
}

pub(crate) async fn delete_locked_user(
    State(services): State<crate::State>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    query: Query<Value>,
    axum::extract::Path(path): axum::extract::Path<UnlockUserPath>,
) -> Result<impl IntoResponse> {
    let _admin_user = authenticate_admin(&services, bearer, query.get("access_token").and_then(|v| v.as_str())).await?;
    
    let user_id = OwnedUserId::try_from(path.user_id)
        .map_err(|_| err!(Request(InvalidParam("Invalid user ID"))))?;
    services.login_security.unlock_user(&user_id).await?;
    Ok(Json(json!({ "success": true })))
}

/// GET /_matrix/client/v1/admin/login_security/attempts
#[derive(Debug, Deserialize)]
pub(crate) struct GetAttemptsQuery {
    user: Option<String>,
    ip: Option<String>,
    limit: Option<usize>,
}

pub(crate) async fn get_attempts(
    State(services): State<crate::State>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    query: Query<GetAttemptsQuery>,
) -> Result<impl IntoResponse> {
    let _admin_user = authenticate_admin(&services, bearer, None).await?;
    
    let limit = query.limit.unwrap_or(50);
    let mut response = serde_json::Map::new();
    
    if let Some(user_str) = &query.user {
        let user_id = OwnedUserId::try_from(user_str.as_str())
            .map_err(|_| err!(Request(InvalidParam("Invalid user ID"))))?;
        let attempts = services.login_security.get_login_attempts_for_user(&user_id, limit).await?;
        response.insert("user_attempts".to_string(), json!(attempts));
    } else if let Some(ip_addr) = &query.ip {
        let attempts = services.login_security.get_login_attempts_for_ip(ip_addr, limit).await?;
        response.insert("ip_attempts".to_string(), json!(attempts));
    } else {
        return Err!(Request(InvalidParam("Must specify either 'user' or 'ip'")));
    }
    
    Ok(Json(Value::Object(response)))
}

/// DELETE /_matrix/client/v1/admin/login_security/attempts?older_than_days={days}
#[derive(Debug, Deserialize)]
pub(crate) struct CleanupAttemptsQuery {
    older_than_days: u32,
}

pub(crate) async fn delete_old_attempts(
    State(services): State<crate::State>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    query: Query<CleanupAttemptsQuery>,
) -> Result<impl IntoResponse> {
    let _admin_user = authenticate_admin(&services, bearer, None).await?;
    
    let cutoff = conduwuit::utils::millis_since_unix_epoch() - (query.older_than_days as u64 * 24 * 60 * 60 * 1000);
    let deleted = services.login_security.delete_attempts_older_than(cutoff).await?;
    Ok(Json(json!({ "deleted": deleted })))
}