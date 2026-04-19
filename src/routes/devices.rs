use axum::{
    Json, Router,
    extract::State,
    routing::{delete, post},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::auth::RawSignedRequest;
use crate::db::queries;
use crate::error::ApiError;
use crate::protocol::device::{DeviceRegistrationRequest, DeviceRegistrationResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/devices", post(register))
        .route("/devices/self", delete(delete_self))
}

async fn register(
    State(state): State<AppState>,
    signed: RawSignedRequest,
) -> Result<Json<DeviceRegistrationResponse>, ApiError> {
    let body: DeviceRegistrationRequest = signed.body_json()?;

    // device_id must be first 16 bytes of SHA-256(identity_pk).
    let digest = Sha256::digest(body.identity_pk.as_bytes());
    let mut expected = [0u8; 16];
    expected.copy_from_slice(&digest[..16]);
    if body.device_id.as_bytes() != &expected {
        return Err(ApiError::BadRequest(
            "device_id does not match SHA-256(identity_pk)[..16]".to_string(),
        ));
    }

    // Signed-request header device_id must match body device_id.
    if signed.device_id.as_bytes() != body.device_id.as_bytes() {
        return Err(ApiError::BadRequest(
            "header device-id does not match body device_id".to_string(),
        ));
    }

    // Verify the signature using the pubkey the caller is registering.
    signed.verify_with(body.identity_pk.as_bytes())?;

    let now = OffsetDateTime::now_utc();
    let registered_at =
        queries::upsert_device(&state.db, &body.device_id, &body.identity_pk, now).await?;

    tracing::info!(
        device_id = %body.device_id,
        "device registered",
    );

    Ok(Json(DeviceRegistrationResponse {
        device_id: body.device_id,
        registered_at,
    }))
}

async fn delete_self(
    State(state): State<AppState>,
    signed: RawSignedRequest,
) -> Result<Json<Value>, ApiError> {
    // Body is expected to be empty; verify signature against the registered device pubkey.
    let pk = queries::get_device_pk(&state.db, &signed.device_id)
        .await?
        .ok_or(ApiError::Unauthorized("unknown device"))?;
    signed.verify_with(&pk)?;

    if !signed.body_bytes.is_empty() {
        return Err(ApiError::BadRequest(
            "delete expects empty body".to_string(),
        ));
    }

    queries::delete_device(&state.db, &signed.device_id).await?;
    tracing::info!(device_id = %signed.device_id, "device deleted self");
    Ok(Json(json!({ "status": "ok" })))
}
