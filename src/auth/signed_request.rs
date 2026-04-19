//! Axum extractors for signed requests.
//!
//! - `SignedRequest<T>`: verifies the signature against the device's registered identity key.
//!   The device must already exist in `devices`. Used by every signed endpoint except
//!   `POST /devices` (where the pubkey is in the body).
//!
//! - `RawSignedRequest`: returns headers + raw body + verified device_id without deserializing
//!   the body. `POST /devices` uses this so it can read the pubkey out of the body and verify
//!   against that.

use axum::body::{Bytes, to_bytes};
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderMap, Method};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::de::DeserializeOwned;
use std::str::FromStr;
use time::OffsetDateTime;

use crate::crypto::{request_signing_input, verify_ed25519};
use crate::db::queries;
use crate::error::ApiError;
use crate::protocol::common::{DeviceId, HexBytes};
use crate::state::AppState;

const HDR_DEVICE_ID: &str = "x-krone-device-id";
const HDR_TIMESTAMP: &str = "x-krone-timestamp";
const HDR_SIGNATURE: &str = "x-krone-signature";

pub struct SignedRequest<T> {
    pub device_id: DeviceId,
    pub timestamp: i64,
    pub body: T,
}

pub struct RawSignedRequest {
    pub device_id: DeviceId,
    pub timestamp: i64,
    pub body_bytes: Bytes,
    pub signature: [u8; 64],
    pub method: Method,
    pub path_with_query: String,
}

struct ParsedHeaders {
    device_id: DeviceId,
    timestamp: i64,
    signature: [u8; 64],
}

impl<T> FromRequest<AppState> for SignedRequest<T>
where
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();

        let parsed = parse_signature_headers(&parts.headers, state)?;
        let path_with_query = path_and_query(&parts.uri);
        let method = parts.method.clone();

        let max = max_body_bytes(state, &method, &path_with_query);
        let body_bytes = to_bytes(body, max)
            .await
            .map_err(|_| ApiError::PayloadTooLarge)?;

        let pk = queries::get_device_pk(&state.db, &parsed.device_id)
            .await?
            .ok_or(ApiError::Unauthorized("unknown device"))?;

        let input = request_signing_input(
            parsed.timestamp,
            &parsed.device_id.to_hex(),
            method.as_str(),
            &path_with_query,
            &body_bytes,
        );

        verify_ed25519(&pk, &input, &parsed.signature)
            .map_err(|_| ApiError::Unauthorized("bad signature"))?;

        // Anti-replay: reject if we've already seen this exact (device_id, signature).
        let is_new = queries::record_signature_seen(
            &state.db,
            &parsed.device_id,
            &parsed.signature,
            now_utc(),
        )
        .await?;
        if !is_new {
            return Err(ApiError::Unauthorized("request replay detected"));
        }

        // Best-effort observability tick.
        let _ = queries::touch_device(&state.db, &parsed.device_id, now_utc()).await;

        let body: T = serde_json::from_slice(&body_bytes)
            .map_err(|e| ApiError::BadRequest(format!("invalid json body: {e}")))?;

        Ok(SignedRequest {
            device_id: parsed.device_id,
            timestamp: parsed.timestamp,
            body,
        })
    }
}

impl FromRequest<AppState> for RawSignedRequest {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();

        let parsed = parse_signature_headers(&parts.headers, state)?;
        let path_with_query = path_and_query(&parts.uri);
        let method = parts.method.clone();

        let max = max_body_bytes(state, &method, &path_with_query);
        let body_bytes = to_bytes(body, max)
            .await
            .map_err(|_| ApiError::PayloadTooLarge)?;

        Ok(RawSignedRequest {
            device_id: parsed.device_id,
            timestamp: parsed.timestamp,
            body_bytes,
            signature: parsed.signature,
            method,
            path_with_query,
        })
    }
}

impl RawSignedRequest {
    /// Verify this request's signature against a supplied public key and record the
    /// (device_id, signature) pair in the anti-replay cache. Used by `POST /devices`
    /// (pubkey in body) and signed GET/DELETE endpoints whose body type is `()`.
    pub async fn verify_with(
        &self,
        state: &AppState,
        public_key: &[u8; 32],
    ) -> Result<(), ApiError> {
        let input = request_signing_input(
            self.timestamp,
            &self.device_id.to_hex(),
            self.method.as_str(),
            &self.path_with_query,
            &self.body_bytes,
        );
        verify_ed25519(public_key, &input, &self.signature)
            .map_err(|_| ApiError::Unauthorized("bad signature"))?;

        let is_new =
            queries::record_signature_seen(&state.db, &self.device_id, &self.signature, now_utc())
                .await?;
        if !is_new {
            return Err(ApiError::Unauthorized("request replay detected"));
        }
        Ok(())
    }

    pub fn body_json<T: DeserializeOwned>(&self) -> Result<T, ApiError> {
        serde_json::from_slice(&self.body_bytes)
            .map_err(|e| ApiError::BadRequest(format!("invalid json body: {e}")))
    }
}

fn parse_signature_headers(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<ParsedHeaders, ApiError> {
    let device_id_str = header_str(headers, HDR_DEVICE_ID)?;
    let device_id: DeviceId = HexBytes::from_str(device_id_str)
        .map_err(|e| ApiError::BadRequest(format!("invalid device-id header: {e}")))?;

    let ts_str = header_str(headers, HDR_TIMESTAMP)?;
    let timestamp: i64 = ts_str
        .parse()
        .map_err(|_| ApiError::Unauthorized("invalid timestamp header"))?;

    let skew = state.cfg.policy.clock_skew_seconds;
    let now_secs = now_utc().unix_timestamp();
    // Saturating ops so a pathological i64::MIN timestamp can't panic the arithmetic.
    // saturating_abs on i64::MIN returns i64::MAX, which is correctly > any finite skew.
    if now_secs.saturating_sub(timestamp).saturating_abs() > skew {
        return Err(ApiError::Unauthorized("timestamp skew exceeded"));
    }

    let sig_str = header_str(headers, HDR_SIGNATURE)?;
    let sig_vec = B64
        .decode(sig_str.as_bytes())
        .map_err(|_| ApiError::Unauthorized("invalid signature header (not base64)"))?;
    if sig_vec.len() != 64 {
        return Err(ApiError::Unauthorized("signature must be 64 bytes"));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_vec);

    Ok(ParsedHeaders {
        device_id,
        timestamp,
        signature,
    })
}

fn header_str<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, ApiError> {
    headers
        .get(name)
        .ok_or(ApiError::Unauthorized("missing auth header"))?
        .to_str()
        .map_err(|_| ApiError::Unauthorized("non-ascii auth header"))
}

fn path_and_query(uri: &axum::http::Uri) -> String {
    uri.path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string())
}

fn max_body_bytes(state: &AppState, method: &Method, path_with_query: &str) -> usize {
    // Only `POST /envelopes` carries ciphertext; cap everything else tightly so a single
    // misbehaving client can't burn memory on endpoints that only handle small JSON.
    let path = path_with_query.split('?').next().unwrap_or(path_with_query);
    let is_submit = method == Method::POST && path == "/envelopes";

    if is_submit {
        // Worst-case legitimate batch: MAX_BATCH envelopes × base64(ciphertext_max) + per-envelope
        // fixed fields (ULID, hex IDs, tags, nonce, sig, keys) + outer JSON framing. Base64 is
        // 4/3× decoded; use ×2 + 512 B per envelope for padding and safety.
        let envelope = state.cfg.policy.max_envelope_bytes as usize;
        let per_envelope_wire = envelope.saturating_mul(2).saturating_add(512);
        per_envelope_wire
            .saturating_mul(crate::config::MAX_ENVELOPES_PER_BATCH)
            .saturating_add(128 * 1024)
    } else {
        // Register/ack/delete bodies are kilobytes at most.
        128 * 1024
    }
}

fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}
