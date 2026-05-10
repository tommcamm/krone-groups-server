//! Middleware that signs every outgoing response with the server Ed25519 key
//! and attaches `x-server-signature` + `x-request-id` headers.

use axum::body::Bytes;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, response::Parts};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ulid::Ulid;

use crate::crypto::response_signing_input;
use crate::state::AppState;

const REQUEST_ID_HEADER: &str = "x-request-id";
const SERVER_SIG_HEADER: &str = "x-server-signature";

pub async fn sign_responses(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    // Ensure the request has a request-id we can echo back (used in the signing input).
    let request_id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| Ulid::new().to_string());

    if let Ok(hv) = HeaderValue::from_str(&request_id) {
        req.headers_mut().insert(REQUEST_ID_HEADER, hv);
    }

    let res = next.run(req).await;
    let (mut parts, body) = res.into_parts();

    // Buffer the body so we can hash it. 16 MiB cap is far above anything we return.
    let bytes = match to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "response body exceeded buffer cap");
            // Preserving the original (likely 2xx) status would ship a success status with a
            // failure body — return a proper 500 so clients treat it as the error it is.
            parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            parts.headers.remove(axum::http::header::CONTENT_LENGTH);
            let bytes = Bytes::from_static(b"internal error");
            attach_signature(&mut parts, &request_id, &state, &bytes);
            return Response::from_parts(parts, Body::from(bytes));
        }
    };

    attach_signature(&mut parts, &request_id, &state, &bytes);
    Response::from_parts(parts, Body::from(bytes))
}

fn attach_signature(parts: &mut Parts, request_id: &str, state: &AppState, bytes: &[u8]) {
    let status = parts.status.as_u16();
    let input = response_signing_input(request_id, status, bytes);
    let sig = state.signer.sign(&input);
    let sig_b64 = B64.encode(sig);

    if let Ok(hv) = HeaderValue::from_str(&sig_b64) {
        parts.headers.insert(SERVER_SIG_HEADER, hv);
    }
    if let Ok(hv) = HeaderValue::from_str(request_id) {
        parts.headers.insert(REQUEST_ID_HEADER, hv);
    }
}
