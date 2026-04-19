use axum::{Json, Router, extract::State, routing::get};

use crate::protocol::common::HexBytes;
use crate::protocol::server_info::{Policy, ServerInfoResponse};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/server-info", get(server_info))
}

async fn server_info(State(state): State<AppState>) -> Json<ServerInfoResponse> {
    let cfg = &state.cfg;
    Json(ServerInfoResponse {
        protocol_version: "1.0.0".into(),
        server_version: format!("krone-groups-server/{}", cfg.server_version),
        server_pk: HexBytes(state.signer.public_key_bytes()),
        policy: Policy {
            ttl_seconds: cfg.policy.ttl_seconds,
            max_envelope_bytes: cfg.policy.max_envelope_bytes,
            max_inbox_per_device: cfg.policy.max_inbox_per_device,
            max_envelopes_per_device_per_hour: cfg.policy.max_envelopes_per_device_per_hour,
            clock_skew_seconds: cfg.policy.clock_skew_seconds,
        },
    })
}
