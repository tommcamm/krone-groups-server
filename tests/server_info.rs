use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use http_body_util::BodyExt;
use tower::ServiceExt;

use krone_groups_server::crypto::{bip39_fingerprint, response_signing_input, verify_ed25519};
use krone_groups_server::protocol::server_info::ServerInfoResponse;

mod common;

#[tokio::test]
async fn server_info_returns_signed_json() {
    let harness = common::build_harness().await;
    let signer_pk = harness.signer_pk;

    let res = harness
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/server-info")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(res.status(), StatusCode::OK);

    // Grab signature headers before consuming the body.
    let sig_b64 = res
        .headers()
        .get("x-server-signature")
        .expect("sig header")
        .to_str()
        .expect("sig ascii")
        .to_string();
    let request_id = res
        .headers()
        .get("x-request-id")
        .expect("request id header")
        .to_str()
        .expect("id ascii")
        .to_string();

    let bytes = res.into_body().collect().await.expect("collect").to_bytes();

    let parsed: ServerInfoResponse = serde_json::from_slice(&bytes).expect("parse");
    assert_eq!(parsed.protocol_version, "1.0.0");
    assert_eq!(*parsed.server_pk.as_bytes(), signer_pk);
    assert!(parsed.policy.ttl_seconds >= 60);

    // Verify response signature against the server pubkey we know from the harness.
    let sig_bytes = B64.decode(sig_b64.as_bytes()).expect("b64 sig");
    assert_eq!(sig_bytes.len(), 64, "ed25519 sig is 64 bytes");
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let input = response_signing_input(&request_id, 200, &bytes);
    verify_ed25519(&signer_pk, &input, &sig_arr).expect("verify server sig");
}

#[test]
fn fingerprint_is_eight_words() {
    let pk = [7u8; 32];
    let fp = bip39_fingerprint(&pk);
    assert_eq!(fp.split_whitespace().count(), 8);
}
