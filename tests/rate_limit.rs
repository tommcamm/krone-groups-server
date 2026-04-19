//! Per-device submission rate limit — exceeding the hourly budget returns 429.

use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;
use ulid::Ulid;

mod common;

use common::signing::ClientIdentity;
use krone_groups_server::config::{AppConfig, Policy};
use krone_groups_server::router_for_tests;
use krone_groups_server::state::AppState;

fn base64_std(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

async fn register(router: &axum::Router, id: &ClientIdentity) {
    let body = json!({
        "device_id": id.device_id_hex(),
        "identity_pk": hex::encode(id.public_key()),
    })
    .to_string();
    let req = id.sign_request(
        "POST",
        "/devices",
        body.as_bytes(),
        ClientIdentity::now_ts(),
    );
    let res = router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn per_device_submission_cap_returns_429() {
    // Build a harness with a tight per-device cap (3/hour) so the test is fast.
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let database_url = format!("sqlite://{}/krone.sqlite?mode=rwc", data_dir.display());
    let policy = Policy {
        max_envelopes_per_device_per_hour: 3,
        ..Policy::default()
    };
    let cfg = AppConfig {
        bind_addr: "127.0.0.1:0".parse().expect("parse"),
        data_dir,
        database_url,
        policy,
        server_seed_hex: Some(common::TEST_SERVER_SEED_HEX.to_string()),
        server_version: "test".into(),
    };
    let state = AppState::init(cfg).await.expect("state init");
    let router = router_for_tests(state);

    let alice = ClientIdentity::from_seed([0xAA; 32]);
    let bob = ClientIdentity::from_seed([0xBB; 32]);
    register(&router, &alice).await;
    register(&router, &bob).await;

    // Helper to submit one envelope.
    let submit = async |n: u8| -> StatusCode {
        let env = json!({
            "envelope_id": Ulid::new().to_string(),
            "recipient_device_id": bob.device_id_hex(),
            "recipient_tag": hex::encode([n; 32]),
            "epoch": 1,
            "seq": n as u64,
            "nonce": hex::encode([n; 24]),
            "ciphertext": base64_std(&[0xAB; 16]),
            "content_signature": base64_std(&[0xCD; 64]),
        });
        let body = json!({ "envelopes": [env] }).to_string();
        let req = alice.sign_request(
            "POST",
            "/envelopes",
            body.as_bytes(),
            ClientIdentity::now_ts(),
        );
        router.clone().oneshot(req).await.expect("oneshot").status()
    };

    // First three succeed; fourth hits the cap.
    for i in 0..3u8 {
        assert_eq!(submit(i + 1).await, StatusCode::OK, "submit {} failed", i);
    }
    assert_eq!(submit(99).await, StatusCode::TOO_MANY_REQUESTS);
}
