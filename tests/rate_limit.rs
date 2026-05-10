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

fn submit_body(recipient_hex: &str, envelope_id: Ulid, n: u8) -> String {
    let env = json!({
        "envelope_id": envelope_id.to_string(),
        "recipient_device_id": recipient_hex,
        "recipient_tag": hex::encode([n; 32]),
        "epoch": 1,
        "seq": n as u64,
        "nonce": hex::encode([n; 24]),
        "ciphertext": base64_std(&[0xAB; 16]),
        "content_signature": base64_std(&[0xCD; 64]),
    });
    json!({ "envelopes": [env] }).to_string()
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
        let body = submit_body(&bob.device_id_hex(), Ulid::new(), n);
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

#[tokio::test]
async fn exact_duplicate_retry_is_accepted_at_submission_cap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let database_url = format!("sqlite://{}/krone.sqlite?mode=rwc", data_dir.display());
    let policy = Policy {
        max_envelopes_per_device_per_hour: 1,
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

    let alice = ClientIdentity::from_seed([0xAC; 32]);
    let bob = ClientIdentity::from_seed([0xBC; 32]);
    register(&router, &alice).await;
    register(&router, &bob).await;

    let base = ClientIdentity::now_ts();
    let body = submit_body(&bob.device_id_hex(), Ulid::new(), 7);

    let req = alice.sign_request("POST", "/envelopes", body.as_bytes(), base);
    let res = router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    let retry = alice.sign_request("POST", "/envelopes", body.as_bytes(), base + 1);
    let res = router.clone().oneshot(retry).await.expect("oneshot");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "exact duplicate retries must not consume sender quota"
    );

    let fresh_body = submit_body(&bob.device_id_hex(), Ulid::new(), 8);
    let fresh = alice.sign_request("POST", "/envelopes", fresh_body.as_bytes(), base + 2);
    let res = router.clone().oneshot(fresh).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}
