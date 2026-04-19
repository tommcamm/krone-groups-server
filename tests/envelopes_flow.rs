//! End-to-end test: Alice registers, Bob registers, Alice submits an envelope to Bob,
//! Bob reads his inbox, Bob acks, Bob's inbox goes empty.

use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;
use ulid::Ulid;

mod common;

use common::signing::ClientIdentity;

async fn register(harness: &common::TestHarness, id: &ClientIdentity) {
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
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK, "register failed");
}

fn base64_std(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn sample_envelope(recipient_hex: &str) -> (Ulid, serde_json::Value) {
    let envelope_id = Ulid::new();
    let ciphertext = vec![0xAB; 64];
    let content_signature = vec![0xCD; 64]; // arbitrary; server doesn't verify content sig
    let nonce = vec![0xEF; 24];
    let recipient_tag = vec![0x11; 32];

    let v = json!({
        "envelope_id": envelope_id.to_string(),
        "recipient_device_id": recipient_hex,
        "recipient_tag": hex::encode(recipient_tag),
        "epoch": 1,
        "seq": 7,
        "nonce": hex::encode(nonce),
        "ciphertext": base64_std(&ciphertext),
        "content_signature": base64_std(&content_signature),
    });
    (envelope_id, v)
}

#[tokio::test]
async fn full_round_trip() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0x11; 32]);
    let bob = ClientIdentity::from_seed([0x22; 32]);

    register(&harness, &alice).await;
    register(&harness, &bob).await;

    // Alice submits an envelope to Bob.
    let (env_id, env) = sample_envelope(&bob.device_id_hex());
    let submit_body = json!({ "envelopes": [env] }).to_string();
    let req = alice.sign_request(
        "POST",
        "/envelopes",
        submit_body.as_bytes(),
        ClientIdentity::now_ts(),
    );
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(parsed["accepted"].as_array().expect("accepted").len(), 1);
    assert_eq!(
        parsed["accepted"][0].as_str().expect("ulid"),
        env_id.to_string()
    );

    // Bob reads inbox.
    let req = bob.sign_request("GET", "/envelopes/inbox", b"", ClientIdentity::now_ts());
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let inbox: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let envs = inbox["envelopes"].as_array().expect("envelopes array");
    assert_eq!(envs.len(), 1, "expected 1 envelope in inbox");
    assert_eq!(
        envs[0]["envelope_id"].as_str().expect("ulid"),
        env_id.to_string()
    );
    assert_eq!(
        envs[0]["sender_device_id"].as_str().expect("sender"),
        alice.device_id_hex()
    );
    assert_eq!(
        envs[0]["recipient_device_id"].as_str().expect("recipient"),
        bob.device_id_hex()
    );

    // Bob acks.
    let ack_body = json!({ "envelope_ids": [env_id.to_string()] }).to_string();
    let req = bob.sign_request(
        "POST",
        "/envelopes/ack",
        ack_body.as_bytes(),
        ClientIdentity::now_ts(),
    );
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(parsed["acknowledged"].as_u64().expect("n"), 1);

    // Second inbox read is empty.
    let req = bob.sign_request("GET", "/envelopes/inbox", b"", ClientIdentity::now_ts());
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let inbox: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let envs = inbox["envelopes"].as_array().expect("envelopes array");
    assert!(
        envs.is_empty(),
        "inbox should be empty after ack, got {envs:?}"
    );
}

#[tokio::test]
async fn duplicate_envelope_id_is_idempotent() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0x33; 32]);
    let bob = ClientIdentity::from_seed([0x44; 32]);

    register(&harness, &alice).await;
    register(&harness, &bob).await;

    let (env_id, env) = sample_envelope(&bob.device_id_hex());
    let submit_body = json!({ "envelopes": [env.clone()] }).to_string();

    for _ in 0..3 {
        let req = alice.sign_request(
            "POST",
            "/envelopes",
            submit_body.as_bytes(),
            ClientIdentity::now_ts(),
        );
        let res = harness.router.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(res.status(), StatusCode::OK);
    }

    // Bob should still only see one envelope.
    let req = bob.sign_request("GET", "/envelopes/inbox", b"", ClientIdentity::now_ts());
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let inbox: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let envs = inbox["envelopes"].as_array().expect("envelopes array");
    assert_eq!(envs.len(), 1);
    assert_eq!(
        envs[0]["envelope_id"].as_str().expect("ulid"),
        env_id.to_string()
    );
}

#[tokio::test]
async fn sender_cannot_address_self() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0x55; 32]);
    register(&harness, &alice).await;

    let (_, env) = sample_envelope(&alice.device_id_hex());
    let submit_body = json!({ "envelopes": [env] }).to_string();
    let req = alice.sign_request(
        "POST",
        "/envelopes",
        submit_body.as_bytes(),
        ClientIdentity::now_ts(),
    );
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn inbox_pagination_honors_limit_and_cursor() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0x66; 32]);
    let bob = ClientIdentity::from_seed([0x77; 32]);
    register(&harness, &alice).await;
    register(&harness, &bob).await;

    // Submit 5 envelopes.
    let mut ids = Vec::new();
    for _ in 0..5 {
        let (id, env) = sample_envelope(&bob.device_id_hex());
        ids.push(id);
        let body = json!({ "envelopes": [env] }).to_string();
        let req = alice.sign_request(
            "POST",
            "/envelopes",
            body.as_bytes(),
            ClientIdentity::now_ts(),
        );
        let res = harness.router.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(res.status(), StatusCode::OK);
    }

    // First page: limit 2.
    let req = bob.sign_request(
        "GET",
        "/envelopes/inbox?limit=2",
        b"",
        ClientIdentity::now_ts(),
    );
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let inbox: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let envs = inbox["envelopes"].as_array().expect("envelopes array");
    assert_eq!(envs.len(), 2);
    let cursor = inbox["next_cursor"].as_str().expect("cursor").to_string();

    // Second page.
    let path = format!("/envelopes/inbox?limit=2&since={}", urlencoded(&cursor));
    let req = bob.sign_request("GET", &path, b"", ClientIdentity::now_ts());
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let inbox: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let envs = inbox["envelopes"].as_array().expect("envelopes array");
    assert_eq!(envs.len(), 2);
}

fn urlencoded(s: &str) -> String {
    // Minimal encoder — the cursor contains digits, `-`, and base32 chars; no reserved chars.
    s.to_string()
}
