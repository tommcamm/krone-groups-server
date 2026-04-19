use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

mod common;

use common::signing::ClientIdentity;

#[tokio::test]
async fn register_device_happy_path() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xAA; 32]);

    let body = json!({
        "device_id": alice.device_id_hex(),
        "identity_pk": hex::encode(alice.public_key()),
    })
    .to_string();

    let req = alice.sign_request(
        "POST",
        "/devices",
        body.as_bytes(),
        ClientIdentity::now_ts(),
    );
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK, "got {:?}", res);

    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        body["device_id"].as_str().expect("hex"),
        alice.device_id_hex()
    );
    assert!(body["registered_at"].is_string());
}

#[tokio::test]
async fn register_is_idempotent() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xAB; 32]);

    let body = json!({
        "device_id": alice.device_id_hex(),
        "identity_pk": hex::encode(alice.public_key()),
    })
    .to_string();

    for _ in 0..3 {
        let req = alice.sign_request(
            "POST",
            "/devices",
            body.as_bytes(),
            ClientIdentity::now_ts(),
        );
        let res = harness.router.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(res.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn register_rejects_mismatched_device_id() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xAC; 32]);

    // Wrong device id (all zeros, not derived from pubkey).
    let body = json!({
        "device_id": "00000000000000000000000000000000",
        "identity_pk": hex::encode(alice.public_key()),
    })
    .to_string();

    // Sign with Alice's key but header device-id matches the wrong one so header-check fails too.
    // We still expect a 400 because header device-id must match body device-id AND body device-id
    // must be SHA-256(identity_pk)[..16]. Whichever check fires first, it's a 400.
    let req = Request::builder()
        .method("POST")
        .uri("/devices")
        .header("content-type", "application/json")
        .header("x-krone-device-id", "00000000000000000000000000000000")
        .header("x-krone-timestamp", ClientIdentity::now_ts().to_string())
        .header("x-krone-signature", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")
        .body(Body::from(body))
        .expect("build");

    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert!(
        res.status() == StatusCode::BAD_REQUEST || res.status() == StatusCode::UNAUTHORIZED,
        "unexpected status {}",
        res.status()
    );
}

#[tokio::test]
async fn register_rejects_expired_timestamp() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xAD; 32]);

    let body = json!({
        "device_id": alice.device_id_hex(),
        "identity_pk": hex::encode(alice.public_key()),
    })
    .to_string();

    // 10 minutes in the past exceeds the 120s window.
    let old_ts = ClientIdentity::now_ts() - 600;
    let req = alice.sign_request("POST", "/devices", body.as_bytes(), old_ts);
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_rejects_tampered_body() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xAE; 32]);

    let good_body = json!({
        "device_id": alice.device_id_hex(),
        "identity_pk": hex::encode(alice.public_key()),
    })
    .to_string();

    let req = alice.sign_request(
        "POST",
        "/devices",
        good_body.as_bytes(),
        ClientIdentity::now_ts(),
    );

    // Swap in a different (valid-shape) body after signing, keeping the original signature.
    let (parts, _) = req.into_parts();
    let tampered = json!({
        "device_id": alice.device_id_hex(),
        "identity_pk": hex::encode([0x00; 32]),
    })
    .to_string();
    let tampered_req = Request::from_parts(parts, Body::from(tampered));

    let res = harness
        .router
        .clone()
        .oneshot(tampered_req)
        .await
        .expect("oneshot");
    // Tampering may be caught at body-verification (400) or signature-verification (401).
    // Either way the request must be rejected, never accepted.
    assert!(
        res.status() == StatusCode::UNAUTHORIZED || res.status() == StatusCode::BAD_REQUEST,
        "expected 400 or 401, got {}",
        res.status()
    );
}

#[tokio::test]
async fn signed_request_rejects_tampered_signature() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xB0; 32]);

    // Register first.
    let body = json!({
        "device_id": alice.device_id_hex(),
        "identity_pk": hex::encode(alice.public_key()),
    })
    .to_string();
    let req = alice.sign_request(
        "POST",
        "/devices",
        body.as_bytes(),
        ClientIdentity::now_ts(),
    );
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    // Craft a DELETE with the right shape but flip one bit in the signature.
    let req = alice.sign_request("DELETE", "/devices/self", b"", ClientIdentity::now_ts());
    let (mut parts, body) = req.into_parts();
    // Replace the signature with a valid-looking but wrong one.
    let bogus_sig: Vec<u8> = vec![0xAA; 64];
    let b64 = base64::engine::general_purpose::STANDARD.encode(bogus_sig);
    parts
        .headers
        .insert("x-krone-signature", b64.parse().expect("header"));
    let tampered = Request::from_parts(parts, body);

    let res = harness
        .router
        .clone()
        .oneshot(tampered)
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_self_reaps_orphan_envelopes() {
    // When the only recipient of an envelope deregisters, the envelope must be deleted
    // along with its recipient row — otherwise it lingers in `envelopes` until TTL.
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xC0; 32]);
    let bob = ClientIdentity::from_seed([0xC1; 32]);

    let register = async |id: &ClientIdentity| {
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
        assert_eq!(res.status(), StatusCode::OK);
    };
    register(&alice).await;
    register(&bob).await;

    // Alice sends Bob an envelope. Bob is the only recipient.
    let env = json!({
        "envelope_id": ulid::Ulid::new().to_string(),
        "recipient_device_id": bob.device_id_hex(),
        "recipient_tag": hex::encode([0x22u8; 32]),
        "epoch": 1,
        "seq": 1,
        "nonce": hex::encode([0x33u8; 24]),
        "ciphertext": base64::engine::general_purpose::STANDARD.encode([0xAAu8; 16]),
        "content_signature": base64::engine::general_purpose::STANDARD.encode([0xBBu8; 64]),
    });
    let submit_body = json!({ "envelopes": [env] }).to_string();
    let req = alice.sign_request(
        "POST",
        "/envelopes",
        submit_body.as_bytes(),
        ClientIdentity::now_ts(),
    );
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    // Count envelopes directly in the DB before delete.
    let (before,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM envelopes")
        .fetch_one(&harness.db)
        .await
        .expect("count before");
    assert_eq!(before, 1);

    // Bob deregisters.
    let req = bob.sign_request("DELETE", "/devices/self", b"", ClientIdentity::now_ts());
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    // The envelope row must be gone — otherwise it would linger until TTL.
    let (after,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM envelopes")
        .fetch_one(&harness.db)
        .await
        .expect("count after");
    assert_eq!(after, 0, "expected the orphan envelope to be reaped");
}

#[tokio::test]
async fn delete_self_requires_registration_first() {
    let harness = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xAF; 32]);

    // Before registering, delete should be unauthorized (unknown device).
    let req = alice.sign_request("DELETE", "/devices/self", b"", ClientIdentity::now_ts());
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Register.
    let body = json!({
        "device_id": alice.device_id_hex(),
        "identity_pk": hex::encode(alice.public_key()),
    })
    .to_string();
    let req = alice.sign_request(
        "POST",
        "/devices",
        body.as_bytes(),
        ClientIdentity::now_ts(),
    );
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    // Now delete succeeds.
    let req = alice.sign_request("DELETE", "/devices/self", b"", ClientIdentity::now_ts());
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    // Subsequent delete is again unauthorized.
    let req = alice.sign_request("DELETE", "/devices/self", b"", ClientIdentity::now_ts());
    let res = harness.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
