//! Verifies the reaper deletes fully-ACK'd envelopes and anything past TTL.

use axum::http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use tower::ServiceExt;
use ulid::Ulid;

use krone_groups_server::db::queries;
use krone_groups_server::jobs::reaper;

mod common;

use common::signing::ClientIdentity;

fn base64_std(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn sample_envelope(recipient_hex: &str) -> (Ulid, serde_json::Value) {
    let envelope_id = Ulid::new();
    let v = json!({
        "envelope_id": envelope_id.to_string(),
        "recipient_device_id": recipient_hex,
        "recipient_tag": hex::encode([0x11u8; 32]),
        "epoch": 1,
        "seq": 7,
        "nonce": hex::encode([0xEFu8; 24]),
        "ciphertext": base64_std(&[0xABu8; 64]),
        "content_signature": base64_std(&[0xCDu8; 64]),
    });
    (envelope_id, v)
}

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
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn reaper_removes_fully_acked_envelopes() {
    let h = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xE1; 32]);
    let bob = ClientIdentity::from_seed([0xE2; 32]);
    register(&h, &alice).await;
    register(&h, &bob).await;

    // Alice sends 3 envelopes.
    let mut ids = Vec::new();
    for _ in 0..3 {
        let (id, env) = sample_envelope(&bob.device_id_hex());
        ids.push(id);
        let body = json!({ "envelopes": [env] }).to_string();
        let req = alice.sign_request(
            "POST",
            "/envelopes",
            body.as_bytes(),
            ClientIdentity::now_ts(),
        );
        let res = h.router.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(res.status(), StatusCode::OK);
    }

    let before = queries::count_pending(
        &h.db,
        &krone_groups_server::protocol::common::HexBytes(bob.device_id),
    )
    .await
    .expect("count");
    assert_eq!(before, 3);

    // Bob acks all three.
    let ack_body = json!({
        "envelope_ids": ids.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
    })
    .to_string();
    let req = bob.sign_request(
        "POST",
        "/envelopes/ack",
        ack_body.as_bytes(),
        ClientIdentity::now_ts(),
    );
    let res = h.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    // Now the reaper should delete the envelopes (all recipients acked).
    let deleted = reaper::reap_once(&h.state, OffsetDateTime::now_utc())
        .await
        .expect("reap");
    assert!(deleted >= 3, "expected >= 3 deleted, got {deleted}");

    let after = queries::count_pending(
        &h.db,
        &krone_groups_server::protocol::common::HexBytes(bob.device_id),
    )
    .await
    .expect("count");
    assert_eq!(after, 0);
}

#[tokio::test]
async fn reaper_removes_expired_envelopes() {
    let h = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xE3; 32]);
    let bob = ClientIdentity::from_seed([0xE4; 32]);
    register(&h, &alice).await;
    register(&h, &bob).await;

    let (_id, env) = sample_envelope(&bob.device_id_hex());
    let body = json!({ "envelopes": [env] }).to_string();
    let req = alice.sign_request(
        "POST",
        "/envelopes",
        body.as_bytes(),
        ClientIdentity::now_ts(),
    );
    let res = h.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    // Fast-forward the clock past TTL.
    let policy_ttl = h.state.cfg.policy.ttl_seconds as i64;
    let future = OffsetDateTime::now_utc() + TimeDuration::seconds(policy_ttl + 60);

    let deleted = reaper::reap_once(&h.state, future).await.expect("reap");
    assert!(deleted >= 1);

    // Bob's inbox is empty.
    let req = bob.sign_request("GET", "/envelopes/inbox", b"", ClientIdentity::now_ts());
    let res = h.router.clone().oneshot(req).await.expect("oneshot");
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let inbox: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert!(inbox["envelopes"].as_array().expect("arr").is_empty());
}
