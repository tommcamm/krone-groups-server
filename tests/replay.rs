//! Anti-replay cache (design-spec §11 defense-in-depth): the same (device_id, signature)
//! pair is rejected after its first sighting. Ed25519 is deterministic so re-signing the
//! same (ts, body) pair produces the same signature — exactly what the cache catches.

use axum::http::StatusCode;
use base64::Engine;
use serde_json::json;
use time::{Duration as TimeDuration, OffsetDateTime};
use tower::ServiceExt;
use ulid::Ulid;

mod common;

use common::signing::ClientIdentity;
use krone_groups_server::db::queries;
use krone_groups_server::jobs::reaper;
use krone_groups_server::protocol::common::HexBytes;

fn base64_std(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

async fn register(h: &common::TestHarness, id: &ClientIdentity, ts: i64) -> StatusCode {
    let body = json!({
        "device_id": id.device_id_hex(),
        "identity_pk": hex::encode(id.public_key()),
    })
    .to_string();
    let req = id.sign_request("POST", "/devices", body.as_bytes(), ts);
    h.router
        .clone()
        .oneshot(req)
        .await
        .expect("oneshot")
        .status()
}

#[tokio::test]
async fn replay_of_signed_registration_is_rejected() {
    let h = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xD0; 32]);
    let ts = ClientIdentity::now_ts();

    // First send succeeds and caches the signature.
    assert_eq!(register(&h, &alice, ts).await, StatusCode::OK);

    // Identical (ts, body) reproduces the same signature → replay.
    assert_eq!(register(&h, &alice, ts).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replay_of_signed_envelope_submit_is_rejected() {
    let h = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xD1; 32]);
    let bob = ClientIdentity::from_seed([0xD2; 32]);
    assert_eq!(
        register(&h, &alice, ClientIdentity::now_ts()).await,
        StatusCode::OK
    );
    assert_eq!(
        register(&h, &bob, ClientIdentity::now_ts() + 1).await,
        StatusCode::OK
    );

    let env = json!({
        "envelope_id": Ulid::new().to_string(),
        "recipient_device_id": bob.device_id_hex(),
        "recipient_tag": hex::encode([0x22u8; 32]),
        "epoch": 1,
        "seq": 1,
        "nonce": hex::encode([0x33u8; 24]),
        "ciphertext": base64_std(&[0xAAu8; 16]),
        "content_signature": base64_std(&[0xBBu8; 64]),
    });
    let submit_body = json!({ "envelopes": [env] }).to_string();
    let submit_ts = ClientIdentity::now_ts() + 2;

    let req = alice.sign_request("POST", "/envelopes", submit_body.as_bytes(), submit_ts);
    let res = h.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    // Replay the exact same signed submit.
    let req = alice.sign_request("POST", "/envelopes", submit_body.as_bytes(), submit_ts);
    let res = h.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replay_of_signed_inbox_read_is_rejected() {
    // Inbox is a GET with empty body; its signature still covers (method, path, ts, device_id)
    // so two identical reads produce the same signature and the second must be rejected.
    let h = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xD3; 32]);
    assert_eq!(
        register(&h, &alice, ClientIdentity::now_ts()).await,
        StatusCode::OK
    );

    let read_ts = ClientIdentity::now_ts() + 1;
    let req = alice.sign_request("GET", "/envelopes/inbox", b"", read_ts);
    let res = h.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    let req = alice.sign_request("GET", "/envelopes/inbox", b"", read_ts);
    let res = h.router.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn distinct_requests_from_same_device_succeed() {
    // The cache must not block legitimate traffic: the same device issuing different
    // signed requests (different timestamps) always gets through.
    let h = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xD4; 32]);
    let base = ClientIdentity::now_ts();
    assert_eq!(register(&h, &alice, base).await, StatusCode::OK);

    for i in 1..=5 {
        let req = alice.sign_request("GET", "/envelopes/inbox", b"", base + i);
        let res = h.router.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "iteration {i} should have succeeded"
        );
    }
}

#[tokio::test]
async fn replay_is_rejected_after_signature_is_verified() {
    // A bad signature must fail with 401 BEFORE the replay cache is consulted —
    // otherwise an attacker could poison the cache with forged signatures.
    // We observe this indirectly: a valid-but-wrong signature is rejected once, and
    // a subsequent correctly-signed request with the same (ts, body) still succeeds.
    let h = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xD5; 32]);
    assert_eq!(
        register(&h, &alice, ClientIdentity::now_ts()).await,
        StatusCode::OK
    );

    let ts = ClientIdentity::now_ts() + 1;
    let good = alice.sign_request("GET", "/envelopes/inbox", b"", ts);

    // Flip the signature to a bogus one.
    let (mut parts, body) = good.into_parts();
    let bogus = base64::engine::general_purpose::STANDARD.encode([0xAAu8; 64]);
    parts
        .headers
        .insert("x-krone-signature", bogus.parse().expect("header"));
    let bad = axum::http::Request::from_parts(parts, body);
    let res = h.router.clone().oneshot(bad).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "bogus sig must 401");

    // Now re-sign properly with the same (ts, body). If the bogus path had cached the
    // signature keyed off the device, this would be rejected. It must succeed.
    let good = alice.sign_request("GET", "/envelopes/inbox", b"", ts);
    let res = h.router.clone().oneshot(good).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn reaper_prunes_expired_seen_signatures() {
    let h = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xD6; 32]);
    assert_eq!(
        register(&h, &alice, ClientIdentity::now_ts()).await,
        StatusCode::OK
    );

    // Confirm a row was cached.
    let (before,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM seen_signatures")
        .fetch_one(&h.db)
        .await
        .expect("count");
    assert!(before >= 1);

    // Fast-forward the reaper past the retention window.
    let skew = h.state.cfg.policy.clock_skew_seconds;
    let future = OffsetDateTime::now_utc() + TimeDuration::seconds(skew * 3 + 600);
    let _ = reaper::reap_once(&h.state, future).await.expect("reap");

    let (after,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM seen_signatures")
        .fetch_one(&h.db)
        .await
        .expect("count");
    assert_eq!(after, 0, "expired rows should be pruned");
}

#[tokio::test]
async fn record_signature_seen_is_idempotent_on_collision() {
    // Direct DB-level test: the first insert reports new (true), the second (same key)
    // reports not new (false). This is what the replay check keys off.
    let h = common::build_harness().await;
    let alice = ClientIdentity::from_seed([0xD7; 32]);
    let sig = [0x99u8; 64];
    let now = OffsetDateTime::now_utc();
    let device_id = HexBytes(alice.device_id);

    let first = queries::record_signature_seen(&h.db, &device_id, &sig, now)
        .await
        .expect("record1");
    assert!(first, "first sighting should report new");

    let second = queries::record_signature_seen(&h.db, &device_id, &sig, now)
        .await
        .expect("record2");
    assert!(!second, "duplicate should report replay");
}
