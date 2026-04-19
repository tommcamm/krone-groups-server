//! End-to-end tests that spawn the real krone-groups-server binary, speak HTTP
//! over a real TCP socket, and exercise the full middleware stack — including
//! `tower_governor`, which the in-process oneshot tests bypass via
//! `router_for_tests()`.
//!
//! Gated behind `#[ignore]` to keep `cargo test` fast. Run explicitly:
//!
//! ```text
//! cargo test --test e2e -- --ignored
//! ```
//!
//! Every test spawns its own child process in its own temp directory on an
//! OS-assigned port, so tests run in parallel without colliding.

#![allow(clippy::expect_used)]

mod common;

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use common::signing::{ClientIdentity, SignedHeaders};

const SERVER_SEED_HEX: &str = common::TEST_SERVER_SEED_HEX;

/// Pre-computed Ed25519 public key derived from `SERVER_SEED_HEX`. Mirrors the
/// deterministic server identity used by the oneshot harness so response
/// signatures can be verified without standing up a full `AppState`.
const SERVER_PK_HEX: &str = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

struct ServerGuard {
    child: Option<Child>,
    base_url: String,
    _tmp: tempfile::TempDir,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().expect("local_addr").port()
}

async fn spawn_server() -> ServerGuard {
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_url = format!("sqlite://{}/krone.sqlite?mode=rwc", tmp.path().display());

    let binary = env!("CARGO_BIN_EXE_krone-groups-server");
    let child = Command::new(binary)
        .env("KRONE_BIND", &bind)
        .env("KRONE_DATA_DIR", tmp.path())
        .env("KRONE_DATABASE_URL", &db_url)
        .env("KRONE_SERVER_SEED", SERVER_SEED_HEX)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server binary");

    let base_url = format!("http://{bind}");
    let mut guard = ServerGuard {
        child: Some(child),
        base_url: base_url.clone(),
        _tmp: tmp,
    };

    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(r) = client
            .get(format!("{base_url}/healthz"))
            .timeout(Duration::from_millis(250))
            .send()
            .await
            && r.status().is_success()
        {
            return guard;
        }
        if Instant::now() >= deadline {
            // Take the child before panicking so the Drop still cleans up.
            let mut c = guard
                .child
                .take()
                .expect("child present before readiness timeout");
            let _ = c.kill();
            let _ = c.wait();
            panic!("server at {base_url} did not become ready within 5s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn apply_signed(
    builder: reqwest::RequestBuilder,
    headers: &SignedHeaders,
) -> reqwest::RequestBuilder {
    builder
        .header("content-type", "application/json")
        .header("x-krone-device-id", &headers.device_id)
        .header("x-krone-timestamp", &headers.timestamp)
        .header("x-krone-signature", &headers.signature_b64)
}

async fn signed_request(
    client: &reqwest::Client,
    base_url: &str,
    identity: &ClientIdentity,
    method: &str,
    path: &str,
    body: &[u8],
    ts: i64,
) -> reqwest::Response {
    let headers = identity.sign_headers(method, path, body, ts);
    let url = format!("{base_url}{path}");
    let method_parsed: reqwest::Method = method.parse().expect("http method");
    let builder = client.request(method_parsed, url).body(body.to_vec());
    apply_signed(builder, &headers)
        .send()
        .await
        .expect("send signed request")
}

#[tokio::test]
#[ignore]
async fn healthz_over_real_tcp() {
    let server = spawn_server().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/healthz", server.base_url))
        .send()
        .await
        .expect("healthz");
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
#[ignore]
async fn server_info_response_signature_verifies() {
    let server = spawn_server().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/server-info", server.base_url))
        .send()
        .await
        .expect("server-info");
    assert_eq!(res.status(), StatusCode::OK);
    let status_code = res.status().as_u16();
    let request_id = res
        .headers()
        .get("x-request-id")
        .expect("x-request-id present")
        .to_str()
        .expect("ascii request id")
        .to_string();
    let signature_b64 = res
        .headers()
        .get("x-server-signature")
        .expect("x-server-signature present")
        .to_str()
        .expect("ascii signature")
        .to_string();
    let body_bytes = res.bytes().await.expect("body");

    // Rebuild the signing input exactly as the server does and verify.
    let body_hash = Sha256::digest(&body_bytes);
    let mut input = Vec::new();
    input.extend_from_slice(b"krone-res-v1\n");
    input.extend_from_slice(request_id.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(status_code.to_string().as_bytes());
    input.push(b'\n');
    input.extend_from_slice(&body_hash);

    let pk_bytes: [u8; 32] = hex::decode(SERVER_PK_HEX)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let vk = VerifyingKey::from_bytes(&pk_bytes).expect("valid pk");
    let sig_bytes = B64.decode(signature_b64).expect("base64 signature");
    let sig = Signature::from_slice(&sig_bytes).expect("valid signature bytes");
    vk.verify(&input, &sig).expect("server signature verifies");
}

#[tokio::test]
#[ignore]
async fn full_flow_register_submit_inbox_ack_over_tcp() {
    let server = spawn_server().await;
    let client = reqwest::Client::new();
    let alice = ClientIdentity::from_seed([0xA1; 32]);
    let bob = ClientIdentity::from_seed([0xB0; 32]);

    // Alice and Bob register.
    for id in [&alice, &bob] {
        let body = json!({
            "device_id": id.device_id_hex(),
            "identity_pk": hex::encode(id.public_key()),
        })
        .to_string();
        let res = signed_request(
            &client,
            &server.base_url,
            id,
            "POST",
            "/devices",
            body.as_bytes(),
            ClientIdentity::now_ts(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK, "register failed");
    }

    // Alice submits an envelope to Bob. Step timestamps to dodge the replay cache.
    let t0 = ClientIdentity::now_ts() + 5;
    let envelope_id = Ulid::new();
    let envelope = json!({
        "envelope_id": envelope_id.to_string(),
        "recipient_device_id": bob.device_id_hex(),
        "recipient_tag": hex::encode([0x11u8; 32]),
        "epoch": 1,
        "seq": 1,
        "nonce": hex::encode([0xEFu8; 24]),
        "ciphertext": B64.encode([0xABu8; 64]),
        "content_signature": B64.encode([0xCDu8; 64]),
    });
    let submit_body = json!({ "envelopes": [envelope] }).to_string();
    let res = signed_request(
        &client,
        &server.base_url,
        &alice,
        "POST",
        "/envelopes",
        submit_body.as_bytes(),
        t0,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let submit: serde_json::Value = res.json().await.expect("submit json");
    assert_eq!(
        submit["accepted"][0].as_str().expect("ulid"),
        envelope_id.to_string()
    );

    // Bob reads, acks, re-reads empty.
    let res = signed_request(
        &client,
        &server.base_url,
        &bob,
        "GET",
        "/envelopes/inbox",
        b"",
        t0 + 1,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let inbox: serde_json::Value = res.json().await.expect("inbox json");
    let envs = inbox["envelopes"].as_array().expect("envelopes");
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0]["envelope_id"], envelope_id.to_string());

    let ack_body = json!({ "envelope_ids": [envelope_id.to_string()] }).to_string();
    let res = signed_request(
        &client,
        &server.base_url,
        &bob,
        "POST",
        "/envelopes/ack",
        ack_body.as_bytes(),
        t0 + 2,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let ack: serde_json::Value = res.json().await.expect("ack json");
    assert_eq!(ack["acknowledged"].as_u64(), Some(1));

    let res = signed_request(
        &client,
        &server.base_url,
        &bob,
        "GET",
        "/envelopes/inbox",
        b"",
        t0 + 3,
    )
    .await;
    let inbox: serde_json::Value = res.json().await.expect("inbox json");
    assert!(
        inbox["envelopes"].as_array().expect("array").is_empty(),
        "inbox should be empty after ack",
    );
}

#[tokio::test]
#[ignore]
async fn governor_returns_429_on_burst_over_threshold() {
    // tower_governor is configured for 60-burst + 1/s refill and keys on
    // client SocketAddr. The oneshot test harness skips this layer entirely,
    // so this e2e test is the only regression guard for it.
    let server = spawn_server().await;
    let client = reqwest::Client::new();

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..120 {
        let client = client.clone();
        let url = format!("{}/healthz", server.base_url);
        set.spawn(async move {
            client
                .get(url)
                .send()
                .await
                .map(|r| r.status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        });
    }

    let mut ok = 0u32;
    let mut too_many = 0u32;
    let mut other = 0u32;
    while let Some(joined) = set.join_next().await {
        let status = joined.expect("join");
        match status {
            StatusCode::OK => ok += 1,
            StatusCode::TOO_MANY_REQUESTS => too_many += 1,
            _ => other += 1,
        }
    }

    // `burst_size(60)` with a token-bucket governor typically yields ok counts in
    // the 55–65 range (refill ticks can slip in during the burst), with the rest
    // as 429s. The exact boundary isn't the point — the point is that the layer
    // fires at all, which the oneshot harness can't verify.
    assert!(
        too_many > 0,
        "governor never returned 429 in a 120-burst (ok={ok}, 429={too_many}, other={other})",
    );
    assert!(
        ok >= 40,
        "governor let suspiciously few requests through the burst (ok={ok}, 429={too_many})",
    );
    assert_eq!(other, 0, "unexpected non-200/429 responses: {other}");
}
