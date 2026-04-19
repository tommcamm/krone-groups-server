//! Generates canonical signing vectors for krone-protocol.
//!
//! Run: `cargo run --example gen_vectors > protocol/vectors/signing_vectors.json`
//!
//! Seeds are fixed so output is deterministic. Any implementation of the
//! `krone-req-v1` / `krone-res-v1` signing formats must reproduce these bytes.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use krone_groups_server::crypto::{request_signing_input, response_signing_input};

const SERVER_SEED: [u8; 32] = [0x11; 32];
const ALICE_SEED: [u8; 32] = [0x02; 32];
const BOB_SEED: [u8; 32] = [0x03; 32];

struct Identity {
    name: &'static str,
    signing_key: SigningKey,
    device_id_hex: String,
}

impl Identity {
    fn new(name: &'static str, seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pk = signing_key.verifying_key().to_bytes();
        let digest = Sha256::digest(pk);
        let device_id_hex = hex::encode(&digest[..16]);
        Self {
            name,
            signing_key,
            device_id_hex,
        }
    }
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).expect("json string")
}

fn req_vector(
    name: &str,
    signer: &Identity,
    method: &str,
    path: &str,
    timestamp: i64,
    body: &[u8],
) -> String {
    let body_hash = Sha256::digest(body);
    let input = request_signing_input(timestamp, &signer.device_id_hex, method, path, body);
    let sig = signer.signing_key.sign(&input).to_bytes();
    let body_utf8 = std::str::from_utf8(body).expect("test bodies are utf-8 by construction");
    format!(
        concat!(
            "    {{\n",
            "      \"name\": \"{name}\",\n",
            "      \"signer\": \"{signer}\",\n",
            "      \"method\": \"{method}\",\n",
            "      \"path\": {path_json},\n",
            "      \"timestamp\": {ts},\n",
            "      \"body_utf8\": {body_json},\n",
            "      \"body_sha256_hex\": \"{body_sha}\",\n",
            "      \"signing_input_hex\": \"{input_hex}\",\n",
            "      \"signature_b64\": \"{sig_b64}\"\n",
            "    }}",
        ),
        name = name,
        signer = signer.name,
        method = method,
        path_json = json_string(path),
        ts = timestamp,
        body_json = json_string(body_utf8),
        body_sha = hex::encode(body_hash),
        input_hex = hex::encode(&input),
        sig_b64 = B64.encode(sig),
    )
}

fn res_vector(
    name: &str,
    server_key: &SigningKey,
    request_id: &str,
    status_code: u16,
    body: &[u8],
) -> String {
    let body_hash = Sha256::digest(body);
    let input = response_signing_input(request_id, status_code, body);
    let sig = server_key.sign(&input).to_bytes();
    let body_utf8 = std::str::from_utf8(body).expect("test bodies are utf-8 by construction");
    format!(
        concat!(
            "    {{\n",
            "      \"name\": \"{name}\",\n",
            "      \"request_id\": \"{rid}\",\n",
            "      \"status_code\": {code},\n",
            "      \"body_utf8\": {body_json},\n",
            "      \"body_sha256_hex\": \"{body_sha}\",\n",
            "      \"signing_input_hex\": \"{input_hex}\",\n",
            "      \"signature_b64\": \"{sig_b64}\"\n",
            "    }}",
        ),
        name = name,
        rid = request_id,
        code = status_code,
        body_json = json_string(body_utf8),
        body_sha = hex::encode(body_hash),
        input_hex = hex::encode(&input),
        sig_b64 = B64.encode(sig),
    )
}

fn main() {
    let server = SigningKey::from_bytes(&SERVER_SEED);
    let server_pk = server.verifying_key().to_bytes();

    let alice = Identity::new("alice", ALICE_SEED);
    let bob = Identity::new("bob", BOB_SEED);

    let alice_pk = alice.signing_key.verifying_key().to_bytes();
    let bob_pk = bob.signing_key.verifying_key().to_bytes();

    let reg_body_alice = format!(
        "{{\"device_id\":\"{}\",\"identity_pk\":\"{}\"}}",
        alice.device_id_hex,
        hex::encode(alice_pk),
    );

    let envelope_body = concat!(
        "{\"envelopes\":[{",
        "\"envelope_id\":\"01HZY0000000000000000ENVEL\",",
        "\"recipient_device_id\":\"",
    )
    .to_string()
        + &bob.device_id_hex
        + concat!(
            "\",",
            "\"recipient_tag\":\"",
            "7e6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e",
            "\",",
            "\"epoch\":0,",
            "\"seq\":1,",
            "\"nonce\":\"000102030405060708090a0b0c0d0e0f1011121314151617\",",
            "\"ciphertext\":\"Y2lwaGVydGV4dC1zdHVi\",",
            "\"content_signature\":\"c2lnbmF0dXJlLXN0dWI=\"",
            "}]}",
        );

    let request_vectors = [
        req_vector(
            "post_devices_registration_alice",
            &alice,
            "POST",
            "/devices",
            1_750_000_000,
            reg_body_alice.as_bytes(),
        ),
        req_vector(
            "get_inbox_empty_body",
            &alice,
            "GET",
            "/envelopes/inbox?since=0&limit=100",
            1_750_000_050,
            b"",
        ),
        req_vector(
            "post_envelopes_single_recipient",
            &alice,
            "POST",
            "/envelopes",
            1_750_000_100,
            envelope_body.as_bytes(),
        ),
        req_vector(
            "delete_self_bob",
            &bob,
            "DELETE",
            "/devices/self",
            1_750_000_200,
            b"",
        ),
    ];

    let response_vectors = [
        res_vector(
            "health_ok",
            &server,
            "01HZY0000000000000000RID001",
            200,
            b"{\"status\":\"ok\"}",
        ),
        res_vector(
            "envelope_submit_ok",
            &server,
            "01HZY0000000000000000RID002",
            200,
            b"{\"accepted\":1,\"duplicates\":0}",
        ),
        res_vector(
            "error_401_bad_signature",
            &server,
            "01HZY0000000000000000RID003",
            401,
            b"{\"error\":\"unauthorized\",\"message\":\"invalid signature\"}",
        ),
    ];

    let description = "Canonical Ed25519 signing vectors for krone-req-v1 (request) and \
krone-res-v1 (response) formats. Every krone-protocol implementation MUST reproduce \
body_sha256_hex, signing_input_hex, and signature_b64 byte-for-byte from the given \
inputs. Regenerate via: cargo run --example gen_vectors in krone-groups-server.";

    println!("{{");
    println!("  \"format_version\": 1,");
    println!("  \"description\": {},", json_string(description));
    println!("  \"generator\": \"krone-groups-server examples/gen_vectors.rs\",");
    println!("  \"server\": {{");
    println!("    \"seed_hex\": \"{}\",", hex::encode(SERVER_SEED));
    println!("    \"public_key_hex\": \"{}\"", hex::encode(server_pk));
    println!("  }},");
    println!("  \"clients\": {{");
    println!("    \"alice\": {{");
    println!("      \"seed_hex\": \"{}\",", hex::encode(ALICE_SEED));
    println!("      \"public_key_hex\": \"{}\",", hex::encode(alice_pk));
    println!("      \"device_id_hex\": \"{}\"", alice.device_id_hex);
    println!("    }},");
    println!("    \"bob\": {{");
    println!("      \"seed_hex\": \"{}\",", hex::encode(BOB_SEED));
    println!("      \"public_key_hex\": \"{}\",", hex::encode(bob_pk));
    println!("      \"device_id_hex\": \"{}\"", bob.device_id_hex);
    println!("    }}");
    println!("  }},");
    println!("  \"request_vectors\": [");
    println!("{}", request_vectors.join(",\n"));
    println!("  ],");
    println!("  \"response_vectors\": [");
    println!("{}", response_vectors.join(",\n"));
    println!("  ]");
    println!("}}");
}
