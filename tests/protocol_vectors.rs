//! Reproduces every vector in `protocol/vectors/signing_vectors.json` and asserts
//! byte-for-byte equality against the recorded expectations. This is the parity
//! contract between this crate and any other krone-protocol implementation: if a
//! change to signing_input or response_signing_input makes these fail, the wire
//! format has shifted and the Android client will stop verifying.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

use krone_groups_server::crypto::{request_signing_input, response_signing_input};

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("protocol/vectors/signing_vectors.json")
}

fn load_vectors() -> Value {
    let raw =
        fs::read_to_string(vectors_path()).expect("read protocol/vectors/signing_vectors.json");
    serde_json::from_str(&raw).expect("parse signing_vectors.json")
}

fn signing_key_from_seed_hex(seed_hex: &str) -> SigningKey {
    let bytes = hex::decode(seed_hex).expect("seed hex");
    let arr: [u8; 32] = bytes.try_into().expect("seed is 32 bytes");
    SigningKey::from_bytes(&arr)
}

fn get_str<'a>(v: &'a Value, field: &str) -> &'a str {
    v.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {field}"))
}

fn get_i64(v: &Value, field: &str) -> i64 {
    v.get(field)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("missing integer field {field}"))
}

#[test]
fn format_version_matches() {
    let vectors = load_vectors();
    assert_eq!(
        vectors.get("format_version").and_then(Value::as_u64),
        Some(1),
        "unknown vector format version — this crate only understands v1",
    );
}

#[test]
fn clients_derive_expected_identities() {
    let vectors = load_vectors();
    let clients = vectors
        .get("clients")
        .and_then(Value::as_object)
        .expect("clients object");
    for (name, entry) in clients {
        let seed_hex = get_str(entry, "seed_hex");
        let expected_pk = get_str(entry, "public_key_hex");
        let expected_device_id = get_str(entry, "device_id_hex");

        let sk = signing_key_from_seed_hex(seed_hex);
        let pk = sk.verifying_key().to_bytes();
        let digest = Sha256::digest(pk);
        let device_id_hex = hex::encode(&digest[..16]);

        assert_eq!(hex::encode(pk), expected_pk, "{name} public_key_hex");
        assert_eq!(device_id_hex, expected_device_id, "{name} device_id_hex");
    }
}

#[test]
fn request_vectors_reproduce_bytewise() {
    let vectors = load_vectors();
    let clients = vectors
        .get("clients")
        .and_then(Value::as_object)
        .expect("clients object");

    let request_vectors = vectors
        .get("request_vectors")
        .and_then(Value::as_array)
        .expect("request_vectors array");

    assert!(!request_vectors.is_empty(), "no request vectors to check");

    for vec in request_vectors {
        let name = get_str(vec, "name");
        let signer_name = get_str(vec, "signer");
        let method = get_str(vec, "method");
        let path = get_str(vec, "path");
        let timestamp = get_i64(vec, "timestamp");
        let body_utf8 = get_str(vec, "body_utf8");
        let expected_body_sha = get_str(vec, "body_sha256_hex");
        let expected_input_hex = get_str(vec, "signing_input_hex");
        let expected_sig_b64 = get_str(vec, "signature_b64");

        let signer_entry = clients
            .get(signer_name)
            .unwrap_or_else(|| panic!("{name}: unknown signer {signer_name}"));
        let signer_seed = get_str(signer_entry, "seed_hex");
        let device_id_hex = get_str(signer_entry, "device_id_hex");

        let body = body_utf8.as_bytes();

        let body_sha_hex = hex::encode(Sha256::digest(body));
        assert_eq!(
            body_sha_hex, expected_body_sha,
            "{name}: body_sha256_hex mismatch",
        );

        let input = request_signing_input(timestamp, device_id_hex, method, path, body);
        assert_eq!(
            hex::encode(&input),
            expected_input_hex,
            "{name}: signing_input_hex mismatch",
        );

        let sk = signing_key_from_seed_hex(signer_seed);
        let sig = sk.sign(&input).to_bytes();
        assert_eq!(
            B64.encode(sig),
            expected_sig_b64,
            "{name}: signature_b64 mismatch",
        );
    }
}

#[test]
fn response_vectors_reproduce_bytewise() {
    let vectors = load_vectors();
    let server = vectors.get("server").expect("server object");
    let server_seed = get_str(server, "seed_hex");
    let expected_server_pk = get_str(server, "public_key_hex");

    let server_key = signing_key_from_seed_hex(server_seed);
    assert_eq!(
        hex::encode(server_key.verifying_key().to_bytes()),
        expected_server_pk,
        "server public_key_hex mismatch",
    );

    let response_vectors = vectors
        .get("response_vectors")
        .and_then(Value::as_array)
        .expect("response_vectors array");

    assert!(!response_vectors.is_empty(), "no response vectors to check");

    for vec in response_vectors {
        let name = get_str(vec, "name");
        let request_id = get_str(vec, "request_id");
        let status_code = u16::try_from(get_i64(vec, "status_code")).expect("u16 status");
        let body_utf8 = get_str(vec, "body_utf8");
        let expected_body_sha = get_str(vec, "body_sha256_hex");
        let expected_input_hex = get_str(vec, "signing_input_hex");
        let expected_sig_b64 = get_str(vec, "signature_b64");

        let body = body_utf8.as_bytes();

        assert_eq!(
            hex::encode(Sha256::digest(body)),
            expected_body_sha,
            "{name}: body_sha256_hex mismatch",
        );

        let input = response_signing_input(request_id, status_code, body);
        assert_eq!(
            hex::encode(&input),
            expected_input_hex,
            "{name}: signing_input_hex mismatch",
        );

        let sig = server_key.sign(&input).to_bytes();
        assert_eq!(
            B64.encode(sig),
            expected_sig_b64,
            "{name}: signature_b64 mismatch",
        );
    }
}
