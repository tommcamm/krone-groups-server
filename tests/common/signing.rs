//! Test helper that signs requests the way a real client would.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{HeaderValue, Request};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

pub struct ClientIdentity {
    pub signing_key: SigningKey,
    pub device_id: [u8; 16],
}

pub struct SignedHeaders {
    pub device_id: String,
    pub timestamp: String,
    pub signature_b64: String,
}

impl ClientIdentity {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pk = signing_key.verifying_key().to_bytes();
        let digest = Sha256::digest(pk);
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&digest[..16]);
        Self {
            signing_key,
            device_id,
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn device_id_hex(&self) -> String {
        hex::encode(self.device_id)
    }

    pub fn sign_headers(
        &self,
        method: &str,
        path_with_query: &str,
        body: &[u8],
        timestamp: i64,
    ) -> SignedHeaders {
        let input = build_signing_input(
            timestamp,
            &self.device_id_hex(),
            method,
            path_with_query,
            body,
        );
        let sig = self.signing_key.sign(&input).to_bytes();
        SignedHeaders {
            device_id: self.device_id_hex(),
            timestamp: timestamp.to_string(),
            signature_b64: B64.encode(sig),
        }
    }

    pub fn sign_request(
        &self,
        method: &str,
        path_with_query: &str,
        body: &[u8],
        timestamp: i64,
    ) -> Request<Body> {
        let h = self.sign_headers(method, path_with_query, body, timestamp);
        Request::builder()
            .method(method)
            .uri(path_with_query)
            .header("content-type", "application/json")
            .header(
                "x-krone-device-id",
                HeaderValue::from_str(&h.device_id).expect("ascii"),
            )
            .header(
                "x-krone-timestamp",
                HeaderValue::from_str(&h.timestamp).expect("ascii"),
            )
            .header(
                "x-krone-signature",
                HeaderValue::from_str(&h.signature_b64).expect("ascii"),
            )
            .body(Body::from(body.to_vec()))
            .expect("build request")
    }

    pub fn now_ts() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }
}

#[allow(dead_code)]
fn build_signing_input(
    timestamp: i64,
    device_id_hex: &str,
    method: &str,
    path_with_query: &str,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut buf = Vec::new();
    buf.extend_from_slice(b"krone-req-v1\n");
    buf.extend_from_slice(timestamp.to_string().as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(device_id_hex.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(method.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(path_with_query.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(&body_hash);
    buf
}
