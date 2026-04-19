//! Build the canonical byte sequences that go into Ed25519 sign/verify.
//! Format is fixed by `protocol/README.md`; changing it is a breaking protocol bump.

use sha2::{Digest, Sha256};

const REQ_TAG: &[u8] = b"krone-req-v1\n";
const RES_TAG: &[u8] = b"krone-res-v1\n";

pub fn request_signing_input(
    timestamp_secs: i64,
    device_id_hex: &str,
    method: &str,
    path_with_query: &str,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut buf = Vec::with_capacity(
        REQ_TAG.len() + 20 + device_id_hex.len() + method.len() + path_with_query.len() + 32 + 5,
    );
    buf.extend_from_slice(REQ_TAG);
    buf.extend_from_slice(timestamp_secs.to_string().as_bytes());
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

pub fn response_signing_input(request_id: &str, status_code: u16, body: &[u8]) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut buf = Vec::with_capacity(RES_TAG.len() + request_id.len() + 8 + 32 + 3);
    buf.extend_from_slice(RES_TAG);
    buf.extend_from_slice(request_id.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(status_code.to_string().as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(&body_hash);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_input_is_deterministic() {
        let a = request_signing_input(100, "abcd", "POST", "/devices", b"{}");
        let b = request_signing_input(100, "abcd", "POST", "/devices", b"{}");
        assert_eq!(a, b);
    }

    #[test]
    fn body_change_changes_hash_portion() {
        let a = request_signing_input(100, "abcd", "POST", "/devices", b"{}");
        let b = request_signing_input(100, "abcd", "POST", "/devices", b"{\"x\":1}");
        assert_ne!(a, b);
    }
}
