//! Validates that our Rust wire types serialize into JSON that conforms to the
//! schemas in `protocol/schemas/`. Keeps Rust types and the contract in sync.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use jsonschema::Resource;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

use krone_groups_server::protocol::common::{
    Base64Bytes, DeviceId, EnvelopeId, HexBytes, IdentityPk, Nonce, RecipientTag, Signature,
};
use krone_groups_server::protocol::device::{
    DeviceRegistrationRequest, DeviceRegistrationResponse,
};
use krone_groups_server::protocol::envelope::{
    AckRequest, AckResponse, Envelope, EnvelopeSubmitRequest, EnvelopeSubmitResponse,
    InboxEnvelope, InboxResponse,
};
use krone_groups_server::protocol::error::{ErrorBody, ErrorResponse};
use krone_groups_server::protocol::server_info::{Policy, ServerInfoResponse};

fn schemas_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("protocol/schemas")
}

fn load_schema(name: &str) -> (Value, Vec<(String, Value)>) {
    let dir = schemas_dir();
    let path = dir.join(name);
    let main: Value = serde_json::from_str(&fs::read_to_string(&path).expect("read schema"))
        .expect("parse schema");

    // Load every other .json sibling so $ref resolution works.
    let mut extras = Vec::new();
    for entry in fs::read_dir(&dir).expect("readdir schemas") {
        let entry = entry.expect("entry");
        let fname = entry.file_name().into_string().expect("utf8 name");
        if fname == name || !fname.ends_with(".json") {
            continue;
        }
        let sibling: Value =
            serde_json::from_str(&fs::read_to_string(entry.path()).expect("read sibling"))
                .expect("parse sibling");
        extras.push((fname, sibling));
    }
    (main, extras)
}

fn compile(name: &str) -> jsonschema::Validator {
    let (schema, extras) = load_schema(name);
    let mut options = jsonschema::options();
    for (fname, doc) in extras {
        let uri = format!("https://krone.app/protocol/1/{fname}");
        options = options.with_resource(uri, Resource::from_contents(doc).expect("resource"));
    }
    options.build(&schema).expect("build schema")
}

fn assert_valid(validator: &jsonschema::Validator, sample: &Value) {
    let errors: Vec<String> = validator
        .iter_errors(sample)
        .map(|e| format!("{e} at {}", e.instance_path))
        .collect();
    assert!(
        errors.is_empty(),
        "schema errors: {errors:#?}\nsample: {sample:#}"
    );
}

fn hex_n<const N: usize>(b: u8) -> HexBytes<N> {
    HexBytes([b; N])
}

fn sample_device_id() -> DeviceId {
    hex_n::<16>(0xA1)
}
fn sample_other_device_id() -> DeviceId {
    hex_n::<16>(0xB2)
}
fn sample_identity_pk() -> IdentityPk {
    hex_n::<32>(0x11)
}
fn sample_recipient_tag() -> RecipientTag {
    hex_n::<32>(0xC3)
}
fn sample_nonce() -> Nonce {
    hex_n::<24>(0x77)
}
fn sample_content_sig() -> Signature {
    hex_n::<64>(0x42)
}

#[test]
fn server_info_response_conforms() {
    let v = compile("server_info_response.schema.json");
    let sample = ServerInfoResponse {
        protocol_version: "1.0.0".into(),
        server_version: "krone-groups-server/test".into(),
        server_pk: sample_identity_pk(),
        policy: Policy {
            ttl_seconds: 2_592_000,
            max_envelope_bytes: 65_536,
            max_inbox_per_device: 10_000,
            max_envelopes_per_device_per_hour: 600,
            clock_skew_seconds: 120,
        },
    };
    assert_valid(&v, &serde_json::to_value(&sample).expect("to_value"));
}

#[test]
fn device_registration_request_conforms() {
    let v = compile("device_registration_request.schema.json");
    let sample = DeviceRegistrationRequest {
        device_id: sample_device_id(),
        identity_pk: sample_identity_pk(),
    };
    assert_valid(&v, &serde_json::to_value(&sample).expect("to_value"));
}

#[test]
fn device_registration_response_conforms() {
    let v = compile("device_registration_response.schema.json");
    let sample = DeviceRegistrationResponse {
        device_id: sample_device_id(),
        registered_at: time::OffsetDateTime::from_unix_timestamp(1_750_000_000).expect("timestamp"),
    };
    assert_valid(&v, &serde_json::to_value(&sample).expect("to_value"));
}

#[test]
fn envelope_submit_request_conforms() {
    let v = compile("envelope_submit_request.schema.json");
    let env = Envelope {
        envelope_id: EnvelopeId::new(),
        recipient_device_id: sample_other_device_id(),
        recipient_tag: sample_recipient_tag(),
        epoch: 0,
        seq: 1,
        nonce: sample_nonce(),
        ciphertext: Base64Bytes::new(vec![0xAA, 0xBB, 0xCC]),
        content_signature: Base64Bytes::new(sample_content_sig().into_inner().to_vec()),
    };
    let req = EnvelopeSubmitRequest {
        envelopes: vec![env],
    };
    assert_valid(&v, &serde_json::to_value(&req).expect("to_value"));
}

#[test]
fn envelope_submit_response_conforms() {
    let v = compile("envelope_submit_response.schema.json");
    let resp = EnvelopeSubmitResponse {
        accepted: vec![EnvelopeId::new()],
    };
    assert_valid(&v, &serde_json::to_value(&resp).expect("to_value"));
}

#[test]
fn inbox_response_conforms() {
    let v = compile("inbox_response.schema.json");
    let env = InboxEnvelope {
        envelope_id: EnvelopeId::new(),
        sender_device_id: sample_device_id(),
        recipient_device_id: sample_other_device_id(),
        recipient_tag: sample_recipient_tag(),
        epoch: 2,
        seq: 5,
        nonce: sample_nonce(),
        ciphertext: Base64Bytes::new(B64.decode("q83v").expect("b64 sample")),
        content_signature: Base64Bytes::new(vec![1u8; 64]),
        created_at: time::OffsetDateTime::from_unix_timestamp(1_750_000_000).expect("ts"),
    };
    let resp = InboxResponse {
        envelopes: vec![env],
        next_cursor: Some("c_1".into()),
    };
    assert_valid(&v, &serde_json::to_value(&resp).expect("to_value"));
}

#[test]
fn ack_request_conforms() {
    let v = compile("ack_request.schema.json");
    let req = AckRequest {
        envelope_ids: vec![EnvelopeId::new(), EnvelopeId::new()],
    };
    assert_valid(&v, &serde_json::to_value(&req).expect("to_value"));
}

#[test]
fn ack_response_conforms() {
    let v = compile("ack_response.schema.json");
    let resp = AckResponse { acknowledged: 3 };
    assert_valid(&v, &serde_json::to_value(&resp).expect("to_value"));
}

#[test]
fn error_response_conforms() {
    let v = compile("error_response.schema.json");
    let resp = ErrorResponse {
        error: ErrorBody {
            code: "unauthorized".into(),
            message: "bad signature".into(),
        },
    };
    assert_valid(&v, &serde_json::to_value(&resp).expect("to_value"));
}

#[test]
fn schemas_directory_exists() {
    let dir = schemas_dir();
    assert!(
        dir.exists(),
        "expected {} to exist — did you run `git submodule update --init`?",
        dir.display()
    );
    assert!(Path::new(&dir.join("common.schema.json")).exists());
}
