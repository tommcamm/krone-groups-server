use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::common::{Base64Bytes, DeviceId, EnvelopeId, Nonce, RecipientTag};

/// Inbound envelope as submitted by the sender (no server-assigned fields yet).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub envelope_id: EnvelopeId,
    pub recipient_device_id: DeviceId,
    pub recipient_tag: RecipientTag,
    pub epoch: u64,
    pub seq: u64,
    pub nonce: Nonce,
    pub ciphertext: Base64Bytes,
    pub content_signature: Base64Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeSubmitRequest {
    pub envelopes: Vec<Envelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeSubmitResponse {
    pub accepted: Vec<EnvelopeId>,
}

/// Envelope as returned by `/envelopes/inbox` — has the sender-from-auth plus `created_at` attached.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxEnvelope {
    pub envelope_id: EnvelopeId,
    pub sender_device_id: DeviceId,
    pub recipient_device_id: DeviceId,
    pub recipient_tag: RecipientTag,
    pub epoch: u64,
    pub seq: u64,
    pub nonce: Nonce,
    pub ciphertext: Base64Bytes,
    pub content_signature: Base64Bytes,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxResponse {
    pub envelopes: Vec<InboxEnvelope>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRequest {
    pub envelope_ids: Vec<EnvelopeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckResponse {
    pub acknowledged: u64,
}
