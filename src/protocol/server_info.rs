use serde::{Deserialize, Serialize};

use super::common::IdentityPk;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfoResponse {
    pub protocol_version: String,
    pub server_version: String,
    pub server_pk: IdentityPk,
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub ttl_seconds: u64,
    pub max_envelope_bytes: u64,
    pub max_inbox_per_device: u32,
    pub max_envelopes_per_device_per_hour: u32,
    pub clock_skew_seconds: i64,
}
