//! Wire-format types. These mirror the JSON Schemas in the `krone-protocol` submodule
//! at `protocol/schemas/`. Keep them in sync; `tests/protocol_schema.rs` validates that
//! serialized samples conform to the schemas.

pub mod common;
pub mod device;
pub mod envelope;
pub mod error;
pub mod server_info;

pub use common::{Base64Bytes, DeviceId, EnvelopeId, HexBytes, Nonce, RecipientTag, Signature};
