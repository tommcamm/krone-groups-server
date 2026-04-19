use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ulid::Ulid;

// --- Fixed-length hex-encoded byte arrays ---

/// N bytes, serialized as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HexBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> HexBytes<N> {
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
    pub fn into_inner(self) -> [u8; N] {
        self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl<const N: usize> fmt::Debug for HexBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HexBytes<{}>({})", N, self.to_hex())
    }
}

impl<const N: usize> fmt::Display for HexBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl<const N: usize> FromStr for HexBytes<N> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != N * 2 {
            return Err(format!("expected {} hex chars, got {}", N * 2, s.len()));
        }
        if !s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
            return Err("expected lowercase hex".to_string());
        }
        let v = hex::decode(s).map_err(|e| e.to_string())?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(&v);
        Ok(HexBytes(arr))
    }
}

impl<const N: usize> Serialize for HexBytes<N> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_hex())
    }
}

impl<'de, const N: usize> Deserialize<'de> for HexBytes<N> {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        HexBytes::from_str(&s).map_err(serde::de::Error::custom)
    }
}

pub type DeviceId = HexBytes<16>;
pub type RecipientTag = HexBytes<32>;
pub type Nonce = HexBytes<24>;
pub type IdentityPk = HexBytes<32>;
pub type Signature = HexBytes<64>;

// --- Variable-length base64 bytes (standard, padded) ---

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Base64Bytes(pub Vec<u8>);

impl Base64Bytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn to_b64(&self) -> String {
        B64.encode(&self.0)
    }
}

impl fmt::Debug for Base64Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Base64Bytes({} bytes)", self.0.len())
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_b64())
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        B64.decode(s.as_bytes())
            .map(Base64Bytes)
            .map_err(serde::de::Error::custom)
    }
}

// --- ULID newtype (delegates serialization to ulid crate) ---

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnvelopeId(pub Ulid);

impl EnvelopeId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }
    pub fn as_bytes(&self) -> [u8; 16] {
        self.0.to_bytes()
    }
}

impl Default for EnvelopeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EnvelopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for EnvelopeId {
    type Err = ulid::DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ulid::from_str(s).map(EnvelopeId)
    }
}
