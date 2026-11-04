//! Base64 helpers and a serde adapter so byte fields travel as strings in JSON.

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::CryptoError;

pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode(text: &str) -> crate::Result<Vec<u8>> {
    STANDARD.decode(text).map_err(|e| CryptoError::Encoding(format!("base64: {e}")))
}

pub fn decode_array<const N: usize>(text: &str, label: &str) -> crate::Result<[u8; N]> {
    let bytes = decode(text)?;
    bytes.try_into().map_err(|_| CryptoError::Encoding(format!("{label} must be {N} bytes")))
}

/// `#[serde(with = "base64_bytes")]` for `Vec<u8>` fields.
pub mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        super::encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        super::decode(&text).map_err(serde::de::Error::custom)
    }
}
