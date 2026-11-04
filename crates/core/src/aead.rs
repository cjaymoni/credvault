//! AES-256-GCM with a random 96-bit nonce.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::encoding::base64_bytes;
use crate::{CryptoError, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Ciphertext plus the nonce it was produced with. Deserialising enforces the
/// nonce length, so a `Sealed` built from JSON is always structurally valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "nonce_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Like `base64_bytes`, but rejects anything that is not exactly `NONCE_LEN` bytes.
mod nonce_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::NONCE_LEN;
    use crate::encoding;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&encoding::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = encoding::decode(&text).map_err(serde::de::Error::custom)?;
        if bytes.len() != NONCE_LEN {
            return Err(serde::de::Error::custom(format!("nonce must be {NONCE_LEN} bytes")));
        }
        Ok(bytes)
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

/// Encrypt `plaintext`; `aad` is authenticated but not encrypted and must be
/// supplied again to decrypt.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Sealed {
    let nonce = random_bytes::<NONCE_LEN>();
    let cipher = Aes256Gcm::new(key.into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("AES-GCM encryption cannot fail with valid key and nonce sizes");
    Sealed { nonce: nonce.to_vec(), ciphertext }
}

pub fn decrypt(key: &[u8; KEY_LEN], sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>> {
    // Fields are public, so re-check here even though deserialisation already did.
    if sealed.nonce.len() != NONCE_LEN {
        return Err(CryptoError::Encoding(format!("nonce must be {NONCE_LEN} bytes")));
    }
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ciphertext, aad })
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_aad() {
        let key = random_bytes::<KEY_LEN>();
        let sealed = encrypt(&key, b"hello", b"context");
        assert_eq!(decrypt(&key, &sealed, b"context").unwrap(), b"hello");
    }

    #[test]
    fn wrong_key_or_aad_or_tamper_fails() {
        let key = random_bytes::<KEY_LEN>();
        let other = random_bytes::<KEY_LEN>();
        let sealed = encrypt(&key, b"hello", b"ctx");
        assert!(decrypt(&other, &sealed, b"ctx").is_err());
        assert!(decrypt(&key, &sealed, b"different").is_err());
        let mut tampered = sealed.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(decrypt(&key, &tampered, b"ctx").is_err());
    }

    #[test]
    fn wrong_nonce_length_is_rejected_before_decrypting() {
        let key = random_bytes::<KEY_LEN>();
        let mut sealed = encrypt(&key, b"hello", b"");
        sealed.nonce.pop();
        assert!(matches!(decrypt(&key, &sealed, b""), Err(CryptoError::Encoding(_))));
        sealed.nonce.clear();
        assert!(matches!(decrypt(&key, &sealed, b""), Err(CryptoError::Encoding(_))));
    }

    #[test]
    fn nonces_differ_between_calls() {
        let key = random_bytes::<KEY_LEN>();
        assert_ne!(encrypt(&key, b"x", b"").nonce, encrypt(&key, b"x", b"").nonce);
    }

    #[test]
    fn serializes_as_base64_strings() {
        let key = random_bytes::<KEY_LEN>();
        let sealed = encrypt(&key, b"x", b"");
        let json = serde_json::to_string(&sealed).unwrap();
        assert!(json.contains("\"nonce\":\""));
        let back: Sealed = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sealed);
    }

    #[test]
    fn deserialize_rejects_bad_nonce_length_and_bad_base64() {
        let short_nonce = r#"{"nonce":"AAAA","ciphertext":"AAAA"}"#;
        assert!(serde_json::from_str::<Sealed>(short_nonce).is_err());
        let empty_nonce = r#"{"nonce":"","ciphertext":"AAAA"}"#;
        assert!(serde_json::from_str::<Sealed>(empty_nonce).is_err());
        let not_base64 = r#"{"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"not base64!"}"#;
        assert!(serde_json::from_str::<Sealed>(not_base64).is_err());
    }
}
