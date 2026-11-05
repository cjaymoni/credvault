//! Per-user X25519 key pair and a sealed-box construction for wrapping keys
//! to another user's public key.
//!
//! Sealing: a fresh ephemeral X25519 key pair is generated, a Diffie-Hellman
//! shared secret is computed against the recipient's public key, and an
//! AES-256-GCM key is derived from it with HKDF (salted with both public keys
//! so the key is bound to this sender/recipient pair). Only the holder of the
//! recipient's private key can recompute the shared secret.

use std::fmt;

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};
use zeroize::Zeroizing;

use crate::aead::{self, Sealed, KEY_LEN};
use crate::encoding;
use crate::{CryptoError, Result};

const SEALED_BOX_INFO: &[u8] = b"credvault/sealed-box/v1";
const PRIVATE_KEY_AAD: &[u8] = b"credvault/private-key/v1";
const PUBLIC_KEY_LEN: usize = 32;
/// 96 bits: long enough that a collision cannot be found by brute force, short
/// enough to read out loud in six groups.
const FINGERPRINT_BYTES: usize = 12;

/// Hex digits in a fingerprint once the separators are stripped.
pub const FINGERPRINT_HEX_LEN: usize = 2 * FINGERPRINT_BYTES;

/// Fingerprints are read aloud and typed back in, so only the hex digits carry
/// meaning: spacing, separators and case do not. Normalise before comparing,
/// so that `3F1A 9C0E…` and `3f1a-9c0e-…` are the same fingerprint.
pub fn normalize_fingerprint(text: &str) -> String {
    text.chars().filter(char::is_ascii_hexdigit).map(|c| c.to_ascii_lowercase()).collect()
}

/// A user's public key, safe to publish. Serialises as base64 and can only be
/// deserialised from exactly 32 bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    pub fn from_base64(text: &str) -> Result<Self> {
        Ok(Self(encoding::decode_array::<PUBLIC_KEY_LEN>(text, "public key")?))
    }

    pub fn to_base64(&self) -> String {
        encoding::encode(&self.0)
    }

    /// A short digest for humans to compare out of band, e.g.
    /// `3f1a-9c0e-77b2-d4a5-1b2c-3d4e`. Clients compare the full key bytes;
    /// the fingerprint is only for people.
    /// Two users who see the same fingerprint for a key know the server has
    /// not substituted it.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0);
        digest[..FINGERPRINT_BYTES]
            .chunks(2)
            .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
            .collect::<Vec<_>>()
            .join("-")
    }

    fn dalek(&self) -> DalekPublic {
        DalekPublic::from(self.0)
    }
}

impl TryFrom<String> for PublicKey {
    type Error = CryptoError;

    fn try_from(text: String) -> Result<Self> {
        Self::from_base64(&text)
    }
}

impl From<PublicKey> for String {
    fn from(key: PublicKey) -> Self {
        key.to_base64()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint())
    }
}

/// Data sealed to a public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBox {
    pub ephemeral_public: PublicKey,
    #[serde(flatten)]
    pub sealed: Sealed,
}

/// A user's X25519 key pair. The private half is zeroised on drop.
pub struct Identity {
    secret: StaticSecret,
    public: PublicKey,
}

impl Identity {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey(DalekPublic::from(&secret).to_bytes());
        Self { secret, public }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Encrypt the private key for storage on the server.
    pub fn encrypt_private_key(&self, key: &[u8; KEY_LEN]) -> Sealed {
        aead::encrypt(key, self.secret.as_bytes(), PRIVATE_KEY_AAD)
    }

    /// Recover an identity from its server-stored encrypted private key.
    pub fn decrypt_private_key(key: &[u8; KEY_LEN], sealed: &Sealed) -> Result<Self> {
        let bytes = Zeroizing::new(aead::decrypt(key, sealed, PRIVATE_KEY_AAD)?);
        let array: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes.as_slice().try_into().map_err(|_| CryptoError::Encoding("private key must be 32 bytes".into()))?,
        );
        let secret = StaticSecret::from(*array);
        let public = PublicKey(DalekPublic::from(&secret).to_bytes());
        Ok(Self { secret, public })
    }

    /// Open a box that was sealed to this identity's public key.
    pub fn open(&self, boxed: &SealedBox) -> Result<Vec<u8>> {
        let shared = self.secret.diffie_hellman(&boxed.ephemeral_public.dalek());
        // A low-order ephemeral point yields an all-zero shared secret that an
        // attacker could predict; treat it as tampering.
        if !shared.was_contributory() {
            return Err(CryptoError::Decrypt);
        }
        let key = derive_box_key(shared.as_bytes(), &boxed.ephemeral_public, &self.public);
        aead::decrypt(&key, &boxed.sealed, SEALED_BOX_INFO)
    }
}

/// Seal `plaintext` so that only `recipient` can open it.
pub fn seal(recipient: &PublicKey, plaintext: &[u8]) -> Result<SealedBox> {
    let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = PublicKey(DalekPublic::from(&ephemeral_secret).to_bytes());
    let shared = ephemeral_secret.diffie_hellman(&recipient.dalek());
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidInput("recipient public key is a low-order point".into()));
    }
    let key = derive_box_key(shared.as_bytes(), &ephemeral_public, recipient);
    Ok(SealedBox { ephemeral_public, sealed: aead::encrypt(&key, plaintext, SEALED_BOX_INFO) })
}

fn derive_box_key(shared: &[u8; 32], ephemeral: &PublicKey, recipient: &PublicKey) -> Zeroizing<[u8; KEY_LEN]> {
    let mut salt = [0u8; 2 * PUBLIC_KEY_LEN];
    salt[..PUBLIC_KEY_LEN].copy_from_slice(&ephemeral.0);
    salt[PUBLIC_KEY_LEN..].copy_from_slice(&recipient.0);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(SEALED_BOX_INFO, out.as_mut())
        .expect("32-byte HKDF output is always valid");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_open() {
        let alice = Identity::generate();
        let boxed = seal(alice.public_key(), b"secret key material").unwrap();
        assert_eq!(alice.open(&boxed).unwrap(), b"secret key material");
    }

    #[test]
    fn only_recipient_can_open() {
        let alice = Identity::generate();
        let mallory = Identity::generate();
        let boxed = seal(alice.public_key(), b"for alice").unwrap();
        assert!(mallory.open(&boxed).is_err());
    }

    #[test]
    fn private_key_round_trips_through_encryption() {
        let alice = Identity::generate();
        let key = aead::random_bytes::<KEY_LEN>();
        let stored = alice.encrypt_private_key(&key);
        let restored = Identity::decrypt_private_key(&key, &stored).unwrap();
        assert_eq!(restored.public_key(), alice.public_key());

        let boxed = seal(alice.public_key(), b"hi").unwrap();
        assert_eq!(restored.open(&boxed).unwrap(), b"hi");
    }

    #[test]
    fn wrong_encryption_key_fails() {
        let alice = Identity::generate();
        let stored = alice.encrypt_private_key(&aead::random_bytes::<KEY_LEN>());
        assert!(Identity::decrypt_private_key(&aead::random_bytes::<KEY_LEN>(), &stored).is_err());
    }

    #[test]
    fn public_key_base64_round_trip_and_validation() {
        let alice = Identity::generate();
        let text = alice.public_key().to_base64();
        assert_eq!(PublicKey::from_base64(&text).unwrap(), *alice.public_key());
        assert!(PublicKey::from_base64("AAAA").is_err());
        assert!(PublicKey::from_base64("not base64!").is_err());
    }

    #[test]
    fn public_key_deserialization_enforces_length() {
        assert!(serde_json::from_str::<PublicKey>("\"AAAA\"").is_err());
        assert!(serde_json::from_str::<PublicKey>("\"\"").is_err());
        let alice = Identity::generate();
        let json = serde_json::to_string(alice.public_key()).unwrap();
        assert_eq!(serde_json::from_str::<PublicKey>(&json).unwrap(), *alice.public_key());
    }

    #[test]
    fn fingerprints_compare_ignoring_separators_and_case() {
        let alice = Identity::generate();
        let fp = alice.public_key().fingerprint();
        let canonical = normalize_fingerprint(&fp);
        assert_eq!(canonical.len(), FINGERPRINT_HEX_LEN);
        assert!(canonical.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // The same fingerprint typed back in any of the ways a person might.
        for typed in [fp.clone(), fp.to_uppercase(), fp.replace('-', " "), fp.replace('-', "")] {
            assert_eq!(normalize_fingerprint(&typed), canonical, "{typed:?}");
        }
        // Non-hex noise is dropped, but a different key is still different.
        assert_eq!(normalize_fingerprint(&format!("  {fp}  ")), canonical);
        assert_ne!(normalize_fingerprint(&Identity::generate().public_key().fingerprint()), canonical);
        assert_eq!(normalize_fingerprint(""), "");
    }

    #[test]
    fn fingerprint_is_stable_short_and_distinct() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let fp = alice.public_key().fingerprint();
        assert_eq!(fp, alice.public_key().fingerprint());
        assert_eq!(fp.len(), 29, "{fp}");
        assert_eq!(fp.matches('-').count(), 5);
        assert_ne!(fp, bob.public_key().fingerprint());
        assert_eq!(
            PublicKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap().fingerprint().len(),
            29
        );
    }

    #[test]
    fn low_order_public_key_is_rejected() {
        let zero = PublicKey::from_base64(&encoding::encode(&[0u8; 32])).unwrap();
        assert!(seal(&zero, b"x").is_err());

        let alice = Identity::generate();
        let mut boxed = seal(alice.public_key(), b"x").unwrap();
        boxed.ephemeral_public = zero;
        assert!(alice.open(&boxed).is_err());
    }

    #[test]
    fn sealed_box_json_round_trip() {
        let alice = Identity::generate();
        let boxed = seal(alice.public_key(), b"x").unwrap();
        let json = serde_json::to_string(&boxed).unwrap();
        let back: SealedBox = serde_json::from_str(&json).unwrap();
        assert_eq!(alice.open(&back).unwrap(), b"x");
    }

    #[test]
    fn debug_shows_fingerprint_not_bytes() {
        let alice = Identity::generate();
        let text = format!("{:?}", alice.public_key());
        assert!(text.starts_with("PublicKey("));
        assert!(!text.contains(&alice.public_key().to_base64()));
    }
}
