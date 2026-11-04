//! Client-side cryptography for credvault.
//!
//! The server only ever sees ciphertext. The scheme:
//!
//! 1. A master key is derived from the account password with Argon2id.
//!    Two sub-keys come from it via HKDF: an *auth hash* that is sent to the
//!    server as the login credential, and an *encryption key* that protects
//!    the user's X25519 private key at rest on the server.
//! 2. Each stored secret has its own random AES-256-GCM key. The payload
//!    (username, password, url, notes) is encrypted with that key, with the
//!    secret's plaintext name as associated data so the server cannot relabel
//!    one secret as another.
//! 3. The secret's key is wrapped for every person who may read it by sealing
//!    it to their X25519 public key. Sharing a secret with someone means
//!    wrapping the key for them; revoking means rotating the secret's key and
//!    re-wrapping it for everyone who still has access.
//!
//! Public keys are fetched from the server. Clients must let users compare
//! [`PublicKey::fingerprint`] out of band and pin keys on first use, otherwise
//! a malicious server could substitute its own key and read shared secrets.

pub mod aead;
pub mod api;
pub mod identity;
pub mod kdf;
pub mod password;
pub mod secret;

mod encoding;

pub use aead::Sealed;
pub use identity::{Identity, PublicKey, SealedBox};
pub use kdf::MasterKey;
pub use secret::{SecretKey, SecretPayload, WrappedKey};

/// Errors from the crypto layer. Deliberately vague about *why* decryption
/// failed so that callers cannot leak oracle information.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed: wrong key or tampered data")]
    Decrypt,
    #[error("key derivation failed")]
    Kdf,
    #[error("invalid encoding: {0}")]
    Encoding(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
