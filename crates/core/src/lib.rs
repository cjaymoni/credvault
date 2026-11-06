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
//! Every encrypted blob carries the version of the scheme that produced it
//! (see [`aead::SEALED_FORMAT`]), and every secret's plaintext carries the
//! version of its own field layout (see [`secret::PAYLOAD_FORMAT`]). Both are
//! authenticated, and both are readable before the data they describe, so a
//! scheme this build cannot run is reported as that rather than as the
//! "decryption failed" a wrong passphrase also produces.
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
    /// Stored data written by a newer build than this one. Refused rather than
    /// partially read: a client that dropped what it did not understand and
    /// then saved the record back would destroy data it never showed the user.
    #[error("this {what} was saved by a newer version of credvault (format {found}); update the app to open it")]
    NewerFormat { what: &'static str, found: u32 },
    /// Stored data in a format this build does not implement. Distinct from
    /// [`CryptoError::Decrypt`] on purpose: a wrong passphrase and a scheme
    /// this build cannot run are different problems with different answers,
    /// and an AEAD that simply fails to open cannot tell them apart.
    #[error("this {what} is in format {found}, which this version of credvault cannot read")]
    UnknownFormat { what: &'static str, found: u32 },
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Compare a format tag read out of stored data against what this build writes.
///
/// Refusing is the point. A build that read the parts it recognised and
/// ignored the rest would go on to save the record back, destroying whatever
/// it had quietly dropped.
pub(crate) fn check_format(what: &'static str, found: u32, expected: u32) -> Result<()> {
    if found > expected {
        return Err(CryptoError::NewerFormat { what, found });
    }
    if found != expected {
        return Err(CryptoError::UnknownFormat { what, found });
    }
    Ok(())
}
