//! Master key derivation from the account password.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::aead::KEY_LEN;
use crate::encoding;
use crate::{CryptoError, Result};

// Argon2id with 64 MiB memory, 3 passes, 1 lane. This is above OWASP's
// minimum recommendation (47 MiB, 1 pass, 1 lane); it costs well under a
// second on a laptop and the email salt makes precomputed tables useless.
//
// WARNING: every constant in this block is part of the key derivation. Changing
// any of them changes every existing user's auth hash and encryption key, and
// there is no password recovery. The known-answer test at the bottom of this
// file pins them; if it fails you must add a versioned migration path, not
// update the expected values.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

const SALT_DOMAIN: &[u8] = b"credvault/master-salt/v1";
const AUTH_INFO: &[u8] = b"credvault/auth-hash/v1";
const ENC_INFO: &[u8] = b"credvault/private-key-encryption/v1";
const SELF_WRAP_INFO: &[u8] = b"credvault/self-wrap/v1";

/// The account password is the only thing protecting the vault, there is no
/// recovery, and a stolen database can be attacked offline at whatever rate
/// the attacker's hardware allows. Argon2 raises the cost per guess but
/// cannot make a short password long, so the floor is set well above the
/// eight characters that are conventional for ordinary logins.
///
/// This is policy for a *new* password only. See [`validate_new_password`].
pub const MIN_PASSWORD_LEN: usize = 12;

/// Length in bytes of the decoded auth hash sent to the server.
pub const AUTH_HASH_LEN: usize = KEY_LEN;

/// The root key for one account. Never leaves the client.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

/// Email addresses are compared case-insensitively everywhere, so normalise
/// before using one as a salt or an identifier.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Check that `text` is a well-formed auth hash (base64 of exactly
/// `AUTH_HASH_LEN` bytes). Servers call this before doing any expensive work.
pub fn validate_auth_hash(text: &str) -> Result<()> {
    encoding::decode_array::<AUTH_HASH_LEN>(text, "auth hash").map(|_| ())
}

/// The salt is derived from the email so the client can log in without first
/// asking the server for a salt. It is unique per account, not secret, and is
/// deliberately not bound to a server: the same email and password produce the
/// same auth hash on every credvault server.
fn salt_for(email: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SALT_DOMAIN);
    hasher.update(normalize_email(email).as_bytes());
    hasher.finalize().into()
}

/// Check a password someone is about to register with.
///
/// Deliberately separate from [`MasterKey::derive`], which must stay free of
/// policy: `derive` also runs on every login, so enforcing a length floor
/// there would lock anyone who registered under an older, shorter floor out
/// of a vault that cannot be recovered. Raising the floor must only ever
/// affect accounts being created.
pub fn validate_new_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(CryptoError::InvalidInput(format!("password must be at least {MIN_PASSWORD_LEN} characters")));
    }
    Ok(())
}

impl MasterKey {
    /// Derive the master key. Applies no password policy: see
    /// [`validate_new_password`] for why that belongs at registration only.
    pub fn derive(password: &str, email: &str) -> Result<Self> {
        let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(KEY_LEN))
            .map_err(|_| CryptoError::Kdf)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        argon.hash_password_into(password.as_bytes(), &salt_for(email), &mut out).map_err(|_| CryptoError::Kdf)?;
        Ok(Self(out))
    }

    fn expand(&self, info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        Hkdf::<Sha256>::new(None, &self.0).expand(info, out.as_mut()).expect("32-byte HKDF output is always valid");
        out
    }

    /// The credential sent to the server at login. The server hashes it again
    /// before storing, so a database leak never reveals it directly.
    pub fn auth_hash(&self) -> Zeroizing<String> {
        Zeroizing::new(encoding::encode(self.expand(AUTH_INFO).as_ref()))
    }

    /// Key that encrypts the user's X25519 private key for storage on the server.
    pub fn private_key_encryption_key(&self) -> Zeroizing<[u8; KEY_LEN]> {
        self.expand(ENC_INFO)
    }

    /// Key that wraps the owner's own copy of each secret key. Only the owner
    /// can derive it, so the server cannot forge or substitute an owner copy
    /// the way it could a sealed box.
    pub fn self_wrap_key(&self) -> Zeroizing<[u8; KEY_LEN]> {
        self.expand(SELF_WRAP_INFO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_same_keys_and_email_is_case_insensitive() {
        let a = MasterKey::derive("correct horse", "Me@Example.com").unwrap();
        let b = MasterKey::derive("correct horse", " me@example.com ").unwrap();
        assert_eq!(a.auth_hash(), b.auth_hash());
        assert_eq!(a.private_key_encryption_key(), b.private_key_encryption_key());
    }

    #[test]
    fn different_password_or_email_changes_everything() {
        let a = MasterKey::derive("correct horse", "me@example.com").unwrap();
        let b = MasterKey::derive("correct horsf", "me@example.com").unwrap();
        let c = MasterKey::derive("correct horse", "you@example.com").unwrap();
        assert_ne!(a.auth_hash(), b.auth_hash());
        assert_ne!(a.auth_hash(), c.auth_hash());
    }

    #[test]
    fn auth_hash_differs_from_encryption_key() {
        let key = MasterKey::derive("correct horse", "me@example.com").unwrap();
        assert_ne!(encoding::decode(&key.auth_hash()).unwrap(), key.private_key_encryption_key().as_slice());
    }

    #[test]
    fn the_length_floor_applies_to_new_passwords_only() {
        assert!(validate_new_password("short").is_err());
        assert!(validate_new_password(&"x".repeat(MIN_PASSWORD_LEN - 1)).is_err());
        assert!(validate_new_password(&"x".repeat(MIN_PASSWORD_LEN)).is_ok());
        // Counted in characters, not bytes, so a short non-ASCII password is
        // not waved through by its encoded length.
        assert!(validate_new_password(&"é".repeat(MIN_PASSWORD_LEN - 1)).is_err());

        // Deriving must stay policy-free: raising the floor would otherwise
        // lock an existing account out of a vault nobody can recover.
        assert!(MasterKey::derive("short", "me@example.com").is_ok());
        let old = MasterKey::derive("8charpw!", "me@example.com").unwrap();
        assert_eq!(*old.auth_hash(), *MasterKey::derive("8charpw!", "me@example.com").unwrap().auth_hash());
    }

    #[test]
    fn auth_hash_validation() {
        let key = MasterKey::derive("correct horse", "me@example.com").unwrap();
        assert!(validate_auth_hash(&key.auth_hash()).is_ok());
        assert!(validate_auth_hash("").is_err());
        assert!(validate_auth_hash("AAAA").is_err());
        assert!(validate_auth_hash("not base64!").is_err());
        assert!(validate_auth_hash(&"A".repeat(200_000)).is_err());
    }

    /// Known-answer test. If this fails, the derivation changed and every
    /// existing account is locked out. Do NOT just update the expected values.
    #[test]
    fn derivation_is_pinned_to_known_answers() {
        let key = MasterKey::derive("correct horse battery staple", "kat@example.com").unwrap();
        assert_eq!(*key.auth_hash(), "XigVQPJZDSptfM+JsmmHSJQC71RDkD6BVU//9dKaerk=");
        assert_eq!(
            encoding::encode(key.private_key_encryption_key().as_ref()),
            "blMSv8ORNtqn6ezOCx4uciZ4TL8PaP0qkXLbsgs+Sbs="
        );
        assert_eq!(encoding::encode(key.self_wrap_key().as_ref()), "rb7aNm3V+yj17WCptYQGmz+QDztf+PUlmVLA+VI63i4=");
        assert_ne!(key.self_wrap_key(), key.private_key_encryption_key());
    }
}
