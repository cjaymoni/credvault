//! Per-secret encryption and key wrapping for sharing.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::{self, Sealed, KEY_LEN};
use crate::identity::{self, Identity, PublicKey, SealedBox};
use crate::{CryptoError, Result};

pub const MAX_FIELD_LEN: usize = 4096;
pub const MAX_NAME_LEN: usize = 200;

const SELF_WRAP_AAD: &[u8] = b"credvault/self-wrap/v1";

/// A secret's key wrapped for one person. The two forms differ in who could
/// have produced them: anyone can seal a box to a public key, but only the
/// owner can derive the self-wrap key, so an `Owner` copy proves the owner
/// made it and the server cannot swap in a key it knows.
///
/// Serialised without a tag so copies stored before this type existed (plain
/// sealed boxes) still parse: a sealed box has `ephemeral_public`, an owner
/// copy does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WrappedKey {
    /// Sealed to a member's X25519 public key.
    Shared(SealedBox),
    /// Encrypted under the owner's self-wrap key (see `MasterKey::self_wrap_key`).
    Owner(Sealed),
}

impl WrappedKey {
    pub fn ciphertext_len(&self) -> usize {
        match self {
            Self::Shared(boxed) => boxed.sealed.ciphertext.len(),
            Self::Owner(sealed) => sealed.ciphertext.len(),
        }
    }
}

/// The sensitive fields of a credential. Encrypted as one JSON blob so the
/// server cannot tell which fields are present.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretPayload {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
}

/// Never print the password or notes, even in debug output.
impl fmt::Debug for SecretPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretPayload")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("notes", &"<redacted>")
            .finish()
    }
}

impl SecretPayload {
    pub fn validate(&self) -> Result<()> {
        if self.password.is_empty() {
            return Err(CryptoError::InvalidInput("password must not be empty".into()));
        }
        for (label, value) in
            [("username", &self.username), ("password", &self.password), ("url", &self.url), ("notes", &self.notes)]
        {
            if value.len() > MAX_FIELD_LEN {
                return Err(CryptoError::InvalidInput(format!("{label} is longer than {MAX_FIELD_LEN} bytes")));
            }
        }
        Ok(())
    }
}

/// Validate the plaintext display name stored alongside the ciphertext.
pub fn validate_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(CryptoError::InvalidInput("name must not be empty".into()));
    }
    if trimmed.len() > MAX_NAME_LEN {
        return Err(CryptoError::InvalidInput(format!("name is longer than {MAX_NAME_LEN} bytes")));
    }
    Ok(trimmed.to_string())
}

/// The random key that encrypts one secret's payload.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub fn generate() -> Self {
        Self(aead::random_bytes())
    }

    /// Encrypt `payload` under this key. The (trimmed) `name` is authenticated
    /// as associated data, so the server cannot present this ciphertext under
    /// a different name. Renaming a secret therefore re-encrypts it.
    pub fn encrypt(&self, name: &str, payload: &SecretPayload) -> Result<Sealed> {
        let name = validate_name(name)?;
        payload.validate()?;
        // The serialised plaintext is wiped as soon as it has been encrypted.
        let json =
            zeroize::Zeroizing::new(serde_json::to_vec(payload).map_err(|e| CryptoError::Encoding(e.to_string()))?);
        Ok(aead::encrypt(&self.0, &json, name.as_bytes()))
    }

    /// Decrypt a payload that was encrypted under `name`.
    pub fn decrypt(&self, name: &str, sealed: &Sealed) -> Result<SecretPayload> {
        let name = validate_name(name)?;
        let json = zeroize::Zeroizing::new(aead::decrypt(&self.0, sealed, name.as_bytes())?);
        serde_json::from_slice(&json).map_err(|e| CryptoError::Encoding(format!("payload: {e}")))
    }

    /// Wrap this key for another user so they can read the secret.
    pub fn wrap_for(&self, recipient: &PublicKey) -> Result<SealedBox> {
        identity::seal(recipient, &self.0)
    }

    /// Wrap this key for its owner under their self-wrap key.
    pub fn wrap_for_owner(&self, self_wrap_key: &[u8; KEY_LEN]) -> Sealed {
        aead::encrypt(self_wrap_key, &self.0, SELF_WRAP_AAD)
    }

    /// Recover the key from the owner's own copy.
    pub fn unwrap_owner(self_wrap_key: &[u8; KEY_LEN], sealed: &Sealed) -> Result<Self> {
        let bytes = zeroize::Zeroizing::new(aead::decrypt(self_wrap_key, sealed, SELF_WRAP_AAD)?);
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array: zeroize::Zeroizing<[u8; KEY_LEN]> = zeroize::Zeroizing::new(
            bytes.try_into().map_err(|_| CryptoError::Encoding("secret key must be 32 bytes".into()))?,
        );
        Ok(Self(*array))
    }

    /// Recover the key from a copy sealed to `me`.
    pub fn unwrap_with(me: &Identity, wrapped: &SealedBox) -> Result<Self> {
        let bytes = zeroize::Zeroizing::new(me.open(wrapped)?);
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "GitHub";

    fn payload() -> SecretPayload {
        SecretPayload {
            username: "jüde".into(),
            password: "pässwörd🔐".into(),
            url: "https://example.com".into(),
            notes: "".into(),
        }
    }

    #[test]
    fn owner_and_shared_user_can_both_decrypt() {
        let owner = Identity::generate();
        let friend = Identity::generate();
        let key = SecretKey::generate();
        let sealed = key.encrypt(NAME, &payload()).unwrap();

        let for_owner = key.wrap_for(owner.public_key()).unwrap();
        let for_friend = key.wrap_for(friend.public_key()).unwrap();

        let owner_key = SecretKey::unwrap_with(&owner, &for_owner).unwrap();
        let friend_key = SecretKey::unwrap_with(&friend, &for_friend).unwrap();
        assert_eq!(owner_key.decrypt(NAME, &sealed).unwrap(), payload());
        assert_eq!(friend_key.decrypt(NAME, &sealed).unwrap(), payload());
    }

    #[test]
    fn name_is_authenticated_but_whitespace_insensitive() {
        let key = SecretKey::generate();
        let sealed = key.encrypt("  GitHub ", &payload()).unwrap();
        assert_eq!(key.decrypt("GitHub", &sealed).unwrap(), payload());
        assert!(key.decrypt("GitLab", &sealed).is_err());
        assert!(key.encrypt("   ", &payload()).is_err());
    }

    #[test]
    fn owner_copy_round_trips_and_needs_the_owners_key() {
        let key = SecretKey::generate();
        let self_wrap = aead::random_bytes::<KEY_LEN>();
        let other = aead::random_bytes::<KEY_LEN>();
        let wrapped = key.wrap_for_owner(&self_wrap);
        let restored = SecretKey::unwrap_owner(&self_wrap, &wrapped).unwrap();
        let sealed = key.encrypt(NAME, &payload()).unwrap();
        assert_eq!(restored.decrypt(NAME, &sealed).unwrap(), payload());
        assert!(SecretKey::unwrap_owner(&other, &wrapped).is_err());
        // An owner copy is not a sealed box, so nobody's identity opens it.
        let me = Identity::generate();
        let as_box = SealedBox { ephemeral_public: me.public_key().clone(), sealed: wrapped };
        assert!(SecretKey::unwrap_with(&me, &as_box).is_err());
    }

    #[test]
    fn wrapped_key_json_distinguishes_the_two_forms_and_reads_legacy_boxes() {
        let key = SecretKey::generate();
        let me = Identity::generate();
        let shared = WrappedKey::Shared(key.wrap_for(me.public_key()).unwrap());
        let owner = WrappedKey::Owner(key.wrap_for_owner(&aead::random_bytes::<KEY_LEN>()));
        for original in [&shared, &owner] {
            let json = serde_json::to_string(original).unwrap();
            assert_eq!(&serde_json::from_str::<WrappedKey>(&json).unwrap(), original);
        }
        // A sealed box stored before `WrappedKey` existed carries no tag.
        let legacy = serde_json::to_string(&key.wrap_for(me.public_key()).unwrap()).unwrap();
        assert!(matches!(serde_json::from_str::<WrappedKey>(&legacy).unwrap(), WrappedKey::Shared(_)));
        let owner_json = serde_json::to_string(&owner).unwrap();
        assert!(owner_json.contains("\"nonce\"") && !owner_json.contains("ephemeral_public"));
    }

    #[test]
    fn stranger_cannot_unwrap() {
        let owner = Identity::generate();
        let stranger = Identity::generate();
        let key = SecretKey::generate();
        let for_owner = key.wrap_for(owner.public_key()).unwrap();
        assert!(SecretKey::unwrap_with(&stranger, &for_owner).is_err());
    }

    #[test]
    fn empty_password_and_oversized_fields_rejected() {
        let key = SecretKey::generate();
        let mut bad = payload();
        bad.password = String::new();
        assert!(key.encrypt(NAME, &bad).is_err());
        let mut big = payload();
        big.notes = "n".repeat(MAX_FIELD_LEN + 1);
        assert!(key.encrypt(NAME, &big).is_err());
    }

    #[test]
    fn name_validation() {
        assert_eq!(validate_name("  GitHub ").unwrap(), "GitHub");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn debug_output_redacts_password_and_notes() {
        let mut p = payload();
        p.notes = "very private".into();
        let text = format!("{p:?}");
        assert!(text.contains("jüde"));
        assert!(!text.contains("pässwörd"));
        assert!(!text.contains("very private"));
    }
}
