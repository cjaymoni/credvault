//! AES-256-GCM with a random 96-bit nonce.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::encoding::base64_bytes;
use crate::{CryptoError, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Version of the client-side encryption scheme that produced a [`Sealed`]:
/// the key derivation branches behind it, the cipher, and how the associated
/// data is built.
///
/// Bump it whenever a blob written before the change can no longer be opened
/// by the current code path — a different HKDF info string, a different
/// cipher, a different AAD layout. Because every blob carries it, a build that
/// meets an unfamiliar one says so, instead of reporting the wrong passphrase
/// that a failed AEAD open otherwise looks exactly like.
///
/// It is one number for every kind of blob rather than one per kind. A bump
/// made for the key derivation therefore also retires secret payloads, which
/// are encrypted under random keys the derivation never touched. That costs an
/// unnecessary re-encrypt during a migration and buys one thing worth more:
/// there is a single answer to "what scheme wrote this", and no way to forget
/// which of several numbers a change was supposed to move.
pub const SEALED_FORMAT: u32 = 1;

/// Separates the purpose from whatever else a blob is bound to. A domain is a
/// fixed ASCII constant, so a zero byte cannot occur inside one.
const DOMAIN_SEPARATOR: u8 = 0;

/// What a sealed blob is for.
///
/// Two jobs at once. `domain` is authenticated with the ciphertext, so a blob
/// written for one purpose cannot be presented as another. `what` names the
/// blob in errors, so a format mismatch reads as something a person can act on
/// instead of "decryption failed".
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    what: &'static str,
    domain: &'static [u8],
    /// Anything else this blob is bound to and that must be supplied again to
    /// open it, such as the plaintext name a secret is stored under. Empty for
    /// a blob bound to nothing but its purpose.
    extra: &'a [u8],
}

impl Context<'static> {
    pub const fn new(what: &'static str, domain: &'static [u8]) -> Self {
        Self { what, domain, extra: &[] }
    }
}

impl<'a> Context<'a> {
    /// Bind this blob to `extra` as well as to its purpose.
    pub fn bound_to(self, extra: &'a [u8]) -> Context<'a> {
        Context { what: self.what, domain: self.domain, extra }
    }

    /// How this blob is named to a person.
    pub fn what(&self) -> &'static str {
        self.what
    }

    /// The bytes AES-GCM authenticates: the scheme version, the purpose, then
    /// whatever else the blob is bound to.
    ///
    /// The version goes in as well as being checked before decrypting, so that
    /// a build which one day reads two versions cannot be made to open a blob
    /// under the weaker of them by flipping the tag.
    ///
    /// `version` is a fixed four bytes and `domain` is followed by a separator
    /// that cannot occur within it, so no `extra` can be chosen that runs the
    /// pieces together into a different, also-valid triple.
    fn associated_data(&self, version: u32) -> Vec<u8> {
        let mut aad = Vec::with_capacity(4 + self.domain.len() + 1 + self.extra.len());
        aad.extend_from_slice(&version.to_be_bytes());
        aad.extend_from_slice(self.domain);
        aad.push(DOMAIN_SEPARATOR);
        aad.extend_from_slice(self.extra);
        aad
    }
}

/// Ciphertext, the nonce it was produced with, and the scheme that produced
/// it. Deserialising enforces the nonce length, so a `Sealed` built from JSON
/// is always structurally valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// The [`SEALED_FORMAT`] this blob was written under. In the clear, so a
    /// reader can tell a scheme it cannot handle from a wrong key before it
    /// tries; authenticated, so it cannot be altered.
    pub v: u32,
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

/// Encrypt `plaintext` for `context`, which is authenticated but not
/// encrypted and must be supplied again to decrypt.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8], context: &Context<'_>) -> Sealed {
    let nonce = random_bytes::<NONCE_LEN>();
    let aad = context.associated_data(SEALED_FORMAT);
    let cipher = Aes256Gcm::new(key.into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
        .expect("AES-GCM encryption cannot fail with valid key and nonce sizes");
    Sealed { v: SEALED_FORMAT, nonce: nonce.to_vec(), ciphertext }
}

/// Decrypt a blob written for `context`.
///
/// # Errors
///
/// [`CryptoError::NewerFormat`] or [`CryptoError::UnknownFormat`] if the blob
/// was written under a scheme this build does not implement — checked first,
/// so that case never reaches the cipher and is never mistaken for a wrong
/// key. [`CryptoError::Decrypt`] if the key, the context, or the ciphertext is
/// wrong.
pub fn decrypt(key: &[u8; KEY_LEN], sealed: &Sealed, context: &Context<'_>) -> Result<Vec<u8>> {
    crate::check_format(context.what(), sealed.v, SEALED_FORMAT)?;
    // Fields are public, so re-check here even though deserialisation already did.
    if sealed.nonce.len() != NONCE_LEN {
        return Err(CryptoError::Encoding(format!("nonce must be {NONCE_LEN} bytes")));
    }
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ciphertext, aad: &aad_for(sealed, context) })
        .map_err(|_| CryptoError::Decrypt)
}

/// The associated data a stored blob was written with. Built from the blob's
/// own version, which `decrypt` has already established is one this build
/// implements.
fn aad_for(sealed: &Sealed, context: &Context<'_>) -> Vec<u8> {
    context.associated_data(sealed.v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: Context = Context::new("thing", b"credvault/test/one");
    const TWO: Context = Context::new("other thing", b"credvault/test/two");

    #[test]
    fn round_trip_with_context() {
        let key = random_bytes::<KEY_LEN>();
        let sealed = encrypt(&key, b"hello", &ONE);
        assert_eq!(decrypt(&key, &sealed, &ONE).unwrap(), b"hello");
    }

    #[test]
    fn wrong_key_or_context_or_tamper_fails() {
        let key = random_bytes::<KEY_LEN>();
        let other = random_bytes::<KEY_LEN>();
        let sealed = encrypt(&key, b"hello", &ONE);
        assert!(decrypt(&other, &sealed, &ONE).is_err());
        // A blob written for one purpose does not open as another, even with
        // the right key.
        assert!(decrypt(&key, &sealed, &TWO).is_err());
        assert!(decrypt(&key, &sealed, &ONE.bound_to(b"extra")).is_err());
        let mut tampered = sealed.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(decrypt(&key, &tampered, &ONE).is_err());
    }

    #[test]
    fn what_a_blob_is_bound_to_must_be_given_back_exactly() {
        let key = random_bytes::<KEY_LEN>();
        let sealed = encrypt(&key, b"hello", &ONE.bound_to(b"GitHub"));
        assert_eq!(decrypt(&key, &sealed, &ONE.bound_to(b"GitHub")).unwrap(), b"hello");
        assert!(decrypt(&key, &sealed, &ONE.bound_to(b"GitLab")).is_err());
        assert!(decrypt(&key, &sealed, &ONE).is_err());
    }

    /// The separator is what stops a chosen binding from impersonating a
    /// different domain-and-binding pair that happens to concatenate the same.
    #[test]
    fn a_binding_cannot_run_together_with_the_domain() {
        const PREFIX: Context = Context::new("thing", b"credvault/test/ab");
        const SHORT: Context = Context::new("thing", b"credvault/test/a");
        let key = random_bytes::<KEY_LEN>();
        let sealed = encrypt(&key, b"hello", &PREFIX);
        assert!(decrypt(&key, &sealed, &SHORT.bound_to(b"b")).is_err());
    }

    /// The version is checked before the cipher runs, so a scheme this build
    /// cannot execute is reported as exactly that — not as the wrong
    /// passphrase, which is what a failed AEAD open otherwise looks like.
    #[test]
    fn a_blob_from_another_scheme_is_named_not_mistaken_for_a_wrong_key() {
        let key = random_bytes::<KEY_LEN>();
        let mut sealed = encrypt(&key, b"hello", &ONE);

        sealed.v = SEALED_FORMAT + 1;
        let error = decrypt(&key, &sealed, &ONE).unwrap_err();
        assert!(matches!(error, CryptoError::NewerFormat { found, .. } if found == SEALED_FORMAT + 1), "{error:?}");
        assert!(error.to_string().contains("thing"), "{error}");

        sealed.v = 0;
        assert!(matches!(decrypt(&key, &sealed, &ONE), Err(CryptoError::UnknownFormat { found: 0, .. })));
    }

    /// The tag is in the clear but not free to change: it is authenticated, so
    /// a build that one day reads two versions cannot be walked back to the
    /// older one.
    #[test]
    fn the_version_tag_is_authenticated() {
        let key = random_bytes::<KEY_LEN>();
        let mut sealed = encrypt(&key, b"hello", &ONE);
        // Forge a blob whose body was written under one version and whose tag
        // claims the version this build implements.
        let forged = Sealed {
            v: SEALED_FORMAT,
            nonce: sealed.nonce.clone(),
            ciphertext: {
                let aad = ONE.associated_data(SEALED_FORMAT + 1);
                let cipher = Aes256Gcm::new((&key).into());
                cipher.encrypt(Nonce::from_slice(&sealed.nonce), Payload { msg: b"hello", aad: &aad }).unwrap()
            },
        };
        assert!(matches!(decrypt(&key, &forged, &ONE), Err(CryptoError::Decrypt)));
        sealed.v = SEALED_FORMAT;
        assert_eq!(decrypt(&key, &sealed, &ONE).unwrap(), b"hello");
    }

    #[test]
    fn wrong_nonce_length_is_rejected_before_decrypting() {
        let key = random_bytes::<KEY_LEN>();
        let mut sealed = encrypt(&key, b"hello", &ONE);
        sealed.nonce.pop();
        assert!(matches!(decrypt(&key, &sealed, &ONE), Err(CryptoError::Encoding(_))));
        sealed.nonce.clear();
        assert!(matches!(decrypt(&key, &sealed, &ONE), Err(CryptoError::Encoding(_))));
    }

    /// AES-256-GCM with a 96-bit nonce and a 128-bit tag, and no padding.
    ///
    /// The last part is a property worth stating rather than discovering: a
    /// blob's length gives away its plaintext's length exactly. That is
    /// accepted here — the server already knows roughly how big a credential
    /// record is — but anything that ever stores something length-sensitive
    /// under this needs its own padding.
    #[test]
    fn the_aead_is_aes_256_gcm_shaped() {
        let key = random_bytes::<KEY_LEN>();
        for len in [0usize, 1, 15, 16, 17, 1024] {
            let sealed = encrypt(&key, &vec![0u8; len], &ONE);
            assert_eq!(sealed.nonce.len(), NONCE_LEN, "96-bit nonce");
            assert_eq!(sealed.ciphertext.len(), len + 16, "plaintext length plus a 128-bit tag");
        }
    }

    #[test]
    fn nonces_differ_between_calls() {
        let key = random_bytes::<KEY_LEN>();
        assert_ne!(encrypt(&key, b"x", &ONE).nonce, encrypt(&key, b"x", &ONE).nonce);
    }

    #[test]
    fn serializes_with_its_version_and_base64_strings() {
        let key = random_bytes::<KEY_LEN>();
        let sealed = encrypt(&key, b"x", &ONE);
        let json = serde_json::to_string(&sealed).unwrap();
        assert!(json.starts_with(r#"{"v":1,"nonce":""#), "{json}");
        let back: Sealed = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sealed);
    }

    /// Required, not defaulted: a blob with no version is not a blob this
    /// build has any business guessing about.
    #[test]
    fn deserialize_rejects_a_missing_version_bad_nonce_length_and_bad_base64() {
        let untagged = r#"{"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAA"}"#;
        assert!(serde_json::from_str::<Sealed>(untagged).is_err());
        let short_nonce = r#"{"v":1,"nonce":"AAAA","ciphertext":"AAAA"}"#;
        assert!(serde_json::from_str::<Sealed>(short_nonce).is_err());
        let empty_nonce = r#"{"v":1,"nonce":"","ciphertext":"AAAA"}"#;
        assert!(serde_json::from_str::<Sealed>(empty_nonce).is_err());
        let not_base64 = r#"{"v":1,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"not base64!"}"#;
        assert!(serde_json::from_str::<Sealed>(not_base64).is_err());
    }
}
