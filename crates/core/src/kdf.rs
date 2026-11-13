//! Master key derivation from the account password.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::aead::KEY_LEN;
use crate::encoding;
use crate::{CryptoError, Result};

// Argon2id with 64 MiB memory, 3 passes, 1 lane. This is above OWASP's
// minimum recommendation (47 MiB, 1 pass, 1 lane); it costs well under a
// second on a laptop and the email salt makes precomputed tables useless.
//
// WARNING: every constant in this block, and every info string below it, is
// part of the key derivation. Changing any of them changes every existing
// user's auth hash and encryption key, and there is no password recovery.
//
// The known-answer test at the bottom of this file pins them. If it fails,
// do not just update the expected values — the versioned migration path is:
//
//   * a change that feeds an encrypted blob (`ENC_INFO`, `SELF_WRAP_INFO`,
//     `SALT_DOMAIN`) must bump `aead::SEALED_FORMAT`, so a vault written
//     under the old derivation is reported as a scheme this build cannot run
//     rather than as a wrong password;
//   * a change to `AUTH_INFO` has no blob to carry a version, so it must bump
//     `api::PROTOCOL_VERSION` and `api::MIN_CLIENT_PROTOCOL`, which is what
//     tells an older client to update instead of showing it a login failure.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

// These labels separate domains; they carry no version. A derivation's
// version is held by whatever reads what the derivation produced —
// `aead::SEALED_FORMAT` for the branches that end up inside an encrypted blob,
// `api::PROTOCOL_VERSION` for the one that is sent to a server — because only
// those are somewhere a reader can see it and say something useful about it. A
// version here would be a second, invisible one, and the two would drift.
//
// Every label names the primitive it belongs to, so a label can never be read
// as belonging to another: `credvault/kdf/...` is HKDF-SHA256 expansion of the
// master key, `credvault/aead/...` is AES-GCM associated data (see
// [`crate::aead::Context`]).
const SALT_DOMAIN: &[u8] = b"credvault/kdf/master-salt";
/// The auth hash is bound to the server it is presented to, so a credential
/// captured by one server cannot be replayed to another. The address is
/// appended to this prefix; see [`MasterKey::auth_hash`].
const AUTH_INFO: &[u8] = b"credvault/kdf/auth-hash";
/// Separates the fixed prefix from the server address, so no address can be
/// chosen that makes the two run together into a different valid pair.
const AUTH_INFO_SEPARATOR: u8 = 0;
/// Deliberately *not* bound to a server. These protect data at rest, so a
/// vault copied to a different server address must still open.
const ENC_INFO: &[u8] = b"credvault/kdf/private-key-encryption";
const SELF_WRAP_INFO: &[u8] = b"credvault/kdf/self-wrap";

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

/// The address of one klavyn server, in the single canonical form the auth
/// hash is derived from.
///
/// Parsing is the only way to make one, so the same server typed two ways
/// cannot produce two different credentials and lock someone out of an
/// account they can otherwise reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddress(String);

impl ServerAddress {
    /// Canonicalise a server address.
    ///
    /// Lower-cases the scheme and host, drops a default port and any trailing
    /// slash, and keeps the path, so two instances behind one host are still
    /// distinct.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if `address` is not an absolute `http`
    /// or `https` URL, or if it carries anything that is not part of
    /// addressing a server: credentials, a query, or a fragment. Those would
    /// otherwise give one server several canonical forms.
    pub fn parse(address: &str) -> Result<Self> {
        let invalid = |reason: &str| CryptoError::InvalidInput(format!("invalid server address: {reason}"));
        let url = Url::parse(address.trim()).map_err(|e| invalid(&e.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(invalid("use http:// or https://"));
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(invalid("no host"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(invalid("remove the username and password from the URL"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(invalid("remove the query and fragment from the URL"));
        }
        Ok(Self(url.as_str().trim_end_matches('/').to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The salt is derived from the email so the client can log in without first
/// asking the server for a salt. It is unique per account and not secret.
///
/// It is deliberately not bound to a server: the master key it stretches is
/// what decrypts the vault, so binding it here would tie the data to an
/// address and make a moved server unreadable. The server binding belongs to
/// the one sub-key that is a credential; see [`MasterKey::auth_hash`].
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

    /// The credential sent to `server` at login. The server hashes it again
    /// before storing, so a database leak never reveals it directly.
    ///
    /// Bound to the server's address: the same email and password produce a
    /// *different* credential on every server, so an operator who logs what
    /// clients send cannot replay it against someone else's instance. The
    /// encryption keys below are deliberately not bound this way.
    pub fn auth_hash(&self, server: &ServerAddress) -> Zeroizing<String> {
        let mut info = Vec::with_capacity(AUTH_INFO.len() + 1 + server.as_str().len());
        info.extend_from_slice(AUTH_INFO);
        info.push(AUTH_INFO_SEPARATOR);
        info.extend_from_slice(server.as_str().as_bytes());
        Zeroizing::new(encoding::encode(self.expand(&info).as_ref()))
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

    fn server() -> ServerAddress {
        ServerAddress::parse("https://vault.example.com").unwrap()
    }

    #[test]
    fn same_inputs_same_keys_and_email_is_case_insensitive() {
        let a = MasterKey::derive("correct horse", "Me@Example.com").unwrap();
        let b = MasterKey::derive("correct horse", " me@example.com ").unwrap();
        assert_eq!(a.auth_hash(&server()), b.auth_hash(&server()));
        assert_eq!(a.private_key_encryption_key(), b.private_key_encryption_key());
    }

    #[test]
    fn different_password_or_email_changes_everything() {
        let a = MasterKey::derive("correct horse", "me@example.com").unwrap();
        let b = MasterKey::derive("correct horsf", "me@example.com").unwrap();
        let c = MasterKey::derive("correct horse", "you@example.com").unwrap();
        assert_ne!(a.auth_hash(&server()), b.auth_hash(&server()));
        assert_ne!(a.auth_hash(&server()), c.auth_hash(&server()));
    }

    /// The property the binding exists for: a credential handed to one server
    /// is useless at another, so a hostile operator cannot replay what its
    /// users send it.
    #[test]
    fn the_same_account_has_a_different_credential_on_every_server() {
        let key = MasterKey::derive("correct horse", "me@example.com").unwrap();
        let hashes = [
            "https://vault.example.com",
            "https://vault.example.org",
            "https://other.example.com",
            "http://127.0.0.1:8787",
            "https://vault.example.com:8443",
            "https://vault.example.com/second",
        ]
        .map(|address| key.auth_hash(&ServerAddress::parse(address).unwrap()).to_string());
        for (i, left) in hashes.iter().enumerate() {
            for right in &hashes[i + 1..] {
                assert_ne!(left, right);
            }
        }
        // The encryption keys stay unbound, or moving a server would make
        // every vault on it undecryptable.
        let here = key.private_key_encryption_key();
        let wrap = key.self_wrap_key();
        assert_eq!(here, MasterKey::derive("correct horse", "me@example.com").unwrap().private_key_encryption_key());
        assert_ne!(here.as_slice(), wrap.as_slice());
    }

    #[test]
    fn one_server_written_several_ways_gives_one_credential() {
        let key = MasterKey::derive("correct horse", "me@example.com").unwrap();
        let canonical = key.auth_hash(&ServerAddress::parse("https://vault.example.com").unwrap());
        for typed in [
            "https://vault.example.com",
            "https://vault.example.com/",
            "  https://vault.example.com  ",
            "HTTPS://VAULT.EXAMPLE.COM",
            // 443 is https's default port and is dropped on parsing.
            "https://vault.example.com:443",
        ] {
            assert_eq!(key.auth_hash(&ServerAddress::parse(typed).unwrap()), canonical, "{typed}");
        }
    }

    #[test]
    fn server_addresses_are_canonical_or_refused() {
        assert_eq!(ServerAddress::parse("HTTP://Localhost:8787/").unwrap().as_str(), "http://localhost:8787");
        assert_eq!(
            ServerAddress::parse("https://a.example.com/vault/").unwrap().as_str(),
            "https://a.example.com/vault"
        );
        assert_eq!(ServerAddress::parse("https://a.example.com:443").unwrap().to_string(), "https://a.example.com");

        for bad in [
            "",
            "not a url",
            "vault.example.com",                 // no scheme
            "ftp://vault.example.com",           // wrong scheme
            "file:///etc/passwd",                // no host
            "https://user:pw@vault.example.com", // credentials
            "https://vault.example.com?x=1",     // query
            "https://vault.example.com#frag",    // fragment
        ] {
            assert!(ServerAddress::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn auth_hash_differs_from_encryption_key() {
        let key = MasterKey::derive("correct horse", "me@example.com").unwrap();
        assert_ne!(encoding::decode(&key.auth_hash(&server())).unwrap(), key.private_key_encryption_key().as_slice());
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
        assert_eq!(
            *old.auth_hash(&server()),
            *MasterKey::derive("8charpw!", "me@example.com").unwrap().auth_hash(&server())
        );
    }

    #[test]
    fn auth_hash_validation() {
        let key = MasterKey::derive("correct horse", "me@example.com").unwrap();
        assert!(validate_auth_hash(&key.auth_hash(&server())).is_ok());
        assert!(validate_auth_hash("").is_err());
        assert!(validate_auth_hash("AAAA").is_err());
        assert!(validate_auth_hash("not base64!").is_err());
        assert!(validate_auth_hash(&"A".repeat(200_000)).is_err());
    }

    /// Decode a hex literal from a published test vector.
    fn hex(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2), "hex vector has an odd length");
        text.as_bytes()
            .chunks(2)
            .map(|pair| {
                let digit = |c: u8| (c as char).to_digit(16).expect("vector is not hex") as u8;
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    /// RFC 5869 test case 1, run through the same `Hkdf<Sha256>` every sub-key
    /// is expanded with.
    ///
    /// This checks the construction, not the hash: the realistic failure here
    /// is wiring the pieces up wrongly — salt and IKM transposed, info passed
    /// as salt, the wrong output length — all of which produce plausible
    /// looking keys that no other test in this file would notice.
    #[test]
    fn hkdf_matches_rfc_5869_test_case_1() {
        let ikm = [0x0b_u8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm).expand(&info, &mut okm).unwrap();
        assert_eq!(
            okm.to_vec(),
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
    }

    /// The Argon2 cost is a security parameter, so it is asserted rather than
    /// left to a comment. The floor is OWASP's minimum for Argon2id.
    #[test]
    fn argon2_parameters_stay_above_the_floor() {
        let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(KEY_LEN)).unwrap();
        assert_eq!(params.m_cost(), 64 * 1024, "memory, in KiB");
        assert_eq!(params.t_cost(), 3, "passes");
        assert_eq!(params.p_cost(), 1, "lanes");
        assert_eq!(params.output_len(), Some(KEY_LEN));
        assert!(params.m_cost() >= 47 * 1024, "below OWASP's 47 MiB minimum");
        assert!(params.t_cost() >= 1);
    }

    /// Known-answer test, and the tripwire for the whole derivation. If this
    /// fails, every existing account is locked out. Do NOT just update the
    /// expected values: see the WARNING at the top of this file for which
    /// version number a given change has to bump first.
    ///
    /// Updating these values is how an account gets locked out, so the test
    /// exists to make that impossible to do by accident. A failure here means
    /// a derivation moved, and the fix is to put it back or to bump the
    /// version that covers it — never to paste in the new answer.
    #[test]
    fn derivation_is_pinned_to_known_answers() {
        let key = MasterKey::derive("correct horse battery staple", "kat@example.com").unwrap();
        assert_eq!(
            *key.auth_hash(&ServerAddress::parse("https://vault.example.com").unwrap()),
            "YeI/thb1JpGv/YZmHUA3AFvh+0Zbl3C4D/DwB8InjS4="
        );
        assert_eq!(
            encoding::encode(key.private_key_encryption_key().as_ref()),
            "Nz9XGrw5HXVxoUmku/go/13j+5/vAmd5qiZJxFPNvrk="
        );
        assert_eq!(encoding::encode(key.self_wrap_key().as_ref()), "QNWQUYqvgmKiu7TNhXk+ogTUbQnoof2PK7H5LbU6Wlw=");
        assert_ne!(key.self_wrap_key(), key.private_key_encryption_key());
    }
}
