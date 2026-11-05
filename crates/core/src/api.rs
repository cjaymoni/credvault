//! Request and response types shared by the server and clients. Everything sensitive is
//! an opaque `Sealed`/`SealedBox` produced on the client.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{PublicKey, Sealed, SealedBox, WrappedKey};

pub const MAX_EMAIL_LEN: usize = 254;
pub const MAX_MESSAGE_LEN: usize = 1000;
/// Upper bound on any encrypted blob, generous for a credential record.
pub const MAX_BLOB_BYTES: usize = 64 * 1024;
/// Upper bound on a registration token sent by a client.
pub const MAX_REGISTRATION_TOKEN_LEN: usize = 256;

const REDACTED: &str = "<redacted>";

#[derive(Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    /// Wiped on drop at both ends; it is a reusable login credential.
    pub auth_hash: Zeroizing<String>,
    pub public_key: PublicKey,
    pub encrypted_private_key: Sealed,
    /// Required when the server was started with a registration token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_token: Option<String>,
}

impl fmt::Debug for RegisterRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterRequest")
            .field("email", &self.email)
            .field("auth_hash", &REDACTED)
            .field("public_key", &self.public_key)
            .field("registration_token", &self.registration_token.as_ref().map(|_| REDACTED))
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth_hash: Zeroizing<String>,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest").field("email", &self.email).field("auth_hash", &REDACTED).finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct SessionResponse {
    pub token: String,
    pub user: UserProfile,
}

impl fmt::Debug for SessionResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionResponse").field("token", &REDACTED).field("user", &self.user).finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: i64,
    pub email: String,
    pub public_key: PublicKey,
    pub encrypted_private_key: Sealed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicUser {
    pub id: i64,
    pub email: String,
    pub public_key: PublicKey,
}

/// Looking someone up requires already knowing their fingerprint, confirmed
/// out of band. Without that the directory would answer whether any address
/// has an account, which is the one thing a stranger must not be able to ask.
#[derive(Debug, Serialize, Deserialize)]
pub struct LookupQuery {
    pub email: String,
    /// The fingerprint the caller expects, in any spacing or case.
    pub fingerprint: String,
}

/// Longest fingerprint string accepted before normalising; a real one is 29
/// characters and this leaves room for whatever separators someone types.
pub const MAX_FINGERPRINT_INPUT_LEN: usize = 128;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSecretRequest {
    pub name: String,
    pub payload: Sealed,
    /// The secret key wrapped for the creator; must be `WrappedKey::Owner`.
    pub wrapped_key: WrappedKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateSecretRequest {
    /// The `key_version` the client encrypted with; a mismatch is a 409.
    pub key_version: i64,
    pub name: String,
    pub payload: Sealed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretView {
    pub id: i64,
    pub name: String,
    pub owner_email: String,
    pub is_owner: bool,
    pub payload: Sealed,
    /// `Owner` for the owner's row, `Shared` for everyone else.
    pub wrapped_key: WrappedKey,
    pub updated_at: DateTime<Utc>,
    /// Incremented by every key rotation. Clients send it back with writes.
    pub key_version: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Created {
    pub id: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Member {
    pub user_id: i64,
    pub email: String,
    /// Included so the owner can re-wrap a rotated key without extra lookups.
    pub public_key: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingInvite {
    pub id: i64,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessView {
    pub members: Vec<Member>,
    pub invites: Vec<PendingInvite>,
}

/// One member's copy of a rotated secret key: `Owner` for the owner's own
/// entry, `Shared` for every other member.
#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedKeyFor {
    pub user_id: i64,
    pub wrapped_key: WrappedKey,
}

/// Revoke one member and rotate the secret's key in the same request. The
/// payload is re-encrypted under a fresh key and `wrapped_keys` must contain
/// that key wrapped for every remaining member, including the owner.
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeAccessRequest {
    /// The version being replaced; a mismatch means another device rotated first.
    pub key_version: i64,
    pub payload: Sealed,
    pub wrapped_keys: Vec<WrappedKeyFor>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeAccessResponse {
    /// Pending invites carried the old key and were cancelled; re-invite if needed.
    pub cancelled_invites: u64,
    /// The version now in force.
    pub key_version: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InviteRequest {
    /// The key version the wrapped key was made from; a mismatch is a 409.
    pub key_version: i64,
    pub email: String,
    /// The invitee's fingerprint, for the same reason the lookup needs one:
    /// without it, which addresses have accounts could be read off this
    /// endpoint instead.
    pub fingerprint: String,
    /// The secret key wrapped for the invitee's public key.
    pub wrapped_key: SealedBox,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InviteView {
    pub id: i64,
    pub secret_name: String,
    pub inviter_email: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_credentials() {
        let login = LoginRequest { email: "a@example.com".into(), auth_hash: Zeroizing::new("SECRET-HASH".into()) };
        let text = format!("{login:?}");
        assert!(text.contains("a@example.com"));
        assert!(!text.contains("SECRET-HASH"));
    }

    #[test]
    fn registration_token_is_optional_on_the_wire() {
        let json = r#"{"email":"a@example.com","auth_hash":"x","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","encrypted_private_key":{"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA=="}}"#;
        let request: RegisterRequest = serde_json::from_str(json).unwrap();
        assert!(request.registration_token.is_none());
    }
}
