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

/// How many secrets one account may own.
///
/// Far above what a person keeps and far below what it takes to fill a disk.
/// The server stores only ciphertext it cannot read, so it has no way to tell
/// a real vault from someone writing until the volume is full — and a full
/// volume stops every account on the server, not just the one that did it.
pub const MAX_SECRETS_PER_ACCOUNT: i64 = 1_000;

/// How many invites one account may have outstanding at once, as the inviter.
///
/// This bounds what one account can create. It does *not* bound what can be
/// pushed into someone else's list, because several accounts can each spend
/// their own budget on the same person; see
/// [`MAX_PENDING_INVITES_RECEIVED`].
pub const MAX_PENDING_INVITES_PER_ACCOUNT: i64 = 100;

/// How many unanswered invites one account may be sent.
///
/// Higher than the per-inviter cap, because being invited by many people is
/// legitimate in a way that inviting many people at once is not. What it stops
/// is a crowd of accounts each spending their own budget on one victim, which
/// the per-inviter cap alone allows.
pub const MAX_PENDING_INVITES_RECEIVED: i64 = 500;

const REDACTED: &str = "<redacted>";

// ----- protocol version -------------------------------------------------------

/// Version of the wire protocol spoken between a client and a server.
///
/// Bump it when a change would make a peer get an answer *wrong*: a field
/// whose meaning moved, an endpoint whose contract changed, a response an
/// older client would misread. A field that older peers can ignore safely is
/// additive and needs no bump.
pub const PROTOCOL_VERSION: u32 = 1;

/// The oldest server protocol a client built from this source will talk to.
pub const MIN_SERVER_PROTOCOL: u32 = 1;

/// The oldest client protocol a server built from this source still serves.
///
/// Raising this locks out installed clients, so it moves only when serving
/// them would be wrong rather than merely inconvenient.
pub const MIN_CLIENT_PROTOCOL: u32 = 1;

/// The body of `GET /health`.
///
/// Unauthenticated, so it carries the protocol numbers and nothing else. In
/// particular it does not report the build version, which would tell a passer
/// by which release to look up advisories for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    /// Always `"ok"`. A body at all is what says the process is serving.
    pub status: String,
    /// The protocol this server speaks.
    pub protocol: u32,
    /// The oldest client protocol this server still serves.
    pub min_client_protocol: u32,
}

impl Health {
    /// What a server built from this source reports.
    pub fn current() -> Self {
        Self { status: "ok".into(), protocol: PROTOCOL_VERSION, min_client_protocol: MIN_CLIENT_PROTOCOL }
    }
}

/// Why this build and a particular server cannot understand each other.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolMismatch {
    #[error(
        "this server needs a newer credvault: it serves protocol {required} and later, and this app speaks {speaks}"
    )]
    ClientTooOld { required: u32, speaks: u32 },
    #[error(
        "this server is too old for this app: it speaks protocol {speaks}, and this app needs {required} or later"
    )]
    ServerTooOld { speaks: u32, required: u32 },
}

/// Decide whether this build can talk to a server that reports `health`.
///
/// Both numbers are needed, and neither alone would do. The server's
/// `protocol` says what it speaks, which is how a client refuses one too old
/// to understand it. `min_client_protocol` says what it still serves, which is
/// how a *newer* server tells an old client to update rather than letting it
/// fail later, one confusing request at a time. A server ahead of this client
/// that still serves this client's protocol is compatible, and that is the
/// ordinary case after a server upgrade.
pub fn check_protocol(health: &Health) -> Result<(), ProtocolMismatch> {
    if PROTOCOL_VERSION < health.min_client_protocol {
        return Err(ProtocolMismatch::ClientTooOld { required: health.min_client_protocol, speaks: PROTOCOL_VERSION });
    }
    if health.protocol < MIN_SERVER_PROTOCOL {
        return Err(ProtocolMismatch::ServerTooOld { speaks: health.protocol, required: MIN_SERVER_PROTOCOL });
    }
    Ok(())
}

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
    /// Whether this account signs in with a password. False for an account
    /// created through Google, which still has a passphrase for its vault but
    /// does not use it as a server credential. Clients need this to know
    /// whether a passphrase change should also change the login.
    #[serde(default = "yes")]
    pub password_login: bool,
}

fn yes() -> bool {
    true
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

// ----- sign in with Google (OpenID Connect) ---------------------------------

/// Longest authorization code a client may send. Google's are far shorter;
/// this only stops an unbounded string reaching the token endpoint.
pub const MAX_AUTH_CODE_LEN: usize = 2048;
/// Longest `state` or ticket a client may send back. Both are issued by the
/// server as 32 random bytes in URL-safe base64, so 128 is generous.
pub const MAX_OPAQUE_TOKEN_LEN: usize = 128;

/// What a sign-in flow is for. A flow started to link an identity to an
/// existing account must not be completable as a sign-in, or someone who can
/// trick a user into starting a link could sign in as them instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthPurpose {
    /// Sign in, creating the account if the identity is not known yet.
    SignIn,
    /// Bind this identity to the account that is already signed in.
    Link,
}

impl OAuthPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign_in",
            Self::Link => "link",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "sign_in" => Some(Self::SignIn),
            "link" => Some(Self::Link),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthStartRequest {
    /// Loopback address the native app is listening on, e.g.
    /// `http://127.0.0.1:49152/callback`. The server checks it is a loopback
    /// address before handing it to the provider.
    pub redirect_uri: String,
    #[serde(default = "sign_in_purpose")]
    pub purpose: OAuthPurpose,
}

fn sign_in_purpose() -> OAuthPurpose {
    OAuthPurpose::SignIn
}

#[derive(Serialize, Deserialize)]
pub struct OAuthStartResponse {
    /// Open this in the system browser.
    pub authorization_url: String,
    /// Echoed back by the provider; the client returns it with the code so the
    /// server can find the attempt it belongs to.
    pub state: String,
    /// Proof that the caller is the client that began this flow.
    ///
    /// `state` and `code` both travel through the browser, so they are visible
    /// in the address bar, in history, and to anything with access to the
    /// profile. PKCE does not help: the server is the confidential client and
    /// holds the verifier, so the code is bound to the server rather than to
    /// the app that will redeem it. This is the piece that is bound to the
    /// app — handed over the client's own HTTPS connection, never placed in
    /// the authorization URL, and required again at the callback.
    pub app_secret: Zeroizing<String>,
}

impl fmt::Debug for OAuthStartResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthStartResponse")
            .field("authorization_url", &self.authorization_url)
            .field("state", &self.state)
            .field("app_secret", &REDACTED)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct OAuthCallbackRequest {
    pub state: String,
    /// The `app_secret` from [`OAuthStartResponse`].
    pub app_secret: Zeroizing<String>,
    /// Single-use, but still a credential until it is spent.
    pub code: Zeroizing<String>,
}

impl fmt::Debug for OAuthCallbackRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthCallbackRequest")
            .field("state", &self.state)
            .field("app_secret", &REDACTED)
            .field("code", &REDACTED)
            .finish()
    }
}

/// Either the identity is already bound to an account, or it is not and the
/// client has to create one. The server cannot create it alone: an account
/// needs a key pair that only a client holding a passphrase can produce.
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OAuthCallbackResponse {
    SignedIn(SessionResponse),
    RegistrationRequired {
        /// Short-lived; present it to `/oauth/register` with a fresh key pair.
        ticket: String,
        /// The provider's verified address. This becomes the account email and
        /// therefore the key-derivation salt, so the client must derive its
        /// master key from exactly this string.
        email: String,
    },
}

impl fmt::Debug for OAuthCallbackResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignedIn(session) => f.debug_tuple("SignedIn").field(session).finish(),
            Self::RegistrationRequired { email, .. } => {
                f.debug_struct("RegistrationRequired").field("ticket", &REDACTED).field("email", email).finish()
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct OAuthRegisterRequest {
    pub ticket: String,
    pub public_key: PublicKey,
    pub encrypted_private_key: Sealed,
    /// Required when the server was started with a registration token. A
    /// verified Google address is not by itself permission to have an account
    /// on someone else's server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_token: Option<String>,
}

impl fmt::Debug for OAuthRegisterRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthRegisterRequest")
            .field("ticket", &REDACTED)
            .field("public_key", &self.public_key)
            .field("registration_token", &self.registration_token.as_ref().map(|_| REDACTED))
            .finish_non_exhaustive()
    }
}

/// Change the passphrase a vault is derived from.
///
/// Everything derived from the old passphrase is replaced at once, because
/// half of it would be unrecoverable: a new credential without re-wrapped keys
/// locks the owner out of their own secrets, and re-wrapped keys without a new
/// credential do the same from the other side.
///
/// Payloads are deliberately absent. Each secret's AES key is random and does
/// not change; only the owner's wrapping of it does, so the work is
/// proportional to how many secrets are owned rather than to their size. For
/// the same reason the X25519 identity is untouched: secrets shared *with*
/// this account, and invites addressed to it, keep working.
#[derive(Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    /// Proof of the current passphrase, for an account that signs in with a
    /// password: a session alone is not enough to change that account's
    /// passphrase.
    ///
    /// A Google account has no password login and so nothing the server can
    /// check, and this is absent. For those accounts a session *is* enough to
    /// replace the stored key material, which is a destructive power a session
    /// already has — it can delete every secret — but one that leaves the
    /// vault looking intact. Closing it would mean storing a passphrase-derived
    /// verifier for Google accounts as well; see the README.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_auth_hash: Option<Zeroizing<String>>,
    /// The new credential, for accounts that sign in with a password. Absent
    /// for a Google account, whose login is not a passphrase and must not
    /// become one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_auth_hash: Option<Zeroizing<String>>,
    /// The X25519 private key re-encrypted under the new encryption key.
    pub encrypted_private_key: Sealed,
    /// Every owner copy of a secret key, re-wrapped under the new self-wrap
    /// key. Must cover exactly the secrets this account owns.
    pub rewrapped_keys: Vec<RewrappedKey>,
}

impl fmt::Debug for ChangePasswordRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangePasswordRequest")
            .field("current_auth_hash", &self.current_auth_hash.as_ref().map(|_| REDACTED))
            .field("new_auth_hash", &self.new_auth_hash.as_ref().map(|_| REDACTED))
            .field("rewrapped_keys", &self.rewrapped_keys.len())
            .finish_non_exhaustive()
    }
}

/// One secret's key, without its payload.
///
/// `GET /api/secrets` carries every payload, which is right for showing a
/// vault and wrong for re-wrapping one: at the quota that is tens of megabytes
/// of ciphertext fetched only to be dropped, over a connection that then has
/// to stay up long enough to send the answer back.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretKeyView {
    pub id: i64,
    pub key_version: i64,
    pub is_owner: bool,
    pub wrapped_key: WrappedKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RewrappedKey {
    pub secret_id: i64,
    /// The `key_version` this was re-wrapped against. A rotation that lands
    /// mid-change would leave the new owner copy holding a key that no longer
    /// opens the payload, so a mismatch is a 409 rather than a write.
    pub key_version: i64,
    /// Must be [`WrappedKey::Owner`]: nobody else can produce one.
    pub wrapped_key: WrappedKey,
}

/// What this server supports, so a client knows whether to offer the button
/// and whether to ask for a registration token before creating an account.
#[derive(Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub password_sign_in: bool,
    pub google_sign_in: bool,
    /// True when the server was started with a registration token. Clients
    /// prompt for it during signup; the server checks it regardless of what
    /// this says.
    pub registration_token_required: bool,
    /// True when the server accepts no new accounts at all.
    pub registration_closed: bool,
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
    fn a_server_built_from_this_source_is_compatible() {
        check_protocol(&Health::current()).expect("client and server from one tree must agree");
    }

    /// The case that makes this worth having: the server moved ahead, still
    /// serves this client, and nothing should stop.
    #[test]
    fn a_newer_server_that_still_serves_this_client_is_fine() {
        let health = Health { protocol: PROTOCOL_VERSION + 5, ..Health::current() };
        assert!(check_protocol(&health).is_ok());
    }

    #[test]
    fn a_server_that_has_dropped_this_client_says_so() {
        let health =
            Health { protocol: PROTOCOL_VERSION + 5, min_client_protocol: PROTOCOL_VERSION + 1, ..Health::current() };
        let error = check_protocol(&health).unwrap_err();
        assert!(matches!(error, ProtocolMismatch::ClientTooOld { .. }), "{error:?}");
        assert!(error.to_string().contains("newer credvault"), "{error}");
    }

    #[test]
    fn a_server_older_than_this_client_can_talk_to_says_so() {
        let health = Health { protocol: MIN_SERVER_PROTOCOL - 1, min_client_protocol: 0, ..Health::current() };
        let error = check_protocol(&health).unwrap_err();
        assert!(matches!(error, ProtocolMismatch::ServerTooOld { .. }), "{error:?}");
        assert!(error.to_string().contains("too old"), "{error}");
    }

    #[test]
    fn health_does_not_report_the_build_version() {
        let json = serde_json::to_string(&Health::current()).unwrap();
        assert_eq!(json, r#"{"status":"ok","protocol":1,"min_client_protocol":1}"#);
    }

    #[test]
    fn registration_token_is_optional_on_the_wire() {
        let json = r#"{"email":"a@example.com","auth_hash":"x","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","encrypted_private_key":{"v":1,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA=="}}"#;
        let request: RegisterRequest = serde_json::from_str(json).unwrap();
        assert!(request.registration_token.is_none());
    }
}
