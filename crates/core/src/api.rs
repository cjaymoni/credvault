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

/// How many unanswered invites one account may be sent in total.
///
/// Higher than the per-inviter cap, because being invited by many people is
/// legitimate in a way that inviting many people at once is not.
pub const MAX_PENDING_INVITES_RECEIVED: i64 = 500;

/// How many unanswered invites one account may have waiting for one other
/// account.
///
/// This is the cap that matters for abuse. Without it the ceiling above is
/// reachable by a handful of accounts — five, at the per-inviter cap — each
/// staying inside its own budget, and the victim's invite list is then closed
/// to everyone until they work through hundreds of entries by hand.
///
/// Set above what one legitimate burst looks like: handing a new colleague the
/// credentials they need is a dozen or two in a sitting, and that must not hit
/// a wall. At this value it takes twenty accounts to fill someone's list
/// rather than five, and no single account can take more than a twentieth.
pub const MAX_PENDING_INVITES_PER_PAIR: i64 = 25;

const REDACTED: &str = "<redacted>";

// ----- protocol version -------------------------------------------------------

/// Version of the wire protocol spoken between a client and a server.
///
/// Bump it when a change would make a peer get an answer *wrong*: a field
/// whose meaning moved, an endpoint whose contract changed, a response an
/// older client would misread. A field that older peers can ignore safely is
/// additive and needs no bump.
///
/// 2 was never tagged, but `main` has served it since it merged, so a build
/// speaking it can be running somewhere. That is the condition the paragraph
/// under 2 set for the next change being a 3 rather than an edit to 2.
///
/// 3: `/oauth/start` answers with the parts of an authorization request —
/// `client_id`, `nonce` and `code_challenge` — where it answered with a
/// finished `authorization_url`. The client composes the URL itself, so the
/// endpoint, the scheme, the host, the scope and the prompt are its own
/// constants rather than the server's choice. See F-12 in the security audit.
///
/// 2: `/oauth/link` gained a required `current_auth_hash` and now answers with
/// a profile where it answered `204`; `/oauth/unlink` is new and answers with
/// a fresh session, because removing a link ends every session the link could
/// have minted; `DELETE /sessions` answers with a fresh session too, and now
/// spares the caller's rather than ending it, so the request that evicts
/// someone can be followed immediately by the one that locks them out.
pub const PROTOCOL_VERSION: u32 = 3;

/// The oldest server protocol a client built from this source will talk to.
///
/// 3, because a protocol-2 server answers `/oauth/start` with a finished URL
/// and none of the three values this client needs to build one. The response
/// does not deserialise, and the sign-in fails somewhere with nothing useful
/// to say about which side is behind.
///
/// There is deliberately no fallback to the old `authorization_url`. A client
/// that used the server's URL whenever the new fields were absent could be
/// put back on that path by a server that simply left them out, and the whole
/// of what protocol 3 removes is the server's say over where the browser
/// goes. A property a server can talk you out of is not one.
///
/// It was 2 for the reason below, which still holds and is covered by this.
/// A protocol-1 server answers the link request *successfully* and the client
/// cannot tell: the old handler takes the callback fields, ignores the
/// `current_auth_hash` it does not know about, writes the identity row and
/// answers `204`; the client then fails to read a profile out of an empty
/// body and reports that linking failed. The link exists, the account holder
/// believes it does not, that server returns no `google_email` so nothing
/// displays it, and it has no `/oauth/unlink` to remove it with — which is
/// the invisible, unremovable, standalone credential F-13 exists to prevent,
/// reached by nothing worse than updating the app before the server.
///
/// Refusing at `check_protocol` says so before any credential is sent, which
/// is what that path is for.
pub const MIN_SERVER_PROTOCOL: u32 = 3;

/// The oldest client protocol a server built from this source still serves.
///
/// Raising this locks out installed clients, so it moves only when serving
/// them would be wrong rather than merely inconvenient. Still 1.
///
/// An older client fails at `/oauth/start`, where the answer no longer
/// carries the `authorization_url` it looks for, and a protocol-1 client
/// fails at `/oauth/link` as it already did, because that handler requires a
/// `current_auth_hash` it does not send. Everything else works, including
/// unlocking the vault — which is why raising this would be the worse trade:
/// it would lock those clients out of their secrets to spare them an error on
/// one route.
///
/// Both failures are sign-ins that do not happen, which is the safe
/// direction: unlike the link request that moved this file's other minimum,
/// nothing is written and nothing is believed. What it costs an operator
/// mid-upgrade is written down in the README, under Versions.
pub const MIN_CLIENT_PROTOCOL: u32 = 1;

// A build where either minimum has overtaken the version it was raised
// alongside is a build that refuses its own counterpart from the same tree.
const _: () = assert!(MIN_SERVER_PROTOCOL <= PROTOCOL_VERSION, "this client could not talk to its own server");
const _: () = assert!(MIN_CLIENT_PROTOCOL <= PROTOCOL_VERSION, "this server would refuse its own client");

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
    /// The Google address linked to this account, if there is one.
    ///
    /// Carried so a link can be seen and removed. A sign-in credential that
    /// nothing displays is one the account holder cannot notice has been
    /// added, and this one outlives both a passphrase change and a
    /// sign-out-everywhere.
    #[serde(default)]
    pub google_email: Option<String>,
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

/// The parts of an authorization request that the client cannot know, and
/// nothing else.
///
/// This used to carry the finished `authorization_url` and the client checked
/// it before opening it. The client now composes it from its own constants,
/// so the endpoint, the scheme, the host, the scope and the prompt are no
/// longer the server's to choose — not the page the browser opens, not the
/// permissions it asks for, and not whether an account chooser is shown. The
/// three values below are opaque to both sides; see F-12 in the security
/// audit for what that leaves a hostile server, which is not nothing.
#[derive(Serialize, Deserialize)]
pub struct OAuthStartResponse {
    /// The OAuth client the server is registered with at the provider. Not a
    /// secret — it travels in the authorization URL — and not something the
    /// client can pin, because the registration belongs to whoever runs the
    /// server.
    pub client_id: String,
    /// Echoed back by the provider; the client returns it with the code so the
    /// server can find the attempt it belongs to.
    pub state: String,
    /// Bound into the id token and checked by the server when the code is
    /// exchanged. The client only carries it.
    pub nonce: String,
    /// The public half of the server's PKCE pair. The server keeps the
    /// verifier because the server is the confidential client that redeems the
    /// code, which is why this does not bind the flow to the app and
    /// `app_secret` has to.
    pub code_challenge: String,
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
            .field("client_id", &self.client_id)
            .field("state", &self.state)
            .field("nonce", &self.nonce)
            .field("code_challenge", &self.code_challenge)
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

/// Finishing a link: the callback, plus proof of the account passphrase.
///
/// The proof is what separates this from every other authenticated call. A
/// link is a second, standalone way into the account, so a session alone must
/// not be enough to create one — for the same reason a session alone cannot
/// change the passphrase. See [`ChangePasswordRequest::current_auth_hash`].
///
/// The callback's three fields are spelled out here rather than flattened in
/// from [`OAuthCallbackRequest`]. `#[serde(flatten)]` deserializes through
/// serde's buffering path, which collects every field it did not match by
/// name into a plain `String` first — so `app_secret` and `code` would each
/// get an un-zeroized heap copy on the way in, on the one route that also
/// carries a passphrase proof. The JSON on the wire is identical either way.
#[derive(Serialize, Deserialize)]
pub struct OAuthLinkRequest {
    pub state: String,
    /// The `app_secret` from [`OAuthStartResponse`].
    pub app_secret: Zeroizing<String>,
    /// Single-use, but still a credential until it is spent.
    pub code: Zeroizing<String>,
    /// Proof of the current passphrase, for an account that signs in with a
    /// password. A Google account has no password login and so nothing the
    /// server can check, and this is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_auth_hash: Option<Zeroizing<String>>,
}

impl OAuthLinkRequest {
    /// Finish a link begun by [`OAuthStartRequest`], proving the passphrase.
    pub fn new(callback: OAuthCallbackRequest, current_auth_hash: Option<Zeroizing<String>>) -> Self {
        let OAuthCallbackRequest { state, app_secret, code } = callback;
        Self { state, app_secret, code, current_auth_hash }
    }

    /// The callback half, for the code path that redeems it.
    pub fn callback(&self) -> OAuthCallbackRequest {
        OAuthCallbackRequest { state: self.state.clone(), app_secret: self.app_secret.clone(), code: self.code.clone() }
    }
}

impl fmt::Debug for OAuthLinkRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthLinkRequest")
            .field("state", &self.state)
            .field("app_secret", &REDACTED)
            .field("code", &REDACTED)
            .field("current_auth_hash", &self.current_auth_hash.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// Removing a link. Proof of the passphrase is required here too: removing a
/// credential is as much a credential change as adding one.
#[derive(Serialize, Deserialize)]
pub struct OAuthUnlinkRequest {
    pub current_auth_hash: Zeroizing<String>,
}

impl fmt::Debug for OAuthUnlinkRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthUnlinkRequest").field("current_auth_hash", &REDACTED).finish()
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
    /// Carried so that a refusal can name the secret it is about. The name is
    /// plaintext on the server already, so this reveals nothing `/secrets`
    /// does not.
    pub name: String,
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

    /// A tripwire, not a tautology.
    ///
    /// Every endpoint contract this version describes is written down on
    /// `PROTOCOL_VERSION` itself. Changing one without moving the constant is
    /// the mistake that ships a server older clients silently misread, and it
    /// has happened once already. Failing here makes the bump a deliberate
    /// two-line edit rather than something to remember.
    #[test]
    fn the_protocol_numbers_are_what_this_source_documents() {
        assert_eq!(PROTOCOL_VERSION, 3);
        assert_eq!(MIN_SERVER_PROTOCOL, 3);
        assert_eq!(MIN_CLIENT_PROTOCOL, 1);
    }

    #[test]
    fn health_does_not_report_the_build_version() {
        // Spelled out from the constants rather than hardcoded: the point of
        // this test is which fields are on the wire, and it should not need
        // editing every time one of the numbers moves.
        let json = serde_json::to_string(&Health::current()).unwrap();
        assert_eq!(
            json,
            format!(r#"{{"status":"ok","protocol":{PROTOCOL_VERSION},"min_client_protocol":{MIN_CLIENT_PROTOCOL}}}"#)
        );
    }

    #[test]
    fn registration_token_is_optional_on_the_wire() {
        let json = r#"{"email":"a@example.com","auth_hash":"x","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","encrypted_private_key":{"v":1,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA=="}}"#;
        let request: RegisterRequest = serde_json::from_str(json).unwrap();
        assert!(request.registration_token.is_none());
    }
}
