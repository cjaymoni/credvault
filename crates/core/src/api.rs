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

/// How many projects one account may own.
///
/// A bound for the same reason [`MAX_SECRETS_PER_ACCOUNT`] is one, and far
/// below it: projects are headings over secrets, so an account that has more
/// of them than it has secrets has stopped organising anything. Well above
/// what anyone files by hand.
pub const MAX_PROJECTS_PER_ACCOUNT: i64 = 200;

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
/// 4: projects. `/projects` is new — list, create, rename, delete — a
/// secret says which project it is filed under, and `PUT
/// /secrets/{id}/project` moves one between projects without touching its
/// ciphertext or its key. An invite now says whether the person being
/// invited may also see where the secret is filed, which is off unless
/// asked for, and `POST /secrets/{id}/access/{user_id}/project` changes that
/// answer afterwards. Every change to a route that already existed is a
/// field older peers can ignore — a request they omit, or a response field
/// they do not read — which is why `MIN_CLIENT_PROTOCOL` does not move; the
/// new routes are the part a protocol-3 server does not have, and that is
/// what `MIN_SERVER_PROTOCOL` answers for.
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
pub const PROTOCOL_VERSION: u32 = 4;

/// The oldest server protocol a client built from this source will talk to.
///
/// 4, because a protocol-3 server has no `/projects` at all and answers 404
/// to every one of them.
///
/// This is the stricter kind of refusal, and worth saying plainly:
/// `check_protocol` runs before a credential is sent, so the vault does not
/// open either. It is still the right answer. Projects are not one button on
/// one sign-in path, they are the shape of the list itself: an app that
/// connected anyway would group a vault it had no way to regroup, offer a
/// panel that could not list, create or delete, and fail with a bare 404 at
/// the moment someone tried to fix it. Which side to upgrade first is in the
/// README, under Versions.
///
/// It was 3 for the reason below, which still holds and is covered by this.
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
pub const MIN_SERVER_PROTOCOL: u32 = 4;

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

/// One of the caller's own projects.
///
/// The name is stored and returned in plaintext, like a secret's name and
/// for the same reason: it is a label the interface has to draw. It is worth
/// stating what that costs, because it is new metadata -- a server operator
/// learns that this account keeps a project called Perspectiv and which of
/// its secrets are filed together. Nothing about the credentials themselves
/// changes; payloads stay sealed and keys stay wrapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectView {
    pub id: i64,
    pub name: String,
    /// How many of the caller's secrets are filed under it. Zero is a real
    /// answer: an empty project draws no heading in the vault, so this is
    /// the only place it is visible.
    pub secret_count: i64,
}

/// Where a secret is filed, told to someone who may know.
///
/// Tagged, and two shapes rather than one, because only one of the two
/// carries an id. A project id names one of the *owner's* projects: it is
/// what a move request takes, and handing it to a member would let them
/// learn which of the owner's other secrets sit beside this one by watching
/// the id repeat. A member gets the name and nothing else, and the type
/// makes that a fact about the shape rather than a rule someone has to
/// remember to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "as", rename_all = "snake_case")]
pub enum SecretProject {
    /// The viewer owns this secret, and `id` is one of their own projects.
    Own { id: i64, name: String },
    /// The viewer is a member, and the owner chose to tell them where it
    /// sits. The name is the project's name now, not a copy taken when the
    /// invite was sent, so a rename reaches everyone who may see it.
    Shared { name: String },
}

/// Create a project, or rename one.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectRequest {
    pub name: String,
}

/// Where an edit leaves the secret filed.
///
/// Three answers rather than two, and deliberately not an `Option<i64>`. An
/// `Option` cannot tell "I did not mention the project" apart from "take it
/// out of its project", and the first is what every client older than
/// protocol 4 sends with each edit it makes. [`Keep`](Self::Keep) is the
/// default, so one of those clients editing a password leaves the filing
/// alone instead of quietly emptying it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "project_id", rename_all = "snake_case")]
pub enum ProjectAssignment {
    /// Leave the secret where it is. What an absent field means.
    #[default]
    Keep,
    /// File it under no project.
    Clear,
    /// File it under this project, which must be one the caller owns.
    Set(i64),
}

/// Move a secret between projects, or out of one.
///
/// Its own request, and its own route, because refiling reads and writes no
/// ciphertext: there is no payload to re-encrypt and so no `key_version` to
/// carry. `None` means no project; the body is nothing but the assignment,
/// so there is no absent case for it to be confused with.
#[derive(Debug, Serialize, Deserialize)]
pub struct MoveSecretRequest {
    pub project_id: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSecretRequest {
    pub name: String,
    pub payload: Sealed,
    /// The secret key wrapped for the creator; must be `WrappedKey::Owner`.
    pub wrapped_key: WrappedKey,
    /// The project to file it under, if any. `default` so a client that
    /// knows nothing about projects still creates secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateSecretRequest {
    /// The `key_version` the client encrypted with; a mismatch is a 409.
    pub key_version: i64,
    pub name: String,
    pub payload: Sealed,
    /// Where this edit leaves the secret filed. Absent means leave it alone;
    /// see [`ProjectAssignment`].
    #[serde(default)]
    pub project: ProjectAssignment,
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
    /// Where this secret is filed, as far as this viewer may see.
    ///
    /// `None` means either that it is filed nowhere or that it is filed
    /// somewhere this viewer was not shown; the two are deliberately the
    /// same answer, so that a member cannot tell an unfiled secret from one
    /// whose filing was withheld. See [`SecretProject`].
    pub project: Option<SecretProject>,
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
    /// Whether this member may see which project the secret is filed under.
    /// What the owner's sharing panel draws the toggle from.
    pub sees_project: bool,
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
    /// Whether this person may also see which project the secret is filed
    /// under.
    ///
    /// Off unless asked for, and `default` so a client that knows nothing
    /// about projects shares a credential and nothing more. Sharing one
    /// password is not sharing how a vault is organised, and the quiet
    /// answer is the one that cannot be regretted. The owner can change
    /// their mind either way afterwards; see [`ShareProjectRequest`].
    #[serde(default)]
    pub share_project: bool,
}

/// Turn one member's view of a secret's project on or off after the fact.
///
/// A privacy choice that could not be taken back would not be much of a
/// choice, so the answer given at invite time is not final.
#[derive(Debug, Serialize, Deserialize)]
pub struct ShareProjectRequest {
    pub share_project: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InviteView {
    pub id: i64,
    pub secret_name: String,
    pub inviter_email: String,
    pub message: String,
    pub created_at: DateTime<Utc>,
    /// The project the secret is filed under, when the inviter chose to
    /// share that. Shown before the invite is answered, deliberately: it is
    /// part of what is being offered, and someone deciding whether to accept
    /// should see the same thing they would see afterwards. Declining does
    /// not unlearn it, which is why the inviter has to ask for it.
    pub project: Option<String>,
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

/// The longest an opaque value in [`OAuthStartResponse`] may be.
///
/// Comfortably above every real one — a base64url token of 32 bytes is 43
/// characters and the longest Google client id seen is under 80 — and low
/// enough that a value built to be a payload rather than a token is refused
/// before it reaches a browser.
pub const MAX_OPAQUE_VALUE_LEN: usize = 512;

/// Why a value is not one [`OAuthStartResponse`] may carry.
///
/// The client turns each of these into its own sentence, so they are separate
/// rather than one boolean.
#[derive(Debug, PartialEq, Eq)]
pub enum NotAnOpaqueValue {
    Empty,
    TooLong,
    /// Holds something outside the permitted set.
    BadCharacters,
}

/// Whether a value is one [`OAuthStartResponse`] may carry: non-empty, no
/// longer than [`MAX_OPAQUE_VALUE_LEN`], and spelled only in RFC 3986's
/// unreserved characters (`ALPHA / DIGIT / "-" / "." / "_" / "~"`).
///
/// This lives in core because both halves of the protocol depend on it and
/// neither can see the other: the server emits values inside this set, and the
/// client refuses values outside it before composing an authorization URL.
/// Two copies would be one base64 alphabet away from every sign-in failing
/// with the client accusing the operator's own server of hostility. The server
/// pins its side in `generated_values_satisfy_the_contract_the_client_enforces`
/// and the client pins its side in `values_that_are_not_opaque_tokens_are_refused`.
///
/// The set is the intersection of what a base64url token uses and what a
/// Google client id uses, so widening it needs a reason on both sides.
///
/// # Errors
/// [`NotAnOpaqueValue`] saying which of the three rules the value broke.
pub fn check_opaque_oauth_value(value: &str) -> Result<(), NotAnOpaqueValue> {
    if value.is_empty() {
        return Err(NotAnOpaqueValue::Empty);
    }
    // Before the length, so that the reason given for a non-ASCII value is
    // the charset rather than the length. `len()` counts bytes, so a value of
    // 300 multi-byte characters is over the limit while having fewer
    // characters than it names, and the refusal the client builds from
    // `TooLong` says "characters". Checking the charset first means only
    // all-ASCII values ever reach that message, where the two agree.
    if !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')) {
        return Err(NotAnOpaqueValue::BadCharacters);
    }
    if value.len() > MAX_OPAQUE_VALUE_LEN {
        return Err(NotAnOpaqueValue::TooLong);
    }
    Ok(())
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
///
/// Every field but `app_secret` reaches an authorization URL, and each one
/// must satisfy [`check_opaque_oauth_value`]. That is the contract a server
/// implementing this endpoint has to meet, and the client enforces it.
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
        assert_eq!(PROTOCOL_VERSION, 4);
        assert_eq!(MIN_SERVER_PROTOCOL, 4);
        assert_eq!(MIN_CLIENT_PROTOCOL, 1);
    }

    /// The property the three-state assignment exists for.
    ///
    /// A protocol-3 client edits a secret by sending the four fields it knows
    /// about and nothing else. If that read as "unfile it", every edit made
    /// from an app one release behind would silently empty the filing of the
    /// secret it touched, and the user would find out by looking at a vault
    /// that had quietly reorganised itself.
    #[test]
    fn an_edit_that_does_not_mention_the_project_leaves_it_alone() {
        let json =
            r#"{"key_version":0,"name":"Cloudflare","payload":{"v":1,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA=="}}"#;
        let request: UpdateSecretRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.project, ProjectAssignment::Keep);
    }

    #[test]
    fn the_three_assignments_are_distinct_on_the_wire() {
        for assignment in [ProjectAssignment::Keep, ProjectAssignment::Clear, ProjectAssignment::Set(7)] {
            let json = serde_json::to_string(&assignment).unwrap();
            let back: ProjectAssignment = serde_json::from_str(&json).unwrap();
            assert_eq!(back, assignment, "{json}");
        }
        assert_eq!(serde_json::to_string(&ProjectAssignment::Clear).unwrap(), r#"{"action":"clear"}"#);
        assert_eq!(serde_json::to_string(&ProjectAssignment::Set(7)).unwrap(), r#"{"action":"set","project_id":7}"#);
    }

    /// Sharing a credential must not quietly share the shape of the vault it
    /// came from, so the flag that does is off unless the inviter asked for
    /// it -- including when the inviter is an app that has never heard of
    /// projects.
    #[test]
    fn an_invite_shares_no_project_unless_it_says_so() {
        let json = r#"{"key_version":0,"email":"bob@example.com","fingerprint":"AAAA","wrapped_key":{"ephemeral_public":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","v":1,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA=="}}"#;
        let request: InviteRequest = serde_json::from_str(json).unwrap();
        assert!(!request.share_project);
        assert!(request.message.is_empty());
    }

    /// A member's view of a project carries a name and no id. The id would
    /// let them watch it repeat across the secrets they hold and work out
    /// which of the owner's others sit together.
    #[test]
    fn only_an_owner_gets_a_project_id() {
        let shared = serde_json::to_string(&SecretProject::Shared { name: "Perspectiv".into() }).unwrap();
        assert_eq!(shared, r#"{"as":"shared","name":"Perspectiv"}"#);
        let own = serde_json::to_string(&SecretProject::Own { id: 3, name: "Perspectiv".into() }).unwrap();
        assert_eq!(own, r#"{"as":"own","id":3,"name":"Perspectiv"}"#);
    }

    /// The other half of the same guarantee, on the other route: a client
    /// that does not know about projects creates unfiled secrets rather than
    /// failing to create any.
    #[test]
    fn the_project_is_optional_when_creating_a_secret() {
        let json = r#"{"name":"Cloudflare","payload":{"v":1,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA=="},"wrapped_key":{"wrap":"owner","key":{"v":1,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AA=="}}}"#;
        let request: CreateSecretRequest = serde_json::from_str(json).unwrap();
        assert!(request.project_id.is_none());
    }

    /// The set is the intersection of what the server's base64url tokens use
    /// and what a Google client id uses. Both ends of that intersection are
    /// pinned here, because widening it weakens the client's second layer and
    /// narrowing it refuses values a correct server sends.
    #[test]
    fn an_opaque_oauth_value_is_a_token_or_a_client_id_and_nothing_else() {
        for ok in [
            // A `random_token()` output: 32 bytes of base64url, 43 characters.
            "G844yM5uFc7EGLBZZiEUXkEKMUQIsMUUVEZQIeSx4Yg",
            "1234567890-abcdef.apps.googleusercontent.com", // a Google client id
            "with-dashes_and_underscores.and~tildes",
            &"x".repeat(MAX_OPAQUE_VALUE_LEN),
        ] {
            assert_eq!(check_opaque_oauth_value(ok), Ok(()), "{ok} is a value a correct server sends");
        }

        assert_eq!(check_opaque_oauth_value(""), Err(NotAnOpaqueValue::Empty));
        assert_eq!(check_opaque_oauth_value(&"x".repeat(MAX_OPAQUE_VALUE_LEN + 1)), Err(NotAnOpaqueValue::TooLong));
        // 300 characters, 600 bytes: over the byte limit, under the count the
        // `TooLong` sentence would name. The charset is the true reason, and
        // this is the only case that tells the two orderings apart — without
        // it the check order above is free to drift back.
        assert_eq!(check_opaque_oauth_value(&"é".repeat(300)), Err(NotAnOpaqueValue::BadCharacters));
        for bad in [
            "has space",
            "padded=",     // base64 standard alphabet
            "slash/plus+", // the other two standard-alphabet characters
            "&scope=https://www.googleapis.com/auth/drive",
            "javascript:alert(1)",
            "percent%2Fencoded", // already encoded, so encoding it again changes it
            "new\nline",
            "unicodé",
        ] {
            assert_eq!(check_opaque_oauth_value(bad), Err(NotAnOpaqueValue::BadCharacters), "{bad} must be refused");
        }
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
