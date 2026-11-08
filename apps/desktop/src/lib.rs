//! credvault app: a Tauri shell around credvault-core, built as a library so the
//! desktop binary and the iOS/Android shells share one entry point. All encryption and
//! decryption happens here; the server only ever receives ciphertext.

mod client;
mod known_keys;
mod oauth_listener;

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use credvault_core::aead::KEY_LEN;
use credvault_core::api::*;
use credvault_core::identity::{normalize_fingerprint, FINGERPRINT_HEX_LEN};
use credvault_core::kdf::ServerAddress;
use credvault_core::secret::CustomField;
use credvault_core::{kdf, password, secret, Identity, MasterKey, PublicKey, SecretKey, SecretPayload, WrappedKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_opener::OpenerExt;
use zeroize::Zeroizing;

use client::{ApiClient, ClientError};
use known_keys::{KeyStatus, KnownKeys};
use oauth_listener::RedirectListener;

/// How long a copied password stays on the clipboard before it is wiped.
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
const KNOWN_KEYS_FILE: &str = "known_keys.json";
/// The server starts every secret at this key version.
const NEW_SECRET_KEY_VERSION: i64 = 0;

/// What the UI needs to know about the logged-in user.
#[derive(Clone, Serialize)]
struct UserSummary {
    email: String,
    server_url: String,
    /// Shown so the user can read it to people who want to share with them.
    fingerprint: String,
    /// Whether changing the passphrase also changes how this account signs in.
    password_login: bool,
    /// The linked Google address, if any, so the UI can show that a second
    /// way into this account exists.
    google_email: Option<String>,
}

/// A secret with everything except the password decrypted for display. If
/// `error` is set the item could not be decrypted; the other decrypted fields
/// are empty and the UI offers to remove it.
#[derive(Clone, Serialize)]
struct SecretSummary {
    id: i64,
    name: String,
    username: String,
    url: String,
    notes: String,
    fields: Vec<FieldSummary>,
    is_owner: bool,
    owner_email: String,
    updated_at: chrono::DateTime<chrono::Utc>,
    error: Option<String>,
}

/// A custom field as the list shows it. The value of a field the user marked
/// sensitive is withheld, exactly as the password is, and fetched only when
/// they ask to see or copy that one field.
#[derive(Clone, Serialize)]
struct FieldSummary {
    id: String,
    label: String,
    /// Whether a sensitive field has anything stored. The value itself is
    /// withheld, but without this the editor cannot tell "hidden, with a
    /// value you have not seen" from "hidden and empty", and would refuse
    /// to un-hide the second on the grounds that it would erase something.
    has_value: bool,
    /// Empty for a sensitive field, whatever is stored otherwise.
    value: String,
    secret: bool,
}

/// A custom field as the edit form submits it. A `value` of `None` means
/// "keep what is stored for this id", the way a blank password box means
/// "keep the password". `id` is `None` only for a row the user just added.
#[derive(Clone, Deserialize)]
struct FieldInput {
    #[serde(default)]
    id: Option<String>,
    label: String,
    value: Option<String>,
    #[serde(default)]
    secret: bool,
}

/// Everything the new/edit form submits, in one piece so creating and editing
/// take the same shape and neither grows an unreadable argument list.
#[derive(Clone, Deserialize)]
struct SecretForm {
    name: String,
    username: String,
    /// Required when creating. On an edit, `None` keeps the stored password
    /// without it ever passing through the UI.
    password: Option<Zeroizing<String>>,
    #[serde(default)]
    url: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    fields: Vec<FieldInput>,
}

fn field_summaries(payload: &SecretPayload) -> Vec<FieldSummary> {
    payload
        .fields
        .iter()
        .map(|field| FieldSummary {
            id: field.id.clone(),
            label: field.label.clone(),
            has_value: !field.value.is_empty(),
            value: if field.secret { String::new() } else { field.value.clone() },
            secret: field.secret,
        })
        .collect()
}

/// Turn submitted fields into the ones to store. A field submitted without a
/// value keeps the value stored under the same id; if there is none to keep,
/// that is an error rather than a field silently emptied of a recovery code
/// the user believed was still there.
fn resolve_fields(submitted: Vec<FieldInput>, stored: &[CustomField]) -> CommandResult<Vec<CustomField>> {
    let mut resolved: Vec<CustomField> = Vec::with_capacity(submitted.len());
    for field in submitted {
        let kept = field.id.as_deref().and_then(|id| stored.iter().find(|f| f.id == id));
        // Named by whatever it is stored as, because a row that lost its label
        // may be standing for a value nobody can see and could not retype.
        let label = secret::validate_label(&field.label).map_err(|error| match kept {
            Some(kept) if field.label.trim().is_empty() => {
                CommandError::new("crypto", format!("enter a label for the field stored as \"{}\"", kept.label))
            }
            _ => user_facing(error),
        })?;
        let value = match field.value {
            Some(value) => value,
            // Found by id: the only thing that still means the same field
            // after another device has renamed or reordered the others.
            None => match kept {
                // Keeping a value only makes sense while it stays hidden. The
                // editor cannot produce this pair, but the rule the whole
                // design rests on should not be enforced only in the half
                // that does not write the payload: copying an unseen value
                // into a now-visible field would publish it to the list, and
                // to everyone the secret is shared with.
                Some(kept) if kept.secret && !field.secret && !kept.value.is_empty() => {
                    return Err(CommandError::new(
                        "field_value_required",
                        format!(
                        "enter a value for \"{label}\": it was never shown here, so it cannot be un-hidden without one"
                    ),
                    ))
                }
                Some(kept) => kept.value.clone(),
                None => {
                    return Err(CommandError::new("field_value_required", format!("enter a value for \"{label}\"")))
                }
            },
        };
        // A row the user just added has no id yet; an existing one keeps its own.
        let id = field.id.unwrap_or_else(secret::new_field_id);
        if resolved.iter().any(|f| f.id == id) {
            return Err(CommandError::new("duplicate_field", format!("\"{label}\" was sent twice")));
        }
        resolved.push(CustomField { id, label, value, secret: field.secret });
    }
    Ok(resolved)
}

/// Result of looking someone up before inviting them. `public_key` is what the
/// UI hands back on confirmation, so the command can compare whole keys.
#[derive(Clone, Serialize)]
struct InviteeInfo {
    email: String,
    fingerprint: String,
    public_key: String,
    #[serde(flatten)]
    status: KeyStatus,
}

/// A member the user confirmed by fingerprint; the command checks the bytes.
#[derive(Clone, Deserialize)]
struct ConfirmedKey {
    user_id: i64,
    public_key: String,
}

/// A remaining member whose key this device has not confirmed yet.
#[derive(Debug, Clone, Serialize)]
struct UnconfirmedMember {
    user_id: i64,
    email: String,
    fingerprint: String,
    public_key: String,
    #[serde(flatten)]
    status: KeyStatus,
}

#[derive(Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RevokeOutcome {
    Done {
        cancelled_invites: u64,
    },
    /// Nothing was changed; the UI must show these fingerprints and call again
    /// with the ones the user confirmed.
    Confirm {
        members: Vec<UnconfirmedMember>,
    },
}

/// Limits the UI enforces before calling a command, served from the crate that
/// owns them so the two never drift apart.
#[derive(Clone, Serialize)]
struct UiConstants {
    min_password_length: usize,
    max_message_length: usize,
    generated_password_length: usize,
    max_custom_fields: usize,
    max_label_length: usize,
    max_field_length: usize,
}

struct Session {
    api: ApiClient,
    user_id: i64,
    email: String,
    identity: Identity,
    /// Wraps our own copies of secret keys; only we can derive it, so the
    /// server cannot forge an owner copy.
    self_wrap_key: Zeroizing<[u8; KEY_LEN]>,
    /// Decrypted secret keys from the last list, so reveal/update need no re-unwrap.
    keys: HashMap<i64, LoadedKey>,
    /// Whether the passphrase is also this account's server credential. False
    /// for an account created through Google, whose passphrase derives the
    /// vault keys but is not a login.
    password_login: bool,
    /// The Google address that can sign in to this account, if one is linked.
    /// Kept so the UI can show a second way in exists and offer to remove it.
    google_email: Option<String>,
}

/// A secret's unwrapped key with the server's key version it came from. Writes
/// echo the version, so a rotation by another device is refused (409) instead
/// of silently re-encrypting under a key a revoked member still holds.
struct LoadedKey {
    key: SecretKey,
    version: i64,
}

/// A Google sign-in that has got as far as the server but cannot finish
/// until the user supplies a passphrase: Google proves who they are, and only
/// the passphrase produces the key that opens the vault.
enum PendingGoogle {
    /// The account exists. The passphrase decrypts the stored private key.
    Unlock { api: ApiClient, session: SessionResponse },
    /// No account yet. The passphrase becomes a new master key, and the key
    /// pair derived from it is what finally creates the account.
    CreateAccount { api: ApiClient, ticket: String, email: String },
}

impl PendingGoogle {
    fn email(&self) -> &str {
        match self {
            Self::Unlock { session, .. } => &session.user.email,
            Self::CreateAccount { email, .. } => email,
        }
    }
}

/// What the UI should ask for next after the browser step.
#[derive(Clone, Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
enum GoogleSignInStage {
    /// Existing account: ask for the passphrase that unlocks it.
    Unlock { email: String },
    /// New account: ask for a passphrase to create, and a registration token
    /// if the server wants one.
    CreateAccount { email: String, registration_token_required: bool },
}

struct AppState {
    session: Mutex<Option<Session>>,
    /// Set between the browser step of a Google sign-in and the passphrase
    /// that completes it. Held here rather than handed to the UI so the
    /// server session token and the registration ticket stay in Rust.
    pending_google: Mutex<Option<PendingGoogle>>,
    known_keys: Mutex<KnownKeys>,
    known_keys_path: PathBuf,
    /// Bumped on every copy; a clear task only fires if it is still current.
    clipboard_generation: AtomicU64,
    /// Digest of the last value copied, until it is cleared, so "Clear now"
    /// can wipe the clipboard early without the value itself being kept.
    copied_digest: Mutex<Option<[u8; 32]>>,
    startup_warnings: Mutex<Vec<String>>,
}

impl AppState {
    fn new(known_keys_path: PathBuf) -> std::io::Result<Self> {
        let (known_keys, warning) = load_known_keys_or_recover(&known_keys_path)?;
        Ok(Self {
            session: Mutex::new(None),
            pending_google: Mutex::new(None),
            known_keys: Mutex::new(known_keys),
            known_keys_path,
            clipboard_generation: AtomicU64::new(0),
            copied_digest: Mutex::new(None),
            startup_warnings: Mutex::new(warning.into_iter().collect()),
        })
    }
}

/// A corrupt pin file must not stop the app from starting; it is moved aside
/// (never silently discarded) and the user is told their pins are gone.
fn load_known_keys_or_recover(path: &Path) -> std::io::Result<(KnownKeys, Option<String>)> {
    match KnownKeys::load(path) {
        Ok(known) => Ok((known, None)),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            let aside = path.with_extension(format!("json.corrupt-{}", chrono::Utc::now().format("%Y%m%d%H%M%S")));
            std::fs::rename(path, &aside)?;
            tracing::warn!(%error, moved_to = %aside.display(), "known keys file was unreadable");
            let warning = format!(
                "The saved key fingerprints could not be read and were moved to {}. People you confirmed before \
                 will need confirming again.",
                aside.display()
            );
            Ok((KnownKeys::default(), Some(warning)))
        }
        Err(error) => Err(error),
    }
}

/// Errors cross the IPC boundary as `{ code, message }` so the UI can branch
/// on `code` instead of matching message text.
#[derive(Debug, Clone, Serialize)]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
    /// How long until a throttled request is worth retrying. Carried so the
    /// UI can compose its own sentence from the number instead of quoting the
    /// server's, which in this threat model is a string the adversary chooses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

impl CommandError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), retry_after_secs: None }
    }

    /// The one code that carries a wait. A constructor rather than a builder
    /// on the general type, so a wait cannot be attached to a code that does
    /// not mean one, and nothing raises `throttled` without going through
    /// here. `new("throttled", …)` would still compile; this makes the right
    /// thing the easy one rather than the only one.
    fn throttled(message: impl Into<String>, retry_after_secs: Option<u64>) -> Self {
        Self { code: "throttled", message: message.into(), retry_after_secs }
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<String> for CommandError {
    fn from(message: String) -> Self {
        Self::new("error", message)
    }
}

impl From<&str> for CommandError {
    fn from(message: &str) -> Self {
        Self::new("error", message)
    }
}

impl From<ClientError> for CommandError {
    fn from(error: ClientError) -> Self {
        if let ClientError::TooManyRequests { retry_after_secs, .. } = &error {
            let retry_after_secs = *retry_after_secs;
            return Self::throttled(error.to_string(), retry_after_secs);
        }
        let code = match error {
            ClientError::Network(_) => "network",
            ClientError::Server(_) => "server",
            ClientError::NotFound(_) => "not_found",
            ClientError::Conflict(_) => "conflict",
            ClientError::Unauthorized => "unauthorized",
            // Handled above, where the wait travels with the code.
            ClientError::TooManyRequests { .. } => "throttled",
            ClientError::InvalidUrl(_) => "invalid_url",
            ClientError::Incompatible(_) => "incompatible",
        };
        Self::new(code, error.to_string())
    }
}

type CommandResult<T> = Result<T, CommandError>;

fn user_facing(error: credvault_core::CryptoError) -> CommandError {
    CommandError::new("crypto", error.to_string())
}

/// Explain why a vault would not open.
///
/// A wrong passphrase and a vault written under a scheme this build does not
/// implement are different problems with different answers, and only the first
/// is fixed by typing more carefully. Collapsing both into "wrong passphrase"
/// would send someone hunting for a typo in a passphrase that was correct;
/// collapsing both into "your data may be corrupted" is worse still. The
/// format tags carried by every stored blob are what make the two tellable
/// apart, so this is where that distinction has to be spent.
fn unlock_failure(error: credvault_core::CryptoError, wrong_passphrase: &str) -> CommandError {
    use credvault_core::CryptoError;
    match error {
        CryptoError::Decrypt => CommandError::new("locked", wrong_passphrase),
        CryptoError::NewerFormat { .. } | CryptoError::UnknownFormat { .. } => user_facing(error),
        other => CommandError::new("locked", format!("could not unlock your keys: {other}")),
    }
}

/// Derive the master key on a blocking thread; Argon2 takes a few hundred ms.
async fn derive_master(password: Zeroizing<String>, email: String) -> CommandResult<MasterKey> {
    tokio::task::spawn_blocking(move || MasterKey::derive(&password, &email))
        .await
        .map_err(|e| format!("key derivation task failed: {e}"))?
        .map_err(user_facing)
}

fn with_session<T>(state: &AppState, f: impl FnOnce(&mut Session) -> CommandResult<T>) -> CommandResult<T> {
    let mut guard = state.session.lock().map_err(|_| "session lock poisoned".to_string())?;
    let session = guard.as_mut().ok_or_else(|| "not logged in".to_string())?;
    f(session)
}

/// [`with_session`], but only if the open session is still `user_id`'s.
///
/// Every command that reads the session, awaits something slow, and then
/// writes the answer back goes through this. The session can be replaced while
/// the slow part runs — a browser round trip, a passphrase change that
/// re-wraps a large vault — and writing one account's answer onto another
/// account's session ranges from a wrong label to a wrap key that locks an
/// account out of its own secrets.
///
/// # Errors
/// `locked` if nothing is unlocked, or if the session is now someone else's.
fn with_same_session<T>(
    state: &AppState,
    user_id: i64,
    f: impl FnOnce(&mut Session) -> CommandResult<T>,
) -> CommandResult<T> {
    with_session(state, |session| {
        if session.user_id != user_id {
            return Err(CommandError::new("locked", "you signed in as someone else while that was in flight"));
        }
        f(session)
    })
}

/// Open a client for `server` and refuse to go on if this build and that
/// server do not speak the same protocol.
///
/// Every command that reaches a server for the first time goes through here,
/// so a mismatch is reported once, plainly, before a passphrase is typed or a
/// credential is sent — rather than as whatever confusing failure the first
/// real request happens to produce.
async fn connect(server: &ServerAddress) -> CommandResult<ApiClient> {
    let api = ApiClient::new(server.as_str())?;
    api.check_protocol().await?;
    Ok(api)
}

/// Clone the API handle out of the session so async work does not hold the lock.
fn api(state: &AppState) -> CommandResult<ApiClient> {
    with_session(state, |s| Ok(s.api.clone()))
}

/// Canonicalise the server address and apply this client's transport policy.
///
/// Canonical form comes from [`ServerAddress`], which is also what the auth
/// hash is derived from, so the address shown in the UI, the address keys are
/// pinned against, and the address the credential is bound to are the same
/// string. On top of that: `http://` only for loopback hosts, because the auth
/// hash is a reusable login credential and must never cross a network in the
/// clear.
fn normalize_server_url(url: &str) -> CommandResult<ServerAddress> {
    let address = ServerAddress::parse(url).map_err(user_facing)?;
    let parsed = url::Url::parse(address.as_str()).map_err(|e| format!("invalid server URL: {e}"))?;
    let is_loopback = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err("server URL must include a host".into()),
    };
    if parsed.scheme() == "http" && !is_loopback {
        return Err("http:// is only allowed for localhost; use https:// for a remote server so your login \
                    credential is not sent in the clear"
            .into());
    }
    Ok(address)
}

// ----- account commands -------------------------------------------------------

#[tauri::command]
async fn register(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
    password: Zeroizing<String>,
    registration_token: Option<String>,
) -> CommandResult<UserSummary> {
    let server_url = normalize_server_url(&server_url)?;
    // The length floor applies here and nowhere else: logging in must keep
    // working for an account created under an older, shorter floor.
    kdf::validate_new_password(&password).map_err(user_facing)?;
    // Before the key derivation, not after: Argon2 takes a few hundred ms, and
    // there is no reason to spend them on a server that cannot be used.
    let api = connect(&server_url).await?;
    let master = derive_master(password, email.clone()).await?;
    let identity = Identity::generate();
    let session = api
        .register(&RegisterRequest {
            email: email.clone(),
            auth_hash: master.auth_hash(&server_url),
            public_key: identity.public_key().clone(),
            encrypted_private_key: identity.encrypt_private_key(&master.private_key_encryption_key()),
            registration_token: registration_token.filter(|token| !token.trim().is_empty()),
        })
        .await?;
    install_session(
        &state,
        api.with_token(&session.token),
        AccountFacts::of(&session.user),
        identity,
        master.self_wrap_key(),
    )
}

#[tauri::command]
async fn login(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
    password: Zeroizing<String>,
) -> CommandResult<UserSummary> {
    let server_url = normalize_server_url(&server_url)?;
    let api = connect(&server_url).await?;
    let master = derive_master(password, email.clone()).await?;
    let session = api.login(&LoginRequest { email, auth_hash: master.auth_hash(&server_url) }).await?;
    let identity =
        Identity::decrypt_private_key(&master.private_key_encryption_key(), &session.user.encrypted_private_key)
            .map_err(|error| unlock_failure(error, "that password does not unlock this vault"))?;
    install_session(
        &state,
        api.with_token(&session.token),
        AccountFacts::of(&session.user),
        identity,
        master.self_wrap_key(),
    )
}

fn summary_of(session: &Session) -> UserSummary {
    UserSummary {
        email: session.email.clone(),
        server_url: session.api.base_url().to_string(),
        fingerprint: session.identity.public_key().fingerprint(),
        password_login: session.password_login,
        google_email: session.google_email.clone(),
    }
}

/// What the server says about an account, as a session needs it. Grouped so
/// the four places that install a session pass one value they all have rather
/// than a growing row of positional arguments.
struct AccountFacts {
    user_id: i64,
    email: String,
    password_login: bool,
    google_email: Option<String>,
}

impl AccountFacts {
    fn of(profile: &UserProfile) -> Self {
        Self {
            user_id: profile.id,
            email: profile.email.clone(),
            password_login: profile.password_login,
            google_email: profile.google_email.clone(),
        }
    }
}

fn install_session(
    state: &AppState,
    api: ApiClient,
    account: AccountFacts,
    identity: Identity,
    self_wrap_key: Zeroizing<[u8; KEY_LEN]>,
) -> CommandResult<UserSummary> {
    let AccountFacts { user_id, email, password_login, google_email } = account;
    let session =
        Session { api, user_id, email, identity, self_wrap_key, keys: HashMap::new(), password_login, google_email };
    let summary = summary_of(&session);
    let mut guard = state.session.lock().map_err(|_| "session lock poisoned".to_string())?;
    *guard = Some(session);
    Ok(summary)
}

#[tauri::command]
async fn logout(state: State<'_, AppState>) -> CommandResult<()> {
    let api = match api(&state) {
        Ok(api) => api,
        Err(_) => return Ok(()),
    };
    // Best effort: the local session is dropped regardless of server reachability.
    if let Err(error) = api.logout().await {
        tracing::warn!(%error, "server-side logout failed; dropping local session anyway");
    }
    let mut guard = state.session.lock().map_err(|_| "session lock poisoned".to_string())?;
    *guard = None;
    drop(guard);
    clear_pending_google(&state);
    Ok(())
}

/// End every session for this account except this one, which is replaced.
///
/// The move to make first when someone else may be signed in. Every
/// per-account budget can be emptied by whoever already holds a session for
/// that account, so the route that evicts them carries no per-account budget —
/// only one keyed by address, which the evicted party cannot spend on the
/// owner's behalf. It answers when the rest are refusing. This device keeps a
/// token so the next thing the user does, usually removing the Google link
/// that let the other party in, goes out immediately rather than after a
/// sign-in; the evicted party needs a whole OAuth round trip to come back and
/// interfere.
///
/// Unlike [`logout`] this is reported rather than best-effort, and a failure
/// signs this device out too. Someone reaches for it believing another session
/// exists that should not, and the one answer that must never be given wrongly
/// is that it is gone.
///
/// Three kinds of failure, told apart because they mean different things to
/// the person reading them. A lost answer or a server error is genuinely
/// ambiguous: the purge commits before the replacement is issued, so a `500`
/// can mean it happened, and this device is signed out on the safe side. A
/// `401` or a refusal means the request did not run and this token is already
/// worthless, so it goes too, but saying "it is not clear" would invent a
/// doubt. Being throttled also means nothing ran — and there the session is
/// still good, so it is kept and the user waits a few seconds instead of
/// losing the head start this route exists to give them.
///
/// # Errors
/// `ambiguous` when the answer was lost and the outcome is unknown, and
/// `signed-out` when the request plainly did not run: both mean this device is
/// no longer signed in. `throttled` leaves it signed in.
#[tauri::command]
async fn sign_out_other_devices(state: State<'_, AppState>) -> CommandResult<UserSummary> {
    let (api, user_id) = with_session(&state, |session| Ok((session.api.clone(), session.user_id)))?;
    let signed_in = match api.logout_other_devices().await {
        Ok(signed_in) => signed_in,
        // A throttled call is refused by middleware before the handler ever
        // runs, so nothing was purged and the token in hand is still good.
        // Keeping it is the point: this route exists to buy the user a few
        // seconds, and throwing their session away to wait those seconds out
        // spends exactly what it was meant to save — worse, on a shared egress
        // address the evicted party can hold the bucket empty and turn this
        // button into one that only logs the owner out.
        Err(error @ ClientError::TooManyRequests { .. }) => return Err(error.into()),
        Err(error) => {
            clear_local_session(&state);
            clear_pending_google(&state);
            // The rest all end this device's session, because either the
            // outcome is unknown or this token is already gone. Only the
            // sentence differs, and telling someone their other devices might
            // be signed out when they are not is the one answer this command
            // must never give wrongly.
            let ambiguous = matches!(error, ClientError::Network(_) | ClientError::Server(_));
            return Err(if ambiguous {
                CommandError::new(
                    "ambiguous",
                    format!(
                        "{error}. It is not clear whether your other devices were signed out, so this one has \
                         been signed out too. Sign in again and check."
                    ),
                )
            } else {
                CommandError::new("signed-out", format!("{error}. Nothing was signed out. Sign in again."))
            });
        }
    };
    with_same_session(&state, user_id, |session| {
        session.api = api.clone().with_token(&signed_in.token);
        session.google_email = signed_in.user.google_email.clone();
        session.password_login = signed_in.user.password_login;
        Ok(summary_of(session))
    })
}

// ----- sign in with Google ----------------------------------------------------

// Google proves who someone is; it never produces key material. Every path
// through this section therefore ends with a passphrase prompt, and the master
// key is derived on this device exactly as it is for a password login.

fn pending_lock(state: &AppState) -> CommandResult<std::sync::MutexGuard<'_, Option<PendingGoogle>>> {
    state.pending_google.lock().map_err(|_| "pending sign-in lock poisoned".to_string().into())
}

fn clear_pending_google(state: &AppState) {
    if let Ok(mut guard) = state.pending_google.lock() {
        *guard = None;
    }
}

/// The only host this app will send someone to sign in at.
const GOOGLE_AUTHORIZATION_HOST: &str = "accounts.google.com";

/// Refuse to open anything but Google's own sign-in page.
///
/// The server composes this URL, and the server is the party this app guards
/// against. Unchecked, it is a page of the server's choosing opened by a
/// password manager that has just told the user the system browser is the safe
/// place to type a Google password — and, because the string goes to the
/// platform URL handler rather than to a browser, a scheme of the server's
/// choosing too: `file://host/share/x` on Windows is a UNC path that
/// authenticates outward to whoever answers.
///
/// Scheme, host and port are what matter. The query carries `state`, `nonce`
/// and the PKCE challenge, which are the server's to choose and are checked
/// when the callback comes back.
///
/// # Errors
/// `oauth` if the URL does not parse, is not `https`, names a port, or is not
/// Google's authorization host.
fn check_authorization_url(url: &str) -> CommandResult<()> {
    let parsed = url::Url::parse(url)
        .map_err(|e| CommandError::new("oauth", format!("the server sent a sign-in address that is not a URL: {e}")))?;
    // Google's sign-in page is on the default port. Nothing is gained by
    // allowing another, and `accounts.google.com:8443` in a warning is worth
    // naming rather than passing over.
    let is_googles_page = parsed.scheme() == "https"
        && parsed.port().is_none()
        && parsed.host_str().is_some_and(|host| host.eq_ignore_ascii_case(GOOGLE_AUTHORIZATION_HOST));
    if !is_googles_page {
        // `javascript:` and `mailto:` have no host at all, and a sentence with
        // a hole where the destination should be is the last thing this
        // particular warning can afford.
        let destination = match parsed.host_str() {
            Some(host) => match parsed.port() {
                Some(port) => format!("{host} on port {port}"),
                None => host.to_string(),
            },
            None => format!("a {} address naming no host", parsed.scheme()),
        };
        return Err(CommandError::new(
            "oauth",
            format!(
                "this server tried to send you to {destination} to sign in, not to {GOOGLE_AUTHORIZATION_HOST}. \
                 Nothing was opened. Do not trust this server with your Google password."
            ),
        ));
    }
    Ok(())
}

/// Run the browser half of a sign-in and hand back the code it produced.
/// Shared by signing in and by linking, which differ only in purpose.
async fn authorize_with_google(
    app: &AppHandle,
    api: &ApiClient,
    purpose: OAuthPurpose,
) -> CommandResult<OAuthCallbackRequest> {
    let listener = RedirectListener::bind()
        .await
        .map_err(|e| CommandError::new("oauth", format!("could not listen for the sign-in response: {e}")))?;
    let started =
        api.oauth_start(&OAuthStartRequest { redirect_uri: listener.redirect_uri().to_string(), purpose }).await?;

    // The system browser, not the app webview: the user should be typing a
    // Google password into Google's own window, where they can see the URL.
    // Which window that is, is checked here rather than taken on the server's
    // word; see `check_authorization_url`.
    check_authorization_url(&started.authorization_url)?;
    app.opener()
        .open_url(started.authorization_url.clone(), None::<&str>)
        .map_err(|e| CommandError::new("oauth", format!("could not open your browser: {e}")))?;

    let code = listener.wait_for_code(&started.state).await.map_err(|e| CommandError::new("oauth", e.to_string()))?;
    // `app_secret` came back over this client's own HTTPS connection and was
    // never in the URL the browser followed, so returning it with the code is
    // what proves this app started the flow.
    Ok(OAuthCallbackRequest { state: started.state, app_secret: started.app_secret, code })
}

/// What the server at `server_url` supports. Called before the sign-in screen
/// is drawn so the Google button only appears where it works.
#[tauri::command]
async fn server_capabilities(server_url: String) -> CommandResult<Capabilities> {
    let server_url = normalize_server_url(&server_url)?;
    Ok(connect(&server_url).await?.capabilities().await?)
}

/// Do the browser half of a sign-in and report what the user must supply next.
#[tauri::command]
async fn google_sign_in(
    app: AppHandle,
    state: State<'_, AppState>,
    server_url: String,
) -> CommandResult<GoogleSignInStage> {
    let server_url = normalize_server_url(&server_url)?;
    let api = connect(&server_url).await?;
    let capabilities = api.capabilities().await?;
    if !capabilities.google_sign_in {
        return Err(CommandError::new("oauth", "this server does not offer sign in with Google"));
    }

    // Any earlier attempt is void the moment a new one starts.
    clear_pending_google(&state);
    let callback = authorize_with_google(&app, &api, OAuthPurpose::SignIn).await?;

    let (pending, stage) = match api.oauth_callback(&callback).await? {
        OAuthCallbackResponse::SignedIn(session) => {
            let email = session.user.email.clone();
            let api = api.with_token(&session.token);
            (PendingGoogle::Unlock { api, session }, GoogleSignInStage::Unlock { email })
        }
        OAuthCallbackResponse::RegistrationRequired { ticket, email } => (
            PendingGoogle::CreateAccount { api, ticket, email: email.clone() },
            GoogleSignInStage::CreateAccount {
                email,
                registration_token_required: capabilities.registration_token_required,
            },
        ),
    };
    *pending_lock(&state)? = Some(pending);
    Ok(stage)
}

/// The address the pending sign-in is for. It is the key-derivation salt, so
/// the passphrase must be stretched against exactly this string.
fn pending_google_email(state: &AppState) -> CommandResult<String> {
    let guard = pending_lock(state)?;
    guard
        .as_ref()
        .map(|pending| pending.email().to_string())
        .ok_or_else(|| CommandError::new("oauth", "that sign-in is no longer in progress; start it again"))
}

/// Deriving the master key takes long enough for another sign-in to have
/// replaced the pending one. Finishing against that one would use a key
/// derived from the wrong salt: on an unlock it would simply fail, but on a
/// sign-up it would create an account whose passphrase never opens it again.
fn still_the_same_sign_in(pending: &PendingGoogle, email: &str) -> CommandResult<()> {
    if pending.email() != email {
        return Err(CommandError::new("oauth", "another sign-in started in the meantime; try again"));
    }
    Ok(())
}

/// Finish signing in to an account that already exists: decrypt the stored
/// private key with the passphrase.
#[tauri::command]
async fn google_unlock(state: State<'_, AppState>, password: Zeroizing<String>) -> CommandResult<UserSummary> {
    let email = pending_google_email(&state)?;
    let master = derive_master(password, email.clone()).await?;

    // The pending attempt stays in place until the passphrase works, so a
    // typo costs a retry rather than another trip through the browser.
    let unlocked = {
        let guard = pending_lock(&state)?;
        let Some(pending @ PendingGoogle::Unlock { api, session }) = guard.as_ref() else {
            return Err(CommandError::new("oauth", "that sign-in is no longer in progress; start it again"));
        };
        still_the_same_sign_in(pending, &email)?;
        let identity =
            Identity::decrypt_private_key(&master.private_key_encryption_key(), &session.user.encrypted_private_key)
                .map_err(|error| unlock_failure(error, "that passphrase does not unlock this vault"))?;
        (api.clone(), AccountFacts::of(&session.user), identity)
    };

    clear_pending_google(&state);
    let (api, account, identity) = unlocked;
    install_session(&state, api, account, identity, master.self_wrap_key())
}

/// Create the account a first Google sign-in asked for. The key pair is
/// generated here and the private half leaves this device only under a key
/// derived from the passphrase.
#[tauri::command]
async fn google_create_account(
    state: State<'_, AppState>,
    password: Zeroizing<String>,
    registration_token: Option<String>,
) -> CommandResult<UserSummary> {
    kdf::validate_new_password(&password).map_err(user_facing)?;
    let email = pending_google_email(&state)?;
    let master = derive_master(password, email.clone()).await?;

    let (api, ticket) = {
        let guard = pending_lock(&state)?;
        let Some(pending @ PendingGoogle::CreateAccount { api, ticket, .. }) = guard.as_ref() else {
            return Err(CommandError::new("oauth", "that sign-up is no longer in progress; start it again"));
        };
        still_the_same_sign_in(pending, &email)?;
        (api.clone(), ticket.clone())
    };

    let identity = Identity::generate();
    let created = api
        .oauth_register(&OAuthRegisterRequest {
            ticket,
            public_key: identity.public_key().clone(),
            encrypted_private_key: identity.encrypt_private_key(&master.private_key_encryption_key()),
            registration_token: registration_token.filter(|token| !token.trim().is_empty()),
        })
        .await?;

    clear_pending_google(&state);
    install_session(
        &state,
        api.with_token(&created.token),
        AccountFacts::of(&created.user),
        identity,
        master.self_wrap_key(),
    )
}

/// Bind a Google account to the credvault account already signed in, so it can
/// use the button next time.
///
/// The account email is left as it is: it is the salt the vault key comes
/// from, and changing it would make every stored secret undecryptable.
/// The passphrase is required because a linked account is a second way in:
/// it signs in on its own, and it survives both a passphrase change and
/// signing out everywhere. A session token alone must not be able to leave one
/// behind.
#[tauri::command]
async fn google_link(
    app: AppHandle,
    state: State<'_, AppState>,
    current: Zeroizing<String>,
) -> CommandResult<UserSummary> {
    let password_login = with_session(&state, |session| Ok(session.password_login))?;
    if !password_login {
        return Err(CommandError::new("oauth", "this account already signs in with Google"));
    }
    // Asked before the passphrase, because its answer does not depend on what
    // the user typed. Otherwise someone on a server with Google turned off
    // pays a full key derivation to be told it was never on offer — and, with
    // a typo as well, is told the passphrase is wrong, which invites a retry
    // that cannot work.
    let capabilities = api(&state)?.capabilities().await?;
    if !capabilities.google_sign_in {
        return Err(CommandError::new("oauth", "this server does not offer sign in with Google"));
    }

    let PassphraseProof { user_id, api, auth_hash, master, .. } = prove_current_passphrase(&state, current).await?;
    // Nothing below needs the vault key, and what comes next waits on the user
    // reading a consent screen in a browser. Dropped rather than held for it.
    drop(master);

    let callback = authorize_with_google(&app, &api, OAuthPurpose::Link).await?;
    let profile =
        api.oauth_link(&OAuthLinkRequest::new(callback, Some(auth_hash))).await.map_err(passphrase_rejected)?;
    remember_google_email(&state, user_id, profile.google_email)
}

/// Remove the linked Google account, so it can no longer sign in here.
///
/// The server ends every session as it goes, including this one, and answers
/// with a replacement. Installing that replacement is what keeps this device
/// signed in while every other is signed out.
#[tauri::command]
async fn google_unlink(state: State<'_, AppState>, current: Zeroizing<String>) -> CommandResult<UserSummary> {
    let password_login = with_session(&state, |session| Ok(session.password_login))?;
    if !password_login {
        return Err(CommandError::new(
            "oauth",
            "this account signs in with Google only; removing the link would leave no way to sign in",
        ));
    }
    let PassphraseProof { user_id, api, auth_hash, .. } = prove_current_passphrase(&state, current).await?;
    let signed_in =
        api.oauth_unlink(&OAuthUnlinkRequest { current_auth_hash: auth_hash }).await.map_err(passphrase_rejected)?;

    with_same_session(&state, user_id, |session| {
        session.api = api.clone().with_token(&signed_in.token);
        session.google_email = signed_in.user.google_email.clone();
        Ok(summary_of(session))
    })
}

/// Say what a `401` from the link routes actually means.
///
/// Everywhere else a `401` means the token is gone, and the client says so.
/// On these two it cannot: the passphrase was already checked locally and
/// passed, so reaching the server's own check at all means this session's wrap
/// key is stale — the passphrase was changed on another device. Signing in
/// again is still the fix, but "your session has expired" names the wrong
/// cause for someone trying to work out what happened to their account.
fn passphrase_rejected(error: ClientError) -> CommandError {
    match error {
        ClientError::Unauthorized => CommandError::new(
            "locked",
            "the server did not accept that passphrase. If you changed it on another device, \
             sign out here and sign in with the new one.",
        ),
        other => other.into(),
    }
}

/// A passphrase proved against the session that is open, and the account it
/// was proved for.
struct PassphraseProof {
    /// Who the proof is for. Carried so a slow round trip cannot write its
    /// answer onto whatever session happens to be open when it returns.
    user_id: i64,
    /// The client the proof was read from, so everything that follows speaks
    /// to the session it was proved against rather than re-reading the lock.
    api: ApiClient,
    /// The address both hashes are bound to. Read once here, so a caller
    /// deriving a second hash cannot bind it to a different server than the
    /// first — which would rebind the account's credential to an address the
    /// user never signs in at.
    server: ServerAddress,
    /// The account address, which is the key-derivation salt. On the proof
    /// for the same reason as `server`: a caller deriving a second key must
    /// derive it from the same salt as the first, or it re-wraps the vault
    /// under a key the passphrase cannot reproduce.
    email: String,
    /// Whether a passphrase is also this account's server credential, so a
    /// caller does not have to re-read it after an await.
    password_login: bool,
    /// Bound to [`PassphraseProof::server`], so it is useless to any other.
    auth_hash: Zeroizing<String>,
    /// The key the passphrase derived. Handed back because deriving it is the
    /// expensive part and a caller that re-wraps needs it; callers that only
    /// needed the proof drop it, and should do so before anything slow.
    master: MasterKey,
}

/// Derive the master key from `current` and check it opens the session that is
/// already unlocked, returning the proof to send to the server.
///
/// The comparison is local and against the session's own wrap key, so a typo
/// costs one Argon2 pass here instead of a round trip — and, for linking, a
/// whole trip out through Google that then fails at the end.
///
/// # Errors
/// `locked` if nothing is unlocked or the passphrase is not this session's.
async fn prove_current_passphrase(state: &AppState, current: Zeroizing<String>) -> CommandResult<PassphraseProof> {
    // One read of the session for everything that has to agree: the account,
    // the client, the salt and the address the hashes bind to. Each of these
    // read separately could observe a different session, and a command that
    // mixed two accounts' values would write one account's key material over
    // the other's.
    let (email, api, user_id, password_login) = with_session(state, |session| {
        Ok((session.email.clone(), session.api.clone(), session.user_id, session.password_login))
    })?;
    let server = normalize_server_url(api.base_url())?;
    let master = derive_master(current, email.clone()).await?;
    let matches_session: bool = with_session(state, |session| {
        Ok(session.user_id == user_id
            && bool::from(master.self_wrap_key().as_ref().ct_eq(session.self_wrap_key.as_ref())))
    })?;
    if !matches_session {
        return Err(CommandError::new("locked", "that is not your current passphrase"));
    }
    let auth_hash = master.auth_hash(&server);
    Ok(PassphraseProof { user_id, api, server, email, password_login, auth_hash, master })
}

/// Record what the server now says is linked, and hand back the summary the
/// UI redraws from.
///
/// `user_id` is the account the answer was about. Linking blocks on a browser
/// round trip of unbounded length, and the session can be replaced while it
/// runs; without this check the first account's Google address could land on
/// the second account's summary.
fn remember_google_email(state: &AppState, user_id: i64, google_email: Option<String>) -> CommandResult<UserSummary> {
    with_same_session(state, user_id, |session| {
        session.google_email = google_email;
        Ok(summary_of(session))
    })
}

/// Re-read what the server says about this account and update what the
/// session caches.
///
/// The Google address is the field worth re-reading: it can change from
/// another device, and the account panel is where an unwanted link is supposed
/// to become visible. Nothing secret is touched — this replaces facts the
/// server already told us, not key material.
///
/// `password_login` is taken from the server too, which was fixed at sign-in
/// before. A hostile server flipping it gains nothing: false makes
/// `change_password` send no hashes, which the server's own check rejects for
/// a password account, and true makes a Google account send hashes rejected
/// for the opposite reason. Both fail closed, and a server that wants to hide
/// the chip can already do it by returning no `google_email`.
///
/// # Errors
/// `locked` if nothing is unlocked or the session changed while this ran;
/// whatever the client reports if the server cannot be reached.
#[tauri::command]
async fn refresh_account(state: State<'_, AppState>) -> CommandResult<UserSummary> {
    let (api, user_id) = with_session(&state, |session| Ok((session.api.clone(), session.user_id)))?;
    let profile = api.me().await?;
    with_same_session(&state, user_id, |session| {
        session.password_login = profile.password_login;
        session.google_email = profile.google_email.clone();
        Ok(summary_of(session))
    })
}

#[tauri::command]
fn session_info(state: State<'_, AppState>) -> CommandResult<Option<UserSummary>> {
    let guard = state.session.lock().map_err(|_| "session lock poisoned".to_string())?;
    Ok(guard.as_ref().map(summary_of))
}

/// Warnings raised while starting up, handed to the UI once.
#[tauri::command]
fn startup_warnings(state: State<'_, AppState>) -> CommandResult<Vec<String>> {
    let mut warnings = state.startup_warnings.lock().map_err(|_| "warnings lock poisoned".to_string())?;
    Ok(std::mem::take(&mut *warnings))
}

#[tauri::command]
fn ui_constants() -> UiConstants {
    UiConstants {
        min_password_length: kdf::MIN_PASSWORD_LEN,
        max_message_length: MAX_MESSAGE_LEN,
        generated_password_length: password::DEFAULT_LENGTH,
        max_custom_fields: secret::MAX_CUSTOM_FIELDS,
        max_label_length: secret::MAX_LABEL_LEN,
        max_field_length: secret::MAX_FIELD_LEN,
    }
}

/// Change the passphrase this vault is derived from.
///
/// Everything the old passphrase produced is replaced at once, because half a
/// change is a vault nobody can open: the server either takes all of it or
/// none. The payloads are not touched — each secret's key is random and
/// unchanged, so only the owner's wrapping of it is redone — and neither is
/// the key pair, so secrets shared *with* this account keep working.
///
/// # Errors
/// `locked` if the current passphrase is wrong, `conflict` if the vault
/// changed while re-wrapping (refresh and try again), `crypto` if the new
/// passphrase fails the length floor.
#[tauri::command]
async fn change_password(
    state: State<'_, AppState>,
    current: Zeroizing<String>,
    new_password: Zeroizing<String>,
) -> CommandResult<()> {
    kdf::validate_new_password(&new_password).map_err(user_facing)?;

    // Proved locally rather than left to the server, so a typo costs one
    // Argon2 pass instead of a round trip that also re-wraps every key. The
    // derived key comes back with the proof, because re-wrapping needs it and
    // deriving it twice would double the one slow step on this path.
    //
    // Everything else this command sends comes off the proof too, from its one
    // guarded read of the session. Both keys derive from the same salt, so the
    // vault cannot be re-wrapped under a key the passphrase will not reproduce,
    // and both hashes bind to the same address, so the credential cannot be
    // rebound to a server the user never signs in at. Either would be a vault
    // nobody can open again.
    let PassphraseProof {
        user_id,
        api,
        server,
        email,
        password_login,
        auth_hash: current_auth_hash,
        master: old_master,
    } = prove_current_passphrase(&state, current).await?;
    let new_master = derive_master(new_password, email).await?;

    // Keys without payloads: re-wrapping never looks at a payload, and at the
    // quota fetching them would be tens of megabytes read and thrown away.
    // Anything that moves in the meantime is caught by the key version the
    // server checks.
    let keys = api.list_secret_keys().await?;
    let rewrapped_keys = rewrap_owned(&keys, &old_master, &new_master)?;

    // Guarded on the account: this uploads a private key, and uploading one
    // account's key to another would replace that account's key pair and break
    // every secret shared with it.
    let identity_key = with_same_session(&state, user_id, |session| {
        Ok(session.identity.encrypt_private_key(&new_master.private_key_encryption_key()))
    })?;
    let request = ChangePasswordRequest {
        current_auth_hash: password_login.then_some(current_auth_hash),
        new_auth_hash: password_login.then(|| new_master.auth_hash(&server)),
        encrypted_private_key: identity_key,
        rewrapped_keys,
    };
    let session = match api.change_password(&request).await {
        Ok(session) => session,
        // An answer that never arrived is not the same as a change that never
        // happened, and the difference decides which passphrase the vault now
        // has. Treating it as a failure is what loses a vault: the user keeps
        // the old passphrase, discards the new one, and neither opens it.
        Err(ClientError::Network(reason)) => return Err(resolve_lost_answer(&state, &api, reason).await),
        Err(other) => return Err(other.into()),
    };

    // Every other device was signed out, and this one holds a new token and a
    // new self-wrap key. Cached secret keys stay valid — they did not change —
    // but they are dropped rather than reasoned about.
    // Guarded on the account: this takes minutes on a large vault, long enough
    // for the session to have been replaced underneath it.
    with_same_session(&state, user_id, |current| {
        current.api = api.with_token(&session.token);
        current.self_wrap_key = new_master.self_wrap_key();
        current.keys.clear();
        // A passphrase change does not remove a linked Google account, so this
        // is taken from the profile the server just returned rather than
        // assumed either way.
        current.google_email = session.user.google_email.clone();
        Ok(())
    })
}

/// How long to keep asking before settling for an inconclusive answer, and
/// how often.
///
/// Sized against the work being asked about rather than picked round. A probe
/// can land while the server is still inside the transaction, where sessions
/// have not been deleted yet, and "still signed in" then means *not yet*
/// rather than *will not be*. Only watching for the answer to change tells
/// those apart, so this keeps asking rather than sampling twice and guessing.
///
/// A ceiling on the sleeping, not on the whole loop: each probe carries the
/// client's own timeout, so slow answers push the total to roughly this plus
/// one client timeout. Measured at 41s against a 30s budget with a server
/// answering after 19s.
///
/// Safe in both directions, which is why the loop is not bounded harder. A
/// probe that hangs reads as `Unreachable`, breaks the run and ends in
/// `Unknown`. A probe that is merely slow still answers `Alive`, and two of
/// those far apart are stronger evidence that nothing committed than two close
/// together, not weaker.
const PROBE_BUDGET: Duration = Duration::from_secs(30);
const PROBE_INTERVAL: Duration = Duration::from_secs(3);

/// What a probe could establish about a change whose answer never arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChangeOutcome {
    /// The session was still alive on the last `STABLE_READINGS` probes in a
    /// row: the change did not commit.
    NotApplied,
    /// The session is gone, which only the committing transaction does.
    Applied,
    /// The probe could not be made. Nothing is known either way.
    Unknown,
}

/// Work out whether a passphrase change landed when its answer did not.
///
/// The server deletes every session inside the transaction that commits the
/// change, so a token that still works means nothing has committed *yet* —
/// which is not the same as "will not". Watching until the answer settles is
/// what turns that reading into an answer. Even then the honest outcome is
/// sometimes "unknown", and saying so is better than guessing: the guess that
/// loses a vault is telling someone nothing happened when it did.
async fn resolve_lost_answer(state: &AppState, api: &ApiClient, reason: String) -> CommandError {
    let outcome = probe_change(api).await;
    if !matches!(outcome, ChangeOutcome::NotApplied) {
        // The old key material no longer matches the server, or may not. It
        // must not stay in memory behind a screen that says the user is signed
        // out, and it must not quietly unlock the app again on reload.
        clear_local_session(state);
    }
    match outcome {
        ChangeOutcome::NotApplied => CommandError::new(
            "probably_unchanged",
            format!(
                "The server did not answer ({reason}), and your passphrase still looks unchanged. \
                 Keep the new one somewhere safe and try again. If the old one ever stops working, \
                 the change did go through after all and the new one is the right one."
            ),
        ),
        ChangeOutcome::Applied => CommandError::new(
            "changed_but_unconfirmed",
            "Your passphrase was changed, but the confirmation was lost on the way back. \
             Sign in again with the NEW passphrase. (If someone signed this account out from \
             another device just now, the old one may still work — try the new one first.)",
        ),
        ChangeOutcome::Unknown => CommandError::new(
            "changed_but_unknown",
            "The server could not be reached, and it is not clear whether the change went through. \
             Keep the new passphrase, sign in again, and try it before the old one.",
        ),
    }
}

/// What one reading of the session told us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// The session answered: nothing has committed, at least not yet.
    Alive,
    /// The session is gone, which only the committing transaction does.
    Gone,
    /// The question could not be put. Says nothing either way.
    Unreachable,
}

/// How many consecutive `Alive` readings it takes to call a change *not*
/// applied. One is never enough: the server can still be inside the
/// transaction, where the session has not been deleted yet.
const STABLE_READINGS: u32 = 2;

/// Fold one reading into the verdict so far, returning the new run length and
/// the outcome if it is already settled.
///
/// Kept separate from the I/O so it can be tested without a server. This rule
/// decides which of three things a person is told about whether their vault
/// passphrase changed, and the wrong answer is the one that loses a vault.
fn fold_reading(alive_in_a_row: u32, reading: Reading) -> (u32, Option<ChangeOutcome>) {
    match reading {
        // Conclusive the moment it happens; nothing else deletes a session.
        Reading::Gone => (0, Some(ChangeOutcome::Applied)),
        Reading::Alive => (alive_in_a_row + 1, None),
        Reading::Unreachable => (0, None),
    }
}

/// The verdict when the budget runs out with no conclusive reading.
fn settle(alive_in_a_row: u32) -> ChangeOutcome {
    if alive_in_a_row >= STABLE_READINGS {
        ChangeOutcome::NotApplied
    } else {
        ChangeOutcome::Unknown
    }
}

/// Watch whether this session is still alive, until the answer is conclusive
/// or the budget runs out.
///
/// A session that disappears is conclusive the moment it happens, because only
/// the committing transaction deletes it. A session that is still there is
/// never conclusive on its own — it only becomes an answer by staying there.
async fn probe_change(api: &ApiClient) -> ChangeOutcome {
    // `tokio::time`, not `std::time`, so a test can drive this with a paused
    // clock instead of waiting out the real budget.
    let deadline = tokio::time::Instant::now() + PROBE_BUDGET;
    let mut alive_in_a_row = 0;
    loop {
        let reading = match api.me().await {
            Err(ClientError::Unauthorized) => Reading::Gone,
            Ok(_) => Reading::Alive,
            Err(_) => Reading::Unreachable,
        };
        let (run, settled) = fold_reading(alive_in_a_row, reading);
        if let Some(outcome) = settled {
            return outcome;
        }
        alive_in_a_row = run;
        // Checked before sleeping rather than after `me`, which carries a
        // timeout of its own. This bounds the sleeps, not the probes: a run of
        // calls that each sit on that timeout can still overrun the budget,
        // and the only thing that would bound *that* is a shorter deadline on
        // the probe itself.
        if tokio::time::Instant::now() + PROBE_INTERVAL >= deadline {
            return settle(alive_in_a_row);
        }
        tokio::time::sleep(PROBE_INTERVAL).await;
    }
}

/// Drop the session this process is holding, including the master-key material
/// in it. Poisoning is reported rather than ignored, as everywhere else.
fn clear_local_session(state: &AppState) {
    match state.session.lock() {
        Ok(mut guard) => *guard = None,
        Err(poisoned) => {
            tracing::error!("session lock poisoned while clearing the session");
            *poisoned.into_inner() = None;
        }
    }
}

/// Unwrap each owned secret's key with the old self-wrap key and wrap it again
/// with the new one. Secrets shared with this account are skipped: their copies
/// are sealed to the key pair, which does not change.
fn rewrap_owned(keys: &[SecretKeyView], old: &MasterKey, new: &MasterKey) -> CommandResult<Vec<RewrappedKey>> {
    let old_wrap = old.self_wrap_key();
    let new_wrap = new.self_wrap_key();
    let mut rewrapped = Vec::new();
    for view in keys.iter().filter(|view| view.is_owner) {
        let WrappedKey::Owner(sealed) = &view.wrapped_key else {
            return Err(CommandError::new(
                "untrusted_key",
                format!("the server returned a key copy for \"{}\" that you could not have made", view.name),
            ));
        };
        let key = SecretKey::unwrap_owner(&old_wrap, sealed).map_err(user_facing)?;
        rewrapped.push(RewrappedKey {
            secret_id: view.id,
            key_version: view.key_version,
            wrapped_key: WrappedKey::Owner(key.wrap_for_owner(&new_wrap)),
        });
    }
    Ok(rewrapped)
}

// ----- secret commands --------------------------------------------------------

/// Unwrap a secret's key, preferring the cached copy when it is from the same
/// key version. A newer version on the server means another device rotated
/// the key, so the wrapped key is unwrapped again.
fn key_for(session: &mut Session, view: &SecretView) -> CommandResult<()> {
    if session.keys.get(&view.id).is_some_and(|loaded| loaded.version == view.key_version) {
        return Ok(());
    }
    let key = unwrap_view_key(session, view)?;
    session.keys.insert(view.id, LoadedKey { key, version: view.key_version });
    Ok(())
}

/// Which form of wrapped key is acceptable depends on who we are to the
/// secret. Our own secrets must come self-wrapped: only we can derive that
/// key, so a sealed box is something the server could have produced with a
/// key it knows, and is refused however plausible it looks. Secrets shared
/// with us can only ever be sealed boxes.
fn unwrap_view_key(session: &Session, view: &SecretView) -> CommandResult<SecretKey> {
    match (&view.wrapped_key, view.is_owner) {
        (WrappedKey::Owner(sealed), true) => {
            SecretKey::unwrap_owner(&session.self_wrap_key, sealed).map_err(user_facing)
        }
        (WrappedKey::Shared(boxed), false) => SecretKey::unwrap_with(&session.identity, boxed).map_err(user_facing),
        (WrappedKey::Shared(_), true) => Err(CommandError::new(
            "untrusted_key",
            "the server returned a key copy for your own secret in a form it could have made itself; refusing it",
        )),
        (WrappedKey::Owner(_), false) => Err(CommandError::new(
            "untrusted_key",
            "the server returned a key copy in a form that cannot belong to a shared secret",
        )),
    }
}

fn loaded_key(session: &Session, id: i64) -> CommandResult<&LoadedKey> {
    session.keys.get(&id).ok_or_else(|| "secret not loaded; refresh and try again".into())
}

fn decrypt_view(session: &mut Session, view: &SecretView) -> CommandResult<SecretPayload> {
    key_for(session, view)?;
    match loaded_key(session, view.id)?.key.decrypt(&view.name, &view.payload) {
        Ok(payload) => Ok(payload),
        Err(error) => {
            // Never keep a key that does not open its payload.
            session.keys.remove(&view.id);
            Err(user_facing(error))
        }
    }
}

/// Re-fetch one secret and replace its cached key; used after the server says
/// the version we wrote against is stale.
async fn refresh_key(state: &AppState, api: &ApiClient, id: i64) -> CommandResult<()> {
    let view = api.get_secret(id).await?;
    with_session(state, |session| {
        session.keys.remove(&id);
        key_for(session, &view)
    })
}

#[tauri::command]
async fn list_secrets(state: State<'_, AppState>) -> CommandResult<Vec<SecretSummary>> {
    let views = api(&state)?.list_secrets().await?;
    with_session(&state, |session| {
        // Drop keys for secrets that are gone; keep the rest so a server-side
        // key rotation by us is not undone by a stale cache entry elsewhere.
        session.keys.retain(|id, _| views.iter().any(|v| v.id == *id));
        let mut summaries = Vec::with_capacity(views.len());
        for view in views {
            // One undecryptable item must not hide the whole vault, so the
            // failure is reported per item and the loop continues.
            let outcome = key_for(session, &view).and_then(|()| decrypt_view(session, &view));
            let (payload, error) = match outcome {
                Ok(payload) => (payload, None),
                Err(error) => {
                    tracing::warn!(secret_id = view.id, %error, "cannot decrypt secret");
                    (SecretPayload::default(), Some(error.message))
                }
            };
            summaries.push(SecretSummary {
                id: view.id,
                name: view.name,
                username: payload.username.clone(),
                url: payload.url.clone(),
                notes: payload.notes.clone(),
                fields: field_summaries(&payload),
                is_owner: view.is_owner,
                owner_email: view.owner_email,
                updated_at: view.updated_at,
                error,
            });
        }
        Ok(summaries)
    })
}

/// Fetch one secret and decrypt it with the cached key.
async fn load_payload(state: &AppState, id: i64) -> CommandResult<SecretPayload> {
    let view = api(state)?.get_secret(id).await?;
    with_session(state, |session| decrypt_view(session, &view))
}

#[tauri::command]
async fn reveal_password(state: State<'_, AppState>, id: i64) -> CommandResult<Zeroizing<String>> {
    Ok(Zeroizing::new(load_payload(&state, id).await?.password.clone()))
}

#[tauri::command]
async fn copy_password(app: AppHandle, state: State<'_, AppState>, id: i64) -> CommandResult<u64> {
    let password = Zeroizing::new(load_payload(&state, id).await?.password.clone());
    copy_secret_value(app, &state, password)
}

/// The value of one sensitive custom field, fetched only when the user asks
/// for that field, so revealing a recovery code does not also decrypt and
/// hand over everything else on the screen.
async fn load_field_value(state: &AppState, id: i64, field_id: &str) -> CommandResult<Zeroizing<String>> {
    let payload = load_payload(state, id).await?;
    // By id, because several fields may share a label: matching on one would
    // hand back the first of them whichever was asked for, putting the wrong
    // secret on screen and on the clipboard.
    payload
        .fields
        .iter()
        .find(|field| field.id == field_id)
        .map(|field| Zeroizing::new(field.value.clone()))
        .ok_or_else(|| CommandError::new("field_missing", "that field has changed; refresh and try again"))
}

#[tauri::command]
async fn reveal_field(state: State<'_, AppState>, id: i64, field_id: String) -> CommandResult<Zeroizing<String>> {
    load_field_value(&state, id, &field_id).await
}

#[tauri::command]
async fn copy_field(app: AppHandle, state: State<'_, AppState>, id: i64, field_id: String) -> CommandResult<u64> {
    let value = load_field_value(&state, id, &field_id).await?;
    copy_secret_value(app, &state, value)
}

/// Put a sensitive value on the clipboard and arrange for it to be wiped.
fn copy_secret_value(app: AppHandle, state: &AppState, value: Zeroizing<String>) -> CommandResult<u64> {
    // write_secret marks the clip as sensitive (Android masks the preview, iOS
    // keeps it off Universal Clipboard, desktop managers skip their history).
    app.clipboard().write_secret(value.as_str()).map_err(|e| format!("clipboard write failed: {e}"))?;
    // Only a digest outlives this call: the clear task compares hashes, so the
    // plaintext is not kept alive for the whole timeout.
    let digest: [u8; 32] = Sha256::digest(value.as_bytes()).into();
    drop(value);
    // A poisoned slot only costs "Clear now" its target; the timer below
    // still clears the clipboard on schedule.
    if let Ok(mut slot) = state.copied_digest.lock() {
        *slot = Some(digest);
    }
    // A newer copy supersedes this one; its own task takes over the timer.
    let generation = state.clipboard_generation.fetch_add(1, Ordering::SeqCst) + 1;
    tokio::spawn(async move {
        tokio::time::sleep(CLIPBOARD_CLEAR_AFTER).await;
        let state = app.state::<AppState>();
        if state.clipboard_generation.load(Ordering::SeqCst) == generation {
            take_copied_digest(&state.copied_digest);
            clear_clipboard_if_digest_matches(&app, &digest);
        }
    });
    Ok(CLIPBOARD_CLEAR_AFTER.as_secs())
}

/// Wipe the clipboard now rather than when the timer runs out, if it still
/// holds the last value this app copied. Returns whether anything was wiped:
/// false when nothing is pending or the user has copied something else since.
#[tauri::command]
fn clear_copied_value(app: AppHandle, state: State<'_, AppState>) -> bool {
    let Some(digest) = take_copied_digest(&state.copied_digest) else {
        return false;
    };
    // Supersede the pending timer: there is nothing left for it to do.
    state.clipboard_generation.fetch_add(1, Ordering::SeqCst);
    clear_clipboard_if_digest_matches(&app, &digest)
}

/// Hand over the remembered digest exactly once, so a value is cleared by
/// "Clear now" or by its timer, never both.
fn take_copied_digest(slot: &Mutex<Option<[u8; 32]>>) -> Option<[u8; 32]> {
    slot.lock().ok()?.take()
}

/// Wipe the clipboard only if it still holds what we put there, so we never
/// destroy something the user copied since. Returns whether it was wiped.
fn clear_clipboard_if_digest_matches(app: &AppHandle, expected: &[u8; 32]) -> bool {
    let clipboard = app.clipboard();
    let unchanged = match clipboard.read_text() {
        Ok(current) => Sha256::digest(current.as_bytes()).as_slice() == expected,
        Err(error) => {
            tracing::warn!(%error, "clipboard unavailable; cannot clear copied password");
            return false;
        }
    };
    if !unchanged {
        return false;
    }
    match clipboard.clear() {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, "failed to clear copied password from clipboard");
            false
        }
    }
}

#[tauri::command]
async fn create_secret(state: State<'_, AppState>, form: SecretForm) -> CommandResult<i64> {
    let name = secret::validate_name(&form.name).map_err(user_facing)?;
    let password = form
        .password
        .filter(|p| !p.is_empty())
        .ok_or_else(|| CommandError::from("enter a password or generate one"))?;
    // Nothing is stored yet, so every field has to arrive with its value.
    let fields = resolve_fields(form.fields, &[])?;
    let payload = SecretPayload {
        username: form.username,
        password: password.to_string(),
        url: form.url,
        notes: form.notes,
        fields,
    };
    let key = SecretKey::generate();
    let request = with_session(&state, |session| {
        Ok(CreateSecretRequest {
            payload: key.encrypt(&name, &payload).map_err(user_facing)?,
            wrapped_key: WrappedKey::Owner(key.wrap_for_owner(&session.self_wrap_key)),
            name,
        })
    })?;
    let created = api(&state)?.create_secret(&request).await?;
    with_session(&state, |session| {
        session.keys.insert(created.id, LoadedKey { key, version: NEW_SECRET_KEY_VERSION });
        Ok(())
    })?;
    Ok(created.id)
}

/// `password: None` keeps the current password, and a field submitted without
/// a value keeps the stored one; neither ever leaves Rust. A 409 means another
/// device rotated the key since we loaded it: the new key is fetched and the
/// write re-encrypted once, never retried under the old one.
///
/// Known window: `key_version` guards the key, not the payload. A kept value
/// is resolved against the payload read at the start of this call, so if
/// another device changes that field in between, this write puts the old
/// value back. The same has always been true of the blank password box;
/// keeping by id widens it from one field to all of them. Closing it needs a
/// payload version echoed the way `key_version` is, which is worth doing if
/// multi-device editing becomes common.
#[tauri::command]
async fn update_secret(state: State<'_, AppState>, id: i64, form: SecretForm) -> CommandResult<()> {
    let name = secret::validate_name(&form.name).map_err(user_facing)?;
    let password = form.password.filter(|p| !p.is_empty());
    // One fetch covers both "keep the password" and "keep this field".
    let keeps_a_field = form.fields.iter().any(|field| field.value.is_none());
    let existing = if password.is_none() || keeps_a_field { Some(load_payload(&state, id).await?) } else { None };
    let stored_fields: Vec<CustomField> = existing.as_ref().map(|p| p.fields.clone()).unwrap_or_default();
    // `existing` is fetched exactly when the password was not given, so the
    // two are never both absent.
    let password = match password {
        Some(password) => password,
        None => Zeroizing::new(existing.as_ref().map(|p| p.password.clone()).unwrap_or_default()),
    };
    let fields = resolve_fields(form.fields, &stored_fields)?;
    let payload = SecretPayload {
        username: form.username,
        password: password.to_string(),
        url: form.url,
        notes: form.notes,
        fields,
    };
    let api = api(&state)?;
    for attempt in 0..2 {
        let request = with_session(&state, |session| {
            let loaded = loaded_key(session, id)?;
            Ok(UpdateSecretRequest {
                key_version: loaded.version,
                payload: loaded.key.encrypt(&name, &payload).map_err(user_facing)?,
                name: name.clone(),
            })
        })?;
        match api.update_secret(id, &request).await {
            Ok(()) => return Ok(()),
            Err(ClientError::Conflict(_)) if attempt == 0 => refresh_key(&state, &api, id).await?,
            Err(error) => return Err(error.into()),
        }
    }
    Err("the secret keeps changing under us; refresh and try again".into())
}

#[tauri::command]
async fn delete_secret(state: State<'_, AppState>, id: i64) -> CommandResult<()> {
    api(&state)?.delete_secret(id).await?;
    with_session(&state, |session| {
        session.keys.remove(&id);
        Ok(())
    })
}

#[tauri::command]
fn generate_password(length: usize, symbols: bool) -> CommandResult<Zeroizing<String>> {
    password::generate(length, symbols).map(Zeroizing::new).map_err(user_facing)
}

// ----- sharing commands -------------------------------------------------------

#[tauri::command]
async fn get_access(state: State<'_, AppState>, id: i64) -> CommandResult<AccessView> {
    Ok(api(&state)?.get_access(id).await?)
}

/// Step one of inviting: fetch the invitee's key and report whether it matches
/// what we pinned before. The server only answers for a fingerprint we already
/// know, so one must be supplied: the pinned one for someone we have shared
/// with before, otherwise one the user got from them out of band.
///
/// `fingerprint` of `None` means "use the pin". With no pin and nothing typed
/// there is nothing to ask the server with, and the UI is told to collect one
/// rather than being handed a lookup that cannot be made.
#[tauri::command]
async fn lookup_invitee(
    state: State<'_, AppState>,
    email: String,
    fingerprint: Option<String>,
) -> CommandResult<InviteeInfo> {
    let api = api(&state)?;
    let email = kdf::normalize_email(&email);
    let typed = fingerprint.map(|f| f.trim().to_string()).filter(|f| !f.is_empty());
    let asked_with = match typed {
        Some(typed) => typed,
        None => pinned_fingerprint(&state, api.base_url(), &email)?.ok_or_else(|| {
            CommandError::new(
                "fingerprint_required",
                "ask them to read the \"Your key\" fingerprint from the top of their credvault window, and enter it \
                 here. You only need to do this the first time you share with someone.",
            )
        })?,
    };

    // A fingerprint that is not a whole one cannot match anything, and would
    // otherwise be sent to the server as if it were a real check.
    if normalize_fingerprint(&asked_with).len() != FINGERPRINT_HEX_LEN {
        return Err(CommandError::new(
            "fingerprint_required",
            "that does not look like a full fingerprint; it is six groups of four hex digits",
        ));
    }

    let invitee = api.lookup_user(&email, &asked_with).await.map_err(|error| match error {
        // Only a genuine "no match" is answered by checking the fingerprint
        // again. Everything else (throttled, malformed, server fault) keeps
        // its own code, so the UI does not send the user back to retype
        // something that was not the problem.
        ClientError::NotFound(message) => CommandError::new("lookup_failed", message),
        other => other.into(),
    })?;

    // The server checking the fingerprint is what stops it being asked who has
    // an account. It is not what stops it substituting a key, because it is
    // the party we are guarding against: a server that ignored the parameter
    // and answered with its own key would otherwise be reported to the user as
    // the key whose fingerprint they just read out. So check it here too.
    check_served_key(&invitee.public_key, &asked_with)?;

    let status = {
        let known = state.known_keys.lock().map_err(|_| "key store lock poisoned".to_string())?;
        known.check(api.base_url(), &invitee.email, &invitee.public_key)
    };
    Ok(InviteeInfo {
        email: invitee.email,
        fingerprint: invitee.public_key.fingerprint(),
        public_key: invitee.public_key.to_base64(),
        status,
    })
}

/// Whether two fingerprints are the same one, however each was typed. Not
/// constant-time on purpose: a fingerprint is public, and both sides of this
/// comparison are already in the caller's hands.
fn fingerprint_matches(expected: &str, supplied: &str) -> bool {
    normalize_fingerprint(expected) == normalize_fingerprint(supplied)
}

/// Check that the key the server served is the one whose fingerprint the user
/// read out. This is the branch that separates an honest server from a hostile
/// one: the server checks the fingerprint too, but that only stops it being
/// asked who has an account, since it is the party being guarded against. A
/// server that ignored the parameter and answered with its own key would
/// otherwise be reported to the user as the key they just confirmed.
fn check_served_key(served: &PublicKey, asked_with: &str) -> CommandResult<()> {
    if !fingerprint_matches(&served.fingerprint(), asked_with) {
        return Err(CommandError::new(
            "key_changed",
            "the server returned a key with a different fingerprint from the one you entered; do not share with \
             this person until you have checked their fingerprint with them again",
        ));
    }
    Ok(())
}

/// The fingerprint of the key pinned for `email` on this server, if any.
fn pinned_fingerprint(state: &AppState, server: &str, email: &str) -> CommandResult<Option<String>> {
    let known = state.known_keys.lock().map_err(|_| "key store lock poisoned".to_string())?;
    Ok(known.pinned_key(server, email).map(|key| key.fingerprint()))
}

/// The key the UI showed and the user approved must be byte-for-byte the key
/// the server returns now. Fingerprints are for people; this compares keys.
fn check_confirmed_key(served: &PublicKey, confirmed_public_key: &str) -> CommandResult<()> {
    if served.to_base64() != confirmed_public_key.trim() {
        return Err(CommandError::new(
            "key_changed",
            "the server returned a different key than the one you confirmed; look it up again",
        ));
    }
    Ok(())
}

/// Step two: `confirmed_public_key` is the key the user saw and approved. The
/// key is fetched again, must still match, and is pinned once the server has
/// accepted the invite. A 409 (key rotated meanwhile) is retried once.
#[tauri::command]
async fn invite(
    state: State<'_, AppState>,
    id: i64,
    email: String,
    message: String,
    confirmed_public_key: String,
) -> CommandResult<()> {
    let api = api(&state)?;
    // Ask with the fingerprint of the very key the user approved: if the
    // server has since moved to another one, the lookup fails outright rather
    // than handing us a key to check after the fact.
    let confirmed = PublicKey::from_base64(confirmed_public_key.trim()).map_err(user_facing)?;
    let invitee = api.lookup_user(&email, &confirmed.fingerprint()).await?;
    check_confirmed_key(&invitee.public_key, &confirmed_public_key)?;
    for attempt in 0..2 {
        let request = with_session(&state, |session| {
            let loaded = loaded_key(session, id)?;
            Ok(InviteRequest {
                key_version: loaded.version,
                email: invitee.email.clone(),
                fingerprint: invitee.public_key.fingerprint(),
                wrapped_key: loaded.key.wrap_for(&invitee.public_key).map_err(user_facing)?,
                message: message.clone(),
            })
        })?;
        match api.create_invite(id, &request).await {
            Ok(_) => return pin_keys(&state, api.base_url(), &[(invitee.email.clone(), invitee.public_key.clone())]),
            Err(ClientError::Conflict(_)) if attempt == 0 => refresh_key(&state, &api, id).await?,
            Err(error) => return Err(error.into()),
        }
    }
    Err("the secret keeps changing under us; refresh and try again".into())
}

fn pin_keys(state: &AppState, server: &str, keys: &[(String, PublicKey)]) -> CommandResult<()> {
    let mut known = state.known_keys.lock().map_err(|_| "key store lock poisoned".to_string())?;
    for (email, key) in keys {
        known.pin(server, email, key);
    }
    known.save(&state.known_keys_path).map_err(|e| format!("cannot save known keys: {e}").into())
}

/// Revoke `user_id` and rotate the secret's key: the payload is re-encrypted
/// under a fresh key wrapped for everyone who still has access. Every
/// remaining member's key must be pinned on this device or confirmed by the
/// user in `confirmed`; otherwise nothing changes and the unconfirmed members
/// are returned for the UI to show. A 409 from the server (someone accepted,
/// left, or rotated meanwhile) is retried once from fresh data.
#[tauri::command]
async fn revoke_access(
    state: State<'_, AppState>,
    id: i64,
    user_id: i64,
    confirmed: Vec<ConfirmedKey>,
) -> CommandResult<RevokeOutcome> {
    let api = api(&state)?;
    for attempt in 0..2 {
        let (view, access) = tokio::try_join!(api.get_secret(id), api.get_access(id))?;
        let remaining = {
            let known = state.known_keys.lock().map_err(|_| "key store lock poisoned".to_string())?;
            match plan_rewrap(&known, api.base_url(), &access.members, user_id, &confirmed) {
                Ok(remaining) => remaining,
                Err(members) => return Ok(RevokeOutcome::Confirm { members }),
            }
        };
        let (request, new_key) = with_session(&state, |session| {
            let payload = decrypt_view(session, &view)?;
            let new_key = SecretKey::generate();
            let mut wrapped_keys = remaining
                .iter()
                .map(|(user_id, public_key)| {
                    Ok(WrappedKeyFor {
                        user_id: *user_id,
                        wrapped_key: WrappedKey::Shared(new_key.wrap_for(public_key).map_err(user_facing)?),
                    })
                })
                .collect::<CommandResult<Vec<_>>>()?;
            wrapped_keys.push(WrappedKeyFor {
                user_id: session.user_id,
                wrapped_key: WrappedKey::Owner(new_key.wrap_for_owner(&session.self_wrap_key)),
            });
            let payload = new_key.encrypt(&view.name, &payload).map_err(user_facing)?;
            Ok((RevokeAccessRequest { key_version: view.key_version, payload, wrapped_keys }, new_key))
        })?;
        match api.revoke_access(id, user_id, &request).await {
            Ok(result) => {
                // Pin only now: a key is trusted once something was encrypted to it.
                let pins: Vec<(String, PublicKey)> = access
                    .members
                    .iter()
                    .filter(|m| remaining.iter().any(|(id, _)| *id == m.user_id))
                    .map(|m| (m.email.clone(), m.public_key.clone()))
                    .collect();
                pin_keys(&state, api.base_url(), &pins)?;
                with_session(&state, |session| {
                    session.keys.insert(id, LoadedKey { key: new_key, version: result.key_version });
                    Ok(())
                })?;
                return Ok(RevokeOutcome::Done { cancelled_invites: result.cancelled_invites });
            }
            Err(ClientError::Conflict(_)) if attempt == 0 => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err("the secret's membership keeps changing; refresh and try again".into())
}

/// Decide which remaining members the rotated key may be wrapped for. A key
/// the pin store knows is fine; one it has never seen, or has seen differently,
/// needs the user's confirmation, matched on the full key bytes.
fn plan_rewrap(
    known: &KnownKeys,
    server: &str,
    members: &[Member],
    revoked: i64,
    confirmed: &[ConfirmedKey],
) -> Result<Vec<(i64, PublicKey)>, Vec<UnconfirmedMember>> {
    let mut remaining = Vec::new();
    let mut unconfirmed = Vec::new();
    for member in members.iter().filter(|m| m.user_id != revoked) {
        let status = known.check(server, &member.email, &member.public_key);
        let served = member.public_key.to_base64();
        let is_confirmed = confirmed.iter().any(|c| c.user_id == member.user_id && c.public_key == served);
        if matches!(status, KeyStatus::Known) || is_confirmed {
            remaining.push((member.user_id, member.public_key.clone()));
        } else {
            unconfirmed.push(UnconfirmedMember {
                user_id: member.user_id,
                email: member.email.clone(),
                fingerprint: member.public_key.fingerprint(),
                public_key: served,
                status,
            });
        }
    }
    if unconfirmed.is_empty() {
        Ok(remaining)
    } else {
        Err(unconfirmed)
    }
}

#[tauri::command]
async fn cancel_invite(state: State<'_, AppState>, id: i64, invite_id: i64) -> CommandResult<()> {
    Ok(api(&state)?.cancel_invite(id, invite_id).await?)
}

#[tauri::command]
async fn list_invites(state: State<'_, AppState>) -> CommandResult<Vec<InviteView>> {
    Ok(api(&state)?.list_invites().await?)
}

#[tauri::command]
async fn accept_invite(state: State<'_, AppState>, invite_id: i64) -> CommandResult<()> {
    Ok(api(&state)?.accept_invite(invite_id).await?)
}

#[tauri::command]
async fn decline_invite(state: State<'_, AppState>, invite_id: i64) -> CommandResult<()> {
    Ok(api(&state)?.decline_invite(invite_id).await?)
}

/// Entry point shared by the desktop binary and the mobile shells.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            app.manage(AppState::new(data_dir.join(KNOWN_KEYS_FILE))?);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            register,
            login,
            logout,
            sign_out_other_devices,
            server_capabilities,
            google_sign_in,
            google_unlock,
            google_create_account,
            google_link,
            google_unlink,
            change_password,
            refresh_account,
            session_info,
            startup_warnings,
            ui_constants,
            list_secrets,
            reveal_password,
            copy_password,
            reveal_field,
            copy_field,
            clear_copied_value,
            create_secret,
            update_secret,
            delete_secret,
            generate_password,
            get_access,
            lookup_invitee,
            invite,
            revoke_access,
            cancel_invite,
            list_invites,
            accept_invite,
            decline_invite,
        ])
        .run(tauri::generate_context!())
        .expect("error while running credvault");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "Clear now" and the timer must not both act on one copy: whichever
    /// runs first takes the digest and the other finds nothing to clear.
    #[test]
    fn a_copied_digest_is_handed_over_once() {
        let slot = Mutex::new(Some([7u8; 32]));
        assert_eq!(take_copied_digest(&slot), Some([7u8; 32]));
        assert_eq!(take_copied_digest(&slot), None);
    }

    #[test]
    fn nothing_copied_means_nothing_to_clear() {
        assert_eq!(take_copied_digest(&Mutex::new(None)), None);
    }

    /// The server composes the sign-in URL, and the server is the party this
    /// app guards against. Only Google's own authorization page over https is
    /// opened; everything else is refused before the platform URL handler sees
    /// the string.
    #[test]
    fn only_googles_own_sign_in_page_is_opened() {
        let google = "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=y";
        assert!(check_authorization_url(google).is_ok());
        // Case and a different path or query are Google's business, not ours.
        assert!(check_authorization_url("https://ACCOUNTS.GOOGLE.COM/anything?a=b").is_ok());

        for refused in [
            // The phishing shape: a host that merely reads like Google's.
            "https://accounts.google.com.attacker.example/signin",
            "https://accounts-google.com/o/oauth2/v2/auth",
            // Credentials in the authority, which hide the real host.
            "https://accounts.google.com@attacker.example/o/oauth2/v2/auth",
            // A homograph host punycodes to something that is not Google.
            "https://accounts.googlé.com/o/oauth2/v2/auth",
            // Cleartext, even to the right host.
            "http://accounts.google.com/o/oauth2/v2/auth",
            // Schemes that are not a browser at all. The Windows one reaches
            // ShellExecuteW as a UNC path and authenticates outward.
            "file://attacker.example/share/payload.exe",
            "smb://attacker.example/share",
            "javascript:alert(1)",
            "mailto:someone@attacker.example",
            // The right host on a port Google's sign-in page is not on.
            "https://accounts.google.com:8443/o/oauth2/v2/auth",
            // Not a URL.
            "",
            "not a url",
        ] {
            let error = check_authorization_url(refused).expect_err("{refused} must be refused");
            assert_eq!(error.code, "oauth", "{refused}");
        }
    }

    /// The message is the whole product of this check: nothing is opened, so
    /// all the user gets is the sentence. It has to name where the server
    /// tried to send them, including for the schemes that have no host.
    #[test]
    fn the_refusal_names_where_the_server_tried_to_send_you() {
        let host = check_authorization_url("https://accounts.google.com.attacker.example/x").unwrap_err();
        assert!(host.message.contains("accounts.google.com.attacker.example"), "{}", host.message);

        let port = check_authorization_url("https://accounts.google.com:8443/x").unwrap_err();
        assert!(port.message.contains("port 8443"), "{}", port.message);

        // No host at all: the sentence must not come out with a hole in it.
        let hostless = check_authorization_url("javascript:alert(1)").unwrap_err();
        assert!(hostless.message.contains("javascript"), "{}", hostless.message);
        assert!(!hostless.message.contains("send you to  "), "{}", hostless.message);
    }

    #[test]
    fn server_url_requires_https_except_on_loopback() {
        let canonical = |url: &str| normalize_server_url(url).unwrap().as_str().to_string();
        assert_eq!(canonical(" https://vault.example.com/ "), "https://vault.example.com");
        assert_eq!(canonical("https://vault.example.com:8443/base/"), "https://vault.example.com:8443/base");
        assert_eq!(canonical("http://127.0.0.1:8787"), "http://127.0.0.1:8787");
        assert_eq!(canonical("http://LocalHost:8787"), "http://localhost:8787");
        assert_eq!(canonical("HTTPS://Vault.Example.com"), "https://vault.example.com");
        assert_eq!(canonical("http://[::1]:8787"), "http://[::1]:8787");

        let remote = normalize_server_url("http://vault.example.com").unwrap_err();
        assert!(remote.message.contains("https://"), "{remote}");
        assert!(normalize_server_url("http://10.0.0.5:8787").is_err());
        assert!(normalize_server_url("http://localhost.example.com").is_err());
        assert!(normalize_server_url("vault.example.com").is_err());
        assert!(normalize_server_url("ftp://vault.example.com").is_err());
        assert!(normalize_server_url("").is_err());
        assert!(normalize_server_url("https://").is_err());
    }

    /// The address the UI shows, the address keys are pinned against and the
    /// address the credential is bound to must be one string, or a user who
    /// types the same server differently is locked out of their own account.
    #[test]
    fn the_credential_is_bound_to_the_canonical_address() {
        let master = MasterKey::derive("correct horse battery", "kat@example.com").unwrap();
        let typed = normalize_server_url("HTTPS://Vault.Example.com/").unwrap();
        let plain = normalize_server_url("https://vault.example.com").unwrap();
        assert_eq!(master.auth_hash(&typed), master.auth_hash(&plain));

        let elsewhere = normalize_server_url("https://vault.example.org").unwrap();
        assert_ne!(master.auth_hash(&typed), master.auth_hash(&elsewhere));
    }

    /// The rule that decides which of three things a person is told about a
    /// passphrase change whose answer was lost. Driven directly, because the
    /// wrong verdict here is the one that loses a vault.
    #[test]
    fn a_lost_answer_is_only_called_settled_when_the_readings_agree() {
        // A session that disappears is conclusive immediately: nothing but the
        // committing transaction deletes one.
        assert_eq!(fold_reading(0, Reading::Gone).1, Some(ChangeOutcome::Applied));
        assert_eq!(fold_reading(5, Reading::Gone).1, Some(ChangeOutcome::Applied));

        // A session that is still there is never conclusive on its own; it
        // only becomes an answer by holding.
        let run = |readings: &[Reading]| {
            let mut alive = 0;
            for reading in readings {
                let (next, settled) = fold_reading(alive, *reading);
                assert!(settled.is_none(), "{readings:?} should not settle early");
                alive = next;
            }
            settle(alive)
        };
        assert_eq!(run(&[Reading::Alive]), ChangeOutcome::Unknown, "one reading is not a verdict");
        assert_eq!(run(&[Reading::Alive, Reading::Alive]), ChangeOutcome::NotApplied);

        // A failure breaks the run, so a single success after a bad patch
        // cannot decide it. This is the case that used to return NotApplied
        // off one observation.
        assert_eq!(
            run(&[Reading::Alive, Reading::Alive, Reading::Unreachable, Reading::Alive]),
            ChangeOutcome::Unknown,
            "one answer after a run of failures says nothing"
        );
        assert_eq!(run(&[Reading::Unreachable, Reading::Unreachable]), ChangeOutcome::Unknown);
        // And recovering for long enough does settle it.
        assert_eq!(run(&[Reading::Unreachable, Reading::Alive, Reading::Alive]), ChangeOutcome::NotApplied);
    }

    /// The whole point of tagging stored blobs: someone whose passphrase is
    /// correct must not be told it is wrong, and must not be told their data
    /// is corrupt either, when the real problem is a scheme this build cannot
    /// run.
    #[test]
    fn a_vault_from_another_scheme_is_not_reported_as_a_bad_passphrase() {
        use credvault_core::CryptoError;

        let wrong_key = unlock_failure(CryptoError::Decrypt, "that password does not unlock this vault");
        assert_eq!(wrong_key.code, "locked");
        assert_eq!(wrong_key.message, "that password does not unlock this vault");

        for error in [
            CryptoError::NewerFormat { what: "vault key", found: 2 },
            CryptoError::UnknownFormat { what: "vault key", found: 7 },
        ] {
            let reported = unlock_failure(error, "that password does not unlock this vault");
            assert_ne!(reported.code, "locked", "{reported:?}");
            assert!(reported.message.contains("vault key"), "{reported:?}");
            assert!(!reported.message.contains("password"), "{reported:?}");
        }

        // Anything else is still a failure to unlock, and still says so.
        let malformed = unlock_failure(CryptoError::Encoding("private key must be 32 bytes".into()), "wrong password");
        assert_eq!(malformed.code, "locked");
        assert!(malformed.message.contains("32 bytes"), "{malformed:?}");
    }

    /// A throttled request is the one failure that leaves the caller's session
    /// intact, so the UI has to be able to tell it apart and say how long to
    /// wait. Both halves travel on the error.
    #[test]
    fn a_throttled_error_carries_its_own_code_and_the_wait() {
        let throttled = CommandError::from(ClientError::TooManyRequests {
            message: "too many requests; try again in 6 seconds".into(),
            retry_after_secs: Some(6),
        });
        assert_eq!(throttled.code, "throttled");
        assert_eq!(throttled.retry_after_secs, Some(6));

        // A server that sends no usable Retry-After still classifies, and the
        // UI falls back to "in a few seconds".
        let no_hint =
            CommandError::from(ClientError::TooManyRequests { message: "slow down".into(), retry_after_secs: None });
        assert_eq!(no_hint.code, "throttled");
        assert_eq!(no_hint.retry_after_secs, None);

        // Nothing else claims a wait.
        for other in [ClientError::Network("down".into()), ClientError::Server("boom".into())] {
            let error = CommandError::from(other);
            assert_ne!(error.code, "throttled");
            assert_eq!(error.retry_after_secs, None);
        }
    }

    fn test_session(identity: Identity) -> Session {
        Session {
            api: ApiClient::new("http://localhost:1").unwrap(),
            user_id: 1,
            email: "me@example.com".into(),
            identity,
            self_wrap_key: Zeroizing::new(credvault_core::aead::random_bytes()),
            keys: HashMap::new(),
            password_login: true,
            google_email: None,
        }
    }

    /// An owned secret with a self-wrapped owner copy.
    fn view_for(session: &Session, key: &SecretKey, version: i64, payload: &SecretPayload) -> SecretView {
        SecretView {
            id: 7,
            name: "Bank".into(),
            owner_email: "me@example.com".into(),
            is_owner: true,
            payload: key.encrypt("Bank", payload).unwrap(),
            wrapped_key: WrappedKey::Owner(key.wrap_for_owner(&session.self_wrap_key)),
            updated_at: chrono::Utc::now(),
            key_version: version,
        }
    }

    #[test]
    fn an_owner_copy_the_server_could_have_made_is_always_refused() {
        let mut session = test_session(Identity::generate());
        let key = SecretKey::generate();
        let mut view = view_for(&session, &key, 0, &payload());
        // A sealed box to our own public key opens perfectly well, and is
        // exactly what a server that wanted to choose our key would send. It
        // is refused on the grounds of its form alone, from the first fetch.
        view.wrapped_key = WrappedKey::Shared(key.wrap_for(session.identity.public_key()).unwrap());
        let error = key_for(&mut session, &view).unwrap_err();
        assert_eq!(error.code, "untrusted_key");
        assert!(!session.keys.contains_key(&7), "a refused copy must not be cached");

        // Only the self-wrapped form, which only we can produce, is accepted.
        let genuine = view_for(&session, &key, 0, &payload());
        assert!(key_for(&mut session, &genuine).is_ok());
        assert_eq!(decrypt_view(&mut session, &genuine).unwrap(), payload());
    }

    #[test]
    fn shared_secrets_only_come_as_sealed_boxes() {
        let mut session = test_session(Identity::generate());
        let key = SecretKey::generate();
        let mut shared = view_for(&session, &key, 0, &payload());
        shared.is_owner = false;
        shared.owner_email = "ama@example.com".into();
        // An owner-form copy on a shared secret is nonsense, whoever sent it.
        let error = key_for(&mut session, &shared).unwrap_err();
        assert_eq!(error.code, "untrusted_key");
        shared.wrapped_key = WrappedKey::Shared(key.wrap_for(session.identity.public_key()).unwrap());
        assert!(key_for(&mut session, &shared).is_ok());
        assert_eq!(decrypt_view(&mut session, &shared).unwrap(), payload());
    }

    fn payload() -> SecretPayload {
        SecretPayload {
            username: "u".into(),
            password: "p".into(),
            url: String::new(),
            notes: String::new(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn a_rotated_key_replaces_the_stale_cached_one() {
        let mut session = test_session(Identity::generate());
        session.keys.insert(7, LoadedKey { key: SecretKey::generate(), version: 0 });

        // Another device rotated to version 1 with a new key.
        let new_key = SecretKey::generate();
        let view = view_for(&session, &new_key, 1, &payload());
        assert_eq!(decrypt_view(&mut session, &view).unwrap(), payload());
        assert_eq!(session.keys[&7].version, 1);
        assert!(session.keys[&7].key.decrypt("Bank", &view.payload).is_ok());

        // Same version again: the cached key is reused and still works.
        let again = view_for(&session, &new_key, 1, &payload());
        assert_eq!(decrypt_view(&mut session, &again).unwrap(), payload());
    }

    #[test]
    fn a_tampered_payload_fails_and_leaves_no_cached_key() {
        let mut session = test_session(Identity::generate());
        let key = SecretKey::generate();
        let mut view = view_for(&session, &key, 0, &payload());
        view.payload.ciphertext[0] ^= 1;
        assert!(decrypt_view(&mut session, &view).is_err());
        assert!(!session.keys.contains_key(&7));
    }

    fn member(id: i64, email: &str, identity: &Identity) -> Member {
        Member { user_id: id, email: email.into(), public_key: identity.public_key().clone() }
    }

    #[test]
    fn rewrap_requires_pinned_or_confirmed_keys_and_skips_the_revoked_member() {
        let server = "https://vault.example.com";
        let (bob, carol, dave) = (Identity::generate(), Identity::generate(), Identity::generate());
        let members = [
            member(2, "bob@example.com", &bob),
            member(3, "carol@example.com", &carol),
            member(4, "dave@example.com", &dave),
        ];
        let mut known = KnownKeys::default();
        known.pin(server, "bob@example.com", bob.public_key());

        // Revoking Dave: Bob is pinned, Carol is unknown, so nothing may proceed.
        let unconfirmed = plan_rewrap(&known, server, &members, 4, &[]).unwrap_err();
        assert_eq!(unconfirmed.len(), 1);
        assert_eq!(unconfirmed[0].email, "carol@example.com");
        assert_eq!(unconfirmed[0].status, KeyStatus::New);
        assert_eq!(unconfirmed[0].public_key, carol.public_key().to_base64());

        // Confirming Carol's exact key lets it through; Dave is never included.
        let confirmed = [ConfirmedKey { user_id: 3, public_key: carol.public_key().to_base64() }];
        let remaining = plan_rewrap(&known, server, &members, 4, &confirmed).unwrap();
        assert_eq!(remaining.iter().map(|(id, _)| *id).collect::<Vec<_>>(), vec![2, 3]);

        // Confirming a different key for Carol does not count.
        let wrong = [ConfirmedKey { user_id: 3, public_key: dave.public_key().to_base64() }];
        assert!(plan_rewrap(&known, server, &members, 4, &wrong).is_err());

        // A changed pinned key is reported as changed, with the old fingerprint.
        let bob_again = Identity::generate();
        let swapped = [member(2, "bob@example.com", &bob_again)];
        let unconfirmed = plan_rewrap(&known, server, &swapped, 4, &[]).unwrap_err();
        assert_eq!(unconfirmed[0].status, KeyStatus::Changed { pinned_fingerprint: bob.public_key().fingerprint() });
    }

    fn stored_field_id(id: &str, label: &str, value: &str, secret: bool) -> CustomField {
        CustomField { id: id.into(), label: label.into(), value: value.into(), secret }
    }
    fn stored_field(label: &str, value: &str, secret: bool) -> CustomField {
        stored_field_id(&secret::new_field_id(), label, value, secret)
    }
    /// A row the user edited or added: it carries its own value.
    fn submitted(label: &str, value: &str, secret: bool) -> FieldInput {
        FieldInput { id: None, label: label.into(), value: Some(value.into()), secret }
    }

    /// A row standing for the stored field `id`, possibly renamed since.
    fn kept(label: &str, id: &str, secret: bool) -> FieldInput {
        FieldInput { id: Some(id.into()), label: label.into(), value: None, secret }
    }

    /// The payload the UI actually produces, read from a fixture that is
    /// checked in and that `ui-tests/fields.test.js` compares against what
    /// the editor emits. Shared rather than transcribed: a literal copied
    /// across once would let either side rename a key while both suites
    /// stayed green, and this is the only guard on a boundary the
    /// custom-fields work created on purpose. Either suite fails on drift,
    /// whichever runs first; regenerate with UPDATE_FIXTURES=1.
    #[test]
    fn the_payloads_the_ui_sends_deserialize_into_the_commands_that_receive_them() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            created: SecretForm,
            edited: SecretForm,
        }
        let fixture: Fixture =
            serde_json::from_str(include_str!("../ui-tests/testdata/submitted_fields.json")).unwrap();

        // Creating: every row carries its own value and has no id yet.
        assert_eq!(fixture.created.name, "Email");
        assert_eq!(fixture.created.password.as_deref().map(String::as_str), Some("brand-new-password"));
        let created = resolve_fields(fixture.created.fields, &[]).unwrap();
        assert_eq!(created[1].label, "PIN");
        assert_eq!(created[1].value, "4321");
        // The flag deciding whether a value is ever masked is part of the
        // contract: `secret` defaults to false, so a renamed key on the JS
        // side would silently unmask every field it touched.
        assert!(created[1].secret && !created[0].secret, "the hidden flag must survive the crossing");
        assert!(!created[0].id.is_empty() && created[0].id != created[1].id, "each new field gets its own id");

        // Editing: a blank password box keeps the password, and the hidden row
        // that survived deleting its same-named neighbour keeps its own value.
        assert!(fixture.edited.password.is_none(), "a blank password box must arrive as None, not as \"\"");
        let stored = [
            stored_field_id("aa01", "Account number", "12345678", false),
            stored_field_id("bb02", "Recovery code", "FIRST-code", true),
            stored_field_id("cc03", "Recovery code", "SECOND-code", true),
        ];
        let edited = resolve_fields(fixture.edited.fields, &stored).unwrap();
        // The two sides of the boundary: an empty string erases, null keeps.
        assert_eq!(edited[0].value, "", "an emptied visible field is stored empty, not kept");
        assert_eq!(edited[1].value, "SECOND-code", "the deleted row's value must not be the one kept");
        assert_eq!(edited[1].id, "cc03");
        assert!(edited[1].secret && !edited[0].secret);
    }

    /// The stage names are a contract with the sign-in screen: it picks which
    /// prompt to show from `stage`, so renaming a variant here silently breaks
    /// the flow rather than failing to compile.
    #[test]
    fn the_sign_in_stage_tells_the_ui_which_prompt_to_show() {
        let unlock = serde_json::to_value(GoogleSignInStage::Unlock { email: "kat@example.com".into() }).unwrap();
        assert_eq!(unlock["stage"], "unlock");
        assert_eq!(unlock["email"], "kat@example.com");

        let create = serde_json::to_value(GoogleSignInStage::CreateAccount {
            email: "kat@example.com".into(),
            registration_token_required: true,
        })
        .unwrap();
        assert_eq!(create["stage"], "create_account");
        assert_eq!(create["email"], "kat@example.com");
        assert_eq!(create["registration_token_required"], true);
    }

    #[test]
    fn a_key_whose_fingerprint_is_not_the_one_asked_for_is_refused() {
        // The check that separates an honest server from one that ignored the
        // fingerprint and answered with a key of its own choosing.
        let bob = Identity::generate();
        let fp = bob.public_key().fingerprint();
        assert!(check_served_key(bob.public_key(), &fp).is_ok());
        assert!(check_served_key(bob.public_key(), &fp.to_uppercase()).is_ok());

        let server_key = Identity::generate();
        let error = check_served_key(server_key.public_key(), &fp).unwrap_err();
        assert_eq!(error.code, "key_changed");
        assert!(error.message.contains("different fingerprint"), "{error}");
        // A partial entry must not be accepted as a match either.
        assert!(check_served_key(bob.public_key(), &fp[..9]).is_err());
    }

    #[test]
    fn a_fingerprint_matches_however_it_was_typed_but_not_a_different_key() {
        let bob = Identity::generate();
        let fp = bob.public_key().fingerprint();
        for typed in [fp.clone(), fp.to_uppercase(), fp.replace('-', ""), format!("  {fp}  ")] {
            assert!(fingerprint_matches(&bob.public_key().fingerprint(), &typed), "{typed:?}");
        }
        // The check that stops a server handing us a key we did not ask for.
        let other = Identity::generate();
        assert!(!fingerprint_matches(&other.public_key().fingerprint(), &fp));
        // A partial entry must not match by being a prefix of the real one.
        assert!(!fingerprint_matches(&bob.public_key().fingerprint(), &fp[..9]));
        assert!(!fingerprint_matches(&bob.public_key().fingerprint(), ""));
    }

    /// Two fields deliberately sharing a label, which is the case every rule
    /// about identity exists for.
    fn two_recovery_codes() -> [CustomField; 3] {
        [
            stored_field_id("aa01", "Account number", "12345678", false),
            stored_field_id("bb02", "Recovery code", "FIRST-code", true),
            stored_field_id("cc03", "Recovery code", "SECOND-code", true),
        ]
    }

    #[test]
    fn a_field_submitted_without_a_value_keeps_the_stored_one() {
        let stored = two_recovery_codes();
        let resolved = resolve_fields(
            vec![
                submitted("Account", "87654321", false), // edited, so the new value wins
                kept("Recovery code", "bb02", true),     // left untouched in the form
                submitted("PIN", "1234", true),          // added in this edit
            ],
            &stored,
        )
        .unwrap();
        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved[0].value, "87654321");
        assert_eq!(resolved[1].value, "FIRST-code", "an untouched sensitive value must survive the edit");
        assert_eq!(resolved[2].label, "PIN");
        assert!(!resolved[2].id.is_empty(), "a new field is given an id of its own");
        // Labels are stored trimmed.
        assert_eq!(resolve_fields(vec![submitted("  PIN  ", "1", true)], &[]).unwrap()[0].label, "PIN");
    }

    #[test]
    fn a_kept_row_names_its_own_value_however_the_others_move() {
        // Both rows look identical in the form, because neither value is ever
        // shown. Resolving by label would hand back the first match; resolving
        // by position would survive a reorder on another device and hand back
        // whatever now sits there.
        let stored = two_recovery_codes();

        let both =
            resolve_fields(vec![kept("Recovery code", "bb02", true), kept("Recovery code", "cc03", true)], &stored)
                .unwrap();
        assert_eq!(both[0].value, "FIRST-code");
        assert_eq!(both[1].value, "SECOND-code", "the second must not take the first's value");

        // Delete the first row: what survives is the second one's value.
        let survivor = resolve_fields(vec![kept("Recovery code", "cc03", true)], &stored).unwrap();
        assert_eq!(survivor[0].value, "SECOND-code", "deleting the first row must not keep the first row's value");

        // Another device reordered and renamed the others in the meantime.
        // The id still means the same field, so the right value is kept.
        let moved = [
            stored_field_id("cc03", "Recovery code", "SECOND-code", true),
            stored_field_id("bb02", "Primary code", "FIRST-code", true),
        ];
        let after = resolve_fields(vec![kept("Recovery code", "bb02", true)], &moved).unwrap();
        assert_eq!(after[0].value, "FIRST-code", "identity must survive a reorder and a rename elsewhere");
    }

    #[test]
    fn renaming_a_hidden_field_keeps_its_value() {
        // The value was never shown, so demanding it be retyped to rename the
        // row would push someone toward deleting an unrecoverable secret.
        let stored = two_recovery_codes();
        let renamed = resolve_fields(vec![kept("Backup code", "bb02", true)], &stored).unwrap();
        assert_eq!(renamed[0].label, "Backup code");
        assert_eq!(renamed[0].value, "FIRST-code");
        assert_eq!(renamed[0].id, "bb02", "renaming does not change which field it is");
    }

    #[test]
    fn a_kept_row_whose_label_was_blanked_is_refused_by_name_not_dropped() {
        // The UI sends the row rather than filtering it out, so the value it
        // still stands for is refused loudly instead of disappearing with it.
        let stored = two_recovery_codes();
        let blanked = FieldInput { id: Some("bb02".into()), label: String::new(), value: None, secret: true };
        let error = resolve_fields(vec![blanked], &stored).unwrap_err();
        assert_eq!(error.code, "crypto");
        assert!(error.message.contains("label"), "{error}");
    }

    #[test]
    fn an_unseen_value_cannot_be_kept_while_being_un_hidden() {
        // Copying a value nobody has seen into a now-visible field would put
        // it in the list in clear, for the owner and everyone it is shared
        // with. The editor cannot ask for this; the rule is enforced anyway,
        // because this is the half that writes the payload.
        let stored = two_recovery_codes();
        let unmask = FieldInput { id: Some("bb02".into()), label: "Recovery code".into(), value: None, secret: false };
        let error = resolve_fields(vec![unmask], &stored).unwrap_err();
        assert_eq!(error.code, "field_value_required");
        assert!(error.message.contains("un-hidden"), "{error}");

        // Keeping it hidden is fine, and so is un-hiding it with a new value.
        assert!(resolve_fields(vec![kept("Recovery code", "bb02", true)], &stored).is_ok());
        let retyped = FieldInput {
            id: Some("bb02".into()),
            label: "Recovery code".into(),
            value: Some("x".into()),
            secret: false,
        };
        assert_eq!(resolve_fields(vec![retyped], &stored).unwrap()[0].value, "x");
        // A visible stored field may of course be kept visible.
        assert!(resolve_fields(vec![kept("Account number", "aa01", false)], &stored).is_ok());
    }

    #[test]
    fn keeping_a_value_that_was_never_stored_is_refused_rather_than_emptied() {
        let stored = two_recovery_codes();

        // An id that is not in the payload any more: the field was deleted on
        // another device, so there is nothing to keep and saying so beats
        // attaching the row to whatever else is there.
        let error = resolve_fields(vec![kept("Recovery code", "gone", true)], &stored).unwrap_err();
        assert_eq!(error.code, "field_value_required");
        assert!(error.message.contains("Recovery code"), "{error}");

        // A kept row with no id at all cannot be resolved either.
        let orphan = FieldInput { id: None, label: "PIN".into(), value: None, secret: true };
        assert!(resolve_fields(vec![orphan], &stored).is_err());
        // Nor can one against an empty store.
        assert!(resolve_fields(vec![kept("PIN", "bb02", true)], &[]).is_err());
        // A blank label is refused wherever it came from.
        assert!(resolve_fields(vec![submitted("   ", "x", false)], &stored).is_err());
        // The same field may not be sent twice.
        let twice = vec![kept("Recovery code", "bb02", true), kept("Recovery code", "bb02", true)];
        assert!(resolve_fields(twice, &stored).is_err());
    }

    #[test]
    fn the_list_withholds_sensitive_field_values_but_not_the_rest() {
        let payload = SecretPayload {
            username: "jude".into(),
            password: "pw".into(),
            url: String::new(),
            notes: String::new(),
            fields: vec![stored_field("Recovery code", "aaaa-bbbb", true), stored_field("Account", "12345678", false)],
        };
        let summaries = field_summaries(&payload);
        assert_eq!(summaries[0].label, "Recovery code");
        assert_eq!(summaries[0].value, "", "a sensitive value must not travel to the UI with the list");
        assert!(summaries[0].secret);
        assert_eq!(summaries[1].value, "12345678");
        assert!(!summaries[1].secret);

        // `has_value` is what lets the editor tell a withheld value from an
        // absent one. It crosses to JavaScript by name, and the payload
        // fixture only pins the other direction, so pin the name here: a
        // rename would otherwise read as `undefined` in the editor and
        // quietly reinstate the "an empty hidden field can never be
        // un-hidden" dead end.
        assert!(summaries[0].has_value, "a hidden field with a value says so");
        // Built in full: SecretPayload zeroises on drop, so it cannot be
        // moved out of with struct update syntax.
        let mut empty = SecretPayload::default();
        empty.fields =
            vec![CustomField { id: "cc03".into(), label: "Note".into(), value: String::new(), secret: true }];
        assert!(!field_summaries(&empty)[0].has_value, "a hidden field with nothing stored says so too");
        let json = serde_json::to_string(&field_summaries(&empty)[0]).unwrap();
        for key in ["\"id\"", "\"label\"", "\"value\"", "\"secret\"", "\"has_value\""] {
            assert!(json.contains(key), "the editor reads {key} by name: {json}");
        }
    }

    #[test]
    fn invite_confirmation_compares_whole_keys() {
        let bob = Identity::generate();
        let other = Identity::generate();
        assert!(check_confirmed_key(bob.public_key(), &bob.public_key().to_base64()).is_ok());
        assert!(check_confirmed_key(bob.public_key(), &format!("  {}  ", bob.public_key().to_base64())).is_ok());
        let error = check_confirmed_key(bob.public_key(), &other.public_key().to_base64()).unwrap_err();
        assert_eq!(error.code, "key_changed");
        assert!(check_confirmed_key(bob.public_key(), &bob.public_key().fingerprint()).is_err());
    }

    #[test]
    fn corrupt_pin_file_is_moved_aside_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_keys.json");
        std::fs::write(&path, b"{not json").unwrap();
        let (known, warning) = load_known_keys_or_recover(&path).unwrap();
        assert!(!path.exists());
        let moved = std::fs::read_dir(dir.path())
            .unwrap()
            .any(|e| e.unwrap().file_name().to_string_lossy().contains("corrupt"));
        assert!(moved);
        assert!(warning.unwrap().contains("could not be read"));
        let bob = Identity::generate();
        assert_eq!(known.check("https://x", "bob@example.com", bob.public_key()), KeyStatus::New);
    }
}
