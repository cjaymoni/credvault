//! credvault app: a Tauri shell around credvault-core, built as a library so the
//! desktop binary and the iOS/Android shells share one entry point. All encryption and
//! decryption happens here; the server only ever receives ciphertext.

mod client;
mod known_keys;

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use credvault_core::aead::KEY_LEN;
use credvault_core::api::*;
use credvault_core::{kdf, password, secret, Identity, MasterKey, PublicKey, SecretKey, SecretPayload, WrappedKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroizing;

use client::{ApiClient, ClientError};
use known_keys::{KeyStatus, KnownKeys};

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
    is_owner: bool,
    owner_email: String,
    updated_at: chrono::DateTime<chrono::Utc>,
    error: Option<String>,
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
}

struct Session {
    api: ApiClient,
    user_id: i64,
    email: String,
    identity: Identity,
    /// Wraps our own copies of secret keys; only we can derive it, so the
    /// server cannot forge an owner copy.
    self_wrap_key: Zeroizing<[u8; KEY_LEN]>,
    /// True until every owner copy on this server has been upgraded from the
    /// sealed-box form; afterwards such a copy is refused as untrusted.
    legacy_owner_copies_allowed: bool,
    /// Decrypted secret keys from the last list, so reveal/update need no re-unwrap.
    keys: HashMap<i64, LoadedKey>,
}

/// A secret's unwrapped key with the server's key version it came from. Writes
/// echo the version, so a rotation by another device is refused (409) instead
/// of silently re-encrypting under a key a revoked member still holds.
struct LoadedKey {
    key: SecretKey,
    version: i64,
}

struct AppState {
    session: Mutex<Option<Session>>,
    known_keys: Mutex<KnownKeys>,
    known_keys_path: PathBuf,
    /// Bumped on every copy; a clear task only fires if it is still current.
    clipboard_generation: AtomicU64,
    startup_warnings: Mutex<Vec<String>>,
}

impl AppState {
    fn new(known_keys_path: PathBuf) -> std::io::Result<Self> {
        let (known_keys, warning) = load_known_keys_or_recover(&known_keys_path)?;
        Ok(Self {
            session: Mutex::new(None),
            known_keys: Mutex::new(known_keys),
            known_keys_path,
            clipboard_generation: AtomicU64::new(0),
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
}

impl CommandError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
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
        let code = match error {
            ClientError::Network(_) => "network",
            ClientError::Server(_) => "server",
            ClientError::Conflict(_) => "conflict",
            ClientError::Unauthorized => "unauthorized",
            ClientError::InvalidUrl(_) => "invalid_url",
        };
        Self::new(code, error.to_string())
    }
}

type CommandResult<T> = Result<T, CommandError>;

fn user_facing(error: credvault_core::CryptoError) -> CommandError {
    CommandError::new("crypto", error.to_string())
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

/// Clone the API handle out of the session so async work does not hold the lock.
fn api(state: &AppState) -> CommandResult<ApiClient> {
    with_session(state, |s| Ok(s.api.clone()))
}

/// Accept `http://` only for loopback hosts: the auth hash is a reusable login
/// credential and must never cross a network in the clear.
fn normalize_server_url(url: &str) -> CommandResult<String> {
    let trimmed = url.trim().trim_end_matches('/');
    let parsed = url::Url::parse(trimmed).map_err(|e| format!("invalid server URL: {e}"))?;
    let is_loopback = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err("server URL must include a host".into()),
    };
    match parsed.scheme() {
        "https" => {}
        "http" if is_loopback => {}
        "http" => {
            return Err("http:// is only allowed for localhost; use https:// for a remote server so your login \
                        credential is not sent in the clear"
                .into())
        }
        other => return Err(format!("unsupported URL scheme {other:?}; use https://").into()),
    }
    // The parsed form lower-cases the scheme and host, so the same server typed
    // two ways shares one set of pinned keys.
    Ok(parsed.to_string().trim_end_matches('/').to_string())
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
    let master = derive_master(password, email.clone()).await?;
    let identity = Identity::generate();
    let api = ApiClient::new(&server_url)?;
    let session = api
        .register(&RegisterRequest {
            email: email.clone(),
            auth_hash: master.auth_hash(),
            public_key: identity.public_key().clone(),
            encrypted_private_key: identity.encrypt_private_key(&master.private_key_encryption_key()),
            registration_token: registration_token.filter(|token| !token.trim().is_empty()),
        })
        .await?;
    install_session(
        &state,
        api.with_token(&session.token),
        session.user.id,
        session.user.email,
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
    let master = derive_master(password, email.clone()).await?;
    let api = ApiClient::new(&server_url)?;
    let session = api.login(&LoginRequest { email, auth_hash: master.auth_hash() }).await?;
    let identity =
        Identity::decrypt_private_key(&master.private_key_encryption_key(), &session.user.encrypted_private_key)
            .map_err(|_| {
                CommandError::new("locked", "could not unlock your keys; the account data may be corrupted")
            })?;
    install_session(
        &state,
        api.with_token(&session.token),
        session.user.id,
        session.user.email,
        identity,
        master.self_wrap_key(),
    )
}

fn summary_of(session: &Session) -> UserSummary {
    UserSummary {
        email: session.email.clone(),
        server_url: session.api.base_url().to_string(),
        fingerprint: session.identity.public_key().fingerprint(),
    }
}

fn install_session(
    state: &AppState,
    api: ApiClient,
    user_id: i64,
    email: String,
    identity: Identity,
    self_wrap_key: Zeroizing<[u8; KEY_LEN]>,
) -> CommandResult<UserSummary> {
    let legacy_owner_copies_allowed = {
        let known = state.known_keys.lock().map_err(|_| "key store lock poisoned".to_string())?;
        !known.is_owner_keys_upgraded(api.base_url())
    };
    let session =
        Session { api, user_id, email, identity, self_wrap_key, legacy_owner_copies_allowed, keys: HashMap::new() };
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
    Ok(())
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
    }
}

// ----- secret commands --------------------------------------------------------

/// Unwrap a secret's key, preferring the cached copy when it is from the same
/// key version. A newer version on the server means another device rotated
/// the key, so the wrapped key is unwrapped again. Returns whether the copy
/// was a legacy owner copy that should be upgraded.
fn key_for(session: &mut Session, view: &SecretView) -> CommandResult<bool> {
    if session.keys.get(&view.id).is_some_and(|loaded| loaded.version == view.key_version) {
        return Ok(false);
    }
    let (key, legacy) = unwrap_view_key(session, view)?;
    session.keys.insert(view.id, LoadedKey { key, version: view.key_version });
    Ok(legacy)
}

/// Which form of wrapped key is acceptable depends on who we are to the
/// secret. Our own secrets must come self-wrapped, because a sealed box is
/// something the server could have produced with a key it knows; a sealed box
/// is tolerated only while legacy copies are still being upgraded. Secrets
/// shared with us can only ever be sealed boxes.
fn unwrap_view_key(session: &Session, view: &SecretView) -> CommandResult<(SecretKey, bool)> {
    match (&view.wrapped_key, view.is_owner) {
        (WrappedKey::Owner(sealed), true) => {
            Ok((SecretKey::unwrap_owner(&session.self_wrap_key, sealed).map_err(user_facing)?, false))
        }
        (WrappedKey::Shared(boxed), false) => {
            Ok((SecretKey::unwrap_with(&session.identity, boxed).map_err(user_facing)?, false))
        }
        (WrappedKey::Shared(boxed), true) if session.legacy_owner_copies_allowed => {
            Ok((SecretKey::unwrap_with(&session.identity, boxed).map_err(user_facing)?, true))
        }
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
        key_for(session, &view).map(|_legacy| ())
    })
}

#[tauri::command]
async fn list_secrets(state: State<'_, AppState>) -> CommandResult<Vec<SecretSummary>> {
    let api = api(&state)?;
    let views = api.list_secrets().await?;
    let (summaries, legacy) = with_session(&state, |session| {
        // Drop keys for secrets that are gone; keep the rest so a server-side
        // key rotation by us is not undone by a stale cache entry elsewhere.
        session.keys.retain(|id, _| views.iter().any(|v| v.id == *id));
        let mut summaries = Vec::with_capacity(views.len());
        let mut legacy = Vec::new();
        for view in views {
            // One undecryptable item must not hide the whole vault, so the
            // failure is reported per item and the loop continues.
            let outcome = key_for(session, &view)
                .and_then(|is_legacy| decrypt_view(session, &view).map(|payload| (payload, is_legacy)));
            let (payload, error) = match outcome {
                Ok((payload, is_legacy)) => {
                    if is_legacy {
                        legacy.push((view.id, view.key_version));
                    }
                    (payload, None)
                }
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
                is_owner: view.is_owner,
                owner_email: view.owner_email,
                updated_at: view.updated_at,
                error,
            });
        }
        Ok((summaries, legacy))
    })?;
    upgrade_legacy_owner_copies(&state, &api, legacy).await;
    Ok(summaries)
}

/// Owner copies stored as sealed boxes predate self-wrapping. Replace each one
/// with a self-wrapped copy, and once none are left on this server refuse the
/// sealed-box form for owned secrets from then on, so the server cannot
/// reintroduce it. Failures are logged and retried on the next refresh.
async fn upgrade_legacy_owner_copies(state: &AppState, api: &ApiClient, legacy: Vec<(i64, i64)>) {
    let mut remaining = legacy.len();
    for (id, key_version) in legacy {
        let wrapped = with_session(state, |session| {
            Ok(WrappedKey::Owner(loaded_key(session, id)?.key.wrap_for_owner(&session.self_wrap_key)))
        });
        let wrapped_key = match wrapped {
            Ok(wrapped_key) => wrapped_key,
            Err(error) => {
                tracing::warn!(secret_id = id, %error, "cannot build the self-wrapped owner copy");
                continue;
            }
        };
        match api.upgrade_owner_key(id, &UpgradeOwnerKeyRequest { key_version, wrapped_key }).await {
            Ok(()) => remaining -= 1,
            Err(error) => {
                tracing::warn!(secret_id = id, %error, "could not upgrade the owner key copy; will retry on refresh")
            }
        }
    }
    if remaining > 0 {
        return;
    }
    let locked_down = with_session(state, |session| {
        session.legacy_owner_copies_allowed = false;
        Ok(())
    })
    .and_then(|()| {
        let mut known = state.known_keys.lock().map_err(|_| "key store lock poisoned".to_string())?;
        known.mark_owner_keys_upgraded(api.base_url());
        known.save(&state.known_keys_path).map_err(|e| format!("cannot save known keys: {e}").into())
    });
    if let Err(error) = locked_down {
        tracing::warn!(%error, "owner copies upgraded but the lock-down could not be recorded");
    }
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
    // write_secret marks the clip as sensitive (Android masks the preview, iOS
    // keeps it off Universal Clipboard, desktop managers skip their history).
    app.clipboard().write_secret(password.as_str()).map_err(|e| format!("clipboard write failed: {e}"))?;
    // Only a digest outlives this call: the clear task compares hashes, so the
    // plaintext is not kept alive for the whole timeout.
    let digest: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    drop(password);
    // A newer copy supersedes this one; its own task takes over the timer.
    let generation = state.clipboard_generation.fetch_add(1, Ordering::SeqCst) + 1;
    tokio::spawn(async move {
        tokio::time::sleep(CLIPBOARD_CLEAR_AFTER).await;
        let state = app.state::<AppState>();
        if state.clipboard_generation.load(Ordering::SeqCst) == generation {
            clear_clipboard_if_digest_matches(&app, &digest);
        }
    });
    Ok(CLIPBOARD_CLEAR_AFTER.as_secs())
}

/// Wipe the clipboard only if it still holds what we put there, so we never
/// destroy something the user copied since.
fn clear_clipboard_if_digest_matches(app: &AppHandle, expected: &[u8; 32]) {
    let clipboard = app.clipboard();
    let unchanged = match clipboard.read_text() {
        Ok(current) => Sha256::digest(current.as_bytes()).as_slice() == expected,
        Err(error) => {
            tracing::warn!(%error, "clipboard unavailable; cannot clear copied password");
            return;
        }
    };
    if unchanged {
        if let Err(error) = clipboard.clear() {
            tracing::warn!(%error, "failed to clear copied password from clipboard");
        }
    }
}

#[tauri::command]
async fn create_secret(
    state: State<'_, AppState>,
    name: String,
    username: String,
    password: Zeroizing<String>,
    url: String,
    notes: String,
) -> CommandResult<i64> {
    let name = secret::validate_name(&name).map_err(user_facing)?;
    let payload = SecretPayload { username, password: password.to_string(), url, notes };
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

/// `password: None` keeps the current password without it ever leaving Rust.
/// A 409 means another device rotated the key since we loaded it: the new key
/// is fetched and the write re-encrypted once, never retried under the old one.
#[tauri::command]
async fn update_secret(
    state: State<'_, AppState>,
    id: i64,
    name: String,
    username: String,
    password: Option<Zeroizing<String>>,
    url: String,
    notes: String,
) -> CommandResult<()> {
    let name = secret::validate_name(&name).map_err(user_facing)?;
    let password = match password.filter(|p| !p.is_empty()) {
        Some(password) => password,
        None => Zeroizing::new(load_payload(&state, id).await?.password.clone()),
    };
    let payload = SecretPayload { username, password: password.to_string(), url, notes };
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

/// Step one of inviting: fetch the invitee's key and report its fingerprint
/// and whether it matches what we pinned before. The UI shows this for the
/// user to confirm out of band before `invite` is called.
#[tauri::command]
async fn lookup_invitee(state: State<'_, AppState>, email: String) -> CommandResult<InviteeInfo> {
    let api = api(&state)?;
    let invitee = api.lookup_user(&email).await?;
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
    let invitee = api.lookup_user(&email).await?;
    check_confirmed_key(&invitee.public_key, &confirmed_public_key)?;
    for attempt in 0..2 {
        let request = with_session(&state, |session| {
            let loaded = loaded_key(session, id)?;
            Ok(InviteRequest {
                key_version: loaded.version,
                email: invitee.email.clone(),
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
            session_info,
            startup_warnings,
            ui_constants,
            list_secrets,
            reveal_password,
            copy_password,
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

    #[test]
    fn server_url_requires_https_except_on_loopback() {
        assert_eq!(normalize_server_url(" https://vault.example.com/ ").unwrap(), "https://vault.example.com");
        assert_eq!(
            normalize_server_url("https://vault.example.com:8443/base/").unwrap(),
            "https://vault.example.com:8443/base"
        );
        assert_eq!(normalize_server_url("http://127.0.0.1:8787").unwrap(), "http://127.0.0.1:8787");
        assert_eq!(normalize_server_url("http://LocalHost:8787").unwrap(), "http://localhost:8787");
        assert_eq!(normalize_server_url("HTTPS://Vault.Example.com").unwrap(), "https://vault.example.com");
        assert_eq!(normalize_server_url("http://[::1]:8787").unwrap(), "http://[::1]:8787");

        let remote = normalize_server_url("http://vault.example.com").unwrap_err();
        assert!(remote.message.contains("https://"), "{remote}");
        assert!(normalize_server_url("http://10.0.0.5:8787").is_err());
        assert!(normalize_server_url("http://localhost.example.com").is_err());
        assert!(normalize_server_url("vault.example.com").is_err());
        assert!(normalize_server_url("ftp://vault.example.com").is_err());
        assert!(normalize_server_url("").is_err());
        assert!(normalize_server_url("https://").is_err());
    }

    fn test_session(identity: Identity) -> Session {
        Session {
            api: ApiClient::new("http://localhost:1").unwrap(),
            user_id: 1,
            email: "me@example.com".into(),
            identity,
            self_wrap_key: Zeroizing::new(credvault_core::aead::random_bytes()),
            legacy_owner_copies_allowed: true,
            keys: HashMap::new(),
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
    fn owner_copies_must_be_self_wrapped_once_the_server_is_upgraded() {
        let mut session = test_session(Identity::generate());
        let key = SecretKey::generate();
        let mut view = view_for(&session, &key, 0, &payload());
        view.wrapped_key = WrappedKey::Shared(key.wrap_for(session.identity.public_key()).unwrap());

        // Still migrating: accepted and flagged as legacy.
        assert!(key_for(&mut session, &view).unwrap());
        session.keys.clear();

        // Locked down: the same copy is refused as something the server could have made.
        session.legacy_owner_copies_allowed = false;
        let error = key_for(&mut session, &view).unwrap_err();
        assert_eq!(error.code, "untrusted_key");
        assert!(!session.keys.contains_key(&7));

        // A genuine self-wrapped copy is fine and is not legacy.
        let genuine = view_for(&session, &key, 0, &payload());
        assert!(!key_for(&mut session, &genuine).unwrap());
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
        assert!(!key_for(&mut session, &shared).unwrap());
        assert_eq!(decrypt_view(&mut session, &shared).unwrap(), payload());
    }

    fn payload() -> SecretPayload {
        SecretPayload { username: "u".into(), password: "p".into(), url: String::new(), notes: String::new() }
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
