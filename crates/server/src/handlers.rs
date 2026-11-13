//! HTTP handlers. Authorization is enforced here in SQL by user id; the
//! server never decrypts anything.

use std::collections::{HashMap, HashSet};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use credvault_core::identity::normalize_fingerprint;
use credvault_core::kdf::{normalize_email, validate_auth_hash};
use credvault_core::{secret, PublicKey, Sealed, WrappedKey};
use sha2::{Digest, Sha256};
use sqlx::{SqliteExecutor, SqlitePool, Transaction};
use subtle::ConstantTimeEq;

use zeroize::Zeroizing;

use crate::auth::{self, AuthUser};
use crate::error::{ApiError, ApiResult};
use crate::extract::ApiJson;
use crate::ratelimit::RateLimiter;
use crate::{oauth, AppState, RegistrationPolicy};
use credvault_core::api::*;

type Tx = Transaction<'static, sqlx::Sqlite>;

// ----- validation helpers --------------------------------------------------

fn validate_email(email: &str) -> ApiResult<String> {
    let email = normalize_email(email);
    let has_bad_chars = email.chars().any(|c| c.is_whitespace() || c.is_control());
    let looks_like_email = !has_bad_chars
        && email.len() <= MAX_EMAIL_LEN
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        });
    if !looks_like_email {
        return Err(ApiError::BadRequest("invalid email address".into()));
    }
    Ok(email)
}

fn check_blob_size(label: &str, len: usize) -> ApiResult<()> {
    if len > MAX_BLOB_BYTES {
        return Err(ApiError::BadRequest(format!("{label} exceeds {MAX_BLOB_BYTES} bytes")));
    }
    Ok(())
}

/// Serialise a client-supplied blob for storage. The structural checks (nonce
/// length, key length) already happened when the request was deserialised.
fn encode_sealed(label: &str, sealed: &Sealed) -> ApiResult<String> {
    check_blob_size(label, sealed.ciphertext.len())?;
    Ok(serde_json::to_string(sealed)?)
}

fn encode_wrapped(label: &str, wrapped: &WrappedKey) -> ApiResult<String> {
    check_blob_size(label, wrapped.ciphertext_len())?;
    Ok(serde_json::to_string(wrapped)?)
}

/// The owner's own copy must be self-wrapped, so the server (or anyone else)
/// cannot hand the owner a key it knows; everyone else's copy must be a
/// sealed box, which is the only form they can open.
fn check_wrapped_kind(wrapped: &WrappedKey, is_owner: bool) -> ApiResult<()> {
    match (wrapped, is_owner) {
        (WrappedKey::Owner(_), true) | (WrappedKey::Shared(_), false) => Ok(()),
        (WrappedKey::Shared(_), true) => {
            Err(ApiError::BadRequest("the owner's copy of the key must be self-wrapped, not a sealed box".into()))
        }
        (WrappedKey::Owner(_), false) => {
            Err(ApiError::BadRequest("a member's copy of the key must be a sealed box".into()))
        }
    }
}

/// Decode a value the server itself stored; failure means corruption, not bad input.
fn decode_stored<T: serde::de::DeserializeOwned>(text: &str) -> ApiResult<T> {
    serde_json::from_str(text).map_err(ApiError::internal)
}

fn decode_stored_public_key(text: &str) -> ApiResult<PublicKey> {
    PublicKey::from_base64(text).map_err(ApiError::internal)
}

/// Both "no such secret" and "not yours" are 404 so that secret ids cannot be
/// probed by users who do not own them.
/// Resolve the project a write names, proving it is one the caller owns.
///
/// Refused as not found rather than forbidden, deliberately: whether a given
/// project id exists at all is a fact about somebody else's vault, and a
/// 403 here would answer it. `None` is "no project" and needs no lookup.
async fn require_own_project<'e>(
    executor: impl SqliteExecutor<'e>,
    project_id: Option<i64>,
    user_id: i64,
) -> ApiResult<Option<i64>> {
    let Some(id) = project_id else {
        return Ok(None);
    };
    let found: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM projects WHERE id = ? AND owner_id = ?")
        .bind(id)
        .bind(user_id)
        .fetch_optional(executor)
        .await?;
    found.map(|_| Some(id)).ok_or_else(|| ApiError::NotFound("project not found".into()))
}

async fn require_owner<'e>(executor: impl SqliteExecutor<'e>, secret_id: i64, user_id: i64) -> ApiResult<()> {
    let owned: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM secrets WHERE id = ? AND owner_id = ?")
        .bind(secret_id)
        .bind(user_id)
        .fetch_optional(executor)
        .await?;
    owned.map(|_| ()).ok_or_else(|| ApiError::NotFound("secret not found".into()))
}

/// Owner check plus key-version check in one query. A stale version means the
/// client encrypted with a key that another device has since rotated; letting
/// the write through would hand the revoked member the new contents.
async fn require_key_version<'e>(
    executor: impl SqliteExecutor<'e>,
    secret_id: i64,
    user_id: i64,
    expected: i64,
) -> ApiResult<()> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT key_version FROM secrets WHERE id = ? AND owner_id = ?")
        .bind(secret_id)
        .bind(user_id)
        .fetch_optional(executor)
        .await?;
    match row {
        None => Err(ApiError::NotFound("secret not found".into())),
        Some((version,)) if version == expected => Ok(()),
        Some(_) => Err(ApiError::Conflict(STALE_KEY_MESSAGE.into())),
    }
}

/// Spend one token from a per-account bucket, or say how long to wait.
///
/// Keyed by account rather than address: an address can be rotated at will and
/// an account cannot, so this is the only key that actually bounds what one
/// caller can make the server do.
fn spend_account_budget(limiter: &RateLimiter<i64>, user_id: i64, what: &str) -> ApiResult<()> {
    match limiter.try_acquire_keyed(user_id) {
        Ok(()) => Ok(()),
        Err(wait) => {
            tracing::warn!(user_id, operation = what, "rate limited");
            Err(ApiError::TooManyRequests { retry_after_secs: wait.as_secs().max(1) })
        }
    }
}

/// Refuse a write that would take an account past a quota.
///
/// Counted inside the caller's write transaction, never before it: two
/// simultaneous creates that each read the count separately would both see
/// room and both insert.
async fn check_quota(tx: &mut Tx, label: &str, sql: &str, user_id: i64, limit: i64) -> ApiResult<()> {
    let (used,): (i64,) = sqlx::query_as(sql).bind(user_id).fetch_one(&mut **tx).await?;
    if used >= limit {
        return Err(ApiError::Forbidden(format!("you already have {used} {label}, which is the limit of {limit}")));
    }
    Ok(())
}

const STALE_KEY_MESSAGE: &str = "the secret's key was rotated since you loaded it; refresh and try again";
const MEMBERSHIP_CHANGED_MESSAGE: &str = "the secret's membership changed since you loaded it; refresh and try again";

/// SQLite's default deferred transaction can fail with SQLITE_BUSY when a
/// read-then-write transaction tries to upgrade its lock. Taking the write
/// lock up front makes it wait for `busy_timeout` instead.
async fn begin_write(pool: &SqlitePool) -> ApiResult<Tx> {
    Ok(pool.begin_with("BEGIN IMMEDIATE").await?)
}

async fn issue_session(pool: &SqlitePool, user_id: i64) -> ApiResult<String> {
    let (token, digest) = auth::new_session_token();
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(digest)
        .bind(user_id)
        .bind(auth::session_expiry())
        .execute(pool)
        .await?;
    // Piggyback housekeeping on logins so expired rows never accumulate.
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?").bind(auth::now_timestamp()).execute(pool).await?;
    Ok(token)
}

async fn load_profile(pool: &SqlitePool, user_id: i64) -> ApiResult<UserProfile> {
    // The join is a left join against an index that is unique on
    // (provider, user_id), so it adds at most one row and the Google address
    // is null when nothing is linked.
    let (id, email, public_key, encrypted_private_key, password_login, google_email): (
        i64,
        String,
        String,
        String,
        bool,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT u.id, u.email, u.public_key, u.encrypted_private_key, u.password_login, g.email \
         FROM users u \
         LEFT JOIN oauth_identities g ON g.user_id = u.id AND g.provider = ? \
         WHERE u.id = ?",
    )
    .bind(oauth::PROVIDER_GOOGLE)
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(UserProfile {
        id,
        email,
        public_key: decode_stored_public_key(&public_key)?,
        encrypted_private_key: decode_stored(&encrypted_private_key)?,
        password_login,
        google_email,
    })
}

fn check_registration_policy(policy: &RegistrationPolicy, presented: Option<&str>) -> ApiResult<()> {
    match policy {
        RegistrationPolicy::Open => Ok(()),
        RegistrationPolicy::Closed => Err(ApiError::Forbidden("registration is closed on this server".into())),
        RegistrationPolicy::Token(expected) => {
            let presented = presented.ok_or_else(|| ApiError::Forbidden("a registration token is required".into()))?;
            if presented.len() > MAX_REGISTRATION_TOKEN_LEN {
                return Err(ApiError::BadRequest("registration token is too long".into()));
            }
            // Hashing both sides gives a constant-time comparison that does not
            // leak the expected token's length.
            let matches: bool = Sha256::digest(presented.as_bytes()).ct_eq(&Sha256::digest(expected.as_bytes())).into();
            if matches {
                Ok(())
            } else {
                Err(ApiError::Forbidden("invalid registration token".into()))
            }
        }
    }
}

// ----- accounts -------------------------------------------------------------

pub async fn register(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<RegisterRequest>,
) -> ApiResult<(StatusCode, Json<SessionResponse>)> {
    // Everything cheap is validated before the Argon2 hash and the insert, so
    // a bad request never leaves a half-usable account behind.
    let email = validate_email(&body.email)?;
    validate_auth_hash(&body.auth_hash)?;
    check_registration_policy(&state.config.registration, body.registration_token.as_deref())?;
    let private_key = encode_sealed("encrypted_private_key", &body.encrypted_private_key)?;
    let public_key = body.public_key.to_base64();
    let credential = auth::hash_credential(body.auth_hash).await?;

    let inserted = sqlx::query(
        "INSERT INTO users (email, auth_hash, public_key, encrypted_private_key, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&email)
    .bind(credential)
    .bind(public_key)
    .bind(private_key)
    .bind(Utc::now())
    .execute(&state.pool)
    .await;

    let user_id = match inserted {
        Ok(result) => result.last_insert_rowid(),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(ApiError::Conflict("an account with that email already exists".into()))
        }
        Err(other) => return Err(other.into()),
    };

    let token = issue_session(&state.pool, user_id).await?;
    let user = load_profile(&state.pool, user_id).await?;
    Ok((StatusCode::CREATED, Json(SessionResponse { token, user })))
}

pub async fn login(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<LoginRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let email = validate_email(&body.email)?;
    validate_auth_hash(&body.auth_hash)?;
    let row: Option<(i64, String)> = sqlx::query_as("SELECT id, auth_hash FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(&state.pool)
        .await?;

    let user_id = auth::verify_login(row, body.auth_hash).await?.ok_or(ApiError::Unauthorized)?;

    let token = issue_session(&state.pool, user_id).await?;
    let user = load_profile(&state.pool, user_id).await?;
    Ok(Json(SessionResponse { token, user }))
}

pub async fn logout(State(state): State<AppState>, user: AuthUser) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = ? AND user_id = ?")
        .bind(&user.token_hash)
        .bind(user.id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Invalidate every session for the caller except this one, which is replaced.
///
/// The caller keeps a way in on purpose. This is the first move against
/// someone holding a session they should not have, and the second move is
/// usually to take away whatever let them in — removing a Google link,
/// changing the passphrase. Ending the caller's session too would send them
/// back through a sign-in to do it, which on a slow derivation is seconds the
/// evicted party can use to come back and start spending the per-account
/// budgets again. Handing back a token makes the next request immediate, and
/// an attacker needs a whole OAuth round trip to interfere with it.
///
/// Rationed per address and deliberately never per account. Every per-account
/// limit can be emptied by whoever is already signed in as that account, so a
/// bucket keyed that way would let the party being evicted block their own
/// eviction. An address bucket throttles a flooder at their own address and
/// leaves the owner's alone, and the owner needs one request against a burst
/// of ten.
///
/// A limiter of some kind is needed because handing back a token makes this
/// route self-renewing: it costs the caller nothing, and each call takes the
/// single write lock three times — the purge, the insert, and the expiry
/// housekeeping inside [`issue_session`]. Before the replacement, the first
/// request killed the caller's token and every further one had to go through
/// `/login`, which was throttle enough on its own.
///
/// Both of the other handlers that end every session, [`change_password`] and
/// [`oauth_unlink`], replace the caller's for the same reason.
pub async fn logout_other_devices(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<SessionResponse>> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user.id).execute(&state.pool).await?;
    let token = issue_session(&state.pool, user.id).await?;
    let profile = load_profile(&state.pool, user.id).await?;
    Ok(Json(SessionResponse { token, user: profile }))
}

pub async fn me(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<UserProfile>> {
    Ok(Json(load_profile(&state.pool, user.id).await?))
}

/// Stand-in used when no account exists. A real public key, so the absent
/// case runs the same decode and the same SHA-256 as a present one rather
/// than comparing against a constant: the two branches should differ in
/// their answer, not in how much work they do. The same trick as the dummy
/// hash on the login path.
const ABSENT_PUBLIC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Its fingerprint, derived on every call. Deliberately not memoised: the
/// point is to spend the decode and the hash that the present branch spends,
/// and a cached value would skip exactly the work being matched.
///
/// Infallible by construction, and it must stay that way: propagating an
/// error here would make a mistyped constant answer 500 on the no-account
/// branch while the wrong-fingerprint branch still answered 404, which is
/// the oracle this whole helper exists to avoid.
fn absent_fingerprint() -> String {
    PublicKey::from_base64(ABSENT_PUBLIC_KEY)
        .map(|key| key.fingerprint())
        .unwrap_or_else(|_| "0".repeat(credvault_core::identity::FINGERPRINT_HEX_LEN))
}

/// One answer for every way a lookup can fail. It must never say which, or it
/// would be the oracle this endpoint exists to avoid being.
const LOOKUP_FAILED_MESSAGE: &str =
    "no account matches that email and fingerprint; check the fingerprint with them directly";

/// Resolve an email to the public key to share with, but only for a caller who
/// already knows that key's fingerprint. Someone who has confirmed a
/// fingerprint out of band learns nothing new; someone guessing at addresses
/// learns nothing at all, because a wrong fingerprint, a wrong address and an
/// address with no account are the same 404.
///
/// The budget on top is per account rather than per address, which a caller
/// can change at will, and bounds guessing at fingerprints as well.
pub async fn lookup_user(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<LookupQuery>,
) -> ApiResult<Json<PublicUser>> {
    let found = resolve_by_fingerprint(&state, &state.pool, user.id, &query.email, &query.fingerprint).await?;
    Ok(Json(PublicUser { id: found.id, email: found.email, public_key: found.public_key }))
}

/// An account the caller proved they already knew the fingerprint of.
struct ResolvedUser {
    id: i64,
    email: String,
    public_key: PublicKey,
}

/// Resolve an email to an account, but only for a caller who already knows
/// that account's fingerprint. Every way this can fail gives one answer, so
/// no endpoint built on it can be asked whether an address has an account.
///
/// Both endpoints that take an email go through here, because an oracle is
/// only closed if it is closed everywhere: an invite that answered "no such
/// account" would hand back exactly what the lookup refuses to say. For the
/// same reason the caller's budget is spent here rather than at the call
/// sites, so an endpoint added later cannot be built on this unthrottled.
async fn resolve_by_fingerprint<'e>(
    state: &AppState,
    executor: impl SqliteExecutor<'e>,
    caller: i64,
    email: &str,
    fingerprint: &str,
) -> ApiResult<ResolvedUser> {
    if let Err(wait) = state.lookup_limiter.try_acquire_keyed(caller) {
        tracing::warn!(user_id = caller, "directory lookup rate limited");
        return Err(ApiError::TooManyRequests { retry_after_secs: wait.as_secs().max(1) });
    }
    if fingerprint.len() > MAX_FINGERPRINT_INPUT_LEN {
        return Err(ApiError::BadRequest("fingerprint is too long".into()));
    }
    let email = validate_email(email)?;
    let row: Option<(i64, String, String)> = sqlx::query_as("SELECT id, email, public_key FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(executor)
        .await?;

    // The comparison runs exactly once either way, against the real
    // fingerprint or the stand-in, so the two cases are indistinguishable.
    let found = match row {
        Some((id, email, stored)) => Some(ResolvedUser { id, email, public_key: decode_stored_public_key(&stored)? }),
        None => None,
    };
    // Both branches decode a key and fingerprint it before the single
    // comparison, so the crypto is symmetric. The database work is not — a
    // hit returns a row and allocates, a miss does not — so what actually
    // bounds what an attacker can measure is the per-account budget above,
    // along with the identical status and body on every failure.
    let expected = match &found {
        Some(found) => found.public_key.fingerprint(),
        None => absent_fingerprint(),
    };
    let matched = fingerprint_matches(&expected, fingerprint);
    match found {
        Some(found) if matched => Ok(found),
        _ => Err(ApiError::NotFound(LOOKUP_FAILED_MESSAGE.into())),
    }
}

/// Compare two fingerprints in constant time, ignoring how they were typed.
/// Hashing both sides equalises the length as well as the content, so a near
/// miss cannot be told from a wild one by how long the answer took.
fn fingerprint_matches(expected: &str, supplied: &str) -> bool {
    let expected = Sha256::digest(normalize_fingerprint(expected).as_bytes());
    let supplied = Sha256::digest(normalize_fingerprint(supplied).as_bytes());
    expected.ct_eq(&supplied).into()
}

/// Replace everything derived from the account passphrase, in one transaction.
///
/// The three pieces have to move together or the vault becomes unopenable: a
/// new credential without re-wrapped keys locks the owner out of their own
/// secrets, and re-wrapped keys without a new credential do the same from the
/// other side. Neither is recoverable, because the server holds no plaintext.
///
/// # Errors
/// [`ApiError::Unauthorized`] if the current passphrase is wrong;
/// [`ApiError::BadRequest`] if the submission is malformed or does not match
/// the account's login type; [`ApiError::Conflict`] if the account or any of
/// its secrets changed while the client was re-wrapping.
pub async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    ApiJson(body): ApiJson<ChangePasswordRequest>,
) -> ApiResult<Json<SessionResponse>> {
    // Before anything expensive: this verifies one Argon2 hash and computes
    // another, so an unbounded caller is a way to starve the process.
    //
    // Spent on every outcome, including the conflicts. Refunding those was
    // tried and is not safe: a conflict is raised *after* both Argon2 passes,
    // and three of the ways to provoke one are decided entirely by the request
    // body — an empty `rewrapped_keys` is enough — so a caller who knows their
    // own passphrase could mint unlimited work for free.
    spend_account_budget(&state.password_limiter, user.id, "password change")?;
    let private_key = encode_sealed("encrypted_private_key", &body.encrypted_private_key)?;
    let mut rewrapped: HashMap<i64, (i64, String)> = HashMap::with_capacity(body.rewrapped_keys.len());
    for entry in &body.rewrapped_keys {
        // Only the owner can produce an owner copy, which is what stops the
        // server handing itself a key it knows.
        check_wrapped_kind(&entry.wrapped_key, true)?;
        let encoded = encode_wrapped("wrapped_key", &entry.wrapped_key)?;
        if rewrapped.insert(entry.secret_id, (entry.key_version, encoded)).is_some() {
            return Err(ApiError::BadRequest(format!("secret {} is listed twice", entry.secret_id)));
        }
    }

    let (stored_credential, password_login): (String, bool) =
        sqlx::query_as("SELECT auth_hash, password_login FROM users WHERE id = ?")
            .bind(user.id)
            .fetch_one(&state.pool)
            .await?;

    // Argon2 twice over, so both run before the write lock is taken rather
    // than holding SQLite's single writer for the best part of a second.
    let new_credential = verify_and_rehash(&body, &stored_credential, password_login).await?;

    let mut tx = begin_write(&state.pool).await?;
    // Compare-and-swap on the stored credential. Two passphrase changes racing
    // would otherwise both pass the check above and the loser's re-wrapped
    // keys would be written under a key nobody holds.
    let changed =
        sqlx::query("UPDATE users SET auth_hash = ?, encrypted_private_key = ? WHERE id = ? AND auth_hash = ?")
            .bind(&new_credential)
            .bind(private_key)
            .bind(user.id)
            .bind(&stored_credential)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if changed == 0 {
        return Err(ApiError::Conflict("this account changed while you were typing; try again".into()));
    }

    let owned: Vec<(i64, i64)> = sqlx::query_as("SELECT id, key_version FROM secrets WHERE owner_id = ?")
        .bind(user.id)
        .fetch_all(&mut *tx)
        .await?;
    if owned.len() != rewrapped.len() {
        return Err(ApiError::Conflict(REWRAP_MISMATCH_MESSAGE.into()));
    }
    for (secret_id, key_version) in &owned {
        // A rotation landing mid-change would leave the new owner copy holding
        // a key that no longer opens the payload.
        let Some((against, wrapped_key)) = rewrapped.get(secret_id) else {
            return Err(ApiError::Conflict(REWRAP_MISMATCH_MESSAGE.into()));
        };
        if against != key_version {
            return Err(ApiError::Conflict(STALE_KEY_MESSAGE.into()));
        }
        let updated = sqlx::query("UPDATE secret_keys SET wrapped_key = ? WHERE secret_id = ? AND user_id = ?")
            .bind(wrapped_key)
            .bind(secret_id)
            .bind(user.id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if updated != 1 {
            return Err(ApiError::Conflict(REWRAP_MISMATCH_MESSAGE.into()));
        }
    }

    // Every other device is signed out: ending sessions is most of the point
    // of changing a passphrase you think someone else has.
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user.id).execute(&mut *tx).await?;
    tx.commit().await?;

    let token = issue_session(&state.pool, user.id).await?;
    let profile = load_profile(&state.pool, user.id).await?;
    Ok(Json(SessionResponse { token, user: profile }))
}

const REWRAP_MISMATCH_MESSAGE: &str = "the secrets you own changed while you were typing; refresh and try again";

/// Check the current passphrase and produce the credential to store.
///
/// A Google account has no password login, and must not gain one here: its
/// stored credential is a hash of random bytes and stays exactly as it was.
async fn verify_and_rehash(
    body: &ChangePasswordRequest,
    stored_credential: &str,
    password_login: bool,
) -> ApiResult<String> {
    if !password_login {
        if body.current_auth_hash.is_some() || body.new_auth_hash.is_some() {
            return Err(ApiError::BadRequest(
                "this account signs in with Google, so it has no password to change".into(),
            ));
        }
        return Ok(stored_credential.to_string());
    }

    let current = body
        .current_auth_hash
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("the current password is required".into()))?;
    let new = body.new_auth_hash.as_ref().ok_or_else(|| ApiError::BadRequest("a new password is required".into()))?;
    validate_auth_hash(current)?;
    validate_auth_hash(new)?;

    let stored = stored_credential.to_string();
    let presented = current.clone();
    let verified = tokio::task::spawn_blocking(move || auth::verify_credential(&presented, &stored))
        .await
        .map_err(ApiError::internal)?;
    if !verified {
        return Err(ApiError::Unauthorized);
    }
    auth::hash_credential(new.clone()).await
}

// ----- secrets --------------------------------------------------------------

// ----- projects ------------------------------------------------------------

/// The caller's own projects, each with how many of their secrets it holds.
///
/// The owner predicate on the join is redundant today -- every path that
/// sets a `project_id` proves the project belongs to the caller first -- and
/// is there because this count is a number shown to a person. One stray row
/// from a later route, or from a hand-edited database, would otherwise be a
/// small cross-account leak with no other symptom.
///
/// One statement with a `LEFT JOIN`, not a count per project: the list is
/// drawn on every refresh and a query per row would be a query per heading.
/// `LEFT` so a project nobody has filed anything under still appears, with
/// zero -- it is the only place an empty project is visible, because it
/// draws no heading over the vault.
pub async fn list_projects(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<ProjectView>>> {
    let rows: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT p.id, p.name, COUNT(s.id) FROM projects p \
         LEFT JOIN secrets s ON s.project_id = p.id AND s.owner_id = p.owner_id \
         WHERE p.owner_id = ? GROUP BY p.id, p.name ORDER BY p.name COLLATE NOCASE",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows.into_iter().map(|(id, name, secret_count)| ProjectView { id, name, secret_count }).collect()))
}

pub async fn create_project(
    State(state): State<AppState>,
    user: AuthUser,
    ApiJson(body): ApiJson<ProjectRequest>,
) -> ApiResult<(StatusCode, Json<Created>)> {
    let name = secret::validate_project_name(&body.name)?;
    let mut tx = begin_write(&state.pool).await?;
    check_quota(
        &mut tx,
        "projects",
        "SELECT COUNT(*) FROM projects WHERE owner_id = ?",
        user.id,
        MAX_PROJECTS_PER_ACCOUNT,
    )
    .await?;
    let inserted = sqlx::query("INSERT INTO projects (owner_id, name, created_at) VALUES (?, ?, ?)")
        .bind(user.id)
        .bind(name)
        .bind(Utc::now())
        .execute(&mut *tx)
        .await;
    // The unique index decides this, not a SELECT first: two devices creating
    // the same project at once would both pass a check and both insert.
    let project_id = match inserted {
        Ok(result) => result.last_insert_rowid(),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(ApiError::Conflict("you already have a project with that name".into()))
        }
        Err(other) => return Err(other.into()),
    };
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(Created { id: project_id })))
}

pub async fn rename_project(
    State(state): State<AppState>,
    user: AuthUser,
    Path(project_id): Path<i64>,
    ApiJson(body): ApiJson<ProjectRequest>,
) -> ApiResult<StatusCode> {
    let name = secret::validate_project_name(&body.name)?;
    // Scoped by owner in the statement, so another account's project is a
    // 404 and never a write.
    let renamed = sqlx::query("UPDATE projects SET name = ? WHERE id = ? AND owner_id = ?")
        .bind(name)
        .bind(project_id)
        .bind(user.id)
        .execute(&state.pool)
        .await;
    let affected = match renamed {
        Ok(result) => result.rows_affected(),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(ApiError::Conflict("you already have a project with that name".into()))
        }
        Err(other) => return Err(other.into()),
    };
    if affected == 0 {
        return Err(ApiError::NotFound("project not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Delete a project. The secrets filed under it are not touched: the column
/// is `ON DELETE SET NULL`, so they become unfiled and nothing else changes.
/// Losing a heading must never mean losing a credential.
pub async fn delete_project(
    State(state): State<AppState>,
    user: AuthUser,
    Path(project_id): Path<i64>,
) -> ApiResult<StatusCode> {
    let affected = sqlx::query("DELETE FROM projects WHERE id = ? AND owner_id = ?")
        .bind(project_id)
        .bind(user.id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(ApiError::NotFound("project not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Change whether one member may see where a secret is filed.
///
/// The answer given when the invite was sent is not final: a choice about
/// what someone else can see that could not be taken back would not be much
/// of a choice. Scoped to people who actually hold a key for the secret, so
/// this cannot be used to probe which accounts exist.
pub async fn set_member_project(
    State(state): State<AppState>,
    user: AuthUser,
    Path((secret_id, member_id)): Path<(i64, i64)>,
    ApiJson(body): ApiJson<ShareProjectRequest>,
) -> ApiResult<StatusCode> {
    let mut tx = begin_write(&state.pool).await?;
    require_owner(&mut *tx, secret_id, user.id).await?;
    // `user_id != ?` excludes the owner's own membership row, which is not a
    // member in the sense the sharing panel means and whose flag would do
    // nothing: owning the secret is already how the owner sees its project.
    let affected =
        sqlx::query("UPDATE secret_keys SET share_project = ? WHERE secret_id = ? AND user_id = ? AND user_id != ?")
            .bind(body.share_project)
            .bind(secret_id)
            .bind(member_id)
            .bind(user.id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if affected == 0 {
        return Err(ApiError::NotFound("that person is not a member of this secret".into()));
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

type SecretRow = (i64, String, String, i64, String, String, DateTime<Utc>, i64, Option<i64>, Option<String>);

/// The id is handed out only to the owner, and the name only to someone who
/// may see it: the `CASE` decides the first and the join condition decides
/// the second, so a member's row carries neither unless the owner said so.
/// Doing it here rather than in Rust means there is no branch to forget on a
/// route that reuses this projection.
const SECRET_VIEW_SQL: &str =
    "SELECT s.id, s.name, s.payload, s.owner_id, owner.email, k.wrapped_key, s.updated_at, s.key_version, \
            CASE WHEN s.owner_id = k.user_id THEN s.project_id END, p.name \
     FROM secret_keys k \
     JOIN secrets s ON s.id = k.secret_id \
     JOIN users owner ON owner.id = s.owner_id \
     LEFT JOIN projects p ON p.id = s.project_id AND (s.owner_id = k.user_id OR k.share_project = 1) \
     WHERE k.user_id = ?";

fn secret_view(row: SecretRow, viewer_id: i64) -> ApiResult<SecretView> {
    let (id, name, payload, owner_id, owner_email, wrapped_key, updated_at, key_version, project_id, project_name) =
        row;
    // An id without a name cannot happen -- the owner's join is
    // unconditional and the foreign key keeps the row alive -- and if it ever
    // did, saying nothing is the safe half of the pair.
    let project = match (project_id, project_name) {
        (Some(id), Some(name)) => Some(SecretProject::Own { id, name }),
        (None, Some(name)) => Some(SecretProject::Shared { name }),
        _ => None,
    };
    Ok(SecretView {
        id,
        name,
        owner_email,
        is_owner: owner_id == viewer_id,
        payload: decode_stored(&payload)?,
        wrapped_key: decode_stored(&wrapped_key)?,
        updated_at,
        key_version,
        project,
    })
}

/// Every secret key this caller holds, without the payloads.
///
/// What a passphrase change needs: it re-wraps keys and never looks at a
/// payload, so fetching them would be tens of megabytes read and discarded.
pub async fn list_secret_keys(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<SecretKeyView>>> {
    let rows: Vec<(i64, String, i64, i64, String)> = sqlx::query_as(
        "SELECT s.id, s.name, s.key_version, s.owner_id, k.wrapped_key \
         FROM secret_keys k JOIN secrets s ON s.id = k.secret_id \
         WHERE k.user_id = ? ORDER BY s.id",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    rows.into_iter()
        .map(|(id, name, key_version, owner_id, wrapped_key)| {
            Ok(SecretKeyView {
                id,
                name,
                key_version,
                is_owner: owner_id == user.id,
                wrapped_key: decode_stored(&wrapped_key)?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

pub async fn list_secrets(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<SecretView>>> {
    let rows: Vec<SecretRow> = sqlx::query_as(&format!("{SECRET_VIEW_SQL} ORDER BY s.name COLLATE NOCASE"))
        .bind(user.id)
        .fetch_all(&state.pool)
        .await?;
    rows.into_iter().map(|row| secret_view(row, user.id)).collect::<ApiResult<Vec<_>>>().map(Json)
}

/// One secret the caller may read (as owner or member).
pub async fn get_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(secret_id): Path<i64>,
) -> ApiResult<Json<SecretView>> {
    let row: Option<SecretRow> = sqlx::query_as(&format!("{SECRET_VIEW_SQL} AND s.id = ?"))
        .bind(user.id)
        .bind(secret_id)
        .fetch_optional(&state.pool)
        .await?;
    let row = row.ok_or_else(|| ApiError::NotFound("secret not found".into()))?;
    Ok(Json(secret_view(row, user.id)?))
}

pub async fn create_secret(
    State(state): State<AppState>,
    user: AuthUser,
    ApiJson(body): ApiJson<CreateSecretRequest>,
) -> ApiResult<(StatusCode, Json<Created>)> {
    let name = secret::validate_name(&body.name)?;
    let payload = encode_sealed("payload", &body.payload)?;
    check_wrapped_kind(&body.wrapped_key, true)?;
    let wrapped_key = encode_wrapped("wrapped_key", &body.wrapped_key)?;
    let now = Utc::now();

    let mut tx = begin_write(&state.pool).await?;
    check_quota(
        &mut tx,
        "secrets",
        "SELECT COUNT(*) FROM secrets WHERE owner_id = ?",
        user.id,
        MAX_SECRETS_PER_ACCOUNT,
    )
    .await?;
    // Inside the transaction, so a project deleted between the check and the
    // insert cannot leave a secret pointing at a row that is gone.
    let project_id = require_own_project(&mut *tx, body.project_id, user.id).await?;
    let secret_id = sqlx::query(
        "INSERT INTO secrets (owner_id, name, payload, project_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(user.id)
    .bind(name)
    .bind(payload)
    .bind(project_id)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();
    sqlx::query("INSERT INTO secret_keys (secret_id, user_id, wrapped_key, created_at) VALUES (?, ?, ?, ?)")
        .bind(secret_id)
        .bind(user.id)
        .bind(wrapped_key)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok((StatusCode::CREATED, Json(Created { id: secret_id })))
}

pub async fn update_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(secret_id): Path<i64>,
    ApiJson(body): ApiJson<UpdateSecretRequest>,
) -> ApiResult<StatusCode> {
    let name = secret::validate_name(&body.name)?;
    let payload = encode_sealed("payload", &body.payload)?;
    // What the assignment adds to the SET clause. Three literals chosen by a
    // match, never anything the caller wrote: the id travels as a bind like
    // every other value.
    let (set_project, set_to) = match body.project {
        ProjectAssignment::Keep => ("", None),
        ProjectAssignment::Clear => (", project_id = NULL", None),
        ProjectAssignment::Set(id) => (", project_id = ?", Some(id)),
    };

    // One transaction rather than one statement, now that a project has to be
    // proved to belong to the caller first. Ownership and key version are
    // still decided by the write itself, so there is no window in which the
    // secret can change hands, disappear or be rotated between check and
    // write; `BEGIN IMMEDIATE` holds the writer lock across both.
    let mut tx = begin_write(&state.pool).await?;
    require_own_project(&mut *tx, set_to, user.id).await?;
    let sql = format!(
        "UPDATE secrets SET name = ?, payload = ?, updated_at = ?{set_project} \
         WHERE id = ? AND owner_id = ? AND key_version = ?"
    );
    let mut update = sqlx::query(&sql).bind(name).bind(payload).bind(Utc::now());
    if let Some(id) = set_to {
        update = update.bind(id);
    }
    let affected = update.bind(secret_id).bind(user.id).bind(body.key_version).execute(&mut *tx).await?.rows_affected();
    if affected == 0 {
        // Tell a stale client apart from a wrong one.
        require_key_version(&mut *tx, secret_id, user.id, body.key_version).await?;
        return Err(ApiError::NotFound("secret not found".into()));
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Move one secret into a project, or out of whatever it is in.
///
/// Its own route because refiling reads and writes no ciphertext: there is no
/// payload to re-encrypt, so there is no `key_version` to carry and no
/// conflict for a stale one to cause. `updated_at` is deliberately left
/// alone -- it says when the credential last changed, and moving it between
/// two headings did not change it.
pub async fn move_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(secret_id): Path<i64>,
    ApiJson(body): ApiJson<MoveSecretRequest>,
) -> ApiResult<StatusCode> {
    let mut tx = begin_write(&state.pool).await?;
    let project_id = require_own_project(&mut *tx, body.project_id, user.id).await?;
    let affected = sqlx::query("UPDATE secrets SET project_id = ? WHERE id = ? AND owner_id = ?")
        .bind(project_id)
        .bind(secret_id)
        .bind(user.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(ApiError::NotFound("secret not found".into()));
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Owners delete the secret for everyone; shared users just drop their access.
pub async fn delete_secret(
    State(state): State<AppState>,
    user: AuthUser,
    Path(secret_id): Path<i64>,
) -> ApiResult<StatusCode> {
    let as_owner = sqlx::query("DELETE FROM secrets WHERE id = ? AND owner_id = ?")
        .bind(secret_id)
        .bind(user.id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if as_owner > 0 {
        return Ok(StatusCode::NO_CONTENT);
    }
    let as_member = sqlx::query("DELETE FROM secret_keys WHERE secret_id = ? AND user_id = ?")
        .bind(secret_id)
        .bind(user.id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if as_member == 0 {
        return Err(ApiError::NotFound("secret not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ----- sharing --------------------------------------------------------------

pub async fn secret_access(
    State(state): State<AppState>,
    user: AuthUser,
    Path(secret_id): Path<i64>,
) -> ApiResult<Json<AccessView>> {
    require_owner(&state.pool, secret_id, user.id).await?;
    let members: Vec<(i64, String, String, bool)> = sqlx::query_as(
        "SELECT u.id, u.email, u.public_key, k.share_project FROM secret_keys k JOIN users u ON u.id = k.user_id \
         WHERE k.secret_id = ? AND k.user_id != ? ORDER BY u.email",
    )
    .bind(secret_id)
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    let invites: Vec<(i64, String)> = sqlx::query_as(
        "SELECT i.id, u.email FROM invites i JOIN users u ON u.id = i.invitee_id \
         WHERE i.secret_id = ? ORDER BY u.email",
    )
    .bind(secret_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(AccessView {
        members: members
            .into_iter()
            .map(|(user_id, email, public_key, sees_project)| {
                Ok(Member { user_id, email, public_key: decode_stored_public_key(&public_key)?, sees_project })
            })
            .collect::<ApiResult<Vec<_>>>()?,
        invites: invites.into_iter().map(|(id, email)| PendingInvite { id, email }).collect(),
    }))
}

/// Remove one member and rotate the secret's key in one transaction. The
/// client supplies the payload re-encrypted under a fresh key plus that key
/// wrapped for every remaining member; the server checks the set matches
/// exactly so nobody is silently left on the old key or added.
pub async fn revoke_access(
    State(state): State<AppState>,
    user: AuthUser,
    Path((secret_id, member_id)): Path<(i64, i64)>,
    ApiJson(body): ApiJson<RevokeAccessRequest>,
) -> ApiResult<Json<RevokeAccessResponse>> {
    if member_id == user.id {
        return Err(ApiError::BadRequest("owners cannot revoke their own access; delete the secret instead".into()));
    }
    let payload = encode_sealed("payload", &body.payload)?;
    let mut new_keys: HashMap<i64, String> = HashMap::with_capacity(body.wrapped_keys.len());
    for entry in &body.wrapped_keys {
        check_wrapped_kind(&entry.wrapped_key, entry.user_id == user.id)?;
        let encoded = encode_wrapped("wrapped_key", &entry.wrapped_key)?;
        if new_keys.insert(entry.user_id, encoded).is_some() {
            return Err(ApiError::BadRequest(format!("wrapped_keys lists user {} twice", entry.user_id)));
        }
    }

    let mut tx = begin_write(&state.pool).await?;
    require_key_version(&mut *tx, secret_id, user.id, body.key_version).await?;
    let removed = sqlx::query("DELETE FROM secret_keys WHERE secret_id = ? AND user_id = ?")
        .bind(secret_id)
        .bind(member_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(ApiError::NotFound("that user does not have access".into()));
    }

    let remaining: Vec<(i64,)> = sqlx::query_as("SELECT user_id FROM secret_keys WHERE secret_id = ?")
        .bind(secret_id)
        .fetch_all(&mut *tx)
        .await?;
    let remaining: HashSet<i64> = remaining.into_iter().map(|(id,)| id).collect();
    let provided: HashSet<i64> = new_keys.keys().copied().collect();
    if remaining != provided {
        // Someone accepted or left between the client's fetch and this request.
        return Err(ApiError::Conflict(MEMBERSHIP_CHANGED_MESSAGE.into()));
    }

    let now = Utc::now();
    let key_version = body.key_version + 1;
    sqlx::query("UPDATE secrets SET payload = ?, updated_at = ?, key_version = ? WHERE id = ?")
        .bind(payload)
        .bind(now)
        .bind(key_version)
        .bind(secret_id)
        .execute(&mut *tx)
        .await?;
    // One statement per remaining member: the set is the handful of people a
    // single secret is shared with, and each row gets a different value.
    for (member, wrapped_key) in &new_keys {
        sqlx::query("UPDATE secret_keys SET wrapped_key = ? WHERE secret_id = ? AND user_id = ?")
            .bind(wrapped_key)
            .bind(secret_id)
            .bind(member)
            .execute(&mut *tx)
            .await?;
    }
    // Pending invites carry the old key; they must be re-issued.
    let cancelled_invites =
        sqlx::query("DELETE FROM invites WHERE secret_id = ?").bind(secret_id).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;

    Ok(Json(RevokeAccessResponse { cancelled_invites, key_version }))
}

pub async fn create_invite(
    State(state): State<AppState>,
    user: AuthUser,
    Path(secret_id): Path<i64>,
    ApiJson(body): ApiJson<InviteRequest>,
) -> ApiResult<(StatusCode, Json<Created>)> {
    // Everything that needs no database is checked before the write lock is taken.
    let email = validate_email(&body.email)?;
    if body.message.len() > MAX_MESSAGE_LEN {
        return Err(ApiError::BadRequest(format!("message exceeds {MAX_MESSAGE_LEN} bytes")));
    }
    // Stored in the same form `secret_keys` uses, because accepting an invite
    // copies this value straight across. An invite can only ever carry a
    // sealed box, which is what makes it a `Shared` copy.
    let wrapped_key = encode_wrapped("wrapped_key", &WrappedKey::Shared(body.wrapped_key))?;

    // Same proof the lookup demands: knowing the fingerprint. Otherwise this
    // endpoint answers the question the lookup refuses to. Resolved before the
    // write lock is taken: the wrapped key was sealed to this person on the
    // client long before the request, so re-reading their row inside the
    // transaction would buy nothing and would hold the database's single
    // writer lock across a hash and a decode.
    let invitee = resolve_by_fingerprint(&state, &state.pool, user.id, &email, &body.fingerprint).await?;
    if invitee.id == user.id {
        return Err(ApiError::BadRequest("you already own this secret".into()));
    }
    let invitee_id = invitee.id;

    // The version check and the insert share one transaction: otherwise a
    // rotation committing in between would purge the pending invites and leave
    // this one behind, holding a key that no longer opens the payload.
    let mut tx = begin_write(&state.pool).await?;
    check_quota(
        &mut tx,
        "invites waiting to be answered",
        "SELECT COUNT(*) FROM invites WHERE inviter_id = ?",
        user.id,
        MAX_PENDING_INVITES_PER_ACCOUNT,
    )
    .await?;
    // Counted against the invitee as well. The cap above bounds one account;
    // it does nothing about a crowd of accounts each spending their own budget
    // on the same person, which is what would make their invite list unusable.
    //
    // Written out rather than going through `check_quota`, because that one
    // reports the count it found and this count belongs to someone else. The
    // caller learns only that the person is at the cap, which is the least that
    // can explain the refusal.
    let (waiting_for_them,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invites WHERE invitee_id = ?")
        .bind(invitee_id)
        .fetch_one(&mut *tx)
        .await?;
    // And a much tighter cap on what *this* account may have waiting for them.
    // The ceiling above alone is reachable by five accounts inside their own
    // budgets, which would close the person's list to everyone else.
    let (waiting_from_us,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM invites WHERE invitee_id = ? AND inviter_id = ?")
            .bind(invitee_id)
            .bind(user.id)
            .fetch_one(&mut *tx)
            .await?;
    if waiting_for_them >= MAX_PENDING_INVITES_RECEIVED || waiting_from_us >= MAX_PENDING_INVITES_PER_PAIR {
        // One message for both caps. Which one was hit is not the caller's
        // business — the other person's totals are theirs — and this wording
        // is true either way, where "they have too many" would not be when the
        // caller is the only one who sent any.
        return Err(ApiError::Forbidden(
            "there are too many invitations waiting for that person to answer; ask them to clear some first".into(),
        ));
    }
    // A wrapped key made from a rotated-away version would never open the payload.
    require_key_version(&mut *tx, secret_id, user.id, body.key_version).await?;

    let already_member: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM secret_keys WHERE secret_id = ? AND user_id = ?")
            .bind(secret_id)
            .bind(invitee_id)
            .fetch_optional(&mut *tx)
            .await?;
    if already_member.is_some() {
        return Err(ApiError::Conflict("that user already has access".into()));
    }

    let inserted = sqlx::query(
        "INSERT INTO invites (secret_id, inviter_id, invitee_id, wrapped_key, message, share_project, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(secret_id)
    .bind(user.id)
    .bind(invitee_id)
    .bind(wrapped_key)
    .bind(body.message.trim())
    .bind(body.share_project)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await;

    let invite_id = match inserted {
        Ok(result) => result.last_insert_rowid(),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(ApiError::Conflict("that user already has a pending invite".into()))
        }
        Err(other) => return Err(other.into()),
    };
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(Created { id: invite_id })))
}

pub async fn cancel_invite(
    State(state): State<AppState>,
    user: AuthUser,
    Path((secret_id, invite_id)): Path<(i64, i64)>,
) -> ApiResult<StatusCode> {
    // Only the inviter (the owner) may cancel; enforced in the same statement.
    let affected = sqlx::query("DELETE FROM invites WHERE id = ? AND secret_id = ? AND inviter_id = ?")
        .bind(invite_id)
        .bind(secret_id)
        .bind(user.id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(ApiError::NotFound("invite not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// id, secret name, inviter's email, message, when, and the project name
/// when the inviter chose to share it.
type InviteRow = (i64, String, String, String, DateTime<Utc>, Option<String>);

pub async fn list_invites(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<InviteView>>> {
    let rows: Vec<InviteRow> = sqlx::query_as(
        "SELECT i.id, s.name, u.email, i.message, i.created_at, p.name FROM invites i \
         JOIN secrets s ON s.id = i.secret_id \
         JOIN users u ON u.id = i.inviter_id \
         LEFT JOIN projects p ON p.id = s.project_id AND i.share_project = 1 \
         WHERE i.invitee_id = ? ORDER BY i.created_at DESC",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, secret_name, inviter_email, message, created_at, project)| InviteView {
                id,
                secret_name,
                inviter_email,
                message,
                created_at,
                project,
            })
            .collect(),
    ))
}

pub async fn accept_invite(
    State(state): State<AppState>,
    user: AuthUser,
    Path(invite_id): Path<i64>,
) -> ApiResult<StatusCode> {
    let mut tx = begin_write(&state.pool).await?;
    let invite: Option<(i64, String, bool)> =
        sqlx::query_as("SELECT secret_id, wrapped_key, share_project FROM invites WHERE id = ? AND invitee_id = ?")
            .bind(invite_id)
            .bind(user.id)
            .fetch_optional(&mut *tx)
            .await?;
    let (secret_id, wrapped_key, share_project) =
        invite.ok_or_else(|| ApiError::NotFound("invite not found".into()))?;

    // The inviter's answer travels with the invite into the membership it
    // becomes, so what the invitee was shown before accepting is what they
    // keep seeing afterwards.
    sqlx::query(
        "INSERT OR IGNORE INTO secret_keys (secret_id, user_id, wrapped_key, share_project, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(secret_id)
    .bind(user.id)
    .bind(wrapped_key)
    .bind(share_project)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM invites WHERE id = ?").bind(invite_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn decline_invite(
    State(state): State<AppState>,
    user: AuthUser,
    Path(invite_id): Path<i64>,
) -> ApiResult<StatusCode> {
    let affected = sqlx::query("DELETE FROM invites WHERE id = ? AND invitee_id = ?")
        .bind(invite_id)
        .bind(user.id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(ApiError::NotFound("invite not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ----- sign in with Google --------------------------------------------------

/// Accounts created through Google have no password to check. Rather than
/// making `users.auth_hash` nullable and teaching every login path about the
/// exception, the column holds an Argon2 hash of 32 random bytes that nobody
/// has ever seen. Password login for such an account then fails through the
/// ordinary code path, with the ordinary timing, because the credential simply
/// does not match — there is no special case to get wrong.
async fn unusable_credential() -> ApiResult<String> {
    let random: [u8; 32] = credvault_core::aead::random_bytes();
    auth::hash_credential(Zeroizing::new(BASE64.encode(random))).await
}

fn check_opaque_len(label: &str, value: &str, max: usize) -> ApiResult<()> {
    if value.is_empty() || value.len() > max {
        return Err(ApiError::BadRequest(format!("{label} is missing or too long")));
    }
    Ok(())
}

/// Unauthenticated liveness probe, and the protocol numbers clients check
/// before they send a credential anywhere. Served at `/health`, outside
/// `/api`, because it is also what a monitor and an operator's `curl` hit.
pub async fn health() -> Json<Health> {
    Json(Health::current())
}

pub async fn capabilities(State(state): State<AppState>) -> Json<Capabilities> {
    Json(Capabilities {
        password_sign_in: true,
        google_sign_in: state.config.oauth.is_some(),
        registration_token_required: matches!(state.config.registration, RegistrationPolicy::Token(_)),
        registration_closed: matches!(state.config.registration, RegistrationPolicy::Closed),
    })
}

/// Begin a sign-in: record the attempt and return the URL to open in a browser.
pub async fn oauth_start(
    State(state): State<AppState>,
    user: Option<AuthUser>,
    ApiJson(body): ApiJson<OAuthStartRequest>,
) -> ApiResult<Json<OAuthStartResponse>> {
    let provider = state.config.require_oauth()?;
    let redirect_uri = oauth::validate_loopback_redirect(&body.redirect_uri)?;
    // Linking binds an identity to an account, so the attempt has to say which
    // account, and only that session may finish it. Signing in has no account
    // yet and is anonymous by nature.
    let user_id = match body.purpose {
        OAuthPurpose::Link => Some(user.ok_or(ApiError::Unauthorized)?.id),
        OAuthPurpose::SignIn => None,
    };
    let (state_token, nonce) = oauth::new_state_and_nonce();
    let (code_verifier, code_challenge) = oauth::pkce_pair();
    let app_secret = oauth::new_app_secret();

    sqlx::query(
        "INSERT INTO oauth_attempts \
         (state_hash, purpose, app_secret_hash, user_id, code_verifier, nonce, redirect_uri, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(oauth::hash_opaque(&state_token))
    .bind(body.purpose.as_str())
    .bind(oauth::hash_opaque(&app_secret))
    .bind(user_id)
    .bind(code_verifier.as_str())
    .bind(&nonce)
    .bind(&redirect_uri)
    .bind(auth::now_timestamp() + oauth::ATTEMPT_LIFETIME_SECS)
    .execute(&state.pool)
    .await?;

    // Abandoned attempts are the common case (a user closes the browser tab),
    // so prune here rather than letting them accumulate.
    sqlx::query("DELETE FROM oauth_attempts WHERE expires_at <= ?")
        .bind(auth::now_timestamp())
        .execute(&state.pool)
        .await?;

    // The client composes the authorization URL out of these and its own
    // constants. Nothing here names a page, a scheme or a scope, which is the
    // point: see `OAuthStartResponse`.
    Ok(Json(OAuthStartResponse {
        client_id: provider.client_id().to_string(),
        state: state_token,
        nonce,
        code_challenge,
        app_secret,
    }))
}

/// One authorization attempt, taken out of the table as it is read.
struct ConsumedAttempt {
    code_verifier: Zeroizing<String>,
    nonce: String,
    redirect_uri: String,
    /// The account a link flow was started from; `None` for a sign-in.
    user_id: Option<i64>,
}

/// Take the attempt matching `state`, if it is unexpired, was started for
/// `purpose`, and the caller can produce the secret it was started with.
///
/// The match and the delete are one statement. That makes a `state` single-use
/// under two simultaneous requests, and it means a wrong secret finds no row
/// rather than spending someone else's attempt. A wrong secret and a wrong
/// state are therefore the same answer, which is the point: neither says
/// whether the other was right.
async fn consume_attempt(
    pool: &SqlitePool,
    state_token: &str,
    app_secret: &str,
    purpose: OAuthPurpose,
    started_by: Option<i64>,
) -> ApiResult<ConsumedAttempt> {
    // `IS` rather than `=` so the sign-in case matches a NULL owner. Every
    // condition is in the one statement, so an attempt presented with the
    // wrong secret or by the wrong session finds no row at all — it is not
    // deleted, and the client that really started it can still finish.
    let row: Option<(String, String, String, String, Option<i64>)> = sqlx::query_as(
        "DELETE FROM oauth_attempts \
         WHERE state_hash = ? AND app_secret_hash = ? AND user_id IS ? AND expires_at > ? \
         RETURNING purpose, code_verifier, nonce, redirect_uri, user_id",
    )
    .bind(oauth::hash_opaque(state_token))
    .bind(oauth::hash_opaque(app_secret))
    .bind(started_by)
    .bind(auth::now_timestamp())
    .fetch_optional(pool)
    .await?;

    let (stored_purpose, code_verifier, nonce, redirect_uri, user_id) =
        row.ok_or_else(|| ApiError::BadRequest("this sign-in has expired or was already used; start it again".into()))?;
    // A flow begun to link an identity must not finish as a sign-in, or the
    // reverse. The row is consumed either way, so a mismatched attempt is also
    // spent rather than left for a second try.
    if oauth::purpose_from_storage(&stored_purpose)? != purpose {
        return Err(ApiError::BadRequest("this sign-in was started for something else; start it again".into()));
    }
    Ok(ConsumedAttempt { code_verifier: Zeroizing::new(code_verifier), nonce, redirect_uri, user_id })
}

/// Exchange the code for a verified identity, consuming the attempt first.
/// Also returns the account the attempt was started from, which only a link
/// flow has.
async fn verified_identity_from_callback(
    state: &AppState,
    body: &OAuthCallbackRequest,
    purpose: OAuthPurpose,
    started_by: Option<i64>,
) -> ApiResult<(oauth::VerifiedIdentity, Option<i64>)> {
    let provider = state.config.require_oauth()?;
    check_opaque_len("state", &body.state, MAX_OPAQUE_TOKEN_LEN)?;
    check_opaque_len("app_secret", &body.app_secret, MAX_OPAQUE_TOKEN_LEN)?;
    check_opaque_len("code", &body.code, MAX_AUTH_CODE_LEN)?;
    let attempt = consume_attempt(&state.pool, &body.state, &body.app_secret, purpose, started_by).await?;
    let identity = provider
        .exchange(oauth::ExchangeRequest {
            code: body.code.clone(),
            code_verifier: attempt.code_verifier,
            redirect_uri: attempt.redirect_uri,
            nonce: attempt.nonce,
        })
        .await?;
    Ok((identity, attempt.user_id))
}

/// Finish a sign-in. Either the identity is already bound to an account and a
/// session is issued, or it is not and the client is asked to create one: the
/// server cannot, because an account needs a key pair only the client can make.
pub async fn oauth_callback(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<OAuthCallbackRequest>,
) -> ApiResult<Json<OAuthCallbackResponse>> {
    let (identity, _) = verified_identity_from_callback(&state, &body, OAuthPurpose::SignIn, None).await?;

    let existing: Option<(i64,)> =
        sqlx::query_as("SELECT user_id FROM oauth_identities WHERE provider = ? AND subject = ?")
            .bind(oauth::PROVIDER_GOOGLE)
            .bind(&identity.subject)
            .fetch_optional(&state.pool)
            .await?;

    if let Some((user_id,)) = existing {
        let token = issue_session(&state.pool, user_id).await?;
        let user = load_profile(&state.pool, user_id).await?;
        return Ok(Json(OAuthCallbackResponse::SignedIn(SessionResponse { token, user })));
    }

    // An address that already has a password account is never adopted
    // automatically: whoever controls that Google address today could
    // otherwise take over an account created by whoever held it before.
    // Linking has to start from inside an authenticated session.
    let email_taken: Option<(i64,)> = sqlx::query_as("SELECT id FROM users WHERE email = ?")
        .bind(&identity.email)
        .fetch_optional(&state.pool)
        .await?;
    if email_taken.is_some() {
        return Err(ApiError::Conflict(
            "an account already exists for that address; sign in with your passphrase and link Google from settings"
                .into(),
        ));
    }

    let ticket = oauth::new_ticket();
    sqlx::query(
        "INSERT INTO oauth_pending_registrations (ticket_hash, provider, subject, email, expires_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(oauth::hash_opaque(&ticket))
    .bind(oauth::PROVIDER_GOOGLE)
    .bind(&identity.subject)
    .bind(&identity.email)
    .bind(auth::now_timestamp() + oauth::ATTEMPT_LIFETIME_SECS)
    .execute(&state.pool)
    .await?;
    sqlx::query("DELETE FROM oauth_pending_registrations WHERE expires_at <= ?")
        .bind(auth::now_timestamp())
        .execute(&state.pool)
        .await?;

    Ok(Json(OAuthCallbackResponse::RegistrationRequired { ticket, email: identity.email }))
}

/// Create the account a `RegistrationRequired` ticket stands for. The client
/// has by now asked for a new passphrase and derived a key pair from it and
/// from the email in the ticket; neither reaches the server in usable form.
pub async fn oauth_register(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<OAuthRegisterRequest>,
) -> ApiResult<(StatusCode, Json<SessionResponse>)> {
    state.config.require_oauth()?;
    check_opaque_len("ticket", &body.ticket, MAX_OPAQUE_TOKEN_LEN)?;
    check_registration_policy(&state.config.registration, body.registration_token.as_deref())?;
    let private_key = encode_sealed("encrypted_private_key", &body.encrypted_private_key)?;
    let public_key = body.public_key.to_base64();

    let pending: Option<(String, String, String)> = sqlx::query_as(
        "DELETE FROM oauth_pending_registrations WHERE ticket_hash = ? AND expires_at > ? \
         RETURNING provider, subject, email",
    )
    .bind(oauth::hash_opaque(&body.ticket))
    .bind(auth::now_timestamp())
    .fetch_optional(&state.pool)
    .await?;
    let (provider, subject, email) = pending
        .ok_or_else(|| ApiError::BadRequest("this sign-up has expired or was already used; start it again".into()))?;

    let credential = unusable_credential().await?;

    let mut tx = begin_write(&state.pool).await?;
    let inserted = sqlx::query(
        "INSERT INTO users (email, auth_hash, password_login, public_key, encrypted_private_key, created_at) \
         VALUES (?, ?, 0, ?, ?, ?)",
    )
    .bind(&email)
    .bind(credential)
    .bind(public_key)
    .bind(private_key)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await;

    let user_id = match inserted {
        Ok(result) => result.last_insert_rowid(),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(ApiError::Conflict("an account with that email already exists".into()))
        }
        Err(other) => return Err(other.into()),
    };

    // Same transaction as the user row: an account with no way to sign in
    // would be unreachable and unrecoverable.
    let linked = sqlx::query(
        "INSERT INTO oauth_identities (provider, subject, user_id, email, linked_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&provider)
    .bind(&subject)
    .bind(user_id)
    .bind(&email)
    .bind(auth::now_timestamp())
    .execute(&mut *tx)
    .await;
    if let Err(sqlx::Error::Database(db)) = &linked {
        if db.is_unique_violation() {
            return Err(ApiError::Conflict("that Google account is already linked to an account here".into()));
        }
    }
    linked?;
    tx.commit().await?;

    let token = issue_session(&state.pool, user_id).await?;
    let user = load_profile(&state.pool, user_id).await?;
    Ok((StatusCode::CREATED, Json(SessionResponse { token, user })))
}

/// Check the account passphrase before a sign-in credential is added or removed.
///
/// A session is deliberately not enough. A linked identity signs in on its
/// own, and it survives both `change_password` and "sign out everywhere" —
/// the two things an account holder reaches for after a token leak. A
/// credential that outlives the theft of the token that created it must cost
/// more than that token to create, and the passphrase is the one thing a
/// stolen session does not carry. This is the rule `change_password` already
/// applies, for the same reason.
///
/// The caller has already established that this account signs in with a
/// password. One that does not has no passphrase the server could check, and
/// is refused by each caller with a message of its own before this is reached.
///
/// # Errors
/// [`ApiError::Unauthorized`] if the passphrase is wrong;
/// [`ApiError::BadRequest`] if it is malformed.
async fn verify_account_passphrase(stored_credential: String, presented: Zeroizing<String>) -> ApiResult<()> {
    validate_auth_hash(&presented)?;
    let verified = tokio::task::spawn_blocking(move || auth::verify_credential(&presented, &stored_credential))
        .await
        .map_err(ApiError::internal)?;
    if !verified {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

/// The stored credential and whether a passphrase is what opens this account.
///
/// One indexed lookup for both, because every caller of
/// [`verify_account_passphrase`] needs to know the second before it can decide
/// whether to ask the first.
async fn load_credential(pool: &SqlitePool, user_id: i64) -> ApiResult<(String, bool)> {
    Ok(sqlx::query_as("SELECT auth_hash, password_login FROM users WHERE id = ?").bind(user_id).fetch_one(pool).await?)
}

/// Bind a Google identity to the account already signed in, so that account
/// can use the button next time.
///
/// The account email is deliberately left alone. It is the salt the vault key
/// is derived from, so changing it would make every existing secret
/// undecryptable; the Google address is recorded on the identity row instead.
pub async fn oauth_link(
    State(state): State<AppState>,
    user: AuthUser,
    ApiJson(body): ApiJson<OAuthLinkRequest>,
) -> ApiResult<Json<UserProfile>> {
    spend_account_budget(&state.link_limiter, user.id, "google link")?;

    // Both checks happen before the attempt is spent and before Google is
    // called: a caller who cannot prove the passphrase has no business doing
    // either. An account with no password login is refused outright rather
    // than waved through — today its one identity row is all its unique index
    // allows, so the insert below would fail anyway, but that is a schema
    // invariant in another file and not something this route should rest on.
    let (stored_credential, password_login) = load_credential(&state.pool, user.id).await?;
    if !password_login {
        return Err(ApiError::BadRequest("this account already signs in with Google".into()));
    }
    let presented = body.current_auth_hash.clone().ok_or_else(|| {
        ApiError::BadRequest(
            "the current passphrase is required to link a Google account; if this app never asked for it, it is \
             older than this server and needs updating"
                .into(),
        )
    })?;
    // Spent here rather than at the top, because this is the only line below
    // that costs an Argon2 pass: the two refusals above reject without one and
    // should not burn the budget that bounds passphrase guessing. That budget
    // is shared with `change_password` so that linking cannot be used to widen
    // the guess rate — but deliberately not with `oauth_unlink`, which has to
    // stay reachable while someone is spending this one; see
    // `AppState::unlink_limiter`.
    spend_account_budget(&state.password_limiter, user.id, "google link passphrase")?;
    verify_account_passphrase(stored_credential, presented).await?;

    // The caller's id is part of what selects the attempt, so a link can only
    // be finished by the session that began it. Without that, any
    // authenticated caller holding a valid link state and secret could bind
    // that identity to their own account instead.
    let (identity, _) =
        verified_identity_from_callback(&state, &body.callback(), OAuthPurpose::Link, Some(user.id)).await?;

    let linked = sqlx::query(
        "INSERT INTO oauth_identities (provider, subject, user_id, email, linked_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(oauth::PROVIDER_GOOGLE)
    .bind(&identity.subject)
    .bind(user.id)
    .bind(&identity.email)
    .bind(auth::now_timestamp())
    .execute(&state.pool)
    .await;

    match linked {
        // The profile goes back so the client can show the address that can
        // now sign in. A link nobody can see is a link nobody can revoke.
        Ok(_) => Ok(Json(load_profile(&state.pool, user.id).await?)),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            Err(ApiError::Conflict("that Google account, or this credvault account, is already linked".into()))
        }
        Err(other) => Err(other.into()),
    }
}

/// Remove the Google identity bound to the account, so it can no longer be
/// used to sign in.
///
/// Every session is ended with it, and the caller is handed a fresh one. A
/// link that should not have been there has had up to a session lifetime to
/// mint tokens, and those tokens do not mention where they came from; deleting
/// the row alone would leave the credential removed and its issue still
/// working for another month. This is the same reasoning, and the same
/// transaction shape, as [`change_password`].
///
/// Refused for an account created through Google: that identity is its only
/// credential, and removing it would leave an account with nothing that can
/// open it and no way to recover, since the server holds no plaintext.
///
/// # Errors
/// [`ApiError::Unauthorized`] if the passphrase is wrong;
/// [`ApiError::BadRequest`] if this account signs in with Google only, or the
/// passphrase proof is malformed;
/// [`ApiError::NotFound`] if nothing is linked.
pub async fn oauth_unlink(
    State(state): State<AppState>,
    user: AuthUser,
    ApiJson(body): ApiJson<OAuthUnlinkRequest>,
) -> ApiResult<Json<SessionResponse>> {
    // Its own budget, so traffic on `/password` and `/oauth/link` cannot
    // decide whether this route answers. It does not make the route
    // unstarvable — nothing keyed by account can be, against someone holding a
    // session for that account — and `AppState::unlink_limiter` says what to
    // reach for instead.
    spend_account_budget(&state.unlink_limiter, user.id, "google unlink")?;
    // Read before the passphrase is checked, so a Google-only account is told
    // why it cannot unlink rather than that it supplied a passphrase it has no
    // business having. It also saves an Argon2 verify on a request that cannot
    // succeed.
    let (stored_credential, password_login) = load_credential(&state.pool, user.id).await?;
    if !password_login {
        return Err(ApiError::BadRequest(
            "this account signs in with Google only; removing the link would leave no way to sign in".into(),
        ));
    }
    verify_account_passphrase(stored_credential, body.current_auth_hash.clone()).await?;

    let mut tx = begin_write(&state.pool).await?;
    // The delete comes first on purpose. It takes the write lock, and when it
    // matches nothing this returns before any other statement has run — so the
    // early return below has nothing to undo rather than relying on the
    // rollback. Adding a read above it would give up both properties.
    let removed = sqlx::query("DELETE FROM oauth_identities WHERE user_id = ? AND provider = ?")
        .bind(user.id)
        .bind(oauth::PROVIDER_GOOGLE)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(ApiError::NotFound("no Google account is linked to this account".into()));
    }
    // In the same transaction as the delete: a crash between the two would
    // otherwise leave the sessions the link minted alive with nothing left to
    // explain where they came from.
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user.id).execute(&mut *tx).await?;
    tx.commit().await?;

    let token = issue_session(&state.pool, user.id).await?;
    let profile = load_profile(&state.pool, user.id).await?;
    Ok(Json(SessionResponse { token, user: profile }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_validation() {
        assert_eq!(validate_email(" Alice@Example.COM ").unwrap(), "alice@example.com");
        for bad in ["", "alice", "@example.com", "alice@", "alice@nodot", "alice@.com", "alice@com.", "a b@example.com"]
        {
            assert!(validate_email(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(validate_email("ali\u{0}ce@example.com").is_err());
        assert!(validate_email("ali\tce@example.com").is_err());
        assert!(validate_email(&format!("{}@example.com", "a".repeat(MAX_EMAIL_LEN))).is_err());
    }

    #[test]
    fn registration_policy() {
        assert!(check_registration_policy(&RegistrationPolicy::Open, None).is_ok());
        assert!(matches!(
            check_registration_policy(&RegistrationPolicy::Closed, Some("x")),
            Err(ApiError::Forbidden(_))
        ));
        let policy = RegistrationPolicy::Token("s3cret".into());
        assert!(check_registration_policy(&policy, Some("s3cret")).is_ok());
        assert!(matches!(check_registration_policy(&policy, Some("wrong")), Err(ApiError::Forbidden(_))));
        assert!(matches!(check_registration_policy(&policy, Some("s3cret ")), Err(ApiError::Forbidden(_))));
        assert!(matches!(check_registration_policy(&policy, None), Err(ApiError::Forbidden(_))));
        let long = "x".repeat(MAX_REGISTRATION_TOKEN_LEN + 1);
        assert!(matches!(check_registration_policy(&policy, Some(&long)), Err(ApiError::BadRequest(_))));
    }

    #[test]
    fn fingerprint_comparison_ignores_formatting_and_rejects_near_misses() {
        let real = "3f1a-9c0e-77b2-d4a5-1b2c-3d4e";
        assert!(fingerprint_matches(real, real));
        assert!(fingerprint_matches(real, "3F1A9C0E77B2D4A51B2C3D4E"));
        assert!(fingerprint_matches(real, "  3f1a 9c0e 77b2 d4a5 1b2c 3d4e  "));
        // One digit out, a truncation, and an empty guess all fail.
        assert!(!fingerprint_matches(real, "3f1a-9c0e-77b2-d4a5-1b2c-3d4f"));
        assert!(!fingerprint_matches(real, "3f1a-9c0e-77b2"));
        assert!(!fingerprint_matches(real, ""));
        assert!(!fingerprint_matches(real, &absent_fingerprint()));
    }

    #[test]
    fn blob_size_limit() {
        assert!(check_blob_size("payload", MAX_BLOB_BYTES).is_ok());
        assert!(check_blob_size("payload", MAX_BLOB_BYTES + 1).is_err());
    }
}
