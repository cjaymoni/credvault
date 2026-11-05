//! HTTP handlers. Authorization is enforced here in SQL by user id; the
//! server never decrypts anything.

use std::collections::{HashMap, HashSet};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use credvault_core::identity::normalize_fingerprint;
use credvault_core::kdf::{normalize_email, validate_auth_hash};
use credvault_core::{secret, PublicKey, Sealed, WrappedKey};
use sha2::{Digest, Sha256};
use sqlx::{SqliteExecutor, SqlitePool, Transaction};
use subtle::ConstantTimeEq;

use crate::auth::{self, AuthUser};
use crate::error::{ApiError, ApiResult};
use crate::extract::ApiJson;
use crate::{AppState, RegistrationPolicy};
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
    let (id, email, public_key, encrypted_private_key): (i64, String, String, String) =
        sqlx::query_as("SELECT id, email, public_key, encrypted_private_key FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(UserProfile {
        id,
        email,
        public_key: decode_stored_public_key(&public_key)?,
        encrypted_private_key: decode_stored(&encrypted_private_key)?,
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

/// Invalidate every session for the caller, including the one making the request.
pub async fn logout_everywhere(State(state): State<AppState>, user: AuthUser) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user.id).execute(&state.pool).await?;
    Ok(StatusCode::NO_CONTENT)
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

// ----- secrets --------------------------------------------------------------

type SecretRow = (i64, String, String, i64, String, String, DateTime<Utc>, i64);

const SECRET_VIEW_SQL: &str =
    "SELECT s.id, s.name, s.payload, s.owner_id, owner.email, k.wrapped_key, s.updated_at, s.key_version \
     FROM secret_keys k \
     JOIN secrets s ON s.id = k.secret_id \
     JOIN users owner ON owner.id = s.owner_id \
     WHERE k.user_id = ?";

fn secret_view(row: SecretRow, viewer_id: i64) -> ApiResult<SecretView> {
    let (id, name, payload, owner_id, owner_email, wrapped_key, updated_at, key_version) = row;
    Ok(SecretView {
        id,
        name,
        owner_email,
        is_owner: owner_id == viewer_id,
        payload: decode_stored(&payload)?,
        wrapped_key: decode_stored(&wrapped_key)?,
        updated_at,
        key_version,
    })
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
    let secret_id =
        sqlx::query("INSERT INTO secrets (owner_id, name, payload, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(user.id)
            .bind(name)
            .bind(payload)
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
    // Ownership and key version are checked in the same statement, so there is
    // no window in which the secret can change hands, disappear or be rotated
    // between check and write.
    let affected = sqlx::query(
        "UPDATE secrets SET name = ?, payload = ?, updated_at = ? WHERE id = ? AND owner_id = ? AND key_version = ?",
    )
    .bind(name)
    .bind(payload)
    .bind(Utc::now())
    .bind(secret_id)
    .bind(user.id)
    .bind(body.key_version)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if affected == 0 {
        // Tell a stale client apart from a wrong one.
        require_key_version(&state.pool, secret_id, user.id, body.key_version).await?;
        return Err(ApiError::NotFound("secret not found".into()));
    }
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
    let members: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT u.id, u.email, u.public_key FROM secret_keys k JOIN users u ON u.id = k.user_id \
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
            .map(|(user_id, email, public_key)| {
                Ok(Member { user_id, email, public_key: decode_stored_public_key(&public_key)? })
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
        "INSERT INTO invites (secret_id, inviter_id, invitee_id, wrapped_key, message, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(secret_id)
    .bind(user.id)
    .bind(invitee_id)
    .bind(wrapped_key)
    .bind(body.message.trim())
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

pub async fn list_invites(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<InviteView>>> {
    let rows: Vec<(i64, String, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT i.id, s.name, u.email, i.message, i.created_at FROM invites i \
         JOIN secrets s ON s.id = i.secret_id \
         JOIN users u ON u.id = i.inviter_id \
         WHERE i.invitee_id = ? ORDER BY i.created_at DESC",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, secret_name, inviter_email, message, created_at)| InviteView {
                id,
                secret_name,
                inviter_email,
                message,
                created_at,
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
    let invite: Option<(i64, String)> =
        sqlx::query_as("SELECT secret_id, wrapped_key FROM invites WHERE id = ? AND invitee_id = ?")
            .bind(invite_id)
            .bind(user.id)
            .fetch_optional(&mut *tx)
            .await?;
    let (secret_id, wrapped_key) = invite.ok_or_else(|| ApiError::NotFound("invite not found".into()))?;

    sqlx::query("INSERT OR IGNORE INTO secret_keys (secret_id, user_id, wrapped_key, created_at) VALUES (?, ?, ?, ?)")
        .bind(secret_id)
        .bind(user.id)
        .bind(wrapped_key)
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
