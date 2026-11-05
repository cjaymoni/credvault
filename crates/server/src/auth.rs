//! Credential hashing, session tokens, and the authenticated-user extractor.

use std::sync::OnceLock;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::ApiError;
use crate::AppState;

pub const SESSION_LIFETIME_DAYS: i64 = 30;
const TOKEN_BYTES: usize = 32;
const BEARER_PREFIX: &str = "Bearer ";

/// Hash the client's auth hash once more so a database leak cannot be
/// replayed as a login credential. Argon2 is CPU-bound, so this runs on the
/// blocking pool rather than an executor thread.
pub async fn hash_credential(auth_hash: Zeroizing<String>) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || hash_credential_blocking(&auth_hash)).await.map_err(ApiError::internal)?
}

fn hash_credential_blocking(auth_hash: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(auth_hash.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(ApiError::internal)
}

pub fn verify_credential(auth_hash: &str, stored: &str) -> bool {
    PasswordHash::new(stored)
        .map(|parsed| Argon2::default().verify_password(auth_hash.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

/// Argon2 hash of a random value, used only to equalise login timing for
/// unknown emails. Call once at startup so the first login does not pay for it.
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let random: [u8; 32] = credvault_core::aead::random_bytes();
        hash_credential_blocking(&base64::engine::general_purpose::STANDARD.encode(random))
            .expect("hashing a random credential cannot fail")
    })
}

/// Decide whether a login succeeds. `verify` always runs exactly once, against
/// a dummy hash when the email is unknown, so response time does not reveal
/// which emails have accounts. An unknown email never logs in, whatever
/// `verify` says about the dummy.
pub fn resolve_login(
    row: Option<(i64, String)>,
    auth_hash: &str,
    verify: impl FnOnce(&str, &str) -> bool,
) -> Option<i64> {
    let (user_id, stored) = match row {
        Some((id, stored)) => (Some(id), stored),
        None => (None, dummy_hash().to_string()),
    };
    let verified = verify(auth_hash, &stored);
    if verified {
        user_id
    } else {
        None
    }
}

/// Run `resolve_login` with the real Argon2 verifier on the blocking pool.
pub async fn verify_login(row: Option<(i64, String)>, auth_hash: Zeroizing<String>) -> Result<Option<i64>, ApiError> {
    tokio::task::spawn_blocking(move || resolve_login(row, &auth_hash, verify_credential))
        .await
        .map_err(ApiError::internal)
}

/// A fresh random bearer token and the SHA-256 digest stored for it.
pub fn new_session_token() -> (String, String) {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let digest = hash_token(&token);
    (token, digest)
}

pub fn hash_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// Unix timestamp (seconds) at which a session issued now expires.
pub fn session_expiry() -> i64 {
    (Utc::now() + Duration::days(SESSION_LIFETIME_DAYS)).timestamp()
}

pub fn now_timestamp() -> i64 {
    Utc::now().timestamp()
}

/// Extractor that resolves the `Authorization: Bearer <token>` header to a user.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: i64,
    pub email: String,
    /// Digest of the presenting session's token, so handlers can act on it
    /// (e.g. logout) without re-parsing the header.
    pub token_hash: String,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix(BEARER_PREFIX))
            .ok_or(ApiError::Unauthorized)?;
        let token_hash = hash_token(token);

        let row: Option<(i64, String)> = sqlx::query_as(
            "SELECT users.id, users.email FROM sessions \
             JOIN users ON users.id = sessions.user_id \
             WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
        )
        .bind(&token_hash)
        .bind(now_timestamp())
        .fetch_optional(&state.pool)
        .await?;

        let (id, email) = row.ok_or(ApiError::Unauthorized)?;
        Ok(AuthUser { id, email, token_hash })
    }
}

/// Resolve a session only if one was offered.
///
/// A missing `Authorization` header is `None`, not a rejection: one endpoint
/// serves both an anonymous sign-in and an authenticated link, and which it is
/// cannot be known until the body is parsed. A header that *is* present and
/// does not resolve is still an error — a stale token must not quietly become
/// an anonymous request and start the wrong kind of flow.
impl axum::extract::OptionalFromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Option<Self>, Self::Rejection> {
        if !parts.headers.contains_key(axum::http::header::AUTHORIZATION) {
            return Ok(None);
        }
        <Self as FromRequestParts<AppState>>::from_request_parts(parts, state).await.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn unknown_email_still_runs_the_verifier_and_never_logs_in() {
        let calls = Cell::new(0);
        let seen_dummy = Cell::new(false);
        let result = resolve_login(None, "whatever", |_, stored| {
            calls.set(calls.get() + 1);
            seen_dummy.set(stored == dummy_hash());
            true // even a (hypothetical) match on the dummy must not log in
        });
        assert_eq!(calls.get(), 1);
        assert!(seen_dummy.get());
        assert_eq!(result, None);
    }

    #[test]
    fn known_email_logs_in_only_when_verifier_accepts() {
        let row = Some((42, "stored-hash".to_string()));
        assert_eq!(resolve_login(row.clone(), "h", |hash, stored| hash == "h" && stored == "stored-hash"), Some(42));
        assert_eq!(resolve_login(row, "h", |_, _| false), None);
    }

    #[test]
    fn real_verifier_round_trip_and_garbage_hash() {
        let stored = hash_credential_blocking("auth-hash").unwrap();
        assert!(verify_credential("auth-hash", &stored));
        assert!(!verify_credential("other", &stored));
        assert!(!verify_credential("auth-hash", "not a phc string"));
    }

    #[test]
    fn session_tokens_are_random_and_hashed() {
        let (a, a_hash) = new_session_token();
        let (b, _) = new_session_token();
        assert_ne!(a, b);
        assert_eq!(hash_token(&a), a_hash);
        assert_ne!(a, a_hash);
        assert!(session_expiry() > now_timestamp());
    }
}
