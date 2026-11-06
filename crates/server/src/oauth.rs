//! Sign in with Google, over OpenID Connect's authorization-code flow.
//!
//! The server is the confidential client: it holds the client secret and does
//! the code exchange itself, so nothing secret ships inside the desktop app.
//! The desktop app only opens a URL, catches the redirect on a loopback
//! listener, and hands the code back here.
//!
//! What Google proves is *who the user is*. It never produces key material, so
//! a signed-in user still has to supply their passphrase before anything can
//! be decrypted; see `kdf::MasterKey`. Nothing in this module touches
//! plaintext secrets or keys.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use credvault_core::api::OAuthPurpose;
use credvault_core::kdf::normalize_email;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{ApiError, ApiResult};

/// Google's discovery document, pinned rather than fetched. These endpoints
/// have been stable for a decade, and fetching them at runtime would add a
/// network dependency on the path of every sign-in for no security gain.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";
pub const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
pub const GOOGLE_JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Google also accepts the bare host as an issuer in some tokens.
const GOOGLE_ALT_ISSUER: &str = "accounts.google.com";

/// Provider name stored in `oauth_identities.provider`.
pub const PROVIDER_GOOGLE: &str = "google";

/// How long an authorization attempt or a pending registration stays valid.
/// Long enough to find the browser window and pick an account, short enough
/// that an abandoned attempt is not lying around.
pub const ATTEMPT_LIFETIME_SECS: i64 = 10 * 60;

/// Clock skew allowed when checking `exp` and `iat`.
const CLOCK_SKEW_SECS: u64 = 60;

/// Cache lifetime for Google's signing keys. A key whose `kid` is unknown
/// triggers an immediate refetch regardless, so this only bounds staleness.
const JWKS_CACHE_SECS: u64 = 60 * 60;

const HTTP_TIMEOUT_SECS: u64 = 10;

/// An identity the provider has vouched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The provider's stable, immutable id for this user. The only thing a
    /// sign-in is resolved by.
    pub subject: String,
    /// The verified address, normalised. Used as the account email, and
    /// therefore as the client's key-derivation salt.
    pub email: String,
}

/// What a client needs to send the user to the provider.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub redirect_uri: String,
}

/// What the provider needs to turn a code into an identity.
pub struct ExchangeRequest {
    pub code: Zeroizing<String>,
    pub code_verifier: Zeroizing<String>,
    pub redirect_uri: String,
    pub nonce: String,
}

/// Public so that tests outside this crate can implement [`OAuthProvider`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Implemented by [`GoogleProvider`] in production and by a stub in tests, so
/// handler behaviour can be tested without reaching the network.
pub trait OAuthProvider: Send + Sync + 'static {
    /// The URL to open in the user's browser.
    fn authorization_url(&self, request: &AuthorizationRequest) -> String;

    /// Exchange an authorization code and return the identity it proves.
    fn exchange<'a>(&'a self, request: ExchangeRequest) -> BoxFuture<'a, ApiResult<VerifiedIdentity>>;
}

// ----- opaque tokens and PKCE ----------------------------------------------

/// 32 random bytes, URL-safe base64. Used for `state`, `nonce`, the PKCE
/// verifier, and registration tickets.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The digest stored for a `state` or a ticket, so a leaked database cannot be
/// used to complete someone else's flow. Same construction as session tokens.
pub fn hash_opaque(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// A PKCE verifier and its S256 challenge.
pub fn pkce_pair() -> (Zeroizing<String>, String) {
    let verifier = Zeroizing::new(random_token());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// A fresh `state` and `nonce`.
pub fn new_state_and_nonce() -> (String, String) {
    (random_token(), random_token())
}

/// A fresh registration ticket.
pub fn new_ticket() -> String {
    random_token()
}

/// A fresh proof that a callback comes from the client that began the flow.
/// Zeroizing because, unlike `state`, it never belongs in a URL or a log.
pub fn new_app_secret() -> Zeroizing<String> {
    Zeroizing::new(random_token())
}

// ----- redirect URI ---------------------------------------------------------

/// Accept only a loopback redirect, which is what a native app can actually
/// receive (RFC 8252). Without this check the server would hand authorization
/// codes for its own client id to any address a caller named.
pub fn validate_loopback_redirect(raw: &str) -> ApiResult<String> {
    const REJECT: &str = "redirect_uri must be a loopback http URL such as http://127.0.0.1:1234/callback";
    let url = Url::parse(raw).map_err(|_| ApiError::BadRequest(REJECT.into()))?;
    let is_loopback = matches!(url.host_str(), Some("127.0.0.1") | Some("[::1]"));
    if url.scheme() != "http" || !is_loopback || url.port().is_none() {
        return Err(ApiError::BadRequest(REJECT.into()));
    }
    // A fragment or credentials in the URL would be sent to the provider as
    // part of the registered redirect and have no legitimate use here.
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(ApiError::BadRequest(REJECT.into()));
    }
    Ok(url.to_string())
}

// ----- id token claims ------------------------------------------------------

/// The claims this server cares about. Everything else Google sends is ignored.
#[derive(Debug, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub nonce: Option<String>,
}

/// How an id token is checked once its signature verifies.
///
/// Expected values and *required* claims are two different settings, and both
/// are needed. `set_audience` and `set_issuer` are checked only when the claim
/// is present, so a token signed by a key in Google's keyset but carrying
/// neither would pass both by omitting them; `required_spec_claims` is what
/// makes their absence a rejection. `exp` is in the set by default and is
/// named here so the whole set is visible in one place.
fn id_token_validation(client_id: &str, issuer: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[issuer, GOOGLE_ALT_ISSUER]);
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);
    validation.leeway = CLOCK_SKEW_SECS;
    validation.validate_exp = true;
    validation
}

/// Check the claims a signature cannot: that this token answers *our* request,
/// and that the address in it was actually verified by the provider.
///
/// Signature, algorithm, issuer, audience and expiry are checked by
/// [`verify_id_token`] before this runs.
///
/// # Errors
/// [`ApiError::Unauthorized`] if the nonce does not match the one issued for
/// this attempt, the subject is empty, or the email is missing or unverified.
pub fn verify_identity_claims(claims: &IdTokenClaims, expected_nonce: &str) -> ApiResult<VerifiedIdentity> {
    let presented = claims.nonce.as_deref().unwrap_or_default();
    let nonce_matches: bool =
        Sha256::digest(presented.as_bytes()).ct_eq(&Sha256::digest(expected_nonce.as_bytes())).into();
    if !nonce_matches {
        return Err(ApiError::Unauthorized);
    }
    if claims.sub.is_empty() {
        return Err(ApiError::Unauthorized);
    }
    // An unverified address must never become an account email: it is the
    // name other users invite, and the salt the vault key is derived from.
    let email = claims.email.as_deref().unwrap_or_default();
    if !claims.email_verified || email.is_empty() {
        return Err(ApiError::Forbidden(
            "this Google account has no verified email address, which credvault requires".into(),
        ));
    }
    Ok(VerifiedIdentity { subject: claims.sub.clone(), email: normalize_email(email) })
}

// ----- Google ---------------------------------------------------------------

/// Everything needed to talk to Google. Endpoints are fields rather than
/// constants so tests can point them at a local stand-in.
#[derive(Clone)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    pub issuer: String,
    pub auth_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

impl GoogleConfig {
    pub fn new(client_id: String, client_secret: Zeroizing<String>) -> Self {
        Self {
            client_id,
            client_secret,
            issuer: GOOGLE_ISSUER.to_string(),
            auth_endpoint: GOOGLE_AUTH_ENDPOINT.to_string(),
            token_endpoint: GOOGLE_TOKEN_ENDPOINT.to_string(),
            jwks_uri: GOOGLE_JWKS_URI.to_string(),
        }
    }
}

pub struct GoogleProvider {
    config: GoogleConfig,
    http: reqwest::Client,
    jwks: RwLock<Option<CachedJwks>>,
}

struct CachedJwks {
    keys: Arc<HashMap<String, DecodingKey>>,
    fetched_at: Instant,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

impl GoogleProvider {
    pub fn new(config: GoogleConfig) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(HTTP_TIMEOUT_SECS)).build()?;
        Ok(Self { config, http, jwks: RwLock::new(None) })
    }

    fn cached_keys(&self) -> Option<Arc<HashMap<String, DecodingKey>>> {
        let guard = self.jwks.read().ok()?;
        let cached = guard.as_ref()?;
        (cached.fetched_at.elapsed() < Duration::from_secs(JWKS_CACHE_SECS)).then(|| Arc::clone(&cached.keys))
    }

    async fn fetch_keys(&self) -> ApiResult<Arc<HashMap<String, DecodingKey>>> {
        let response = self
            .http
            .get(&self.config.jwks_uri)
            .send()
            .await
            .map_err(|e| provider_unavailable("fetching Google's signing keys", e))?;
        let set: JwkSet = response
            .error_for_status()
            .map_err(|e| provider_unavailable("fetching Google's signing keys", e))?
            .json()
            .await
            .map_err(|e| provider_unavailable("parsing Google's signing keys", e))?;

        let mut keys = HashMap::new();
        for jwk in set.keys {
            if jwk.kty != "RSA" {
                continue;
            }
            match DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
                Ok(key) => {
                    keys.insert(jwk.kid, key);
                }
                // One malformed key must not break sign-in for everyone; the
                // others are still usable and an unknown kid fails loudly below.
                Err(error) => tracing::warn!(kid = %jwk.kid, %error, "skipping unusable Google signing key"),
            }
        }
        if keys.is_empty() {
            return Err(ApiError::Internal("Google returned no usable signing keys".into()));
        }

        let keys = Arc::new(keys);
        if let Ok(mut guard) = self.jwks.write() {
            *guard = Some(CachedJwks { keys: Arc::clone(&keys), fetched_at: Instant::now() });
        }
        Ok(keys)
    }

    /// The key for `kid`, refetching once if the cache does not have it.
    /// Google rotates keys, so an unknown `kid` is expected, not an attack.
    async fn key_for(&self, kid: &str) -> ApiResult<DecodingKey> {
        if let Some(keys) = self.cached_keys() {
            if let Some(key) = keys.get(kid) {
                return Ok(key.clone());
            }
        }
        let keys = self.fetch_keys().await?;
        keys.get(kid).cloned().ok_or_else(|| {
            tracing::warn!(%kid, "id token signed by a key Google does not publish");
            ApiError::Unauthorized
        })
    }

    async fn verify_id_token(&self, id_token: &str, nonce: &str) -> ApiResult<VerifiedIdentity> {
        let header = decode_header(id_token).map_err(|_| ApiError::Unauthorized)?;
        // Pinning RS256 here as well as in `Validation` keeps an `alg: none`
        // or HMAC token from ever reaching key lookup.
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::Unauthorized);
        }
        let kid = header.kid.ok_or(ApiError::Unauthorized)?;
        let key = self.key_for(&kid).await?;

        let validation = id_token_validation(&self.config.client_id, &self.config.issuer);

        let data = decode::<IdTokenClaims>(id_token, &key, &validation).map_err(|error| {
            tracing::warn!(%error, "id token rejected");
            ApiError::Unauthorized
        })?;
        verify_identity_claims(&data.claims, nonce)
    }
}

impl OAuthProvider for GoogleProvider {
    fn authorization_url(&self, request: &AuthorizationRequest) -> String {
        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("redirect_uri", request.redirect_uri.as_str()),
            ("response_type", "code"),
            ("scope", "openid email"),
            ("state", request.state.as_str()),
            ("nonce", request.nonce.as_str()),
            ("code_challenge", request.code_challenge.as_str()),
            ("code_challenge_method", "S256"),
            // Always show the chooser: without it a user with several Google
            // accounts silently signs in as whichever one the browser has.
            ("prompt", "select_account"),
        ];
        match Url::parse_with_params(&self.config.auth_endpoint, params) {
            Ok(url) => url.to_string(),
            // The endpoint is a constant, so this cannot happen in practice.
            Err(error) => {
                tracing::error!(%error, "google auth endpoint is not a valid URL");
                String::new()
            }
        }
    }

    fn exchange<'a>(&'a self, request: ExchangeRequest) -> BoxFuture<'a, ApiResult<VerifiedIdentity>> {
        Box::pin(async move {
            let form = [
                ("grant_type", "authorization_code"),
                ("code", request.code.as_str()),
                ("code_verifier", request.code_verifier.as_str()),
                ("redirect_uri", request.redirect_uri.as_str()),
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
            ];
            let response = self
                .http
                .post(&self.config.token_endpoint)
                .form(&form)
                .send()
                .await
                .map_err(|e| provider_unavailable("exchanging the authorization code", e))?;

            let status = response.status();
            if !status.is_success() {
                // Google's body explains *why* the code was rejected; it is
                // useful in the log and not something to hand to the caller.
                let detail = response.text().await.unwrap_or_default();
                tracing::warn!(%status, detail = %detail, "google rejected the authorization code");
                return Err(ApiError::BadRequest("the sign-in could not be completed; start it again".into()));
            }

            let token: TokenResponse =
                response.json().await.map_err(|e| provider_unavailable("reading Google's token response", e))?;
            self.verify_id_token(&token.id_token, &request.nonce).await
        })
    }
}

/// Google being unreachable is our problem to report, not the caller's to fix,
/// and the operation is named so the log says which call failed.
fn provider_unavailable(operation: &'static str, error: reqwest::Error) -> ApiError {
    tracing::error!(%error, operation, "google sign-in request failed");
    ApiError::Internal(format!("google sign-in is temporarily unavailable ({operation})").into())
}

/// Parse a stored `purpose` column.
pub fn purpose_from_storage(text: &str) -> ApiResult<OAuthPurpose> {
    OAuthPurpose::parse(text)
        .ok_or_else(|| ApiError::Internal(format!("unrecognised oauth attempt purpose {text:?}").into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(nonce: Option<&str>, email: Option<&str>, verified: bool) -> IdTokenClaims {
        IdTokenClaims {
            sub: "108123456789".into(),
            email: email.map(str::to_string),
            email_verified: verified,
            nonce: nonce.map(str::to_string),
        }
    }

    #[test]
    fn accepts_a_matching_nonce_and_verified_email() {
        let identity = verify_identity_claims(&claims(Some("n"), Some("Me@Example.COM"), true), "n").unwrap();
        assert_eq!(identity.subject, "108123456789");
        // Normalised, because the client derives its key from this string.
        assert_eq!(identity.email, "me@example.com");
    }

    #[test]
    fn rejects_a_token_issued_for_another_attempt() {
        let err = verify_identity_claims(&claims(Some("other"), Some("a@b.com"), true), "n").unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized));
    }

    #[test]
    fn rejects_a_token_with_no_nonce() {
        let err = verify_identity_claims(&claims(None, Some("a@b.com"), true), "n").unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized));
    }

    #[test]
    fn rejects_an_unverified_or_missing_email() {
        for case in [claims(Some("n"), Some("a@b.com"), false), claims(Some("n"), None, true)] {
            let err = verify_identity_claims(&case, "n").unwrap_err();
            assert!(matches!(err, ApiError::Forbidden(_)), "{err:?}");
        }
        let mut empty = claims(Some("n"), Some(""), true);
        empty.email = Some(String::new());
        assert!(matches!(verify_identity_claims(&empty, "n"), Err(ApiError::Forbidden(_))));
    }

    #[test]
    fn rejects_an_empty_subject() {
        let mut case = claims(Some("n"), Some("a@b.com"), true);
        case.sub = String::new();
        assert!(matches!(verify_identity_claims(&case, "n"), Err(ApiError::Unauthorized)));
    }

    #[test]
    fn loopback_redirects_only() {
        for good in ["http://127.0.0.1:49152/callback", "http://[::1]:8080/cb", "http://127.0.0.1:1/"] {
            assert!(validate_loopback_redirect(good).is_ok(), "{good}");
        }
        for bad in [
            "https://evil.example.com/callback",   // not loopback
            "http://evil.example.com:80/callback", // not loopback
            "http://127.0.0.1/callback",           // no port
            "http://localhost:8080/callback",      // name, not the literal
            "http://127.0.0.1:8080/cb#frag",       // fragment
            "http://user:pw@127.0.0.1:8080/cb",    // credentials
            "not a url",
            "",
        ] {
            assert!(validate_loopback_redirect(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn pkce_challenge_is_the_sha256_of_the_verifier() {
        let (verifier, challenge) = pkce_pair();
        assert_eq!(challenge, URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())));
        let (other, other_challenge) = pkce_pair();
        assert_ne!(*verifier, *other);
        assert_ne!(challenge, other_challenge);
    }

    #[test]
    fn opaque_tokens_are_random_and_stored_as_digests() {
        let (state, nonce) = new_state_and_nonce();
        assert_ne!(state, nonce);
        assert_ne!(state, new_state_and_nonce().0);
        assert_eq!(hash_opaque(&state), hash_opaque(&state));
        assert_ne!(hash_opaque(&state), state);
        assert_ne!(new_ticket(), new_ticket());
    }

    /// A token that simply leaves `aud` or `iss` out must not slip through the
    /// gap between "this is the value I expect" and "this claim has to be
    /// there". The claims struct does not carry either field, so nothing
    /// downstream would notice their absence.
    #[test]
    fn audience_and_issuer_are_required_not_merely_expected() {
        let validation = id_token_validation("client-id.apps.googleusercontent.com", GOOGLE_ISSUER);
        for claim in ["exp", "aud", "iss"] {
            assert!(validation.required_spec_claims.contains(claim), "{claim} must be required");
        }
        assert_eq!(validation.algorithms, vec![Algorithm::RS256]);
        assert!(validation.validate_exp);
        // Requiring `aud` to be present and checking what it says are two
        // separate switches in jsonwebtoken: with this one off the claim is
        // still demanded, and then any audience at all is accepted.
        assert!(validation.validate_aud, "a required audience that is never compared is not a check");
        assert_eq!(validation.leeway, CLOCK_SKEW_SECS);
    }

    #[test]
    fn authorization_url_carries_every_parameter() {
        let provider =
            GoogleProvider::new(GoogleConfig::new("client-123".into(), Zeroizing::new("sec".into()))).unwrap();
        let url = provider.authorization_url(&AuthorizationRequest {
            state: "st".into(),
            nonce: "no".into(),
            code_challenge: "ch".into(),
            redirect_uri: "http://127.0.0.1:49152/callback".into(),
        });
        let parsed = Url::parse(&url).unwrap();
        let params: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(params["client_id"], "client-123");
        assert_eq!(params["redirect_uri"], "http://127.0.0.1:49152/callback");
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["scope"], "openid email");
        assert_eq!(params["state"], "st");
        assert_eq!(params["nonce"], "no");
        assert_eq!(params["code_challenge"], "ch");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["prompt"], "select_account");
        // The secret is never part of a URL the user's browser will follow.
        assert!(!url.contains("sec"));
    }

    #[test]
    fn purposes_round_trip_through_storage() {
        for purpose in [OAuthPurpose::SignIn, OAuthPurpose::Link] {
            assert_eq!(purpose_from_storage(purpose.as_str()).unwrap(), purpose);
        }
        assert!(purpose_from_storage("something-else").is_err());
    }
}
