//! credvault sync server: accounts, encrypted secrets, and sharing invites.

pub use credvault_core::api;
pub mod auth;
pub mod error;
mod extract;
mod handlers;
pub mod oauth;
pub mod ratelimit;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{delete, get, post};
use axum::{middleware, Router};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use oauth::OAuthProvider;
use ratelimit::{AuthLimit, RateLimiter};

/// Largest request body the server accepts; blobs are capped lower in handlers.
///
/// Sized by the one request that is legitimately large: a passphrase change
/// carries every owner copy of a secret key at once, because changing half of
/// what the passphrase derives would leave a vault nobody can open. At the
/// quota that is roughly 175 KB of base64 and JSON.
pub const MAX_REQUEST_BYTES: usize = 512 * 1024;

/// Roughly what one re-wrapped key costs on the wire: a 12-byte nonce and a
/// 48-byte ciphertext in base64, inside two JSON objects, with room to spare.
const REWRAPPED_KEY_WIRE_BYTES: usize = 256;

/// The two limits are set independently and must not drift into a state where
/// a vault at the quota cannot have its passphrase changed — which would be
/// discovered by a user who had already typed a new one.
const _: () = assert!(
    api::MAX_SECRETS_PER_ACCOUNT as usize * REWRAPPED_KEY_WIRE_BYTES < MAX_REQUEST_BYTES,
    "a full re-wrap must fit in one request body"
);

/// Token buckets: per client address for the unauthenticated endpoints, per
/// caller id for the directory lookup.
#[derive(Clone, Debug)]
pub struct RateLimits {
    pub login_burst: u32,
    pub login_refill: Duration,
    pub register_burst: u32,
    pub register_refill: Duration,
    /// Per authenticated user, not per address: an address can be rotated at
    /// will and an account cannot, and this is what bounds guessing at
    /// fingerprints. Hiding who has an account is not its job;
    /// `resolve_by_fingerprint` does that on its own.
    pub lookup_burst: u32,
    pub lookup_refill: Duration,
    /// Also per authenticated user. A passphrase change verifies one Argon2
    /// hash and computes another, and holds the write lock while it rewrites
    /// every owner key, which makes it the most expensive thing an account can
    /// ask for. The verify is also an online guess at the current passphrase,
    /// so it must not be unbounded.
    pub password_burst: u32,
    pub password_refill: Duration,
    /// Per authenticated user, because the ceiling exists to stop one account
    /// driving unbounded outbound requests to Google. An address-keyed bucket
    /// would miss that: an account can rotate addresses, and several accounts
    /// behind one NAT would share a budget none of them spent.
    pub link_burst: u32,
    pub link_refill: Duration,
}

impl Default for RateLimits {
    /// Logins: a burst of 10, then one every 6 seconds. Registrations: a
    /// burst of 5, then one per minute. Lookups: a burst of 30, then one
    /// every 3 seconds. Sharing with one person spends three: the lookup
    /// that shows their fingerprint, the re-lookup that confirms the key
    /// they approved, and the invite itself. Still far more than sharing
    /// needs and far less than walking a list of addresses needs.
    fn default() -> Self {
        Self {
            login_burst: 10,
            login_refill: Duration::from_secs(6),
            register_burst: 5,
            register_refill: Duration::from_secs(60),
            lookup_burst: 30,
            lookup_refill: Duration::from_secs(3),
            // Changing a passphrase is a thing a person does rarely and
            // deliberately; five in a row is already generous.
            password_burst: 5,
            password_refill: Duration::from_secs(60),
            link_burst: 5,
            link_refill: Duration::from_secs(60),
        }
    }
}

/// Who may create accounts.
#[derive(Clone, Default)]
pub enum RegistrationPolicy {
    /// Anyone who can reach the server. Fine on loopback; not for a public host.
    #[default]
    Open,
    /// Nobody; existing accounts keep working.
    Closed,
    /// Only requests that present this token.
    Token(String),
}

#[derive(Clone, Default)]
pub struct ServerConfig {
    pub registration: RegistrationPolicy,
    /// Believe the rightmost `X-Forwarded-For` entry when rate limiting. Only
    /// enable behind a reverse proxy that overwrites the header.
    pub trust_forwarded_for: bool,
    pub rate_limits: RateLimits,
    /// Sign in with Google, when the operator has configured a client id and
    /// secret. `None` leaves the OAuth endpoints answering 404 and the
    /// capabilities endpoint reporting that the button should not be shown.
    pub oauth: Option<Arc<dyn OAuthProvider>>,
}

impl ServerConfig {
    /// The configured provider, or a 404 explaining that this server does not
    /// offer Google sign-in. Handlers call this rather than unwrapping.
    pub fn require_oauth(&self) -> Result<&Arc<dyn OAuthProvider>, error::ApiError> {
        self.oauth
            .as_ref()
            .ok_or_else(|| error::ApiError::NotFound("google sign-in is not enabled on this server".into()))
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<ServerConfig>,
    /// Throttles the email directory per caller. Handlers take a token from it
    /// rather than a middleware, because the caller is only known after the
    /// session has been resolved.
    pub lookup_limiter: Arc<RateLimiter<i64>>,
    /// Throttles passphrase changes per account. In the handler rather than a
    /// middleware for the same reason as the lookup: the caller is only known
    /// once the session has been resolved.
    pub password_limiter: Arc<RateLimiter<i64>>,
    /// Throttles Google links per account, bounding the outbound requests one
    /// account can make the server perform.
    pub link_limiter: Arc<RateLimiter<i64>>,
}

/// Open (creating if needed) the SQLite database and apply migrations.
pub async fn connect(database_path: &Path) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(database_path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new().max_connections(8).connect_with(options).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Build the application. Serve it with
/// `app.into_make_service_with_connect_info::<SocketAddr>()`: the rate
/// limiter needs the peer address and fails every limited request without it.
pub fn build_router(pool: SqlitePool, config: ServerConfig) -> Router {
    // Pay for the timing-equalisation hash now rather than on the first login.
    auth::dummy_hash();

    let limits = config.rate_limits.clone();
    let limit_for = |burst, refill| AuthLimit {
        limiter: Arc::new(RateLimiter::new(burst, refill)),
        trust_forwarded_for: config.trust_forwarded_for,
    };
    let login_limit = limit_for(limits.login_burst, limits.login_refill);
    let register_limit = limit_for(limits.register_burst, limits.register_refill);
    // Separate buckets: starting a sign-in and completing one are different
    // costs, and one must not exhaust the other's allowance.
    let oauth_start_limit = limit_for(limits.login_burst, limits.login_refill);
    let oauth_callback_limit = limit_for(limits.login_burst, limits.login_refill);
    let oauth_register_limit = limit_for(limits.register_burst, limits.register_refill);
    // An address bucket in front of the link route, to absorb floods before a
    // session is even resolved. The ceiling that actually bounds what one
    // account can make the server fetch from Google is per-user and lives in
    // the handler; see `AppState::link_limiter`.
    let oauth_link_limit = limit_for(limits.login_burst, limits.login_refill);
    let lookup_limiter = Arc::new(RateLimiter::new(limits.lookup_burst, limits.lookup_refill));
    let password_limiter = Arc::new(RateLimiter::new(limits.password_burst, limits.password_refill));
    let link_limiter = Arc::new(RateLimiter::new(limits.link_burst, limits.link_refill));

    let api = Router::new()
        .route(
            "/register",
            post(handlers::register).layer(middleware::from_fn_with_state(register_limit, ratelimit::limit)),
        )
        .route("/login", post(handlers::login).layer(middleware::from_fn_with_state(login_limit, ratelimit::limit)))
        .route("/capabilities", get(handlers::capabilities))
        .route(
            "/oauth/start",
            post(handlers::oauth_start).layer(middleware::from_fn_with_state(oauth_start_limit, ratelimit::limit)),
        )
        .route(
            "/oauth/callback",
            post(handlers::oauth_callback)
                .layer(middleware::from_fn_with_state(oauth_callback_limit, ratelimit::limit)),
        )
        .route(
            "/oauth/register",
            post(handlers::oauth_register)
                .layer(middleware::from_fn_with_state(oauth_register_limit, ratelimit::limit)),
        )
        .route(
            "/oauth/link",
            post(handlers::oauth_link).layer(middleware::from_fn_with_state(oauth_link_limit, ratelimit::limit)),
        )
        .route("/logout", post(handlers::logout))
        .route("/sessions", delete(handlers::logout_everywhere))
        .route("/me", get(handlers::me))
        .route("/password", post(handlers::change_password))
        .route("/users/lookup", get(handlers::lookup_user))
        .route("/secrets", get(handlers::list_secrets).post(handlers::create_secret))
        .route("/secrets/keys", get(handlers::list_secret_keys))
        .route("/secrets/{id}", get(handlers::get_secret).put(handlers::update_secret).delete(handlers::delete_secret))
        .route("/secrets/{id}/access", get(handlers::secret_access))
        .route("/secrets/{id}/access/{user_id}/revoke", post(handlers::revoke_access))
        .route("/secrets/{id}/invites", post(handlers::create_invite))
        .route("/secrets/{id}/invites/{invite_id}", delete(handlers::cancel_invite))
        .route("/invites", get(handlers::list_invites))
        .route("/invites/{id}/accept", post(handlers::accept_invite))
        .route("/invites/{id}/decline", post(handlers::decline_invite));

    Router::new()
        .route("/health", get(handlers::health))
        .nest("/api", api)
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState { pool, config: Arc::new(config), lookup_limiter, password_limiter, link_limiter })
}

/// Convenience for callers that want the connect-info service type spelled out.
pub type MakeService = axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, SocketAddr>;

pub fn into_service(app: Router) -> MakeService {
    app.into_make_service_with_connect_info::<SocketAddr>()
}
