//! credvault sync server: accounts, encrypted secrets, and sharing invites.

pub use credvault_core::api;
pub mod auth;
pub mod error;
mod extract;
mod handlers;
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

use ratelimit::{AuthLimit, RateLimiter};

/// Largest request body the server accepts; blobs are capped lower in handlers.
const MAX_REQUEST_BYTES: usize = 256 * 1024;

/// Per-client-address token buckets for the unauthenticated endpoints.
#[derive(Clone, Debug)]
pub struct RateLimits {
    pub login_burst: u32,
    pub login_refill: Duration,
    pub register_burst: u32,
    pub register_refill: Duration,
}

impl Default for RateLimits {
    /// Logins: a burst of 10, then one every 6 seconds. Registrations: a
    /// burst of 5, then one per minute.
    fn default() -> Self {
        Self {
            login_burst: 10,
            login_refill: Duration::from_secs(6),
            register_burst: 5,
            register_refill: Duration::from_secs(60),
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
}

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<ServerConfig>,
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

    let limit_for = |burst, refill| AuthLimit {
        limiter: Arc::new(RateLimiter::new(burst, refill)),
        trust_forwarded_for: config.trust_forwarded_for,
    };
    let limits = &config.rate_limits;
    let login_limit = limit_for(limits.login_burst, limits.login_refill);
    let register_limit = limit_for(limits.register_burst, limits.register_refill);

    let api = Router::new()
        .route(
            "/register",
            post(handlers::register).layer(middleware::from_fn_with_state(register_limit, ratelimit::limit)),
        )
        .route("/login", post(handlers::login).layer(middleware::from_fn_with_state(login_limit, ratelimit::limit)))
        .route("/logout", post(handlers::logout))
        .route("/sessions", delete(handlers::logout_everywhere))
        .route("/me", get(handlers::me))
        .route("/users/lookup", get(handlers::lookup_user))
        .route("/secrets", get(handlers::list_secrets).post(handlers::create_secret))
        .route("/secrets/{id}", get(handlers::get_secret).put(handlers::update_secret).delete(handlers::delete_secret))
        .route("/secrets/{id}/owner-key", axum::routing::put(handlers::upgrade_owner_key))
        .route("/secrets/{id}/access", get(handlers::secret_access))
        .route("/secrets/{id}/access/{user_id}/revoke", post(handlers::revoke_access))
        .route("/secrets/{id}/invites", post(handlers::create_invite))
        .route("/secrets/{id}/invites/{invite_id}", delete(handlers::cancel_invite))
        .route("/invites", get(handlers::list_invites))
        .route("/invites/{id}/accept", post(handlers::accept_invite))
        .route("/invites/{id}/decline", post(handlers::decline_invite));

    Router::new()
        .route("/health", get(|| async { "ok" }))
        .nest("/api", api)
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState { pool, config: Arc::new(config) })
}

/// Convenience for callers that want the connect-info service type spelled out.
pub type MakeService = axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, SocketAddr>;

pub fn into_service(app: Router) -> MakeService {
    app.into_make_service_with_connect_info::<SocketAddr>()
}
