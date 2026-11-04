use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::Parser;
use credvault_server::{RateLimits, RegistrationPolicy, ServerConfig};

/// credvault sync server. Stores only ciphertext; run it anywhere you trust
/// to keep data, and put it behind HTTPS (a reverse proxy) for real use.
// No Debug: a derived one would print the registration token.
#[derive(Parser)]
#[command(name = "credvault-server", version)]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "CREDVAULT_BIND", default_value = "127.0.0.1:8787")]
    bind: SocketAddr,

    /// Directory for the SQLite database.
    #[arg(long, env = "CREDVAULT_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Require this token to create an account (clients send it as
    /// `registration_token`). Recommended for any server reachable by others.
    #[arg(long, env = "CREDVAULT_REGISTRATION_TOKEN", conflicts_with = "closed_registration", hide_env_values = true)]
    registration_token: Option<String>,

    /// Refuse all new registrations; existing accounts keep working.
    #[arg(long, env = "CREDVAULT_CLOSED_REGISTRATION")]
    closed_registration: bool,

    /// Rate-limit by the rightmost X-Forwarded-For address instead of the peer
    /// address. Only enable behind a reverse proxy that sets that header.
    #[arg(long, env = "CREDVAULT_TRUST_FORWARDED_FOR")]
    trust_forwarded_for: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let data_dir = args
        .data_dir
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".credvault-server")))
        .ok_or("cannot determine data directory; pass --data-dir")?;
    create_private_dir(&data_dir)?;

    // The database file is created owner-only *before* SQLite opens it, so the
    // -wal and -shm files it spawns inherit that mode from the start.
    let database_path = data_dir.join("credvault.db");
    create_private_file(&database_path)?;
    let pool = credvault_server::connect(&database_path).await?;
    for suffix in ["", "-wal", "-shm"] {
        let path = data_dir.join(format!("credvault.db{suffix}"));
        if path.exists() {
            restrict_file_permissions(&path)?;
        }
    }

    let registration = if args.closed_registration {
        RegistrationPolicy::Closed
    } else if let Some(token) = args.registration_token {
        RegistrationPolicy::Token(token)
    } else {
        RegistrationPolicy::Open
    };
    if matches!(registration, RegistrationPolicy::Open) && !args.bind.ip().is_loopback() {
        tracing::warn!("registration is open on a non-loopback address; consider --registration-token");
    }
    let config = ServerConfig {
        registration,
        trust_forwarded_for: args.trust_forwarded_for,
        rate_limits: RateLimits::default(),
    };

    let app = credvault_server::build_router(pool, config);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(address = %args.bind, data_dir = %data_dir.display(), "credvault-server listening");
    axum::serve(listener, credvault_server::into_service(app)).await?;
    Ok(())
}

/// The data directory holds credential hashes and all ciphertext, so it must
/// not be readable by other local users. An existing directory is tightened
/// too, since `DirBuilder` only sets the mode on directories it creates.
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// Create the database file empty and owner-only if it does not exist yet.
fn create_private_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(path).map(|_| ())
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(path).map(|_| ())
    }
}

/// SQLite creates `-wal` and `-shm` files with the same mode as the database
/// file, so restricting the database file covers all three.
fn restrict_file_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}
