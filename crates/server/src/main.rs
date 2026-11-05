use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use std::sync::Arc;

use clap::Parser;
use credvault_server::oauth::{GoogleConfig, GoogleProvider};
use credvault_server::{RateLimits, RegistrationPolicy, ServerConfig};
use zeroize::Zeroizing;

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

    /// Google OAuth client id. Setting it, with the matching secret, enables
    /// "Sign in with Google". The client must be of type "Desktop app": the
    /// app listens on a loopback port the OS picks, and only that client type
    /// accepts a redirect URI whose port is not registered in advance.
    #[arg(long, env = "CREDVAULT_GOOGLE_CLIENT_ID", requires = "google_client_secret")]
    google_client_id: Option<String>,

    /// Google OAuth client secret. Kept on the server so it is never shipped
    /// inside the desktop app.
    #[arg(long, env = "CREDVAULT_GOOGLE_CLIENT_SECRET", requires = "google_client_id", hide_env_values = true)]
    google_client_secret: Option<String>,
}

/// Build the Google provider when both halves of the credential are present.
///
/// A blank value counts as absent: `docker compose` turns an unset variable
/// into an empty environment variable, which clap otherwise reports as a value
/// and would enable sign-in with an empty client id. Half a credential is a
/// configuration mistake worth stopping for, rather than quietly running
/// without the button the operator meant to switch on.
fn google_provider(
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Result<Option<Arc<GoogleProvider>>, Box<dyn std::error::Error>> {
    let present = |value: Option<String>| value.filter(|text| !text.trim().is_empty());
    match (present(client_id), present(client_secret)) {
        (Some(id), Some(secret)) => {
            let provider = GoogleProvider::new(GoogleConfig::new(id, Zeroizing::new(secret)))?;
            Ok(Some(Arc::new(provider)))
        }
        (None, None) => Ok(None),
        _ => Err("google sign-in needs both a client id and a client secret".into()),
    }
}

/// Flags whose environment variable is set but empty.
///
/// `docker compose` turns an unset variable into an empty one, and clap reads
/// an empty value for a `bool` flag as a value that is missing rather than as
/// a flag that is off — so the server refuses to start. A blank value means
/// "not set", the same way it does for the Google credentials.
const BLANK_MEANS_UNSET: [&str; 2] = ["CREDVAULT_CLOSED_REGISTRATION", "CREDVAULT_TRUST_FORWARDED_FOR"];

fn clear_blank_flag_env() {
    for key in BLANK_MEANS_UNSET {
        if std::env::var(key).is_ok_and(|value| value.trim().is_empty()) {
            std::env::remove_var(key);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    clear_blank_flag_env();
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
    let oauth = google_provider(args.google_client_id, args.google_client_secret)?;
    tracing::info!(google_sign_in = oauth.is_some(), "authentication methods");
    let config = ServerConfig {
        registration,
        trust_forwarded_for: args.trust_forwarded_for,
        rate_limits: RateLimits::default(),
        oauth: oauth.map(|provider| provider as Arc<dyn credvault_server::oauth::OAuthProvider>),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutates process environment, so it is one test rather than several:
    /// the others in this file read no environment at all.
    #[test]
    fn a_blank_flag_variable_counts_as_unset_rather_than_stopping_the_server() {
        for key in BLANK_MEANS_UNSET {
            std::env::set_var(key, "");
            clear_blank_flag_env();
            assert!(std::env::var(key).is_err(), "{key} blank should be removed");

            std::env::set_var(key, "   ");
            clear_blank_flag_env();
            assert!(std::env::var(key).is_err(), "{key} whitespace should be removed");

            // A real value is left alone, and so is a variable nobody set.
            std::env::set_var(key, "true");
            clear_blank_flag_env();
            assert_eq!(std::env::var(key).unwrap(), "true");
            std::env::remove_var(key);
            clear_blank_flag_env();
            assert!(std::env::var(key).is_err());
        }
    }

    #[test]
    fn google_sign_in_is_off_unless_both_halves_are_really_set() {
        assert!(google_provider(None, None).unwrap().is_none());
        // Compose writes an unset variable as an empty one; that is not config.
        assert!(google_provider(Some(String::new()), Some(String::new())).unwrap().is_none());
        assert!(google_provider(Some("  ".into()), Some("\t".into())).unwrap().is_none());
        assert!(google_provider(Some("id".into()), Some("secret".into())).unwrap().is_some());
    }

    #[test]
    fn half_a_credential_stops_the_server() {
        for (id, secret) in [
            (Some("id".to_string()), None),
            (None, Some("secret".to_string())),
            (Some("id".to_string()), Some("  ".to_string())),
        ] {
            assert!(google_provider(id, secret).is_err());
        }
    }
}
