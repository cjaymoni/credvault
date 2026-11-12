use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use std::sync::Arc;

use clap::Parser;
use credvault_core::api::{check_opaque_oauth_value, NotAnOpaqueValue, MAX_OPAQUE_VALUE_LEN};

/// How much of a rejected client id the startup error quotes back. Enough
/// to recognise the value by, short enough that a huge variable cannot be
/// printed in full.
const ECHOED_PREFIX_LEN: usize = 80;
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
    // Trimmed, not merely tested for whitespace: a value out of a .env file or
    // a compose file routinely arrives with a trailing newline, and neither of
    // these credentials can legitimately begin or end with whitespace.
    let present = |value: Option<String>| value.map(|text| text.trim().to_string()).filter(|text| !text.is_empty());
    match (present(client_id), present(client_secret)) {
        (Some(id), Some(secret)) => {
            // The client id is handed to the app and goes straight into an
            // authorization URL, where the app refuses anything outside the
            // set `check_opaque_oauth_value` names -- with a sentence telling
            // the user not to trust this server with their Google password.
            // A stray character in the configuration would otherwise produce
            // that accusation on every sign-in, aimed at the operator's own
            // server, with nothing at startup having said so. The other three
            // values in that response are generated here and pinned by
            // `generated_values_satisfy_the_contract_the_client_enforces`;
            // this is the one that comes from outside.
            // The reason is kept rather than both rules being recited, so an
            // operator with an over-long id is not also lectured about
            // punctuation.
            //
            // What is echoed back is bounded and truncated, because this line
            // is reached exactly when the value is *not* a client id: the
            // likely cause is the two Google variables being swapped, and the
            // secret one is declared `hide_env_values` precisely so it is
            // never printed. A prefix is enough to recognise a swap by.
            if let Err(reason) = check_opaque_oauth_value(&id) {
                let detail = match reason {
                    NotAnOpaqueValue::Empty => "empty".to_string(),
                    NotAnOpaqueValue::TooLong => {
                        format!(
                            "{} characters long, and at most {MAX_OPAQUE_VALUE_LEN} are allowed",
                            id.chars().count()
                        )
                    }
                    NotAnOpaqueValue::BadCharacters => {
                        let shown: String = id.chars().take(ECHOED_PREFIX_LEN).collect();
                        let ellipsis = if id.chars().count() > ECHOED_PREFIX_LEN { "..." } else { "" };
                        format!(
                            "spelled with characters a client id cannot hold; it may use only \
                             letters, digits and the marks - . _ ~, and this one begins {shown:?}{ellipsis}"
                        )
                    }
                };
                return Err(format!("CREDVAULT_GOOGLE_CLIENT_ID is {detail}").into());
            }
            // The other half never reaches a URL, so it is not held to the same
            // set — but an invisible character inside it is a copy-paste
            // artefact that no Google secret has, and leaving it produces a
            // sign-in that fails at the token exchange saying only that it
            // could not be completed. Same reasoning as the id: fail where an
            // operator is reading. The value is never quoted back.
            //
            // An allow-list rather than a deny-list of whitespace and control
            // characters, because the artefacts most worth catching are in
            // neither Unicode category: a BOM out of a Windows-authored .env
            // is not `White_Space`, so `trim` leaves it too, and a zero-width
            // space is not `Cc`. Printable ASCII covers `GOCSPX-` plus
            // base64url with nothing to reason about.
            if !secret.chars().all(|c| c.is_ascii_graphic()) {
                return Err("CREDVAULT_GOOGLE_CLIENT_SECRET holds a character no Google client secret \
                            does — it is printable ASCII throughout"
                    .into());
            }
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

/// Which registrations the server accepts, from the two flags that decide it.
///
/// A blank token counts as no token, the same way a blank Google credential
/// counts as none: `docker compose` turns an unset variable into an empty one
/// and clap reports that as a value. Taken literally it would build a gate
/// whose key is the empty string -- and no client can present that, because
/// an empty field is sent as `null` and the policy refuses a missing token
/// outright. The operator would have shut registration rather than opened it,
/// and the server would look healthy while doing it.
///
/// Closed wins over a token: clap already refuses both at once, and the
/// stricter of the two is the safe way to read a combination that got past it.
fn registration_policy(closed: bool, token: Option<String>) -> RegistrationPolicy {
    if closed {
        return RegistrationPolicy::Closed;
    }
    // Trimmed for the same reason the Google credential is: a value out of a
    // .env file routinely arrives with a trailing newline, and a token cannot
    // legitimately begin or end with whitespace -- the client trims the field
    // before sending it, so such a token could never be presented intact.
    match token.map(|text| text.trim().to_string()).filter(|text| !text.is_empty()) {
        Some(token) => RegistrationPolicy::Token(token),
        None => RegistrationPolicy::Open,
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

    let registration = registration_policy(args.closed_registration, args.registration_token);
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
    fn a_blank_registration_token_opens_registration_rather_than_sealing_it() {
        // The shapes compose and a .env file produce for "I did not set this".
        for blank in [Some(String::new()), Some("   ".to_string()), Some("\n".to_string()), None] {
            assert!(
                matches!(registration_policy(false, blank.clone()), RegistrationPolicy::Open),
                "{blank:?} must leave registration open, not gate it behind a token nobody can send",
            );
        }
    }

    #[test]
    fn a_real_token_gates_registration_and_keeps_its_own_value() {
        let gated = registration_policy(false, Some("s3cret".into()));
        assert!(matches!(&gated, RegistrationPolicy::Token(token) if token == "s3cret"));
        // A .env file's trailing newline is not part of the token: the client
        // trims the field, so a token carrying one could never be matched.
        let trimmed = registration_policy(false, Some("  s3cret\n".into()));
        assert!(matches!(&trimmed, RegistrationPolicy::Token(token) if token == "s3cret"));
    }

    #[test]
    fn closed_registration_wins_over_a_token() {
        assert!(matches!(registration_policy(true, None), RegistrationPolicy::Closed));
        assert!(matches!(registration_policy(true, Some("s3cret".into())), RegistrationPolicy::Closed));
    }

    #[test]
    fn google_sign_in_is_off_unless_both_halves_are_really_set() {
        assert!(google_provider(None, None).unwrap().is_none());
        // Compose writes an unset variable as an empty one; that is not config.
        assert!(google_provider(Some(String::new()), Some(String::new())).unwrap().is_none());
        assert!(google_provider(Some("  ".into()), Some("\t".into())).unwrap().is_none());
        assert!(google_provider(Some("id".into()), Some("secret".into())).unwrap().is_some());
    }

    /// A client id the app will refuse has to stop the server, because the
    /// alternative is that it starts, looks healthy, and tells every user on
    /// every sign-in not to trust it.
    #[test]
    fn a_client_id_the_app_would_refuse_stops_the_server() {
        // The shapes a .env or compose file actually produces.
        for bad in ["id with a space", "\"quoted-id\"", "id&scope=drive", "id/../x", &"x".repeat(600)] {
            let built = google_provider(Some(bad.to_string()), Some("secret".into()));
            assert!(built.is_err(), "{bad:?} must not start the server");
            let message = built.err().unwrap().to_string();
            assert!(message.contains("CREDVAULT_GOOGLE_CLIENT_ID"), "the refusal must name the flag: {message}");
        }
        // A real one, and the same one with the newline a .env file adds,
        // which is trimmed rather than refused.
        for good in ["1234567890-abcdef.apps.googleusercontent.com", "1234567890-abcdef.apps.googleusercontent.com\n"] {
            assert!(google_provider(Some(good.to_string()), Some("secret\n".into())).unwrap().is_some(), "{good:?}");
        }
    }

    /// A secret with a newline in it reaches Google and comes back as a
    /// failed exchange the user is told nothing useful about, so it stops the
    /// server too. Unlike the id, it is never quoted back.
    #[test]
    fn a_secret_carrying_whitespace_stops_the_server_without_printing_it() {
        const SECRET: &str = "GOCSPX-wrapped\nacross-lines";
        let built = google_provider(Some("client-id".into()), Some(SECRET.to_string()));
        let message = built.err().expect("an interior newline must stop the server").to_string();
        assert!(message.contains("CREDVAULT_GOOGLE_CLIENT_SECRET"), "the refusal must name the flag: {message}");
        assert!(!message.contains("GOCSPX"), "the refusal must not quote the secret: {message}");
        // The characters a deny-list of whitespace and control categories
        // misses, and that `trim` leaves in place: a BOM from a Windows-saved
        // .env, and a zero-width space from a web console.
        for invisible in ["\u{feff}GOCSPX-fine", "GOCSPX-fi\u{200b}ne"] {
            let built = google_provider(Some("client-id".into()), Some(invisible.to_string()));
            assert!(built.is_err(), "an invisible character must stop the server: {invisible:?}");
        }

        // Surrounding whitespace is still trimmed rather than refused, which
        // is the common case and not a mistake worth stopping for.
        assert!(google_provider(Some("client-id".into()), Some("  GOCSPX-fine\n".into())).unwrap().is_some());
    }

    /// The rejected id is quoted back so a swap of the two Google variables is
    /// recognisable, which means it has to be bounded: this line is reached
    /// precisely when the value is not what it claims to be.
    #[test]
    fn a_rejected_client_id_is_quoted_back_but_not_in_full() {
        let huge = format!("{}!", "a".repeat(5_000));
        let message = google_provider(Some(huge), Some("secret".into())).err().unwrap().to_string();
        assert!(message.len() < 400, "a huge variable must not be printed in full: {} chars", message.len());
        assert!(message.contains("aaa"), "enough must be shown to recognise the value: {message}");
        assert!(message.ends_with("\"..."), "a truncated value must say so: {message}");
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
