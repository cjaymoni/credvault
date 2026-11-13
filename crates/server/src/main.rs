use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use std::sync::Arc;

use clap::Parser;
use klavyn_core::api::{check_opaque_oauth_value, NotAnOpaqueValue, MAX_OPAQUE_VALUE_LEN};

/// How much of a rejected client id the startup error quotes back. Enough
/// to recognise the value by, short enough that a huge variable cannot be
/// printed in full.
const ECHOED_PREFIX_LEN: usize = 80;
use klavyn_server::analytics::Analytics;
use klavyn_server::oauth::{GoogleConfig, GoogleProvider};
use klavyn_server::{RateLimits, RegistrationPolicy, ServerConfig};
use zeroize::Zeroizing;

/// klavyn sync server. Stores only ciphertext; run it anywhere you trust
/// to keep data, and put it behind HTTPS (a reverse proxy) for real use.
// No Debug: a derived one would print the registration token.
#[derive(Parser)]
#[command(name = "klavyn-server", version)]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "KLAVYN_BIND", default_value = "127.0.0.1:8787")]
    bind: SocketAddr,

    /// Directory for the SQLite database.
    #[arg(long, env = "KLAVYN_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Require this token to create an account (clients send it as
    /// `registration_token`). Recommended for any server reachable by others.
    #[arg(long, env = "KLAVYN_REGISTRATION_TOKEN", conflicts_with = "closed_registration", hide_env_values = true)]
    registration_token: Option<String>,

    /// Refuse all new registrations; existing accounts keep working.
    #[arg(long, env = "KLAVYN_CLOSED_REGISTRATION")]
    closed_registration: bool,

    /// Rate-limit by the rightmost X-Forwarded-For address instead of the peer
    /// address. Only enable behind a reverse proxy that sets that header.
    #[arg(long, env = "KLAVYN_TRUST_FORWARDED_FOR")]
    trust_forwarded_for: bool,

    /// Google OAuth client id. Setting it, with the matching secret, enables
    /// "Sign in with Google". The client must be of type "Desktop app": the
    /// app listens on a loopback port the OS picks, and only that client type
    /// accepts a redirect URI whose port is not registered in advance.
    #[arg(long, env = "KLAVYN_GOOGLE_CLIENT_ID", requires = "google_client_secret")]
    google_client_id: Option<String>,

    /// Google OAuth client secret. Kept on the server so it is never shipped
    /// inside the desktop app.
    #[arg(long, env = "KLAVYN_GOOGLE_CLIENT_SECRET", requires = "google_client_id", hide_env_values = true)]
    google_client_secret: Option<String>,

    /// PostHog project API key. Setting it switches on anonymous reach
    /// telemetry: one event per app that asks this server what it supports,
    /// carrying a platform, an app version, a country, and an id that stops
    /// being derivable when the day rolls over. No account, no address, and
    /// nothing from anybody's vault -- `klavyn_server::analytics` is the
    /// whole of it. Unset, which is the default, means no outbound request is
    /// ever made.
    ///
    /// This is a *project* key, meant to be shipped to clients by design, not
    /// a personal API key. It is still declared hidden so an operator who
    /// pastes the wrong one does not find it in a startup log.
    #[arg(long, env = "KLAVYN_POSTHOG_API_KEY", hide_env_values = true)]
    posthog_api_key: Option<String>,

    /// Where to send that telemetry. Defaults to PostHog's EU cloud; set it to
    /// `https://us.i.posthog.com` for the US region, or to your own address
    /// for a self-hosted PostHog. Ignored without a key.
    #[arg(long, env = "KLAVYN_POSTHOG_HOST", default_value = klavyn_server::analytics::DEFAULT_HOST)]
    posthog_host: String,
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
                return Err(format!("KLAVYN_GOOGLE_CLIENT_ID is {detail}").into());
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
                return Err("KLAVYN_GOOGLE_CLIENT_SECRET holds a character no Google client secret \
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

/// Settings whose environment variable is set but empty, which `docker
/// compose` produces for every variable it interpolates and the operator has
/// not filled in.
///
/// Clap reads an env-sourced empty string as a value that is *present*, and
/// that breaks two different ways. Off a `bool` flag it is a missing value and
/// the server refuses to start. Off `--registration-token` it is a present
/// value, so `conflicts_with = "closed_registration"` fires -- and the
/// documented way to close registration is to set the flag and leave the token
/// blank, which compose turns into exactly that pair. Measured against the
/// built binary: the server exited 2 with "the argument
/// '--registration-token' cannot be used with '--closed-registration'", and
/// under `restart: unless-stopped` that is a crash loop taking the whole
/// service down -- while the operator's compose reported success.
///
/// So blank means "not set" here, before clap ever looks, for every variable
/// the compose file interpolates. The trimming inside `registration_policy`
/// and `google_provider` stays as well: this handles the parse, those handle
/// a value that arrives with a stray newline.
const BLANK_MEANS_UNSET: [&str; 7] = [
    "KLAVYN_CLOSED_REGISTRATION",
    "KLAVYN_TRUST_FORWARDED_FOR",
    "KLAVYN_REGISTRATION_TOKEN",
    "KLAVYN_GOOGLE_CLIENT_ID",
    "KLAVYN_GOOGLE_CLIENT_SECRET",
    "KLAVYN_POSTHOG_API_KEY",
    // Not merely tidy: this one has a `default_value`, and an empty string
    // from compose would otherwise be a present value that overrides it --
    // the server would refuse to start over a host that is not a URL, for a
    // variable the operator never filled in.
    "KLAVYN_POSTHOG_HOST",
];

/// The two settings clap parses as `bool`, which it accepts only as exactly
/// `true` or `false`.
const BOOL_FLAGS: [&str; 2] = ["KLAVYN_CLOSED_REGISTRATION", "KLAVYN_TRUST_FORWARDED_FOR"];

/// Spellings an operator plausibly writes, and what each one means.
///
/// Anything outside this list still reaches clap, which stops the server and
/// names the variable and the values it takes. That is a stop with a reason;
/// what this table prevents is a stop over a capital letter.
///
/// `off` and `no` are deliberately absent, and the asymmetry is the point.
/// The variable is called `CLOSED_REGISTRATION`, so those two read both ways:
/// "closed-registration is off" means open, and "registration: off" means
/// closed. The truthy spellings have the same ambiguity -- `on` could be read
/// as "registration on" -- but they resolve to *closed*, which is the
/// restrictive direction and is noticed within minutes because sign-ups stop.
/// A falsey misreading resolves to open to anyone, on a public vault, silently.
/// Measured before they were removed: `KLAVYN_CLOSED_REGISTRATION=off`
/// booted and logged `registration="open to anyone"`. So they stop the server
/// instead, and the operator is asked what they meant.
const BOOLISH: [(&str, &str); 6] =
    [("true", "true"), ("yes", "true"), ("on", "true"), ("1", "true"), ("false", "false"), ("0", "false")];

/// Make the environment say what the operator meant, before clap reads it.
///
/// Two passes, both for the same reason: a value that is nearly right must not
/// take the whole server down. Blank means unset (see [`BLANK_MEANS_UNSET`]),
/// and a recognised spelling of a boolean becomes the one spelling clap takes.
///
/// Measured on the built binary before this existed: `KLAVYN_CLOSED_REGISTRATION`
/// set to `TRUE`, `True`, `1`, `yes`, or `true` with a trailing space each
/// exited 2 with "invalid value". The README tells an operator to set that
/// variable to stop new sign-ups, so a capital letter, or a line copied with a
/// space, or a `.env` edited on Windows, turned "stop new accounts" into a
/// container that crash-loops under `restart: unless-stopped` -- the sync
/// service down for every existing user, with compose reporting success.
fn normalize_env() {
    for key in BLANK_MEANS_UNSET {
        if std::env::var(key).is_ok_and(|value| value.trim().is_empty()) {
            std::env::remove_var(key);
        }
    }
    for key in BOOL_FLAGS {
        let Ok(value) = std::env::var(key) else { continue };
        let written = value.trim().to_ascii_lowercase();
        match BOOLISH.iter().find(|(spelling, _)| *spelling == written) {
            // Falsey means "this setting is not in use", which is what a blank
            // one already means, so they become the same thing. Leaving
            // `false` in the environment instead makes clap count the flag as
            // present, and `conflicts_with` then refuses it beside a
            // registration token: exit 2, and a crash loop under
            // `restart: unless-stopped`. The flag defaults to false anyway, so
            // removing it parses identically where it already worked.
            Some((_, "false")) => std::env::remove_var(key),
            Some((_, canonical)) => std::env::set_var(key, canonical),
            None => {}
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Before the runtime exists. `set_var`/`remove_var` are only sound while
    // the process is single-threaded, and `#[tokio::main]` builds a
    // multi-thread runtime -- workers and the IO driver are alive before the
    // body runs. Nothing read the environment from those threads in practice,
    // but it costs nothing to do this where it is actually defined.
    normalize_env();
    run()
}

#[tokio::main]
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let data_dir = args
        .data_dir
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".klavyn-server")))
        .ok_or("cannot determine data directory; pass --data-dir")?;
    create_private_dir(&data_dir)?;

    // The database file is created owner-only *before* SQLite opens it, so the
    // -wal and -shm files it spawns inherit that mode from the start.
    let database_path = data_dir.join("klavyn.db");
    create_private_file(&database_path)?;
    let pool = klavyn_server::connect(&database_path).await?;
    for suffix in ["", "-wal", "-shm"] {
        let path = data_dir.join(format!("klavyn.db{suffix}"));
        if path.exists() {
            restrict_file_permissions(&path)?;
        }
    }

    let registration = registration_policy(args.closed_registration, args.registration_token);
    // Said on every start whichever state it is in, at info, next to the
    // address. A line that only appears when something is wrong is a line an
    // operator cannot use to confirm that nothing is: "is this host open?"
    // has to be answerable by reading, not by failing to find a warning.
    tracing::info!(registration = registration.describe(), address = %args.bind, "registration policy");
    if matches!(registration, RegistrationPolicy::Open) && !args.bind.ip().is_loopback() {
        tracing::warn!("registration is open on a non-loopback address; consider --registration-token");
    }
    let oauth = google_provider(args.google_client_id, args.google_client_secret)?;
    tracing::info!(google_sign_in = oauth.is_some(), "authentication methods");

    // Said at info on every start, in both states, for the same reason the
    // registration policy is: whether a server is reporting anything is a
    // question an operator must be able to answer by reading a log line,
    // not by failing to find one.
    let analytics = match args.posthog_api_key.map(|key| key.trim().to_string()).filter(|key| !key.is_empty()) {
        Some(key) => {
            let started = Analytics::start(key, &args.posthog_host)?;
            tracing::info!(host = %args.posthog_host, "anonymous reach telemetry is on");
            if !args.trust_forwarded_for {
                // Country comes from a header only a proxy may be believed
                // about. Without --trust-forwarded-for the events still go,
                // and every one of them has no country -- which looks like
                // PostHog being broken rather than like a setting being off.
                tracing::warn!(
                    "telemetry is on without --trust-forwarded-for, so no event will carry a country; \
                     set that flag if a reverse proxy sets CF-IPCountry"
                );
            }
            Some(started)
        }
        None => {
            tracing::info!("anonymous reach telemetry is off");
            None
        }
    };

    let config = ServerConfig {
        registration,
        trust_forwarded_for: args.trust_forwarded_for,
        rate_limits: RateLimits::default(),
        oauth: oauth.map(|provider| provider as Arc<dyn klavyn_server::oauth::OAuthProvider>),
        analytics,
    };

    let app = klavyn_server::build_router(pool, config);
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!(address = %args.bind, data_dir = %data_dir.display(), "klavyn-server listening");
    axum::serve(listener, klavyn_server::into_service(app)).await?;
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

    /// One deterministic pseudo-random number, so a failure is reproducible
    /// from the seed rather than only on the run that found it.
    fn next_number(state: &mut u64) -> usize {
        *state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        (*state >> 33) as usize
    }

    /// Words an operator could plausibly write in a boolean setting, and the
    /// junk around them.
    ///
    /// Words rather than random characters, because the first version of this
    /// drew 0-6 characters from a 45-character bag and the arithmetic is
    /// brutal: reaching a three-letter target costs about one draw in 23,000,
    /// so 5000 pairs produced `off` -- the exact spelling of the last shipped
    /// fail-open -- zero times. A generator that cannot reach the defect it
    /// was written for is worse than no generator, because it reads like
    /// coverage. The near-miss set is where all four shipped defects lived,
    /// so it is sampled deliberately rather than hoped for.
    const WORDS: [&str; 20] = [
        "", "true", "false", "yes", "no", "on", "off", "0", "1", "y", "n", "t", "f", "enabled", "disabled", "closed",
        "open", "none", "null", "maybe",
    ];

    /// One of those words, wearing the damage a `.env` file does to it: the
    /// capitalisation someone types, the trailing newline an editor leaves,
    /// the CR from a file written on Windows, the quotes someone adds because
    /// other lines have them.
    fn generated_value(state: &mut u64) -> String {
        let word = WORDS[next_number(state) % WORDS.len()];
        let cased = match next_number(state) % 4 {
            0 => word.to_string(),
            1 => word.to_ascii_uppercase(),
            2 => {
                let mut chars = word.chars();
                chars.next().map(|c| c.to_ascii_uppercase().to_string() + chars.as_str()).unwrap_or_default()
            }
            _ => word.to_string(),
        };
        match next_number(state) % 6 {
            0 => format!("{cased} "),
            1 => format!("{cased}\n"),
            2 => format!("{cased}\r\n"),
            3 => format!(" {cased}"),
            4 => format!("\"{cased}\""),
            _ => cased,
        }
    }

    /// Mutates process environment, so it is one test rather than several:
    /// the others in this file read no environment at all.
    #[test]
    fn a_blank_flag_variable_counts_as_unset_rather_than_stopping_the_server() {
        for key in BLANK_MEANS_UNSET {
            std::env::set_var(key, "");
            normalize_env();
            assert!(std::env::var(key).is_err(), "{key} blank should be removed");

            std::env::set_var(key, "   ");
            normalize_env();
            assert!(std::env::var(key).is_err(), "{key} whitespace should be removed");

            // A real value is left alone, and so is a variable nobody set.
            std::env::set_var(key, "true");
            normalize_env();
            assert_eq!(std::env::var(key).unwrap(), "true");
            std::env::remove_var(key);
            normalize_env();
            assert!(std::env::var(key).is_err());
        }

        // The three states the deploy guide documents, spelled the way
        // `docker compose` actually spells them: every interpolated variable
        // present, the unfilled ones empty rather than absent. The previous
        // version of this file passed every test while the third of these
        // exited 2 at startup, because nothing exercised the parse.
        for (closed, token, expected) in
            [("", "abc123", "token required"), ("", "", "open to anyone"), ("true", "", "closed")]
        {
            std::env::set_var("KLAVYN_CLOSED_REGISTRATION", closed);
            std::env::set_var("KLAVYN_REGISTRATION_TOKEN", token);
            normalize_env();
            let args = Args::try_parse_from(["klavyn-server"]).unwrap_or_else(|e| {
                panic!("compose produces CLOSED={closed:?} TOKEN={token:?}; clap must take it: {e}")
            });
            let policy = registration_policy(args.closed_registration, args.registration_token);
            assert_eq!(policy.describe(), expected, "CLOSED={closed:?} TOKEN={token:?}");
        }

        // Spellings of the documented value that an operator plausibly types.
        // Each of these used to exit 2, which under `restart: unless-stopped`
        // is a crash loop reached by capitalising a word.
        for written in ["true", "TRUE", "True", "1", "yes", "on", "true ", "true\n"] {
            std::env::set_var("KLAVYN_CLOSED_REGISTRATION", written);
            std::env::set_var("KLAVYN_REGISTRATION_TOKEN", "");
            normalize_env();
            let args = Args::try_parse_from(["klavyn-server"])
                .unwrap_or_else(|e| panic!("CLOSED={written:?} must not stop the server: {e}"));
            let policy = registration_policy(args.closed_registration, args.registration_token);
            assert_eq!(policy.describe(), "closed", "CLOSED={written:?}");
        }

        // The falsey half, which had no test while it was the half that could
        // open a vault. A token alongside it must still mean "token
        // required" rather than the exit 2 that a present-but-false flag used
        // to produce.
        for written in ["false", "FALSE", "0", "false "] {
            for (token, expected) in [("", "open to anyone"), ("abc123", "token required")] {
                std::env::set_var("KLAVYN_CLOSED_REGISTRATION", written);
                std::env::set_var("KLAVYN_REGISTRATION_TOKEN", token);
                normalize_env();
                let args = Args::try_parse_from(["klavyn-server"])
                    .unwrap_or_else(|e| panic!("CLOSED={written:?} TOKEN={token:?} must not stop the server: {e}"));
                let policy = registration_policy(args.closed_registration, args.registration_token);
                assert_eq!(policy.describe(), expected, "CLOSED={written:?} TOKEN={token:?}");
            }
        }

        // Spellings that read both ways on a variable called CLOSED_REGISTRATION
        // must stop the server rather than pick one. Getting this wrong opens a
        // vault silently; see BOOLISH.
        for ambiguous in ["off", "no", "maybe"] {
            std::env::set_var("KLAVYN_CLOSED_REGISTRATION", ambiguous);
            std::env::set_var("KLAVYN_REGISTRATION_TOKEN", "");
            normalize_env();
            assert!(Args::try_parse_from(["klavyn-server"]).is_err(), "{ambiguous:?} must stop the server");
        }

        // Asking for both at once is still refused rather than guessed at.
        std::env::set_var("KLAVYN_CLOSED_REGISTRATION", "true");
        std::env::set_var("KLAVYN_REGISTRATION_TOKEN", "abc123");
        normalize_env();
        assert!(Args::try_parse_from(["klavyn-server"]).is_err(), "a token and closed together must be refused");

        // Everything above this point is a list of values somebody chose, and
        // four times running the defect was in a value nobody chose: `off`
        // booted a public vault open to anyone while eight truthy spellings
        // had tests, because the half that was tested was not the half that
        // could do harm. Hand-picked cases only catch what the author already
        // suspected.
        //
        // So state the rule instead of the cases, and check it against pairs
        // nobody chose. Two things must hold, because this setting has failed
        // in two directions:
        //
        //   open   -- the server is open to anyone only where the operator
        //             wrote nothing, or a spelling that means "not in use".
        //   boots  -- a spelling the deploy guide tells an operator to write
        //             never stops the server. A refusal is a fine answer to
        //             nonsense, but under `restart: unless-stopped` it is a
        //             crash loop, so it must not be the answer to `TRUE`.
        //
        // Checking only the first would let the fixes for it keep producing
        // the second, which is exactly what happened twice.
        // Parsed strictly. Falling back to the default on a malformed seed
        // reports a pass for a run nobody asked for, and the literal below is
        // written in hex, so `KLAVYN_FUZZ_SEED=0x5EED0000001` is the first
        // thing someone reproducing a failure would reach for.
        let seed_used = match std::env::var("KLAVYN_FUZZ_SEED") {
            Ok(written) => {
                let digits = written.trim().replace('_', "");
                let parsed = match digits.strip_prefix("0x") {
                    Some(hex) => u64::from_str_radix(hex, 16),
                    None => digits.parse(),
                };
                parsed.unwrap_or_else(|_| panic!("KLAVYN_FUZZ_SEED={written:?} is not a u64"))
            }
            Err(_) => 0x5EED_0000_0001_u64,
        };
        let mut seed = seed_used;
        for _ in 0..5_000 {
            let closed = generated_value(&mut seed);
            // Empty about half the time on purpose. Drawn from the same word
            // bag as `closed`, a token is non-empty ~96% of runs, and a
            // non-empty token makes the pair either a `conflicts_with`
            // refusal or a Token policy -- neither of which can tell a correct
            // implementation from a broken one. Both assertions below can only
            // discriminate on a blank token, so "5000 pairs" was overselling
            // the reach by two orders of magnitude.
            let token =
                if next_number(&mut seed).is_multiple_of(2) { String::new() } else { generated_value(&mut seed) };
            std::env::set_var("KLAVYN_CLOSED_REGISTRATION", &closed);
            std::env::set_var("KLAVYN_REGISTRATION_TOKEN", &token);
            normalize_env();

            // Spelled out here rather than read from BOOLISH on purpose. An
            // oracle that derives the answer from the code it is judging
            // widens when that code widens, which is exactly the route `off`
            // would take back in under a green suite.
            let written = closed.trim().to_ascii_lowercase();
            let documented_truthy = matches!(written.as_str(), "true" | "yes" | "on" | "1");
            let documented_falsey = matches!(written.as_str(), "" | "false" | "0");
            let token_written = token.trim().to_string();

            let Ok(args) = Args::try_parse_from(["klavyn-server"]) else {
                // Asking for a token and closed at once is refused on purpose.
                assert!(
                    !((documented_truthy || documented_falsey) && token_written.is_empty()),
                    "a documented spelling stopped the server, which under \
                     `restart: unless-stopped` is a crash loop: CLOSED={closed:?} \
                     TOKEN={token:?} (seed {seed_used})"
                );
                continue;
            };
            let policy = registration_policy(args.closed_registration, args.registration_token);
            if matches!(policy, RegistrationPolicy::Open) {
                assert!(
                    documented_falsey && token_written.is_empty(),
                    "registration opened on input nobody asked to open: \
                     CLOSED={closed:?} TOKEN={token:?} (seed {seed_used})"
                );
            }
        }

        std::env::remove_var("KLAVYN_CLOSED_REGISTRATION");
        std::env::remove_var("KLAVYN_REGISTRATION_TOKEN");
    }

    /// Which service each documented setting has to reach. Everything the
    /// server reads belongs to `klavyn`; the certificate pair is the
    /// proxy's.
    ///
    /// The default is the server, so a new proxy-only setting fails this test
    /// by name rather than passing unnoticed. Add it to the match arm when it
    /// does -- not to an exclusion list, which is what hid two settings here
    /// before.
    fn owning_service(name: &str) -> &'static str {
        match name {
            "KLAVYN_DOMAIN" | "KLAVYN_ACME_EMAIL" | "KLAVYN_SITE_DOMAIN" => "caddy",
            _ => "klavyn",
        }
    }

    /// The `environment:` block of one service, with comments stripped.
    ///
    /// Scoped and stripped because a plain text search over the whole file
    /// accepts three things that leave the bug reachable: the variable named
    /// in the *other* service, named only in a comment, or named on a line
    /// that is commented out.
    fn environment_of(compose: &str, service: &str) -> String {
        // Walked line by line rather than split on text. A service's body is
        // indented past its name, so any substring boundary like "\n  " also
        // matches the service's own lines; the boundary that means "the next
        // service" is a line indented exactly to the service level.
        let is_service = |line: &str| line.starts_with("  ") && !line.starts_with("   ");
        let mut lines = compose.lines().skip_while(|line| line.trim_end() != format!("  {service}:"));
        assert!(lines.next().is_some(), "no service `{service}:` in docker-compose.yml");

        // Bounded to this service first, so one with no `environment:` of its
        // own cannot borrow the next one's and pass -- deleting the block
        // outright is the most extreme form of what this guards against.
        let body: Vec<&str> = lines.take_while(|line| !is_service(line)).collect();
        let mut after_key = body.iter().skip_while(|line| line.trim_end() != "    environment:").skip(1).peekable();
        assert!(after_key.peek().is_some(), "service `{service}:` has no `environment:` block");

        // Coupled to this file's two-space-per-level indentation: a reindent
        // makes the block invisible and every setting reports as missing,
        // which is the direction a brittle test should fail in.
        after_key
            .take_while(|line| line.trim().is_empty() || line.starts_with("      "))
            .map(|line| line.split_once('#').map_or(*line, |(code, _)| code))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every `KLAVYN_*` setting the deploy docs tell an operator to use
    /// must actually reach the container that reads it.
    ///
    /// Written because one did not. `deploy/README.md` documented
    /// `KLAVYN_CLOSED_REGISTRATION=true` as the way to stop new accounts,
    /// and it was absent from the compose `environment:` block, so setting it
    /// reached compose's interpolation context and never the server. Combined
    /// with a blank token meaning "open", following the documented way to
    /// shut registration left it open to anyone instead -- the failure
    /// pointing the opposite way from the one the operator was guarding
    /// against.
    ///
    /// `.env.example` is read as well as the README, because it is the file
    /// the operator actually edits and two settings are documented only there.
    #[test]
    fn every_setting_the_deploy_docs_name_reaches_the_container_that_reads_it() {
        let deploy = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
        let compose = std::fs::read_to_string(deploy.join("docker-compose.yml")).expect("docker-compose.yml");
        let documented: std::collections::BTreeSet<String> = ["README.md", ".env.example"]
            .iter()
            .flat_map(|file| {
                let text = std::fs::read_to_string(deploy.join(file)).unwrap_or_else(|_| panic!("deploy/{file}"));
                text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    // The bare prefix is not a setting: the rename guide in
                    // README.md shows `sed 's/^CREDVAULT_/KLAVYN_/'`, which
                    // splits into exactly that word. Nothing can deliver it,
                    // so counting it would fail the test forever. A real name
                    // has something after the underscore.
                    .filter(|word| word.starts_with("KLAVYN_") && word.len() > "KLAVYN_".len())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(documented.contains("KLAVYN_CLOSED_REGISTRATION"), "the close path must stay documented");
        assert!(documented.contains("KLAVYN_REGISTRATION_TOKEN"), "the token must stay documented");

        let missing: Vec<&String> = documented
            .iter()
            .filter(|name| {
                // By key position, so `SOMETHING_ELSE: ${KLAVYN_X:-}` does
                // not count as delivering KLAVYN_X under its own name --
                // and by the interpolated name too, so the operator's `.env`
                // is what actually reaches the container. Both halves of the
                // line carry the same identifier, which means a typo shows on
                // one side only: `KLAVYN_CLOSED_REGISTRATION:
                // ${KLAVYN_CLOSED_REGISTRATON:-}` passed a key-only check
                // while reproducing the original blocker -- the operator sets
                // it and registration stays open.
                //
                // The interpolated name has to *end* where the name ends. A
                // bare `contains("${NAME")` also accepts `${NAME_OLD:-}`,
                // which delivers nothing under this name: demonstrated on
                // KLAVYN_CLOSED_REGISTRATION, where the test passed while
                // registration stayed open to anyone. No documented name is a
                // prefix of another today, which is the only thing that made
                // that latent rather than live; a rename leaving the old key
                // behind, or a `${NAME_FILE}` secrets convention, reaches it.
                //
                // A name compose hardcodes is not accepted either. Nothing
                // documented is hardcoded today, so this costs nothing now --
                // and the day one is, an operator has been told to set a value
                // in `.env` that cannot reach the container, which is the
                // original blocker wearing a different hat and should fail
                // loudly rather than be waived by name.
                let block = environment_of(&compose, owning_service(name));
                let opening = format!("${{{name}");
                !block.lines().any(|line| {
                    let line = line.trim_start();
                    line.starts_with(&format!("{name}:"))
                        && line.match_indices(&opening).any(|(at, matched)| {
                            let after = &line[at + matched.len()..];
                            !after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                        })
                })
            })
            .collect();
        assert!(missing.is_empty(), "documented in deploy/ but never reaching their container: {missing:?}");
    }

    #[test]
    fn the_logged_policy_names_the_state_and_never_the_token() {
        assert_eq!(registration_policy(true, None).describe(), "closed");
        assert_eq!(registration_policy(false, None).describe(), "open to anyone");
        let gated = registration_policy(false, Some("s3cret".into()));
        assert_eq!(gated.describe(), "token required");
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
            assert!(message.contains("KLAVYN_GOOGLE_CLIENT_ID"), "the refusal must name the flag: {message}");
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
        assert!(message.contains("KLAVYN_GOOGLE_CLIENT_SECRET"), "the refusal must name the flag: {message}");
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
