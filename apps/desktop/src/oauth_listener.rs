//! One-shot loopback listener that catches the browser redirect at the end of
//! a Google sign-in.
//!
//! A native app cannot receive a redirect at a public URL, so it listens on
//! `127.0.0.1` on a port the operating system picks and registers that as the
//! redirect URI (RFC 8252). The listener answers exactly one callback, shows
//! the user a page telling them to go back to the app, and stops.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

/// Path the redirect URI points at. Anything else that connects gets a 404.
const CALLBACK_PATH: &str = "/callback";
/// How long to wait for the user to finish in the browser before giving up.
const WAIT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Nothing legitimate sends a request line longer than this; a client that
/// does is dropped rather than read indefinitely.
const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// How long one connection may take to send its request line. A browser on
/// loopback sends immediately; anything slower is dropped so it cannot hold
/// the listener while the real redirect waits behind it.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a sign-in did not produce a code. All of these are things to show the
/// user, not internal failures.
#[derive(Debug, thiserror::Error)]
pub enum RedirectError {
    #[error("the sign-in window was closed or took too long; try again")]
    TimedOut,
    #[error("Google reported: {0}")]
    Provider(String),
    /// The redirect did not carry the `state` this attempt issued, so it
    /// belongs to a different sign-in (or to no sign-in at all).
    #[error("that sign-in response did not match this attempt; start again")]
    StateMismatch,
    #[error("could not listen for the sign-in response: {0}")]
    Io(#[from] io::Error),
}

pub struct RedirectListener {
    listener: TcpListener,
    redirect_uri: String,
}

impl RedirectListener {
    /// Bind to a free loopback port.
    pub async fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, redirect_uri: format!("http://127.0.0.1:{port}{CALLBACK_PATH}") })
    }

    /// The URI to register with the provider for this attempt.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Wait for the redirect and return the authorization code it carries.
    ///
    /// # Errors
    /// [`RedirectError::StateMismatch`] if the redirect is not the one this
    /// attempt started, [`RedirectError::Provider`] if Google reported an
    /// error (the user declining, most often), [`RedirectError::TimedOut`] if
    /// nothing arrives.
    pub async fn wait_for_code(self, expected_state: &str) -> Result<Zeroizing<String>, RedirectError> {
        tokio::time::timeout(WAIT_TIMEOUT, self.accept_callback(expected_state))
            .await
            .unwrap_or(Err(RedirectError::TimedOut))
    }

    async fn accept_callback(self, expected_state: &str) -> Result<Zeroizing<String>, RedirectError> {
        loop {
            let (mut stream, _) = self.listener.accept().await?;
            // Anything that is not the redirect is answered and forgotten: it
            // does not count against the one that matters and does not end the
            // wait. Browsers open speculative connections, and any other
            // process on this machine can open as many as it likes, so a
            // budget here would be something to exhaust. The overall timeout
            // in `wait_for_code` is what bounds this loop.
            let target = match tokio::time::timeout(READ_TIMEOUT, read_request_target(&mut stream)).await {
                Ok(Ok(Some(target))) => target,
                // Malformed, cut short, or too slow to send a request line.
                Ok(Ok(None)) | Ok(Err(_)) | Err(_) => continue,
            };
            let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
                let _ = respond(&mut stream, "404 Not Found", NOT_FOUND_PAGE).await;
                continue;
            };
            if url.path() != CALLBACK_PATH {
                let _ = respond(&mut stream, "404 Not Found", NOT_FOUND_PAGE).await;
                continue;
            }

            let result = parse_callback(&url, expected_state);
            let page = match &result {
                Ok(_) => DONE_PAGE,
                Err(_) => FAILED_PAGE,
            };
            // The code is in hand by now. Failing to draw the page back to the
            // browser is not a reason to lose it.
            let _ = respond(&mut stream, "200 OK", page).await;
            return result;
        }
    }
}

/// Pull `code` out of a redirect, once it is established that the redirect
/// belongs to this attempt.
///
/// The state is compared before anything else is read, so a redirect someone
/// else triggered is never acted on.
fn parse_callback(url: &url::Url, expected_state: &str) -> Result<Zeroizing<String>, RedirectError> {
    let params: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    let value = |name: &str| params.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone());

    if value("state").as_deref() != Some(expected_state) {
        return Err(RedirectError::StateMismatch);
    }
    if let Some(error) = value("error") {
        // Provider error codes are short and safe to show; the description is
        // not always present and not always meaningful.
        return Err(RedirectError::Provider(error));
    }
    match value("code") {
        Some(code) if !code.is_empty() => Ok(Zeroizing::new(code)),
        _ => Err(RedirectError::Provider("the redirect carried no authorization code".into())),
    }
}

/// Read the request line and return its target (`/callback?...`). `None` when
/// the request is malformed or oversized, which is not worth reporting.
async fn read_request_target(stream: &mut TcpStream) -> io::Result<Option<String>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") || buffer.len() > MAX_REQUEST_BYTES {
            break;
        }
    }
    let Some(line_end) = buffer.windows(2).position(|window| window == b"\r\n") else {
        return Ok(None);
    };
    let Ok(line) = std::str::from_utf8(&buffer[..line_end]) else {
        return Ok(None);
    };
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if method != "GET" || !target.starts_with('/') {
        return Ok(None);
    }
    Ok(Some(target.to_string()))
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

// Built once at first use rather than formatted per request.
static DONE_PAGE: &str = "\
<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Signed in</title><style>body{font:16px/1.5 system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#0f1115;color:#e7e9ee}main{text-align:center;padding:2rem}h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;opacity:.75}</style></head><body><main><h1>Signed in</h1><p>You can close this tab and go back to credvault.</p></main></body></html>";

static FAILED_PAGE: &str = "\
<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Sign-in failed</title><style>body{font:16px/1.5 system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#0f1115;color:#e7e9ee}main{text-align:center;padding:2rem}h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;opacity:.75}</style></head><body><main><h1>Sign-in failed</h1><p>Close this tab and try again from credvault.</p></main></body></html>";

static NOT_FOUND_PAGE: &str = "<!doctype html><title>Not found</title><p>Not found.";

#[cfg(test)]
mod tests {
    use super::*;

    fn callback_url(query: &str) -> url::Url {
        url::Url::parse(&format!("http://127.0.0.1:1234/callback?{query}")).unwrap()
    }

    #[test]
    fn a_matching_state_yields_the_code() {
        let code = parse_callback(&callback_url("code=abc123&state=st"), "st").unwrap();
        assert_eq!(*code, "abc123");
    }

    #[test]
    fn the_state_is_checked_before_anything_else_is_read() {
        for query in ["code=abc&state=other", "code=abc", "error=access_denied&state=other", ""] {
            let error = parse_callback(&callback_url(query), "st").unwrap_err();
            assert!(matches!(error, RedirectError::StateMismatch), "{query}: {error:?}");
        }
    }

    #[test]
    fn a_provider_error_is_reported_rather_than_treated_as_a_code() {
        let error = parse_callback(&callback_url("error=access_denied&state=st"), "st").unwrap_err();
        assert!(matches!(&error, RedirectError::Provider(code) if code == "access_denied"));
        // An error wins even if a code is also present.
        let error = parse_callback(&callback_url("error=invalid_scope&code=abc&state=st"), "st").unwrap_err();
        assert!(matches!(&error, RedirectError::Provider(code) if code == "invalid_scope"));
    }

    #[test]
    fn a_redirect_with_no_code_is_an_error_not_an_empty_code() {
        for query in ["state=st", "state=st&code="] {
            assert!(matches!(parse_callback(&callback_url(query), "st"), Err(RedirectError::Provider(_))), "{query}");
        }
    }

    #[tokio::test]
    async fn the_listener_answers_one_callback_and_ignores_other_paths() {
        let listener = RedirectListener::bind().await.unwrap();
        let redirect = listener.redirect_uri().to_string();
        assert!(redirect.starts_with("http://127.0.0.1:"));
        assert!(redirect.ends_with("/callback"));

        let waiting = tokio::spawn(async move { listener.wait_for_code("st").await });

        let http = reqwest::Client::new();
        let base = redirect.trim_end_matches("/callback").to_string();
        // A speculative request for something else must not consume the wait.
        let stray = http.get(format!("{base}/favicon.ico")).send().await.unwrap();
        assert_eq!(stray.status(), reqwest::StatusCode::NOT_FOUND);

        let done = http.get(format!("{redirect}?code=the-code&state=st")).send().await.unwrap();
        assert!(done.text().await.unwrap().contains("go back to credvault"));
        assert_eq!(*waiting.await.unwrap().unwrap(), "the-code");
    }

    /// Anything on this machine can connect to the port. None of it may cost
    /// the user their sign-in.
    #[tokio::test]
    async fn junk_connections_do_not_starve_the_listener() {
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::TcpStream;

        let listener = RedirectListener::bind().await.unwrap();
        let redirect = listener.redirect_uri().to_string();
        let base = redirect.trim_end_matches("/callback").to_string();
        let address = base.trim_start_matches("http://").to_string();
        let waiting = tokio::spawn(async move { listener.wait_for_code("st").await });

        // Far more than the old budget of 16, in the three shapes a hostile
        // local process has: a request for something else, a connection that
        // sends a partial line and leaves, and one that sends nothing at all.
        let http = reqwest::Client::new();
        for _ in 0..30 {
            let _ = http.get(format!("{base}/favicon.ico")).send().await;
            if let Ok(mut partial) = TcpStream::connect(&address).await {
                let _ = partial.write_all(b"GET /callb").await;
                drop(partial);
            }
            if let Ok(silent) = TcpStream::connect(&address).await {
                drop(silent);
            }
        }

        // The real redirect still lands.
        let done = http.get(format!("{redirect}?code=survived&state=st")).send().await.unwrap();
        assert!(done.text().await.unwrap().contains("go back to credvault"));
        assert_eq!(*waiting.await.unwrap().unwrap(), "survived");
    }

    /// A connection that holds the socket open without sending is the one that
    /// used to block everything behind it. Takes about `READ_TIMEOUT`.
    #[tokio::test]
    async fn a_stalled_connection_does_not_block_the_redirect_behind_it() {
        use tokio::net::TcpStream;

        let listener = RedirectListener::bind().await.unwrap();
        let redirect = listener.redirect_uri().to_string();
        let address = redirect.trim_start_matches("http://").trim_end_matches("/callback").to_string();
        let waiting = tokio::spawn(async move { listener.wait_for_code("st").await });

        // Connect and say nothing, keeping the socket open for the duration.
        let stalled = TcpStream::connect(&address).await.unwrap();

        let done = reqwest::Client::new()
            .get(format!("{redirect}?code=not-blocked&state=st"))
            .timeout(READ_TIMEOUT * 4)
            .send()
            .await
            .unwrap();
        assert!(done.status().is_success());
        assert_eq!(*waiting.await.unwrap().unwrap(), "not-blocked");
        drop(stalled);
    }

    #[tokio::test]
    async fn a_redirect_for_another_attempt_is_refused() {
        let listener = RedirectListener::bind().await.unwrap();
        let redirect = listener.redirect_uri().to_string();
        let waiting = tokio::spawn(async move { listener.wait_for_code("expected").await });

        let response = reqwest::get(format!("{redirect}?code=the-code&state=someone-elses")).await.unwrap();
        assert!(response.text().await.unwrap().contains("Sign-in failed"));
        assert!(matches!(waiting.await.unwrap(), Err(RedirectError::StateMismatch)));
    }
}
