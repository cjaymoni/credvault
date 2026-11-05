//! One-shot loopback listener that catches the browser redirect at the end of
//! a Google sign-in.
//!
//! A native app cannot receive a redirect at a public URL, so it listens on
//! `127.0.0.1` on a port the operating system picks and registers that as the
//! redirect URI (RFC 8252). The listener answers exactly one callback, shows
//! the user a page telling them to go back to the app, and stops.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

/// Path the redirect URI points at. Anything else that connects gets a 404.
const CALLBACK_PATH: &str = "/callback";
/// How long to wait for the user to finish in the browser before giving up.
const WAIT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Nothing legitimate sends a request line longer than this; a client that
/// does is dropped rather than read indefinitely.
const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// How long one connection may take to send its request line.
///
/// A browser on loopback writes before the accept has even returned, so this
/// is enormously generous. It is kept short on purpose: it is how long a
/// silent connection can occupy one of the slots below, and so how long a real
/// redirect can be made to wait behind a flood of them.
const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// How many connections may be in flight at once.
///
/// This bounds file descriptors. Answering connections concurrently means each
/// one holds a socket while it is being read, and without a ceiling a local
/// process looping on connect takes the whole app past its descriptor limit --
/// breaking the webview and the HTTP client, not just this listener.
///
/// The slot is taken before accepting, so surplus connections wait in the
/// kernel's backlog rather than being accepted and dropped, which would refuse
/// real redirects whenever a flood held the slots. The backlog is not free,
/// though: it is finite and clamped well below what is asked for, and once it
/// fills the kernel refuses connections before this process sees them. What
/// keeps it from filling is not its size but `FIRST_BYTE_TIMEOUT` -- a silent
/// socket gives its slot back in a fraction of a second, so holding them all
/// takes a sustained flood rather than a few hundred idle connections.
///
/// A local process determined to spend CPU on this can still delay a sign-in.
/// It can also delay one by starving the machine, and neither is something a
/// loopback listener can prevent. What this does prevent is doing it cheaply,
/// and doing it by taking down the rest of the app.
const MAX_IN_FLIGHT: usize = 128;
/// How long a connection may stay silent before its slot is reclaimed.
///
/// A browser writes the request line before the accept has returned, so a
/// connection that has said nothing after this is not a redirect. This is the
/// cost of one hostile socket, and so what sets how hard the listener is to
/// flood.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_millis(250);
/// How long writing the response page may take before the slot is reclaimed.
/// The code has already been handed over by then; this only stops a peer that
/// stalls its read from holding a slot.
const RESPOND_TIMEOUT: Duration = Duration::from_secs(2);
/// How long to wait after an accept error before trying again. Accept fails
/// for transient reasons (no descriptors, a peer that vanished), and none of
/// them is a reason to end the user's sign-in.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

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
    /// The redirect belongs to a different sign-in. The listener answers and
    /// ignores these rather than ending the wait on one.
    #[error("that sign-in response did not match this attempt; start again")]
    StateMismatch,
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
        let expected: Arc<str> = Arc::from(expected_state);
        // Each connection is answered in its own task, so a socket that stalls
        // costs only its own deadline. Answering them in turn would make N
        // stalled sockets cost N deadlines in a row, and enough of them reach
        // WAIT_TIMEOUT before the real redirect is ever read.
        let (sender, mut answers) = mpsc::channel::<Result<Zeroizing<String>, RedirectError>>(1);
        let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
        loop {
            // Taking the slot and accepting are one future, so that waiting
            // for either never stops the answer channel being polled. Gating
            // the whole loop on a free slot would let a code already in hand
            // sit unread behind sockets that have nothing to do with it.
            let accept_next = async {
                let permit = Arc::clone(&permits).acquire_owned().await.ok()?;
                match self.listener.accept().await {
                    Ok((stream, _)) => Some((stream, permit)),
                    // Never fatal. Propagating here would let any local process
                    // end the sign-in by exhausting descriptors, which is the
                    // starvation this listener exists to resist.
                    Err(error) => {
                        tracing::debug!(%error, "ignoring a failed accept on the sign-in listener");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        None
                    }
                }
            };
            tokio::select! {
                Some(answer) = answers.recv() => return answer,
                accepted = accept_next => {
                    if let Some((stream, permit)) = accepted {
                        tokio::spawn(answer_one(stream, Arc::clone(&expected), sender.clone(), permit));
                    }
                }
            }
        }
    }
}

/// Answer one connection, and report an answer only for a redirect carrying
/// this attempt's `state`.
///
/// Everything else — a stalled socket, a speculative request for another path,
/// a redirect belonging to a different sign-in — is served and forgotten. None
/// of it may end the wait, because any process on this machine can produce all
/// three.
async fn answer_one(
    mut stream: TcpStream,
    expected_state: Arc<str>,
    sender: mpsc::Sender<Result<Zeroizing<String>, RedirectError>>,
    _permit: OwnedSemaphorePermit,
) {
    // A redirect has already written by the time it is accepted; a socket that
    // is merely open has not. Giving the slot back on that distinction is what
    // makes a flood of silent connections expensive to sustain rather than
    // free.
    if !matches!(tokio::time::timeout(FIRST_BYTE_TIMEOUT, stream.readable()).await, Ok(Ok(()))) {
        return;
    }
    let Ok(Ok(Some(target))) = tokio::time::timeout(READ_TIMEOUT, read_request_target(&mut stream)).await else {
        return;
    };
    let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
        let _ = tokio::time::timeout(RESPOND_TIMEOUT, respond(&mut stream, "404 Not Found", NOT_FOUND_PAGE)).await;
        return;
    };
    if url.path() != CALLBACK_PATH {
        let _ = tokio::time::timeout(RESPOND_TIMEOUT, respond(&mut stream, "404 Not Found", NOT_FOUND_PAGE)).await;
        return;
    }

    let result = parse_callback(&url, &expected_state);
    if matches!(result, Err(RedirectError::StateMismatch)) {
        // Not this attempt's redirect. Tell whoever sent it, and go on waiting
        // for the one that is. Logged because a genuine mismatch -- a stale
        // tab, a resumed browser -- now ends in a timeout rather than an
        // error, and this is the only trace of why.
        tracing::debug!("ignoring a sign-in redirect for a different attempt");
        let _ = tokio::time::timeout(RESPOND_TIMEOUT, respond(&mut stream, "200 OK", FAILED_PAGE)).await;
        return;
    }
    let page = if result.is_ok() { DONE_PAGE } else { FAILED_PAGE };
    // Reported before the page is drawn, not after: `respond` has no deadline
    // of its own, so a peer that stalls its read would hold this task open and
    // the code would never arrive. Failing to draw the page is survivable;
    // hanging before handing over the result is not.
    let _ = sender.send(result).await;
    let _ = tokio::time::timeout(RESPOND_TIMEOUT, respond(&mut stream, "200 OK", page)).await;
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

    /// Sockets opened and held without sending are what used to queue behind
    /// each other: answering them in turn made sixty of them cost five minutes,
    /// which is the whole wait. Held open together, they must cost one read
    /// deadline between them.
    #[tokio::test]
    async fn many_stalled_connections_do_not_block_the_redirect() {
        use tokio::net::TcpStream;

        let listener = RedirectListener::bind().await.unwrap();
        let redirect = listener.redirect_uri().to_string();
        let address = redirect.trim_start_matches("http://").trim_end_matches("/callback").to_string();
        let waiting = tokio::spawn(async move { listener.wait_for_code("st").await });

        // Enough that, answered one at a time, they would exhaust WAIT_TIMEOUT.
        // Far more than the slots, and more than the kernel's backlog, which
        // is the case that used to refuse the redirect outright: silent
        // sockets release their slot on FIRST_BYTE_TIMEOUT, so the queue keeps
        // draining instead of filling.
        let stalled: Vec<TcpStream> = {
            let mut held = Vec::new();
            for _ in 0..MAX_IN_FLIGHT * 3 {
                match TcpStream::connect(&address).await {
                    Ok(socket) => held.push(socket),
                    // A refusal here is the kernel's backlog, not the app's
                    // doing; the point of the test is what happens next.
                    Err(_) => break,
                }
            }
            held
        };

        // More sockets than there are slots, so the redirect has to come out
        // of the backlog behind them. It must still be served, and within one
        // recycle of the slots rather than the whole wait.
        let started = std::time::Instant::now();
        // Retried briefly, because a connection can still be refused while the
        // backlog drains. A browser does not retry, so what matters is that
        // the window is short rather than permanent.
        let mut attempt = Err(());
        for _ in 0..20 {
            match reqwest::Client::new()
                .get(format!("{redirect}?code=not-blocked&state=st"))
                .timeout(READ_TIMEOUT * 2)
                .send()
                .await
            {
                Ok(response) => {
                    attempt = Ok(response);
                    break;
                }
                Err(_) => tokio::time::sleep(FIRST_BYTE_TIMEOUT).await,
            }
        }
        let done = attempt.expect("the redirect must get through while silent sockets are held");
        assert!(done.status().is_success());
        assert_eq!(*waiting.await.unwrap().unwrap(), "not-blocked");
        assert!(
            started.elapsed() < READ_TIMEOUT * 4,
            "the redirect waited {:?} behind sockets that never sent anything",
            started.elapsed()
        );
        drop(stalled);
    }

    /// A few silent connections, which is what actually happens in practice,
    /// must cost the redirect nothing at all.
    #[tokio::test]
    async fn a_few_stalled_connections_do_not_delay_the_redirect() {
        use tokio::net::TcpStream;

        let listener = RedirectListener::bind().await.unwrap();
        let redirect = listener.redirect_uri().to_string();
        let address = redirect.trim_start_matches("http://").trim_end_matches("/callback").to_string();
        let waiting = tokio::spawn(async move { listener.wait_for_code("st").await });

        let mut stalled = Vec::new();
        for _ in 0..4 {
            stalled.push(TcpStream::connect(&address).await.unwrap());
        }

        let started = std::time::Instant::now();
        let done = reqwest::get(format!("{redirect}?code=prompt&state=st")).await.unwrap();
        assert!(done.status().is_success());
        assert_eq!(*waiting.await.unwrap().unwrap(), "prompt");
        assert!(started.elapsed() < READ_TIMEOUT, "a few silent sockets delayed the redirect");
        drop(stalled);
    }

    /// A redirect carrying someone else's state is told it failed, but it does
    /// not end this attempt: anything on this machine can send one, and a
    /// sign-in that any local process can cancel is the starvation bug wearing
    /// a different hat.
    #[tokio::test]
    async fn a_redirect_for_another_attempt_does_not_end_the_wait() {
        let listener = RedirectListener::bind().await.unwrap();
        let redirect = listener.redirect_uri().to_string();
        let waiting = tokio::spawn(async move { listener.wait_for_code("expected").await });

        let response = reqwest::get(format!("{redirect}?code=the-code&state=someone-elses")).await.unwrap();
        assert!(response.text().await.unwrap().contains("Sign-in failed"));

        // The real one still lands.
        let done = reqwest::get(format!("{redirect}?code=mine&state=expected")).await.unwrap();
        assert!(done.text().await.unwrap().contains("go back to credvault"));
        assert_eq!(*waiting.await.unwrap().unwrap(), "mine");
    }

    /// A provider error *does* end the wait, because the state matched: it is
    /// this user's own redirect reporting that they declined.
    #[tokio::test]
    async fn a_provider_error_for_this_attempt_ends_the_wait() {
        let listener = RedirectListener::bind().await.unwrap();
        let redirect = listener.redirect_uri().to_string();
        let waiting = tokio::spawn(async move { listener.wait_for_code("st").await });

        let response = reqwest::get(format!("{redirect}?error=access_denied&state=st")).await.unwrap();
        assert!(response.text().await.unwrap().contains("Sign-in failed"));
        assert!(matches!(waiting.await.unwrap(), Err(RedirectError::Provider(code)) if code == "access_denied"));
    }
}
