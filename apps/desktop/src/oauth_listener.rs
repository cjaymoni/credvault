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
/// How long one connection may take to send its request line and headers.
///
/// A browser on loopback writes before the accept has even returned, so a
/// second is enormously generous for the real thing — a redirect carrying a
/// 6 KB query string was served in under 5ms. It is kept short because it is
/// also what a hostile connection costs, and so how fast slots come back while
/// one is being held open.
///
/// Worst-case slot occupancy is this *plus* `RESPOND_TIMEOUT`, because the two
/// deadlines run in series. A peer that stalls its read does not reach the
/// second one in practice — the response is about a kilobyte and fits any
/// receive buffer a peer can ask for, measured at 2.4ms with `SO_RCVBUF`
/// forced to 1 — but that is a property of the page size, not of this code.
/// Growing those pages would triple the worst case.
const READ_TIMEOUT: Duration = Duration::from_secs(1);
/// How many connections may be in flight at once.
///
/// This bounds file descriptors. Answering connections concurrently means each
/// one holds a socket while it is being read, and without a ceiling a local
/// process looping on connect takes the whole app past its descriptor limit --
/// breaking the webview and the HTTP client, not just this listener.
///
/// What this listener does and does not promise, stated plainly, because two
/// earlier versions of this comment claimed more than the code delivered:
///
/// * A handful of silent or malformed connections cost the sign-in nothing.
///   Every connection, hostile or not, gives its slot back within
///   `READ_TIMEOUT`, so a few of them delay a redirect by at most that.
/// * A flood ends when it ends. Nothing is left wedged, no slot leaks, and the
///   next redirect is served.
/// * The rest of the app is never taken down with it: descriptors are capped
///   here, and a failed accept is not fatal.
///
/// It does *not* promise immunity. A local process holding more sockets than
/// there are slots plus kernel backlog will have the browser's redirect
/// refused for as long as it holds them, and no arrangement of this loop
/// changes that -- the queue is finite and the browser tries once. What the
/// deadline buys is that the sockets must be *held*, continuously, and that
/// the denial stops when they are released.
///
/// A first-byte deadline shorter than `READ_TIMEOUT` was tried here and
/// removed, so that it is not reintroduced. It released wholly silent sockets
/// sooner, but a connection that sent a single byte still held its slot for
/// the full read deadline — and the one-byte shape was always available, so it
/// raised the cost of the laziest flood and nothing else. Against that it
/// added a path that could drop a real redirect whose first byte was late,
/// with no response and no log line, leaving the user to wait out
/// `WAIT_TIMEOUT` for a code that had already arrived.
const MAX_IN_FLIGHT: usize = 128;
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

    /// This address goes two ways at once: the app sends it to the server,
    /// which stores it by parsing it and replays the parsed form to Google at
    /// the token exchange, and the app also composes the authorization URL
    /// with the string as written. If parsing changed it — a stripped default
    /// port, an added trailing slash — the two requests would name different
    /// redirects and Google would refuse the code, with nothing on either side
    /// to say why.
    ///
    /// `validate_loopback_redirect` on the server is the other half of this
    /// and rejects anything without an explicit port, so the one shape that
    /// would normalise differently cannot arrive. This end pins that the shape
    /// produced here is the one that survives.
    #[tokio::test]
    async fn the_listener_address_survives_the_round_trip_through_a_url_parser() {
        let listener = RedirectListener::bind().await.unwrap();
        let written = listener.redirect_uri();
        let parsed = url::Url::parse(written).expect("the listener must produce a URL");
        assert_eq!(parsed.to_string(), written, "parsing must not rewrite the redirect");
        assert!(parsed.port().is_some(), "an explicit port is what keeps the parse an identity");
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

    /// A flood that is over is over: nothing stays wedged, no slot leaks, and
    /// the next redirect is served normally.
    ///
    /// This does not assert that the redirect gets through *during* a flood
    /// larger than the slots plus the kernel backlog. It does not, the queue
    /// is finite, and a test claiming otherwise would be the third one here to
    /// assert something the code cannot do.
    #[tokio::test]
    async fn the_listener_recovers_once_a_flood_stops() {
        use tokio::net::TcpStream;

        let listener = RedirectListener::bind().await.unwrap();
        let redirect = listener.redirect_uri().to_string();
        let address = redirect.trim_start_matches("http://").trim_end_matches("/callback").to_string();
        let waiting = tokio::spawn(async move { listener.wait_for_code("st").await });

        {
            let mut silent = Vec::new();
            for _ in 0..MAX_IN_FLIGHT * 2 {
                // A refusal here is the kernel's queue filling, which is
                // allowed; what is not allowed is the listener failing to
                // recover afterwards. Counted so this cannot quietly become a
                // test of a flood of one.
                if let Ok(socket) = TcpStream::connect(&address).await {
                    silent.push(socket);
                }
            }
            assert!(silent.len() > MAX_IN_FLIGHT, "only {} sockets were opened; this is not a flood", silent.len());
        }
        // Everything dropped. Give the slots one deadline to come back.
        tokio::time::sleep(READ_TIMEOUT).await;

        let started = std::time::Instant::now();
        let done = reqwest::Client::new()
            .get(format!("{redirect}?code=recovered&state=st"))
            .timeout(READ_TIMEOUT * 4)
            .send()
            .await
            .expect("the listener must still work after a flood");
        assert!(done.status().is_success());
        assert_eq!(*waiting.await.unwrap().unwrap(), "recovered");
        assert!(started.elapsed() < READ_TIMEOUT, "the listener was still wedged after the flood stopped");
    }

    /// Occupancy is bounded: a connection that never finishes its request must
    /// give its slot back on `READ_TIMEOUT`, so a full set of them delays a
    /// redirect by about that and no longer.
    ///
    /// Every slot is filled, then the redirect is made *once* — a browser does
    /// not retry. Without a deadline on the read this hangs until the sign-in
    /// times out, so deleting that deadline must fail this test.
    #[tokio::test]
    async fn a_connection_that_never_finishes_gives_its_slot_back() {
        use tokio::net::TcpStream;

        let listener = RedirectListener::bind().await.unwrap();
        let redirect = listener.redirect_uri().to_string();
        let address = redirect.trim_start_matches("http://").trim_end_matches("/callback").to_string();
        let waiting = tokio::spawn(async move { listener.wait_for_code("st").await });

        // Exactly the slots, so the redirect queues in a backlog with room in
        // it and the only thing it waits on is a slot coming free. Each sends
        // a partial request line and then holds, which is the shape that costs
        // the most: a silent socket and a one-byte socket cost the same here.
        let mut held = Vec::new();
        for _ in 0..MAX_IN_FLIGHT {
            let mut socket = TcpStream::connect(&address).await.unwrap();
            socket.write_all(b"GET /callb").await.unwrap();
            held.push(socket);
        }

        let started = std::time::Instant::now();
        let done = reqwest::Client::new()
            .get(format!("{redirect}?code=let-through&state=st"))
            .timeout(READ_TIMEOUT * 6)
            .send()
            .await
            .expect("the redirect must be served on its first attempt");
        let waited = started.elapsed();
        assert!(done.status().is_success());
        assert_eq!(*waiting.await.unwrap().unwrap(), "let-through");
        assert!(waited < READ_TIMEOUT * 3, "waited {waited:?}; slots are not being released on the read deadline");
        drop(held);
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
