//! Thin typed HTTP client for the credvault server API.

use credvault_core::api::*;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach the server: {0}")]
    Network(String),
    #[error("{0}")]
    Server(String),
    /// 404: no account matched. Deliberately says nothing about whether the
    /// address or the fingerprint was wrong, because the server does not say.
    #[error("{0}")]
    NotFound(String),
    /// 409: the secret changed under us (key rotated, membership changed, or
    /// a duplicate); callers may refresh and retry once.
    #[error("{0}")]
    Conflict(String),
    #[error("your session has expired; please log in again")]
    Unauthorized,
    /// 429: throttled by the server, which rejects in middleware before the
    /// handler runs. A caller can therefore be certain nothing happened, which
    /// is the whole reason this is not folded into [`ClientError::Server`].
    #[error("{message}")]
    TooManyRequests { message: String, retry_after_secs: Option<u64> },
    #[error("invalid server URL: {0}")]
    InvalidUrl(String),
    /// This build and the server do not speak the same protocol. Reported
    /// before any credential is sent, because nothing later will work.
    #[error("{0}")]
    Incompatible(String),
}

/// Deadline for a passphrase change, which is far slower than anything else
/// the client asks for.
pub const PASSWORD_CHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// How long a connection may sit unused in the pool before it is thrown away
/// rather than reused.
///
/// Reuse is what makes a burst of requests cheap, and keeping it is the only
/// reason this is a ceiling rather than a flat refusal to pool. The ceiling is
/// here because a pooled connection can be dead without this process knowing.
/// Android destroys a frozen app's live TCP sockets, and an app is frozen for
/// being in the background -- measured on a Galaxy S22 at 5.5 seconds after
/// the system browser came to the front, logged by the platform as
/// `Destroyed live tcp sockets for uids={10363}` followed by
/// `freeze com.credvault.desktop`. Writing to one of those fails at the
/// transport, and neither hyper nor this client may retry it, because
/// `/oauth/callback` and `/register` are not safe to send twice. The user sees
/// "cannot reach the server" from a server that is answering fine.
///
/// Five seconds is under that measured window and far over the gap inside a
/// burst, so the common case still reuses. It is a net and not a guarantee:
/// the freeze timing is Samsung's and undocumented, so a caller that cannot
/// afford a dead connection asks for a live one with [`ApiClient::reconnect`]
/// instead of trusting this number.
const IDLE_CONNECTION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(5);

/// What a client does when the connector itself fails, as a pair: the waits
/// between attempts, and a ceiling on the whole sequence.
///
/// The ceiling is the part that is easy to leave out. The waits alone do not
/// bound anything, because each attempt also costs up to this client's request
/// timeout before it fails -- and a connect can be slow, not quick: a resolver
/// with unreachable nameservers blocks for seconds per lookup, and a TCP
/// connect that ends in `ETIMEDOUT` takes a minute or more. Eleven attempts of
/// that is minutes of a frozen-looking screen. With a budget, no further
/// attempt starts once the sequence has run long enough, so a slow failure
/// stops the retrying instead of multiplying it.
#[derive(Debug, PartialEq, Eq)]
struct ConnectRetries {
    /// How long to wait before each attempt after the first. One entry, one
    /// further attempt.
    backoffs: &'static [std::time::Duration],
    /// How long the sequence may run *before a further attempt is started*.
    ///
    /// Not a ceiling on the whole sequence, and the difference is worth having
    /// straight: the attempt this lets start is then bounded only by the
    /// client's request timeout, so the worst case is this plus one timeout --
    /// about 40 seconds for a patient client, and `budget + 180s` for
    /// [`ApiClient::change_password`]. Bounding the end instead would mean
    /// abandoning an attempt already in flight, which for a request that may
    /// have reached the server is the ambiguity this client works to avoid.
    budget: std::time::Duration,
}

/// What every request does by default: one quick go, then report it.
///
/// Short on purpose. A user whose network is genuinely down should be told so
/// while the tap still feels connected to the answer, not after a wait. The
/// one request that needs patience asks for it; see [`PATIENT_CONNECT_RETRIES`].
///
/// The budget is what keeps [`ApiClient::change_password`] honest. That one
/// request is given 180 seconds of its own, and a TCP connect can burn most of
/// them before failing; without a ceiling, retrying it would double the wait on
/// the one request whose doc comment says that leaving the user unable to tell
/// what happened is the thing it must not do.
const BRIEF_CONNECT_RETRIES: ConnectRetries =
    ConnectRetries { backoffs: &[std::time::Duration::from_millis(250)], budget: std::time::Duration::from_secs(2) };

/// The waits used for the requests that must not be allowed to fail: the two
/// that spend a Google authorization code, `/oauth/callback` and
/// `/oauth/link`, both reached from `authorize_with_google`.
///
/// Sized from the measurement, not from a guess. On a Galaxy S22 on mobile
/// data, from the instant the redirect came back from Chrome, this app's DNS
/// lookups were refused -- `No address associated with hostname`, while the
/// same device resolved the name fine from a shell -- for 7.5 seconds, and
/// then started working with no further prompting. Android does that to an app
/// it has frozen for being in the background, and a sign-in finishes in
/// exactly that state: the browser is in front, the app is frozen behind it,
/// and the code arrives there. The old 3-second budget was measured failing;
/// this is a little over twice the observed block, which is the margin a
/// number that came off one phone deserves.
///
/// The user waits rather than being thrown back to the sign-in screen, and the
/// wait only happens when the alternative was failing outright.
const PATIENT_CONNECT_RETRIES: ConnectRetries = ConnectRetries {
    backoffs: &[
        std::time::Duration::from_millis(250),
        std::time::Duration::from_millis(500),
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(3),
        std::time::Duration::from_secs(3),
    ],
    budget: std::time::Duration::from_secs(20),
};

#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
    token: Option<String>,
    /// How hard this client tries when the connector itself fails. Normally
    /// [`BRIEF_CONNECT_RETRIES`]; [`ApiClient::patiently`] is how a client
    /// comes to carry [`PATIENT_CONNECT_RETRIES`] instead.
    connect_retries: &'static ConnectRetries,
}

#[derive(serde::Deserialize)]
struct ErrorBody {
    error: String,
}

impl ApiClient {
    pub fn new(server_url: &str) -> Result<Self, ClientError> {
        reqwest::Url::parse(server_url).map_err(|e| ClientError::InvalidUrl(e.to_string()))?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .pool_idle_timeout(IDLE_CONNECTION_LIFETIME)
            // Not optional, and not merely tidy for a typed JSON API: it is
            // what makes the retry in `send_retrying_connects` safe. reqwest
            // follows up to ten redirects by default, and a connect failure on
            // a later hop is still reported as `is_connect()` -- so a request
            // whose body a first hop had already swallowed would be resent
            // from the top. Measured before this line existed: a 308 pointing
            // at a dead port delivered one `/oauth/callback` body, code and
            // all, eleven times while the user was told the server could not
            // be reached. With no redirects, a connect failure can only ever
            // be the first and only hop.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ClientError::Network(describe_transport_error(&e)))?;
        Ok(Self { http, base_url: server_url.to_string(), token: None, connect_retries: &BRIEF_CONNECT_RETRIES })
    }

    /// The same client, prepared to wait out a connector that is refusing it.
    ///
    /// Scoped deliberately narrowly -- see [`PATIENT_CONNECT_RETRIES`] for what
    /// it costs and why one request is worth it. A client that is parked
    /// somewhere, or that is about to hold a session, gives it back with
    /// [`ApiClient::promptly`].
    pub fn patiently(mut self) -> Self {
        self.connect_retries = &PATIENT_CONNECT_RETRIES;
        self
    }

    /// The same client, back to reporting an unreachable server promptly.
    pub fn promptly(mut self) -> Self {
        self.connect_retries = &BRIEF_CONNECT_RETRIES;
        self
    }

    /// A second client for the same server and session, with a connection pool
    /// of its own and nothing idle in it.
    ///
    /// For the request that follows a trip out of the app. While the system
    /// browser holds the foreground, Android freezes this app and destroys its
    /// live TCP sockets, so whatever the pool is holding is a corpse and the
    /// next write to it fails -- see [`IDLE_CONNECTION_LIFETIME`]. Most callers
    /// can wear that, because the dead connection is evicted on the way out and
    /// a retry succeeds. The one that cannot is the end of a Google sign-in: it
    /// carries an authorization code that is good once, and the user cannot be
    /// sent back to Google for another without starting over.
    ///
    /// Only the pool. Waiting is a separate decision, asked for by name with
    /// [`ApiClient::patiently`].
    pub fn reconnect(&self) -> Result<Self, ClientError> {
        let mut fresh = Self::new(&self.base_url)?;
        fresh.token = self.token.clone();
        fresh.connect_retries = self.connect_retries;
        Ok(fresh)
    }

    /// The same client carrying a session token.
    ///
    /// Also the end of any patience [`ApiClient::reconnect`] granted: holding a
    /// session means the sign-in is over, so this client is back to reporting a
    /// dead network promptly rather than waiting one out.
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self.connect_retries = &BRIEF_CONNECT_RETRIES;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn send<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T, ClientError> {
        self.send_within(method, path, body, None).await
    }

    /// The transport every `/api` request shares, with a deadline of its own.
    /// One request legitimately takes far longer than the rest; see
    /// [`ApiClient::change_password`].
    async fn send_within<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
        timeout: Option<std::time::Duration>,
    ) -> Result<T, ClientError> {
        let url = format!("{}/api{path}", self.base_url);
        let response = self
            .send_retrying_connects(|| {
                let mut request = self.http.request(method.clone(), &url);
                if let Some(timeout) = timeout {
                    request = request.timeout(timeout);
                }
                if let Some(token) = &self.token {
                    request = request.bearer_auth(token);
                }
                if let Some(body) = body {
                    request = request.json(body);
                }
                request
            })
            .await?;
        let status = response.status();
        if status.is_success() {
            if status == StatusCode::NO_CONTENT {
                // Callers expecting () deserialise from "null".
                return serde_json::from_str("null").map_err(|e| ClientError::Server(e.to_string()));
            }
            return response.json().await.map_err(|e| ClientError::Server(format!("bad response: {e}")));
        }
        if let Some(redirect) = redirected_to(status, response.headers()) {
            return Err(ClientError::Server(redirect));
        }
        if status == StatusCode::UNAUTHORIZED && self.token.is_some() {
            return Err(ClientError::Unauthorized);
        }
        // Read before the body is consumed below.
        let retry_after_secs = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok());
        let message =
            response.json::<ErrorBody>().await.map(|b| b.error).unwrap_or_else(|_| format!("server returned {status}"));
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(ClientError::TooManyRequests { message, retry_after_secs });
        }
        if status == StatusCode::CONFLICT {
            return Err(ClientError::Conflict(message));
        }
        if status == StatusCode::NOT_FOUND {
            return Err(ClientError::NotFound(message));
        }
        Err(ClientError::Server(message))
    }

    /// Send, and build the request again and resend it for as long as the
    /// failure is one that proves the request never left the device.
    ///
    /// `reqwest::Error::is_connect` is the connector's own failure: name
    /// resolution, the TCP connect, or the TLS handshake. None of those has
    /// written a request byte, so sending again cannot repeat an effect at the
    /// far end. That is what makes this safe for `/oauth/callback`,
    /// `/register` and the rest, which must never be replayed. A failure on an
    /// established connection is not a connect failure and is not retried
    /// here, because nothing can tell whether the server acted on it.
    ///
    /// The case this exists for: Android refuses a backgrounded app's DNS. A
    /// Google sign-in ends with the system browser in front and this app still
    /// in the background, and the authorization code arrives there -- so the
    /// request that spends it is sent from exactly the state where the
    /// platform answers `No address associated with hostname`, measured on a
    /// Galaxy S22 against a server that was up and that the same device could
    /// resolve from a shell. Moments later the app is in front and the same
    /// lookup succeeds. Waiting it out is the whole fix; the code cannot be
    /// reissued, so failing instead means the user starts the sign-in again.
    async fn send_retrying_connects(
        &self,
        build: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, ClientError> {
        let ConnectRetries { backoffs, budget } = *self.connect_retries;
        let started = std::time::Instant::now();
        let mut remaining = backoffs.iter();
        loop {
            let failure = match build().send().await {
                Ok(response) => return Ok(response),
                Err(error) if error.is_connect() => error,
                Err(error) => return Err(ClientError::Network(describe_transport_error(&error))),
            };
            // The budget is checked against the wait that would follow, not
            // against the time already spent, so a sequence cannot start a
            // sleep it has no room for.
            let Some(backoff) = remaining.next().filter(|backoff| started.elapsed() + **backoff <= budget) else {
                return Err(ClientError::Network(describe_transport_error(&failure)));
            };
            tokio::time::sleep(*backoff).await;
        }
    }

    const NO_BODY: Option<&()> = None;

    /// The server's protocol numbers. Outside `/api`, so this is the same
    /// document an operator curls.
    ///
    /// A 200 that is not this document means the far end is not a credvault
    /// server this build can talk to, so it is reported as an incompatibility
    /// rather than as a malformed response.
    pub async fn health(&self) -> Result<Health, ClientError> {
        let url = format!("{}/health", self.base_url);
        let response = self.send_retrying_connects(|| self.http.get(&url)).await?;
        let status = response.status();
        if !status.is_success() {
            // Before the generic message, because this is the first request a
            // newly typed address ever gets: `connect` runs it before anything
            // else, so a redirect that is only reported as a status code
            // stops someone here with the one thing they need withheld.
            if let Some(redirect) = redirected_to(status, response.headers()) {
                return Err(ClientError::Server(redirect));
            }
            return Err(ClientError::Server(format!("the server's health check returned {status}")));
        }
        response.json().await.map_err(|_| {
            ClientError::Incompatible(
                "this server does not report a protocol version, so it is older than this app can talk to".into(),
            )
        })
    }

    /// Stop before sending anything if this build and the server cannot
    /// understand each other. Unauthenticated and cheap, so every path that
    /// reaches a server for the first time can afford to do it.
    pub async fn check_protocol(&self) -> Result<(), ClientError> {
        let health = self.health().await?;
        credvault_core::api::check_protocol(&health).map_err(|mismatch| ClientError::Incompatible(mismatch.to_string()))
    }

    pub async fn register(&self, body: &RegisterRequest) -> Result<SessionResponse, ClientError> {
        self.send(Method::POST, "/register", Some(body)).await
    }

    pub async fn login(&self, body: &LoginRequest) -> Result<SessionResponse, ClientError> {
        self.send(Method::POST, "/login", Some(body)).await
    }

    /// Replace everything the account passphrase derives, in one request.
    /// All of it or none: see [`ChangePasswordRequest`].
    ///
    /// Given far longer than the shared timeout. The server runs two Argon2
    /// passes and then rewrites one row per owned secret under the write lock,
    /// so on a large vault this is minutes-scale work in the worst case. A
    /// client that gives up while the server is still committing cannot tell
    /// whether the change happened, and that ambiguity is the one thing this
    /// request must not produce.
    pub async fn change_password(&self, body: &ChangePasswordRequest) -> Result<SessionResponse, ClientError> {
        self.send_within(Method::POST, "/password", Some(body), Some(PASSWORD_CHANGE_TIMEOUT)).await
    }

    pub async fn logout(&self) -> Result<(), ClientError> {
        self.send(Method::POST, "/logout", Self::NO_BODY).await
    }

    /// End every session for this account except this one, which comes back
    /// replaced.
    ///
    /// The one eviction route with no budget of any kind, which is what makes
    /// it the first move against someone who holds a session they should not.
    /// Anything rationed per account can be emptied by whoever holds a session
    /// for that account; this cannot, so it still answers when the rest are
    /// refusing. The caller keeps a token so the request that takes away what
    /// let the other party in can follow immediately. Install it or this
    /// device is signed out along with the rest.
    pub async fn logout_other_devices(&self) -> Result<SessionResponse, ClientError> {
        self.send(Method::DELETE, "/sessions", Self::NO_BODY).await
    }

    /// What this server offers, so the UI knows whether to show the Google
    /// button and whether to ask for a registration token.
    pub async fn capabilities(&self) -> Result<Capabilities, ClientError> {
        self.send(Method::GET, "/capabilities", Self::NO_BODY).await
    }

    pub async fn oauth_start(&self, body: &OAuthStartRequest) -> Result<OAuthStartResponse, ClientError> {
        self.send(Method::POST, "/oauth/start", Some(body)).await
    }

    pub async fn oauth_callback(&self, body: &OAuthCallbackRequest) -> Result<OAuthCallbackResponse, ClientError> {
        self.send(Method::POST, "/oauth/callback", Some(body)).await
    }

    pub async fn oauth_register(&self, body: &OAuthRegisterRequest) -> Result<SessionResponse, ClientError> {
        self.send(Method::POST, "/oauth/register", Some(body)).await
    }

    /// Bind a Google identity to the account this client is signed in as.
    pub async fn oauth_link(&self, body: &OAuthLinkRequest) -> Result<UserProfile, ClientError> {
        self.send(Method::POST, "/oauth/link", Some(body)).await
    }

    /// Remove the Google identity bound to this account.
    ///
    /// Answers with a session because the server ends every existing one:
    /// tokens the link could have minted must not outlive it. The caller has
    /// to install the new token or it is signed out along with them.
    pub async fn oauth_unlink(&self, body: &OAuthUnlinkRequest) -> Result<SessionResponse, ClientError> {
        self.send(Method::POST, "/oauth/unlink", Some(body)).await
    }

    /// The fingerprint is part of the query: the server only answers for a
    /// caller who already knows it, so this never reveals whether an address
    /// has an account.
    pub async fn lookup_user(&self, email: &str, fingerprint: &str) -> Result<PublicUser, ClientError> {
        let path = format!("/users/lookup?email={}&fingerprint={}", urlencode(email), urlencode(fingerprint));
        self.send(Method::GET, &path, Self::NO_BODY).await
    }

    pub async fn list_secrets(&self) -> Result<Vec<SecretView>, ClientError> {
        self.send(Method::GET, "/secrets", Self::NO_BODY).await
    }

    /// The signed-in account's own profile. Also used as a liveness probe for
    /// the session token itself: a 401 means the token is gone.
    pub async fn me(&self) -> Result<UserProfile, ClientError> {
        self.send(Method::GET, "/me", Self::NO_BODY).await
    }

    /// Keys without payloads, for re-wrapping a vault.
    pub async fn list_secret_keys(&self) -> Result<Vec<SecretKeyView>, ClientError> {
        self.send(Method::GET, "/secrets/keys", Self::NO_BODY).await
    }

    pub async fn get_secret(&self, id: i64) -> Result<SecretView, ClientError> {
        self.send(Method::GET, &format!("/secrets/{id}"), Self::NO_BODY).await
    }

    pub async fn create_secret(&self, body: &CreateSecretRequest) -> Result<Created, ClientError> {
        self.send(Method::POST, "/secrets", Some(body)).await
    }

    pub async fn update_secret(&self, id: i64, body: &UpdateSecretRequest) -> Result<(), ClientError> {
        self.send(Method::PUT, &format!("/secrets/{id}"), Some(body)).await
    }

    pub async fn delete_secret(&self, id: i64) -> Result<(), ClientError> {
        self.send(Method::DELETE, &format!("/secrets/{id}"), Self::NO_BODY).await
    }

    pub async fn get_access(&self, id: i64) -> Result<AccessView, ClientError> {
        self.send(Method::GET, &format!("/secrets/{id}/access"), Self::NO_BODY).await
    }

    pub async fn revoke_access(
        &self,
        id: i64,
        user_id: i64,
        body: &RevokeAccessRequest,
    ) -> Result<RevokeAccessResponse, ClientError> {
        self.send(Method::POST, &format!("/secrets/{id}/access/{user_id}/revoke"), Some(body)).await
    }

    pub async fn create_invite(&self, id: i64, body: &InviteRequest) -> Result<Created, ClientError> {
        self.send(Method::POST, &format!("/secrets/{id}/invites"), Some(body)).await
    }

    pub async fn cancel_invite(&self, id: i64, invite_id: i64) -> Result<(), ClientError> {
        self.send(Method::DELETE, &format!("/secrets/{id}/invites/{invite_id}"), Self::NO_BODY).await
    }

    pub async fn list_invites(&self) -> Result<Vec<InviteView>, ClientError> {
        self.send(Method::GET, "/invites", Self::NO_BODY).await
    }

    pub async fn accept_invite(&self, invite_id: i64) -> Result<(), ClientError> {
        self.send(Method::POST, &format!("/invites/{invite_id}/accept"), Self::NO_BODY).await
    }

    pub async fn decline_invite(&self, invite_id: i64) -> Result<(), ClientError> {
        self.send(Method::POST, &format!("/invites/{invite_id}/decline"), Self::NO_BODY).await
    }
}

/// How much of a server-supplied `Location` is worth showing. Long enough for
/// any real address, short enough that a banner stays readable.
const MAX_SHOWN_LOCATION_CHARS: usize = 200;

/// Why a redirect this client will not follow is the end of the request, said
/// in a way the person who configured the address can act on.
///
/// Redirects are not followed on purpose: see `ApiClient::new`, where the
/// whole safety of resending a failed request rests on there only ever being
/// one hop. The address bar is the fix, so the answer has to carry the address
/// -- without it this is "server returned 301" and nothing else, which is what
/// a self-hoster behind a trailing-slash or canonical-host redirect would have
/// to debug from.
fn redirected_to(status: StatusCode, headers: &reqwest::header::HeaderMap) -> Option<String> {
    if !status.is_redirection() {
        return None;
    }
    let destination = headers
        .get(reqwest::header::LOCATION)
        .and_then(|location| location.to_str().ok())
        .map(|location| {
            // The far end chooses this and there is no length it has to
            // respect. Enough to recognise an address by, not enough to fill
            // the screen with.
            match location.char_indices().nth(MAX_SHOWN_LOCATION_CHARS) {
                Some((cut, _)) => format!(" to {}...", &location[..cut]),
                None => format!(" to {location}"),
            }
        })
        .unwrap_or_default();
    Some(format!(
        "the server redirected this request{destination}, which this app does not follow; \
         point it at that address instead"
    ))
}

/// Render a transport failure as a sentence that names what actually went
/// wrong.
///
/// `reqwest::Error`'s own `Display` stops at "error sending request for url
/// (...)": the same words for a name that does not resolve, a refused
/// connection, a connection the operating system closed under us and a request
/// that ran out of time. What distinguishes them is in the source chain, which
/// `to_string` drops, so a report of this failure could not be acted on.
///
/// Each distinct cause is appended once, in order, outermost first.
fn describe_transport_error(error: &reqwest::Error) -> String {
    let mut causes = vec![error.to_string()];
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        let text = cause.to_string();
        if !causes.contains(&text) {
            causes.push(text);
        }
        source = cause.source();
    }
    // A deadline this client set is not a fault of the network, and the chain
    // does not always spell it out. Say so, so a slow server is not read as an
    // unreachable one.
    if error.is_timeout() && !causes.iter().any(|cause| cause.contains("timed out")) {
        causes.push("the request timed out".to_string());
    }
    causes.join(": ")
}

/// Percent-encode a query value (RFC 3986 unreserved characters pass through).
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_first_request_a_new_server_gets_names_a_redirect_too() {
        // `connect` runs `health` before anything else, so this is where a
        // wrongly configured address is actually met -- and it has a status
        // ladder of its own, which is how it missed the fix the first time.
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let _ = read_until_marker(&mut stream, "\r\n\r\n").await;
                    let response = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.example.test/health\r\ncontent-length: 0\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        let api = ApiClient::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let Err(ClientError::Server(message)) = api.health().await else {
            panic!("a redirected health check is a failure");
        };
        assert!(message.contains("https://www.example.test/health"), "the address must be named: {message}");
    }

    #[test]
    fn a_redirect_is_reported_with_the_address_it_pointed_at() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::LOCATION, "https://elsewhere.example/api".parse().unwrap());
        let said = redirected_to(StatusCode::PERMANENT_REDIRECT, &headers).expect("a 3xx ends the request");
        assert!(said.contains("https://elsewhere.example/api"), "{said}");

        // A redirect with no usable Location is still a redirect, and still
        // has to be reported rather than read as the server's answer.
        let bare = redirected_to(StatusCode::FOUND, &reqwest::header::HeaderMap::new());
        assert!(bare.is_some(), "a Location-less redirect must still be an error");

        // A server choosing an enormous Location must not fill the banner.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::LOCATION, "h".repeat(5_000).parse().unwrap());
        let long = redirected_to(StatusCode::FOUND, &headers).expect("still a redirect");
        assert!(long.len() < MAX_SHOWN_LOCATION_CHARS + 200, "the address must be cut short: {} chars", long.len());

        for not_a_redirect in [StatusCode::OK, StatusCode::NOT_FOUND, StatusCode::INTERNAL_SERVER_ERROR] {
            assert_eq!(redirected_to(not_a_redirect, &reqwest::header::HeaderMap::new()), None, "{not_a_redirect}");
        }
    }

    #[test]
    fn urlencode_escapes_reserved_characters() {
        assert_eq!(urlencode("a+b@example.com"), "a%2Bb%40example.com");
        assert_eq!(urlencode("plain-ok_.~"), "plain-ok_.~");
    }

    #[test]
    fn rejects_bad_urls() {
        assert!(ApiClient::new("not a url").is_err());
        assert!(ApiClient::new("http://localhost:8787").is_ok());
    }

    /// An address on loopback that nothing is listening on, so connecting to
    /// it fails immediately and without touching the network.
    async fn a_dead_address() -> String {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        format!("http://127.0.0.1:{port}")
    }

    #[tokio::test]
    async fn a_connection_failure_says_more_than_the_url() {
        let api = ApiClient::new(&a_dead_address().await).unwrap();
        let Err(ClientError::Network(message)) = api.health().await else {
            panic!("a closed port must be reported as a network failure");
        };
        // The bare reqwest sentence, plus at least one cause behind it.
        assert!(message.starts_with("error sending request"), "{message}");
        assert!(message.len() > "error sending request".len() + api.base_url().len(), "{message}");
        assert!(message.contains(": "), "the cause chain must be spelled out, got: {message}");
    }

    #[tokio::test]
    async fn a_timeout_is_named_as_one() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accept and then say nothing, so the client hits its own deadline.
        let _accepting = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let api = ApiClient {
            http: reqwest::Client::builder().timeout(std::time::Duration::from_millis(200)).build().unwrap(),
            base_url: format!("http://127.0.0.1:{port}"),
            token: None,
            connect_retries: &BRIEF_CONNECT_RETRIES,
        };
        let Err(ClientError::Network(message)) = api.health().await else {
            panic!("a server that never answers must be reported as a network failure");
        };
        assert!(message.contains("timed out"), "a deadline must be named, got: {message}");
    }

    #[tokio::test]
    async fn a_request_that_never_left_the_device_is_sent_again() {
        // Nothing is listening, so every attempt fails in the connector. The
        // cost of the retries is what proves they happened.
        let api = ApiClient::new(&a_dead_address().await).unwrap();
        let started = std::time::Instant::now();
        assert!(matches!(api.health().await, Err(ClientError::Network(_))));
        let spent = started.elapsed();
        let budget: std::time::Duration = BRIEF_CONNECT_RETRIES.backoffs.iter().sum();
        assert!(spent >= budget, "every backoff must be waited out: {spent:?} < {budget:?}");
    }

    #[tokio::test]
    async fn a_connect_that_succeeds_on_a_later_try_is_not_reported_as_a_failure() {
        // A port that is dead now and alive shortly after is the shape of the
        // bug: Android refuses the app's lookups until it reaches the
        // foreground, then stops refusing them.
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let api = ApiClient::new(&format!("http://127.0.0.1:{port}")).unwrap().patiently();
        let asking = tokio::spawn(async move { api.health().await });

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        // Rebound here rather than inside a spawned task so that losing the
        // race for the port fails this test by name instead of hanging it out
        // to the full budget with no indication why.
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .expect("another process took the port in the gap; rerun");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buffer = [0u8; 2048];
                    let _ = stream.read(&mut buffer).await;
                    let body = r#"{"status":"ok","protocol":3,"min_client_protocol":1}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        let health = asking.await.unwrap().expect("a connector failure that clears must not reach the user");
        assert_eq!(health.protocol, 3);
    }

    /// Accept, read the request, count it, and hang up without answering.
    /// That fails the request *after* its bytes reached the far end, which is
    /// the shape that must never be retried. The count is of connections the
    /// far end accepted, which for a client that opens one per attempt is the
    /// number of attempts that reached it -- so it over-counts rather than
    /// under-counts, which is the safe direction for an exactly-once claim.
    async fn server_that_takes_the_request_and_says_nothing() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>)
    {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = served.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    // Counted once the request is in hand: the point of every
                    // test using this is how many times the far end received
                    // something, not how many times this process sent one.
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    drop(stream);
                });
            }
        });
        (format!("http://127.0.0.1:{port}"), served)
    }

    /// Read from `stream` until `marker` has arrived, or the peer stops
    /// sending, or a second passes. Says whether it arrived.
    async fn read_until_marker(stream: &mut tokio::net::TcpStream, marker: &str) -> bool {
        use tokio::io::AsyncReadExt;
        let mut seen = Vec::new();
        // Per read, not for the whole call: a peer that dribbles bytes keeps
        // this alive, which is fine for a test server on loopback.
        let read_timeout = std::time::Duration::from_secs(1);
        loop {
            let mut buffer = [0u8; 1024];
            match tokio::time::timeout(read_timeout, stream.read(&mut buffer)).await {
                Ok(Ok(0)) | Err(_) => return false,
                Ok(Ok(read)) => seen.extend_from_slice(&buffer[..read]),
                Ok(Err(_)) => return false,
            }
            if String::from_utf8_lossy(&seen).contains(marker) {
                return true;
            }
        }
    }

    fn a_callback() -> OAuthCallbackRequest {
        OAuthCallbackRequest { state: "s".into(), app_secret: String::from("a").into(), code: String::from("c").into() }
    }

    #[tokio::test]
    async fn a_request_the_server_already_has_is_never_sent_again() {
        // The reason the retry is allowed to exist at all. Once the far end
        // has the request, nothing may replay it: /oauth/callback spends a
        // code that is good once, and /register creates an account.
        let (base_url, served) = server_that_takes_the_request_and_says_nothing().await;
        let api = ApiClient::new(&base_url).unwrap().patiently();
        let outcome = api.oauth_callback(&a_callback()).await;
        assert!(matches!(outcome, Err(ClientError::Network(_))), "a server that hangs up is a failure");
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1, "the server must see it exactly once");
    }

    #[tokio::test]
    async fn a_redirect_cannot_turn_one_request_into_many() {
        // This is the shape that broke the safety argument: a first hop takes
        // the body and answers 308, the second hop fails in the connector, and
        // `is_connect()` is true for an error that happened *after* the code
        // was delivered. Measured at eleven deliveries before the client
        // stopped following redirects.
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dead = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = served.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    // Read until the body is in hand, not once: a single read
                    // can return headers alone, and this counter missing a
                    // delivery would read as the replay regression it exists
                    // to catch.
                    if read_until_marker(&mut stream, "app_secret").await {
                        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    let location = format!("http://127.0.0.1:{dead_port}/api/oauth/callback");
                    let response =
                        format!("HTTP/1.1 308 Permanent Redirect\r\nLocation: {location}\r\ncontent-length: 0\r\n\r\n");
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        let api = ApiClient::new(&format!("http://127.0.0.1:{port}")).unwrap().reconnect().unwrap().patiently();
        let outcome = api.oauth_callback(&a_callback()).await;
        let Err(ClientError::Server(message)) = &outcome else {
            panic!("an unfollowed 3xx is the server's answer, got {outcome:?}");
        };
        // The address is the whole point: it is what the person who typed the
        // server URL has to change.
        assert!(
            message.contains(&format!("127.0.0.1:{dead_port}")),
            "the answer must name where it pointed: {message}"
        );
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1, "the code must reach the server exactly once");
    }

    /// Ten waits that cannot all fit: the budget allows the first three and
    /// then stops the sequence. Small enough to run in a blink.
    const TRUNCATED_RETRIES: ConnectRetries = ConnectRetries {
        backoffs: &[std::time::Duration::from_millis(50); 10],
        budget: std::time::Duration::from_millis(180),
    };

    #[tokio::test]
    async fn the_budget_cuts_the_backoff_table_short() {
        // The budget is the half of the policy that bounds anything, and the
        // table it truncates is ten entries long. Timing is the observable:
        // honouring the budget stops near 150ms, ignoring it runs the full
        // 500ms of waits. A closed port fails each connect in microseconds, so
        // what is measured here is the waiting and nothing else.
        let api = ApiClient { connect_retries: &TRUNCATED_RETRIES, ..ApiClient::new(&a_dead_address().await).unwrap() };
        let started = std::time::Instant::now();
        assert!(matches!(api.health().await, Err(ClientError::Network(_))));
        let spent = started.elapsed();

        let whole_table: std::time::Duration = TRUNCATED_RETRIES.backoffs.iter().sum();
        assert!(spent < whole_table / 2, "the budget must stop the sequence early: {spent:?} of {whole_table:?}");
        // 150ms, not 100: three waits fit the budget, and a bound of 100
        // would also pass an off-by-one that took only two. The budget has a
        // tick of room over those three (180 against 150) so that this asserts
        // the count rather than the exact arithmetic of the comparison.
        assert!(spent >= std::time::Duration::from_millis(150), "the three waits that fit must be waited: {spent:?}");
    }

    #[tokio::test]
    async fn the_request_that_spends_a_google_code_waits_out_a_block_that_an_ordinary_one_would_not() {
        // The measured block was 7.5s; an ordinary request must not sit there
        // that long, and the one carrying the code must outlast it.
        let ordinary: std::time::Duration = BRIEF_CONNECT_RETRIES.backoffs.iter().sum();
        let patient: std::time::Duration = PATIENT_CONNECT_RETRIES.backoffs.iter().sum();
        assert!(ordinary < std::time::Duration::from_secs(1), "an offline tap must answer promptly: {ordinary:?}");
        assert!(patient > std::time::Duration::from_millis(7500) * 2, "too little margin over the measurement");
        // Patience is two numbers and the budget is the binding one. A budget
        // tuned below its own table would truncate it silently -- every
        // assertion above would still pass while real patience collapsed,
        // possibly back under the 7.5s block this exists to outlast.
        assert!(
            PATIENT_CONNECT_RETRIES.budget >= patient,
            "a budget under its table truncates it: {:?} < {patient:?}",
            PATIENT_CONNECT_RETRIES.budget,
        );
        assert!(
            BRIEF_CONNECT_RETRIES.budget >= ordinary,
            "the brief retry must fit its own budget: {:?} < {ordinary:?}",
            BRIEF_CONNECT_RETRIES.budget,
        );
        // Said directly rather than reached through the two above, so it
        // survives either of them being retuned.
        assert!(
            PATIENT_CONNECT_RETRIES.budget > std::time::Duration::from_millis(7500) * 2,
            "the budget is the binding bound and must outlast the measured block",
        );

        let api = ApiClient::new("https://example.test").unwrap();
        assert_eq!(api.connect_retries, &BRIEF_CONNECT_RETRIES);
        // Patience is asked for by name; reconnecting alone does not grant it.
        assert_eq!(api.reconnect().unwrap().connect_retries, &BRIEF_CONNECT_RETRIES);
        assert_eq!(api.clone().patiently().connect_retries, &PATIENT_CONNECT_RETRIES);
    }

    #[test]
    fn patience_ends_when_the_sign_in_does() {
        // Otherwise every later tap on a dead network inherits the long wait.
        let signed_in = ApiClient::new("https://example.test").unwrap().patiently().with_token("t");
        assert_eq!(signed_in.connect_retries, &BRIEF_CONNECT_RETRIES);
        assert_eq!(
            ApiClient::new("https://example.test").unwrap().patiently().promptly().connect_retries,
            &BRIEF_CONNECT_RETRIES
        );
    }

    #[test]
    fn reconnecting_keeps_the_server_and_the_session() {
        let api = ApiClient::new("https://example.test").unwrap().with_token("a-session-token");
        let fresh = api.reconnect().unwrap();
        assert_eq!(fresh.base_url(), api.base_url());
        assert_eq!(fresh.token.as_deref(), Some("a-session-token"));
    }

    #[test]
    fn reconnecting_without_a_session_stays_without_one() {
        let fresh = ApiClient::new("https://example.test").unwrap().reconnect().unwrap();
        assert_eq!(fresh.token, None);
    }

    #[tokio::test]
    async fn a_reconnected_client_does_not_inherit_the_pool() {
        // Two clients sharing a pool would share its corpses; the whole point
        // of reconnecting is that this one starts empty. Observable as a
        // second connection on the wire, so count accepts. The server hangs up
        // without answering, which fails both calls at once rather than
        // leaving either to sit out a timeout.
        let (base_url, reached) = server_that_takes_the_request_and_says_nothing().await;

        let api = ApiClient::new(&base_url).unwrap();
        let _ = api.health().await;
        let fresh = api.reconnect().unwrap();
        assert_eq!(fresh.base_url(), api.base_url(), "the same server");
        let _ = fresh.health().await;
        assert_eq!(reached.load(std::sync::atomic::Ordering::SeqCst), 2, "each client dials for itself");
    }

    #[test]
    fn idle_connections_are_dropped_before_a_browser_round_trip_could_kill_them() {
        // Android destroyed this app's sockets 5.5s after it was backgrounded;
        // see IDLE_CONNECTION_LIFETIME for where that number comes from.
        assert!(IDLE_CONNECTION_LIFETIME < std::time::Duration::from_millis(5500));
    }
}
