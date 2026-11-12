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
/// How long to wait before each retry of a request that never left the device
/// in the ordinary case: one quick go, then report it.
///
/// Short on purpose. A user whose network is genuinely down should be told so
/// while the tap still feels connected to the answer, not after a wait. The
/// one place that needs to be patient instead asks for it; see
/// [`PATIENT_CONNECT_RETRIES`].
const BRIEF_CONNECT_RETRIES: &[std::time::Duration] = &[std::time::Duration::from_millis(250)];

/// The waits used for the one request that must not be allowed to fail: the
/// one that spends a Google authorization code.
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
const PATIENT_CONNECT_RETRIES: &[std::time::Duration] = &[
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
];

const IDLE_CONNECTION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
    token: Option<String>,
    /// How hard this client tries when the connector itself fails. Normally
    /// [`BRIEF_CONNECT_RETRIES`]; see [`ApiClient::reconnect`] for the one
    /// client that is patient instead.
    connect_retries: &'static [std::time::Duration],
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
            .build()
            .map_err(|e| ClientError::Network(describe_transport_error(&e)))?;
        Ok(Self { http, base_url: server_url.to_string(), token: None, connect_retries: BRIEF_CONNECT_RETRIES })
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
    pub fn reconnect(&self) -> Result<Self, ClientError> {
        let mut fresh = Self::new(&self.base_url)?;
        fresh.token = self.token.clone();
        fresh.connect_retries = PATIENT_CONNECT_RETRIES;
        Ok(fresh)
    }

    /// The same client carrying a session token.
    ///
    /// Also the end of any patience [`ApiClient::reconnect`] granted: holding a
    /// session means the sign-in is over, so this client is back to reporting a
    /// dead network promptly rather than waiting one out.
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self.connect_retries = BRIEF_CONNECT_RETRIES;
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
        for backoff in self.connect_retries {
            match build().send().await {
                Ok(response) => return Ok(response),
                Err(error) if error.is_connect() => tokio::time::sleep(*backoff).await,
                Err(error) => return Err(ClientError::Network(describe_transport_error(&error))),
            }
        }
        build().send().await.map_err(|e| ClientError::Network(describe_transport_error(&e)))
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
            connect_retries: BRIEF_CONNECT_RETRIES,
        };
        let Err(ClientError::Network(message)) = api.health().await else {
            panic!("a server that never answers must be reported as a network failure");
        };
        assert!(message.contains("timed out"), "a deadline must be named, got: {message}");
    }

    /// Serve one canned HTTP response per connection, counting them.
    async fn counting_server(body: &'static str) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = served.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buffer = [0u8; 2048];
                    let _ = stream.read(&mut buffer).await;
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (format!("http://127.0.0.1:{port}"), served)
    }

    #[tokio::test]
    async fn a_request_that_never_left_the_device_is_sent_again() {
        // Nothing is listening, so every attempt fails in the connector. The
        // cost of the retries is what proves they happened.
        let api = ApiClient::new(&a_dead_address().await).unwrap();
        let started = std::time::Instant::now();
        assert!(matches!(api.health().await, Err(ClientError::Network(_))));
        let spent = started.elapsed();
        let budget: std::time::Duration = BRIEF_CONNECT_RETRIES.iter().sum();
        assert!(spent >= budget, "every backoff must be waited out: {spent:?} < {budget:?}");
    }

    #[tokio::test]
    async fn a_connect_that_succeeds_on_a_later_try_is_not_reported_as_a_failure() {
        // A port that is dead now and alive shortly after is the shape of the
        // bug: Android refuses the lookup until the app reaches the foreground.
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
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

        // Through a reconnected client, because waiting out a connector that
        // clears is exactly what that client is for.
        let api = ApiClient::new(&format!("http://127.0.0.1:{port}")).unwrap().reconnect().unwrap();
        let health = api.health().await.expect("a connector failure that clears must not reach the user");
        assert_eq!(health.protocol, 3);
    }

    #[tokio::test]
    async fn a_request_the_server_answered_is_never_sent_twice() {
        // The reason the retry is allowed to exist at all: once the far end
        // has the request, nothing may replay it. /oauth/callback and
        // /register are not safe to send twice.
        let (base_url, served) = counting_server(r#"{"error":"nope"}"#).await;
        let api = ApiClient::new(&base_url).unwrap();
        let _ = api
            .oauth_callback(&OAuthCallbackRequest {
                state: "s".into(),
                app_secret: String::from("a").into(),
                code: String::from("c").into(),
            })
            .await;
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1, "the server must see it exactly once");
    }

    #[tokio::test]
    async fn the_request_that_spends_a_google_code_waits_out_a_block_that_an_ordinary_one_would_not() {
        // The measured block was 7.5s; an ordinary request must not sit there
        // that long, and the one carrying the code must outlast it.
        let ordinary: std::time::Duration = BRIEF_CONNECT_RETRIES.iter().sum();
        let patient: std::time::Duration = PATIENT_CONNECT_RETRIES.iter().sum();
        assert!(ordinary < std::time::Duration::from_secs(1), "an offline tap must answer promptly: {ordinary:?}");
        assert!(patient > std::time::Duration::from_millis(7500) * 2, "too little margin over the measurement");

        let api = ApiClient::new("https://example.test").unwrap();
        assert_eq!(api.connect_retries, BRIEF_CONNECT_RETRIES);
        assert_eq!(api.reconnect().unwrap().connect_retries, PATIENT_CONNECT_RETRIES);
    }

    #[test]
    fn patience_ends_when_the_sign_in_does() {
        // Otherwise every later tap on a dead network inherits the long wait.
        let signed_in = ApiClient::new("https://example.test").unwrap().reconnect().unwrap().with_token("t");
        assert_eq!(signed_in.connect_retries, BRIEF_CONNECT_RETRIES);
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
        // second connection on the wire, so count accepts.
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                held.push(stream);
            }
        });

        let api = ApiClient {
            http: reqwest::Client::builder().timeout(std::time::Duration::from_millis(200)).build().unwrap(),
            base_url: format!("http://127.0.0.1:{port}"),
            token: None,
            connect_retries: BRIEF_CONNECT_RETRIES,
        };
        let _ = api.health().await;
        let fresh = api.reconnect().unwrap();
        let _ = fresh.health().await;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2, "each client must dial for itself");
    }

    #[test]
    fn idle_connections_are_dropped_before_a_browser_round_trip_could_kill_them() {
        // Android destroyed this app's sockets 5.5s after it was backgrounded;
        // see IDLE_CONNECTION_LIFETIME for where that number comes from.
        assert!(IDLE_CONNECTION_LIFETIME < std::time::Duration::from_millis(5500));
    }
}
