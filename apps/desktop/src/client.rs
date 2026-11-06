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

#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
    token: Option<String>,
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
            .build()
            .map_err(|e| ClientError::Network(e.to_string()))?;
        Ok(Self { http, base_url: server_url.to_string(), token: None })
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
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
        let mut request = self.http.request(method, &url);
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|e| ClientError::Network(e.to_string()))?;
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

    const NO_BODY: Option<&()> = None;

    /// The server's protocol numbers. Outside `/api`, so this is the same
    /// document an operator curls.
    ///
    /// A 200 that is not this document means the far end is not a credvault
    /// server this build can talk to, so it is reported as an incompatibility
    /// rather than as a malformed response.
    pub async fn health(&self) -> Result<Health, ClientError> {
        let url = format!("{}/health", self.base_url);
        let response = self.http.get(&url).send().await.map_err(|e| ClientError::Network(e.to_string()))?;
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
}
