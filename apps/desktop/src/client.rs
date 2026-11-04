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
    /// 409: the secret changed under us (key rotated, membership changed, or
    /// a duplicate); callers may refresh and retry once.
    #[error("{0}")]
    Conflict(String),
    #[error("your session has expired; please log in again")]
    Unauthorized,
    #[error("invalid server URL: {0}")]
    InvalidUrl(String),
}

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
        let mut request = self.http.request(method, format!("{}/api{path}", self.base_url));
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
        let message =
            response.json::<ErrorBody>().await.map(|b| b.error).unwrap_or_else(|_| format!("server returned {status}"));
        if status == StatusCode::CONFLICT {
            return Err(ClientError::Conflict(message));
        }
        Err(ClientError::Server(message))
    }

    const NO_BODY: Option<&()> = None;

    pub async fn register(&self, body: &RegisterRequest) -> Result<SessionResponse, ClientError> {
        self.send(Method::POST, "/register", Some(body)).await
    }

    pub async fn login(&self, body: &LoginRequest) -> Result<SessionResponse, ClientError> {
        self.send(Method::POST, "/login", Some(body)).await
    }

    pub async fn logout(&self) -> Result<(), ClientError> {
        self.send(Method::POST, "/logout", Self::NO_BODY).await
    }

    pub async fn lookup_user(&self, email: &str) -> Result<PublicUser, ClientError> {
        let path = format!("/users/lookup?email={}", urlencode(email));
        self.send(Method::GET, &path, Self::NO_BODY).await
    }

    pub async fn list_secrets(&self) -> Result<Vec<SecretView>, ClientError> {
        self.send(Method::GET, "/secrets", Self::NO_BODY).await
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

    pub async fn upgrade_owner_key(&self, id: i64, body: &UpgradeOwnerKeyRequest) -> Result<(), ClientError> {
        self.send(Method::PUT, &format!("/secrets/{id}/owner-key"), Some(body)).await
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
