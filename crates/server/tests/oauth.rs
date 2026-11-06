//! End-to-end tests for sign in with Google.
//!
//! A stub provider stands in for Google: the protocol work it would do is
//! unit-tested in `credvault_server::oauth`, and what matters here is what the
//! server does with an identity once it has one. Nothing in this file touches
//! the network.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use credvault_core::kdf::ServerAddress;
use credvault_core::{Identity, MasterKey};
use credvault_server::api::*;
use credvault_server::error::ApiError;
use credvault_server::oauth::{AuthorizationRequest, BoxFuture, ExchangeRequest, OAuthProvider, VerifiedIdentity};
use credvault_server::{RegistrationPolicy, ServerConfig};
use reqwest::{Client, StatusCode};
use sqlx::SqlitePool;

const REDIRECT: &str = "http://127.0.0.1:49152/callback";

/// Stands in for Google. Hands out identities for codes it was told about,
/// and records what it was asked so tests can check the parameters the server
/// generated actually reach the provider.
#[derive(Default)]
struct StubProvider {
    identities: Mutex<HashMap<String, VerifiedIdentity>>,
    issued: Mutex<HashMap<String, AuthorizationRequest>>,
    exchanges: Mutex<Vec<(String, String, String)>>,
}

impl StubProvider {
    fn with_code(code: &str, subject: &str, email: &str) -> Arc<Self> {
        let stub = Arc::new(Self::default());
        stub.add_code(code, subject, email);
        stub
    }

    fn add_code(&self, code: &str, subject: &str, email: &str) {
        self.identities
            .lock()
            .unwrap()
            .insert(code.to_string(), VerifiedIdentity { subject: subject.into(), email: email.into() });
    }

    /// The authorization request the server built for `state`.
    fn issued_for(&self, state: &str) -> AuthorizationRequest {
        self.issued.lock().unwrap().get(state).expect("no authorization url issued for that state").clone()
    }

    /// (code, code_verifier, nonce) for every exchange attempted.
    fn exchanges(&self) -> Vec<(String, String, String)> {
        self.exchanges.lock().unwrap().clone()
    }
}

impl OAuthProvider for StubProvider {
    fn authorization_url(&self, request: &AuthorizationRequest) -> String {
        self.issued.lock().unwrap().insert(request.state.clone(), request.clone());
        format!("https://stub.invalid/auth?state={}", request.state)
    }

    fn exchange<'a>(&'a self, request: ExchangeRequest) -> BoxFuture<'a, Result<VerifiedIdentity, ApiError>> {
        Box::pin(async move {
            self.exchanges.lock().unwrap().push((
                request.code.to_string(),
                request.code_verifier.to_string(),
                request.nonce.clone(),
            ));
            self.identities
                .lock()
                .unwrap()
                .get(request.code.as_str())
                .cloned()
                .ok_or_else(|| ApiError::BadRequest("the sign-in could not be completed; start it again".into()))
        })
    }
}

struct TestServer {
    base: String,
    /// The address a user would type; the auth hash is bound to it.
    address: ServerAddress,
    client: Client,
    pool: SqlitePool,
    _dir: tempfile::TempDir,
}

/// Deliberately a local copy rather than a shared harness: this file needs a
/// configured provider and `tests/api.rs` needs none, and the overlap is a
/// handful of lines of setup.
async fn spawn_with(config: ServerConfig) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let pool = credvault_server::connect(&dir.path().join("test.db")).await.unwrap();
    let app = credvault_server::build_router(pool.clone(), config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap()
    });
    TestServer {
        base: format!("http://{addr}/api"),
        address: ServerAddress::parse(&format!("http://{addr}")).unwrap(),
        client: Client::new(),
        pool,
        _dir: dir,
    }
}

async fn spawn(provider: Arc<StubProvider>) -> TestServer {
    spawn_with(ServerConfig { oauth: Some(provider), ..Default::default() }).await
}

impl TestServer {
    async fn post(&self, path: &str, body: serde_json::Value) -> reqwest::Response {
        self.client.post(format!("{}{path}", self.base)).json(&body).send().await.unwrap()
    }

    async fn start(&self, purpose: &str) -> OAuthStartResponse {
        self.start_as(purpose, None).await
    }

    /// Starting a link needs the session the identity will be bound to;
    /// starting a sign-in is anonymous.
    async fn start_as(&self, purpose: &str, token: Option<&str>) -> OAuthStartResponse {
        let response = self.start_response(purpose, token).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", response.text().await.unwrap());
        response.json().await.unwrap()
    }

    async fn start_response(&self, purpose: &str, token: Option<&str>) -> reqwest::Response {
        let mut request = self
            .client
            .post(format!("{}/oauth/start", self.base))
            .json(&serde_json::json!({ "redirect_uri": REDIRECT, "purpose": purpose }));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request.send().await.unwrap()
    }

    /// Redeeming takes the whole start response: the state names the attempt,
    /// the app secret proves this client is the one that began it.
    async fn callback(&self, started: &OAuthStartResponse, code: &str) -> reqwest::Response {
        self.post(
            "/oauth/callback",
            serde_json::json!({ "state": started.state, "app_secret": started.app_secret.as_str(), "code": code }),
        )
        .await
    }

    async fn capabilities(&self) -> Capabilities {
        self.client.get(format!("{}/capabilities", self.base)).send().await.unwrap().json().await.unwrap()
    }
}

/// Complete a first sign-in: start, exchange, then create the account with a
/// key pair derived from `passphrase` and the address Google vouched for.
/// Returns the session and the email the server settled on.
async fn sign_up(
    server: &TestServer,
    code: &str,
    passphrase: &str,
    registration_token: Option<&str>,
) -> (SessionResponse, String) {
    let started = server.start("sign_in").await;
    let response = server.callback(&started, code).await;
    assert_eq!(response.status(), StatusCode::OK, "{}", response.text().await.unwrap());
    let (ticket, email) = match response.json::<OAuthCallbackResponse>().await.unwrap() {
        OAuthCallbackResponse::RegistrationRequired { ticket, email } => (ticket, email),
        OAuthCallbackResponse::SignedIn(_) => panic!("expected a new account to be required"),
    };

    // The client prompts for a passphrase only now, and derives from the
    // address the server reported, because that address is the KDF salt.
    let master = MasterKey::derive(passphrase, &email).unwrap();
    let identity = Identity::generate();
    let body = OAuthRegisterRequest {
        ticket,
        public_key: identity.public_key().clone(),
        encrypted_private_key: identity.encrypt_private_key(&master.private_key_encryption_key()),
        registration_token: registration_token.map(str::to_string),
    };
    let created = server.post("/oauth/register", serde_json::to_value(&body).unwrap()).await;
    assert_eq!(created.status(), StatusCode::CREATED, "{}", created.text().await.unwrap());
    (created.json().await.unwrap(), email)
}

#[tokio::test]
async fn capabilities_say_whether_the_button_should_be_shown() {
    let off = spawn_with(ServerConfig::default()).await.capabilities().await;
    assert!(!off.google_sign_in);
    assert!(off.password_sign_in);
    assert!(!off.registration_token_required);
    assert!(!off.registration_closed);

    let on = spawn(Arc::new(StubProvider::default())).await.capabilities().await;
    assert!(on.google_sign_in);

    let gated = spawn_with(ServerConfig {
        oauth: Some(Arc::new(StubProvider::default())),
        registration: RegistrationPolicy::Token("tok".into()),
        ..Default::default()
    })
    .await
    .capabilities()
    .await;
    assert!(gated.google_sign_in);
    assert!(gated.registration_token_required);
}

#[tokio::test]
async fn the_endpoints_are_absent_when_google_is_not_configured() {
    let server = spawn_with(ServerConfig::default()).await;
    for (path, body) in [
        ("/oauth/start", serde_json::json!({ "redirect_uri": REDIRECT })),
        ("/oauth/callback", serde_json::json!({ "state": "s", "app_secret": "a", "code": "c" })),
        (
            "/oauth/register",
            serde_json::json!({ "ticket": "t", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "encrypted_private_key": { "v": 1, "nonce": "AAAAAAAAAAAAAAAA", "ciphertext": "AA==" } }),
        ),
    ] {
        let response = server.post(path, body).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn first_sign_in_creates_an_account_and_later_ones_reuse_it() {
    let stub = StubProvider::with_code("code-1", "google-sub-1", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;

    let (session, email) = sign_up(&server, "code-1", "correct horse battery", None).await;
    assert_eq!(email, "kat@example.com");
    assert_eq!(session.user.email, "kat@example.com");

    // The vault still decrypts only with the passphrase: the server stored a
    // private key it cannot open, and Google was never involved in the key.
    let master = MasterKey::derive("correct horse battery", &email).unwrap();
    let recovered =
        Identity::decrypt_private_key(&master.private_key_encryption_key(), &session.user.encrypted_private_key)
            .unwrap();
    assert_eq!(recovered.public_key(), &session.user.public_key);
    assert!(Identity::decrypt_private_key(
        &MasterKey::derive("wrong passphrase here", &email).unwrap().private_key_encryption_key(),
        &session.user.encrypted_private_key
    )
    .is_err());

    // Signing in again returns the same account, with no second registration.
    stub.add_code("code-2", "google-sub-1", "kat@example.com");
    let started = server.start("sign_in").await;
    let response = server.callback(&started, "code-2").await;
    assert_eq!(response.status(), StatusCode::OK);
    match response.json::<OAuthCallbackResponse>().await.unwrap() {
        OAuthCallbackResponse::SignedIn(second) => {
            assert_eq!(second.user.id, session.user.id);
            assert_ne!(second.token, session.token);
        }
        OAuthCallbackResponse::RegistrationRequired { .. } => panic!("the account should already exist"),
    }
}

#[tokio::test]
async fn the_identity_is_followed_not_the_address() {
    let stub = StubProvider::with_code("code-1", "google-sub-1", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;
    let (session, _) = sign_up(&server, "code-1", "correct horse battery", None).await;

    // Google changed the address on the same account. The account is found by
    // subject, and its email — the key-derivation salt — is left alone, or
    // every secret it holds would become undecryptable.
    stub.add_code("code-2", "google-sub-1", "kat.new@example.com");
    let started = server.start("sign_in").await;
    let response = server.callback(&started, "code-2").await;
    match response.json::<OAuthCallbackResponse>().await.unwrap() {
        OAuthCallbackResponse::SignedIn(second) => {
            assert_eq!(second.user.id, session.user.id);
            assert_eq!(second.user.email, "kat@example.com");
        }
        OAuthCallbackResponse::RegistrationRequired { .. } => panic!("the subject is unchanged"),
    }

    // A different subject with the *same* address is a different person and
    // must not be handed the account.
    stub.add_code("code-3", "google-sub-2", "kat@example.com");
    let started = server.start("sign_in").await;
    let response = server.callback(&started, "code-3").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn parameters_generated_by_the_server_reach_the_provider() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;

    let started = server.start("sign_in").await;
    assert!(started.authorization_url.contains(&started.state));
    let issued = stub.issued_for(&started.state);
    assert_eq!(issued.redirect_uri, REDIRECT);
    assert!(!issued.nonce.is_empty());
    assert_ne!(issued.nonce, started.state);

    server.callback(&started, "code-1").await;
    let exchanges = stub.exchanges();
    assert_eq!(exchanges.len(), 1);
    let (code, verifier, nonce) = &exchanges[0];
    assert_eq!(code, "code-1");
    assert_eq!(nonce, &issued.nonce, "the nonce must be the one this attempt issued");
    // The verifier is the secret half of the challenge that was published.
    assert!(!verifier.is_empty());
    assert_ne!(verifier, &issued.code_challenge);
}

/// A password account and a session for it, for the flows that need one.
async fn password_session(server: &TestServer, email: &str) -> SessionResponse {
    let identity = Identity::generate();
    let master = MasterKey::derive("correct horse battery staple", email).unwrap();
    server
        .post(
            "/register",
            serde_json::to_value(&RegisterRequest {
                email: email.into(),
                auth_hash: master.auth_hash(&server.address),
                public_key: identity.public_key().clone(),
                encrypted_private_key: identity.encrypt_private_key(&master.private_key_encryption_key()),
                registration_token: None,
            })
            .unwrap(),
        )
        .await
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_state_is_single_use_and_tied_to_what_it_was_started_for() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;

    let started = server.start("sign_in").await;
    assert_eq!(server.callback(&started, "code-1").await.status(), StatusCode::OK);
    // Replaying the same state must not start a second exchange.
    assert_eq!(server.callback(&started, "code-1").await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(stub.exchanges().len(), 1);

    // A state issued for linking cannot be completed as a sign-in. Starting a
    // link needs a session, so this takes a password account rather than the
    // sign-in above, which only produced a registration ticket.
    let session = password_session(&server, "linker@example.com").await;
    let link = server.start_as("link", Some(&session.token)).await;
    assert_eq!(server.callback(&link, "code-1").await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(stub.exchanges().len(), 1, "a mismatched purpose must not reach the provider");

    // Nor can an invented state, nor the right state with the wrong secret.
    let invented = OAuthStartResponse {
        state: "not-a-real-state".into(),
        app_secret: started.app_secret.clone(),
        authorization_url: String::new(),
    };
    assert_eq!(server.callback(&invented, "code-1").await.status(), StatusCode::BAD_REQUEST);
}

/// The secret never travels through the browser, so holding `state` and
/// `code` — everything visible in an address bar or in history — is not
/// enough to finish someone else's sign-in.
#[tokio::test]
async fn a_callback_without_the_app_secret_is_refused() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;
    let started = server.start("sign_in").await;

    let stolen = OAuthStartResponse {
        state: started.state.clone(),
        app_secret: zeroize::Zeroizing::new("guessed".into()),
        authorization_url: String::new(),
    };
    assert_eq!(server.callback(&stolen, "code-1").await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(stub.exchanges().len(), 0, "a wrong secret must not reach the provider");

    // And the attempt was not spent by the attacker: the real client still
    // completes. A wrong secret finds no row rather than deleting one.
    assert_eq!(server.callback(&started, "code-1").await.status(), StatusCode::OK);
}

/// A link attempt records the account it was started from, and that account is
/// part of what selects it. Another session holding every travelling value
/// cannot redeem it, and — because the owner is matched in the same statement
/// that deletes the row — cannot burn it either.
#[tokio::test]
async fn a_link_cannot_be_finished_by_a_different_session() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;
    let alice = password_session(&server, "alice@example.com").await;
    let mallory = password_session(&server, "mallory@example.com").await;

    let link = async |started: &OAuthStartResponse, token: &str| {
        server
            .client
            .post(format!("{}/oauth/link", server.base))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "state": started.state, "app_secret": started.app_secret.as_str(), "code": "code-1"
            }))
            .send()
            .await
            .unwrap()
    };

    let started = server.start_as("link", Some(&alice.token)).await;
    assert_eq!(link(&started, &mallory.token).await.status(), StatusCode::BAD_REQUEST);
    assert_eq!(stub.exchanges().len(), 0, "a wrong session must not reach the provider");

    // The attempt survived the attempt to steal it, so Alice still finishes.
    assert_eq!(link(&started, &alice.token).await.status(), StatusCode::NO_CONTENT);
}

/// Starting a link says which account the identity will be bound to, so it
/// needs that account's session.
#[tokio::test]
async fn starting_a_link_without_a_session_is_refused() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;
    assert_eq!(server.start_response("link", None).await.status(), StatusCode::UNAUTHORIZED);
    // A sign-in has no account yet and stays anonymous.
    assert_eq!(server.start_response("sign_in", None).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_expired_attempt_is_refused() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;
    let started = server.start("sign_in").await;

    sqlx::query("UPDATE oauth_attempts SET expires_at = 1").execute(&server.pool).await.unwrap();

    assert_eq!(server.callback(&started, "code-1").await.status(), StatusCode::BAD_REQUEST);
    assert!(stub.exchanges().is_empty());
}

#[tokio::test]
async fn the_redirect_must_be_a_loopback_address() {
    let server = spawn(Arc::new(StubProvider::default())).await;
    for bad in ["https://evil.example.com/cb", "http://127.0.0.1/cb", "http://localhost:8080/cb", "nonsense"] {
        let response = server.post("/oauth/start", serde_json::json!({ "redirect_uri": bad })).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn a_code_the_provider_rejects_fails_without_creating_anything() {
    let server = spawn(Arc::new(StubProvider::default())).await;
    let started = server.start("sign_in").await;
    assert_eq!(server.callback(&started, "never-issued").await.status(), StatusCode::BAD_REQUEST);

    let accounts: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users").fetch_one(&server.pool).await.unwrap();
    assert_eq!(accounts.0, 0);
}

#[tokio::test]
async fn signing_up_through_google_still_needs_the_registration_token() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn_with(ServerConfig {
        oauth: Some(Arc::clone(&stub) as Arc<dyn OAuthProvider>),
        registration: RegistrationPolicy::Token("let-me-in".into()),
        ..Default::default()
    })
    .await;

    let started = server.start("sign_in").await;
    let response = server.callback(&started, "code-1").await;
    let ticket = match response.json::<OAuthCallbackResponse>().await.unwrap() {
        OAuthCallbackResponse::RegistrationRequired { ticket, .. } => ticket,
        OAuthCallbackResponse::SignedIn(_) => panic!("no account exists yet"),
    };

    let identity = Identity::generate();
    let master = MasterKey::derive("correct horse battery", "kat@example.com").unwrap();
    let mut body = serde_json::to_value(&OAuthRegisterRequest {
        ticket: ticket.clone(),
        public_key: identity.public_key().clone(),
        encrypted_private_key: identity.encrypt_private_key(&master.private_key_encryption_key()),
        registration_token: None,
    })
    .unwrap();

    assert_eq!(server.post("/oauth/register", body.clone()).await.status(), StatusCode::FORBIDDEN);
    body["registration_token"] = serde_json::json!("wrong");
    assert_eq!(server.post("/oauth/register", body.clone()).await.status(), StatusCode::FORBIDDEN);

    // The ticket survives a rejected token, so the user can be asked again
    // without going back through Google.
    body["registration_token"] = serde_json::json!("let-me-in");
    assert_eq!(server.post("/oauth/register", body.clone()).await.status(), StatusCode::CREATED);
    // ...but not twice.
    assert_eq!(server.post("/oauth/register", body).await.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_address_that_already_has_a_password_account_is_not_adopted() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;

    // An ordinary password registration for the same address.
    let identity = Identity::generate();
    let master = MasterKey::derive("correct horse battery", "kat@example.com").unwrap();
    let registered = server
        .post(
            "/register",
            serde_json::to_value(&RegisterRequest {
                email: "kat@example.com".into(),
                auth_hash: master.auth_hash(&server.address),
                public_key: identity.public_key().clone(),
                encrypted_private_key: identity.encrypt_private_key(&master.private_key_encryption_key()),
                registration_token: None,
            })
            .unwrap(),
        )
        .await;
    assert_eq!(registered.status(), StatusCode::CREATED);

    let started = server.start("sign_in").await;
    let response = server.callback(&started, "code-1").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(response.text().await.unwrap().contains("link Google"));
}

#[tokio::test]
async fn a_google_account_cannot_be_signed_into_with_a_password() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;
    let (_, email) = sign_up(&server, "code-1", "correct horse battery", None).await;

    // The passphrase unlocks the vault; it is not a server credential for
    // this account, and the stored hash matches nothing anyone can present.
    let master = MasterKey::derive("correct horse battery", &email).unwrap();
    let response = server
        .post(
            "/login",
            serde_json::to_value(&LoginRequest { email, auth_hash: master.auth_hash(&server.address) }).unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn linking_lets_a_password_account_use_the_button() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;

    let identity = Identity::generate();
    let master = MasterKey::derive("correct horse battery", "kat@example.com").unwrap();
    let session: SessionResponse = server
        .post(
            "/register",
            serde_json::to_value(&RegisterRequest {
                email: "kat@example.com".into(),
                auth_hash: master.auth_hash(&server.address),
                public_key: identity.public_key().clone(),
                encrypted_private_key: identity.encrypt_private_key(&master.private_key_encryption_key()),
                registration_token: None,
            })
            .unwrap(),
        )
        .await
        .json()
        .await
        .unwrap();

    let link = async |started: &OAuthStartResponse, code: &str, token: &str| {
        server
            .client
            .post(format!("{}/oauth/link", server.base))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "state": started.state, "app_secret": started.app_secret.as_str(), "code": code
            }))
            .send()
            .await
            .unwrap()
    };

    // Linking requires a session.
    let started = server.start_as("link", Some(&session.token)).await;
    let anonymous = server.post("/oauth/link", serde_json::json!({ "state": started.state, "code": "code-1" })).await;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let started = server.start_as("link", Some(&session.token)).await;
    assert_eq!(link(&started, "code-1", &session.token).await.status(), StatusCode::NO_CONTENT);

    // The account email is untouched, because it is the key-derivation salt.
    let started = server.start("sign_in").await;
    stub.add_code("code-2", "sub", "kat.renamed@example.com");
    let response = server.callback(&started, "code-2").await;
    match response.json::<OAuthCallbackResponse>().await.unwrap() {
        OAuthCallbackResponse::SignedIn(signed_in) => {
            assert_eq!(signed_in.user.id, session.user.id);
            assert_eq!(signed_in.user.email, "kat@example.com");
        }
        OAuthCallbackResponse::RegistrationRequired { .. } => panic!("the identity was linked"),
    }

    // Linking the same identity, or a second one to the same account, is a
    // conflict rather than a silent extra sign-in path.
    let started = server.start_as("link", Some(&session.token)).await;
    assert_eq!(link(&started, "code-1", &session.token).await.status(), StatusCode::CONFLICT);
    stub.add_code("code-3", "other-sub", "someone@example.com");
    let started = server.start_as("link", Some(&session.token)).await;
    assert_eq!(link(&started, "code-3", &session.token).await.status(), StatusCode::CONFLICT);
}

/// A Google account still has a vault passphrase, and still needs a way to
/// rotate it. Doing so must not quietly give it a password login as well.
#[tokio::test]
async fn a_google_account_can_change_its_passphrase_without_gaining_a_password() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;
    let (session, email) = sign_up(&server, "code-1", "first-passphrase-here", None).await;
    assert!(!session.user.password_login, "a Google account has no password login");

    let old = MasterKey::derive("first-passphrase-here", &email).unwrap();
    let new = MasterKey::derive("second-passphrase-ok", &email).unwrap();
    let identity =
        Identity::decrypt_private_key(&old.private_key_encryption_key(), &session.user.encrypted_private_key).unwrap();

    // No credential either way: there is none to prove and none to set.
    let body = ChangePasswordRequest {
        current_auth_hash: None,
        new_auth_hash: None,
        encrypted_private_key: identity.encrypt_private_key(&new.private_key_encryption_key()),
        rewrapped_keys: Vec::new(),
    };
    let response = server
        .client
        .post(format!("{}/password", server.base))
        .bearer_auth(&session.token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{}", response.text().await.unwrap());
    let fresh: SessionResponse = response.json().await.unwrap();
    assert!(!fresh.user.password_login, "still no password login");

    // The new passphrase opens the private key; the old one does not.
    assert!(Identity::decrypt_private_key(&new.private_key_encryption_key(), &fresh.user.encrypted_private_key).is_ok());
    assert!(
        Identity::decrypt_private_key(&old.private_key_encryption_key(), &fresh.user.encrypted_private_key).is_err()
    );

    // And the passphrase did not become a server credential.
    let attempt = server
        .post(
            "/login",
            serde_json::to_value(&LoginRequest { email: email.to_string(), auth_hash: new.auth_hash(&server.address) })
                .unwrap(),
        )
        .await;
    assert_eq!(attempt.status(), StatusCode::UNAUTHORIZED);
}

/// Offering a credential for an account that has no password login is a
/// mistake worth refusing loudly rather than ignoring.
#[tokio::test]
async fn a_google_account_cannot_set_a_password_through_the_passphrase_change() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;
    let (session, email) = sign_up(&server, "code-1", "first-passphrase-here", None).await;

    let new = MasterKey::derive("second-passphrase-ok", &email).unwrap();
    let identity = Identity::decrypt_private_key(
        &MasterKey::derive("first-passphrase-here", &email).unwrap().private_key_encryption_key(),
        &session.user.encrypted_private_key,
    )
    .unwrap();
    let body = ChangePasswordRequest {
        current_auth_hash: None,
        new_auth_hash: Some(new.auth_hash(&server.address)),
        encrypted_private_key: identity.encrypt_private_key(&new.private_key_encryption_key()),
        rewrapped_keys: Vec::new(),
    };
    let response = server
        .client
        .post(format!("{}/password", server.base))
        .bearer_auth(&session.token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Records the exception documented on `ChangePasswordRequest`: for a Google
/// account the server has nothing to verify, so a session is enough. If this
/// ever stops being true, this test is what says so.
#[tokio::test]
async fn a_google_session_alone_can_replace_the_vault_keys() {
    let stub = StubProvider::with_code("code-1", "sub", "kat@example.com");
    let server = spawn(Arc::clone(&stub)).await;
    let (session, email) = sign_up(&server, "code-1", "first-passphrase-here", None).await;

    // Nothing derived from the current passphrase is presented, and nothing
    // the server holds can tell that these bytes are not a real key.
    let nonsense = MasterKey::derive("attacker-chosen-pass", &email).unwrap();
    let identity = Identity::generate();
    let body = ChangePasswordRequest {
        current_auth_hash: None,
        new_auth_hash: None,
        encrypted_private_key: identity.encrypt_private_key(&nonsense.private_key_encryption_key()),
        rewrapped_keys: Vec::new(),
    };
    let response = server
        .client
        .post(format!("{}/password", server.base))
        .bearer_auth(&session.token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "a Google session is sufficient today");
}
