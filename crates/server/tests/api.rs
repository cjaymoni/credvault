//! End-to-end tests driving the server the way the desktop client does,
//! including real client-side encryption from credvault-core.

use std::net::SocketAddr;

use credvault_core::api::MAX_BLOB_BYTES;
use credvault_core::{Identity, MasterKey, Sealed, SecretKey, SecretPayload, WrappedKey};
use credvault_server::api::*;
use credvault_server::{RateLimits, RegistrationPolicy, ServerConfig};
use reqwest::{Client, Method, StatusCode};
use serde_json::json;
use sqlx::SqlitePool;
use zeroize::Zeroizing;

struct TestServer {
    base: String,
    client: Client,
    pool: SqlitePool,
    _dir: tempfile::TempDir,
}

async fn spawn() -> TestServer {
    spawn_with(ServerConfig::default()).await
}

async fn spawn_with(config: ServerConfig) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let pool = credvault_server::connect(&dir.path().join("test.db")).await.unwrap();
    let app = credvault_server::build_router(pool.clone(), config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap()
    });
    TestServer { base: format!("http://{addr}/api"), client: Client::new(), pool, _dir: dir }
}

struct Account {
    id: i64,
    email: String,
    token: String,
    identity: Identity,
    /// Derived from the master key; wraps this account's own copies of secret keys.
    self_wrap_key: Zeroizing<[u8; 32]>,
}

fn register_body(email: &str, password: &str, identity: &Identity) -> RegisterRequest {
    register_body_from(&MasterKey::derive(password, email).unwrap(), email, identity)
}

fn register_body_from(master: &MasterKey, email: &str, identity: &Identity) -> RegisterRequest {
    RegisterRequest {
        email: email.to_string(),
        auth_hash: master.auth_hash(),
        public_key: identity.public_key().clone(),
        encrypted_private_key: identity.encrypt_private_key(&master.private_key_encryption_key()),
        registration_token: None,
    }
}

/// Argon2id at the real cost is ~0.3 s; tests call it a handful of times only.
async fn register(server: &TestServer, email: &str, password: &str) -> Account {
    let identity = Identity::generate();
    let master = MasterKey::derive(password, email).unwrap();
    let body = register_body_from(&master, email, &identity);
    let response = server.client.post(format!("{}/register", server.base)).json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let session: SessionResponse = response.json().await.unwrap();
    Account {
        id: session.user.id,
        email: session.user.email,
        token: session.token,
        identity,
        self_wrap_key: master.self_wrap_key(),
    }
}

async fn login(server: &TestServer, email: &str, auth_hash: Zeroizing<String>) -> reqwest::Response {
    server
        .client
        .post(format!("{}/login", server.base))
        .json(&LoginRequest { email: email.into(), auth_hash })
        .send()
        .await
        .unwrap()
}

impl TestServer {
    fn req(&self, method: Method, path: &str, account: &Account) -> reqwest::RequestBuilder {
        self.client.request(method, format!("{}{path}", self.base)).bearer_auth(&account.token)
    }

    async fn create_secret(&self, account: &Account, name: &str, payload: &SecretPayload) -> (i64, SecretKey) {
        let key = SecretKey::generate();
        let body = CreateSecretRequest {
            name: name.into(),
            payload: key.encrypt(name, payload).unwrap(),
            wrapped_key: WrappedKey::Owner(key.wrap_for_owner(&account.self_wrap_key)),
        };
        let response = self.req(Method::POST, "/secrets", account).json(&body).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let created: Created = response.json().await.unwrap();
        (created.id, key)
    }

    async fn list(&self, account: &Account) -> Vec<SecretView> {
        self.req(Method::GET, "/secrets", account).send().await.unwrap().json().await.unwrap()
    }

    async fn access(&self, account: &Account, secret_id: i64) -> AccessView {
        let response = self.req(Method::GET, &format!("/secrets/{secret_id}/access"), account).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.unwrap()
    }

    async fn invite(&self, owner: &Account, secret_id: i64, key: &SecretKey, email: &str) -> reqwest::Response {
        let lookup: PublicUser = self
            .req(Method::GET, &format!("/users/lookup?email={email}"), owner)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let key_version = self.key_version(owner, secret_id).await;
        let body = InviteRequest {
            key_version,
            email: email.into(),
            wrapped_key: key.wrap_for(&lookup.public_key).unwrap(),
            message: "for you".into(),
        };
        self.req(Method::POST, &format!("/secrets/{secret_id}/invites"), owner).json(&body).send().await.unwrap()
    }

    /// The version the owner currently sees, or 0 when the caller cannot see the secret.
    async fn key_version(&self, account: &Account, secret_id: i64) -> i64 {
        self.list(account).await.into_iter().find(|v| v.id == secret_id).map(|v| v.key_version).unwrap_or(0)
    }

    async fn accept(&self, account: &Account, invite_id: i64) {
        let response = self.req(Method::POST, &format!("/invites/{invite_id}/accept"), account).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    /// Revoke `member` the way the desktop client does: rotate the key and
    /// re-wrap for everyone still listed, plus the owner.
    async fn revoke(
        &self,
        owner: &Account,
        secret_id: i64,
        member: i64,
        payload: &SecretPayload,
    ) -> (reqwest::Response, SecretKey) {
        let view = self.list(owner).await.into_iter().find(|v| v.id == secret_id).unwrap();
        // A non-owner caller cannot read the access list; send only their own key.
        let members = match self.req(Method::GET, &format!("/secrets/{secret_id}/access"), owner).send().await {
            Ok(response) if response.status() == StatusCode::OK => response.json::<AccessView>().await.unwrap().members,
            _ => Vec::new(),
        };
        let new_key = SecretKey::generate();
        let mut wrapped_keys = vec![WrappedKeyFor {
            user_id: owner.id,
            wrapped_key: WrappedKey::Owner(new_key.wrap_for_owner(&owner.self_wrap_key)),
        }];
        for m in members.iter().filter(|m| m.user_id != member) {
            wrapped_keys.push(WrappedKeyFor {
                user_id: m.user_id,
                wrapped_key: WrappedKey::Shared(new_key.wrap_for(&m.public_key).unwrap()),
            });
        }
        let body = RevokeAccessRequest {
            key_version: view.key_version,
            payload: new_key.encrypt(&view.name, payload).unwrap(),
            wrapped_keys,
        };
        let response = self
            .req(Method::POST, &format!("/secrets/{secret_id}/access/{member}/revoke"), owner)
            .json(&body)
            .send()
            .await
            .unwrap();
        (response, new_key)
    }
}

fn payload() -> SecretPayload {
    SecretPayload {
        username: "jude".into(),
        password: "hunter2!".into(),
        url: "https://example.com".into(),
        notes: String::new(),
    }
}

/// Open whichever form of wrapped key the view carries for this account.
fn unwrap_key(view: &SecretView, account: &Account) -> SecretKey {
    match &view.wrapped_key {
        WrappedKey::Owner(sealed) => SecretKey::unwrap_owner(&account.self_wrap_key, sealed).unwrap(),
        WrappedKey::Shared(boxed) => SecretKey::unwrap_with(&account.identity, boxed).unwrap(),
    }
}

fn decrypt(view: &SecretView, account: &Account) -> SecretPayload {
    unwrap_key(view, account).decrypt(&view.name, &view.payload).unwrap()
}

async fn error_text(response: reqwest::Response) -> String {
    response.json::<serde_json::Value>().await.unwrap()["error"].as_str().unwrap().to_string()
}

// ----- accounts -------------------------------------------------------------

#[tokio::test]
async fn register_login_and_recover_identity() {
    let server = spawn().await;
    let alice = register(&server, "Alice@Example.com", "alice-password").await;
    assert_eq!(alice.email, "alice@example.com");

    let master = MasterKey::derive("alice-password", "alice@example.com").unwrap();
    let response = login(&server, "ALICE@example.com", master.auth_hash()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let session: SessionResponse = response.json().await.unwrap();
    let identity =
        Identity::decrypt_private_key(&master.private_key_encryption_key(), &session.user.encrypted_private_key)
            .unwrap();
    assert_eq!(identity.public_key(), alice.identity.public_key());

    // Wrong password and unknown email both get the same 401.
    let wrong = MasterKey::derive("wrong-password", "alice@example.com").unwrap();
    for (email, hash) in [("alice@example.com", wrong.auth_hash()), ("nobody@example.com", master.auth_hash())] {
        assert_eq!(login(&server, email, hash).await.status(), StatusCode::UNAUTHORIZED);
    }
    // A malformed auth hash is rejected before any work is done.
    assert_eq!(
        login(&server, "alice@example.com", Zeroizing::new("x".repeat(100_000))).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        login(&server, "alice@example.com", Zeroizing::new(String::new())).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn duplicate_email_rejected() {
    let server = spawn().await;
    register(&server, "dup@example.com", "dup-password").await;
    let body = register_body("DUP@example.com", "other-password", &Identity::generate());
    let response = server.client.post(format!("{}/register", server.base)).json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn each_invalid_registration_field_is_rejected_without_creating_an_account() {
    // More attempts than the production registration burst allows.
    let lenient = RateLimits { register_burst: 100, ..Default::default() };
    let server = spawn_with(ServerConfig { rate_limits: lenient, ..Default::default() }).await;
    let good =
        serde_json::to_value(register_body("fresh@example.com", "fresh-password", &Identity::generate())).unwrap();
    let cases: Vec<(&str, serde_json::Value)> = vec![
        ("email", json!("not-an-email")),
        ("email", json!("has space@example.com")),
        ("auth_hash", json!("x")),
        ("auth_hash", json!("")),
        ("public_key", json!("AAAA")),
        ("public_key", json!("not base64!")),
        ("encrypted_private_key", json!({"nonce": "", "ciphertext": ""})),
        ("encrypted_private_key", json!({"nonce": "AAAA", "ciphertext": "AAAA"})),
    ];
    for (field, value) in cases {
        let mut bad = good.clone();
        bad[field] = value.clone();
        let response = server.client.post(format!("{}/register", server.base)).json(&bad).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field} = {value}");
    }
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users").fetch_one(&server.pool).await.unwrap();
    assert_eq!(count, 0, "no half-created accounts");

    // The email is still free afterwards, and the good body works.
    let response = server.client.post(format!("{}/register", server.base)).json(&good).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn malformed_json_and_oversized_bodies_get_clear_errors() {
    let server = spawn().await;
    let response = server
        .client
        .post(format!("{}/register", server.base))
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(error_text(response).await.contains("JSON"));

    let alice = register(&server, "alice@example.com", "alice-password").await;
    let huge = json!({"name": "x", "payload": {"nonce": "AAAAAAAAAAAAAAAA", "ciphertext": "A".repeat(300 * 1024)}});
    let response = server.req(Method::POST, "/secrets", &alice).json(&huge).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn registration_can_be_closed_or_token_gated() {
    let closed = spawn_with(ServerConfig { registration: RegistrationPolicy::Closed, ..Default::default() }).await;
    let body = register_body("a@example.com", "a-password", &Identity::generate());
    let response = closed.client.post(format!("{}/register", closed.base)).json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let gated =
        spawn_with(ServerConfig { registration: RegistrationPolicy::Token("let-me-in".into()), ..Default::default() })
            .await;
    let mut body = register_body("b@example.com", "b-password", &Identity::generate());
    let response = gated.client.post(format!("{}/register", gated.base)).json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    body.registration_token = Some("wrong".into());
    let response = gated.client.post(format!("{}/register", gated.base)).json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    body.registration_token = Some("let-me-in".into());
    let response = gated.client.post(format!("{}/register", gated.base)).json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn login_and_registration_are_rate_limited_per_address() {
    let server = spawn().await;
    let master = MasterKey::derive("some-password", "nobody@example.com").unwrap();
    let mut statuses = Vec::new();
    for _ in 0..11 {
        statuses.push(login(&server, "nobody@example.com", master.auth_hash()).await.status());
    }
    assert!(statuses[..10].iter().all(|s| *s == StatusCode::UNAUTHORIZED), "{statuses:?}");
    assert_eq!(statuses[10], StatusCode::TOO_MANY_REQUESTS);
    let response = login(&server, "nobody@example.com", master.auth_hash()).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().get("retry-after").is_some());

    // Registration has its own, tighter bucket and malformed attempts count.
    let mut statuses = Vec::new();
    for i in 0..6 {
        let bad = json!({"email": format!("u{i}@example.com"), "auth_hash": "x", "public_key": "x", "encrypted_private_key": {}});
        statuses
            .push(server.client.post(format!("{}/register", server.base)).json(&bad).send().await.unwrap().status());
    }
    assert!(statuses[..5].iter().all(|s| *s == StatusCode::BAD_REQUEST), "{statuses:?}");
    assert_eq!(statuses[5], StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn unauthenticated_requests_are_rejected() {
    let server = spawn().await;
    let response = server.client.get(format!("{}/secrets", server.base)).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = server.client.get(format!("{}/secrets", server.base)).bearer_auth("bogus").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_sessions_are_rejected_and_pruned() {
    let server = spawn().await;
    let alice = register(&server, "alice@example.com", "alice-password").await;
    assert_eq!(server.req(Method::GET, "/me", &alice).send().await.unwrap().status(), StatusCode::OK);

    sqlx::query("UPDATE sessions SET expires_at = 1").execute(&server.pool).await.unwrap();
    assert_eq!(server.req(Method::GET, "/me", &alice).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // The next login prunes the expired row.
    let master = MasterKey::derive("alice-password", "alice@example.com").unwrap();
    assert_eq!(login(&server, "alice@example.com", master.auth_hash()).await.status(), StatusCode::OK);
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions").fetch_one(&server.pool).await.unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn logout_invalidates_only_that_token_and_logout_everywhere_all() {
    let server = spawn().await;
    let alice = register(&server, "alice@example.com", "alice-password").await;
    let master = MasterKey::derive("alice-password", "alice@example.com").unwrap();
    let second: SessionResponse = login(&server, "alice@example.com", master.auth_hash()).await.json().await.unwrap();
    let alice_second = with_token(&alice, second.token);

    let response = server.req(Method::POST, "/logout", &alice).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(server.req(Method::GET, "/me", &alice).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.req(Method::GET, "/me", &alice_second).send().await.unwrap().status(), StatusCode::OK);

    let third: SessionResponse = login(&server, "alice@example.com", master.auth_hash()).await.json().await.unwrap();
    let alice_third = with_token(&alice, third.token);
    let response = server.req(Method::DELETE, "/sessions", &alice_second).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(server.req(Method::GET, "/me", &alice_second).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(server.req(Method::GET, "/me", &alice_third).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

/// The same user with a different session token. The identity is unused by
/// the session tests, so a throwaway one stands in.
fn with_token(account: &Account, token: String) -> Account {
    Account {
        id: account.id,
        email: account.email.clone(),
        token,
        identity: Identity::generate(),
        self_wrap_key: account.self_wrap_key.clone(),
    }
}

#[tokio::test]
async fn lookup_validates_email_and_hides_nothing_extra() {
    let server = spawn().await;
    let alice = register(&server, "alice@example.com", "alice-password").await;
    let response = server.req(Method::GET, "/users/lookup?email=not-an-email", &alice).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = server.req(Method::GET, "/users/lookup?email=ghost@example.com", &alice).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = server.req(Method::GET, "/users/lookup?email=ALICE@example.com", &alice).send().await.unwrap();
    let user: PublicUser = response.json().await.unwrap();
    assert_eq!(user.id, alice.id);
    assert_eq!(&user.public_key, alice.identity.public_key());
}

// ----- secrets --------------------------------------------------------------

#[tokio::test]
async fn secret_lifecycle_for_owner() {
    let server = spawn().await;
    let alice = register(&server, "alice@example.com", "alice-password").await;

    let (id, key) = server.create_secret(&alice, "  GitHub ", &payload()).await;
    let listed = server.list(&alice).await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "GitHub");
    assert!(listed[0].is_owner);
    assert_eq!(decrypt(&listed[0], &alice), payload());

    // Fetching one secret matches the list entry.
    let one: SecretView =
        server.req(Method::GET, &format!("/secrets/{id}"), &alice).send().await.unwrap().json().await.unwrap();
    assert_eq!(one.id, id);
    assert_eq!(decrypt(&one, &alice), payload());
    let response = server.req(Method::GET, "/secrets/999", &alice).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // The server holds no plaintext.
    let raw = serde_json::to_string(&listed).unwrap();
    assert!(!raw.contains("hunter2"));
    assert!(!raw.contains("\"jude\""));

    let mut changed = payload();
    changed.password = "new-password".into();
    let response = server
        .req(Method::PUT, &format!("/secrets/{id}"), &alice)
        .json(&UpdateSecretRequest {
            key_version: 0,
            name: "GitHub (work)".into(),
            payload: key.encrypt("GitHub (work)", &changed).unwrap(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let listed = server.list(&alice).await;
    assert_eq!(listed[0].name, "GitHub (work)");
    assert_eq!(decrypt(&listed[0], &alice).password, "new-password");

    // Updating a nonexistent secret is a 404; an oversized blob is a 400.
    let response = server
        .req(Method::PUT, "/secrets/999", &alice)
        .json(&UpdateSecretRequest { key_version: 0, name: "x".into(), payload: key.encrypt("x", &changed).unwrap() })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let oversized = Sealed { nonce: vec![0; 12], ciphertext: vec![0; MAX_BLOB_BYTES + 1] };
    let response = server
        .req(Method::PUT, &format!("/secrets/{id}"), &alice)
        .json(&UpdateSecretRequest { key_version: 0, name: "x".into(), payload: oversized })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = server.req(Method::DELETE, &format!("/secrets/{id}"), &alice).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(server.list(&alice).await.is_empty());

    let response = server.req(Method::DELETE, &format!("/secrets/{id}"), &alice).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn renamed_payload_cannot_be_served_under_another_name() {
    let server = spawn().await;
    let alice = register(&server, "alice@example.com", "alice-password").await;
    let (id, _) = server.create_secret(&alice, "Bank", &payload()).await;
    // A malicious server relabels the row.
    sqlx::query("UPDATE secrets SET name = 'Not the bank' WHERE id = ?").bind(id).execute(&server.pool).await.unwrap();
    let view = server.list(&alice).await.remove(0);
    let key = unwrap_key(&view, &alice);
    assert!(key.decrypt(&view.name, &view.payload).is_err());
    assert!(key.decrypt("Bank", &view.payload).is_ok());
}

// ----- sharing --------------------------------------------------------------

#[tokio::test]
async fn share_one_secret_via_invite_and_revoke_rotates_the_key() {
    let server = spawn().await;
    let alice = register(&server, "alice@example.com", "alice-password").await;
    let bob = register(&server, "bob@example.com", "bob-password").await;
    let carol = register(&server, "carol@example.com", "carol-password").await;
    let (id, key) = server.create_secret(&alice, "Netflix", &payload()).await;

    // Bob sees nothing until invited and accepted.
    assert!(server.list(&bob).await.is_empty());

    let response = server.invite(&alice, id, &key, "Bob@Example.com").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let invite: Created = response.json().await.unwrap();

    let pending: Vec<InviteView> =
        server.req(Method::GET, "/invites", &bob).send().await.unwrap().json().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].secret_name, "Netflix");
    assert_eq!(pending[0].inviter_email, "alice@example.com");
    assert_eq!(pending[0].message, "for you");
    assert!(server.list(&bob).await.is_empty());

    // Owner sees the pending invite in the access list.
    let access = server.access(&alice, id).await;
    assert!(access.members.is_empty());
    assert_eq!(access.invites[0].email, "bob@example.com");

    server.accept(&bob, invite.id).await;

    let bobs = server.list(&bob).await;
    assert_eq!(bobs.len(), 1);
    assert!(!bobs[0].is_owner);
    assert_eq!(bobs[0].owner_email, "alice@example.com");
    assert_eq!(decrypt(&bobs[0], &bob), payload());
    let bobs_old_key = unwrap_key(&bobs[0], &bob);

    // Members are listed with their public key so the owner can re-wrap.
    let access = server.access(&alice, id).await;
    assert_eq!(access.members.len(), 1);
    assert_eq!(&access.members[0].public_key, bob.identity.public_key());

    // Bob cannot edit, delete for everyone, or manage access; the secret
    // simply does not exist for those operations.
    let response = server
        .req(Method::PUT, &format!("/secrets/{id}"), &bob)
        .json(&UpdateSecretRequest { key_version: 0, name: "x".into(), payload: key.encrypt("x", &payload()).unwrap() })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = server.req(Method::GET, &format!("/secrets/{id}/access"), &bob).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(server.list(&alice).await.len(), 1);

    // Inviting again is a conflict now that Bob is a member. A pending invite
    // for Carol will be cancelled by the rotation below.
    let response = server.invite(&alice, id, &key, "bob@example.com").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(server.invite(&alice, id, &key, "carol@example.com").await.status(), StatusCode::CREATED);

    // Owner revokes; Bob loses access and the key is rotated.
    let mut updated = payload();
    updated.password = "rotated".into();
    let (response, new_key) = server.revoke(&alice, id, bob.id, &updated).await;
    assert_eq!(response.status(), StatusCode::OK);
    let result: RevokeAccessResponse = response.json().await.unwrap();
    assert_eq!(result.cancelled_invites, 1);
    assert_eq!(result.key_version, 1);
    assert!(server.list(&bob).await.is_empty());
    assert!(server
        .req(Method::GET, "/invites", &carol)
        .send()
        .await
        .unwrap()
        .json::<Vec<InviteView>>()
        .await
        .unwrap()
        .is_empty());

    let alices = server.list(&alice).await;
    assert_eq!(alices.len(), 1);
    assert_eq!(alices[0].key_version, 1);
    assert_eq!(decrypt(&alices[0], &alice).password, "rotated");
    // Bob's old key no longer opens the stored payload.
    assert!(bobs_old_key.decrypt("Netflix", &alices[0].payload).is_err());
    assert!(new_key.decrypt("Netflix", &alices[0].payload).is_ok());
}

#[tokio::test]
async fn revoke_validates_membership_and_wrapped_key_set() {
    let server = spawn().await;
    let alice = register(&server, "alice@example.com", "alice-password").await;
    let bob = register(&server, "bob@example.com", "bob-password").await;
    let carol = register(&server, "carol@example.com", "carol-password").await;
    let (id, key) = server.create_secret(&alice, "Bank", &payload()).await;
    let invite: Created = server.invite(&alice, id, &key, "bob@example.com").await.json().await.unwrap();
    server.accept(&bob, invite.id).await;
    let invite: Created = server.invite(&alice, id, &key, "carol@example.com").await.json().await.unwrap();
    server.accept(&carol, invite.id).await;

    // Self-revoke is a 400; revoking a non-member is a 404 and changes nothing.
    let (response, _) = server.revoke(&alice, id, alice.id, &payload()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let (response, _) = server.revoke(&alice, id, 9999, &payload()).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(server.list(&bob).await.len(), 1);

    // A non-owner cannot revoke.
    let (response, _) = server.revoke(&bob, id, carol.id, &payload()).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(server.list(&carol).await.len(), 1);

    // Leaving Carol off the new key set is rejected and nothing changes.
    let new_key = SecretKey::generate();
    let body = RevokeAccessRequest {
        key_version: 0,
        payload: new_key.encrypt("Bank", &payload()).unwrap(),
        wrapped_keys: vec![WrappedKeyFor {
            user_id: alice.id,
            wrapped_key: WrappedKey::Owner(new_key.wrap_for_owner(&alice.self_wrap_key)),
        }],
    };
    let response = server
        .req(Method::POST, &format!("/secrets/{id}/access/{}/revoke", bob.id), &alice)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(server.list(&bob).await.len(), 1, "rolled back");
    assert_eq!(decrypt(&server.list(&carol).await[0], &carol), payload());

    // Trying to smuggle in an extra member is rejected too.
    let mallory = register(&server, "mallory@example.com", "mallory-password").await;
    let body = RevokeAccessRequest {
        key_version: 0,
        payload: new_key.encrypt("Bank", &payload()).unwrap(),
        wrapped_keys: vec![
            WrappedKeyFor {
                user_id: alice.id,
                wrapped_key: WrappedKey::Owner(new_key.wrap_for_owner(&alice.self_wrap_key)),
            },
            WrappedKeyFor {
                user_id: carol.id,
                wrapped_key: WrappedKey::Shared(new_key.wrap_for(carol.identity.public_key()).unwrap()),
            },
            WrappedKeyFor {
                user_id: mallory.id,
                wrapped_key: WrappedKey::Shared(new_key.wrap_for(mallory.identity.public_key()).unwrap()),
            },
        ],
    };
    let response = server
        .req(Method::POST, &format!("/secrets/{id}/access/{}/revoke", bob.id), &alice)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(server.list(&mallory).await.is_empty());

    // The correct set works and Carol can still read with her new key.
    let (response, _) = server.revoke(&alice, id, bob.id, &payload()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(server.list(&bob).await.is_empty());
    assert_eq!(decrypt(&server.list(&carol).await[0], &carol), payload());
}

#[tokio::test]
async fn invite_edge_cases() {
    let server = spawn().await;
    let alice = register(&server, "alice@example.com", "alice-password").await;
    let bob = register(&server, "bob@example.com", "bob-password").await;
    let mallory = register(&server, "mallory@example.com", "mallory-password").await;
    let (id, key) = server.create_secret(&alice, "Bank", &payload()).await;

    // Unknown invitee, self-invite, and an oversized message.
    let invite_body = |email: &str, message: String| InviteRequest {
        key_version: 0,
        email: email.into(),
        wrapped_key: key.wrap_for(alice.identity.public_key()).unwrap(),
        message,
    };
    let post_invite =
        |body: InviteRequest| server.req(Method::POST, &format!("/secrets/{id}/invites"), &alice).json(&body).send();
    assert_eq!(
        post_invite(invite_body("ghost@example.com", String::new())).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post_invite(invite_body("alice@example.com", String::new())).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_invite(invite_body("bob@example.com", "m".repeat(MAX_MESSAGE_LEN + 1))).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    // Non-owner cannot invite.
    let response = server.invite(&mallory, id, &key, "bob@example.com").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Duplicate pending invite is a conflict; the wrong user cannot accept or cancel it.
    let first: Created = server.invite(&alice, id, &key, "bob@example.com").await.json().await.unwrap();
    assert_eq!(server.invite(&alice, id, &key, "bob@example.com").await.status(), StatusCode::CONFLICT);
    let response = server.req(Method::POST, &format!("/invites/{}/accept", first.id), &mallory).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response =
        server.req(Method::DELETE, &format!("/secrets/{id}/invites/{}", first.id), &mallory).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(server.list(&mallory).await.is_empty());

    // Bob declines; nothing granted, invite gone.
    let response = server.req(Method::POST, &format!("/invites/{}/decline", first.id), &bob).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(server.list(&bob).await.is_empty());
    let pending: Vec<InviteView> =
        server.req(Method::GET, "/invites", &bob).send().await.unwrap().json().await.unwrap();
    assert!(pending.is_empty());

    // Owner can cancel a pending invite.
    let second: Created = server.invite(&alice, id, &key, "bob@example.com").await.json().await.unwrap();
    let response =
        server.req(Method::DELETE, &format!("/secrets/{id}/invites/{}", second.id), &alice).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // A shared user leaving removes only their own access; a stranger gets 404.
    let third: Created = server.invite(&alice, id, &key, "bob@example.com").await.json().await.unwrap();
    server.accept(&bob, third.id).await;
    let response = server.req(Method::DELETE, &format!("/secrets/{id}"), &mallory).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = server.req(Method::DELETE, &format!("/secrets/{id}"), &bob).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(server.list(&bob).await.is_empty());
    assert_eq!(server.list(&alice).await.len(), 1);
}

#[tokio::test]
async fn writes_with_a_stale_key_version_are_rejected() {
    let server = spawn().await;
    let alice = register(&server, "alice@example.com", "alice-password").await;
    let bob = register(&server, "bob@example.com", "bob-password").await;
    let carol = register(&server, "carol@example.com", "carol-password").await;
    let (id, key) = server.create_secret(&alice, "Bank", &payload()).await;
    let invite: Created = server.invite(&alice, id, &key, "bob@example.com").await.json().await.unwrap();
    server.accept(&bob, invite.id).await;

    // Device A revokes Bob: version 0 -> 1.
    let (response, new_key) = server.revoke(&alice, id, bob.id, &payload()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(server.key_version(&alice, id).await, 1);

    // Device B, still holding version 0 and the old key, tries to update: 409, nothing written.
    let mut changed = payload();
    changed.password = "leaked-to-bob".into();
    let stale =
        UpdateSecretRequest { key_version: 0, name: "Bank".into(), payload: key.encrypt("Bank", &changed).unwrap() };
    let response = server.req(Method::PUT, &format!("/secrets/{id}"), &alice).json(&stale).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(decrypt(&server.list(&alice).await[0], &alice), payload());

    // A stale invite (wrapping the old key) is refused too.
    let lookup: PublicUser = server
        .req(Method::GET, "/users/lookup?email=carol@example.com", &alice)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let stale_invite = InviteRequest {
        key_version: 0,
        email: "carol@example.com".into(),
        wrapped_key: key.wrap_for(&lookup.public_key).unwrap(),
        message: String::new(),
    };
    let response =
        server.req(Method::POST, &format!("/secrets/{id}/invites"), &alice).json(&stale_invite).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // A stale revoke (version 0 after the rotation) is refused as well.
    let stale_revoke = RevokeAccessRequest {
        key_version: 0,
        payload: new_key.encrypt("Bank", &payload()).unwrap(),
        wrapped_keys: vec![WrappedKeyFor {
            user_id: alice.id,
            wrapped_key: WrappedKey::Owner(new_key.wrap_for_owner(&alice.self_wrap_key)),
        }],
    };
    let response = server
        .req(Method::POST, &format!("/secrets/{id}/access/{}/revoke", carol.id), &alice)
        .json(&stale_revoke)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // With the current version and the new key, the update goes through.
    let fresh = UpdateSecretRequest {
        key_version: 1,
        name: "Bank".into(),
        payload: new_key.encrypt("Bank", &changed).unwrap(),
    };
    let response = server.req(Method::PUT, &format!("/secrets/{id}"), &alice).json(&fresh).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let view = server.list(&alice).await.remove(0);
    assert_eq!(view.key_version, 1);
    assert_eq!(new_key.decrypt("Bank", &view.payload).unwrap().password, "leaked-to-bob");
    assert!(key.decrypt("Bank", &view.payload).is_err(), "the revoked key cannot open the new payload");
}

#[tokio::test]
async fn owner_copies_must_be_self_wrapped_and_legacy_ones_can_be_upgraded() {
    let server = spawn().await;
    let alice = register(&server, "alice@example.com", "alice-password").await;
    let bob = register(&server, "bob@example.com", "bob-password").await;

    // A sealed box as the owner's copy is refused: anyone could have made it.
    let key = SecretKey::generate();
    let sealed_owner_copy = CreateSecretRequest {
        name: "Bank".into(),
        payload: key.encrypt("Bank", &payload()).unwrap(),
        wrapped_key: WrappedKey::Shared(key.wrap_for(alice.identity.public_key()).unwrap()),
    };
    let response = server.req(Method::POST, "/secrets", &alice).json(&sealed_owner_copy).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // A secret created before self-wrapping existed has a sealed-box owner row.
    let (id, key) = server.create_secret(&alice, "Bank", &payload()).await;
    let legacy = serde_json::to_string(&key.wrap_for(alice.identity.public_key()).unwrap()).unwrap();
    sqlx::query("UPDATE secret_keys SET wrapped_key = ? WHERE secret_id = ? AND user_id = ?")
        .bind(legacy)
        .bind(id)
        .bind(alice.id)
        .execute(&server.pool)
        .await
        .unwrap();
    let view = server.list(&alice).await.remove(0);
    assert!(matches!(view.wrapped_key, WrappedKey::Shared(_)), "legacy rows still parse");
    assert_eq!(decrypt(&view, &alice), payload());

    // Upgrading: wrong kind 400, wrong owner 404, stale version 409, then 204.
    let upgrade = |wrapped_key, key_version| UpgradeOwnerKeyRequest { key_version, wrapped_key };
    let put = |account: &Account, body: &UpgradeOwnerKeyRequest| {
        server.req(Method::PUT, &format!("/secrets/{id}/owner-key"), account).json(body).send()
    };
    let shared_again = upgrade(WrappedKey::Shared(key.wrap_for(alice.identity.public_key()).unwrap()), 0);
    assert_eq!(put(&alice, &shared_again).await.unwrap().status(), StatusCode::BAD_REQUEST);
    let self_wrapped = upgrade(WrappedKey::Owner(key.wrap_for_owner(&alice.self_wrap_key)), 0);
    assert_eq!(put(&bob, &self_wrapped).await.unwrap().status(), StatusCode::NOT_FOUND);
    let stale = upgrade(WrappedKey::Owner(key.wrap_for_owner(&alice.self_wrap_key)), 3);
    assert_eq!(put(&alice, &stale).await.unwrap().status(), StatusCode::CONFLICT);
    assert_eq!(put(&alice, &self_wrapped).await.unwrap().status(), StatusCode::NO_CONTENT);

    let view = server.list(&alice).await.remove(0);
    assert!(matches!(view.wrapped_key, WrappedKey::Owner(_)));
    assert_eq!(decrypt(&view, &alice), payload());

    // Rotation keeps the rule: the owner's entry must be self-wrapped.
    let invite: Created = server.invite(&alice, id, &key, "bob@example.com").await.json().await.unwrap();
    server.accept(&bob, invite.id).await;
    let new_key = SecretKey::generate();
    let owner_as_box = RevokeAccessRequest {
        key_version: 0,
        payload: new_key.encrypt("Bank", &payload()).unwrap(),
        wrapped_keys: vec![WrappedKeyFor {
            user_id: alice.id,
            wrapped_key: WrappedKey::Shared(new_key.wrap_for(alice.identity.public_key()).unwrap()),
        }],
    };
    let response = server
        .req(Method::POST, &format!("/secrets/{id}/access/{}/revoke", bob.id), &alice)
        .json(&owner_as_box)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(server.list(&bob).await.len(), 1, "nothing changed");
}
