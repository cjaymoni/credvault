//! Hostile-input sweep over the HTTP surface.
//!
//! Every route is hit with bodies, path segments and headers no honest client
//! would send. The property is that the server always *answers*: a panic in a
//! handler drops the connection without a response, so "a status came back"
//! is the assertion that catches it. What the status is matters less than that
//! there is one, though a 5xx is reported separately because a malformed
//! request is the client's fault and should say so.
//!
//! Rate limits are raised out of the way so the handlers themselves are
//! reached rather than the limiter in front of them.

use std::net::SocketAddr;
use std::time::Duration;

use credvault_server::{RateLimits, ServerConfig};
use reqwest::{Client, Method, StatusCode};

struct TestServer {
    base: String,
    client: Client,
    _dir: tempfile::TempDir,
}

async fn spawn() -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let pool = credvault_server::connect(&dir.path().join("test.db")).await.unwrap();
    let config = ServerConfig {
        // High enough that the sweep exercises handlers, not the limiter.
        rate_limits: RateLimits {
            login_burst: 100_000,
            login_refill: Duration::from_secs(1),
            register_burst: 100_000,
            register_refill: Duration::from_secs(1),
            lookup_burst: 100_000,
            lookup_refill: Duration::from_secs(1),
            password_burst: 100_000,
            password_refill: Duration::from_secs(1),
            link_burst: 100_000,
            link_refill: Duration::from_secs(1),
        },
        ..ServerConfig::default()
    };
    let app = credvault_server::build_router(pool, config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap()
    });
    TestServer {
        base: format!("http://{addr}"),
        client: Client::builder().timeout(Duration::from_secs(10)).build().unwrap(),
        _dir: dir,
    }
}

/// Bodies that have broken a JSON-backed API somewhere.
fn hostile_bodies() -> Vec<String> {
    let mut bodies = vec![
        String::new(),
        "null".into(),
        "[]".into(),
        "{}".into(),
        "0".into(),
        "\"\"".into(),
        "true".into(),
        "{".into(),
        "{\"".into(),
        "{\"a\":".into(),
        "{\"a\":}".into(),
        "\u{feff}{}".into(),
        "{\"email\":null,\"auth_hash\":null}".into(),
        // Numbers outside i64, which the key_version and id fields are.
        r#"{"key_version":9223372036854775808,"name":"x"}"#.into(),
        r#"{"key_version":-9223372036854775809,"name":"x"}"#.into(),
        r#"{"key_version":1e309,"name":"x"}"#.into(),
        // Duplicate keys: serde takes the last, which must not confuse anything.
        r#"{"email":"a@b.co","email":"c@d.co","auth_hash":"x"}"#.into(),
        // A NUL and a direction override inside otherwise valid fields.
        "{\"email\":\"a\\u0000b@example.com\",\"auth_hash\":\"x\"}".into(),
        "{\"name\":\"\\u202egnp.txt\",\"payload\":{}}".into(),
        // Lone surrogate, which is valid JSON escaping but not valid UTF-8.
        r#"{"name":"\ud800"}"#.into(),
    ];
    // Deep nesting, to confirm serde's recursion limit answers before the stack does.
    bodies.push(format!("{}{}", "[".repeat(5_000), "]".repeat(5_000)));
    bodies.push(format!(r#"{{"payload":{}}}"#, "[".repeat(5_000)));
    // A long string in a field that has a length cap.
    bodies.push(format!(r#"{{"email":"{}@example.com","auth_hash":"x"}}"#, "a".repeat(100_000)));
    bodies
}

/// Every route, as (method, path). Authenticated ones are included: they must
/// reject the request rather than fall over before deciding to.
fn routes() -> Vec<(Method, &'static str)> {
    vec![
        (Method::POST, "/api/register"),
        (Method::POST, "/api/login"),
        (Method::POST, "/api/logout"),
        (Method::DELETE, "/api/sessions"),
        (Method::GET, "/api/me"),
        (Method::POST, "/api/password"),
        (Method::GET, "/api/capabilities"),
        (Method::POST, "/api/oauth/start"),
        (Method::POST, "/api/oauth/callback"),
        (Method::POST, "/api/oauth/register"),
        (Method::POST, "/api/oauth/link"),
        (Method::GET, "/api/users/lookup"),
        (Method::GET, "/api/secrets"),
        (Method::POST, "/api/secrets"),
        (Method::GET, "/api/secrets/1"),
        (Method::PUT, "/api/secrets/1"),
        (Method::DELETE, "/api/secrets/1"),
        (Method::GET, "/api/secrets/1/access"),
        (Method::POST, "/api/secrets/1/access/2/revoke"),
        (Method::POST, "/api/secrets/1/invites"),
        (Method::DELETE, "/api/secrets/1/invites/1"),
        (Method::GET, "/api/invites"),
        (Method::POST, "/api/invites/1/accept"),
        (Method::POST, "/api/invites/1/decline"),
        (Method::GET, "/health"),
    ]
}

#[tokio::test]
async fn every_route_answers_every_hostile_body() {
    let server = spawn().await;
    let bodies = hostile_bodies();
    let mut server_errors = Vec::new();

    for (method, path) in routes() {
        for body in &bodies {
            let response = server
                .client
                .request(method.clone(), format!("{}{path}", server.base))
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .await;
            // An Err here is the finding: no status means the connection died,
            // which is what a panicking handler looks like from outside.
            let response =
                response.unwrap_or_else(|e| panic!("{method} {path} gave no response for body {:.80}: {e}", body));
            if response.status().is_server_error() {
                server_errors.push(format!("{method} {path} -> {} for body {:.80}", response.status(), body));
            }
        }
    }
    assert!(server_errors.is_empty(), "malformed input should not be a server error:\n{}", server_errors.join("\n"));
}

#[tokio::test]
async fn path_parameters_survive_values_that_are_not_ids() {
    let server = spawn().await;
    let segments = [
        "0",
        "-1",
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775809",
        "1.5",
        "abc",
        "",
        "%00",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "1%20OR%201%3D1",
        "'%20OR%20'1'%3D'1",
        "1;DROP%20TABLE%20secrets",
        &"9".repeat(400),
    ];
    for segment in segments {
        for path in [
            format!("/api/secrets/{segment}"),
            format!("/api/secrets/{segment}/access"),
            format!("/api/secrets/1/access/{segment}/revoke"),
            format!("/api/secrets/1/invites/{segment}"),
            format!("/api/invites/{segment}/accept"),
        ] {
            let response = server.client.get(format!("{}{path}", server.base)).send().await;
            let response = response.unwrap_or_else(|e| panic!("{path} gave no response: {e}"));
            assert!(!response.status().is_server_error(), "{path} -> {}", response.status());
        }
    }
    // The injection attempts above must not have reached the database.
    let still_alive = server.client.get(format!("{}/health", server.base)).send().await.unwrap();
    assert_eq!(still_alive.status(), StatusCode::OK);
}

#[tokio::test]
async fn authorization_headers_that_are_not_tokens_are_refused_cleanly() {
    let server = spawn().await;
    let headers = [
        "",
        "Bearer",
        "Bearer ",
        "bearer lowercase",
        "Basic dXNlcjpwYXNz",
        "Bearer ../../etc/passwd",
        "Bearer ' OR 1=1 --",
        "Bearer \u{00e9}\u{65e5}",
        "Bearer AAAA AAAA",
    ];
    for value in headers {
        let response = server
            .client
            .get(format!("{}/api/me", server.base))
            .header("authorization", value)
            .send()
            .await
            .unwrap_or_else(|e| panic!("header {value:?} gave no response: {e}"));
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "header {value:?}");
    }
    // A header that is not valid as bytes in a header value is rejected by the
    // client; what matters is the server never sees a half-parsed one.
    let long = format!("Bearer {}", "A".repeat(100_000));
    let response = server.client.get(format!("{}/api/me", server.base)).header("authorization", long).send().await;
    if let Ok(response) = response {
        assert!(!response.status().is_server_error(), "oversized bearer -> {}", response.status());
    }
}

#[tokio::test]
async fn query_parameters_survive_hostile_values() {
    let server = spawn().await;
    for query in [
        "",
        "?",
        "?email=",
        "?email=%00",
        "?email=a@b.co",
        "?fingerprint=",
        // Long, but still a URL the client will build: beyond a few tens of
        // kilobytes reqwest refuses before sending, which tests nothing here.
        &format!("?email={}&fingerprint={}", "a".repeat(4_000), "f".repeat(4_000)),
        "?email=a@b.co&email=c@d.co&fingerprint=x",
        "?email[]=a&fingerprint[]=b",
        "?email=%ff%fe",
    ] {
        let sent = server.client.get(format!("{}/api/users/lookup{query}", server.base)).send().await;
        match sent {
            Ok(response) => {
                assert!(!response.status().is_server_error(), "{query:.60} -> {}", response.status())
            }
            // A URL the client itself refuses to build never reaches the
            // server, so it says nothing about the server. A connection that
            // was made and then dropped would, but reqwest reports that the
            // same way, so the two are separated by what the error says.
            Err(error) => assert!(error.is_builder(), "{query:.60} reached the server and then failed: {error}"),
        }
    }
}
