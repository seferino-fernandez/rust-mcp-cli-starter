//! End-to-end tests of the OAuth routes, driven through an axum router.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::middleware::oauth::{OAuthMiddlewareState, oauth_bearer_auth};
use crate::oauth::limiter::{BASE_BACKOFF, MAX_FAILURES, PinLimiter};
use crate::oauth::model::OAuthEndpointState;
use crate::oauth::store::{AccessToken, OAuthStore, OAuthStoreConfig};
use crate::secret_digest::SecretDigest;

use super::*;
use axum::response::Response;
use axum::routing::post;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    middleware as axum_middleware,
    routing::get,
};
use tower::ServiceExt;

fn test_base_url() -> String {
    "http://127.0.0.1:9999".to_string()
}

async fn protected_handler() -> &'static str {
    "OK"
}

/// Build a minimal router with OAuth endpoints + a protected /test route.
/// Returns (`Router`, `OAuthStore`) so tests can reach into the store.
fn build_test_router(oauth_pin: Option<&str>) -> (Router, OAuthStore) {
    build_test_router_with_limiter(oauth_pin, PinLimiter::default())
}

/// Like [`build_test_router`], starting from `pin_limiter`.
fn build_test_router_with_limiter(
    oauth_pin: Option<&str>,
    pin_limiter: PinLimiter,
) -> (Router, OAuthStore) {
    build_test_router_with(oauth_pin, pin_limiter, OAuthStoreConfig::default())
}

/// Like [`build_test_router`], with no PIN and a store built from
/// `store_config`.
fn build_test_router_with_store(store_config: OAuthStoreConfig) -> (Router, OAuthStore) {
    build_test_router_with(None, PinLimiter::default(), store_config)
}

/// Like [`build_test_router_with_limiter`], with a store built from `store_config`.
fn build_test_router_with(
    oauth_pin: Option<&str>,
    pin_limiter: PinLimiter,
    store_config: OAuthStoreConfig,
) -> (Router, OAuthStore) {
    let store_instance = OAuthStore::new(store_config);
    let base = test_base_url();

    let endpoint_state = Arc::new(OAuthEndpointState {
        store: store_instance.clone(),
        base_url: base.clone(),
        oauth_pin: oauth_pin.map(SecretDigest::new),
        pin_limiter: Arc::new(Mutex::new(pin_limiter)),
    });

    let middleware_state = OAuthMiddlewareState {
        store: store_instance.clone(),
        resource_metadata_url: format!("{base}/.well-known/oauth-protected-resource"),
    };

    let oauth_routes = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(endpoints::protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(endpoints::protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(endpoints::authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(endpoints::authorization_server_metadata),
        )
        .route("/oauth/authorize", get(endpoints::authorize))
        .route("/oauth/approve", post(endpoints::approve))
        .route("/oauth/token", post(endpoints::token))
        .route("/oauth/register", post(endpoints::register))
        .with_state(endpoint_state);

    let protected_routes = Router::new().route("/test", get(protected_handler)).layer(
        axum_middleware::from_fn_with_state(middleware_state, oauth_bearer_auth),
    );

    (oauth_routes.merge(protected_routes), store_instance)
}

async fn body_to_string(body: Body) -> String {
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn body_to_json(body: Body) -> serde_json::Value {
    let text = body_to_string(body).await;
    serde_json::from_str(&text).unwrap()
}

/// Send `request` through `app`.
async fn send(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.unwrap()
}

/// `GET uri` with no body.
async fn get_uri(app: &Router, uri: &str) -> Response {
    send(app, Request::get(uri).body(Body::empty()).unwrap()).await
}

/// `GET uri`, asserting a 200, and return the JSON body.
async fn get_json(app: &Router, uri: &str) -> serde_json::Value {
    let response = get_uri(app, uri).await;
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    body_to_json(response.into_body()).await
}

/// `POST path` with `body` as `content_type`.
async fn post_body(app: &Router, path: &str, content_type: &str, body: String) -> Response {
    send(
        app,
        Request::post(path)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

/// `POST path` with `fields` as a URL-encoded form.
async fn post_form(app: &Router, path: &str, fields: &[(&str, &str)]) -> Response {
    let body = serde_urlencoded::to_string(fields).unwrap();
    post_body(app, path, "application/x-www-form-urlencoded", body).await
}

/// The value of header `name`, which `response` must carry.
fn header_str<'r>(response: &'r Response, name: &str) -> &'r str {
    response.headers().get(name).unwrap().to_str().unwrap()
}

#[tokio::test]
async fn protected_route_requires_auth() {
    let (app, _store) = build_test_router(None);
    let response = get_uri(&app, "/test").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let www_auth = header_str(&response, header::WWW_AUTHENTICATE.as_str());
    assert!(
        www_auth.contains("oauth-protected-resource"),
        "WWW-Authenticate: {www_auth}"
    );
}

#[tokio::test]
async fn metadata_endpoints_return_json() {
    let (app, _store) = build_test_router(None);

    let resource = get_json(&app, "/.well-known/oauth-protected-resource").await;
    assert_ne!(
        *resource["authorization_servers"].as_array().unwrap(),
        Vec::<serde_json::Value>::new()
    );
    let scopes = resource["scopes_supported"].as_array().unwrap();
    for expected in ["read", "write"] {
        assert!(scopes.iter().any(|scope| scope == expected), "{expected}");
    }

    let server = get_json(&app, "/.well-known/oauth-authorization-server").await;
    for (field, path) in [
        ("authorization_endpoint", "/oauth/authorize"),
        ("token_endpoint", "/oauth/token"),
    ] {
        assert!(server[field].as_str().unwrap().contains(path), "{field}");
    }
    assert_eq!(
        server["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
}

#[tokio::test]
async fn metadata_at_suffixed_path() {
    let (app, _store) = build_test_router(None);
    let json = get_json(&app, "/.well-known/oauth-protected-resource/mcp").await;
    assert_ne!(
        *json["authorization_servers"].as_array().unwrap(),
        Vec::<serde_json::Value>::new()
    );
}

#[tokio::test]
async fn openid_configuration_returns_metadata() {
    let (app, _store) = build_test_router(None);
    let json = get_json(&app, "/.well-known/openid-configuration").await;
    assert!(
        json["authorization_endpoint"]
            .as_str()
            .unwrap()
            .contains("/oauth/authorize")
    );
}

/// Registration issues a public client: no secret, and the auth method the
/// metadata advertises.
#[tokio::test]
async fn dynamic_client_registration() {
    let (app, _store) = build_test_router(None);
    let registration = post_register_named(
        &app,
        "Test Client",
        &["http://localhost:8080/callback".to_string()],
    )
    .await;
    assert_eq!(registration.status(), StatusCode::CREATED);
    let json = body_to_json(registration.into_body()).await;
    assert!(
        json["client_id"]
            .as_str()
            .unwrap()
            .starts_with("myapp_cid_")
    );
    assert!(json.get("client_secret").is_none(), "{json}");
    assert_eq!(json["token_endpoint_auth_method"], "none");
    assert_eq!(json["client_name"], "Test Client");
    assert_eq!(
        json["redirect_uris"],
        serde_json::json!(["http://localhost:8080/callback"])
    );

    let metadata = get_json(&app, "/.well-known/oauth-authorization-server").await;
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        serde_json::json!(["none"])
    );
}

#[tokio::test]
async fn full_oauth_flow() {
    let (app, _store) = build_test_router(None);

    // 1. Register client
    let client_id = register_named_client(&app, "Test", &["http://localhost/cb"]).await;

    // 2. PKCE verifier (the challenge is derived from it)
    let verifier = "test-verifier-string-that-is-long-enough-for-pkce";

    // 3. Authorize, then submit approval from the consent page
    let approval = approve_request(
        &app,
        &AuthorizeRequest {
            scope: "read write",
            state: "test-state",
            verifier,
            ..AuthorizeRequest::read(&client_id)
        },
        &[("pin", "")],
    )
    .await;

    // Should redirect with code
    assert_eq!(approval.status(), StatusCode::SEE_OTHER);
    let location = location_header(&approval);
    assert!(
        location.starts_with("http://localhost/cb?code=myapp_ac_"),
        "location: {location}"
    );
    assert!(
        location.contains("state=test-state"),
        "location: {location}"
    );
    let auth_code = code_from_location(&location);

    // 4. Exchange code for token
    let token_json = exchange_ok(
        &app,
        &auth_code,
        &client_id,
        "http://localhost/cb",
        verifier,
    )
    .await;
    let access_token = token_json["access_token"].as_str().unwrap().to_string();
    let refresh_token = token_json["refresh_token"].as_str().unwrap().to_string();
    assert!(access_token.starts_with("myapp_at_"));
    assert!(refresh_token.starts_with("myapp_rt_"));
    assert_eq!(token_json["token_type"], "Bearer");
    assert_eq!(token_json["scope"], "read write");

    // 5. Access protected route with token
    let authorized = get_protected(&app, &access_token).await;
    assert_eq!(authorized.status(), StatusCode::OK);
    assert_eq!(body_to_string(authorized.into_body()).await, "OK");

    // 6. Invalid token gets 401
    let invalid = get_protected(&app, "invalid-token").await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);

    // 7. Refresh token
    let new_token_json = refresh_ok(&app, &refresh_token, &client_id).await;
    let new_access_token = new_token_json["access_token"].as_str().unwrap().to_string();
    assert_ne!(new_access_token, access_token, "new token should differ");

    // 8. Old token is revoked
    let revoked = get_protected(&app, &access_token).await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);

    // 9. New token works
    let renewed = get_protected(&app, &new_access_token).await;
    assert_eq!(renewed.status(), StatusCode::OK);
}

/// `GET /test` with `access_token` as the Bearer token.
async fn get_protected(app: &Router, access_token: &str) -> Response {
    send(
        app,
        Request::get("/test")
            .header("authorization", format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn pkce_failure_rejects_token_exchange() {
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;

    // Approve
    let approval = approve_request(
        &app,
        &AuthorizeRequest {
            state: "",
            verifier: "correct-verifier",
            ..AuthorizeRequest::read(&client_id)
        },
        &[("pin", "")],
    )
    .await;
    let auth_code = code_from_location(&location_header(&approval));

    // Exchange with WRONG verifier
    let response = exchange_code(
        &app,
        &auth_code,
        &client_id,
        "http://localhost/cb",
        "wrong-verifier",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["error"], "invalid_grant");
    assert!(json["error_description"].as_str().unwrap().contains("PKCE"));
}

#[tokio::test]
async fn consent_page_has_anti_clickjacking_headers() {
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;

    let challenge = pkce::challenge_from_verifier("test-verifier");

    let response = get_uri(
        &app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
            client_id,
            urlencoding::encode("http://localhost/cb"),
            challenge
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header_str(&response, "x-frame-options"), "DENY");
    let csp = header_str(&response, "content-security-policy");
    assert!(csp.contains("frame-ancestors 'none'"));
}

#[tokio::test]
async fn pin_required_rejects_wrong_pin() {
    let (app, _store) = build_test_router(Some("secret-pin"));
    let client_id = register_client(&app, "http://localhost/cb").await;

    // Approve with wrong pin
    let response = submit_consent(&app, &client_id, true, Some("wrong-pin")).await;
    let location = location_header(&response);
    assert!(
        location.contains("error=access_denied"),
        "location: {location}"
    );
    assert!(
        location.contains("Invalid%20PIN") || location.contains("Invalid+PIN"),
        "location: {location}"
    );
}

/// Register a client for `redirect_uri` and return its `client_id`.
async fn register_client(app: &Router, redirect_uri: &str) -> String {
    let response = post_register(app, &[redirect_uri]).await;
    client_id_of_registration(response).await
}

/// Asserts `response` is a successful registration and returns its
/// `client_id`.
async fn client_id_of_registration(response: Response) -> String {
    assert_eq!(response.status(), StatusCode::CREATED);
    body_to_json(response.into_body()).await["client_id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// POST the consent form with `fields` and return the response.
async fn post_approve(app: &Router, fields: &[(&str, &str)]) -> Response {
    post_form(app, "/oauth/approve", fields).await
}

/// POST the consent form approving `consent_nonce`, adding `extra` fields.
async fn approve_nonce(app: &Router, consent_nonce: &str, extra: &[(&str, &str)]) -> Response {
    let mut fields = vec![("consent_nonce", consent_nonce), ("approved", "true")];
    fields.extend_from_slice(extra);
    post_approve(app, &fields).await
}

/// Authorize `request` like [`authorize_nonce`] and approve the consent
/// page's nonce like [`approve_nonce`].
async fn approve_request(
    app: &Router,
    request: &AuthorizeRequest<'_>,
    extra: &[(&str, &str)],
) -> Response {
    let consent_nonce = authorize_nonce(app, request).await;
    approve_nonce(app, &consent_nonce, extra).await
}

fn location_header(response: &Response) -> String {
    header_str(response, header::LOCATION.as_str()).to_string()
}

/// The query pairs of a redirect `location`.
fn query_pairs(location: &str) -> Vec<(String, String)> {
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

/// The parameters of a `GET /oauth/authorize` request with the S256
/// challenge of `verifier`.
struct AuthorizeRequest<'a> {
    client_id: &'a str,
    redirect_uri: &'a str,
    scope: &'a str,
    state: &'a str,
    verifier: &'a str,
}

impl<'a> AuthorizeRequest<'a> {
    /// `client_id` asking for `read` at `http://localhost/cb`, with state `s`
    /// and verifier `verifier`.
    fn read(client_id: &'a str) -> Self {
        Self {
            client_id,
            redirect_uri: "http://localhost/cb",
            scope: "read",
            state: "s",
            verifier: "verifier",
        }
    }
}

/// `GET /oauth/authorize` with `request` and return the consent page HTML.
async fn authorize_page(app: &Router, request: &AuthorizeRequest<'_>) -> String {
    let challenge = pkce::challenge_from_verifier(request.verifier);
    let response = get_uri(
        app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            urlencoding::encode(request.client_id),
            urlencoding::encode(request.redirect_uri),
            urlencoding::encode(request.scope),
            urlencoding::encode(request.state),
            urlencoding::encode(&challenge),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_to_string(response.into_body()).await
}

/// The consent nonce a consent page posts back.
fn consent_nonce(html: &str) -> String {
    html.split_once("name=\"consent_nonce\" value=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(nonce, _)| nonce.to_string())
        .expect("consent page carries a consent nonce")
}

/// Authorize through `GET /oauth/authorize` like [`authorize_page`] and return
/// the consent nonce from the page.
async fn authorize_nonce(app: &Router, request: &AuthorizeRequest<'_>) -> String {
    consent_nonce(&authorize_page(app, request).await)
}

/// The authorization code in an approval redirect.
fn code_from_location(location: &str) -> String {
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "code")
        .expect("redirect carries a code")
        .1
        .to_string()
}

/// `POST /oauth/token` with the `authorization_code` grant.
async fn exchange_code(
    app: &Router,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Response {
    post_form(
        app,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ],
    )
    .await
}

/// Like [`exchange_code`], asserting a 200, and return the token JSON.
async fn exchange_ok(
    app: &Router,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    verifier: &str,
) -> serde_json::Value {
    let response = exchange_code(app, code, client_id, redirect_uri, verifier).await;
    assert_eq!(response.status(), StatusCode::OK);
    body_to_json(response.into_body()).await
}

#[tokio::test]
async fn approve_drops_unknown_scopes_and_defaults_to_read() {
    let (app, test_store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;

    let verifier = "unknown-scope-verifier-that-is-long-enough-for-pkce";
    let approval = approve_request(
        &app,
        &AuthorizeRequest {
            scope: "admin",
            state: "",
            verifier,
            ..AuthorizeRequest::read(&client_id)
        },
        &[],
    )
    .await;
    assert_eq!(approval.status(), StatusCode::SEE_OTHER);
    let auth_code = code_from_location(&location_header(&approval));

    let token_json = exchange_ok(
        &app,
        &auth_code,
        &client_id,
        "http://localhost/cb",
        verifier,
    )
    .await;
    assert_eq!(token_json["scope"], "read");
    let access_token = token_json["access_token"].as_str().unwrap();
    assert_eq!(
        test_store
            .validate_access_token(access_token)
            .map(|token| token.scope),
        Some(vec!["read".to_string()])
    );
}

#[tokio::test]
async fn approve_without_pin_field_issues_no_code_when_pin_configured() {
    let (app, _store) = build_test_router(Some("1234"));
    let client_id = register_client(&app, "http://localhost/cb").await;

    // The attacker reads the consent nonce straight out of the consent page.
    let response = approve_request(
        &app,
        &AuthorizeRequest {
            scope: "read write",
            verifier: "attacker-verifier",
            ..AuthorizeRequest::read(&client_id)
        },
        &[],
    )
    .await;
    assert_no_code(&response, "no pin field");
}

/// Asserts `response` redirects with `access_denied` and carries no code.
fn assert_no_code(response: &Response, context: &str) {
    assert_eq!(response.status(), StatusCode::SEE_OTHER, "{context}");
    let location = location_header(response);
    assert!(
        !location.contains("code="),
        "{context} location: {location}"
    );
    assert!(
        location.contains("error=access_denied"),
        "{context} location: {location}"
    );
}

#[tokio::test]
async fn approve_against_empty_configured_pin_issues_no_code() {
    let (app, _store) = build_test_router(Some(""));
    let client_id = register_client(&app, "http://localhost/cb").await;

    // An empty `pin` field and an omitted one must both be refused.
    for pin in [Some(""), None] {
        let response = submit_consent(&app, &client_id, true, pin).await;
        assert_no_code(&response, &format!("pin={pin:?}"));
    }
}

const LIMITED_PIN: &str = "correct-horse";

/// Authorizes `client_id` through `GET /oauth/authorize` and submits the
/// consent form with the page's nonce, approving it when `approved`, with
/// `pin` as the PIN field (omitted when `None`).
async fn submit_consent(
    app: &Router,
    client_id: &str,
    approved: bool,
    pin: Option<&str>,
) -> Response {
    let consent_nonce = authorize_nonce(app, &AuthorizeRequest::read(client_id)).await;
    let mut fields = vec![
        ("consent_nonce", consent_nonce.as_str()),
        ("approved", if approved { "true" } else { "false" }),
    ];
    if let Some(pin) = pin {
        fields.push(("pin", pin));
    }
    post_approve(app, &fields).await
}

/// Asserts `response` redirects with `access_denied` and `description`, and
/// carries no code.
fn assert_denied(response: &Response, description: &str) {
    assert_no_code(response, description);
    let location = location_header(response);
    let encoded = urlencoding::encode(description).replace("%20", "+");
    assert!(location.contains(&encoded), "location: {location}");
}

/// Asserts `response` redirects with an authorization code.
fn assert_code_issued(response: &Response) {
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = location_header(response);
    assert!(location.contains("code="), "location: {location}");
    assert!(!location.contains("error="), "location: {location}");
}

/// Asserts `response` is the backoff refusal: 429, a `Retry-After` of 1 to
/// 60 seconds, `temporarily_unavailable`, and no redirect.
async fn assert_backoff(response: Response) {
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().get(header::LOCATION).is_none());
    let retry_after: u64 = response
        .headers()
        .get(header::RETRY_AFTER)
        .expect("a 429 carries Retry-After")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        (1..=BASE_BACKOFF.as_secs()).contains(&retry_after),
        "Retry-After: {retry_after}"
    );
    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["error"], "temporarily_unavailable");
    assert!(json["error_description"].is_string(), "body: {json}");
}

/// A limiter already in its first backoff.
fn backed_off_limiter() -> PinLimiter {
    let mut limiter = PinLimiter::default();
    let now = Instant::now();
    let started = (0..MAX_FAILURES)
        .filter_map(|_| limiter.record_failure(now))
        .last();
    assert_eq!(started, Some(BASE_BACKOFF));
    limiter
}

/// Submits `pin` for `client_id` `times` times, asserting each is refused as
/// an invalid PIN.
async fn submit_wrong_pins(app: &Router, client_id: &str, pin: &str, times: usize) {
    for _ in 0..times {
        let response = submit_consent(app, client_id, true, Some(pin)).await;
        assert_denied(&response, "Invalid PIN");
    }
}

#[tokio::test]
async fn approve_accepts_only_the_exact_pin() {
    let (app, _store) = build_test_router(Some(LIMITED_PIN));
    let client_id = register_client(&app, "http://localhost/cb").await;

    // Wrong, a prefix, longer, and empty: four failures, under the limit.
    for pin in ["wrong-horse!!", "correct", "correct-horse-battery", ""] {
        submit_wrong_pins(&app, &client_id, pin, 1).await;
    }
    let correct = submit_consent(&app, &client_id, true, Some(LIMITED_PIN)).await;
    assert_code_issued(&correct);
    let response = submit_consent(&app, &client_id, true, None).await;
    assert_denied(&response, "Invalid PIN");
}

#[tokio::test]
async fn five_wrong_pins_back_off_even_the_correct_pin() {
    let (app, _store) = build_test_router(Some(LIMITED_PIN));
    let client_id = register_client(&app, "http://localhost/cb").await;

    submit_wrong_pins(&app, &client_id, "wrong-pin", MAX_FAILURES).await;
    let correct = submit_consent(&app, &client_id, true, Some(LIMITED_PIN)).await;
    assert_backoff(correct).await;
    let response = submit_consent(&app, &client_id, true, Some("wrong-pin")).await;
    assert_backoff(response).await;
}

#[tokio::test]
async fn wrong_pins_from_different_clients_add_up() {
    let (app, _store) = build_test_router(Some(LIMITED_PIN));
    let first = register_client(&app, "http://localhost/cb").await;
    let second = register_client(&app, "http://localhost/cb").await;
    assert_ne!(first, second);

    for client_id in [&first, &second, &first, &second, &first] {
        submit_wrong_pins(&app, client_id, "wrong-pin", 1).await;
    }
    let response = submit_consent(&app, &second, true, Some(LIMITED_PIN)).await;
    assert_backoff(response).await;
}

#[tokio::test]
async fn correct_pin_resets_the_failure_count() {
    let (app, _store) = build_test_router(Some(LIMITED_PIN));
    let client_id = register_client(&app, "http://localhost/cb").await;

    for _ in 0..2 {
        submit_wrong_pins(&app, &client_id, "wrong-pin", MAX_FAILURES - 1).await;
        let response = submit_consent(&app, &client_id, true, Some(LIMITED_PIN)).await;
        assert_code_issued(&response);
    }
}

#[tokio::test]
async fn denials_never_count_as_pin_failures() {
    let (app, _store) = build_test_router(Some(LIMITED_PIN));
    let client_id = register_client(&app, "http://localhost/cb").await;

    for pin in [Some("wrong-pin"), None, Some(LIMITED_PIN)]
        .into_iter()
        .cycle()
        .take(3 * MAX_FAILURES)
    {
        let response = submit_consent(&app, &client_id, false, pin).await;
        assert_denied(&response, "User denied the authorization request");
    }
    let response = submit_consent(&app, &client_id, true, Some(LIMITED_PIN)).await;
    assert_code_issued(&response);
}

#[tokio::test]
async fn denials_during_a_backoff_are_not_refused() {
    let (app, _store) = build_test_router_with_limiter(Some(LIMITED_PIN), backed_off_limiter());
    let client_id = register_client(&app, "http://localhost/cb").await;

    let denial = submit_consent(&app, &client_id, false, Some("wrong-pin")).await;
    assert_denied(&denial, "User denied the authorization request");
    let response = submit_consent(&app, &client_id, true, Some(LIMITED_PIN)).await;
    assert_backoff(response).await;
}

#[tokio::test]
async fn pinless_approvals_never_consult_the_limiter() {
    let (app, _store) = build_test_router_with_limiter(None, backed_off_limiter());
    let client_id = register_client(&app, "http://localhost/cb").await;

    for pin in [Some("wrong-pin"), None, Some("")]
        .into_iter()
        .cycle()
        .take(3 * MAX_FAILURES)
    {
        let response = submit_consent(&app, &client_id, true, pin).await;
        assert_code_issued(&response);
    }
}

/// A poisoned limiter lock is recovered, not a panic in the handler.
#[tokio::test]
async fn poisoned_pin_limiter_is_recovered() {
    let pin_limiter = Arc::new(Mutex::new(PinLimiter::default()));
    let poisoner = Arc::clone(&pin_limiter);
    let joined = std::thread::spawn(move || {
        let _guard = poisoner.lock().unwrap();
        panic!("poisoning the PIN limiter on purpose");
    })
    .join();
    assert!(joined.is_err());
    assert!(pin_limiter.is_poisoned());

    let store = OAuthStore::new(OAuthStoreConfig::default());
    let app = Router::new()
        .route("/oauth/authorize", get(endpoints::authorize))
        .route("/oauth/approve", post(endpoints::approve))
        .route("/oauth/register", post(endpoints::register))
        .with_state(Arc::new(OAuthEndpointState {
            store,
            base_url: test_base_url(),
            oauth_pin: Some(SecretDigest::new(LIMITED_PIN)),
            pin_limiter,
        }));
    let client_id = register_client(&app, "http://localhost/cb").await;
    let response = submit_consent(&app, &client_id, true, Some(LIMITED_PIN)).await;
    assert_code_issued(&response);
}

/// The four `GET /oauth/authorize` parameter errors, as query fragments with
/// the `error` each one reports.
const AUTHORIZE_PARAMETER_ERRORS: [(&str, &str); 4] = [
    (
        "response_type=token&code_challenge=challenge&code_challenge_method=S256",
        "unsupported_response_type",
    ),
    (
        "response_type=code&code_challenge=challenge&code_challenge_method=plain",
        "invalid_request",
    ),
    (
        "response_type=code&code_challenge=challenge",
        "invalid_request",
    ),
    (
        "response_type=code&code_challenge_method=S256",
        "invalid_request",
    ),
];

async fn get_authorize(
    app: &Router,
    parameters: &str,
    client_id: &str,
    redirect_uri: &str,
) -> Response {
    get_uri(
        app,
        &format!(
            "/oauth/authorize?{parameters}&client_id={}&redirect_uri={}&state=xyz",
            urlencoding::encode(client_id),
            urlencoding::encode(redirect_uri),
        ),
    )
    .await
}

/// Asserts each of [`AUTHORIZE_PARAMETER_ERRORS`] for `client_id` at the
/// unregistered `https://evil.example/` is a 400 `invalid_request` naming the
/// client or redirect mismatch, and never a redirect.
async fn assert_parameter_errors_never_redirect_to_evil(app: &Router, client_id: &str) {
    for (parameters, _) in AUTHORIZE_PARAMETER_ERRORS {
        let response = get_authorize(app, parameters, client_id, "https://evil.example/").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{parameters}");
        assert!(
            response.headers().get(header::LOCATION).is_none(),
            "{parameters} redirected"
        );
        let json = body_to_json(response.into_body()).await;
        assert_eq!(json["error"], "invalid_request", "{parameters}");
        assert_eq!(
            json["error_description"], "Unknown client_id or redirect_uri mismatch",
            "{parameters}"
        );
    }
}

#[tokio::test]
async fn authorize_parameter_errors_never_redirect_to_unregistered_uri() {
    let (app, _store) = build_test_router(None);
    register_client(&app, "http://localhost/cb").await;

    assert_parameter_errors_never_redirect_to_evil(&app, "myapp_cid_unregistered").await;
}

#[tokio::test]
async fn authorize_parameter_errors_never_redirect_to_uri_unregistered_for_known_client() {
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;

    assert_parameter_errors_never_redirect_to_evil(&app, &client_id).await;
}

/// A query that does not deserialize is a JSON 400 `invalid_request`, never
/// a redirect, and its body does not echo the query.
#[tokio::test]
async fn authorize_with_malformed_parameters_never_redirects() {
    const MARKER: &str = "echo-marker-5309";
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;

    for query in [
        String::new(),
        format!("client_id={client_id}&redirect_uri=http%3A%2F%2Flocalhost%2F{MARKER}"),
        format!("response_type={MARKER}&redirect_uri=http%3A%2F%2Flocalhost%2Fcb"),
        format!("response_type=code&client_id={client_id}&state={MARKER}"),
    ] {
        let response = get_uri(&app, &format!("/oauth/authorize?{query}")).await;
        let body = assert_json_error_without_redirect(response, "invalid_request", &query).await;
        assert!(!body.contains(MARKER), "{query} echoed: {body}");
        assert!(!body.contains(&client_id), "{query} echoed: {body}");
    }
}

/// Bodies the extractors refuse, for each OAuth endpoint that reads one,
/// with the `error` each gets: `(path, content type, body, error)`.
const MALFORMED_BODIES: [(&str, &str, &str, &str); 8] = [
    (
        "/oauth/token",
        "application/x-www-form-urlencoded",
        "code=echo-marker-5309",
        "invalid_request",
    ),
    (
        "/oauth/token",
        "text/plain",
        "grant_type=echo-marker-5309",
        "invalid_request",
    ),
    (
        "/oauth/approve",
        "application/x-www-form-urlencoded",
        "pin=echo-marker-5309",
        "invalid_request",
    ),
    (
        "/oauth/approve",
        "text/plain",
        "consent_nonce=echo-marker-5309",
        "invalid_request",
    ),
    (
        "/oauth/register",
        "application/json",
        "{\"redirect_uris\": \"echo-marker-5309\"}",
        "invalid_client_metadata",
    ),
    (
        "/oauth/register",
        "application/json",
        "{\"client_name\": \"echo-marker-5309\"",
        "invalid_client_metadata",
    ),
    (
        "/oauth/register",
        "application/json",
        "[1, 2]",
        "invalid_client_metadata",
    ),
    (
        "/oauth/register",
        "text/plain",
        "{\"redirect_uris\": [\"https://echo-marker-5309.example/cb\"]}",
        "invalid_client_metadata",
    ),
];

/// Every body an extractor refuses gets a JSON OAuth error instead of axum's
/// plain-text rejection, and the error does not echo the body.
#[tokio::test]
async fn malformed_oauth_bodies_are_json_errors_without_echo() {
    let (app, store) = build_test_router(None);
    for (path, content_type, body, expected_error) in MALFORMED_BODIES {
        let response = post_body(&app, path, content_type, body.to_string()).await;
        let context = format!("{path} {content_type} {body}");
        let text = assert_json_error_without_redirect(response, expected_error, &context).await;
        assert!(
            !text.contains("echo-marker-5309"),
            "{context} echoed: {text}"
        );
    }
    assert_eq!(store.client_count(), 0);
}

/// Asserts `response` is a JSON 400 carrying `expected_error` and no
/// redirect, and returns the body text.
async fn assert_json_error_without_redirect(
    response: Response,
    expected_error: &str,
    context: &str,
) -> String {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{context}");
    assert!(
        response.headers().get(header::LOCATION).is_none(),
        "{context} redirected"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "{context}"
    );
    let text = body_to_string(response.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["error"], expected_error, "{context}: {json}");
    assert!(json["error_description"].is_string(), "{context}: {json}");
    text
}

#[tokio::test]
async fn authorize_parameter_errors_for_registered_uri_are_json_400_without_redirect() {
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;

    for (parameters, expected_error) in AUTHORIZE_PARAMETER_ERRORS {
        let response = get_authorize(&app, parameters, &client_id, "http://localhost/cb").await;
        assert_json_error_without_redirect(response, expected_error, parameters).await;
    }
}

#[tokio::test]
async fn authorize_is_not_an_open_redirector_for_a_registered_attacker_uri() {
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, "https://evil.example/").await;

    let response =
        get_authorize(&app, "response_type=x", &client_id, "https://evil.example/").await;
    assert_json_error_without_redirect(response, "unsupported_response_type", "response_type=x")
        .await;
}

/// POST `/oauth/register` with `body` as JSON and return the response.
async fn post_register_json(app: &Router, body: &serde_json::Value) -> Response {
    post_body(app, "/oauth/register", "application/json", body.to_string()).await
}

/// POST `/oauth/register` with `redirect_uris` and return the response.
async fn post_register(app: &Router, redirect_uris: &[&str]) -> Response {
    post_register_json(app, &serde_json::json!({ "redirect_uris": redirect_uris })).await
}

#[tokio::test]
async fn registration_accepts_https_loopback_http_and_native_app_schemes() {
    let mut failures = Vec::new();
    for redirect_uri in [
        "https://example.com/cb",
        "https://client.example/cb",
        "https://client.example/cb?app=1",
        "http://localhost:8080/cb",
        "http://localhost:8080/callback",
        "http://127.0.0.1/cb",
        "http://127.0.0.2/cb",
        "http://[::1]:3000/cb",
        "cursor://anysphere.cursor-retrieval/oauth/callback",
        "com.example.app:/cb",
        "com.example.app:/oauth2redirect",
    ] {
        let (app, store) = build_test_router(None);
        let response = post_register(&app, &[redirect_uri]).await;
        let status = response.status();
        let json = body_to_json(response.into_body()).await;
        let stored = match json["client_id"].as_str() {
            Some(client_id) => store.client_for_redirect(client_id, redirect_uri).is_some(),
            None => false,
        };
        if status != StatusCode::CREATED || !stored {
            failures.push(format!("{redirect_uri}: {status} {json}"));
        }
    }
    assert!(failures.is_empty(), "refused:\n{}", failures.join("\n"));
}

#[tokio::test]
async fn registration_refuses_disallowed_redirect_uris_and_stores_no_client() {
    // Each list ends with the URI it is refused for.
    let refused: &[&[&str]] = &[
        &["http://evil.example/cb"],
        &["http://10.0.0.5/cb"],
        &["http://[2001:db8::1]/cb"],
        &["http://localhost.evil.example/cb"],
        &["javascript:alert(1)"],
        &["JavaScript:alert(1)"],
        &["data:text/html,x"],
        &["vbscript:x"],
        &["file:///etc/passwd"],
        &["blob:https://example.com/x"],
        &["about:blank"],
        &["https://example.com/cb#frag"],
        &["https://example.com/cb#"],
        &["https://example.com/cb?code=x"],
        &["https://example.com/cb?state=x"],
        &["https://example.com/cb?error=x"],
        &["https://example.com/cb?error_description=x"],
        &["https://example.com/cb?error_uri=x"],
        &["https://example.com/cb?app=1&iss=x"],
        &["not a url"],
        &["/cb"],
        &[],
        &["https://example.com/cb", "http://evil.example/cb"],
    ];
    let mut failures = Vec::new();
    for redirect_uris in refused {
        let (app, store) = build_test_router(None);
        let response = post_register(&app, redirect_uris).await;
        let status = response.status();
        let json = body_to_json(response.into_body()).await;
        let description = json["error_description"].as_str().unwrap_or("");
        let names_offender = redirect_uris
            .last()
            .is_none_or(|offending| description.contains(offending));
        if status != StatusCode::BAD_REQUEST
            || json["error"] != "invalid_redirect_uri"
            || json.get("client_id").is_some()
            || description.is_empty()
            || !names_offender
            || store.client_count() != 0
        {
            failures.push(format!("{redirect_uris:?}: {status} {json}"));
        }
    }
    assert!(failures.is_empty(), "not refused:\n{}", failures.join("\n"));
}

/// Just over the 24 hours a client may sit unused.
const PAST_CLIENT_IDLE_TTL: Duration = Duration::from_secs(24 * 60 * 60 + 1);

#[tokio::test]
async fn registration_over_the_client_cap_is_429_until_a_client_expires() {
    let (app, store) = build_test_router_with_store(OAuthStoreConfig {
        max_clients: 2,
        ..OAuthStoreConfig::default()
    });
    let first = register_client(&app, "http://localhost/cb").await;
    register_client(&app, "http://localhost/cb").await;

    let response = post_register(&app, &["http://localhost/cb"]).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["error"], "invalid_client_metadata");
    assert!(json["error_description"].is_string(), "{json}");
    assert!(json.get("client_id").is_none(), "{json}");
    assert_eq!(store.client_count(), 2);

    // A client unused for a day no longer counts against the cap.
    store.backdate_client(&first, PAST_CLIENT_IDLE_TTL);
    register_client(&app, "http://localhost/cb").await;
    assert!(!store.has_client(&first));
    assert_eq!(store.client_count(), 2);
}

#[tokio::test]
async fn sweep_drops_unused_client_so_authorize_refuses_it() {
    let (app, store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;
    store.backdate_client(&client_id, PAST_CLIENT_IDLE_TTL);
    store.sweep_expired();

    let response = get_authorize(
        &app,
        "response_type=code&code_challenge=challenge&code_challenge_method=S256",
        &client_id,
        "http://localhost/cb",
    )
    .await;
    assert_json_error_without_redirect(response, "invalid_request", "swept client").await;
}

/// POST `/oauth/register` with `client_name` and `redirect_uris`.
async fn post_register_named(
    app: &Router,
    client_name: &str,
    redirect_uris: &[String],
) -> Response {
    post_register_json(
        app,
        &serde_json::json!({
            "client_name": client_name,
            "redirect_uris": redirect_uris,
        }),
    )
    .await
}

/// `https://example.com/` plus a path that makes it exactly `bytes` long.
fn redirect_uri_of_len(bytes: usize) -> String {
    let base = "https://example.com/";
    format!(
        "{base}{}",
        "a".repeat(bytes.checked_sub(base.len()).unwrap())
    )
}

/// `count` distinct `https://example.com/cb{index}` redirect URIs.
fn numbered_redirect_uris(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("https://example.com/cb{index}"))
        .collect()
}

#[tokio::test]
async fn registration_accepts_metadata_at_its_size_limits() {
    let (app, store) = build_test_router(None);
    let uris = numbered_redirect_uris(10);
    let ascii_name = post_register_named(&app, &"n".repeat(256), &uris).await;
    assert_eq!(ascii_name.status(), StatusCode::CREATED);

    // 256 characters, counted as characters: 512 bytes.
    let multibyte_name = post_register_named(&app, &"é".repeat(256), &uris[..1]).await;
    assert_eq!(multibyte_name.status(), StatusCode::CREATED);

    let response = post_register_named(&app, "n", &[redirect_uri_of_len(2048)]).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(store.client_count(), 3);
}

#[tokio::test]
async fn registration_refuses_metadata_over_its_size_limits_and_stores_nothing() {
    let one = vec!["https://example.com/cb".to_string()];
    let cases: [(String, Vec<String>, &str); 3] = [
        ("n".repeat(257), one, "client_name"),
        ("n".to_string(), numbered_redirect_uris(11), "redirect_uris"),
        (
            "n".to_string(),
            vec![redirect_uri_of_len(2049)],
            "redirect_uri",
        ),
    ];
    for (client_name, redirect_uris, names) in cases {
        let (app, store) = build_test_router(None);
        let response = post_register_named(&app, &client_name, &redirect_uris).await;
        let text =
            assert_json_error_without_redirect(response, "invalid_client_metadata", names).await;
        assert!(text.contains(names), "{names}: {text}");
        assert!(!text.contains("aaaa"), "{names} echoed: {text}");
        assert_eq!(store.client_count(), 0, "{names}");
    }
}

/// `GET /oauth/authorize` for a client registered for `http://localhost/cb`,
/// with `code_challenge` and `state`, and return the response.
async fn authorize_with(
    app: &Router,
    client_id: &str,
    code_challenge: &str,
    state: &str,
) -> Response {
    get_uri(
        app,
        &format!(
            "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256",
            urlencoding::encode(client_id),
            urlencoding::encode("http://localhost/cb"),
            urlencoding::encode(state),
            urlencoding::encode(code_challenge),
        ),
    )
    .await
}

#[tokio::test]
async fn authorize_accepts_state_and_code_challenge_at_their_limits() {
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;
    let unreserved = "AZaz09-._~";
    for (challenge, state) in [
        ("a".repeat(43), "s".repeat(2048)),
        ("a".repeat(128), String::new()),
        (format!("{unreserved}{}", "b".repeat(33)), "s".to_string()),
    ] {
        let response = authorize_with(&app, &client_id, &challenge, &state).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "challenge {challenge:?}, state of {} bytes",
            state.len()
        );
    }
}

#[tokio::test]
async fn authorize_refuses_an_oversized_state_or_malformed_code_challenge() {
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;
    let valid = "a".repeat(43);
    let cases = [
        (valid, "s".repeat(2049), "state"),
        ("a".repeat(42), "s".to_string(), "code_challenge"),
        ("a".repeat(129), "s".to_string(), "code_challenge"),
        (
            format!("{}=", "a".repeat(42)),
            "s".to_string(),
            "code_challenge",
        ),
        (
            format!("{}+", "a".repeat(42)),
            "s".to_string(),
            "code_challenge",
        ),
        (
            format!("{}é", "a".repeat(41)),
            "s".to_string(),
            "code_challenge",
        ),
        (
            format!("{} ", "a".repeat(42)),
            "s".to_string(),
            "code_challenge",
        ),
    ];
    for (challenge, state, names) in cases {
        let response = authorize_with(&app, &client_id, &challenge, &state).await;
        let context = format!("challenge {challenge:?}, state of {} bytes", state.len());
        let text = assert_json_error_without_redirect(response, "invalid_request", &context).await;
        assert!(text.contains(names), "{context}: {text}");
    }
}

/// Asserts `GET /oauth/authorize` for `client_id` renders a consent page, and
/// returns its nonce.
async fn authorize_ok(app: &Router, client_id: &str) -> String {
    let challenge = pkce::challenge_from_verifier("verifier");
    let response = authorize_with(app, client_id, &challenge, "s").await;
    assert_eq!(response.status(), StatusCode::OK);
    consent_nonce(&body_to_string(response.into_body()).await)
}

/// Asserts approving the `evicted` nonce is refused, and approving each of
/// `kept` issues a code.
async fn assert_only_evicted_nonce_refused(app: &Router, evicted: &str, kept: &[String]) {
    assert_bad_nonce(approve_nonce(app, evicted, &[]).await).await;
    for nonce in kept {
        let response = approve_nonce(app, nonce, &[]).await;
        assert_code_issued(&response);
    }
}

/// Past the per-client cap `/oauth/authorize` still succeeds, evicting that
/// client's oldest request, whose nonce is then refused at approve.
#[tokio::test]
async fn authorize_past_the_per_client_cap_evicts_that_clients_oldest() {
    let (app, store) = build_test_router_with_store(OAuthStoreConfig {
        max_pending_per_client: 2,
        ..OAuthStoreConfig::default()
    });
    let flooder = register_client(&app, "http://localhost/cb").await;
    let victim = register_client(&app, "http://localhost/cb").await;
    let victim_nonce = authorize_ok(&app, &victim).await;
    let oldest = authorize_ok(&app, &flooder).await;
    for _ in 0..5 {
        authorize_ok(&app, &flooder).await;
    }
    let newest = authorize_ok(&app, &flooder).await;
    assert!(store.holds_authorization(&victim_nonce));

    assert_only_evicted_nonce_refused(&app, &oldest, &[newest, victim_nonce]).await;
}

/// Past the global cap `/oauth/authorize` still succeeds, evicting the
/// oldest request of all, whose nonce is then refused at approve.
#[tokio::test]
async fn authorize_past_the_global_cap_evicts_the_oldest() {
    let (app, _store) = build_test_router_with_store(OAuthStoreConfig {
        max_pending_authorizations: 2,
        ..OAuthStoreConfig::default()
    });
    let mut clients = Vec::new();
    for _ in 0..3 {
        clients.push(register_client(&app, "http://localhost/cb").await);
    }
    let mut nonces = Vec::new();
    for client_id in &clients {
        nonces.push(authorize_ok(&app, client_id).await);
    }

    assert_only_evicted_nonce_refused(&app, &nonces[0], &nonces[1..]).await;
}

/// Registers a client for `http://localhost/cb` and returns it with a consent
/// nonce from a `read` authorization.
async fn registered_consent_nonce(app: &Router) -> (String, String) {
    let client_id = register_client(app, "http://localhost/cb").await;
    let consent_nonce = authorize_nonce(app, &AuthorizeRequest::read(&client_id)).await;
    (client_id, consent_nonce)
}

/// The consent nonce names only the client; once the client is gone the
/// nonce is refused rather than approved.
#[tokio::test]
async fn consent_nonce_for_a_removed_client_is_refused() {
    let (app, store) = build_test_router(None);
    let (client_id, consent_nonce) = registered_consent_nonce(&app).await;
    store.forget_client(&client_id);

    let response = approve_nonce(&app, &consent_nonce, &[]).await;
    assert_bad_nonce(response).await;
}

#[tokio::test]
async fn redirects_keep_query_already_on_registered_uri() {
    const REDIRECT_URI: &str = "http://localhost/cb?app=1";
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, REDIRECT_URI).await;

    for (approved, expected_key) in [("true", "code"), ("false", "error")] {
        let consent_nonce = authorize_nonce(
            &app,
            &AuthorizeRequest {
                redirect_uri: REDIRECT_URI,
                state: "s t&u",
                ..AuthorizeRequest::read(&client_id)
            },
        )
        .await;
        let response = post_approve(
            &app,
            &[
                ("consent_nonce", consent_nonce.as_str()),
                ("approved", approved),
            ],
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "approved={approved}"
        );
        let location = location_header(&response);
        assert_eq!(location.matches('?').count(), 1, "{location}");
        let query = query_pairs(&location);
        assert!(query.contains(&("app".into(), "1".into())), "{location}");
        assert!(
            query.iter().any(|(key, _)| key == expected_key),
            "{location}"
        );
        assert!(
            query.contains(&("state".into(), "s t&u".into())),
            "{location}"
        );
    }
}

/// A `state` carrying URL syntax is encoded into one query value, so it can
/// neither add parameters nor end the query.
#[tokio::test]
async fn redirect_encodes_a_hostile_state() {
    const HOSTILE_STATE: &str = "x&code=forged#frag";
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;

    let response = approve_request(
        &app,
        &AuthorizeRequest {
            state: HOSTILE_STATE,
            ..AuthorizeRequest::read(&client_id)
        },
        &[],
    )
    .await;
    let location = location_header(&response);
    let redirect = url::Url::parse(&location).unwrap();
    assert!(redirect.fragment().is_none(), "{location}");
    let query = query_pairs(&location);
    assert_eq!(
        query.iter().filter(|(key, _)| key == "code").count(),
        1,
        "{location}"
    );
    assert!(
        query.contains(&("state".into(), HOSTILE_STATE.into())),
        "{location}"
    );
}

#[tokio::test]
async fn registered_uri_that_url_reserialises_still_exchanges() {
    // `url::Url` serialises this as `http://localhost:3000/`, but `/token`
    // compares the redirect URI the client sends byte for byte.
    const REDIRECT_URI: &str = "http://localhost:3000";
    assert_ne!(
        url::Url::parse(REDIRECT_URI).unwrap().as_str(),
        REDIRECT_URI
    );
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, REDIRECT_URI).await;
    let verifier = "verifier-that-is-long-enough-for-pkce-checks";

    let approval = approve_request(
        &app,
        &AuthorizeRequest {
            redirect_uri: REDIRECT_URI,
            verifier,
            ..AuthorizeRequest::read(&client_id)
        },
        &[],
    )
    .await;
    assert_eq!(approval.status(), StatusCode::SEE_OTHER);
    let location = location_header(&approval);
    assert!(
        location.starts_with("http://localhost:3000/?"),
        "{location}"
    );

    let json = exchange_ok(
        &app,
        &code_from_location(&location),
        &client_id,
        REDIRECT_URI,
        verifier,
    )
    .await;
    assert!(json["access_token"].is_string(), "{json}");
}

/// Register a client named `client_name` for `redirect_uris` and return its
/// `client_id`.
async fn register_named_client(app: &Router, client_name: &str, redirect_uris: &[&str]) -> String {
    let redirect_uris: Vec<String> = redirect_uris.iter().map(ToString::to_string).collect();
    client_id_of_registration(post_register_named(app, client_name, &redirect_uris).await).await
}

/// Asserts `response` is the bad-nonce refusal: 403, `invalid_request`, and
/// no redirect, so no code.
async fn assert_bad_nonce(response: Response) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get(header::LOCATION).is_none());
    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["error"], "invalid_request");
    assert_eq!(json["error_description"], "Invalid or expired CSRF nonce");
}

#[tokio::test]
async fn approval_grants_only_what_authorize_validated() {
    let (app, _store) = build_test_router(None);
    let client_id = register_named_client(
        &app,
        "Test",
        &["http://localhost/cb", "http://localhost/other"],
    )
    .await;
    let other_client_id = register_client(&app, "http://localhost/other").await;
    let verifier = "original-verifier-that-is-long-enough-for-pkce";
    let forged_challenge =
        pkce::challenge_from_verifier("forged-verifier-that-is-long-enough-for-pkce");

    // Every authorize parameter posted again, each one different.
    let approval = approve_request(
        &app,
        &AuthorizeRequest {
            state: "original-state",
            verifier,
            ..AuthorizeRequest::read(&client_id)
        },
        &[
            ("client_id", other_client_id.as_str()),
            ("redirect_uri", "http://localhost/other"),
            ("scope", "write"),
            ("state", "forged-state"),
            ("code_challenge", &forged_challenge),
            ("code_challenge_method", "plain"),
        ],
    )
    .await;

    assert_eq!(approval.status(), StatusCode::SEE_OTHER);
    let location = location_header(&approval);
    let redirect = url::Url::parse(&location).unwrap();
    assert_eq!(
        &redirect[..url::Position::AfterPath],
        "http://localhost/cb",
        "{location}"
    );
    assert!(
        query_pairs(&location).contains(&("state".into(), "original-state".into())),
        "{location}"
    );

    let json = exchange_ok(
        &app,
        &code_from_location(&location),
        &client_id,
        "http://localhost/cb",
        verifier,
    )
    .await;
    assert_eq!(json["scope"], "read");
}

#[tokio::test]
async fn consent_nonce_is_spent_by_its_first_use() {
    let (app, _store) = build_test_router(None);
    let client_id = register_client(&app, "http://localhost/cb").await;

    for first_decision in ["true", "false"] {
        let consent_nonce = authorize_nonce(&app, &AuthorizeRequest::read(&client_id)).await;
        let first_use = post_approve(
            &app,
            &[
                ("consent_nonce", consent_nonce.as_str()),
                ("approved", first_decision),
            ],
        )
        .await;
        assert_eq!(
            first_use.status(),
            StatusCode::SEE_OTHER,
            "{first_decision}"
        );

        let response = approve_nonce(&app, &consent_nonce, &[]).await;
        assert_bad_nonce(response).await;
    }
}

/// A wrong PIN spends the nonce too, so each guess needs a fresh
/// `/oauth/authorize`.
#[tokio::test]
async fn consent_nonce_is_spent_by_a_wrong_pin() {
    let (app, _store) = build_test_router(Some(LIMITED_PIN));
    let (_client_id, consent_nonce) = registered_consent_nonce(&app).await;

    let wrong_pin = approve_nonce(&app, &consent_nonce, &[("pin", "wrong-pin")]).await;
    assert_denied(&wrong_pin, "Invalid PIN");
    let response = approve_nonce(&app, &consent_nonce, &[("pin", LIMITED_PIN)]).await;
    assert_bad_nonce(response).await;
}

#[tokio::test]
async fn consent_nonce_past_its_ttl_is_refused() {
    let (app, _store) = build_test_router_with_store(OAuthStoreConfig {
        csrf_nonce_ttl: Duration::ZERO,
        ..OAuthStoreConfig::default()
    });
    let (_client_id, consent_nonce) = registered_consent_nonce(&app).await;
    tokio::time::sleep(Duration::from_millis(10)).await;

    let response = approve_nonce(&app, &consent_nonce, &[]).await;
    assert_bad_nonce(response).await;
}

#[tokio::test]
async fn unknown_consent_nonce_is_refused() {
    let (app, _store) = build_test_router(None);
    let response = approve_nonce(&app, "myapp_consent_unknown", &[]).await;
    assert_bad_nonce(response).await;
}

/// Strings that would mean the consent page reads its own URL.
const URL_READING_SCRIPT: [&str; 3] = ["URLSearchParams", "window.location", "location.search"];

/// Asserts `html` has no script that reads the page's own URL.
fn assert_reads_no_url(html: &str) {
    for script in URL_READING_SCRIPT {
        assert!(!html.contains(script), "page contains {script}");
    }
}

#[tokio::test]
async fn consent_page_renders_the_pending_authorization() {
    let (app, _store) = build_test_router(None);
    let client_id =
        register_named_client(&app, "Consent Client", &["https://consent.example/cb"]).await;
    let request = AuthorizeRequest {
        redirect_uri: "https://consent.example/cb",
        scope: "read write",
        ..AuthorizeRequest::read(&client_id)
    };

    let html = authorize_page(&app, &request).await;
    assert!(html.contains("Consent Client"), "{html}");
    assert!(html.contains(&client_id), "{html}");
    assert!(html.contains("consent.example"), "{html}");
    assert!(html.contains("Read-only access to the API"), "{html}");
    assert!(html.contains("Read and write access to the API"), "{html}");
    assert!(!html.contains("name=\"pin\""), "{html}");
    assert!(!html.contains("[["), "unfilled placeholder: {html}");
    assert_reads_no_url(&html);

    // Unknown scopes are dropped, and `read` is granted when none are left.
    let read_only_html = authorize_page(
        &app,
        &AuthorizeRequest {
            scope: "admin",
            ..request
        },
    )
    .await;
    assert!(
        read_only_html.contains("Read-only access to the API"),
        "{read_only_html}"
    );
    assert!(
        !read_only_html.contains("Read and write access to the API"),
        "{read_only_html}"
    );
    assert!(!read_only_html.contains("admin"), "{read_only_html}");
}

/// Registers a client for `redirect_uri` on a router with `oauth_pin` and
/// returns the consent page for a `read` authorization in `state` there.
async fn consent_page_for(oauth_pin: Option<&str>, redirect_uri: &str, state: &str) -> String {
    let (app, _store) = build_test_router(oauth_pin);
    let client_id = register_client(&app, redirect_uri).await;
    let request = AuthorizeRequest {
        redirect_uri,
        state,
        ..AuthorizeRequest::read(&client_id)
    };
    authorize_page(&app, &request).await
}

/// The page carries the nonce and the decision, and none of the request's
/// own parameters for the form to post back.
#[tokio::test]
async fn consent_form_posts_back_only_the_nonce_decision_and_pin() {
    let html = consent_page_for(Some(LIMITED_PIN), "http://localhost/cb", "state-value").await;
    let names: Vec<&str> = html
        .split("name=\"")
        .skip(1)
        .filter_map(|rest| rest.split_once('"').map(|(name, _)| name))
        .filter(|name| *name != "viewport")
        .collect();
    assert_eq!(names, ["consent_nonce", "approved", "pin"], "{html}");
    let challenge = pkce::challenge_from_verifier("verifier");
    assert!(!html.contains(&challenge), "{html}");
    assert!(!html.contains("state-value"), "{html}");
}

#[tokio::test]
async fn consent_page_renders_the_pin_field_only_when_a_pin_is_configured() {
    let html = consent_page_for(Some("1234"), "http://localhost/cb", "s").await;
    assert!(html.contains("name=\"pin\""), "{html}");
}

#[tokio::test]
async fn consent_page_escapes_what_it_renders() {
    let html = consent_page_for(None, "https://a\"b'c&d.example/cb", "s").await;
    assert!(
        html.contains("a&quot;b&#x27;c&amp;d.example"),
        "host not escaped: {html}"
    );
    assert!(!html.contains("a\"b'c&d.example"), "{html}");
    assert_reads_no_url(&html);
}

#[tokio::test]
async fn consent_page_escapes_the_client_name() {
    const CLIENT_NAME: &str = "<img src=x onerror=\"alert('x')\">&[[consent_nonce]]";
    let (app, _store) = build_test_router(None);
    let client_id = register_named_client(&app, CLIENT_NAME, &["http://localhost/cb"]).await;

    let html = authorize_page(&app, &AuthorizeRequest::read(&client_id)).await;
    assert!(
        html.contains(
            "&lt;img src=x onerror=&quot;alert(&#x27;x&#x27;)&quot;&gt;&amp;[[consent_nonce]]"
        ),
        "client name not escaped: {html}"
    );
    assert!(!html.contains("<img"), "{html}");
}

#[tokio::test]
async fn consent_page_escapes_a_hostless_redirect_uri() {
    // An opaque URI has no host, so the page shows the whole URI. `url::Url`
    // keeps `<`, `>` and `"` in its path, so `html_escape` is all that stops
    // them from reaching the page as markup.
    let html = consent_page_for(None, "myapp:<script>alert(\"x\")</script>", "s").await;
    assert!(html.contains("&lt;script&gt;"), "{html}");
    assert!(html.contains("&quot;x&quot;"), "{html}");
    assert!(!html.contains("<script>alert"), "{html}");
}

/// Has `store` issue client `cid` a `read` access token.
fn issue_read_token(store: &OAuthStore) -> AccessToken {
    store.create_access_token("cid".into(), vec!["read".into()])
}

#[tokio::test]
async fn refresh_token_older_than_thirty_days_is_invalid_grant() {
    let (app, test_store) = build_test_router(None);
    let access_token = issue_read_token(&test_store);
    test_store.backdate_refresh_token(
        &access_token.refresh_token,
        Duration::from_secs(30 * 24 * 60 * 60 + 1),
    );

    let response = post_refresh(&app, &access_token.refresh_token, &[("client_id", "cid")]).await;
    assert_invalid_grant(response).await;
}

/// An expired, swept access token does not take its refresh token with it.
#[tokio::test]
async fn refresh_succeeds_after_the_access_token_expires_and_is_swept() {
    let (app, test_store) = build_test_router_with_store(OAuthStoreConfig {
        token_expiry_secs: 0,
        ..OAuthStoreConfig::default()
    });
    let issued = issue_read_token(&test_store);
    tokio::time::sleep(Duration::from_millis(10)).await;
    test_store.sweep_expired();
    assert!(test_store.validate_access_token(&issued.token).is_none());

    let json = refresh_ok(&app, &issued.refresh_token, "cid").await;
    assert!(json["access_token"].is_string(), "{json}");
}

/// POST a `refresh_token` grant for `refresh_token`, adding `extra` fields.
async fn post_refresh(app: &Router, refresh_token: &str, extra: &[(&str, &str)]) -> Response {
    let mut fields = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    fields.extend_from_slice(extra);
    post_form(app, "/oauth/token", &fields).await
}

/// Refresh `refresh_token` as `client_id`, asserting a 200, and return the
/// token JSON.
async fn refresh_ok(app: &Router, refresh_token: &str, client_id: &str) -> serde_json::Value {
    let response = post_refresh(app, refresh_token, &[("client_id", client_id)]).await;
    assert_eq!(response.status(), StatusCode::OK);
    body_to_json(response.into_body()).await
}

async fn assert_invalid_grant(response: Response) {
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_to_json(response.into_body()).await;
    assert_eq!(json["error"], "invalid_grant", "{json}");
}

/// A refused first attempt must consume the token: the issuing client then
/// gets `invalid_grant` for it too.
async fn assert_refused_and_consumed(extra: &[(&str, &str)]) {
    let (app, test_store) = build_test_router(None);
    let issued = issue_read_token(&test_store);

    assert_invalid_grant(post_refresh(&app, &issued.refresh_token, extra).await).await;
    assert_invalid_grant(post_refresh(&app, &issued.refresh_token, &[("client_id", "cid")]).await)
        .await;
}

#[tokio::test]
async fn refresh_with_issuing_client_id_returns_a_new_pair() {
    let (app, test_store) = build_test_router(None);
    let issued = issue_read_token(&test_store);

    let json = refresh_ok(&app, &issued.refresh_token, "cid").await;
    assert_ne!(json["access_token"], issued.token.as_str());
    assert_ne!(json["refresh_token"], issued.refresh_token.as_str());
    assert_eq!(json["scope"], "read");

    // The rotated-out refresh token is spent.
    assert_invalid_grant(post_refresh(&app, &issued.refresh_token, &[("client_id", "cid")]).await)
        .await;
}

#[tokio::test]
async fn refresh_with_other_client_id_is_invalid_grant_and_consumes_the_token() {
    assert_refused_and_consumed(&[("client_id", "myapp_cid_someone-else")]).await;
}

#[tokio::test]
async fn refresh_without_client_id_is_invalid_grant_and_consumes_the_token() {
    assert_refused_and_consumed(&[]).await;
}

#[tokio::test]
async fn refresh_with_empty_client_id_is_invalid_grant_and_consumes_the_token() {
    assert_refused_and_consumed(&[("client_id", "")]).await;
}

#[tokio::test]
async fn refresh_client_mismatch_body_matches_unknown_refresh_token_body() {
    let (app, test_store) = build_test_router(None);
    let issued = issue_read_token(&test_store);

    let mismatch = post_refresh(&app, &issued.refresh_token, &[("client_id", "other")]).await;
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    let unknown = post_refresh(&app, "myapp_rt_unknown", &[("client_id", "cid")]).await;
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);

    let mismatch_body = axum::body::to_bytes(mismatch.into_body(), usize::MAX)
        .await
        .unwrap();
    let unknown_body = axum::body::to_bytes(unknown.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(mismatch_body, unknown_body);
}

/// Collects formatted log output so a test can read it back.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

thread_local! {
    /// Where log lines emitted on this thread go while a [`LogCapture`] is live.
    static CAPTURED_LOGS: std::cell::RefCell<Option<LogBuffer>> =
        const { std::cell::RefCell::new(None) };
}

/// Writes to the emitting thread's capture buffer, or discards the line.
struct ThreadLogWriter(Option<LogBuffer>);

impl std::io::Write for ThreadLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.0 {
            Some(logs) => logs.write(buf),
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Captures every log line, `TRACE` and above, emitted on the current thread
/// until dropped. The default current-thread `#[tokio::test]` runtime runs the
/// router on the test thread, so a request's logs land here.
///
/// The subscriber is process-wide (`set_global_default`, installed once), not
/// `set_default`: see the root cause on
/// `refresh_client_mismatch_warns_with_both_client_ids_and_no_token`. Each
/// line is routed to the capturing thread's buffer, so tests sharing the
/// process don't see each other's logs.
struct LogCapture(LogBuffer);

impl LogCapture {
    fn start() -> Self {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(|| ThreadLogWriter(CAPTURED_LOGS.with(|logs| logs.borrow().clone())))
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no other global tracing subscriber in the test process");
            // Registering the dispatcher rebuilt every callsite's interest before
            // the global default became visible; rebuild again so a callsite first
            // hit in between doesn't keep the `Interest::never()` it got from
            // `NoSubscriber`.
            tracing::callsite::rebuild_interest_cache();
        });
        let logs = LogBuffer::default();
        CAPTURED_LOGS.with(|captured| *captured.borrow_mut() = Some(logs.clone()));
        Self(logs)
    }

    fn output(&self) -> String {
        let bytes = self
            .0
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        String::from_utf8(bytes).unwrap()
    }
}

impl Drop for LogCapture {
    fn drop(&mut self) {
        CAPTURED_LOGS.with(|captured| *captured.borrow_mut() = None);
    }
}

/// Issues a `read` token for `cid` on a fresh router and asserts refreshing
/// it as `other` is `invalid_grant`. Returns the issued token.
async fn refuse_refresh_from_other_client() -> AccessToken {
    let (app, test_store) = build_test_router(None);
    let issued = issue_read_token(&test_store);
    let refused = post_refresh(&app, &issued.refresh_token, &[("client_id", "other")]).await;
    assert_invalid_grant(refused).await;
    issued
}

/// A refused refresh logs a `WARN` naming both clients and never a token.
///
/// Root cause of this test's old flakiness under plain `cargo test` (it passed
/// under nextest, one process per test): it captured with a scoped
/// `tracing::subscriber::set_default` subscriber. In tracing-core 0.1.36,
/// `src/callsite.rs`, `dispatchers::Dispatchers::register_dispatch` sets
/// `has_just_one` while at most one dispatcher is registered, so
/// `Dispatchers::rebuilder` returns `Rebuilder::JustOne`, whose `for_each`
/// asks only `dispatcher::get_default`, the default of whichever thread
/// registers the callsite. When another test, on its own thread with no
/// subscriber, first hit this `warn!` while the scoped subscriber was live,
/// `rebuild_callsite_interest` (from `DefaultCallsite::register`) asked
/// `NoSubscriber::register_callsite` (`src/subscriber.rs`), got
/// `Interest::never()` and cached it process-wide in the callsite. The `event!`
/// macro (tracing 0.1.44, `src/macros.rs`) skips a callsite whose interest is
/// never before it consults the current thread's subscriber, so the warning
/// never reached the capture. A callsite registered before `set_default` was
/// not the problem: `register_dispatch` rebuilds every registered callsite.
///
/// [`LogCapture`] installs a global subscriber instead, so every thread's
/// registration sees it. The test hits the callsite on a subscriber-less
/// thread first, as a concurrent test would, so it fails deterministically if
/// the capture goes back to a scoped subscriber.
#[tokio::test]
async fn refresh_client_mismatch_warns_with_both_client_ids_and_no_token() {
    let logs = LogCapture::start();
    std::thread::spawn(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(refuse_refresh_from_other_client());
    })
    .join()
    .unwrap();

    let issued = refuse_refresh_from_other_client().await;

    let output = logs.output();
    let warning = output
        .lines()
        .find(|line| line.contains("WARN") && line.contains("client_id mismatch"))
        .unwrap_or_else(|| panic!("no client mismatch warning in: {output}"));
    assert!(warning.contains("expected_client=cid"), "{warning}");
    assert!(warning.contains("actual_client=other"), "{warning}");
    assert!(!output.contains(&issued.refresh_token), "{output}");
    assert!(!output.contains(&issued.token), "{output}");
}

/// A wrong PIN distinctive enough to find in the logs.
const LOGGED_WRONG_PIN: &str = "wrong-pin-81726354";
/// An unknown bearer token distinctive enough to find in the logs.
const LOGGED_UNKNOWN_BEARER: &str = "myapp_at_unknown-49382716";

/// Drives the whole flow, with a PIN, at `TRACE` and asserts that no access
/// token, refresh token, authorization code or PIN ever reaches the logs,
/// including on the failure paths.
#[tokio::test]
async fn tracing_output_never_contains_tokens_codes_or_the_pin() {
    let logs = LogCapture::start();
    let (app, _store) = build_test_router(Some(LIMITED_PIN));
    let client_id = register_named_client(&app, "Logged Client", &["http://localhost/cb"]).await;
    let verifier = "log-capture-verifier-that-is-long-enough-for-pkce";

    // A wrong PIN, then the right one.
    submit_wrong_pins(&app, &client_id, LOGGED_WRONG_PIN, 1).await;
    let approval = approve_request(
        &app,
        &AuthorizeRequest {
            scope: "read write",
            verifier,
            ..AuthorizeRequest::read(&client_id)
        },
        &[("pin", LIMITED_PIN)],
    )
    .await;
    let code = code_from_location(&location_header(&approval));

    // Exchange the code, then replay it.
    let first = exchange_ok(&app, &code, &client_id, "http://localhost/cb", verifier).await;
    let access_token = first["access_token"].as_str().unwrap().to_string();
    let refresh_token = first["refresh_token"].as_str().unwrap().to_string();
    assert_invalid_grant(
        exchange_code(&app, &code, &client_id, "http://localhost/cb", verifier).await,
    )
    .await;

    // Use the access token, and an unknown one.
    for bearer in [access_token.as_str(), LOGGED_UNKNOWN_BEARER] {
        get_protected(&app, bearer).await;
    }

    // Rotate, then present the new refresh token from the wrong client.
    let second = refresh_ok(&app, &refresh_token, &client_id).await;
    let new_access_token = second["access_token"].as_str().unwrap().to_string();
    let new_refresh_token = second["refresh_token"].as_str().unwrap().to_string();
    assert_invalid_grant(post_refresh(&app, &new_refresh_token, &[("client_id", "other")]).await)
        .await;
    assert_invalid_grant(post_refresh(&app, &refresh_token, &[("client_id", &client_id)]).await)
        .await;

    let output = logs.output();
    // The capture saw the flow, down to `DEBUG`.
    for expected in [
        "POST /oauth/register",
        "GET /oauth/authorize",
        "POST /oauth/approve",
        "Authorization code issued",
        "Access token refreshed",
        "client_id mismatch",
    ] {
        assert!(
            output.contains(expected),
            "missing {expected:?} in: {output}"
        );
    }
    for (what, secret) in [
        ("PIN", LIMITED_PIN),
        ("wrong PIN", LOGGED_WRONG_PIN),
        ("unknown bearer token", LOGGED_UNKNOWN_BEARER),
        ("authorization code", code.as_str()),
        ("access token", access_token.as_str()),
        ("refresh token", refresh_token.as_str()),
        ("rotated access token", new_access_token.as_str()),
        ("rotated refresh token", new_refresh_token.as_str()),
    ] {
        assert!(!output.contains(secret), "{what} logged: {output}");
    }
}

/// The lockout that five wrong PINs start logs a `WARN` with its
/// `Retry-After` seconds, and never the PIN, right or wrong.
#[tokio::test]
async fn pin_lockout_warns_with_retry_after_and_no_pin() {
    let logs = LogCapture::start();
    let (app, _store) = build_test_router(Some(LIMITED_PIN));
    let client_id = register_client(&app, "http://localhost/cb").await;

    submit_wrong_pins(&app, &client_id, LOGGED_WRONG_PIN, MAX_FAILURES).await;
    assert_backoff(submit_consent(&app, &client_id, true, Some(LIMITED_PIN)).await).await;

    let output = logs.output();
    let warnings: Vec<&str> = output
        .lines()
        .filter(|line| line.contains("WARN") && line.contains("locked out"))
        .collect();
    assert_eq!(warnings.len(), 1, "one lockout, one warning: {output}");
    let retry_after = format!("retry_after_secs={}", BASE_BACKOFF.as_secs());
    assert!(
        warnings.iter().all(|line| line.contains(&retry_after)),
        "{output}"
    );
    assert!(
        !output.contains(LOGGED_WRONG_PIN),
        "wrong PIN logged: {output}"
    );
    assert!(!output.contains(LIMITED_PIN), "PIN logged: {output}");
}
