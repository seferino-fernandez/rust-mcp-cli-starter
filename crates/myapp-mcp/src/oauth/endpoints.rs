use axum::http::header;
use axum::{
    Form, Json,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use crate::oauth::model::{
    ApprovalForm, AuthorizationServerMetadata, AuthorizeQuery, OAuthEndpointState,
    PendingAuthorization, ProtectedResourceMetadata, RegistrationRequest, TokenRequest,
};

use super::limiter::retry_after_secs;
use super::pkce;
use super::store::RefreshError;

const CONSENT_HTML: &str = include_str!("consent.html");

/// `GET /.well-known/oauth-protected-resource`: returns resource metadata
/// including supported scopes and authorization server references.
pub async fn protected_resource_metadata(
    State(state): State<Arc<OAuthEndpointState>>,
) -> impl IntoResponse {
    tracing::debug!("GET /.well-known/oauth-protected-resource");
    let scopes = vec!["read".to_string(), "write".to_string()];
    Json(ProtectedResourceMetadata {
        resource: state.base_url.clone(),
        authorization_servers: vec![state.base_url.clone()],
        scopes_supported: scopes,
        bearer_methods_supported: vec!["header".to_string()],
    })
}

/// `GET /.well-known/oauth-authorization-server`: returns authorization server
/// metadata including endpoints, supported grant types, and PKCE methods.
pub async fn authorization_server_metadata(
    State(state): State<Arc<OAuthEndpointState>>,
) -> impl IntoResponse {
    tracing::debug!("GET /.well-known/oauth-authorization-server");
    let scopes = vec!["read".to_string(), "write".to_string()];
    Json(AuthorizationServerMetadata {
        issuer: state.base_url.clone(),
        authorization_endpoint: format!("{}/oauth/authorize", state.base_url),
        token_endpoint: format!("{}/oauth/token", state.base_url),
        registration_endpoint: format!("{}/oauth/register", state.base_url),
        scopes_supported: scopes,
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
    })
}

/// `GET /oauth/authorize`: validates the authorization request, stores it as
/// a [`PendingAuthorization`] and renders the consent form for it. Requires
/// PKCE `code_challenge` with method `S256`.
///
/// The client and `redirect_uri` are checked first: an unknown client or an
/// unregistered URI gets a JSON 400 and is never redirected to (RFC 6749
/// §4.1.2.1). Parameter errors are JSON 400s too and are never redirected
/// either: registration is open, so a redirect here would let anyone bounce a
/// browser off this server to a URI they registered. Only the consent
/// decision posted to `/oauth/approve` redirects.
///
/// Of the requested scopes only `read` and `write` are kept, and `read` is
/// granted when none are left.
pub async fn authorize(
    State(state): State<Arc<OAuthEndpointState>>,
    Query(params): Query<AuthorizeQuery>,
) -> Response {
    tracing::debug!(
        client_id = %params.client_id,
        redirect_uri = %params.redirect_uri,
        response_type = %params.response_type,
        scope = ?params.scope,
        "GET /oauth/authorize"
    );
    let Some(client) = state
        .store
        .client_for_redirect(&params.client_id, &params.redirect_uri)
    else {
        return unknown_client_response();
    };
    let Ok(redirect_url) = url::Url::parse(&params.redirect_uri) else {
        return unknown_client_response();
    };
    if params.response_type != "code" {
        return bad_request(
            "unsupported_response_type",
            "Only response_type=code is supported",
        );
    }

    let code_challenge_method = match params.code_challenge_method {
        Some(method) if method == "S256" => method,
        Some(other) => {
            return bad_request(
                "invalid_request",
                &format!("Unsupported code_challenge_method: {other}. Only S256 is supported."),
            );
        }
        None => {
            return bad_request(
                "invalid_request",
                "code_challenge and code_challenge_method=S256 are required",
            );
        }
    };

    let Some(code_challenge) = params.code_challenge else {
        return bad_request("invalid_request", "code_challenge is required");
    };

    let requested_scopes: Vec<String> = params
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .filter(|scope| *scope == "read" || *scope == "write")
        .map(ToString::to_string)
        .collect();
    let scopes = if requested_scopes.is_empty() {
        vec!["read".to_string()]
    } else {
        requested_scopes
    };

    let pending = PendingAuthorization {
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uri: params.redirect_uri,
        redirect_url,
        scopes,
        code_challenge,
        code_challenge_method,
        state: params.state,
    };
    let consent_nonce = state.store.begin_authorization(pending.clone());
    let html = render_consent(&pending, &consent_nonce, state.oauth_pin.is_some());
    (
        [
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"),
        ],
        Html(html),
    )
        .into_response()
}

/// `POST /oauth/approve`: processes the consent form submission. On approval,
/// issues an authorization code and redirects to the client's `redirect_uri`.
/// A configured PIN that is empty or whitespace-only never matches.
///
/// The form's consent nonce names the [`PendingAuthorization`] that
/// `GET /oauth/authorize` validated and is spent on first use, whatever the
/// outcome. The client, redirect URI, scopes, PKCE challenge and `state`
/// all come from that record; the form carries only the nonce, the decision
/// and the PIN.
///
/// With a PIN configured, an approval is first checked against the global
/// [`PinLimiter`](super::limiter::PinLimiter): during a backoff it gets
/// `429 Too Many Requests` with `Retry-After` and the PIN is not compared.
/// Denials and pinless approvals never touch the limiter.
pub async fn approve(
    State(state): State<Arc<OAuthEndpointState>>,
    Form(form): Form<ApprovalForm>,
) -> Response {
    tracing::debug!(approved = %form.approved, "POST /oauth/approve");

    let Some(pending) = state.store.take_authorization(&form.consent_nonce) else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Invalid or expired CSRF nonce"
            })),
        )
            .into_response();
    };
    tracing::debug!(
        client_id = %pending.client_id,
        scope = ?pending.scopes,
        "Consent for pending authorization"
    );
    let state_param = pending.state.as_deref().unwrap_or("");

    if form.approved != "true" {
        return redirect_with_error(
            pending.redirect_url,
            state_param,
            "access_denied",
            "User denied the authorization request",
        );
    }

    if let Some(ref expected_pin) = state.oauth_pin {
        let provided_pin = form.pin.as_deref().unwrap_or("");
        // Check, compare and record under one lock, so concurrent guesses
        // cannot all pass `check` before any failure is recorded. Startup
        // refuses an empty PIN; the digest never matches one either, so an
        // empty `pin` field can never match it.
        let outcome = {
            let mut limiter = state
                .pin_limiter
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            match limiter.check(now) {
                Err(remaining) => PinOutcome::Refused(remaining),
                Ok(()) if expected_pin.matches(provided_pin) => {
                    limiter.record_success(now);
                    PinOutcome::Correct
                }
                Ok(()) => PinOutcome::Wrong {
                    backoff: limiter.record_failure(now),
                    failures: limiter.failures_since_reset(),
                },
            }
        };
        match outcome {
            PinOutcome::Correct => {}
            PinOutcome::Refused(remaining) => return pin_backoff_response(remaining),
            PinOutcome::Wrong { backoff, failures } => {
                if let Some(backoff) = backoff {
                    tracing::warn!(
                        backoff_secs = backoff.as_secs(),
                        failures,
                        "Too many wrong consent PINs; refusing approvals during backoff"
                    );
                }
                return redirect_with_error(
                    pending.redirect_url,
                    state_param,
                    "access_denied",
                    "Invalid PIN",
                );
            }
        }
    }

    let code = state.store.create_auth_code(
        pending.client_id.clone(),
        pending.redirect_uri,
        pending.scopes.clone(),
        pending.code_challenge.clone(),
        pending.code_challenge_method.clone(),
    );
    tracing::info!(scope = ?pending.scopes, "Authorization code issued");

    let mut pairs = vec![("code", code.as_str())];
    if !state_param.is_empty() {
        pairs.push(("state", state_param));
    }
    redirect_to_client(pending.redirect_url, &pairs)
}

/// Renders the consent page for `pending`, posting `consent_nonce` back.
/// Every inserted value is HTML-escaped, and the PIN field is only rendered
/// when `pin_required`.
fn render_consent(
    pending: &PendingAuthorization,
    consent_nonce: &str,
    pin_required: bool,
) -> String {
    let redirect_host = pending
        .redirect_url
        .host_str()
        .unwrap_or_else(|| pending.redirect_url.as_str());
    let scope_items: String = pending
        .scopes
        .iter()
        .map(|scope| {
            let label = match scope.as_str() {
                "read" => "Read-only access to the API",
                "write" => "Read and write access to the API",
                other => other,
            };
            format!(
                "    <div class=\"scope-item\">{}</div>\n",
                html_escape(label)
            )
        })
        .collect();
    let pin_field = if pin_required {
        concat!(
            "    <div class=\"pin-field\">\n",
            "      <label for=\"pin\">Enter PIN to authorize:</label>\n",
            "      <input type=\"password\" id=\"pin\" name=\"pin\" autocomplete=\"off\">\n",
            "    </div>\n",
        )
    } else {
        ""
    };
    let client_name = html_escape(
        pending
            .client_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or("An unnamed client"),
    );
    let client_id = html_escape(&pending.client_id);
    let redirect_host = html_escape(redirect_host);
    let consent_nonce = html_escape(consent_nonce);

    // One pass over the template, so an inserted value is never scanned
    // for placeholders itself.
    let mut html = String::with_capacity(CONSENT_HTML.len());
    let mut rest = CONSENT_HTML;
    while let Some((before, after)) = rest.split_once("[[")
        && let Some((name, after)) = after.split_once("]]")
    {
        html.push_str(before);
        html.push_str(match name {
            "client_name" => &client_name,
            "client_id" => &client_id,
            "redirect_host" => &redirect_host,
            "scope_items" => &scope_items,
            "consent_nonce" => &consent_nonce,
            "pin_field" => pin_field,
            _ => "",
        });
        rest = after;
    }
    html.push_str(rest);
    html
}

/// Escapes `& < > " '` so `value` is inert in HTML text and quoted attributes.
fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// What the limiter and the PIN comparison decided for one approval.
enum PinOutcome {
    Correct,
    /// Wrong PIN, with the backoff it started (if any) and the failures
    /// since the limiter last reset.
    Wrong {
        backoff: Option<Duration>,
        failures: u32,
    },
    /// Refused during a backoff, with the time left in it.
    Refused(Duration),
}

/// `429 Too Many Requests` for an approval refused during a PIN backoff.
fn pin_backoff_response(remaining: Duration) -> Response {
    let retry_after = retry_after_secs(remaining);
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.to_string())],
        Json(serde_json::json!({
            "error": "temporarily_unavailable",
            "error_description": format!(
                "Too many wrong PINs; approvals are paused. Retry after {retry_after} seconds."
            )
        })),
    )
        .into_response()
}

/// `POST /oauth/token`: handles token exchange (`authorization_code`) and
/// token refresh (`refresh_token`) grant types.
pub async fn token(
    State(state): State<Arc<OAuthEndpointState>>,
    Form(req): Form<TokenRequest>,
) -> Response {
    tracing::debug!(
        grant_type = %req.grant_type,
        client_id = %req.client_id,
        "POST /oauth/token"
    );
    match req.grant_type.as_str() {
        "authorization_code" => handle_code_exchange(&state, &req),
        "refresh_token" => handle_refresh(&state, &req),
        _ => token_error(
            "unsupported_grant_type",
            "Supported: authorization_code, refresh_token",
        ),
    }
}

fn handle_code_exchange(state: &OAuthEndpointState, req: &TokenRequest) -> Response {
    tracing::debug!(client_id = %req.client_id, "Exchanging authorization code for tokens");

    let code_verifier = match req.code_verifier {
        Some(ref verifier) if !verifier.is_empty() => verifier.as_str(),
        _ => {
            tracing::warn!("Token exchange failed: missing code_verifier");
            return token_error("invalid_request", "code_verifier is required");
        }
    };

    let Some(auth_code) = state.store.consume_auth_code(&req.code) else {
        tracing::warn!("Token exchange failed: invalid or expired authorization code");
        return token_error("invalid_grant", "Invalid or expired authorization code");
    };

    if !pkce::verify(
        &auth_code.code_challenge_method,
        code_verifier,
        &auth_code.code_challenge,
    ) {
        tracing::warn!(client_id = %req.client_id, "Token exchange failed: PKCE verification failed");
        return token_error("invalid_grant", "PKCE verification failed");
    }

    if auth_code.client_id != req.client_id || auth_code.redirect_uri != req.redirect_uri {
        tracing::warn!(
            expected_client = %auth_code.client_id,
            actual_client = %req.client_id,
            "Token exchange failed: client_id or redirect_uri mismatch"
        );
        return token_error("invalid_grant", "client_id or redirect_uri mismatch");
    }

    let access_token = state
        .store
        .create_access_token(auth_code.client_id, auth_code.scope.clone());
    tracing::info!(scope = ?auth_code.scope, "Access token issued");

    token_response(
        &access_token.token,
        &access_token.refresh_token,
        access_token.expires_in,
        &auth_code.scope,
    )
}

/// Rotates a refresh token. The request must name the client the token was
/// issued to in `client_id`; any other value, including none, consumes the
/// token and gets the same body as an unknown token.
fn handle_refresh(state: &OAuthEndpointState, req: &TokenRequest) -> Response {
    tracing::debug!("Refreshing access token");
    if req.refresh_token.is_empty() {
        tracing::warn!("Refresh failed: missing refresh_token");
        return token_error("invalid_request", "refresh_token is required");
    }

    match state
        .store
        .refresh_access_token(&req.refresh_token, &req.client_id)
    {
        Ok(new_access_token) => {
            tracing::info!("Access token refreshed");
            token_response(
                &new_access_token.token,
                &new_access_token.refresh_token,
                new_access_token.expires_in,
                &new_access_token.scope,
            )
        }
        Err(RefreshError::InvalidToken) => {
            tracing::warn!("Refresh failed: invalid refresh token");
            token_error("invalid_grant", "Invalid refresh token")
        }
        Err(RefreshError::ClientMismatch { expected_client }) => {
            tracing::warn!(
                expected_client = %expected_client,
                actual_client = %req.client_id,
                "Refresh failed: client_id mismatch, refresh token consumed"
            );
            // Same body as an unknown token, so the caller learns nothing about it.
            token_error("invalid_grant", "Invalid refresh token")
        }
    }
}

fn token_response(
    access_token: &str,
    refresh_token: &str,
    expires_in: u64,
    scope: &[String],
) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": refresh_token,
            "scope": scope.join(" ")
        })),
    )
        .into_response()
}

fn token_error(error: &str, description: &str) -> Response {
    bad_request(error, description)
}

/// `POST /oauth/register`: dynamic client registration endpoint.
/// Registers a public client and returns its new `client_id` with
/// `token_endpoint_auth_method: "none"`; no `client_secret` is issued, so the
/// client authenticates with PKCE only.
///
/// Every entry in `redirect_uris` must pass [`redirect_uri_violation`]. An
/// empty list or any refused entry gets a JSON 400 `invalid_redirect_uri`
/// (RFC 7591 §3.2.2) and no client is stored. Once the store holds
/// [`MAX_CLIENTS`](super::store::MAX_CLIENTS) clients, registration gets a
/// JSON 429 until unused clients expire.
pub async fn register(
    State(state): State<Arc<OAuthEndpointState>>,
    Json(req): Json<RegistrationRequest>,
) -> Response {
    tracing::debug!(
        client_name = ?req.client_name,
        redirect_uris = ?req.redirect_uris,
        "POST /oauth/register"
    );
    if req.redirect_uris.is_empty() {
        return bad_request(
            "invalid_redirect_uri",
            "At least one redirect_uri is required",
        );
    }
    if let Some(description) = req
        .redirect_uris
        .iter()
        .find_map(|uri| redirect_uri_violation(uri))
    {
        tracing::warn!(%description, "Dynamic client registration refused");
        return bad_request("invalid_redirect_uri", &description);
    }

    let Some(client) = state
        .store
        .register_client(req.client_name, req.redirect_uris.clone())
    else {
        tracing::warn!("Dynamic client registration refused: store at capacity");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "invalid_client_metadata",
                "error_description": "client registration limit reached; retry later"
            })),
        )
            .into_response();
    };
    tracing::info!(client_id = %client.client_id, "Dynamic client registered");

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "client_id": client.client_id,
            "client_name": client.client_name,
            "redirect_uris": req.redirect_uris,
            "token_endpoint_auth_method": "none"
        })),
    )
        .into_response()
}

/// Schemes a registered `redirect_uri` may not use: each can run script or
/// read local content in the user agent rather than reach a client.
const BLOCKED_REDIRECT_SCHEMES: [&str; 6] =
    ["javascript", "data", "file", "vbscript", "blob", "about"];

/// Authorization-response parameters a registered `redirect_uri` may not
/// already carry, so a redirect never repeats them (RFC 6749 §3.1).
const RESERVED_REDIRECT_PARAMS: [&str; 6] = [
    "code",
    "state",
    "error",
    "error_description",
    "error_uri",
    "iss",
];

/// Returns why `redirect_uri` cannot be registered, or `None` when it can.
///
/// It must parse as an absolute URL, carry no fragment (RFC 6749 §3.1.2) and
/// none of [`RESERVED_REDIRECT_PARAMS`] in its query, and be `https`, `http`
/// to a loopback host (`localhost`, `127.0.0.0/8` or `[::1]`), or a native-app
/// private-use scheme (RFC 8252 §7.1) other than [`BLOCKED_REDIRECT_SCHEMES`].
fn redirect_uri_violation(redirect_uri: &str) -> Option<String> {
    let Ok(url) = url::Url::parse(redirect_uri) else {
        return Some(format!(
            "redirect_uri {redirect_uri:?} is not an absolute URL"
        ));
    };
    // `Url` lowercases the scheme, so this match is case-insensitive.
    if BLOCKED_REDIRECT_SCHEMES.contains(&url.scheme()) {
        return Some(format!(
            "redirect_uri {redirect_uri:?} uses the disallowed scheme {:?}",
            url.scheme()
        ));
    }
    if url.fragment().is_some() {
        return Some(format!(
            "redirect_uri {redirect_uri:?} must not include a fragment"
        ));
    }
    if let Some((name, _)) = url
        .query_pairs()
        .find(|(name, _)| RESERVED_REDIRECT_PARAMS.contains(&name.as_ref()))
    {
        return Some(format!(
            "redirect_uri {redirect_uri:?} must not include the authorization response \
             parameter {name:?} in its query"
        ));
    }
    if url.scheme() == "http" {
        let loopback = match url.host() {
            Some(url::Host::Domain(domain)) => domain == "localhost",
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        };
        if !loopback {
            return Some(format!(
                "redirect_uri {redirect_uri:?} uses http to a non-loopback host; use https, \
                 or http only to localhost, 127.0.0.0/8 or [::1]"
            ));
        }
    }
    None
}

fn redirect_with_error(
    redirect_url: url::Url,
    state: &str,
    error: &str,
    description: &str,
) -> Response {
    let mut pairs = vec![("error", error), ("error_description", description)];
    if !state.is_empty() {
        pairs.push(("state", state));
    }
    redirect_to_client(redirect_url, &pairs)
}

/// Redirects to a client's registered redirect URL with `pairs` appended to
/// its query. Any query the registered URI already carries is kept and every
/// value is encoded.
fn redirect_to_client(mut redirect_url: url::Url, pairs: &[(&str, &str)]) -> Response {
    {
        let mut query = redirect_url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
    }
    Redirect::to(redirect_url.as_str()).into_response()
}

fn unknown_client_response() -> Response {
    bad_request(
        "invalid_request",
        "Unknown client_id or redirect_uri mismatch",
    )
}

/// A `400 Bad Request` with an OAuth `error` and `error_description` JSON body.
fn bad_request(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": error,
            "error_description": description
        })),
    )
        .into_response()
}
