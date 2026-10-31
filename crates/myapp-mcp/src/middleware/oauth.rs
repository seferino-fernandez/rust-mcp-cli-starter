use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::auth::Scopes;
use crate::oauth::store::OAuthStore;

/// State shared with the OAuth bearer-token authentication middleware layer.
#[derive(Clone)]
pub struct OAuthMiddlewareState {
    pub store: OAuthStore,
    pub resource_metadata_url: String,
}

/// Axum middleware that validates an OAuth 2.1 Bearer token from the
/// `Authorization` header.
///
/// On success it inserts the token's [`Scopes`] into the request extensions
/// before forwarding, so the MCP handler can enforce them per tool. No other
/// authentication mode inserts them.
pub async fn oauth_bearer_auth(
    State(state): State<OAuthMiddlewareState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    tracing::debug!(%method, %uri, "oauth_bearer_auth: incoming request");

    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header_value| header_value.to_str().ok())
        .and_then(|auth_header| auth_header.strip_prefix("Bearer "));

    let token = match token {
        Some(value) if !value.is_empty() => value,
        _ => {
            tracing::debug!(%method, %uri, "oauth_bearer_auth: no Bearer token present");
            return unauthorized_response(&state.resource_metadata_url, None);
        }
    };

    if let Some(access_token) = state.store.validate_access_token(token) {
        let scopes = Scopes::parse(&access_token.scope);
        tracing::debug!(
            %method, %uri,
            scope = %scopes,
            "oauth_bearer_auth: token validated"
        );
        req.extensions_mut().insert(scopes);
        next.run(req).await
    } else {
        tracing::warn!(%method, %uri, "oauth_bearer_auth: invalid or expired token");
        unauthorized_response(&state.resource_metadata_url, Some("invalid_token"))
    }
}

/// A `401` whose `WWW-Authenticate` challenge names the resource metadata and
/// every supported scope, so a client can request the scopes it needs.
fn unauthorized_response(resource_metadata_url: &str, error: Option<&str>) -> Response {
    let scopes = Scopes::ALL;
    let www_auth = match error {
        Some(err) => format!(
            "Bearer resource_metadata=\"{resource_metadata_url}\", scope=\"{scopes}\", \
             error=\"{err}\""
        ),
        None => format!("Bearer resource_metadata=\"{resource_metadata_url}\", scope=\"{scopes}\""),
    };

    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, www_auth)],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Scope;
    use crate::oauth::store::OAuthStoreConfig;
    use axum::{Extension, Router, routing::get};
    use tower::ServiceExt;

    const METADATA_URL: &str = "http://127.0.0.1:9999/.well-known/oauth-protected-resource";

    /// Echoes the scopes the middleware attached, or `none` without any.
    async fn echo_scopes(scopes: Option<Extension<Scopes>>) -> String {
        scopes.map_or_else(
            || "none".to_string(),
            |Extension(scopes)| scopes.to_string(),
        )
    }

    fn protected_app() -> (Router, OAuthStore) {
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let state = OAuthMiddlewareState {
            store: store.clone(),
            resource_metadata_url: METADATA_URL.to_string(),
        };
        let app = Router::new().route("/mcp", get(echo_scopes)).layer(
            axum::middleware::from_fn_with_state(state, oauth_bearer_auth),
        );
        (app, store)
    }

    async fn get_with(app: Router, bearer: Option<&str>) -> Response {
        let mut request = Request::get("/mcp");
        if let Some(token) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        app.oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn challenge(response: &Response) -> &str {
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("a 401 carries a challenge")
            .to_str()
            .unwrap()
    }

    #[tokio::test]
    async fn attaches_the_token_scopes_to_the_request() {
        for (granted, expected) in [
            (vec!["read"], "read"),
            (vec!["read", "write"], "read write"),
            (vec!["write", "admin"], "write"),
        ] {
            let (app, store) = protected_app();
            let token = store.create_access_token(
                "client".to_string(),
                granted.iter().map(ToString::to_string).collect(),
            );
            let response = get_with(app, Some(&token.token)).await;
            assert_eq!(response.status(), StatusCode::OK, "{granted:?}");
            assert_eq!(body_text(response).await, expected, "{granted:?}");
        }
    }

    #[tokio::test]
    async fn challenge_advertises_every_supported_scope() {
        let all: Vec<&str> = Scope::ALL.iter().map(|scope| scope.as_str()).collect();
        let expected_scope = format!("scope=\"{}\"", all.join(" "));

        let (app, _store) = protected_app();
        let missing = get_with(app, None).await;
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            challenge(&missing),
            format!("Bearer resource_metadata=\"{METADATA_URL}\", {expected_scope}")
        );

        let (app, _store) = protected_app();
        let invalid = get_with(app, Some("not-a-token")).await;
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            challenge(&invalid),
            format!(
                "Bearer resource_metadata=\"{METADATA_URL}\", {expected_scope}, \
                 error=\"invalid_token\""
            )
        );
    }
}
