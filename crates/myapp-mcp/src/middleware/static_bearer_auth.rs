//! Static Bearer token authentication for the `/mcp` endpoint.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

use crate::secret_digest::SecretDigest;

/// The configured static bearer token, held only as its digest.
#[derive(Clone, Debug)]
pub struct StaticAuthToken(pub SecretDigest);

/// Axum middleware that admits a request only when its `Authorization`
/// header is `Bearer ` followed by the configured token, answering `401`
/// otherwise.
pub async fn static_bearer_auth(
    State(expected): State<StaticAuthToken>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    tracing::debug!(%method, %uri, "static_bearer_auth: incoming request");

    let header = req
        .headers()
        .get("authorization")
        .and_then(|header_value| header_value.to_str().ok())
        .and_then(|auth_header| auth_header.strip_prefix("Bearer "))
        .unwrap_or("");

    // Startup refuses an empty token; the digest never matches one either,
    // so a missing or empty `Authorization` header can never match it.
    if !expected.0.matches(header) {
        tracing::warn!(%method, %uri, "static_bearer_auth: rejected invalid token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    tracing::debug!(%method, %uri, "static_bearer_auth: accepted");
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::middleware;
    use tower::ServiceExt;

    /// Sends one request through a router guarded by the static-bearer layer
    /// expecting `expected`, with `authorization` as the header (if any).
    async fn status_for(expected: &str, authorization: Option<&str>) -> StatusCode {
        let router = axum::Router::new()
            .route("/mcp", axum::routing::get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                StaticAuthToken(SecretDigest::new(expected)),
                static_bearer_auth,
            ));
        let mut request = Request::builder().uri("/mcp");
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        let response = router
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        response.status()
    }

    #[tokio::test]
    async fn empty_expected_token_rejects_every_request() {
        for expected in ["", "   ", "\n\t "] {
            for authorization in [None, Some("Bearer "), Some("Basic dXNlcjpwYXNz"), Some("")] {
                assert_eq!(
                    status_for(expected, authorization).await,
                    StatusCode::UNAUTHORIZED,
                    "expected {expected:?} must reject authorization {authorization:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn whitespace_expected_token_rejects_its_own_value() {
        assert_eq!(
            status_for("   ", Some("Bearer    ")).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn non_empty_token_admits_only_a_matching_bearer() {
        assert_eq!(
            status_for("s3cret", Some("Bearer s3cret")).await,
            StatusCode::OK
        );
        assert_eq!(
            status_for("s3cret", Some("Bearer wrong")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(status_for("s3cret", None).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn prefix_longer_and_empty_bearers_are_rejected() {
        for authorization in [
            "Bearer s3cr",
            "Bearer s3cret-and-more",
            "Bearer s3cret ",
            "Bearer ",
            "bearer s3cret",
        ] {
            assert_eq!(
                status_for("s3cret", Some(authorization)).await,
                StatusCode::UNAUTHORIZED,
                "authorization {authorization:?} must be rejected"
            );
        }
    }
}
