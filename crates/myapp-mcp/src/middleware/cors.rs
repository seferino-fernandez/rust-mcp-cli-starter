//! CORS layer for the OAuth endpoints.

use axum::http;
use tower_http::cors::{Any, CorsLayer};

use crate::config::OAuthCorsConfig;

/// Builds the CORS layer for OAuth routes from [`OAuthCorsConfig`].
///
/// If origins contains `"*"`, allows all origins. Otherwise, parses each
/// origin string as an allowed `HeaderValue`.
pub(crate) fn oauth_cors_layer(cors_config: OAuthCorsConfig) -> CorsLayer {
    let methods = [http::Method::GET, http::Method::POST, http::Method::OPTIONS];

    if cors_config.origins.iter().any(|origin| origin == "*") {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(methods)
            .allow_headers(Any)
    } else {
        let origins: Vec<http::HeaderValue> = cors_config
            .origins
            .into_iter()
            .filter_map(|origin| origin.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(methods)
            .allow_headers(Any)
    }
}
