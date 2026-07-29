use std::sync::Arc;
use std::time::Duration;

use crate::config::{McpConfig, ServerConfig};
use crate::middleware::cors::oauth_cors_layer;
use crate::middleware::oauth::{OAuthMiddlewareState, oauth_bearer_auth};
use crate::middleware::static_bearer_auth::{StaticAuthToken, static_bearer_auth};
use crate::oauth;
use crate::oauth::model::OAuthEndpointState;
use crate::oauth::store::{OAuthStore, OAuthStoreConfig};
use crate::shared::{create_api_client, resolve_base_url};
use crate::tools::AppTools;
use axum::{
    middleware::{self},
    routing::{get, post},
};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager,
    tower::{StreamableHttpServerConfig, StreamableHttpService},
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Validates that the configured auth mode is safe for the bind address before
/// the server starts, failing fast with an actionable message otherwise.
///
/// - `token`: a token must be present.
/// - `none`: only allowed on a loopback address.
/// - `oauth`: refuses a wildcard CORS origin (any site could drive the flow) and
///   refuses plain HTTP on a non-loopback address (tokens/PKCE would traverse
///   the network unencrypted) unless `oauth_allow_insecure_http` is set.
fn validate_transport_security(
    config: &ServerConfig,
    addr: &std::net::SocketAddr,
) -> anyhow::Result<()> {
    match config.mcp.auth_mode.as_str() {
        "token" => {
            if config.mcp.token.is_none() {
                anyhow::bail!(
                    "auth_mode=\"token\" requires a token. Set MYAPP_MCP_TOKEN, \
                     pass --token <value>, or add [mcp] token = \"...\" to config.toml"
                );
            }
        }
        "none" => {
            if !addr.ip().is_loopback() {
                anyhow::bail!(
                    "auth_mode=\"none\" is only allowed on loopback addresses. \
                     Current bind address: {addr}"
                );
            }
        }
        "oauth" => {
            if config
                .mcp
                .oauth_cors
                .origins
                .iter()
                .any(|origin| origin == "*")
            {
                anyhow::bail!(
                    "auth_mode=\"oauth\" refuses a wildcard CORS origin (\"*\"): it would let any \
                     website drive the OAuth flow. Set [mcp.oauth_cors] origins to an explicit \
                     allow-list."
                );
            }
            let base_url = resolve_base_url(config, addr);
            let plaintext = !base_url.starts_with("https://");
            if plaintext && !addr.ip().is_loopback() && !config.mcp.oauth_allow_insecure_http {
                anyhow::bail!(
                    "auth_mode=\"oauth\" over plain HTTP on a non-loopback address ({addr}) is \
                     refused: OAuth tokens and PKCE would traverse the network unencrypted. Serve \
                     HTTPS (set [mcp] base_url to an https:// URL) or, on a trusted private \
                     network, set [mcp] oauth_allow_insecure_http = true."
                );
            }
        }
        other => anyhow::bail!("Unknown auth_mode: {other}. Use \"token\", \"oauth\", or \"none\""),
    }
    Ok(())
}

pub async fn serve(config: &ServerConfig) -> anyhow::Result<()> {
    let addr: std::net::SocketAddr = format!("{}:{}", config.mcp.host, config.mcp.port).parse()?;
    validate_transport_security(config, &addr)?;

    let api_client = create_api_client(config)?;
    let max_response_bytes = config.mcp.max_response_bytes;

    let cancellation_token = CancellationToken::new();
    let session_manager: Arc<LocalSessionManager> = Arc::default();
    let service: StreamableHttpService<AppTools, LocalSessionManager> = StreamableHttpService::new(
        move || Ok(AppTools::new(api_client.clone(), max_response_bytes)),
        session_manager,
        StreamableHttpServerConfig::default()
            // Sessions apply only to protocol versions older than 2026-07-28.
            // Per SEP-2567 the 2026-07-28 protocol removed them, so modern
            // clients are served statelessly regardless of this setting; keeping
            // it on preserves sessions and resumability for older clients.
            .with_legacy_session_mode(true)
            .with_cancellation_token(cancellation_token.child_token())
            // Guards against DNS rebinding. Defaults to loopback only, so a
            // non-loopback deployment must list its own hostnames here.
            .with_allowed_hosts(config.mcp.allowed_hosts.clone()),
    );

    tracing::debug!(auth_mode = %config.mcp.auth_mode, "Building router");
    let router = match config.mcp.auth_mode.as_str() {
        "token" => {
            tracing::info!("Using static bearer token authentication");
            // Presence was validated above; treat an absent token as empty
            // rather than panicking, to satisfy the no-unwrap lint wall.
            let token = config
                .mcp
                .token
                .as_ref()
                .map(|secret| secret.expose_secret().to_string())
                .unwrap_or_default();
            axum::Router::new()
                .nest_service("/mcp", service)
                .layer(middleware::from_fn_with_state(
                    StaticAuthToken(token),
                    static_bearer_auth,
                ))
        }
        "oauth" => {
            tracing::info!("Using OAuth 2.1 authentication with PKCE");
            let base_url = resolve_base_url(config, &addr);
            let store_config = OAuthStoreConfig::from_mcp_config(&config.mcp);
            let sweep_interval = Duration::from_secs(config.mcp.oauth_sweep_interval_secs);
            let store = OAuthStore::new(store_config);

            store
                .clone()
                .spawn_sweep_task(sweep_interval, cancellation_token.child_token());

            let endpoint_state = Arc::new(OAuthEndpointState {
                store: store.clone(),
                base_url: base_url.clone(),
                oauth_pin: config
                    .mcp
                    .oauth_pin
                    .as_ref()
                    .map(|secret| secret.expose_secret().to_string()),
            });

            let middleware_state = OAuthMiddlewareState {
                store,
                resource_metadata_url: format!("{base_url}/.well-known/oauth-protected-resource"),
            };

            tracing::debug!(
                %base_url,
                pin_required = endpoint_state.oauth_pin.is_some(),
                "OAuth routes configured"
            );

            let cors_layer = oauth_cors_layer(config.mcp.oauth_cors.clone());

            let oauth_routes = axum::Router::new()
                .route(
                    "/.well-known/oauth-protected-resource",
                    get(oauth::endpoints::protected_resource_metadata),
                )
                .route(
                    "/.well-known/oauth-protected-resource/mcp",
                    get(oauth::endpoints::protected_resource_metadata),
                )
                .route(
                    "/.well-known/oauth-authorization-server",
                    get(oauth::endpoints::authorization_server_metadata)
                        .options(oauth::endpoints::authorization_server_metadata),
                )
                .route(
                    "/.well-known/openid-configuration",
                    get(oauth::endpoints::authorization_server_metadata)
                        .options(oauth::endpoints::authorization_server_metadata),
                )
                .route("/oauth/authorize", get(oauth::endpoints::authorize))
                .route("/oauth/approve", post(oauth::endpoints::approve))
                .route(
                    "/oauth/token",
                    post(oauth::endpoints::token).options(oauth::endpoints::token),
                )
                .route(
                    "/oauth/register",
                    post(oauth::endpoints::register).options(oauth::endpoints::register),
                )
                .layer(cors_layer)
                .with_state(endpoint_state);

            let mcp_routes = axum::Router::new().nest_service("/mcp", service).layer(
                middleware::from_fn_with_state(middleware_state, oauth_bearer_auth),
            );

            oauth_routes.merge(mcp_routes)
        }
        "none" => {
            tracing::warn!("Running with auth_mode=none: no authentication on MCP endpoints");
            axum::Router::new().nest_service("/mcp", service)
        }
        // Unreachable: auth_mode was validated above; kept as a defensive guard.
        // The two matches must stay in sync if you add or rename an auth mode.
        other => anyhow::bail!("Unknown auth_mode: {other}. Use \"token\", \"oauth\", or \"none\""),
    };

    if !addr.ip().is_loopback() {
        tracing::warn!(
            "MCP server binding to non-loopback address {}. \
             Ensure network access is intentional and properly secured.",
            addr
        );
        // Warn rather than fail: binding 0.0.0.0 inside a container while being
        // addressed as localhost is legitimate. But if the Host header carries a
        // public hostname, rmcp's DNS-rebinding guard rejects the request with
        // 403 before it reaches a handler, which is hard to diagnose blind.
        if config.mcp.allowed_hosts == McpConfig::default().allowed_hosts {
            tracing::warn!(
                "[mcp] allowed_hosts is still the loopback default {:?} while \
                 binding to {}. Requests whose Host header is not in that list \
                 will be rejected with 403. Set [mcp] allowed_hosts (or \
                 MYAPP_MCP_ALLOWED_HOSTS) to your public hostname(s).",
                config.mcp.allowed_hosts,
                addr
            );
        }
    }

    tracing::info!(
        "Starting HTTP MCP server on {} (auth_mode={})",
        addr,
        config.mcp.auth_mode
    );
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(cancellation_token))
        .await?;

    Ok(())
}

/// Waits for SIGINT (Ctrl+C) or SIGTERM (Unix), then cancels `cancellation_token`
/// so background tasks (e.g. the OAuth store sweep) exit alongside the HTTP server.
///
/// SIGTERM handling matters for container orchestrators (Docker, Kubernetes) that
/// request graceful shutdown via SIGTERM before escalating to SIGKILL.
async fn shutdown_signal(cancellation_token: CancellationToken) {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install SIGINT handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("Received SIGINT, shutting down HTTP MCP server"),
        () = terminate => tracing::info!("Received SIGTERM, shutting down HTTP MCP server"),
    }

    cancellation_token.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OAuthCorsConfig;
    use axum::body::Body;
    use tower::ServiceExt;

    /// Build a minimal router with the CORS layer applied and send a preflight request.
    /// Returns the `access-control-allow-origin` header value if present.
    async fn preflight_origin(
        cors_config: &OAuthCorsConfig,
        request_origin: &str,
    ) -> Option<String> {
        let cors_layer = oauth_cors_layer(cors_config.clone());
        let router = axum::Router::new()
            .route("/test", axum::routing::get(|| async { "ok" }))
            .layer(cors_layer);

        let request = axum::http::Request::builder()
            .method("OPTIONS")
            .uri("/test")
            .header("origin", request_origin)
            .header("access-control-request-method", "GET")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        response
            .headers()
            .get("access-control-allow-origin")
            .map(|header_val| header_val.to_str().unwrap().to_string())
    }

    #[tokio::test]
    async fn cors_allows_configured_origin() {
        let cors_config = OAuthCorsConfig {
            origins: vec!["http://localhost".to_string()],
        };
        let allowed = preflight_origin(&cors_config, "http://localhost").await;
        assert_eq!(allowed.as_deref(), Some("http://localhost"));
    }

    #[tokio::test]
    async fn cors_rejects_unconfigured_origin() {
        let cors_config = OAuthCorsConfig {
            origins: vec!["http://localhost".to_string()],
        };
        let allowed = preflight_origin(&cors_config, "http://evil.com").await;
        assert!(
            allowed.is_none(),
            "unconfigured origin should not receive CORS header, got: {allowed:?}"
        );
    }

    #[tokio::test]
    async fn cors_wildcard_allows_any_origin() {
        let cors_config = OAuthCorsConfig {
            origins: vec!["*".to_string()],
        };
        let allowed = preflight_origin(&cors_config, "http://anything.example.com").await;
        assert_eq!(allowed.as_deref(), Some("*"));
    }

    #[tokio::test]
    async fn cors_multiple_origins_allowed() {
        let cors_config = OAuthCorsConfig {
            origins: vec![
                "http://localhost".to_string(),
                "https://app.example.com".to_string(),
            ],
        };
        let first = preflight_origin(&cors_config, "http://localhost").await;
        assert_eq!(first.as_deref(), Some("http://localhost"));

        let second = preflight_origin(&cors_config, "https://app.example.com").await;
        assert_eq!(second.as_deref(), Some("https://app.example.com"));
    }

    #[tokio::test]
    async fn cors_default_config_allows_localhost() {
        let cors_config = OAuthCorsConfig::default();
        let allowed = preflight_origin(&cors_config, "http://127.0.0.1").await;
        assert_eq!(allowed.as_deref(), Some("http://127.0.0.1"));
    }

    fn oauth_config(
        origins: Vec<&str>,
        base_url: Option<&str>,
        allow_insecure: bool,
    ) -> ServerConfig {
        let mut config = ServerConfig::default();
        config.mcp.auth_mode = "oauth".to_string();
        config.mcp.oauth_cors = OAuthCorsConfig {
            origins: origins.into_iter().map(str::to_string).collect(),
        };
        config.mcp.base_url = base_url.map(str::to_string);
        config.mcp.oauth_allow_insecure_http = allow_insecure;
        config
    }

    fn non_loopback() -> std::net::SocketAddr {
        std::net::SocketAddr::from(([203, 0, 113, 1], 8080))
    }

    #[test]
    fn oauth_refuses_wildcard_cors_origin() {
        let config = oauth_config(vec!["*"], Some("https://mcp.example.com"), false);
        let err = validate_transport_security(&config, &non_loopback())
            .expect_err("wildcard CORS under oauth must be refused");
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn oauth_refuses_plaintext_on_non_loopback() {
        let config = oauth_config(
            vec!["https://app.example.com"],
            Some("http://mcp.example.com"),
            false,
        );
        let err = validate_transport_security(&config, &non_loopback())
            .expect_err("plaintext oauth off-loopback must be refused");
        assert!(err.to_string().contains("plain HTTP"), "got: {err}");
    }

    #[test]
    fn oauth_allows_plaintext_on_non_loopback_with_override() {
        let config = oauth_config(
            vec!["https://app.example.com"],
            Some("http://mcp.example.com"),
            true,
        );
        validate_transport_security(&config, &non_loopback())
            .expect("override permits plaintext oauth off-loopback");
    }

    #[test]
    fn none_mode_refuses_non_loopback() {
        let mut config = ServerConfig::default();
        config.mcp.auth_mode = "none".to_string();
        let err = validate_transport_security(&config, &non_loopback())
            .expect_err("auth_mode=none off-loopback must be refused");
        assert!(err.to_string().contains("loopback"), "got: {err}");
    }

    #[test]
    fn token_mode_requires_token() {
        let mut config = ServerConfig::default();
        config.mcp.auth_mode = "token".to_string();
        config.mcp.token = None;
        let err = validate_transport_security(&config, &non_loopback())
            .expect_err("auth_mode=token without a token must be refused");
        assert!(err.to_string().contains("token"), "got: {err}");
    }
}

/// End-to-end wire tests for the MCP streamable HTTP transport.
///
/// These drive [`StreamableHttpService`] directly rather than the full router,
/// so they cover exactly the rmcp surface this crate configures without pulling
/// in auth middleware. They exist because none of the protocol behavior they
/// assert is checked by the compiler: the advertised version, the session
/// boundary at 2026-07-28, the `resultType` discriminator, and the SEP-2549
/// cache hints all compile identically whether or not they are correct.
#[cfg(test)]
mod wire_tests {
    use super::*;
    use axum::body::Body;
    use rmcp::model::ProtocolVersion;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    const V_MODERN: &str = "2026-07-28";
    const V_LEGACY: &str = "2025-11-25";

    fn mcp_service() -> StreamableHttpService<AppTools, LocalSessionManager> {
        // `ApiClient::new` performs no I/O, and neither `initialize` nor
        // `tools/list` ever calls the upstream API, so these tests need no
        // network and no mock server.
        let core_config = myapp_core::Config {
            api_key: Some(myapp_core::SecretString::from("test-key")),
            ..myapp_core::Config::default()
        };
        let client = myapp_core::ApiClient::new(core_config).expect("client builds");
        StreamableHttpService::new(
            move || Ok(AppTools::new(client.clone(), 1024 * 1024)),
            Arc::default(),
            StreamableHttpServerConfig::default()
                .with_legacy_session_mode(true)
                .with_allowed_hosts(McpConfig::default().allowed_hosts),
        )
    }

    /// Sends one JSON-RPC message and returns the status, headers, and every
    /// JSON payload in the response (SSE `data:` frames, or a lone JSON body).
    async fn post(
        service: &StreamableHttpService<AppTools, LocalSessionManager>,
        body: Value,
        session_id: Option<&str>,
        protocol_version: Option<&str>,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Vec<Value>) {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/")
            // Loopback, to satisfy rmcp's DNS-rebinding guard.
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(id) = session_id {
            request = request.header("mcp-session-id", id);
        }
        // rmcp cross-validates this header against `_meta.protocolVersion`, so a
        // request declaring one must send the other. Omitted on `initialize`,
        // where the client does not yet know the negotiated version.
        if let Some(version) = protocol_version {
            request = request.header("mcp-protocol-version", version);

            // SEP-2243 routing headers, required from 2026-07-28 onward and
            // validated by the server against the body. Derived here the same
            // way a real client derives them, so these tests exercise the
            // validation path rather than side-stepping it.
            if version >= V_MODERN {
                if let Some(method) = body.get("method").and_then(Value::as_str) {
                    request = request.header("mcp-method", method);
                }
                let name = body
                    .get("params")
                    .and_then(|params| params.get("name").or_else(|| params.get("uri")))
                    .and_then(Value::as_str);
                if let Some(name) = name {
                    request = request.header("mcp-name", name);
                }
            }
        }
        let request = request
            .body(Body::from(body.to_string()))
            .expect("request builds");

        let response = service.clone().oneshot(request).await.expect("infallible");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(Body::new(response.into_body()), usize::MAX)
            .await
            .expect("body collects");
        let text = String::from_utf8_lossy(&bytes).to_string();

        // Responses are `text/event-stream` unless the body is bare JSON.
        let payloads = if text.contains("data:") {
            text.lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .filter_map(|data| serde_json::from_str(data.trim()).ok())
                .collect()
        } else {
            serde_json::from_str::<Value>(&text).into_iter().collect()
        };
        (status, headers, payloads)
    }

    fn initialize(version: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": { "name": "wire-test", "version": "0" }
            }
        })
    }

    /// A 2026-07-28 `tools/list`. Stateless requests carry their own lifecycle
    /// metadata in `_meta` instead of relying on a session (SEP-2575).
    fn modern_tools_list() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": V_MODERN,
                    "io.modelcontextprotocol/clientInfo": { "name": "wire-test", "version": "0" },
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
    }

    fn legacy_tools_list() -> Value {
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })
    }

    fn result_of(payloads: &[Value]) -> Value {
        payloads
            .iter()
            .find(|payload| payload.get("result").is_some())
            .unwrap_or_else(|| panic!("no result in payloads: {payloads:?}"))["result"]
            .clone()
    }

    /// Per SEP-2567 the 2026-07-28 protocol removed sessions, so a modern client
    /// is served statelessly even though `legacy_session_mode` is on.
    #[tokio::test]
    async fn modern_client_negotiates_2026_07_28_without_a_session() {
        let service = mcp_service();
        let (status, headers, payloads) = post(&service, initialize(V_MODERN), None, None).await;

        assert!(
            status.is_success(),
            "initialize failed: {status} {payloads:?}"
        );
        assert_eq!(result_of(&payloads)["protocolVersion"], V_MODERN);
        assert!(
            headers.get("mcp-session-id").is_none(),
            "2026-07-28 requests must be stateless, got {headers:?}"
        );
    }

    /// The other half of dual mode: `legacy_session_mode` still gives pre-2026
    /// clients a session, so they keep resumability.
    #[tokio::test]
    async fn legacy_client_still_gets_a_session() {
        let service = mcp_service();
        let (status, headers, payloads) = post(&service, initialize(V_LEGACY), None, None).await;

        assert!(
            status.is_success(),
            "initialize failed: {status} {payloads:?}"
        );
        assert_eq!(result_of(&payloads)["protocolVersion"], V_LEGACY);
        assert!(
            headers.get("mcp-session-id").is_some(),
            "legacy sessions must still be issued, got {headers:?}"
        );
    }

    /// A modern peer gets the SEP-2322 `resultType` discriminator and the
    /// SEP-2549 cache hints set in `ServerHandler::list_tools`.
    #[tokio::test]
    async fn modern_tools_list_carries_result_type_and_cache_hints() {
        let service = mcp_service();
        let (_, _, _) = post(&service, initialize(V_MODERN), None, None).await;
        let (status, _, payloads) = post(&service, modern_tools_list(), None, Some(V_MODERN)).await;

        assert!(
            status.is_success(),
            "tools/list failed: {status} {payloads:?}"
        );
        let result = result_of(&payloads);
        assert_eq!(result["resultType"], "complete");
        assert_eq!(result["ttlMs"], 300_000);
        assert_eq!(result["cacheScope"], "private");
        assert_eq!(
            result["tools"].as_array().map(Vec::len),
            Some(5),
            "all five tools must be advertised"
        );
    }

    /// The legacy wire shape is unchanged: rmcp clears `resultType` before
    /// replying to a peer that negotiated an older version.
    #[tokio::test]
    async fn legacy_tools_list_omits_result_type() {
        let service = mcp_service();
        let (_, headers, _) = post(&service, initialize(V_LEGACY), None, None).await;
        let session = headers
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .expect("legacy initialize issues a session")
            .to_string();

        let (status, _, payloads) = post(&service, legacy_tools_list(), Some(&session), None).await;
        assert!(
            status.is_success(),
            "tools/list failed: {status} {payloads:?}"
        );
        let result = result_of(&payloads);
        assert!(
            result.get("resultType").is_none(),
            "legacy peers must not receive resultType: {result}"
        );
        assert_eq!(result["tools"].as_array().map(Vec::len), Some(5));
    }

    /// `ProtocolVersion::LATEST` still resolves to 2025-11-25 in rmcp 3.0, which
    /// is why `get_info` names 2026-07-28 explicitly. If this ever fails, the SDK
    /// moved its default and the hardcoded constant should be revisited.
    #[test]
    fn sdk_latest_still_lags_the_version_we_advertise() {
        assert_eq!(ProtocolVersion::LATEST, ProtocolVersion::V_2025_11_25);
    }
}
