use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::auth::AuthMode;
use crate::config::{McpConfig, ServerConfig};
use crate::middleware::cors::oauth_cors_layer;
use crate::middleware::oauth::{OAuthMiddlewareState, oauth_bearer_auth};
use crate::middleware::static_bearer_auth::{StaticAuthToken, static_bearer_auth};
use crate::oauth;
use crate::oauth::model::OAuthEndpointState;
use crate::oauth::store::{OAuthStore, OAuthStoreConfig};
use crate::secret_digest::SecretDigest;
use crate::shared::{create_api_client, resolve_base_url};
use crate::tools::AppTools;
use axum::{
    middleware::{self},
    routing::{get, post},
};
use myapp_core::SecretString;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager,
    tower::{StreamableHttpServerConfig, StreamableHttpService},
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Every way to set the OAuth consent PIN, named by every PIN refusal.
const OAUTH_PIN_SETTINGS: &str = "pass --oauth-pin <value>, set MYAPP_MCP_OAUTH_PIN or \
                                  MYAPP_MCP_OAUTH_PIN_FILE, or add [mcp] oauth_pin = \"...\" or \
                                  oauth_pin_file = \"...\" to config.toml";

/// The fewest Unicode characters a configured consent PIN may have.
const MIN_OAUTH_PIN_CHARS: usize = 8;

/// The HTTP transport's authentication, resolved from config with the data
/// each mode needs.
#[derive(Debug)]
enum HttpAuth {
    /// A static bearer token, known to be non-blank.
    Token(SecretString),
    /// OAuth 2.1 with PKCE.
    OAuth(OAuthSettings),
    /// No authentication; loopback only.
    None,
}

/// What the OAuth routes need beyond the store, resolved once at startup.
#[derive(Debug)]
struct OAuthSettings {
    /// The external base URL advertised in OAuth metadata.
    base_url: String,
    /// The PIN the consent screen requires, if any.
    pin: Option<SecretString>,
}

impl HttpAuth {
    /// Resolves the configured auth mode for the bind address, failing fast
    /// with an actionable message when it is unsafe.
    ///
    /// - `token`: a non-empty, non-whitespace token must be present.
    /// - `none`: only allowed on a loopback address.
    /// - `oauth`: refuses a wildcard CORS origin (any site could drive the
    ///   flow), refuses plain HTTP on a non-loopback address (tokens/PKCE
    ///   would traverse the network unencrypted) unless
    ///   `oauth_allow_insecure_http` is set, refuses a non-loopback address
    ///   without a consent PIN (any caller could approve itself), and refuses
    ///   an empty or whitespace-only PIN, or one shorter than
    ///   [`MIN_OAUTH_PIN_CHARS`] characters, on any bind.
    fn resolve(config: &ServerConfig, addr: &SocketAddr) -> anyhow::Result<Self> {
        match config.mcp.auth_mode {
            AuthMode::Token => {
                let Some(token) = config
                    .mcp
                    .token
                    .clone()
                    .filter(|token| !token.expose_secret().trim().is_empty())
                else {
                    anyhow::bail!(
                        "auth_mode=\"token\" requires a non-empty token. Pass --token <value>, \
                         set MYAPP_MCP_TOKEN or MYAPP_MCP_TOKEN_FILE, or add [mcp] token = \
                         \"...\" or token_file = \"...\" to config.toml"
                    );
                };
                Ok(Self::Token(token))
            }
            AuthMode::None => {
                if !addr.ip().is_loopback() {
                    anyhow::bail!(
                        "auth_mode=\"none\" is only allowed on loopback addresses. \
                         Current bind address: {addr}"
                    );
                }
                Ok(Self::None)
            }
            AuthMode::OAuth => {
                if config
                    .mcp
                    .oauth_cors
                    .origins
                    .iter()
                    .any(|origin| origin == "*")
                {
                    anyhow::bail!(
                        "auth_mode=\"oauth\" refuses a wildcard CORS origin (\"*\"): it would let \
                         any website drive the OAuth flow. Set [mcp.oauth_cors] origins to an \
                         explicit allow-list."
                    );
                }
                let base_url = resolve_base_url(config, addr);
                let plaintext = !base_url.starts_with("https://");
                if plaintext && !addr.ip().is_loopback() && !config.mcp.oauth_allow_insecure_http {
                    anyhow::bail!(
                        "auth_mode=\"oauth\" over plain HTTP on a non-loopback address ({addr}) \
                         is refused: OAuth tokens and PKCE would traverse the network \
                         unencrypted. Serve HTTPS (set [mcp] base_url to an https:// URL) or, on \
                         a trusted private network, set [mcp] oauth_allow_insecure_http = true."
                    );
                }
                let pin = config.mcp.oauth_pin.clone();
                match pin.as_ref().map(SecretString::expose_secret) {
                    Some(pin) if pin.trim().is_empty() => anyhow::bail!(
                        "auth_mode=\"oauth\" refuses an empty consent PIN: an empty or \
                         whitespace-only PIN is a misconfiguration, not a request for no PIN. \
                         Set a PIN of at least {MIN_OAUTH_PIN_CHARS} characters: \
                         {OAUTH_PIN_SETTINGS}."
                    ),
                    Some(pin) if pin.chars().count() < MIN_OAUTH_PIN_CHARS => anyhow::bail!(
                        "auth_mode=\"oauth\" refuses a consent PIN shorter than \
                         {MIN_OAUTH_PIN_CHARS} characters: a short PIN can be guessed. Set a \
                         longer PIN: {OAUTH_PIN_SETTINGS}."
                    ),
                    None if !addr.ip().is_loopback() => anyhow::bail!(
                        "auth_mode=\"oauth\" on a non-loopback address ({addr}) requires a \
                         consent PIN: without one, any client that can reach the server can \
                         approve its own authorization request and mint a full-access token. \
                         Set a PIN of at least {MIN_OAUTH_PIN_CHARS} characters: \
                         {OAUTH_PIN_SETTINGS}."
                    ),
                    _ => {}
                }
                Ok(Self::OAuth(OAuthSettings { base_url, pin }))
            }
        }
    }
}

/// Builds the socket address to bind from an IP address literal and a port.
///
/// Accepts IPv4 (`127.0.0.1`), bare IPv6 (`::1`), bracketed IPv6 (`[::1]`) and
/// IPv6 with a numeric scope id (`fe80::1%2` or `[fe80::1%2]`). Hostnames such
/// as `localhost` are refused rather than resolved, so the bind address is
/// exactly what the config says.
fn listen_addr(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let host = host.trim();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // A bare IPv6 literal with a scope id needs brackets to carry a port.
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    authority.parse().map_err(|source| {
        anyhow::anyhow!(
            "mcp host {host:?} must be an IPv4 or IPv6 address literal such as 127.0.0.1, ::1, \
             [::1] or fe80::1%2 (scope ids are numeric); hostnames are not resolved ({source})"
        )
    })
}

/// Builds the streamable HTTP service factory. rmcp calls it for every
/// stateless request and every new legacy session, so it hands out clones of
/// one prebuilt handle instead of rebuilding the tool router.
fn service_factory(
    tools: AppTools,
) -> impl Fn() -> Result<AppTools, std::io::Error> + Send + Sync + 'static {
    move || Ok(tools.clone())
}

/// Builds the one tool handler the HTTP transport serves. Under OAuth it
/// requires scopes on every call, so a request that reaches a tool without
/// them is limited to read-only tools; the `token` and `none` modes grant no
/// scopes and leave every tool callable.
fn http_tools(config: &ServerConfig, auth: &HttpAuth) -> anyhow::Result<AppTools> {
    Ok(
        AppTools::new(create_api_client(config)?, config.mcp.max_response_bytes)
            .with_confirm_destructive(config.mcp.confirm_destructive)
            .with_require_scopes(matches!(auth, HttpAuth::OAuth(_))),
    )
}

pub async fn serve(config: &ServerConfig) -> anyhow::Result<()> {
    let addr = listen_addr(&config.mcp.host, config.mcp.port)?;
    let auth = HttpAuth::resolve(config, &addr)?;

    let tools = http_tools(config, &auth)?;

    let cancellation_token = CancellationToken::new();
    let session_manager: Arc<LocalSessionManager> = Arc::default();
    let service: StreamableHttpService<AppTools, LocalSessionManager> = StreamableHttpService::new(
        service_factory(tools),
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
    let router = match auth {
        HttpAuth::Token(token) => {
            tracing::info!("Using static bearer token authentication");
            axum::Router::new()
                .nest_service("/mcp", service)
                .layer(middleware::from_fn_with_state(
                    StaticAuthToken(SecretDigest::new(token.expose_secret())),
                    static_bearer_auth,
                ))
        }
        HttpAuth::OAuth(OAuthSettings { base_url, pin }) => {
            tracing::info!("Using OAuth 2.1 authentication with PKCE");
            let store_config = OAuthStoreConfig::from_mcp_config(&config.mcp);
            let sweep_interval = Duration::from_secs(config.mcp.oauth_sweep_interval_secs);
            let store = OAuthStore::new(store_config);

            store
                .clone()
                .spawn_sweep_task(sweep_interval, cancellation_token.child_token());

            let endpoint_state = Arc::new(OAuthEndpointState {
                store: store.clone(),
                base_url: base_url.clone(),
                oauth_pin: pin
                    .as_ref()
                    .map(|secret| SecretDigest::new(secret.expose_secret())),
                pin_limiter: Arc::default(),
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
        HttpAuth::None => {
            tracing::warn!("Running with auth_mode=none: no authentication on MCP endpoints");
            axum::Router::new().nest_service("/mcp", service)
        }
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

    /// A PIN long enough to pass the startup rules.
    const VALID_PIN: &str = "12345678";

    fn oauth_config(
        origins: Vec<&str>,
        base_url: Option<&str>,
        allow_insecure: bool,
        pin: Option<&str>,
    ) -> ServerConfig {
        let mut config = ServerConfig::default();
        config.mcp.auth_mode = AuthMode::OAuth;
        config.mcp.oauth_cors = OAuthCorsConfig {
            origins: origins.into_iter().map(str::to_string).collect(),
        };
        config.mcp.base_url = base_url.map(str::to_string);
        config.mcp.oauth_allow_insecure_http = allow_insecure;
        config.mcp.oauth_pin = pin.map(SecretString::from);
        config
    }

    fn non_loopback() -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 1], 8080))
    }

    fn loopback() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 8080))
    }

    /// Asserts the refusal names every way to set the PIN.
    fn assert_names_pin_settings(err: &anyhow::Error) {
        let message = err.to_string();
        for setting in [
            "--oauth-pin",
            "MYAPP_MCP_OAUTH_PIN",
            "MYAPP_MCP_OAUTH_PIN_FILE",
            "[mcp] oauth_pin",
            "oauth_pin_file",
        ] {
            assert!(message.contains(setting), "missing {setting} in: {message}");
        }
    }

    #[test]
    fn oauth_refuses_wildcard_cors_origin() {
        let config = oauth_config(
            vec!["*"],
            Some("https://mcp.example.com"),
            false,
            Some(VALID_PIN),
        );
        let err = HttpAuth::resolve(&config, &non_loopback())
            .expect_err("wildcard CORS under oauth must be refused");
        assert!(err.to_string().contains("wildcard"), "got: {err}");
    }

    #[test]
    fn oauth_refuses_plaintext_on_non_loopback() {
        let config = oauth_config(
            vec!["https://app.example.com"],
            Some("http://mcp.example.com"),
            false,
            Some(VALID_PIN),
        );
        let err = HttpAuth::resolve(&config, &non_loopback())
            .expect_err("plaintext oauth off-loopback must be refused");
        assert!(err.to_string().contains("plain HTTP"), "got: {err}");
    }

    #[test]
    fn oauth_allows_plaintext_on_non_loopback_with_override() {
        let config = oauth_config(
            vec!["https://app.example.com"],
            Some("http://mcp.example.com"),
            true,
            Some(VALID_PIN),
        );
        HttpAuth::resolve(&config, &non_loopback())
            .expect("override permits plaintext oauth off-loopback");
    }

    #[test]
    fn oauth_carries_the_base_url_and_pin() {
        let config = oauth_config(
            vec!["https://app.example.com"],
            Some("https://mcp.example.com"),
            false,
            Some(VALID_PIN),
        );
        let HttpAuth::OAuth(settings) = HttpAuth::resolve(&config, &non_loopback()).unwrap() else {
            panic!("auth_mode=oauth must resolve to HttpAuth::OAuth");
        };
        assert_eq!(settings.base_url, "https://mcp.example.com");
        assert_eq!(
            settings.pin.as_ref().map(SecretString::expose_secret),
            Some(VALID_PIN)
        );
    }

    #[test]
    fn oauth_refuses_no_pin_on_non_loopback_https() {
        let config = oauth_config(
            vec!["https://app.example.com"],
            Some("https://mcp.example.com"),
            false,
            None,
        );
        let err = HttpAuth::resolve(&config, &non_loopback())
            .expect_err("pinless oauth off-loopback must be refused");
        assert!(err.to_string().contains("consent PIN"), "got: {err}");
        assert_names_pin_settings(&err);
    }

    #[test]
    fn oauth_insecure_http_override_does_not_waive_pin() {
        let config = oauth_config(
            vec!["https://app.example.com"],
            Some("http://mcp.example.com"),
            true,
            None,
        );
        let err = HttpAuth::resolve(&config, &non_loopback())
            .expect_err("oauth_allow_insecure_http must not waive the PIN");
        assert!(err.to_string().contains("consent PIN"), "got: {err}");
        assert_names_pin_settings(&err);
    }

    /// An oauth config on `addr` with `pin`, served over HTTPS off loopback.
    fn oauth_config_for(addr: &SocketAddr, pin: &str) -> ServerConfig {
        if addr.ip().is_loopback() {
            oauth_config(vec!["http://localhost"], None, false, Some(pin))
        } else {
            oauth_config(
                vec!["https://app.example.com"],
                Some("https://mcp.example.com"),
                false,
                Some(pin),
            )
        }
    }

    #[test]
    fn oauth_refuses_empty_or_whitespace_pin_on_every_bind() {
        for pin in ["", " ", "        ", "\t\n         "] {
            for addr in [loopback(), non_loopback()] {
                let err = HttpAuth::resolve(&oauth_config_for(&addr, pin), &addr)
                    .expect_err("a blank PIN must be refused");
                assert!(
                    err.to_string().contains("empty consent PIN"),
                    "pin={pin:?} addr={addr} got: {err}"
                );
                assert_names_pin_settings(&err);
            }
        }
    }

    #[test]
    fn oauth_refuses_seven_character_pin_on_every_bind() {
        // Seven characters, counted as characters: the second is 14 bytes.
        for pin in ["1234567", "ñññññññ"] {
            for addr in [loopback(), non_loopback()] {
                let err = HttpAuth::resolve(&oauth_config_for(&addr, pin), &addr)
                    .expect_err("a 7-character PIN must be refused");
                assert!(
                    err.to_string().contains("shorter than 8 characters"),
                    "pin={pin:?} addr={addr} got: {err}"
                );
                assert_names_pin_settings(&err);
            }
        }
    }

    #[test]
    fn oauth_allows_eight_character_pin_on_every_bind() {
        for pin in [VALID_PIN, "éééééééé"] {
            for addr in [loopback(), non_loopback()] {
                HttpAuth::resolve(&oauth_config_for(&addr, pin), &addr)
                    .unwrap_or_else(|err| panic!("pin={pin:?} addr={addr}: {err}"));
            }
        }
    }

    #[test]
    fn oauth_allows_no_pin_on_loopback() {
        let config = oauth_config(vec!["http://localhost"], None, false, None);
        let HttpAuth::OAuth(settings) =
            HttpAuth::resolve(&config, &loopback()).expect("pinless oauth on loopback is allowed")
        else {
            panic!("auth_mode=oauth must resolve to HttpAuth::OAuth");
        };
        assert!(settings.pin.is_none());
    }

    #[test]
    fn none_mode_refuses_non_loopback() {
        let mut config = ServerConfig::default();
        config.mcp.auth_mode = AuthMode::None;
        let err = HttpAuth::resolve(&config, &non_loopback())
            .expect_err("auth_mode=none off-loopback must be refused");
        assert!(err.to_string().contains("loopback"), "got: {err}");
        assert!(matches!(
            HttpAuth::resolve(&config, &loopback()),
            Ok(HttpAuth::None)
        ));
    }

    #[test]
    fn token_mode_requires_token() {
        let mut config = ServerConfig::default();
        config.mcp.auth_mode = AuthMode::Token;
        config.mcp.token = None;
        let err = HttpAuth::resolve(&config, &non_loopback())
            .expect_err("auth_mode=token without a token must be refused");
        assert!(err.to_string().contains("token"), "got: {err}");
    }

    /// An empty or whitespace-only token is refused on any bind, and the error
    /// names every way to set one.
    #[test]
    fn token_mode_refuses_empty_or_whitespace_token() {
        for blank in ["", " ", "\t\n "] {
            let mut config = ServerConfig::default();
            config.mcp.token = Some(SecretString::from(blank));
            let message = HttpAuth::resolve(&config, &loopback())
                .expect_err("a blank token must be refused")
                .to_string();
            for source in [
                "--token",
                "MYAPP_MCP_TOKEN",
                "MYAPP_MCP_TOKEN_FILE",
                "[mcp] token",
                "token_file",
            ] {
                assert!(message.contains(source), "{blank:?}: {message}");
            }
        }
    }

    #[test]
    fn token_mode_carries_the_token() {
        let mut config = ServerConfig::default();
        config.mcp.token = Some(SecretString::from("s3cret"));
        let HttpAuth::Token(token) = HttpAuth::resolve(&config, &non_loopback()).unwrap() else {
            panic!("auth_mode=token must resolve to HttpAuth::Token");
        };
        assert_eq!(token.expose_secret(), "s3cret");
    }

    /// Only the OAuth mode's handler requires scopes.
    #[test]
    fn http_tools_require_scopes_only_under_oauth() {
        let mut config = ServerConfig::default();
        config.core.api_key = Some(SecretString::from("test-key"));
        config.mcp.confirm_destructive = false;
        for (auth, required) in [
            (
                HttpAuth::OAuth(OAuthSettings {
                    base_url: "http://127.0.0.1:8080".to_string(),
                    pin: None,
                }),
                true,
            ),
            (HttpAuth::Token(SecretString::from("s3cret")), false),
            (HttpAuth::None, false),
        ] {
            let tools = http_tools(&config, &auth).unwrap();
            assert_eq!(tools.require_scopes, required, "{auth:?}");
            assert!(!tools.confirm_destructive, "{auth:?}");
        }
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn listen_addr_keeps_ipv4_host() {
        assert_eq!(
            listen_addr("127.0.0.1", 8080).unwrap(),
            addr("127.0.0.1:8080")
        );
    }

    #[test]
    fn listen_addr_brackets_bare_ipv6_host() {
        assert_eq!(listen_addr("::1", 8080).unwrap(), addr("[::1]:8080"));
    }

    #[test]
    fn listen_addr_accepts_bracketed_ipv6_host() {
        assert_eq!(listen_addr("[::1]", 8080).unwrap(), addr("[::1]:8080"));
    }

    #[test]
    fn listen_addr_keeps_ipv6_scope_id_bare_or_bracketed() {
        for host in ["fe80::1%2", "[fe80::1%2]"] {
            let SocketAddr::V6(v6) = listen_addr(host, 8080).unwrap() else {
                panic!("{host}: expected an IPv6 address");
            };
            assert_eq!(v6.ip(), &"fe80::1".parse::<std::net::Ipv6Addr>().unwrap());
            assert_eq!(v6.scope_id(), 2, "{host}");
            assert_eq!(v6.port(), 8080, "{host}");
        }
    }

    #[test]
    fn listen_addr_rejects_hostnames_and_named_scope_ids() {
        for host in ["localhost", "mcp.example.com", "fe80::1%eth0"] {
            let message = listen_addr(host, 8080).unwrap_err().to_string();
            assert!(message.contains(&format!("{host:?}")), "{message}");
            assert!(
                message.contains("127.0.0.1, ::1, [::1] or fe80::1%2"),
                "{message}"
            );
        }
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
            service_factory(AppTools::new(client, 1024 * 1024)),
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
    /// is served statelessly even though `legacy_session_mode` is on. It never
    /// sends `initialize`; each request carries its own lifecycle `_meta`.
    #[tokio::test]
    async fn modern_client_is_served_without_a_session() {
        let service = mcp_service();
        let (status, headers, payloads) =
            post(&service, modern_tools_list(), None, Some(V_MODERN)).await;

        assert!(
            status.is_success(),
            "tools/list failed: {status} {payloads:?}"
        );
        assert_eq!(result_of(&payloads)["resultType"], "complete");
        assert!(
            headers.get("mcp-session-id").is_none(),
            "2026-07-28 requests must be stateless, got {headers:?}"
        );
    }

    /// 2026-07-28 replaced the `initialize` handshake, so an `initialize` naming
    /// it is answered with the newest version that still has one (rmcp >= 3.2).
    #[tokio::test]
    async fn initialize_naming_2026_07_28_falls_back_to_newest_legacy_version() {
        let service = mcp_service();
        let (status, _, payloads) = post(&service, initialize(V_MODERN), None, None).await;

        assert!(
            status.is_success(),
            "initialize failed: {status} {payloads:?}"
        );
        assert_eq!(result_of(&payloads)["protocolVersion"], V_LEGACY);
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

    /// A modern `tools/call` of `name` with `arguments`, with every routing
    /// header a 2026-07-28 client sends, including the `Mcp-Param-Item-Id`
    /// promoted from `id`, as `bearer`.
    fn oauth_tool_call(name: &str, arguments: Value, bearer: &str) -> axum::http::Request<Body> {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("authorization", format!("Bearer {bearer}"))
            .header("mcp-protocol-version", V_MODERN)
            .header("mcp-method", "tools/call")
            .header("mcp-name", name);
        if let Some(id) = arguments.get("id") {
            request = request.header("mcp-param-item-id", id.to_string());
        }
        let body = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": V_MODERN,
                    "io.modelcontextprotocol/clientInfo": { "name": "wire-test", "version": "0" },
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        });
        request
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    /// The OAuth middleware's scopes reach `call_tool` through the streamable
    /// HTTP transport: a `read` token is refused a write tool on the wire and
    /// the upstream is never contacted, while a `write` token reaches it.
    #[tokio::test]
    async fn oauth_scopes_are_enforced_on_the_wire() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v3/item/7"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let store = OAuthStore::new(OAuthStoreConfig::default());
        let service: StreamableHttpService<AppTools, LocalSessionManager> =
            StreamableHttpService::new(
                service_factory(crate::tools::test_support::tools_for(&server)),
                Arc::default(),
                StreamableHttpServerConfig::default()
                    .with_legacy_session_mode(true)
                    .with_allowed_hosts(McpConfig::default().allowed_hosts),
            );
        let app = axum::Router::new().nest_service("/mcp", service).layer(
            middleware::from_fn_with_state(
                OAuthMiddlewareState {
                    store: store.clone(),
                    resource_metadata_url: "http://localhost/.well-known/oauth-protected-resource"
                        .to_string(),
                },
                oauth_bearer_auth,
            ),
        );

        let mut results = Vec::new();
        for scope in ["read", "write"] {
            let token = store.create_access_token("wire-test".to_string(), vec![scope.to_string()]);
            let request = oauth_tool_call("myapp_delete_item", json!({ "id": 7 }), &token.token);
            let response = app.clone().oneshot(request).await.expect("infallible");
            assert!(
                response.status().is_success(),
                "{scope}: {}",
                response.status()
            );
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body collects");
            let text = String::from_utf8_lossy(&bytes).to_string();
            let payloads: Vec<Value> = if text.contains("data:") {
                text.lines()
                    .filter_map(|line| line.strip_prefix("data:"))
                    .filter_map(|data| serde_json::from_str(data.trim()).ok())
                    .collect()
            } else {
                serde_json::from_str::<Value>(&text).into_iter().collect()
            };
            results.push(result_of(&payloads));
        }

        let [read, write] = results.as_slice() else {
            panic!("two results: {results:?}");
        };
        assert_eq!(read["isError"], true, "{read}");
        assert_eq!(
            read["content"][0]["text"],
            "insufficient_scope: tool 'myapp_delete_item' requires the 'write' scope",
            "{read}"
        );
        assert_ne!(write["isError"], true, "{write}");
        assert_eq!(write["structuredContent"]["deleted"], true, "{write}");
    }

    /// Every stateless request and legacy session gets the one handler built
    /// at startup rather than a freshly assembled router.
    #[test]
    fn service_factory_shares_one_built_handler() {
        let factory = service_factory(crate::tools::test_support::tools_at(
            myapp_core::Config::default().base_url,
            1024 * 1024,
        ));
        let first = factory().expect("factory yields a handler");
        let second = factory().expect("factory yields a handler");
        assert!(
            first.shares_state_with(&second),
            "each per-request handler must share the state built at startup"
        );
    }

    /// rmcp 3.8 answers the 2026-07-28 `server/discover` request from
    /// `get_info`: the supported versions, the tools capability and this
    /// server's own identity.
    #[tokio::test]
    async fn server_discover_advertises_the_modern_protocol() {
        let service = mcp_service();
        let body = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": V_MODERN,
                    "io.modelcontextprotocol/clientInfo": { "name": "wire-test", "version": "0" },
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        });
        let (status, headers, payloads) = post(&service, body, None, Some(V_MODERN)).await;

        assert!(
            status.is_success(),
            "server/discover failed: {status} {payloads:?}"
        );
        assert!(headers.get("mcp-session-id").is_none(), "{headers:?}");
        let result = result_of(&payloads);
        assert!(
            result["supportedVersions"]
                .as_array()
                .is_some_and(|versions| versions.iter().any(|version| version == V_MODERN)),
            "{result}"
        );
        assert!(result["capabilities"]["tools"].is_object(), "{result}");
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            env!("CARGO_PKG_NAME"),
            "{result}"
        );
    }

    /// `ProtocolVersion::LATEST` caught up to 2026-07-28 in rmcp 3.5, but
    /// `get_info` still names 2026-07-28 explicitly so an SDK bump can't make
    /// this server advertise a version it hasn't implemented. If this ever
    /// fails, the SDK moved its default and the hardcoded constant should be
    /// revisited.
    #[test]
    fn sdk_latest_matches_the_version_we_advertise() {
        assert_eq!(ProtocolVersion::LATEST, ProtocolVersion::V_2026_07_28);
    }
}
