//! Server configuration: core client config + MCP-specific settings.
//!
//! [`ServerConfig`] embeds the core [`Config`](myapp_core::Config) and adds an
//! [`McpConfig`] for the MCP server (HTTP bind + endpoint auth). Both are loaded
//! from the same `config.toml`: core fields at the top level, MCP fields under
//! `[mcp]`. Environment overrides use the `MYAPP_MCP_*` prefix, and `*_FILE`
//! variants read a secret from a file (Docker secret convention).

use myapp_core::Config;
use myapp_core::SecretString;
use myapp_core::env::{Env, SystemEnv, env_non_empty, env_non_empty_u64};
use serde::Deserialize;
use std::fmt::{Debug, Formatter};
use std::fs;
use std::path::Path;

const ENV_MCP_HOST: &str = "MYAPP_MCP_HOST";
const ENV_MCP_PORT: &str = "MYAPP_MCP_PORT";
const ENV_MCP_TOKEN: &str = "MYAPP_MCP_TOKEN";
const ENV_MCP_TOKEN_FILE: &str = "MYAPP_MCP_TOKEN_FILE";
const ENV_MCP_AUTH_MODE: &str = "MYAPP_MCP_AUTH_MODE";
const ENV_MCP_BASE_URL: &str = "MYAPP_MCP_BASE_URL";
const ENV_MCP_OAUTH_PIN: &str = "MYAPP_MCP_OAUTH_PIN";
const ENV_MCP_OAUTH_PIN_FILE: &str = "MYAPP_MCP_OAUTH_PIN_FILE";
const ENV_MCP_OAUTH_TOKEN_EXPIRY_SECS: &str = "MYAPP_MCP_OAUTH_TOKEN_EXPIRY_SECS";
const ENV_MCP_OAUTH_AUTH_CODE_TTL_SECS: &str = "MYAPP_MCP_OAUTH_AUTH_CODE_TTL_SECS";
const ENV_MCP_OAUTH_CSRF_NONCE_TTL_SECS: &str = "MYAPP_MCP_OAUTH_CSRF_NONCE_TTL_SECS";
const ENV_MCP_OAUTH_SWEEP_INTERVAL_SECS: &str = "MYAPP_MCP_OAUTH_SWEEP_INTERVAL_SECS";
const ENV_MCP_OAUTH_CORS_ORIGINS: &str = "MYAPP_MCP_OAUTH_CORS_ORIGINS";
const ENV_MCP_MAX_RESPONSE_BYTES: &str = "MYAPP_MCP_MAX_RESPONSE_BYTES";

const DEFAULT_MCP_HOST: &str = "127.0.0.1";
const DEFAULT_MCP_PORT: u16 = 8080;
const DEFAULT_MCP_AUTH_MODE: &str = "token";
const DEFAULT_OAUTH_TOKEN_EXPIRY_SECS: u64 = 3600;
const DEFAULT_OAUTH_AUTH_CODE_TTL_SECS: u64 = 60;
const DEFAULT_OAUTH_CSRF_NONCE_TTL_SECS: u64 = 600;
const DEFAULT_OAUTH_SWEEP_INTERVAL_SECS: u64 = 300;
/// Default cap on serialized tool-result size: 1 MiB. Generous enough not to
/// clip normal API responses, while guarding against pathological payloads.
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// CORS configuration for the MCP OAuth routes.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct OAuthCorsConfig {
    /// Allowed origins for CORS preflight and simple requests.
    ///
    /// Use `["*"]` to allow all origins. Defaults to localhost variants.
    pub origins: Vec<String>,
}

impl Default for OAuthCorsConfig {
    fn default() -> Self {
        Self {
            origins: vec![
                "http://localhost".to_string(),
                "http://127.0.0.1".to_string(),
                "http://[::1]".to_string(),
            ],
        }
    }
}

/// MCP-server-specific settings (host/port + endpoint auth).
#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    /// Bind address for the HTTP transport.
    pub host: String,
    /// Bind port for the HTTP transport.
    pub port: u16,
    /// Optional public base URL for OAuth redirect URIs.
    pub base_url: Option<String>,
    /// Static bearer token for token-based auth. Mutually exclusive with `token_file`.
    pub token: Option<SecretString>,
    /// Path to a file containing the bearer token (alternative to inline `token`).
    pub token_file: Option<String>,
    /// Authentication mode: `"token"`, `"oauth"`, or `"none"`.
    pub auth_mode: String,
    /// PIN code for OAuth authorization. Mutually exclusive with `oauth_pin_file`.
    pub oauth_pin: Option<SecretString>,
    /// Path to a file containing the OAuth PIN (alternative to inline `oauth_pin`).
    pub oauth_pin_file: Option<String>,
    /// OAuth access token lifetime in seconds.
    pub oauth_token_expiry_secs: u64,
    /// TTL for OAuth authorization codes in seconds.
    pub oauth_auth_code_ttl_secs: u64,
    /// TTL for OAuth CSRF nonces in seconds.
    pub oauth_csrf_nonce_ttl_secs: u64,
    /// Interval between sweeps of expired OAuth entries in seconds.
    pub oauth_sweep_interval_secs: u64,
    /// CORS configuration for OAuth routes.
    #[serde(default)]
    pub oauth_cors: OAuthCorsConfig,
    /// Maximum serialized size (bytes) of a tool result. Results exceeding this
    /// are replaced with a bounded `response_too_large` error. Defaults to 1 MiB.
    pub max_response_bytes: usize,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_MCP_HOST.to_string(),
            port: DEFAULT_MCP_PORT,
            base_url: None,
            token: None,
            token_file: None,
            auth_mode: DEFAULT_MCP_AUTH_MODE.to_string(),
            oauth_pin: None,
            oauth_pin_file: None,
            oauth_token_expiry_secs: DEFAULT_OAUTH_TOKEN_EXPIRY_SECS,
            oauth_auth_code_ttl_secs: DEFAULT_OAUTH_AUTH_CODE_TTL_SECS,
            oauth_csrf_nonce_ttl_secs: DEFAULT_OAUTH_CSRF_NONCE_TTL_SECS,
            oauth_sweep_interval_secs: DEFAULT_OAUTH_SWEEP_INTERVAL_SECS,
            oauth_cors: OAuthCorsConfig::default(),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

impl Debug for McpConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("auth_mode", &self.auth_mode)
            .field("oauth_pin", &self.oauth_pin.as_ref().map(|_| "[REDACTED]"))
            .field("oauth_token_expiry_secs", &self.oauth_token_expiry_secs)
            .field("oauth_auth_code_ttl_secs", &self.oauth_auth_code_ttl_secs)
            .field("oauth_csrf_nonce_ttl_secs", &self.oauth_csrf_nonce_ttl_secs)
            .field("oauth_sweep_interval_secs", &self.oauth_sweep_interval_secs)
            .field("oauth_cors", &self.oauth_cors)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// Full server configuration.
#[derive(Debug, Clone, Default)]
pub struct ServerConfig {
    /// Upstream API client config.
    pub core: Config,
    /// MCP server settings.
    pub mcp: McpConfig,
}

/// On-disk shape used only to extract the `[mcp]` table; core fields are parsed
/// by [`Config`].
#[derive(Debug, Default, Deserialize)]
struct McpConfigFile {
    #[serde(default)]
    mcp: McpConfig,
}

impl ServerConfig {
    /// Loads core config + `[mcp]` from `path` (or default), then env overrides.
    ///
    /// Reads environment variables from the real process environment via
    /// [`SystemEnv`]. For test injection, see [`ServerConfig::load_with_env`].
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        Self::load_with_env(path, &SystemEnv)
    }

    /// Like [`ServerConfig::load`], but reads env vars from the given [`Env`].
    pub fn load_with_env(path: Option<&Path>, env: &impl Env) -> anyhow::Result<Self> {
        let core = Config::load_with_env(path, env)?;

        let mut mcp = match Config::resolve_config_path(path, env) {
            Some(ref file_path) if file_path.exists() => {
                let contents = fs::read_to_string(file_path)?;
                let parsed: McpConfigFile = toml::from_str(&contents)
                    .map_err(|err| anyhow::anyhow!("Invalid config TOML: {err}"))?;
                parsed.mcp
            }
            _ => McpConfig::default(),
        };

        apply_mcp_env(&mut mcp, env)?;
        resolve_mcp_secrets(&mut mcp)?;
        Ok(Self { core, mcp })
    }
}

fn apply_mcp_env(mcp: &mut McpConfig, env: &impl Env) -> anyhow::Result<()> {
    if let Some(host) = env_non_empty(env, ENV_MCP_HOST) {
        mcp.host = host;
    }
    if let Some(raw_port) = env_non_empty(env, ENV_MCP_PORT) {
        mcp.port = raw_port
            .parse::<u16>()
            .map_err(|err| anyhow::anyhow!("invalid {ENV_MCP_PORT} value {raw_port:?}: {err}"))?;
    }
    if let Some(val) = env_non_empty(env, ENV_MCP_TOKEN) {
        mcp.token = Some(SecretString::from(val));
        mcp.token_file = None;
    }
    if let Some(val) = env_non_empty(env, ENV_MCP_TOKEN_FILE) {
        mcp.token_file = Some(val);
    }
    if let Some(val) = env_non_empty(env, ENV_MCP_BASE_URL) {
        mcp.base_url = Some(val);
    }
    if let Some(val) = env_non_empty(env, ENV_MCP_AUTH_MODE) {
        mcp.auth_mode = val;
    }
    if let Some(val) = env_non_empty(env, ENV_MCP_OAUTH_PIN) {
        mcp.oauth_pin = Some(SecretString::from(val));
        mcp.oauth_pin_file = None;
    }
    if let Some(val) = env_non_empty(env, ENV_MCP_OAUTH_PIN_FILE) {
        mcp.oauth_pin_file = Some(val);
    }
    if let Some(val) = env_non_empty_u64(env, ENV_MCP_OAUTH_TOKEN_EXPIRY_SECS) {
        mcp.oauth_token_expiry_secs = val;
    }
    if let Some(val) = env_non_empty_u64(env, ENV_MCP_OAUTH_AUTH_CODE_TTL_SECS) {
        mcp.oauth_auth_code_ttl_secs = val;
    }
    if let Some(val) = env_non_empty_u64(env, ENV_MCP_OAUTH_CSRF_NONCE_TTL_SECS) {
        mcp.oauth_csrf_nonce_ttl_secs = val;
    }
    if let Some(val) = env_non_empty_u64(env, ENV_MCP_OAUTH_SWEEP_INTERVAL_SECS) {
        mcp.oauth_sweep_interval_secs = val;
    }
    if let Some(origins_csv) = env_non_empty(env, ENV_MCP_OAUTH_CORS_ORIGINS) {
        mcp.oauth_cors.origins = origins_csv
            .split(',')
            .map(|origin| origin.trim().to_string())
            .filter(|origin| !origin.is_empty())
            .collect();
    }
    if let Some(val) = env_non_empty_u64(env, ENV_MCP_MAX_RESPONSE_BYTES) {
        // Saturate rather than truncate on 32-bit targets: an absurdly large cap
        // simply becomes "effectively unbounded".
        mcp.max_response_bytes = usize::try_from(val).unwrap_or(usize::MAX);
    }
    Ok(())
}

/// Resolves `*_file` secret references into inline secrets, erroring if both an
/// inline value and a file path are set for the same secret.
fn resolve_mcp_secrets(mcp: &mut McpConfig) -> anyhow::Result<()> {
    resolve_secret(&mut mcp.token, mcp.token_file.take(), "token")?;
    resolve_secret(&mut mcp.oauth_pin, mcp.oauth_pin_file.take(), "oauth_pin")?;
    Ok(())
}

/// Reads a `*_file` secret into `slot`, trimming trailing whitespace. If `slot`
/// already holds an inline value and a file path is also given, returns an error.
fn resolve_secret(
    slot: &mut Option<SecretString>,
    file_path: Option<String>,
    field: &str,
) -> anyhow::Result<()> {
    let Some(path) = file_path else {
        return Ok(());
    };
    if slot.is_some() {
        anyhow::bail!("set either {field} or {field}_file, not both");
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| anyhow::anyhow!("failed to read {field}_file {path}: {err}"))?;
    *slot = Some(SecretString::from(raw.trim().to_string()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use myapp_core::env::MapEnv;

    fn expose_secret_opt(secret: &Option<SecretString>) -> Option<&str> {
        secret.as_ref().map(|val| val.expose_secret())
    }

    #[test]
    fn default_mcp_config_has_expected_values() {
        let config = ServerConfig::default();
        assert_eq!(config.mcp.host, "127.0.0.1");
        assert_eq!(config.mcp.port, 8080);
        assert!(config.mcp.token.is_none());
        assert_eq!(config.mcp.auth_mode, "token");
        assert!(config.mcp.oauth_pin.is_none());
        assert_eq!(config.mcp.oauth_token_expiry_secs, 3600);
    }

    #[test]
    fn mcp_config_from_toml() {
        let toml_str = r#"
[mcp]
host = "0.0.0.0"
port = 9090
token = "my-secret-token"
"#;
        let parsed: McpConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.mcp.host, "0.0.0.0");
        assert_eq!(parsed.mcp.port, 9090);
        assert_eq!(
            expose_secret_opt(&parsed.mcp.token),
            Some("my-secret-token")
        );
    }

    #[test]
    fn debug_redacts_mcp_secrets() {
        let toml_str = r#"
[mcp]
token = "super-secret-token"
oauth_pin = "1234"
"#;
        let parsed: McpConfigFile = toml::from_str(toml_str).unwrap();
        let debug_output = format!("{:?}", parsed.mcp);
        assert!(
            !debug_output.contains("super-secret-token"),
            "Debug should not contain token: {debug_output}"
        );
        assert!(
            !debug_output.contains("\"1234\""),
            "Debug should not contain oauth_pin: {debug_output}"
        );
    }

    #[test]
    fn default_oauth_cors_has_localhost_origins() {
        let config = ServerConfig::default();
        assert_eq!(config.mcp.oauth_cors.origins.len(), 3);
        assert!(
            config
                .mcp
                .oauth_cors
                .origins
                .contains(&"http://localhost".to_string())
        );
        assert!(
            config
                .mcp
                .oauth_cors
                .origins
                .contains(&"http://127.0.0.1".to_string())
        );
        assert!(
            config
                .mcp
                .oauth_cors
                .origins
                .contains(&"http://[::1]".to_string())
        );
    }

    #[test]
    fn oauth_cors_origins_from_toml() {
        let toml_str = r#"
[mcp.oauth_cors]
origins = ["https://app.example.com", "http://localhost:3000"]
"#;
        let parsed: McpConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(
            parsed.mcp.oauth_cors.origins,
            vec!["https://app.example.com", "http://localhost:3000"]
        );
    }

    #[test]
    fn oauth_cors_wildcard_from_toml() {
        let toml_str = r#"
[mcp.oauth_cors]
origins = ["*"]
"#;
        let parsed: McpConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.mcp.oauth_cors.origins, vec!["*"]);
    }

    #[test]
    fn mcp_env_overrides_apply() {
        let env = MapEnv::new()
            .with("MYAPP_MCP_HOST", "0.0.0.0")
            .with("MYAPP_MCP_PORT", "9191")
            .with("MYAPP_MCP_AUTH_MODE", "oauth")
            .with("MYAPP_MCP_TOKEN", "env-token");
        let config = ServerConfig::load_with_env(None, &env).unwrap();
        assert_eq!(config.mcp.host, "0.0.0.0");
        assert_eq!(config.mcp.port, 9191);
        assert_eq!(config.mcp.auth_mode, "oauth");
        assert_eq!(expose_secret_opt(&config.mcp.token), Some("env-token"));
    }

    #[test]
    fn non_numeric_port_env_is_rejected() {
        let env = MapEnv::new().with("MYAPP_MCP_PORT", "not-a-number");
        let err = ServerConfig::load_with_env(None, &env).unwrap_err();
        assert!(err.to_string().contains("MYAPP_MCP_PORT"));
    }

    #[test]
    fn max_response_bytes_defaults_to_one_mib() {
        let config = ServerConfig::default();
        assert_eq!(config.mcp.max_response_bytes, 1024 * 1024);
    }

    #[test]
    fn max_response_bytes_env_override_applies() {
        let env = MapEnv::new().with("MYAPP_MCP_MAX_RESPONSE_BYTES", "4096");
        let config = ServerConfig::load_with_env(None, &env).unwrap();
        assert_eq!(config.mcp.max_response_bytes, 4096);
    }

    #[test]
    fn secret_fields_default_to_none() {
        let config = ServerConfig::default();
        assert!(config.mcp.token.is_none());
        assert!(config.mcp.oauth_pin.is_none());
    }
}
