//! Server configuration: core client config + MCP-specific settings.
//!
//! [`ServerConfig`] embeds the core [`Config`](myapp_core::Config) and adds an
//! [`McpConfig`] for the MCP server (HTTP bind + endpoint auth). Both are loaded
//! from the same `config.toml`: core fields at the top level, MCP fields under
//! `[mcp]`. Environment overrides use the `MYAPP_MCP_*` prefix, and `*_FILE`
//! variants read a secret from a file (Docker secret convention). CLI flags
//! arrive as [`ServerOverrides`], the top layer above all of these.

use clap::ValueEnum;
use myapp_core::SecretString;
use myapp_core::env::{Env, SystemEnv, env_non_empty, env_parse, env_parse_bool};
use myapp_core::secret::MASKED_VALUE;
use myapp_core::{Config, ConfigOverrides};
use serde::Deserialize;
use std::fmt::{Debug, Formatter};
use std::path::Path;

use crate::auth::{AuthMode, Transport};

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
const ENV_MCP_OAUTH_ALLOW_INSECURE_HTTP: &str = "MYAPP_MCP_OAUTH_ALLOW_INSECURE_HTTP";
const ENV_MCP_MAX_RESPONSE_BYTES: &str = "MYAPP_MCP_MAX_RESPONSE_BYTES";
const ENV_MCP_ALLOWED_HOSTS: &str = "MYAPP_MCP_ALLOWED_HOSTS";

const DEFAULT_MCP_HOST: &str = "127.0.0.1";
const DEFAULT_MCP_PORT: u16 = 8080;
const DEFAULT_OAUTH_TOKEN_EXPIRY_SECS: u64 = 3600;
const DEFAULT_OAUTH_AUTH_CODE_TTL_SECS: u64 = 60;
const DEFAULT_OAUTH_CSRF_NONCE_TTL_SECS: u64 = 600;
const DEFAULT_OAUTH_SWEEP_INTERVAL_SECS: u64 = 300;

/// Default cap on serialized tool-result size: 1 MiB. Generous enough not to
/// clip normal API responses, while guarding against pathological payloads.
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Default `Host` allow-list for the streamable HTTP transport: loopback only.
///
/// Mirrors rmcp's own default. Not empty because rmcp treats an empty
/// list as "accept any `Host`", which switches the DNS-rebinding guard off.
const DEFAULT_ALLOWED_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

fn default_allowed_hosts() -> Vec<String> {
    DEFAULT_ALLOWED_HOSTS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

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
    /// Bind address for the HTTP transport: an IPv4 or IPv6 address literal
    /// (`127.0.0.1`, `::1`, `[::1]`, `fe80::1%2`). Hostnames are not resolved.
    pub host: String,
    /// Bind port for the HTTP transport.
    pub port: u16,
    /// Optional public base URL for OAuth redirect URIs.
    pub base_url: Option<String>,
    /// Static bearer token for token-based auth. Mutually exclusive with
    /// `token_file` in the config file; `--token`, `MYAPP_MCP_TOKEN` and
    /// `MYAPP_MCP_TOKEN_FILE` take precedence over both.
    ///
    /// Must be non-empty when `auth_mode = "token"`: an empty or
    /// whitespace-only token is refused at startup.
    ///
    /// HTTP-only: resolved only for [`Transport::Http`], and `None` after a
    /// stdio load.
    pub token: Option<SecretString>,
    /// Path to a file containing the bearer token (alternative to inline `token`).
    /// Consumed while resolving `token`, so `None` after any load.
    pub token_file: Option<String>,
    /// Authentication mode: `"token"`, `"oauth"`, or `"none"`.
    pub auth_mode: AuthMode,
    /// PIN code for OAuth authorization. Mutually exclusive with
    /// `oauth_pin_file` in the config file; `--oauth-pin`,
    /// `MYAPP_MCP_OAUTH_PIN` and `MYAPP_MCP_OAUTH_PIN_FILE` take precedence
    /// over both.
    ///
    /// HTTP-only: resolved only for [`Transport::Http`], and `None` after a
    /// stdio load.
    pub oauth_pin: Option<SecretString>,
    /// Path to a file containing the OAuth PIN (alternative to inline `oauth_pin`).
    /// Consumed while resolving `oauth_pin`, so `None` after any load.
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
    /// Allow OAuth over plain HTTP on a non-loopback address. Off by default:
    /// tokens and PKCE would otherwise traverse the network unencrypted. Set
    /// only on a trusted private network that terminates TLS elsewhere.
    pub oauth_allow_insecure_http: bool,
    /// Maximum serialized size (bytes) of a tool result. Results exceeding this
    /// are replaced with a bounded `response_too_large` error. Defaults to 1 MiB.
    pub max_response_bytes: usize,
    /// Hostnames (or `host:port` authorities) accepted in the inbound `Host`
    /// header, guarding against DNS rebinding attacks on the MCP endpoint.
    ///
    /// Defaults to loopback only, so **binding to a non-loopback address
    /// requires setting this**, otherwise every request carrying your public
    /// hostname is rejected with 403 before it reaches a handler.
    ///
    /// An **empty list disables the check entirely** and accepts any `Host`.
    /// That is a deliberate escape hatch, not a safe default: prefer listing
    /// your real hostnames.
    pub allowed_hosts: Vec<String>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_MCP_HOST.to_string(),
            port: DEFAULT_MCP_PORT,
            base_url: None,
            token: None,
            token_file: None,
            auth_mode: AuthMode::default(),
            oauth_pin: None,
            oauth_pin_file: None,
            oauth_token_expiry_secs: DEFAULT_OAUTH_TOKEN_EXPIRY_SECS,
            oauth_auth_code_ttl_secs: DEFAULT_OAUTH_AUTH_CODE_TTL_SECS,
            oauth_csrf_nonce_ttl_secs: DEFAULT_OAUTH_CSRF_NONCE_TTL_SECS,
            oauth_sweep_interval_secs: DEFAULT_OAUTH_SWEEP_INTERVAL_SECS,
            oauth_cors: OAuthCorsConfig::default(),
            oauth_allow_insecure_http: false,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            allowed_hosts: default_allowed_hosts(),
        }
    }
}

impl Debug for McpConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| MASKED_VALUE))
            .field("auth_mode", &self.auth_mode)
            .field("oauth_pin", &self.oauth_pin.as_ref().map(|_| MASKED_VALUE))
            .field("oauth_token_expiry_secs", &self.oauth_token_expiry_secs)
            .field("oauth_auth_code_ttl_secs", &self.oauth_auth_code_ttl_secs)
            .field("oauth_csrf_nonce_ttl_secs", &self.oauth_csrf_nonce_ttl_secs)
            .field("oauth_sweep_interval_secs", &self.oauth_sweep_interval_secs)
            .field("oauth_cors", &self.oauth_cors)
            .field("oauth_allow_insecure_http", &self.oauth_allow_insecure_http)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("allowed_hosts", &self.allowed_hosts)
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

/// Explicit values that sit above every other layer: the server's CLI flags.
///
/// Each `Some` beats the matching env var, env `*_FILE` var and TOML setting.
/// A winning `token` or `oauth_pin` is used verbatim, even when empty, and no
/// lower layer's secret file is read.
#[derive(Debug, Default)]
pub struct ServerOverrides {
    /// Core client overrides (`--base-url`, `--api-key`).
    pub core: ConfigOverrides,
    /// HTTP bind host (`--host`).
    pub host: Option<String>,
    /// HTTP bind port (`--port`).
    pub port: Option<u16>,
    /// Static bearer token (`--token`).
    pub token: Option<SecretString>,
    /// External base URL for OAuth metadata (`--mcp-base-url`).
    pub base_url: Option<String>,
    /// Authentication mode (`--auth-mode`).
    pub auth_mode: Option<AuthMode>,
    /// OAuth consent PIN (`--oauth-pin`).
    pub oauth_pin: Option<SecretString>,
}

/// On-disk shape used only to extract the `[mcp]` table; core fields are parsed
/// by [`Config`].
#[derive(Debug, Default, Deserialize)]
struct McpConfigFile {
    #[serde(default)]
    mcp: McpConfig,
}

impl ServerConfig {
    /// Loads core config + `[mcp]` from `path` (or default), then env, then
    /// `overrides`.
    ///
    /// A file named by `path` or `MYAPP_CONFIG` must exist, as in
    /// [`Config::load`]; a missing file at a default location means defaults.
    ///
    /// The HTTP-only secrets, `token` and `oauth_pin`, are resolved only for
    /// [`Transport::Http`]. For [`Transport::Stdio`] no secret `*_FILE` is read
    /// and no secret source is checked: all four secret fields are `None`.
    ///
    /// Reads environment variables from the real process environment via
    /// [`SystemEnv`]. For test injection, see [`ServerConfig::load_with_env`].
    pub fn load(
        path: Option<&Path>,
        overrides: &ServerOverrides,
        transport: Transport,
    ) -> anyhow::Result<Self> {
        Self::load_with_env(path, overrides, &SystemEnv, transport)
    }

    /// Like [`ServerConfig::load`], but reads env vars from the given [`Env`].
    pub fn load_with_env(
        path: Option<&Path>,
        overrides: &ServerOverrides,
        env: &impl Env,
        transport: Transport,
    ) -> anyhow::Result<Self> {
        let core = Config::load_with_env(path, &overrides.core, env)?;
        let mut mcp = Config::read_config_file::<McpConfigFile>(path, env)?.mcp;

        apply_mcp_env(&mut mcp, env)?;
        apply_mcp_overrides(&mut mcp, overrides);
        match transport {
            Transport::Http => resolve_mcp_secrets(&mut mcp, overrides, env)?,
            Transport::Stdio => {
                // stdio never uses these, so drop the TOML's unresolved sources.
                mcp.token = None;
                mcp.token_file = None;
                mcp.oauth_pin = None;
                mcp.oauth_pin_file = None;
            }
        }
        Ok(Self { core, mcp })
    }
}

/// Applies the non-secret CLI overrides, which beat env and TOML.
fn apply_mcp_overrides(mcp: &mut McpConfig, overrides: &ServerOverrides) {
    if let Some(host) = &overrides.host {
        mcp.host.clone_from(host);
    }
    if let Some(port) = overrides.port {
        mcp.port = port;
    }
    if let Some(url) = &overrides.base_url {
        mcp.base_url = Some(url.clone());
    }
    if let Some(mode) = overrides.auth_mode {
        mcp.auth_mode = mode;
    }
}

/// Applies the non-secret `MYAPP_MCP_*` env vars, which beat TOML. A value that
/// does not parse is an error naming the variable and the raw value.
fn apply_mcp_env(mcp: &mut McpConfig, env: &impl Env) -> anyhow::Result<()> {
    if let Some(host) = env_non_empty(env, ENV_MCP_HOST) {
        mcp.host = host;
    }
    if let Some(port) = env_parse(env, ENV_MCP_PORT)? {
        mcp.port = port;
    }
    if let Some(val) = env_non_empty(env, ENV_MCP_BASE_URL) {
        mcp.base_url = Some(val);
    }
    if let Some(val) = env_non_empty(env, ENV_MCP_AUTH_MODE) {
        let Ok(mode) = AuthMode::from_str(val.trim(), false) else {
            anyhow::bail!(
                "invalid {ENV_MCP_AUTH_MODE} value {val:?}: expected one of token, oauth, none"
            );
        };
        mcp.auth_mode = mode;
    }
    if let Some(val) = env_parse(env, ENV_MCP_OAUTH_TOKEN_EXPIRY_SECS)? {
        mcp.oauth_token_expiry_secs = val;
    }
    if let Some(val) = env_parse(env, ENV_MCP_OAUTH_AUTH_CODE_TTL_SECS)? {
        mcp.oauth_auth_code_ttl_secs = val;
    }
    if let Some(val) = env_parse(env, ENV_MCP_OAUTH_CSRF_NONCE_TTL_SECS)? {
        mcp.oauth_csrf_nonce_ttl_secs = val;
    }
    if let Some(val) = env_parse(env, ENV_MCP_OAUTH_SWEEP_INTERVAL_SECS)? {
        mcp.oauth_sweep_interval_secs = val;
    }
    if let Some(origins_csv) = env_non_empty(env, ENV_MCP_OAUTH_CORS_ORIGINS) {
        mcp.oauth_cors.origins = origins_csv
            .split(',')
            .map(|origin| origin.trim().to_string())
            .filter(|origin| !origin.is_empty())
            .collect();
    }
    if let Some(val) = env_parse_bool(env, ENV_MCP_OAUTH_ALLOW_INSECURE_HTTP)? {
        mcp.oauth_allow_insecure_http = val;
    }
    if let Some(val) = env_parse::<u64>(env, ENV_MCP_MAX_RESPONSE_BYTES)? {
        // Saturate rather than truncate on 32-bit targets: an absurdly large cap
        // simply becomes "effectively unbounded".
        mcp.max_response_bytes = usize::try_from(val).unwrap_or(usize::MAX);
    }
    if let Some(hosts_csv) = env_non_empty(env, ENV_MCP_ALLOWED_HOSTS) {
        let hosts: Vec<String> = hosts_csv
            .split(',')
            .map(|host| host.trim().to_string())
            .filter(|host| !host.is_empty())
            .collect();
        // Apply only a non-empty result. An all-whitespace or all-comma value
        // parses to nothing, and rmcp reads an empty allow-list as "accept any
        // Host", so assigning it here would silently switch the DNS-rebinding
        // guard off.
        if !hosts.is_empty() {
            mcp.allowed_hosts = hosts;
        }
    }
    Ok(())
}

/// Resolves the HTTP-only `token` and `oauth_pin` from the highest layer that
/// supplies one. Called only for [`Transport::Http`].
///
/// The order is the CLI flag, then the env var, then the env `*_FILE` var,
/// then the TOML inline value or `*_file`.
fn resolve_mcp_secrets(
    mcp: &mut McpConfig,
    overrides: &ServerOverrides,
    env: &impl Env,
) -> anyhow::Result<()> {
    let toml_token = (mcp.token.take(), mcp.token_file.take());
    mcp.token = resolve_secret(
        overrides.token.clone(),
        toml_token,
        env,
        ENV_MCP_TOKEN,
        ENV_MCP_TOKEN_FILE,
        "token",
    )?;
    let toml_pin = (mcp.oauth_pin.take(), mcp.oauth_pin_file.take());
    mcp.oauth_pin = resolve_secret(
        overrides.oauth_pin.clone(),
        toml_pin,
        env,
        ENV_MCP_OAUTH_PIN,
        ENV_MCP_OAUTH_PIN_FILE,
        "oauth_pin",
    )?;
    Ok(())
}

/// Picks one secret's winning layer before reading any file, so a lower
/// layer's file is never read. Setting both the inline value and `*_file` is an
/// error only within the TOML layer, and only when that layer is the one used.
/// A `Some` CLI value wins verbatim, even when empty.
fn resolve_secret(
    cli_value: Option<SecretString>,
    (toml_value, toml_file): (Option<SecretString>, Option<String>),
    env: &impl Env,
    env_var: &str,
    env_file_var: &str,
    field: &str,
) -> anyhow::Result<Option<SecretString>> {
    if cli_value.is_some() {
        return Ok(cli_value);
    }
    if let Some(val) = env_non_empty(env, env_var) {
        return Ok(Some(SecretString::from(val)));
    }
    if let Some(path) = env_non_empty(env, env_file_var) {
        return read_secret_file(&path, field).map(Some);
    }
    match (toml_value, toml_file) {
        (Some(_), Some(_)) => anyhow::bail!("set either {field} or {field}_file, not both"),
        (Some(val), None) => Ok(Some(val)),
        (None, Some(path)) => read_secret_file(&path, field).map(Some),
        (None, None) => Ok(None),
    }
}

/// Reads a `*_file` secret, trimming surrounding whitespace.
fn read_secret_file(path: &str, field: &str) -> anyhow::Result<SecretString> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("failed to read {field}_file {path}: {err}"))?;
    Ok(SecretString::from(raw.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use myapp_core::env::MapEnv;
    use std::fs;

    fn expose_secret_opt(secret: &Option<SecretString>) -> Option<&str> {
        secret.as_ref().map(|val| val.expose_secret())
    }

    /// Writes `toml` as the config file and returns an env pointing at it,
    /// with the temp directory that also holds any secret files. Keeps every
    /// load away from the real user config.
    fn env_with_toml(toml: &str) -> (tempfile::TempDir, MapEnv) {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.toml");
        fs::write(&config, toml).unwrap();
        let env = MapEnv::new().with("MYAPP_CONFIG", config.to_string_lossy().into_owned());
        (directory, env)
    }

    fn isolated_env() -> (tempfile::TempDir, MapEnv) {
        env_with_toml("")
    }

    /// Writes `contents` to `name` under `directory` and returns its path.
    fn secret_file(directory: &tempfile::TempDir, name: &str, contents: &str) -> String {
        let path = directory.path().join(name);
        fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn missing_file(directory: &tempfile::TempDir) -> String {
        directory
            .path()
            .join("missing-secret")
            .to_string_lossy()
            .into_owned()
    }

    fn load_http(env: &MapEnv) -> anyhow::Result<ServerConfig> {
        ServerConfig::load_with_env(None, &ServerOverrides::default(), env, Transport::Http)
    }

    /// Parses `flags` as the server's command line and returns its overrides.
    fn cli_overrides(flags: &[&str]) -> ServerOverrides {
        use clap::Parser;

        let argv = std::iter::once("myapp-mcp").chain(flags.iter().copied());
        crate::shared::Args::try_parse_from(argv)
            .unwrap()
            .overrides()
    }

    #[test]
    fn default_mcp_config_has_expected_values() {
        let config = ServerConfig::default();
        assert_eq!(config.mcp.host, "127.0.0.1");
        assert_eq!(config.mcp.port, 8080);
        assert!(config.mcp.token.is_none());
        assert_eq!(config.mcp.auth_mode, AuthMode::Token);
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
    fn debug_masks_mcp_secrets() {
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
        assert!(
            debug_output.contains(&format!("token: Some({MASKED_VALUE:?})")),
            "{debug_output}"
        );
        assert!(
            debug_output.contains(&format!("oauth_pin: Some({MASKED_VALUE:?})")),
            "{debug_output}"
        );
    }

    #[test]
    fn server_config_debug_masks_the_api_key_too() {
        let mut config = ServerConfig::default();
        config.core.api_key = Some(SecretString::from("upstream-api-key"));
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("upstream-api-key"), "{debug_output}");
        assert!(debug_output.contains(MASKED_VALUE), "{debug_output}");
    }

    #[test]
    fn default_oauth_cors_has_localhost_origins() {
        let config = ServerConfig::default();
        assert_eq!(
            config.mcp.oauth_cors.origins,
            ["http://localhost", "http://127.0.0.1", "http://[::1]"]
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
        let (_directory, env) = isolated_env();
        let env = env
            .with("MYAPP_MCP_HOST", "0.0.0.0")
            .with("MYAPP_MCP_PORT", "9191")
            .with("MYAPP_MCP_AUTH_MODE", "oauth")
            .with("MYAPP_MCP_TOKEN", "env-token");
        let config = load_http(&env).unwrap();
        assert_eq!(config.mcp.host, "0.0.0.0");
        assert_eq!(config.mcp.port, 9191);
        assert_eq!(config.mcp.auth_mode, AuthMode::OAuth);
        assert_eq!(expose_secret_opt(&config.mcp.token), Some("env-token"));
    }

    #[test]
    fn auth_mode_parses_from_toml_env_and_cli() {
        let (_directory, env) = env_with_toml("[mcp]\nauth_mode = \"oauth\"\n");
        assert_eq!(load_http(&env).unwrap().mcp.auth_mode, AuthMode::OAuth);

        let (_directory, env) = isolated_env();
        let env = env.with("MYAPP_MCP_AUTH_MODE", " none ");
        assert_eq!(load_http(&env).unwrap().mcp.auth_mode, AuthMode::None);

        let overrides = cli_overrides(&["--auth-mode", "oauth"]);
        assert_eq!(overrides.auth_mode, Some(AuthMode::OAuth));
    }

    #[test]
    fn kebab_cased_oauth_is_refused_everywhere() {
        use clap::Parser;

        let (_directory, env) = isolated_env();
        let env = env.with("MYAPP_MCP_AUTH_MODE", "o-auth");
        let err = load_http(&env).unwrap_err();
        assert!(
            err.to_string()
                .contains(r#"invalid MYAPP_MCP_AUTH_MODE value "o-auth""#),
            "{err}"
        );

        let (_directory, env) = env_with_toml("[mcp]\nauth_mode = \"o-auth\"\n");
        load_http(&env).unwrap_err();

        let parsed = crate::shared::Args::try_parse_from(["myapp-mcp", "--auth-mode", "o-auth"]);
        assert_eq!(
            parsed.err().map(|err| err.kind()),
            Some(clap::error::ErrorKind::InvalidValue)
        );
    }

    #[test]
    fn unknown_toml_auth_mode_fails_at_load_naming_the_file_and_position() {
        let (directory, env) = env_with_toml("[mcp]\nauth_mode = \"bogus\"\n");
        let err = load_http(&env).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("unknown variant"), "{message}");
        assert!(
            message.contains(&directory.path().join("config.toml").display().to_string()),
            "{message}"
        );
        assert!(message.contains("line 2, column 13"), "{message}");
    }

    #[test]
    fn mcp_toml_error_never_echoes_a_secret_on_the_bad_line() {
        let (_directory, env) = env_with_toml("[mcp]\ntoken = 123456789\n");
        let err = load_http(&env).unwrap_err();
        let message = err.to_string();
        assert!(!message.contains("123456789"), "{message}");
        assert!(message.contains("line 2, column 9"), "{message}");
    }

    const NUMERIC_ENV_VARS: [&str; 6] = [
        ENV_MCP_PORT,
        ENV_MCP_OAUTH_TOKEN_EXPIRY_SECS,
        ENV_MCP_OAUTH_AUTH_CODE_TTL_SECS,
        ENV_MCP_OAUTH_CSRF_NONCE_TTL_SECS,
        ENV_MCP_OAUTH_SWEEP_INTERVAL_SECS,
        ENV_MCP_MAX_RESPONSE_BYTES,
    ];

    #[test]
    fn invalid_numeric_env_fails_naming_variable_and_value() {
        for var in NUMERIC_ENV_VARS {
            for raw in ["abc", "-1", "1.5"] {
                let (_directory, env) = isolated_env();
                let env = env.with(var, raw);
                let message = load_http(&env).unwrap_err().to_string();
                assert!(
                    message.contains(&format!("invalid {var} value {raw:?}")),
                    "{var}={raw}: {message}"
                );
            }
        }
    }

    #[test]
    fn out_of_range_port_env_is_rejected() {
        let (_directory, env) = isolated_env();
        let env = env.with(ENV_MCP_PORT, "70000");
        let err = load_http(&env).unwrap_err();
        assert!(
            err.to_string()
                .contains(r#"invalid MYAPP_MCP_PORT value "70000": number too large"#),
            "{err}"
        );
    }

    #[test]
    fn invalid_bool_env_fails_naming_variable_and_value() {
        let (_directory, env) = isolated_env();
        let env = env.with(ENV_MCP_OAUTH_ALLOW_INSECURE_HTTP, "maybe");
        let err = load_http(&env).unwrap_err();
        assert!(
            err.to_string()
                .contains(r#"invalid MYAPP_MCP_OAUTH_ALLOW_INSECURE_HTTP value "maybe""#),
            "{err}"
        );
    }

    #[test]
    fn numeric_env_is_trimmed() {
        let (_directory, env) = isolated_env();
        let env = env
            .with(ENV_MCP_PORT, " 9191\n")
            .with(ENV_MCP_MAX_RESPONSE_BYTES, "\t4096 ");
        let config = load_http(&env).unwrap();
        assert_eq!(config.mcp.port, 9191);
        assert_eq!(config.mcp.max_response_bytes, 4096);
    }

    #[test]
    fn blank_numeric_and_bool_env_keeps_toml_values() {
        let toml = "[mcp]\nport = 9090\noauth_token_expiry_secs = 7200\n\
                    oauth_auth_code_ttl_secs = 90\noauth_csrf_nonce_ttl_secs = 900\n\
                    oauth_sweep_interval_secs = 120\nmax_response_bytes = 2048\n\
                    oauth_allow_insecure_http = true\n";
        for blank in ["", " \t "] {
            let (_directory, env) = env_with_toml(toml);
            let env = NUMERIC_ENV_VARS
                .into_iter()
                .chain([ENV_MCP_OAUTH_ALLOW_INSECURE_HTTP])
                .fold(env, |env, var| env.with(var, blank));
            let mcp = load_http(&env).unwrap().mcp;
            assert_eq!(mcp.port, 9090, "{blank:?}");
            assert_eq!(mcp.oauth_token_expiry_secs, 7200, "{blank:?}");
            assert_eq!(mcp.oauth_auth_code_ttl_secs, 90, "{blank:?}");
            assert_eq!(mcp.oauth_csrf_nonce_ttl_secs, 900, "{blank:?}");
            assert_eq!(mcp.oauth_sweep_interval_secs, 120, "{blank:?}");
            assert_eq!(mcp.max_response_bytes, 2048, "{blank:?}");
            assert!(mcp.oauth_allow_insecure_http, "{blank:?}");
        }
    }

    #[test]
    fn max_response_bytes_defaults_to_one_mib() {
        let config = ServerConfig::default();
        assert_eq!(config.mcp.max_response_bytes, 1024 * 1024);
    }

    #[test]
    fn max_response_bytes_env_override_applies() {
        let (_directory, env) = isolated_env();
        let env = env.with("MYAPP_MCP_MAX_RESPONSE_BYTES", "4096");
        let config = load_http(&env).unwrap();
        assert_eq!(config.mcp.max_response_bytes, 4096);
    }

    /// The default must stay loopback-only and, above all, non-empty: rmcp reads
    /// an empty allow-list as "accept any `Host`", which turns the DNS-rebinding
    /// guard off for every deployment that never sets this.
    #[test]
    fn allowed_hosts_defaults_to_loopback_and_is_never_empty() {
        let config = ServerConfig::default();
        assert_eq!(config.mcp.allowed_hosts, ["localhost", "127.0.0.1", "::1"]);
    }

    #[test]
    fn allowed_hosts_env_override_applies() {
        let (_directory, env) = isolated_env();
        let env = env.with(
            "MYAPP_MCP_ALLOWED_HOSTS",
            "mcp.example.com, example.com:8443",
        );
        let config = load_http(&env).unwrap();
        assert_eq!(
            config.mcp.allowed_hosts,
            ["mcp.example.com", "example.com:8443"]
        );
    }

    /// An empty or whitespace-only env value must not clear the list, since that
    /// would silently disable the guard. Turning it off stays TOML-only.
    #[test]
    fn empty_allowed_hosts_env_does_not_clear_the_default() {
        let (_directory, env) = isolated_env();
        let env = env.with("MYAPP_MCP_ALLOWED_HOSTS", "  ");
        let config = load_http(&env).unwrap();
        assert_eq!(config.mcp.allowed_hosts, ["localhost", "127.0.0.1", "::1"]);
    }

    #[test]
    fn secret_fields_default_to_none() {
        let config = ServerConfig::default();
        assert!(config.mcp.token.is_none());
        assert!(config.mcp.oauth_pin.is_none());
    }

    #[test]
    fn oauth_allow_insecure_http_defaults_false_and_env_overrides() {
        assert!(!ServerConfig::default().mcp.oauth_allow_insecure_http);

        let (_directory, env) = isolated_env();
        let env = env.with("MYAPP_MCP_OAUTH_ALLOW_INSECURE_HTTP", "true");
        let config = load_http(&env).expect("config loads with the insecure-http override set");
        assert!(config.mcp.oauth_allow_insecure_http);
    }

    #[test]
    fn missing_explicit_config_file_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("typo.toml");
        let err = ServerConfig::load_with_env(
            Some(&missing),
            &ServerOverrides::default(),
            &MapEnv::new(),
            Transport::Stdio,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("config file {} does not exist", missing.display())),
            "{err}"
        );
    }

    #[test]
    fn toml_token_applies_when_no_higher_layer_sets_one() {
        let (_directory, env) = env_with_toml("[mcp]\ntoken = \"toml\"\n");
        let config = load_http(&env).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.token), Some("toml"));
    }

    #[test]
    fn toml_token_file_is_read_and_trimmed() {
        let (directory, _) = isolated_env();
        let path = secret_file(&directory, "token", "  file-token\n");
        let (_config_directory, env) = env_with_toml(&format!("[mcp]\ntoken_file = {path:?}\n"));
        let config = load_http(&env).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.token), Some("file-token"));
        assert!(config.mcp.token_file.is_none());
    }

    #[test]
    fn env_token_file_beats_inline_toml_token() {
        let (directory, env) = env_with_toml("[mcp]\ntoken = \"toml\"\n");
        let path = secret_file(&directory, "token", "  file-token\n");
        let env = env.with("MYAPP_MCP_TOKEN_FILE", path);
        let config = load_http(&env).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.token), Some("file-token"));
    }

    #[test]
    fn env_oauth_pin_file_beats_inline_toml_oauth_pin() {
        let (directory, env) = env_with_toml("[mcp]\noauth_pin = \"toml-pin\"\n");
        let path = secret_file(&directory, "pin", "file-pin\n");
        let env = env.with("MYAPP_MCP_OAUTH_PIN_FILE", path);
        let config = load_http(&env).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.oauth_pin), Some("file-pin"));
    }

    #[test]
    fn env_token_beats_env_token_file_without_reading_it() {
        let (directory, env) = isolated_env();
        let env = env
            .with("MYAPP_MCP_TOKEN", "env-token")
            .with("MYAPP_MCP_TOKEN_FILE", missing_file(&directory));
        let config = load_http(&env).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.token), Some("env-token"));
    }

    #[test]
    fn env_oauth_pin_beats_env_oauth_pin_file_without_reading_it() {
        let (directory, env) = isolated_env();
        let env = env
            .with("MYAPP_MCP_OAUTH_PIN", "env-pin")
            .with("MYAPP_MCP_OAUTH_PIN_FILE", missing_file(&directory));
        let config = load_http(&env).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.oauth_pin), Some("env-pin"));
    }

    #[test]
    fn env_token_beats_toml_token_file_without_reading_it() {
        let (directory, _) = isolated_env();
        let toml = format!("[mcp]\ntoken_file = {:?}\n", missing_file(&directory));
        let (_config_directory, env) = env_with_toml(&toml);
        let env = env.with("MYAPP_MCP_TOKEN", "env-token");
        let config = load_http(&env).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.token), Some("env-token"));
    }

    #[test]
    fn toml_token_and_token_file_together_are_rejected() {
        let (directory, _) = isolated_env();
        let path = secret_file(&directory, "token", "file-token");
        let toml = format!("[mcp]\ntoken = \"toml\"\ntoken_file = {path:?}\n");
        let (_config_directory, env) = env_with_toml(&toml);
        let err = load_http(&env).unwrap_err();
        assert_eq!(err.to_string(), "set either token or token_file, not both");
    }

    #[test]
    fn toml_oauth_pin_and_oauth_pin_file_together_are_rejected() {
        let (directory, _) = isolated_env();
        let path = secret_file(&directory, "pin", "file-pin");
        let toml = format!("[mcp]\noauth_pin = \"toml-pin\"\noauth_pin_file = {path:?}\n");
        let (_config_directory, env) = env_with_toml(&toml);
        let err = load_http(&env).unwrap_err();
        assert_eq!(
            err.to_string(),
            "set either oauth_pin or oauth_pin_file, not both"
        );
    }

    #[test]
    fn empty_env_token_falls_back_to_toml_token() {
        let (_directory, env) = env_with_toml("[mcp]\ntoken = \"toml\"\n");
        let env = env.with("MYAPP_MCP_TOKEN", "");
        let config = load_http(&env).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.token), Some("toml"));
    }

    #[test]
    fn unreadable_env_token_file_is_an_error_naming_the_field_and_path() {
        let (directory, env) = isolated_env();
        let path = missing_file(&directory);
        let env = env.with("MYAPP_MCP_TOKEN_FILE", path.clone());
        let message = load_http(&env).unwrap_err().to_string();
        assert!(
            message.starts_with(&format!("failed to read token_file {path}: ")),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn stdio_load_reads_no_http_secrets() {
        let (directory, _) = isolated_env();
        let path = secret_file(&directory, "token", "file-token");
        let pin_path = secret_file(&directory, "pin", "file-pin");
        // Both TOML conflicts and unreadable env files would fail an HTTP load.
        let toml = format!(
            "[mcp]\ntoken = \"toml\"\ntoken_file = {path:?}\noauth_pin = \"toml-pin\"\noauth_pin_file = {pin_path:?}\n"
        );
        let (_config_directory, env) = env_with_toml(&toml);
        let env = env
            .with("MYAPP_MCP_TOKEN_FILE", missing_file(&directory))
            .with("MYAPP_MCP_OAUTH_PIN_FILE", missing_file(&directory));

        let mcp =
            ServerConfig::load_with_env(None, &ServerOverrides::default(), &env, Transport::Stdio)
                .expect("stdio loads whatever the secret sources hold")
                .mcp;
        assert!(mcp.token.is_none());
        assert!(mcp.token_file.is_none());
        assert!(mcp.oauth_pin.is_none());
        assert!(mcp.oauth_pin_file.is_none());

        load_http(&env).expect_err("http still resolves the secrets");
    }

    #[test]
    fn stdio_ignores_cli_secrets_too() {
        let (_directory, env) = isolated_env();
        let overrides = cli_overrides(&["--token", "cli-token", "--oauth-pin", "cli-pin"]);
        let mcp = ServerConfig::load_with_env(None, &overrides, &env, Transport::Stdio)
            .unwrap()
            .mcp;
        assert!(mcp.token.is_none());
        assert!(mcp.oauth_pin.is_none());
    }

    #[test]
    fn cli_token_beats_env_token_and_toml_token() {
        let (_directory, env) = env_with_toml("[mcp]\ntoken = \"toml\"\n");
        let env = env.with("MYAPP_MCP_TOKEN", "env-token");
        let overrides = cli_overrides(&["--token", "cli-token"]);
        let config = ServerConfig::load_with_env(None, &overrides, &env, Transport::Http).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.token), Some("cli-token"));
    }

    #[test]
    fn cli_token_wins_without_reading_env_token_file() {
        let (directory, env) = isolated_env();
        let env = env.with("MYAPP_MCP_TOKEN_FILE", missing_file(&directory));
        let overrides = cli_overrides(&["--token", "t"]);
        let config = ServerConfig::load_with_env(None, &overrides, &env, Transport::Http).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.token), Some("t"));
    }

    #[test]
    fn cli_oauth_pin_wins_without_reading_env_oauth_pin_file() {
        let (directory, env) = isolated_env();
        let env = env.with("MYAPP_MCP_OAUTH_PIN_FILE", missing_file(&directory));
        let overrides = cli_overrides(&["--oauth-pin", "cli-pin"]);
        let config = ServerConfig::load_with_env(None, &overrides, &env, Transport::Http).unwrap();
        assert_eq!(expose_secret_opt(&config.mcp.oauth_pin), Some("cli-pin"));
    }

    #[test]
    fn cli_api_key_wins_without_reading_env_api_key_file() {
        let (directory, env) = isolated_env();
        let env = env.with("MYAPP_API_KEY_FILE", missing_file(&directory));
        let overrides = cli_overrides(&["--api-key", "cli-key"]);
        let config = ServerConfig::load_with_env(None, &overrides, &env, Transport::Http).unwrap();
        assert_eq!(expose_secret_opt(&config.core.api_key), Some("cli-key"));
    }

    #[test]
    fn cli_base_url_beats_env_and_toml_base_url() {
        let (_directory, env) = env_with_toml("base_url = \"https://toml.example.test\"\n");
        let env = env.with("MYAPP_BASE_URL", "https://env.example.test");
        let overrides = cli_overrides(&["--base-url", "https://cli.example.test"]);
        let config = ServerConfig::load_with_env(None, &overrides, &env, Transport::Http).unwrap();
        assert_eq!(config.core.base_url, "https://cli.example.test");
    }

    #[test]
    fn env_mcp_settings_beat_toml() {
        let toml = "[mcp]\nhost = \"10.0.0.1\"\nport = 9000\nbase_url = \"https://toml.example.test\"\nauth_mode = \"none\"\n";
        let (_directory, env) = env_with_toml(toml);
        let env = env
            .with("MYAPP_MCP_HOST", "10.0.0.2")
            .with("MYAPP_MCP_PORT", "9001")
            .with("MYAPP_MCP_BASE_URL", "https://env.example.test")
            .with("MYAPP_MCP_AUTH_MODE", "token");
        let mcp = load_http(&env).unwrap().mcp;
        assert_eq!(mcp.host, "10.0.0.2");
        assert_eq!(mcp.port, 9001);
        assert_eq!(mcp.base_url.as_deref(), Some("https://env.example.test"));
        assert_eq!(mcp.auth_mode, AuthMode::Token);
    }

    #[test]
    fn cli_mcp_settings_beat_env_and_toml() {
        let toml = "[mcp]\nhost = \"10.0.0.1\"\nport = 9000\nbase_url = \"https://toml.example.test\"\nauth_mode = \"none\"\n";
        let (_directory, env) = env_with_toml(toml);
        let env = env
            .with("MYAPP_MCP_HOST", "10.0.0.2")
            .with("MYAPP_MCP_PORT", "9001")
            .with("MYAPP_MCP_BASE_URL", "https://env.example.test")
            .with("MYAPP_MCP_AUTH_MODE", "token");
        let overrides = cli_overrides(&[
            "--host",
            "10.0.0.3",
            "--port",
            "9002",
            "--mcp-base-url",
            "https://cli.example.test",
            "--auth-mode",
            "oauth",
        ]);
        let config = ServerConfig::load_with_env(None, &overrides, &env, Transport::Http).unwrap();
        assert_eq!(config.mcp.host, "10.0.0.3");
        assert_eq!(config.mcp.port, 9002);
        assert_eq!(
            config.mcp.base_url.as_deref(),
            Some("https://cli.example.test")
        );
        assert_eq!(config.mcp.auth_mode, AuthMode::OAuth);
    }
}
