//! Configuration loading with layered precedence:
//! **CLI flag → `MYAPP_*` env → `MYAPP_*_FILE` env → `config.toml` → defaults.**
//!
//! CLI overrides are applied by the binaries after [`Config::load`]. This
//! module handles file + env layering and reads `*_FILE` secrets (Docker
//! secret convention) at load time, trimming trailing whitespace.

use crate::Result;
use crate::env::{Env, SystemEnv, env_non_empty, env_non_empty_u64};
use crate::error::Error;
use crate::secret::SecretString;
use serde::Deserialize;
use std::path::Path;

/// Default upstream base URL (override per project / via `--base-url`).
const DEFAULT_BASE_URL: &str = "http://localhost:8080";
/// Default total-request timeout.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Default TCP connect timeout.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Default log level.
const DEFAULT_LOG_LEVEL: &str = "info";

/// Top-level configuration for the API client.
#[derive(Debug, Clone)]
pub struct Config {
    /// Upstream API base URL (no trailing slash required).
    pub base_url: String,
    /// API key sent as the `X-Api-Key` header. `None` until resolved.
    pub api_key: Option<SecretString>,
    /// Logging settings.
    pub log: LogConfig,
    /// HTTP transport timeouts.
    pub http: HttpConfig,
}

/// Logging configuration.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Level filter: trace|debug|info|warn|error.
    pub level: String,
}

/// HTTP timeout configuration.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Total request timeout in seconds.
    pub request_timeout_secs: u64,
    /// TCP connect timeout in seconds.
    pub connect_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_string(),
            api_key: None,
            log: LogConfig {
                level: DEFAULT_LOG_LEVEL.to_string(),
            },
            http: HttpConfig {
                request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
                connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            },
        }
    }
}

/// On-disk TOML shape. All fields optional; missing fields use defaults.
#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    base_url: Option<String>,
    api_key: Option<String>,
    api_key_file: Option<String>,
    #[serde(default)]
    log: LogFile,
    #[serde(default)]
    http: HttpFile,
}

#[derive(Debug, Default, Deserialize)]
struct LogFile {
    level: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct HttpFile {
    request_timeout_secs: Option<u64>,
    connect_timeout_secs: Option<u64>,
}

impl Config {
    /// Loads configuration from `path` (or the default location), then applies
    /// environment overrides. CLI overrides are applied by the caller afterward.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        Self::load_with_env(path, &SystemEnv)
    }

    /// [`load`](Self::load) with an injectable [`Env`] for testing.
    pub fn load_with_env(path: Option<&Path>, env: &impl Env) -> Result<Self> {
        let resolved = Self::resolve_config_path(path, env);
        let file: ConfigFile = match resolved {
            Some(ref p) if p.exists() => {
                let text = std::fs::read_to_string(p)?;
                toml::from_str(&text).map_err(|e| Error::Config(e.to_string()))?
            }
            _ => ConfigFile::default(),
        };

        let mut config = Config::default();
        if let Some(v) = file.base_url {
            config.base_url = v;
        }
        if let Some(v) = file.log.level {
            config.log.level = v;
        }
        if let Some(v) = file.http.request_timeout_secs {
            config.http.request_timeout_secs = v;
        }
        if let Some(v) = file.http.connect_timeout_secs {
            config.http.connect_timeout_secs = v;
        }

        // API key from file: direct value vs *_file are mutually exclusive.
        config.api_key = Self::resolve_api_key(file.api_key, file.api_key_file, env)?;

        // Env overrides (highest precedence below CLI).
        if let Some(v) = env_non_empty(env, "MYAPP_BASE_URL") {
            config.base_url = v;
        }
        if let Some(v) = env_non_empty(env, "MYAPP_LOG_LEVEL") {
            config.log.level = v;
        }
        if let Some(v) = env_non_empty_u64(env, "MYAPP_HTTP_REQUEST_TIMEOUT_SECS") {
            config.http.request_timeout_secs = v;
        }
        if let Some(v) = env_non_empty_u64(env, "MYAPP_HTTP_CONNECT_TIMEOUT_SECS") {
            config.http.connect_timeout_secs = v;
        }

        Ok(config)
    }

    /// Resolves the API key with precedence: `MYAPP_API_KEY` env →
    /// `MYAPP_API_KEY_FILE` env → `api_key` (toml) → `api_key_file` (toml).
    fn resolve_api_key(
        file_value: Option<String>,
        file_path: Option<String>,
        env: &impl Env,
    ) -> Result<Option<SecretString>> {
        if let Some(v) = env_non_empty(env, "MYAPP_API_KEY") {
            return Ok(Some(SecretString::from(v)));
        }
        if let Some(p) = env_non_empty(env, "MYAPP_API_KEY_FILE") {
            return Ok(Some(read_secret_file(&p)?));
        }
        match (file_value, file_path) {
            (Some(_), Some(_)) => Err(Error::Config(
                "set either api_key or api_key_file, not both".to_string(),
            )),
            (Some(v), None) => Ok(Some(SecretString::from(v))),
            (None, Some(p)) => Ok(Some(read_secret_file(&p)?)),
            (None, None) => Ok(None),
        }
    }

    /// Determines the config file path: explicit arg → `MYAPP_CONFIG` env →
    /// `~/.config/myapp/config.toml`.
    ///
    /// Exposed so dependent crates (e.g. the MCP server) resolve the same path
    /// without duplicating the precedence logic.
    pub fn resolve_config_path(path: Option<&Path>, env: &impl Env) -> Option<std::path::PathBuf> {
        if let Some(p) = path {
            return Some(p.to_path_buf());
        }
        if let Some(p) = env_non_empty(env, "MYAPP_CONFIG") {
            return Some(std::path::PathBuf::from(p));
        }
        dirs::config_dir().map(|d| d.join("myapp").join("config.toml"))
    }
}

/// Reads a secret from a file, trimming trailing whitespace/newlines.
fn read_secret_file(path: &str) -> Result<SecretString> {
    let raw = std::fs::read_to_string(path)?;
    Ok(SecretString::from(raw.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MapEnv;

    #[test]
    fn env_api_key_beats_file_value() {
        let env = MapEnv::new().with("MYAPP_API_KEY", "from-env");
        let key = Config::resolve_api_key(Some("from-toml".into()), None, &env)
            .unwrap()
            .unwrap();
        assert_eq!(key.expose_secret(), "from-env");
    }

    #[test]
    fn toml_value_and_file_conflict_errors() {
        let env = MapEnv::new();
        let err =
            Config::resolve_api_key(Some("a".into()), Some("/tmp/x".into()), &env).unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn base_url_env_overrides_default() {
        let env = MapEnv::new().with("MYAPP_BASE_URL", "https://api.example.test");
        let config = Config::load_with_env(None, &env).unwrap();
        assert_eq!(config.base_url, "https://api.example.test");
    }

    #[test]
    fn api_key_file_is_read_and_trimmed() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "  secret-key\n\n").unwrap();
        let path = file.path().to_str().unwrap().to_string();

        let env = MapEnv::new().with("MYAPP_API_KEY_FILE", path);
        let key = Config::resolve_api_key(None, None, &env).unwrap().unwrap();
        assert_eq!(key.expose_secret(), "secret-key");
    }
}
