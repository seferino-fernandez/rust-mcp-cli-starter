//! Configuration loading with layered precedence:
//! **CLI flag → `MYAPP_*` env → `MYAPP_*_FILE` env → `config.toml` → defaults.**
//!
//! CLI flags arrive as [`ConfigOverrides`], the top layer, so the loader
//! applies every layer itself. For the API key only the winning layer is read,
//! so a lower layer's `*_FILE` secret (Docker secret convention) is never
//! opened. Secret files are read at load time and trimmed.

use crate::Result;
use crate::env::{Env, SystemEnv, env_non_empty, env_parse};
use crate::error::Error;
use crate::secret::SecretString;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use tracing::level_filters::LevelFilter;

/// Default upstream base URL (override per project / via `--base-url`).
const DEFAULT_BASE_URL: &str = "http://localhost:8080";
/// Default total-request timeout.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Default TCP connect timeout.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

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
#[derive(Debug, Clone, Default)]
pub struct LogConfig {
    /// Level filter: trace|debug|info|warn|error|off. `None` when neither
    /// `MYAPP_LOG_LEVEL` nor `[log] level` sets one, so each binary applies
    /// its own default (see [`LogConfig::resolve_level`]).
    pub level: Option<String>,
}

impl LogConfig {
    /// Resolves the tracing level a binary starts with; `RUST_LOG` is applied
    /// separately and still overrides the result.
    ///
    /// An explicit `-v`/`-q` level (`flag`) wins over the configured
    /// [`level`](Self::level), which wins over `default`. An unparseable
    /// configured level falls back to `default` and also returns a warning for
    /// the caller to print, since logging is not set up yet.
    ///
    /// # Examples
    ///
    /// ```
    /// use myapp_core::config::LogConfig;
    /// use tracing::level_filters::LevelFilter;
    ///
    /// let log = LogConfig { level: Some("debug".into()) };
    /// assert_eq!(log.resolve_level(None, LevelFilter::INFO), (LevelFilter::DEBUG, None));
    /// assert_eq!(
    ///     log.resolve_level(Some(LevelFilter::OFF), LevelFilter::INFO),
    ///     (LevelFilter::OFF, None),
    /// );
    ///
    /// let (level, warning) =
    ///     LogConfig { level: Some("loud".into()) }.resolve_level(None, LevelFilter::ERROR);
    /// assert_eq!(level, LevelFilter::ERROR);
    /// assert!(warning.unwrap().contains("\"loud\""));
    /// ```
    pub fn resolve_level(
        &self,
        flag: Option<LevelFilter>,
        default: LevelFilter,
    ) -> (LevelFilter, Option<String>) {
        if let Some(level) = flag {
            return (level, None);
        }
        let Some(value) = &self.level else {
            return (default, None);
        };
        match value.trim().parse() {
            Ok(level) => (level, None),
            Err(_) => (
                default,
                Some(format!(
                    "ignoring invalid log level {value:?} (expected trace, debug, info, \
                     warn, error or off); using {default}"
                )),
            ),
        }
    }
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
            log: LogConfig::default(),
            http: HttpConfig {
                request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
                connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            },
        }
    }
}

/// Explicit values that sit above every other layer, typically CLI flags.
///
/// They beat `MYAPP_*` env vars, `MYAPP_*_FILE` vars and `config.toml`. A
/// `Some` value wins verbatim, even when empty, and a winning `api_key` means
/// no lower layer's secret file is read.
///
/// # Examples
///
/// ```
/// use myapp_core::env::MapEnv;
/// use myapp_core::{Config, ConfigOverrides, SecretString};
///
/// let overrides = ConfigOverrides {
///     base_url: Some("https://myapp.example.test".into()),
///     api_key: Some(SecretString::from("cli-key")),
/// };
/// let config_file = tempfile::NamedTempFile::new()?;
/// let env = MapEnv::new()
///     .with("MYAPP_CONFIG", config_file.path().to_string_lossy())
///     .with("MYAPP_API_KEY_FILE", "/nonexistent/api-key");
/// let config = Config::load_with_env(None, &overrides, &env)?;
/// assert_eq!(config.base_url, "https://myapp.example.test");
/// assert_eq!(config.api_key.unwrap().expose_secret(), "cli-key");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Default, Clone)]
pub struct ConfigOverrides {
    /// Overrides the upstream API base URL (`--base-url`).
    pub base_url: Option<String>,
    /// Overrides the API key (`--api-key`).
    pub api_key: Option<SecretString>,
}

/// Identifies which layer named the configuration file path.
///
/// A file named by [`ConfigPathSource::Explicit`] or [`ConfigPathSource::Env`]
/// must exist. A [`ConfigPathSource::Default`] location means there is no
/// configuration file unless [`Path::exists`] confirms one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPathSource {
    /// The caller passed the path, typically from a `--config` flag.
    Explicit,
    /// `MYAPP_CONFIG` named the path.
    Env,
    /// The path is a default location: the platform configuration directory or
    /// `~/.config/myapp/config.toml`.
    Default,
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
    /// Loads configuration from `overrides`, the process environment, and the
    /// file at `path` (or the default location).
    ///
    /// A file named by `path` or `MYAPP_CONFIG` must exist; a missing file at a
    /// default location means defaults.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the file named by `path` or
    /// `MYAPP_CONFIG` does not exist, when the TOML does not parse (reporting
    /// line and column, never the source line), when both `api_key` and
    /// `api_key_file` are set in the file, or when a `MYAPP_*` variable holds a
    /// value that does not parse. Returns [`Error::Io`] when a configuration or
    /// secret file cannot be read.
    pub fn load(path: Option<&Path>, overrides: &ConfigOverrides) -> Result<Self> {
        Self::load_with_env(path, overrides, &SystemEnv)
    }

    /// [`load`](Self::load) with an injectable [`Env`] for testing.
    ///
    /// # Errors
    ///
    /// As for [`load`](Self::load).
    pub fn load_with_env(
        path: Option<&Path>,
        overrides: &ConfigOverrides,
        env: &impl Env,
    ) -> Result<Self> {
        Self::load_resolved(Self::resolve_config_path(path, env), overrides, env)
    }

    /// Loads configuration from an already resolved configuration file path.
    fn load_resolved(
        resolved: Option<(PathBuf, ConfigPathSource)>,
        overrides: &ConfigOverrides,
        env: &impl Env,
    ) -> Result<Self> {
        let file: ConfigFile = parse_resolved_config(resolved)?;

        let mut config = Config::default();
        if let Some(v) = file.base_url {
            config.base_url = v;
        }
        if let Some(v) = file.log.level {
            config.log.level = Some(v);
        }
        if let Some(v) = file.http.request_timeout_secs {
            config.http.request_timeout_secs = v;
        }
        if let Some(v) = file.http.connect_timeout_secs {
            config.http.connect_timeout_secs = v;
        }

        // API key from the highest layer that supplies one; lower layers unread.
        config.api_key = Self::resolve_api_key(
            overrides.api_key.clone(),
            file.api_key,
            file.api_key_file,
            env,
        )?;

        // Env overrides (highest precedence below CLI).
        if let Some(v) = env_non_empty(env, "MYAPP_BASE_URL") {
            config.base_url = v;
        }
        if let Some(v) = env_non_empty(env, "MYAPP_LOG_LEVEL") {
            config.log.level = Some(v);
        }
        if let Some(v) = env_parse(env, "MYAPP_HTTP_REQUEST_TIMEOUT_SECS")? {
            config.http.request_timeout_secs = v;
        }
        if let Some(v) = env_parse(env, "MYAPP_HTTP_CONNECT_TIMEOUT_SECS")? {
            config.http.connect_timeout_secs = v;
        }

        // CLI overrides (highest precedence).
        if let Some(v) = &overrides.base_url {
            config.base_url.clone_from(v);
        }

        Ok(config)
    }

    /// Resolves the API key from the highest layer that supplies one:
    /// override → `MYAPP_API_KEY` env → `MYAPP_API_KEY_FILE` env → `api_key` or
    /// `api_key_file` (toml). A `Some` override wins verbatim, even when empty,
    /// and no lower layer is read.
    fn resolve_api_key(
        override_value: Option<SecretString>,
        file_value: Option<String>,
        file_path: Option<String>,
        env: &impl Env,
    ) -> Result<Option<SecretString>> {
        if override_value.is_some() {
            return Ok(override_value);
        }
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

    /// Determines the config file path and the layer that named it: explicit
    /// arg → `MYAPP_CONFIG` env → platform config directory (when the file
    /// exists there) → `~/.config/myapp/config.toml`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::{Path, PathBuf};
    /// use myapp_core::env::MapEnv;
    /// use myapp_core::{Config, ConfigPathSource};
    ///
    /// let env = MapEnv::new().with("MYAPP_CONFIG", "/tmp/myapp.toml");
    /// assert_eq!(
    ///     Config::resolve_config_path(None, &env),
    ///     Some((PathBuf::from("/tmp/myapp.toml"), ConfigPathSource::Env)),
    /// );
    /// assert_eq!(
    ///     Config::resolve_config_path(Some(Path::new("explicit.toml")), &env),
    ///     Some((PathBuf::from("explicit.toml"), ConfigPathSource::Explicit)),
    /// );
    /// ```
    pub fn resolve_config_path(
        path: Option<&Path>,
        env: &impl Env,
    ) -> Option<(PathBuf, ConfigPathSource)> {
        if let Some(p) = path {
            return Some((p.to_path_buf(), ConfigPathSource::Explicit));
        }
        if let Some(p) = env_non_empty(env, "MYAPP_CONFIG") {
            return Some((PathBuf::from(p), ConfigPathSource::Env));
        }
        let platform_path = dirs::config_dir().map(|dir| dir.join("myapp").join("config.toml"));
        let default_path = match platform_path {
            Some(p) if p.exists() => Some(p),
            _ => dirs::home_dir().map(|dir| dir.join(".config").join("myapp").join("config.toml")),
        };
        default_path.map(|p| (p, ConfigPathSource::Default))
    }

    /// Reads the configuration file that [`resolve_config_path`] selects and
    /// deserializes it as `T`, or returns `T::default()` when a default location
    /// holds no file.
    ///
    /// Exposed so dependent crates (e.g. the MCP server) parse their own tables
    /// from the same file under the same missing-file and error rules.
    ///
    /// [`resolve_config_path`]: Self::resolve_config_path
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] naming the path when the file named by `path`
    /// or `MYAPP_CONFIG` does not exist, or when the TOML does not parse as `T`
    /// (reporting line and column, never the source line). Returns
    /// [`Error::Io`] when the file exists but cannot be read.
    pub fn read_config_file<T: DeserializeOwned + Default>(
        path: Option<&Path>,
        env: &impl Env,
    ) -> Result<T> {
        parse_resolved_config(Self::resolve_config_path(path, env))
    }
}

/// Reads and parses a resolved configuration file, treating only a missing
/// default as absent.
fn parse_resolved_config<T: DeserializeOwned + Default>(
    resolved: Option<(PathBuf, ConfigPathSource)>,
) -> Result<T> {
    let Some((path, text)) = read_resolved_config(resolved)? else {
        return Ok(T::default());
    };
    toml::from_str(&text).map_err(|e| {
        Error::Config(format!(
            "invalid config file {}: {}",
            path.display(),
            describe_toml_error(&text, &e)
        ))
    })
}

/// Reads a resolved configuration file. A missing file is an error unless the
/// path is a default location.
fn read_resolved_config(
    resolved: Option<(PathBuf, ConfigPathSource)>,
) -> Result<Option<(PathBuf, String)>> {
    let Some((path, source)) = resolved else {
        return Ok(None);
    };
    let named_by = match source {
        ConfigPathSource::Default if !path.exists() => return Ok(None),
        ConfigPathSource::Default => {
            let text = std::fs::read_to_string(&path)?;
            return Ok(Some((path, text)));
        }
        ConfigPathSource::Explicit => "",
        ConfigPathSource::Env => " set by MYAPP_CONFIG",
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(Some((path, text))),
        // A path under a regular file (ENOTDIR) does not exist either.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Err(Error::Config(format!(
                "config file {}{named_by} does not exist",
                path.display()
            )))
        }
        Err(e) => Err(e.into()),
    }
}

/// Describes a TOML parse error as `line {line}, column {column}: {message}`.
///
/// Uses [`toml::de::Error::message`] and [`toml::de::Error::span`] rather than
/// `Display`, because `Display` quotes the offending source line, and a config
/// line can hold a secret. Line and column are 1-based and computed over
/// `text`; when the error has no span, only the message is returned.
///
/// The message itself still quotes the offending value for serde type and
/// value errors (``invalid type: integer `123456`, expected a string``), so a
/// secret written with the wrong type would leak through it. Every `"…"` and
/// `` `…` `` span in the message is therefore masked as
/// [`MASKED_VALUE`](crate::secret::MASKED_VALUE), keeping the delimiters; an
/// unterminated delimiter masks to the end.
fn describe_toml_error(text: &str, error: &toml::de::Error) -> String {
    let message = mask_quoted_values(error.message());
    let Some(span) = error.span() else {
        return message;
    };
    let before = text.get(..span.start).unwrap_or(text);
    // `split` yields one more piece than there are newlines, so the count is
    // already the 1-based line number.
    let line = before.split('\n').count();
    let current_line = before.rsplit('\n').next().unwrap_or(before);
    let column = current_line.chars().count().saturating_add(1);
    format!("line {line}, column {column}: {message}")
}

/// Replaces the content of every `"…"` and `` `…` `` span with
/// [`MASKED_VALUE`](crate::secret::MASKED_VALUE).
///
/// Serde quotes string values with `Debug`, so a `"` inside a `"…"` span is
/// escaped as `\"`; a backslash there skips the next character instead of
/// letting an embedded quote end the span early.
fn mask_quoted_values(message: &str) -> String {
    let mut masked = String::with_capacity(message.len());
    let mut open: Option<char> = None;
    let mut escaped = false;
    for c in message.chars() {
        match open {
            None => {
                masked.push(c);
                if c == '"' || c == '`' {
                    masked.push_str(crate::secret::MASKED_VALUE);
                    open = Some(c);
                }
            }
            Some(_) if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(delimiter) if c == delimiter => {
                masked.push(c);
                open = None;
            }
            Some(_) => {}
        }
    }
    masked
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

    /// Writes `contents` as `config.toml` in a new temp directory, returning
    /// both so the directory outlives the test body.
    fn config_file(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, contents).unwrap();
        (directory, path)
    }

    fn load(path: &Path, overrides: &ConfigOverrides, env: &MapEnv) -> Result<Config> {
        Config::load_with_env(Some(path), overrides, env)
    }

    fn missing_secret(directory: &tempfile::TempDir) -> String {
        directory
            .path()
            .join("missing-secret")
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn env_api_key_beats_file_value() {
        let env = MapEnv::new().with("MYAPP_API_KEY", "from-env");
        let key = Config::resolve_api_key(None, Some("from-toml".into()), None, &env)
            .unwrap()
            .unwrap();
        assert_eq!(key.expose_secret(), "from-env");
    }

    #[test]
    fn toml_value_and_file_conflict_errors() {
        let env = MapEnv::new();
        let err = Config::resolve_api_key(None, Some("a".into()), Some("/tmp/x".into()), &env)
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn base_url_env_overrides_default() {
        let (_directory, path) = config_file("");
        let env = MapEnv::new().with("MYAPP_BASE_URL", "https://api.example.test");
        let config = load(&path, &ConfigOverrides::default(), &env).unwrap();
        assert_eq!(config.base_url, "https://api.example.test");
    }

    #[test]
    fn api_key_file_is_read_and_trimmed() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "  secret-key\n\n").unwrap();
        let path = file.path().to_str().unwrap().to_string();

        let env = MapEnv::new().with("MYAPP_API_KEY_FILE", path);
        let key = Config::resolve_api_key(None, None, None, &env)
            .unwrap()
            .unwrap();
        assert_eq!(key.expose_secret(), "secret-key");
    }

    #[test]
    fn toml_layer_applies_when_nothing_overrides_it() {
        let (_directory, path) = config_file(
            "base_url = \"https://toml.example.test\"\napi_key = \"toml-key\"\n\
             [log]\nlevel = \"warn\"\n[http]\nrequest_timeout_secs = 45\n",
        );
        let config = load(&path, &ConfigOverrides::default(), &MapEnv::new()).unwrap();
        assert_eq!(config.base_url, "https://toml.example.test");
        assert_eq!(config.api_key.unwrap().expose_secret(), "toml-key");
        assert_eq!(config.log.level.as_deref(), Some("warn"));
        assert_eq!(config.http.request_timeout_secs, 45);
    }

    #[test]
    fn env_api_key_file_beats_toml_api_key() {
        let (directory, path) = config_file("api_key = \"toml-key\"\n");
        let secret = directory.path().join("api-key");
        std::fs::write(&secret, "file-key\n").unwrap();
        let env = MapEnv::new().with("MYAPP_API_KEY_FILE", secret.to_string_lossy());
        let config = load(&path, &ConfigOverrides::default(), &env).unwrap();
        assert_eq!(config.api_key.unwrap().expose_secret(), "file-key");
    }

    #[test]
    fn env_api_key_beats_env_api_key_file_without_reading_it() {
        let (directory, path) = config_file("");
        let env = MapEnv::new()
            .with("MYAPP_API_KEY", "env-key")
            .with("MYAPP_API_KEY_FILE", missing_secret(&directory));
        let config = load(&path, &ConfigOverrides::default(), &env).unwrap();
        assert_eq!(config.api_key.unwrap().expose_secret(), "env-key");
    }

    #[test]
    fn env_api_key_beats_toml_api_key_file_without_reading_it() {
        let directory = tempfile::tempdir().unwrap();
        let toml = format!("api_key_file = {:?}\n", missing_secret(&directory));
        let (_config_directory, path) = config_file(&toml);
        let env = MapEnv::new().with("MYAPP_API_KEY", "env-key");
        let config = load(&path, &ConfigOverrides::default(), &env).unwrap();
        assert_eq!(config.api_key.unwrap().expose_secret(), "env-key");
    }

    #[test]
    fn api_key_override_wins_without_reading_env_api_key_file() {
        let (directory, path) = config_file("api_key = \"toml-key\"\n");
        let env = MapEnv::new()
            .with("MYAPP_API_KEY", "env-key")
            .with("MYAPP_API_KEY_FILE", missing_secret(&directory));
        let overrides = ConfigOverrides {
            api_key: Some(SecretString::from("cli-key")),
            ..ConfigOverrides::default()
        };
        let config = load(&path, &overrides, &env).unwrap();
        assert_eq!(config.api_key.unwrap().expose_secret(), "cli-key");
    }

    #[test]
    fn empty_api_key_override_wins_verbatim() {
        let (_directory, path) = config_file("api_key = \"from-toml\"\n");
        let env = MapEnv::new().with("MYAPP_API_KEY", "from-env");
        let overrides = ConfigOverrides {
            api_key: Some(SecretString::from("")),
            ..ConfigOverrides::default()
        };
        let config = load(&path, &overrides, &env).unwrap();
        assert_eq!(config.api_key.unwrap().expose_secret(), "");
    }

    #[test]
    fn base_url_override_beats_env_and_toml() {
        let (_directory, path) = config_file("base_url = \"https://toml.example.test\"\n");
        let env = MapEnv::new().with("MYAPP_BASE_URL", "https://env.example.test");
        let overrides = ConfigOverrides {
            base_url: Some("https://cli.example.test".into()),
            ..ConfigOverrides::default()
        };
        let config = load(&path, &overrides, &env).unwrap();
        assert_eq!(config.base_url, "https://cli.example.test");
    }

    #[test]
    fn env_beats_toml_for_log_level_and_timeouts() {
        let (_directory, path) = config_file(
            "[log]\nlevel = \"warn\"\n[http]\nrequest_timeout_secs = 45\nconnect_timeout_secs = 5\n",
        );
        let env = MapEnv::new()
            .with("MYAPP_LOG_LEVEL", "debug")
            .with("MYAPP_HTTP_REQUEST_TIMEOUT_SECS", "60")
            .with("MYAPP_HTTP_CONNECT_TIMEOUT_SECS", " 3\n");
        let config = load(&path, &ConfigOverrides::default(), &env).unwrap();
        assert_eq!(config.log.level.as_deref(), Some("debug"));
        assert_eq!(config.http.request_timeout_secs, 60);
        assert_eq!(config.http.connect_timeout_secs, 3);
    }

    #[test]
    fn blank_timeout_env_keeps_toml_value() {
        let (_directory, path) = config_file("[http]\nrequest_timeout_secs = 45\n");
        for blank in ["", " \t "] {
            let env = MapEnv::new().with("MYAPP_HTTP_REQUEST_TIMEOUT_SECS", blank);
            let config = load(&path, &ConfigOverrides::default(), &env).unwrap();
            assert_eq!(config.http.request_timeout_secs, 45, "{blank:?}");
        }
    }

    #[test]
    fn invalid_timeout_env_fails_naming_variable_and_value() {
        let (_directory, path) = config_file("");
        for var in [
            "MYAPP_HTTP_REQUEST_TIMEOUT_SECS",
            "MYAPP_HTTP_CONNECT_TIMEOUT_SECS",
        ] {
            for raw in ["xyz", "-1", "1.5"] {
                let env = MapEnv::new().with(var, raw);
                let err = load(&path, &ConfigOverrides::default(), &env).unwrap_err();
                assert!(matches!(err, Error::Config(_)), "{var}={raw}: {err:?}");
                let message = err.to_string();
                assert!(
                    message.contains(&format!("invalid {var} value {raw:?}")),
                    "{var}={raw}: {message}"
                );
            }
        }
    }

    #[test]
    fn unset_log_level_is_none() {
        let (_directory, path) = config_file("");
        let config = load(&path, &ConfigOverrides::default(), &MapEnv::new()).unwrap();
        assert!(config.log.level.is_none());
        assert!(Config::default().log.level.is_none());
    }

    #[test]
    fn missing_explicit_config_file_errors_with_path() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("typo.toml");
        let err = load(&missing, &ConfigOverrides::default(), &MapEnv::new()).unwrap_err();
        let Error::Config(message) = err else {
            panic!("expected Error::Config, got {err:?}");
        };
        assert_eq!(
            message,
            format!("config file {} does not exist", missing.display())
        );
    }

    #[test]
    fn missing_env_config_file_errors_with_path_and_variable() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("typo.toml");
        let env = MapEnv::new().with("MYAPP_CONFIG", missing.to_string_lossy());
        let err = Config::load_with_env(None, &ConfigOverrides::default(), &env).unwrap_err();
        let Error::Config(message) = err else {
            panic!("expected Error::Config, got {err:?}");
        };
        assert_eq!(
            message,
            format!(
                "config file {} set by MYAPP_CONFIG does not exist",
                missing.display()
            )
        );
    }

    #[test]
    fn explicit_config_path_under_a_regular_file_errors_with_path() {
        let (_directory, path) = config_file("");
        let missing = path.join("x.toml");
        let err = load(&missing, &ConfigOverrides::default(), &MapEnv::new()).unwrap_err();
        let Error::Config(message) = err else {
            panic!("expected Error::Config, got {err:?}");
        };
        assert!(
            message.contains(&missing.display().to_string()),
            "{message}"
        );
    }

    #[test]
    fn missing_default_config_file_loads_defaults() {
        // The default location is injected so the test never reads the real home config.
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("config.toml");
        let config = Config::load_resolved(
            Some((missing, ConfigPathSource::Default)),
            &ConfigOverrides::default(),
            &MapEnv::new(),
        )
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert!(config.api_key.is_none());
    }

    #[test]
    fn unreadable_explicit_config_file_keeps_io_error() {
        let directory = tempfile::tempdir().unwrap();
        let err = load(
            directory.path(),
            &ConfigOverrides::default(),
            &MapEnv::new(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got {err:?}");
    }

    #[test]
    fn toml_syntax_error_reports_position_without_the_source_line() {
        let (_directory, path) =
            config_file("base_url = \"https://x.test\"\napi_key = \"SENTINEL-SECRET\" junk\n");
        let err = load(&path, &ConfigOverrides::default(), &MapEnv::new()).unwrap_err();
        let message = err.to_string();
        assert!(!message.contains("SENTINEL"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("line 2, column "), "{message}");
    }

    #[test]
    fn toml_type_error_masks_the_offending_value() {
        let (_directory, path) = config_file("api_key = 123456789\n");
        let err = load(&path, &ConfigOverrides::default(), &MapEnv::new()).unwrap_err();
        let message = err.to_string();
        assert!(!message.contains("123456789"), "{message}");
        assert!(message.contains("line 1, column 11"), "{message}");
        assert!(message.contains("`********`"), "{message}");
    }

    #[test]
    fn describe_toml_error_without_a_span_is_the_message_alone() {
        use serde::de::Error as _;

        let err = toml::de::Error::custom("boom");
        assert_eq!(describe_toml_error("api_key = \"k\"", &err), "boom");
    }

    #[test]
    fn mask_quoted_values_masks_both_delimiters_and_an_unterminated_one() {
        assert_eq!(
            mask_quoted_values(r#"invalid type: string "SENTINEL", expected u16"#),
            r#"invalid type: string "********", expected u16"#
        );
        assert_eq!(
            mask_quoted_values("invalid type: integer `123456`, expected a string"),
            "invalid type: integer `********`, expected a string"
        );
        assert_eq!(
            mask_quoted_values(r#"invalid type: string "ab\"cd", expected u16"#),
            r#"invalid type: string "********", expected u16"#
        );
        assert_eq!(
            mask_quoted_values("invalid value: `secret, expected"),
            "invalid value: `********"
        );
    }

    #[test]
    fn resolve_level_flag_beats_config_beats_default() {
        let unset = LogConfig::default();
        let configured = LogConfig {
            level: Some("debug".into()),
        };
        assert_eq!(
            unset.resolve_level(None, LevelFilter::INFO),
            (LevelFilter::INFO, None)
        );
        assert_eq!(
            unset.resolve_level(None, LevelFilter::ERROR),
            (LevelFilter::ERROR, None)
        );
        assert_eq!(
            configured.resolve_level(None, LevelFilter::INFO),
            (LevelFilter::DEBUG, None)
        );
        assert_eq!(
            configured.resolve_level(Some(LevelFilter::WARN), LevelFilter::INFO),
            (LevelFilter::WARN, None)
        );
    }

    #[test]
    fn resolve_level_warns_and_falls_back_on_an_invalid_value() {
        let log = LogConfig {
            level: Some("loud".into()),
        };
        let (level, warning) = log.resolve_level(None, LevelFilter::INFO);
        assert_eq!(level, LevelFilter::INFO);
        assert_eq!(
            warning.as_deref(),
            Some(
                "ignoring invalid log level \"loud\" (expected trace, debug, info, \
                 warn, error or off); using info"
            )
        );
    }
}
