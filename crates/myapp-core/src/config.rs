//! Configuration loading with layered precedence:
//! **CLI flag → `MYAPP_*` env → `MYAPP_*_FILE` env → `config.toml` → defaults.**
//!
//! CLI flags arrive as [`ConfigOverrides`], the top layer, so the loader
//! applies every layer itself. For the API key only the winning layer is read,
//! so a lower layer's `*_FILE` secret (Docker secret convention) is never
//! opened. Secret files are read at load time and trimmed.

use crate::Result;
use crate::env::{Env, SystemEnv, env_non_empty, env_parse};
use crate::error::ConfigError;
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
    /// Returns [`Error::Config`](crate::Error::Config) holding a
    /// [`ConfigError`]: [`FileNotFound`](ConfigError::FileNotFound) when the
    /// file named by `path` or `MYAPP_CONFIG` does not exist,
    /// [`Parse`](ConfigError::Parse) when the TOML does not parse (reporting
    /// line and column, never the source line),
    /// [`ApiKeySourceConflict`](ConfigError::ApiKeySourceConflict) when both
    /// `api_key` and `api_key_file` are set in the file, or
    /// [`InvalidEnvValue`](ConfigError::InvalidEnvValue) when a `MYAPP_*`
    /// variable holds a value that does not parse. Returns
    /// [`Error::Io`](crate::Error::Io) when a configuration or secret file
    /// cannot be read.
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
            (Some(_), Some(_)) => Err(ConfigError::ApiKeySourceConflict.into()),
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
    /// Returns [`Error::Config`](crate::Error::Config) naming the path, holding
    /// [`ConfigError::FileNotFound`] when the file named by `path` or
    /// `MYAPP_CONFIG` does not exist, or [`ConfigError::Parse`] when the TOML
    /// does not parse as `T` (reporting line and column, never the source
    /// line). Returns [`Error::Io`](crate::Error::Io) when the file exists but
    /// cannot be read.
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
    toml::from_str(&text).map_err(|e| toml_parse_error(path, &text, &e).into())
}

/// Reads a resolved configuration file. A missing file is an error unless the
/// path is a default location.
fn read_resolved_config(
    resolved: Option<(PathBuf, ConfigPathSource)>,
) -> Result<Option<(PathBuf, String)>> {
    let Some((path, source)) = resolved else {
        return Ok(None);
    };
    let set_by_env = match source {
        ConfigPathSource::Default if !path.exists() => return Ok(None),
        ConfigPathSource::Default => {
            let text = std::fs::read_to_string(&path)?;
            return Ok(Some((path, text)));
        }
        ConfigPathSource::Explicit => false,
        ConfigPathSource::Env => true,
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
            Err(ConfigError::FileNotFound { path, set_by_env }.into())
        }
        Err(e) => Err(e.into()),
    }
}

/// Builds the [`ConfigError::Parse`] for a TOML parse error in the file at
/// `path`, whose message reads `line {line}, column {column}: {message}`.
///
/// Uses [`toml::de::Error::message`] and [`toml::de::Error::span`] rather than
/// `Display`, because `Display` quotes the offending source line, and a config
/// line can hold a secret. Line and column are 1-based and computed over
/// `text`; when the error has no span, both are zero and only the message is
/// shown.
///
/// The message itself still quotes the offending value for serde type and
/// value errors (``invalid type: integer `123456`, expected a string``), so a
/// secret written with the wrong type would leak through it. Everything from
/// the first `"` or `` ` `` up to serde's final `, expected …` tail, or to the
/// end when that tail does not read as schema text, is therefore masked as
/// [`MASKED_VALUE`](crate::secret::MASKED_VALUE); see [`mask_quoted_values`].
fn toml_parse_error(path: PathBuf, text: &str, error: &toml::de::Error) -> ConfigError {
    let message = mask_quoted_values(error.message());
    let (line, column) = error.span().map_or((0, 0), |span| {
        let before = text.get(..span.start).unwrap_or(text);
        // `split` yields one more piece than there are newlines, so the count
        // is already the 1-based line number.
        let line = before.split('\n').count();
        let current_line = before.rsplit('\n').next().unwrap_or(before);
        (line, current_line.chars().count().saturating_add(1))
    });
    ConfigError::Parse {
        path,
        line,
        column,
        message,
    }
}

/// The part of [`toml_parse_error`]'s message after the path:
/// `line {line}, column {column}: {message}`, or the message alone without a
/// span.
#[cfg(test)]
fn describe_toml_error(text: &str, error: &toml::de::Error) -> String {
    match toml_parse_error(PathBuf::new(), text, error) {
        ConfigError::Parse {
            line,
            column,
            message,
            ..
        } => crate::error::Located::new(line, column, &message).to_string(),
        other => other.to_string(),
    }
}

/// Masks the user's value in a serde message as
/// [`MASKED_VALUE`](crate::secret::MASKED_VALUE), keeping serde's schema text.
///
/// Serde appends its expectation (variant or field names, a type) after the
/// user's value, so the message is split at the last `, expected `, wherever it
/// falls relative to quotes. The marker and everything after it are kept
/// verbatim only when that tail has one of serde's schema forms (see
/// [`is_schema_tail`]): ``unknown variant `********`, expected one of `token`,
/// `oauth` ``. When it does not, the marker belongs to the user's value, as in
/// ``unknown field `x, expected S`, there are no fields``, and the split is
/// ignored. Without a kept tail the whole message is the part to mask.
///
/// In that part, everything from the first `"` or `` ` `` to the end is masked
/// as one span, keeping the opening delimiter and, when the part ends with it,
/// the closing one. Delimiters are not paired, because serde does not escape a
/// `` ` `` inside a backtick-quoted value, so a value holding one could
/// otherwise close the span early and leave the rest of itself in clear.
///
/// One case still leaks: a value that itself ends in `, expected ` followed by
/// a schema form, in a message where serde appends no expected clause of its
/// own. The value ``x, expected `a`` quoted at the end of ``duplicate field
/// `…` `` yields the tail `` `a` ``, a valid name list, so `a` stays in clear.
fn mask_quoted_values(message: &str) -> String {
    const EXPECTED: &str = ", expected ";
    let (value, schema) = match message.rsplit_once(EXPECTED) {
        Some((value, schema)) if is_schema_tail(schema) => (value, Some(schema)),
        _ => (message, None),
    };
    let mut masked = String::with_capacity(message.len());
    let mut rest = value.chars();
    while let Some(c) = rest.next() {
        masked.push(c);
        if c == '"' || c == '`' {
            masked.push_str(crate::secret::MASKED_VALUE);
            if rest.as_str().ends_with(c) {
                masked.push(c);
            }
            break;
        }
    }
    if let Some(schema) = schema {
        masked.push_str(EXPECTED);
        masked.push_str(schema);
    }
    masked
}

/// Whether `tail`, the text after serde's `, expected `, has one of serde's
/// schema forms.
///
/// The forms are a list of backtick-quoted names (`` `a` ``, `` `a` or `b` ``,
/// ``one of `a`, `b`, `c` ``), each name drawn from `[A-Za-z0-9_.-]`, and a
/// plain description such as `u16` or `an integer between 0 and 65535`, drawn
/// from ASCII alphanumerics, spaces and `_-.,()`.
fn is_schema_tail(tail: &str) -> bool {
    is_name_list(tail.strip_prefix("one of ").unwrap_or(tail))
        || (!tail.is_empty()
            && tail.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | ',' | '(' | ')')
            }))
}

/// Whether `list` is one or more backtick-quoted names separated by `, `, with
/// at most one ` or `, between the last two, and nothing after the last name.
fn is_name_list(list: &str) -> bool {
    let mut rest = list;
    let mut after_or = false;
    loop {
        let Some((name, after_name)) = rest
            .strip_prefix('`')
            .and_then(|quoted| quoted.split_once('`'))
        else {
            return false;
        };
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            return false;
        }
        if after_name.is_empty() {
            return true;
        }
        if after_or {
            return false;
        }
        if let Some(next) = after_name.strip_prefix(" or ") {
            after_or = true;
            rest = next;
        } else if let Some(next) = after_name.strip_prefix(", ") {
            rest = next;
        } else {
            return false;
        }
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
    use crate::Error;
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
        assert!(matches!(
            err,
            Error::Config(ConfigError::ApiKeySourceConflict)
        ));
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
                assert!(
                    matches!(err, Error::Config(ConfigError::InvalidEnvValue { .. })),
                    "{var}={raw}: {err:?}"
                );
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
        let Error::Config(config @ ConfigError::FileNotFound { .. }) = err else {
            panic!("expected ConfigError::FileNotFound, got {err:?}");
        };
        let message = config.to_string();
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
        let Error::Config(config @ ConfigError::FileNotFound { .. }) = err else {
            panic!("expected ConfigError::FileNotFound, got {err:?}");
        };
        let message = config.to_string();
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
        let Error::Config(config @ ConfigError::FileNotFound { .. }) = err else {
            panic!("expected ConfigError::FileNotFound, got {err:?}");
        };
        let message = config.to_string();
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
    fn mask_quoted_values_keeps_the_expected_tail() {
        assert_eq!(
            mask_quoted_values(
                "unknown variant `SENTINEL`, expected one of `token`, `oauth`, `none`"
            ),
            "unknown variant `********`, expected one of `token`, `oauth`, `none`"
        );
    }

    #[test]
    fn mask_quoted_values_masks_a_marker_inside_a_double_quoted_value() {
        assert_eq!(
            mask_quoted_values(r#"invalid type: string "a, expected SENTINEL", expected u16"#),
            r#"invalid type: string "********", expected u16"#
        );
    }

    #[test]
    fn mask_quoted_values_masks_a_backtick_injected_marker() {
        // Serde does not escape the backtick in the value ``x`, expected SECRET``.
        let masked = mask_quoted_values(
            "unknown variant `x`, expected SECRET`, expected one of `token`, `oauth`, `none`",
        );
        assert_eq!(
            masked,
            "unknown variant `********`, expected one of `token`, `oauth`, `none`"
        );
    }

    #[test]
    fn mask_quoted_values_without_a_marker_masks_from_the_first_delimiter() {
        assert_eq!(
            mask_quoted_values("unknown field `a`b`, there are no fields"),
            "unknown field `********"
        );
        assert_eq!(
            mask_quoted_values("missing field api_key"),
            "missing field api_key"
        );
    }

    #[test]
    fn mask_quoted_values_masks_a_marker_followed_by_a_non_schema_tail() {
        let masked = mask_quoted_values("unknown field `x, expected S`, there are no fields");
        assert_eq!(masked, "unknown field `********");
        assert!(!masked.contains('S'), "{masked}");
    }

    #[test]
    fn mask_quoted_values_masks_a_tail_holding_a_quote_outside_a_list() {
        assert_eq!(
            mask_quoted_values(r#"invalid value: "a, expected u16", SECRET"#),
            r#"invalid value: "********"#
        );
        assert_eq!(
            mask_quoted_values("unknown variant `a, expected `token` SECRET`"),
            "unknown variant `********`"
        );
    }

    #[test]
    fn mask_quoted_values_keeps_each_name_list_form() {
        for tail in [
            "one of `token`, `oauth`, `none`",
            "`token` or `oauth`",
            "`token`",
        ] {
            assert_eq!(
                mask_quoted_values(&format!("unknown variant `SENTINEL`, expected {tail}")),
                format!("unknown variant `********`, expected {tail}")
            );
        }
    }

    #[test]
    fn mask_quoted_values_keeps_a_type_description() {
        for tail in ["u16", "a string"] {
            assert_eq!(
                mask_quoted_values(&format!(
                    r#"invalid type: string "SENTINEL", expected {tail}"#
                )),
                format!(r#"invalid type: string "********", expected {tail}"#)
            );
        }
    }

    #[test]
    fn unknown_variant_round_trip_keeps_the_expected_text_but_not_the_value() {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Mode {
            Token,
            OAuth,
            None,
        }
        #[derive(Debug, Deserialize)]
        struct File {
            #[expect(dead_code, reason = "only the parse error is under test")]
            mode: Mode,
        }

        let text = "mode = \"SENTINEL\"\n";
        let err = toml::from_str::<File>(text).unwrap_err();
        assert_eq!(
            describe_toml_error(text, &err),
            "line 1, column 8: unknown variant `********`, expected one of `token`, `oauth`, `none`"
        );
    }

    #[test]
    fn wrong_type_round_trip_keeps_the_expected_text_but_not_the_value() {
        #[derive(Debug, Deserialize)]
        struct File {
            #[expect(dead_code, reason = "only the parse error is under test")]
            port: u16,
        }

        let text = "port = \"abc\"\n";
        let err = toml::from_str::<File>(text).unwrap_err();
        let described = describe_toml_error(text, &err);
        assert!(!described.contains("abc"), "{described}");
        assert_eq!(
            described,
            "line 1, column 8: invalid type: string \"********\", expected u16"
        );
    }

    #[test]
    fn backtick_injected_variant_names_the_valid_variants_but_not_the_value() {
        #[derive(Debug, Default, Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Mode {
            #[default]
            Token,
            OAuth,
        }
        #[derive(Debug, Default, Deserialize)]
        struct File {
            #[serde(default)]
            #[expect(dead_code, reason = "only the parse error is under test")]
            mode: Mode,
        }

        let text = "mode = \"x`, expected SECRET\"\n";
        let err = toml::from_str::<File>(text).unwrap_err();
        let described = describe_toml_error(text, &err);
        assert!(!described.contains("SECRET"), "{described}");
        assert!(
            described.contains("expected `token` or `oauth`"),
            "{described}"
        );
    }

    #[test]
    fn unknown_variant_error_names_the_valid_variants_but_not_the_value() {
        #[derive(Debug, Default, Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Mode {
            #[default]
            Token,
            OAuth,
        }
        #[derive(Debug, Default, Deserialize)]
        struct File {
            #[serde(default)]
            #[expect(dead_code, reason = "only the parse error is under test")]
            mode: Mode,
        }

        let text = "mode = \"SENTINEL-SECRET\"\n";
        let err = toml::from_str::<File>(text).unwrap_err();
        let described = describe_toml_error(text, &err);
        assert!(!described.contains("SENTINEL"), "{described}");
        assert!(
            described.contains("expected `token` or `oauth`"),
            "{described}"
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
