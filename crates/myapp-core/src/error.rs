//! Error types for the `myapp-core` crate.
//!
//! All fallible operations return [`Error`] through the crate-level
//! [`Result`] alias. [`Error::public_message`] is the one
//! policy for what a CLI user or an MCP client may see.

use std::borrow::Cow;
use std::fmt;
use std::path::PathBuf;

use serde_json::error::Category;
use thiserror::Error;

use crate::SecretString;
use crate::redact::{
    MASKED_VALUE, is_sensitive_free_text_key, redact_json, redact_text, scrub_json_secrets,
    scrub_secret_representations,
};

/// Maximum UTF-8 bytes retained in an upstream error message.
pub(crate) const MAX_ERROR_MESSAGE_BYTES: usize = 8 * 1024;
/// Message used when a data error's text cannot be shown without body values.
const UNMATCHED_DATA_MESSAGE: &str =
    "response contained data that does not match the expected type";
/// Public message for a response the upstream sent but the caller cannot use.
const UNEXPECTED_RESPONSE_MESSAGE: &str = "the upstream server returned an unexpected response";
/// Public message for a transport failure.
const REQUEST_FAILED_MESSAGE: &str = "the upstream request failed";

/// Errors returned by `myapp-core`.
///
/// A variant either shows its inner error in its message or returns it from
/// [`std::error::Error::source`], never both, so a chain printer such as
/// anyhow's `{:#}` prints each cause once.
///
/// The enum is non-exhaustive, so callers should include a fallback match arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying HTTP transport failure (connect, timeout, TLS, etc.).
    ///
    /// Secret query values and user information are masked in the wrapped
    /// error's URL before it is stored.
    #[error("HTTP transport error")]
    Http(#[source] reqwest::Error),

    /// The API returned a non-success status other than a redirect or 429.
    #[error("{0}")]
    Api(ApiError),

    /// The API returned HTTP 429. Honor `retry_after_secs` before retrying.
    #[error("rate limited; retry after {retry_after_secs}s")]
    RateLimited {
        /// Seconds to wait before retrying.
        retry_after_secs: u64,
    },

    /// The API answered with a 3xx redirect, which the client never follows
    /// because the API key header would go to the redirect target.
    ///
    /// The `Location` is deliberately not kept: it can name another host or
    /// carry credentials.
    #[error(
        "the upstream server redirected the request (HTTP {status}); redirects are not \
         followed, so check base_url and any reverse proxy in front of the server"
    )]
    Redirected {
        /// HTTP redirect status code.
        status: u16,
    },

    /// A successful response did not match the endpoint's JSON shape.
    #[error("failed to deserialize response from {endpoint}")]
    Deserialization {
        /// The request path, without its query.
        endpoint: String,
        /// Redacted JSON decoder error that keeps the expected type and position.
        #[source]
        source: DeserializationError,
    },

    /// Configuration is invalid (bad value, conflicting fields, etc.).
    #[error("configuration error: {0}")]
    Config(ConfigError),

    /// Local I/O failure (e.g. reading a `*_FILE` secret).
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    /// No API key was provided by any source.
    #[error(
        "no API key configured; set MYAPP_API_KEY, MYAPP_API_KEY_FILE, \
         --api-key, or api_key in config.toml"
    )]
    MissingApiKey,
}

impl From<reqwest::Error> for Error {
    /// Wraps a transport error after masking the credentials in its URL:
    /// secret query values and user information, then whatever the free-text
    /// rules of [`redact_text`] find, such as a `/passkey/` segment.
    fn from(source: reqwest::Error) -> Self {
        Self::Http(sanitize_reqwest_error(source))
    }
}

impl From<ConfigError> for Error {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl Error {
    /// Builds an [`Error::Api`] from an HTTP status and a raw response body.
    ///
    /// The message is taken from the body's `message`, `detail`, or
    /// `error.message` when the body is JSON, and from the trimmed body
    /// otherwise. Credentials are always masked: JSON bodies get key-based
    /// redaction, and the message gets free-text redaction such as
    /// `apikey=********`. The message is then bounded to 8 KiB.
    ///
    /// # Examples
    ///
    /// ```
    /// use myapp_core::Error;
    ///
    /// let Error::Api(api) = Error::api(500, "upstream failed: apikey=hunter2") else {
    ///     unreachable!("Error::api builds an Api error");
    /// };
    /// assert_eq!(api.status(), 500);
    /// assert_eq!(api.message(), "upstream failed: apikey=********");
    /// ```
    #[must_use]
    pub fn api(status: u16, body: &str) -> Self {
        Self::api_with_secrets(status, body, &[])
    }

    /// Builds an [`Error::Api`] like [`Self::api`], also masking every exact
    /// representation of `secrets`.
    pub(crate) fn api_with_secrets(status: u16, body: &str, secrets: &[SecretString]) -> Self {
        // Exact secrets are scrubbed before redaction as well as after it: a
        // redaction that masks only the start of a secret would otherwise
        // leave its tail for the exact match to miss.
        let mut body = Cow::Borrowed(body);
        if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&body) {
            scrub_json_secrets(&mut json, secrets);
            redact_json(&mut json);
            scrub_json_secrets(&mut json, secrets);
            if let Ok(redacted) = serde_json::to_string(&json) {
                body = Cow::Owned(redacted);
            }
        }
        let message = scrub_secret_representations(&extract_api_message(&body), secrets);
        Self::Api(ApiError {
            status,
            message: bound_message(scrub_secret_representations(
                &redact_text(&message),
                secrets,
            )),
        })
    }

    /// Reports whether the API returned HTTP 404.
    ///
    /// # Examples
    ///
    /// ```
    /// use myapp_core::Error;
    ///
    /// assert!(Error::api(404, r#"{"message":"item not found"}"#).is_not_found());
    /// assert!(!Error::MissingApiKey.is_not_found());
    /// ```
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::Api(api) if api.status == 404)
    }

    /// Returns a message that is safe to show to a CLI user or an MCP client.
    ///
    /// It never holds an upstream body, a request URL, a header, or a secret.
    /// Upstream API errors expose only their status; a 2xx [`Error::Api`] and
    /// [`Error::Deserialization`] both mean the upstream sent a response the
    /// caller cannot use. Transport failures hide the [`reqwest`] detail, I/O
    /// failures name their cause, and redirect, configuration, rate-limit and
    /// missing-key failures keep their [`Display`](fmt::Display) text, which
    /// names no upstream data.
    ///
    /// # Examples
    ///
    /// ```
    /// use myapp_core::Error;
    ///
    /// assert_eq!(
    ///     Error::api(500, "stack trace with internals").public_message(),
    ///     "upstream API request failed with status 500"
    /// );
    /// assert_eq!(
    ///     Error::api(200, "<html>").public_message(),
    ///     "the upstream server returned an unexpected response"
    /// );
    /// ```
    #[must_use]
    pub fn public_message(&self) -> Cow<'_, str> {
        match self {
            Self::Api(api) if (200..300).contains(&api.status) => {
                Cow::Borrowed(UNEXPECTED_RESPONSE_MESSAGE)
            }
            Self::Deserialization { .. } => Cow::Borrowed(UNEXPECTED_RESPONSE_MESSAGE),
            Self::Api(api) => Cow::Owned(format!(
                "upstream API request failed with status {}",
                api.status
            )),
            Self::Http(_) => Cow::Borrowed(REQUEST_FAILED_MESSAGE),
            Self::Io(source) => Cow::Owned(format!("I/O error: {source}")),
            Self::RateLimited { .. }
            | Self::Redirected { .. }
            | Self::Config(_)
            | Self::MissingApiKey => Cow::Owned(self.to_string()),
        }
    }
}

/// Masks the credentials in a transport error's URL.
///
/// The values of query parameters whose decoded name is a sensitive key, as
/// in `apikey`, `password` or `access_token`, and the URL's user information
/// become [`MASKED_VALUE`]. The free-text rules of [`redact_text`] then mask
/// what is left, such as the segment after `/passkey/`. A URL that no longer
/// parses once masked is removed from the error.
fn sanitize_reqwest_error(mut error: reqwest::Error) -> reqwest::Error {
    let Some(url) = error.url_mut() else {
        return error;
    };
    if url.query().is_some() {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(key, value)| {
                let value = if is_sensitive_free_text_key(&key) {
                    MASKED_VALUE.to_string()
                } else {
                    value.into_owned()
                };
                (key.into_owned(), value)
            })
            .collect();
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    let masked_user = !url.username().is_empty() && url.set_username(MASKED_VALUE).is_err();
    let masked_password = url.password().is_some() && url.set_password(Some(MASKED_VALUE)).is_err();
    if masked_user || masked_password {
        return error.without_url();
    }
    let redacted = match redact_text(url.as_str()) {
        Cow::Borrowed(_) => None,
        Cow::Owned(redacted) => Some(redacted),
    };
    if let Some(redacted) = redacted {
        match reqwest::Url::parse(&redacted) {
            Ok(parsed) => *url = parsed,
            Err(_) => return error.without_url(),
        }
    }
    error
}

/// A non-success upstream response other than a redirect or HTTP 429.
///
/// The fields are private so the only way to build one is [`Error::api`],
/// which always redacts the upstream message and bounds it to 8 KiB.
///
/// # Examples
///
/// ```
/// use myapp_core::Error;
///
/// let Error::Api(api) = Error::api(400, r#"{"message":"name is required"}"#) else {
///     unreachable!("Error::api builds an Api error");
/// };
/// assert_eq!(api.status(), 400);
/// assert_eq!(api.message(), "name is required");
/// assert_eq!(api.to_string(), "API error (400): name is required");
/// ```
#[derive(Debug, Clone)]
pub struct ApiError {
    status: u16,
    message: String,
}

impl ApiError {
    /// Returns the HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the redacted upstream message, bounded to 8 KiB.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "API error ({}): {}", self.status, self.message)
    }
}

/// An invalid or conflicting configuration value.
///
/// # Examples
///
/// ```
/// use myapp_core::ConfigError;
///
/// assert_eq!(
///     ConfigError::ApiKeySourceConflict.to_string(),
///     "set either api_key or api_key_file, not both"
/// );
/// ```
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The configuration file sets both `api_key` and `api_key_file`.
    #[error("set either api_key or api_key_file, not both")]
    ApiKeySourceConflict,

    /// The file named by a path argument or `MYAPP_CONFIG` does not exist.
    #[error(
        "config file {}{} does not exist",
        .path.display(),
        if *.set_by_env { " set by MYAPP_CONFIG" } else { "" }
    )]
    FileNotFound {
        /// The path that does not exist.
        path: PathBuf,
        /// Whether `MYAPP_CONFIG` named the path, rather than the caller.
        set_by_env: bool,
    },

    /// The configuration file is not valid TOML for the expected shape.
    ///
    /// The message never quotes the offending line or value, because a
    /// config line can hold the API key.
    #[error(
        "invalid config file {}: {}",
        .path.display(),
        Located::new(*.line, *.column, .message)
    )]
    Parse {
        /// Path of the file that failed to parse.
        path: PathBuf,
        /// One-based line of the error, or zero when unknown.
        line: usize,
        /// One-based column of the error, or zero when unknown.
        column: usize,
        /// Parser message with quoted values masked.
        message: String,
    },

    /// A `MYAPP_*` environment variable holds a value that does not parse.
    #[error("invalid {key} value {raw:?}: {reason}")]
    InvalidEnvValue {
        /// Name of the variable.
        key: String,
        /// The value as set, before trimming.
        raw: String,
        /// Why the value does not parse.
        reason: String,
    },

    /// The API key that won is empty or only whitespace. Such a key could
    /// never authenticate, and scrubbing it from output would mask every
    /// gap between words.
    #[error(
        "API key is empty or whitespace-only; set a real key in MYAPP_API_KEY, \
         MYAPP_API_KEY_FILE, --api-key, or api_key or api_key_file in config.toml"
    )]
    BlankApiKey,

    /// The API key holds bytes that cannot be sent in an HTTP header.
    #[error("API key contains invalid header characters")]
    InvalidApiKeyHeader,
}

/// Formats a parse message as `line {line}, column {column}: {message}`, or the
/// message alone when the line is zero (unknown).
pub(crate) struct Located<'a> {
    line: usize,
    column: usize,
    message: &'a str,
}

impl<'a> Located<'a> {
    /// Pairs `message` with its `line` and `column`; a zero line is unknown.
    pub(crate) const fn new(line: usize, column: usize, message: &'a str) -> Self {
        Self {
            line,
            column,
            message,
        }
    }
}

impl fmt::Display for Located<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line > 0 {
            write!(f, "line {}, column {}: ", self.line, self.column)?;
        }
        f.write_str(self.message)
    }
}

/// Why a response body could not be decoded as JSON.
///
/// The message never contains values from the response body: data errors keep
/// what was expected and the kind of value found, while body strings, numbers,
/// variant names, field names, and custom decoder messages are removed.
///
/// # Examples
///
/// ```
/// use myapp_core::error::DeserializationError;
///
/// let source = serde_json::from_str::<Vec<String>>(r#""hunter2""#).unwrap_err();
/// let error = DeserializationError::from(source);
/// assert_eq!(
///     error.to_string(),
///     "invalid type: string, expected a sequence at line 1 column 9"
/// );
/// assert!(!format!("{error:?}").contains("hunter2"));
/// ```
#[derive(Debug, Clone)]
pub struct DeserializationError {
    message: String,
    line: usize,
    column: usize,
}

impl DeserializationError {
    /// Keeps the position of `error` and its message, with body values
    /// removed and every representation of `secrets` scrubbed.
    pub(crate) fn from_serde(error: &serde_json::Error, secrets: &[SecretString]) -> Self {
        Self {
            message: scrub_secret_representations(&redact_serde_message(error), secrets),
            line: error.line(),
            column: error.column(),
        }
    }

    /// Returns the one-based line where decoding failed, or zero when unknown.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// Returns the column where decoding failed, or zero when unknown.
    #[must_use]
    pub const fn column(&self) -> usize {
        self.column
    }
}

impl From<serde_json::Error> for DeserializationError {
    fn from(error: serde_json::Error) -> Self {
        Self::from_serde(&error, &[])
    }
}

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if self.line > 0 {
            write!(f, " at line {} column {}", self.line, self.column)?;
        }
        Ok(())
    }
}

impl std::error::Error for DeserializationError {}

/// The serde message without its position, with body values removed.
fn redact_serde_message(error: &serde_json::Error) -> String {
    let full = error.to_string();
    let position = format!(" at line {} column {}", error.line(), error.column());
    let message = full.strip_suffix(&position).unwrap_or(&full);
    match error.classify() {
        Category::Io | Category::Syntax | Category::Eof => message.to_string(),
        Category::Data => {
            redact_data_message(message).unwrap_or_else(|| UNMATCHED_DATA_MESSAGE.to_string())
        }
    }
}

/// Rewrites serde's standard data-error texts, returning `None` for any other text.
fn redact_data_message(message: &str) -> Option<String> {
    for prefix in ["invalid type: ", "invalid value: "] {
        if let Some(rest) = message.strip_prefix(prefix) {
            let (unexpected, expected) = rest.rsplit_once(", expected ")?;
            let kind = unexpected
                .split(['"', '`'])
                .next()
                .unwrap_or_default()
                .trim();
            return Some(format!("{prefix}{kind}, expected {expected}"));
        }
    }
    for (prefix, empty) in [
        ("unknown variant ", ", there are no variants"),
        ("unknown field ", ", there are no fields"),
    ] {
        if message.starts_with(prefix) {
            // Check the empty case first: with no candidates, any `, expected `
            // in the message is part of the name taken from the body.
            if message.ends_with(empty) {
                return Some(format!("{prefix}{MASKED_VALUE}{empty}"));
            }
            let (_, expected) = message.rsplit_once(", expected ")?;
            return Some(format!("{prefix}{MASKED_VALUE}, expected {expected}"));
        }
    }
    ["missing field ", "duplicate field ", "invalid length "]
        .iter()
        .any(|prefix| message.starts_with(prefix))
        .then(|| message.to_string())
}

/// Truncates `message` to [`MAX_ERROR_MESSAGE_BYTES`] on a character boundary.
fn bound_message(mut message: String) -> String {
    if message.len() <= MAX_ERROR_MESSAGE_BYTES {
        return message;
    }
    let mut end = MAX_ERROR_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    message.truncate(end);
    message
}

/// Extracts a clean message from an error body.
///
/// Tries `{"message": ...}`, `{"detail": ...}`, and `{"error":{"message":...}}`,
/// falling back to the trimmed body.
fn extract_api_message(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return "upstream returned an empty error response".to_string();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return trimmed.to_string();
    };
    if let Some(message) = value
        .get("message")
        .or_else(|| value.get("detail"))
        .and_then(serde_json::Value::as_str)
    {
        return message.to_string();
    }
    if let Some(message) = value
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(serde_json::Value::as_str)
    {
        return message.to_string();
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer};

    use std::error::Error as _;
    use std::io;
    use std::path::PathBuf;

    use super::{ConfigError, DeserializationError, Error, MAX_ERROR_MESSAGE_BYTES};
    use crate::SecretString;

    const SENTINEL: &str = "sentinel-body-value";

    #[derive(Debug, Deserialize)]
    enum Kind {
        Alpha,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Strict {
        #[expect(dead_code, reason = "decoded only to provoke an unknown-field error")]
        name: String,
    }

    #[derive(Debug, Deserialize)]
    struct Custom {
        #[expect(dead_code, reason = "decoded only to provoke a custom error")]
        #[serde(deserialize_with = "reject_value")]
        value: String,
    }

    fn reject_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
        let value = String::deserialize(deserializer)?;
        Err(D::Error::custom(format!("bad {value}")))
    }

    fn decode_error<T: for<'de> Deserialize<'de> + std::fmt::Debug>(
        json: &str,
    ) -> DeserializationError {
        serde_json::from_str::<T>(json)
            .expect_err("test JSON must fail to decode")
            .into()
    }

    fn assert_redacted(error: &DeserializationError, expected: &str) {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert_eq!(display, expected);
        assert!(!display.contains(SENTINEL), "Display leaked: {display}");
        assert!(!debug.contains(SENTINEL), "Debug leaked: {debug}");
    }

    #[test]
    fn string_for_sequence_keeps_kind_and_expectation() {
        let error = decode_error::<Vec<String>>(&format!(r#""{SENTINEL}""#));
        assert_redacted(
            &error,
            "invalid type: string, expected a sequence at line 1 column 21",
        );
        assert_eq!((error.line(), error.column()), (1, 21));
    }

    #[test]
    fn string_for_integer_keeps_kind_and_expectation() {
        let error = decode_error::<u32>(&format!(r#""{SENTINEL}""#));
        assert_redacted(
            &error,
            "invalid type: string, expected u32 at line 1 column 21",
        );
    }

    #[test]
    fn unknown_variant_redacts_the_variant_name() {
        let error = decode_error::<Kind>(&format!(r#""{SENTINEL}""#));
        assert_redacted(
            &error,
            "unknown variant ********, expected `Alpha` at line 1 column 21",
        );
    }

    #[test]
    fn unknown_field_redacts_the_field_name() {
        let error = decode_error::<Strict>(&["{\"", SENTINEL, "\":1}"].concat());
        assert_redacted(
            &error,
            "unknown field ********, expected `name` at line 1 column 22",
        );
    }

    #[test]
    fn unknown_field_without_candidates_ignores_expected_text_in_the_name() {
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NoFields {}

        let error = decode_error::<NoFields>(&["{\"x, expected ", SENTINEL, "\":1}"].concat());
        assert_redacted(
            &error,
            "unknown field ********, there are no fields at line 1 column 34",
        );
    }

    #[test]
    fn custom_message_fails_closed() {
        let error = decode_error::<Custom>(&["{\"value\":\"", SENTINEL, "\"}"].concat());
        assert_redacted(
            &error,
            "response contained data that does not match the expected type at line 1 column 31",
        );
    }

    #[test]
    fn syntax_error_keeps_serde_text() {
        let error = decode_error::<Vec<u8>>("[1 x]");
        assert_redacted(&error, "expected `,` or `]` at line 1 column 4");
    }

    #[test]
    fn configured_secrets_are_scrubbed_from_kept_text() {
        let source = serde_json::from_str::<(u8, u8)>("[1]").expect_err("tuple is too short");
        let error =
            DeserializationError::from_serde(&source, &[SecretString::from("tuple of size")]);
        assert_eq!(
            error.to_string(),
            "invalid length 1, expected a ******** 2 at line 1 column 3"
        );
    }

    #[test]
    fn api_error_extracts_json_message() {
        let err = Error::api(404, r#"{"message":"not found"}"#);
        assert_eq!(err.to_string(), "API error (404): not found");
    }

    #[test]
    fn api_error_falls_back_to_raw_body() {
        let err = Error::api(500, "boom");
        assert_eq!(err.to_string(), "API error (500): boom");
    }

    #[test]
    fn nested_error_message_is_extracted() {
        let err = Error::api(400, r#"{"error":{"message":"bad request"}}"#);
        assert_eq!(err.to_string(), "API error (400): bad request");
    }

    #[test]
    fn plain_text_api_body_is_redacted() {
        let Error::Api(api) = Error::api(500, "upstream failed: apikey=OTHER") else {
            panic!("Error::api builds an Api error");
        };
        assert_eq!(api.status(), 500);
        assert_eq!(api.message(), "upstream failed: apikey=********");
    }

    #[test]
    fn json_api_body_without_a_message_field_is_redacted() {
        let Error::Api(api) = Error::api(400, r#"{"apiKey":"OTHER"}"#) else {
            panic!("Error::api builds an Api error");
        };
        assert!(!api.message().contains("OTHER"), "{}", api.message());
    }

    #[test]
    fn api_message_is_bounded_to_eight_kib_on_a_char_boundary() {
        let Error::Api(api) = Error::api(500, &"é".repeat(MAX_ERROR_MESSAGE_BYTES)) else {
            panic!("Error::api builds an Api error");
        };
        assert!(api.message().len() <= MAX_ERROR_MESSAGE_BYTES);
        assert!(api.message().len() > MAX_ERROR_MESSAGE_BYTES - 2);
    }

    #[test]
    fn api_with_secrets_masks_a_secret_holding_a_delimiter_whole() {
        // Free-text redaction stops a `password=` value at `&` or a space, so
        // only scrubbing the exact secret first keeps its tail out.
        for secret in ["hunter2&strandedtail", "hunter2 strandedtail"] {
            let secrets = [SecretString::from(secret)];
            for body in [
                format!("rejected password={secret}"),
                serde_json::json!({ "message": format!("rejected password={secret}") }).to_string(),
            ] {
                let error = Error::api_with_secrets(500, &body, &secrets);
                let Error::Api(api) = &error else {
                    panic!("Error::api builds an Api error");
                };
                assert_eq!(api.message(), "rejected password=********", "{body}");
                for text in [error.to_string(), format!("{error:?}")] {
                    assert!(!text.contains("strandedtail"), "leaked tail: {text}");
                }
            }
        }
    }

    #[test]
    fn http_error_exposes_its_source() {
        let source = reqwest::Client::new()
            .get("not a URL")
            .build()
            .expect_err("invalid URL creates a transport error");
        let error = Error::from(source);
        assert_eq!(error.to_string(), "HTTP transport error");
        assert!(error.source().is_some());
    }

    /// Joins the `Display` of `error` and every error in its source chain.
    fn chain_text(error: &Error) -> String {
        let mut text = error.to_string();
        let mut source = error.source();
        while let Some(cause) = source {
            text.push_str(": ");
            text.push_str(&cause.to_string());
            source = cause.source();
        }
        text
    }

    #[test]
    fn chain_prints_each_cause_once() {
        let io = Error::from(io::Error::new(io::ErrorKind::NotFound, "missing.key"));
        assert_eq!(chain_text(&io).matches("missing.key").count(), 1);

        let decoder: DeserializationError = serde_json::from_str::<Vec<String>>("{")
            .expect_err("malformed JSON creates a decoder error")
            .into();
        let decoder_text = decoder.to_string();
        let deserialization = Error::Deserialization {
            endpoint: "/api/v3/item".to_string(),
            source: decoder,
        };
        assert_eq!(
            chain_text(&deserialization)
                .matches(decoder_text.as_str())
                .count(),
            1
        );
    }

    #[test]
    fn public_message_per_variant() {
        let deserialization = Error::Deserialization {
            endpoint: format!("/api/token/{SENTINEL}"),
            source: serde_json::from_str::<String>("{")
                .expect_err("malformed JSON creates a decoder error")
                .into(),
        };
        let http = Error::from(
            reqwest::Client::new()
                .get(format!("not a URL {SENTINEL}"))
                .build()
                .expect_err("invalid URL creates a transport error"),
        );
        let io = Error::from(io::Error::other("missing.key"));
        let displayed = [
            Error::MissingApiKey,
            Error::RateLimited {
                retry_after_secs: 5,
            },
            Error::Redirected { status: 302 },
            Error::Config(ConfigError::ApiKeySourceConflict),
            Error::Config(ConfigError::FileNotFound {
                path: PathBuf::from("/etc/myapp.toml"),
                set_by_env: true,
            }),
        ]
        .map(|error| {
            let display = error.to_string();
            (error, display)
        });

        let mut cases = vec![
            (
                Error::api(500, &format!("body {SENTINEL}")),
                "upstream API request failed with status 500".to_string(),
            ),
            (
                Error::api(200, "x"),
                "the upstream server returned an unexpected response".to_string(),
            ),
            (
                Error::api(404, ""),
                "upstream API request failed with status 404".to_string(),
            ),
            (
                deserialization,
                "the upstream server returned an unexpected response".to_string(),
            ),
            (http, "the upstream request failed".to_string()),
            (io, "I/O error: missing.key".to_string()),
        ];
        cases.extend(displayed);

        for (error, expected) in &cases {
            let message = error.public_message();
            assert_eq!(message, expected.as_str(), "for {error:?}");
            assert!(!message.contains(SENTINEL), "leaked: {message}");
        }
    }

    #[test]
    fn redirected_message_names_the_status_and_the_fix() {
        assert_eq!(
            Error::Redirected { status: 302 }.public_message(),
            "the upstream server redirected the request (HTTP 302); redirects are not \
             followed, so check base_url and any reverse proxy in front of the server"
        );
    }

    #[test]
    fn config_errors_keep_their_messages() {
        let path = PathBuf::from("/tmp/typo.toml");
        for (error, expected) in [
            (
                ConfigError::FileNotFound {
                    path: path.clone(),
                    set_by_env: false,
                },
                "config file /tmp/typo.toml does not exist",
            ),
            (
                ConfigError::FileNotFound {
                    path: path.clone(),
                    set_by_env: true,
                },
                "config file /tmp/typo.toml set by MYAPP_CONFIG does not exist",
            ),
            (
                ConfigError::Parse {
                    path: path.clone(),
                    line: 2,
                    column: 5,
                    message: "boom".to_string(),
                },
                "invalid config file /tmp/typo.toml: line 2, column 5: boom",
            ),
            (
                ConfigError::Parse {
                    path,
                    line: 0,
                    column: 0,
                    message: "boom".to_string(),
                },
                "invalid config file /tmp/typo.toml: boom",
            ),
            (
                ConfigError::InvalidEnvValue {
                    key: "MYAPP_X".to_string(),
                    raw: " soon".to_string(),
                    reason: "invalid digit".to_string(),
                },
                r#"invalid MYAPP_X value " soon": invalid digit"#,
            ),
        ] {
            assert_eq!(error.to_string(), expected);
        }
    }
}
