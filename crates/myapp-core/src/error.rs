//! Error types for the `myapp-core` crate.
//!
//! All fallible operations return [`Error`] through the crate-level
//! [`Result`](crate::Result) alias.

use thiserror::Error;

/// Extracts a clean message from a JSON error body when possible.
///
/// Tries `{"message": ...}`, `{"detail": ...}`, and `{"error":{"message":...}}`,
/// falling back to the raw body.
fn display_api_error(status: u16, body: &str) -> String {
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(msg) = parsed
            .get("message")
            .or_else(|| parsed.get("detail"))
            .and_then(|v| v.as_str())
        {
            return format!("API error ({status}): {msg}");
        }
        if let Some(msg) = parsed
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|v| v.as_str())
        {
            return format!("API error ({status}): {msg}");
        }
    }
    format!("API error ({status}): {body}")
}

/// Errors returned by `myapp-core`.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying HTTP transport failure (connect, timeout, TLS, etc.).
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// The API returned a non-success status. `message` holds the raw body;
    /// the `Display` impl extracts a clean message when the body is JSON.
    #[error("{}", display_api_error(*status, message))]
    Api {
        /// HTTP status code.
        status: u16,
        /// Raw response body.
        message: String,
    },

    /// The API returned HTTP 429. Honor `retry_after_secs` before retrying.
    #[error("rate limited; retry after {retry_after_secs}s")]
    RateLimited {
        /// Seconds to wait before retrying.
        retry_after_secs: u64,
    },

    /// Configuration is invalid (bad value, conflicting fields, etc.).
    #[error("configuration error: {0}")]
    Config(String),

    /// Local I/O failure (e.g. reading a `*_FILE` secret).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// No API key was provided by any source.
    #[error(
        "no API key configured; set MYAPP_API_KEY, MYAPP_API_KEY_FILE, \
         --api-key, or api_key in config.toml"
    )]
    MissingApiKey,
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn api_error_extracts_json_message() {
        let err = Error::Api {
            status: 404,
            message: r#"{"message":"not found"}"#.to_string(),
        };
        assert_eq!(err.to_string(), "API error (404): not found");
    }

    #[test]
    fn api_error_falls_back_to_raw_body() {
        let err = Error::Api {
            status: 500,
            message: "boom".to_string(),
        };
        assert_eq!(err.to_string(), "API error (500): boom");
    }
}
