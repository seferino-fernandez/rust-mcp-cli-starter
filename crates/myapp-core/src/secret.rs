//! Minimal secret-string wrapper that keeps sensitive values out of `Debug`
//! and log output. Redaction covers formatting only: the value is stored as a
//! plain `String` and is not zeroed on drop.

use serde::Deserialize;
use std::fmt;

/// Holds a sensitive string such as an API key, bearer token, or PIN.
///
/// The value is redacted in `Debug` output, so structs that derive `Debug` can
/// hold one without leaking it into logs. Read the underlying value explicitly
/// with [`expose_secret`](SecretString::expose_secret).
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Returns the underlying secret. Use sparingly and never log the result.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = SecretString::from("super-secret-value");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("super-secret-value"));
        assert_eq!(rendered, "SecretString([REDACTED])");
    }

    #[test]
    fn expose_secret_returns_inner() {
        let secret = SecretString::from("abc123".to_string());
        assert_eq!(secret.expose_secret(), "abc123");
    }

    #[test]
    fn deserializes_from_bare_string() {
        let secret: SecretString = serde_json::from_str("\"my-token\"").unwrap();
        assert_eq!(secret.expose_secret(), "my-token");
    }
}
