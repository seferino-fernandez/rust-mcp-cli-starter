//! The one error type MCP tool bodies return.
//!
//! [`ToolError`] owns error sanitisation, so a tool body propagates any core
//! failure with `?` and the model still sees only a concise, non-leaking
//! message.

use std::fmt;

use myapp_core::Error;
use rmcp::model::{ContentBlock, IntoContents};

use super::types::format_tool_error;

/// A tool-call failure, holding the sanitised message the model sees.
///
/// It renders as one text block. rmcp's `IntoCallToolResult` for
/// `Result<T, E>` flags the result `is_error: true`, exactly as it does for an
/// `Err(String)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolError(String);

/// A core failure is shown only through [`format_tool_error`]: the 404 hint
/// or [`Error::public_message`], never an upstream body, URL or secret.
impl From<Error> for ToolError {
    fn from(error: Error) -> Self {
        Self(format_tool_error(&error))
    }
}

/// A result that cannot be serialized for redaction is reported without the
/// serializer's detail, which can quote the data.
impl From<serde_json::Error> for ToolError {
    fn from(_error: serde_json::Error) -> Self {
        Self("failed to serialize tool result".to_string())
    }
}

/// A message a tool or helper words itself, such as an input error, used
/// verbatim.
impl From<String> for ToolError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl IntoContents for ToolError {
    fn into_contents(self) -> Vec<ContentBlock> {
        vec![ContentBlock::text(self.0)]
    }
}

#[cfg(test)]
mod tests {
    use super::ToolError;
    use myapp_core::Error;

    const SENTINEL: &str = "sentinel-secret";

    #[test]
    fn core_error_is_the_public_message() {
        for error in [
            Error::api(500, &format!("raw body with {SENTINEL}")),
            Error::api(
                200,
                &format!("http://application:9696/api?apikey={SENTINEL}"),
            ),
            Error::Redirected { status: 302 },
        ] {
            let expected = error.public_message().into_owned();
            let message = ToolError::from(error).to_string();
            assert_eq!(message, expected);
            assert!(!message.contains(SENTINEL), "leaked: {message}");
        }
    }

    #[test]
    fn not_found_gets_the_list_tool_hint() {
        let message = ToolError::from(Error::api(404, "")).to_string();
        assert!(message.contains("list tool"), "expected a hint: {message}");
    }

    #[test]
    fn serialization_failure_hides_the_detail() {
        let source = serde_json::from_str::<u8>(&format!("\"{SENTINEL}\""))
            .expect_err("a string is not a u8");
        assert_eq!(
            ToolError::from(source).to_string(),
            "failed to serialize tool result"
        );
    }

    #[test]
    fn input_message_is_used_verbatim() {
        assert_eq!(
            ToolError::from("name must not be empty".to_string()).to_string(),
            "name must not be empty"
        );
    }
}
