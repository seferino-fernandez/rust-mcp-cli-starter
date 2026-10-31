//! Secret-safe mapping from core errors to CLI diagnostics.

use myapp_core::Error;

/// Converts a core error into a CLI error carrying only
/// [`Error::public_message`], so upstream response bodies, request URLs,
/// transport details, and deserialization internals never reach the user.
pub fn safe_core_error(error: Error) -> anyhow::Error {
    anyhow::Error::msg(error.public_message().into_owned())
}

#[cfg(test)]
mod tests {
    use super::safe_core_error;
    use myapp_core::Error;

    const SENTINEL: &str = "sentinel-secret";

    #[test]
    fn cli_error_is_the_public_message() {
        let source = serde_json::from_str::<String>("{")
            .expect_err("malformed JSON creates a decoder error");
        for error in [
            Error::api(500, &format!("raw upstream body with apikey={SENTINEL}")),
            Error::api(200, &format!("http://host/api?token={SENTINEL}")),
            Error::Deserialization {
                endpoint: format!("/api/token/{SENTINEL}"),
                source: source.into(),
            },
            Error::Redirected { status: 302 },
            Error::Io(std::io::Error::other("missing.key")),
        ] {
            let expected = error.public_message().into_owned();
            let message = format!("{:#}", safe_core_error(error));
            assert_eq!(message, expected);
            assert!(!message.contains(SENTINEL), "secret leaked: {message}");
        }
    }
}
