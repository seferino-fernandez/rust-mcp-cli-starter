//! Scrubs the exact secrets a client holds, such as its API key, from text
//! and JSON.

use std::borrow::Cow;

use super::MASKED_VALUE;
use super::json::rename_keys;
use crate::SecretString;

/// Scrubs `secrets` from every string and object key in `value`, preparing
/// them once. Keys that collide once scrubbed are all kept, as
/// [`rename_keys`] describes.
pub(crate) fn scrub_json_secrets(value: &mut serde_json::Value, secrets: &[SecretString]) {
    PreparedSecrets::new(secrets).scrub_json(value);
}

/// Scrubs the raw, JSON-escaped, and form-encoded forms of `secrets` from
/// `message`.
///
/// Each raw and JSON-escaped form becomes [`MASKED_VALUE`]. A message that
/// still holds a secret once form-decoded, after its raw forms are removed,
/// becomes [`MASKED_VALUE`] whole.
pub(crate) fn scrub_secret_representations(message: &str, secrets: &[SecretString]) -> String {
    PreparedSecrets::new(secrets).scrub(message).into_owned()
}

/// Secrets with their JSON-escaped forms computed once, ready to scrub any
/// number of strings.
struct PreparedSecrets<'secret>(Vec<PreparedSecret<'secret>>);

struct PreparedSecret<'secret> {
    raw: &'secret str,
    /// The secret as it appears inside a JSON string.
    escaped: Option<String>,
}

impl<'secret> PreparedSecrets<'secret> {
    /// Prepares the `secrets` that hold more than whitespace: an empty or
    /// whitespace-only secret would mask every gap between words, so it is
    /// never a value to scrub. A very short secret, such as one character,
    /// is still scrubbed wherever it appears, which can mangle unrelated
    /// output.
    fn new(secrets: &'secret [SecretString]) -> Self {
        Self(
            secrets
                .iter()
                .map(SecretString::expose_secret)
                .filter(|raw| !raw.trim().is_empty())
                .map(|raw| PreparedSecret {
                    raw,
                    escaped: json_escaped(raw),
                })
                .collect(),
        )
    }

    fn scrub_json(&self, value: &mut serde_json::Value) {
        if self.0.is_empty() {
            return;
        }
        match value {
            serde_json::Value::String(string) => {
                let scrubbed = match self.scrub(string) {
                    Cow::Borrowed(_) => None,
                    Cow::Owned(scrubbed) => Some(scrubbed),
                };
                if let Some(scrubbed) = scrubbed {
                    *string = scrubbed;
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    self.scrub_json(value);
                }
            }
            serde_json::Value::Object(object) => {
                for value in object.values_mut() {
                    self.scrub_json(value);
                }
                rename_keys(object, |key| match self.scrub(key) {
                    Cow::Borrowed(_) => None,
                    Cow::Owned(scrubbed) => Some(scrubbed),
                });
            }
            _ => {}
        }
    }

    /// Scrubs each secret in turn from `message`, borrowing it when nothing
    /// changes.
    ///
    /// The form-encoded check only parses the message when it could find
    /// something: with no `%` or `+`, every decoded name and value is a
    /// substring of the message, so a message without the secret cannot
    /// decode to one with it.
    fn scrub<'message>(&self, message: &'message str) -> Cow<'message, str> {
        let mut scrubbed = Cow::Borrowed(message);
        for secret in &self.0 {
            let raw = secret.raw;
            let holds_raw = scrubbed.contains(raw);
            {
                let without_raw = if holds_raw {
                    Cow::Owned(scrubbed.replace(raw, ""))
                } else {
                    Cow::Borrowed(scrubbed.as_ref())
                };
                let may_decode_to_secret =
                    without_raw.contains(['%', '+']) || without_raw.contains(raw);
                if may_decode_to_secret && encoded_value_contains_secret(&without_raw, raw) {
                    return Cow::Owned(MASKED_VALUE.to_string());
                }
            }
            if holds_raw {
                scrubbed = Cow::Owned(scrubbed.replace(raw, MASKED_VALUE));
            }
            if let Some(escaped) = &secret.escaped
                && scrubbed.contains(escaped.as_str())
            {
                scrubbed = Cow::Owned(scrubbed.replace(escaped.as_str(), MASKED_VALUE));
            }
        }
        scrubbed
    }
}

/// Escapes `raw` as the content of a JSON string.
fn json_escaped(raw: &str) -> Option<String> {
    let serialized = serde_json::to_string(raw).ok()?;
    serialized
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .map(str::to_string)
}

fn encoded_value_contains_secret(value: &str, secret: &str) -> bool {
    ::url::form_urlencoded::parse(value.as_bytes())
        .any(|(name, decoded_value)| name.contains(secret) || decoded_value.contains(secret))
}

#[cfg(test)]
mod tests {
    use super::{scrub_json_secrets, scrub_secret_representations};
    use crate::SecretString;
    use crate::redact::MASKED_VALUE;

    #[test]
    fn raw_escaped_and_encoded_forms_are_scrubbed() {
        let secrets = [SecretString::from("hunter2\"&tail")];
        assert_eq!(
            scrub_secret_representations("key hunter2\"&tail rejected", &secrets),
            "key ******** rejected"
        );
        assert_eq!(
            scrub_secret_representations(r#"{"k":"hunter2\"&tail"}"#, &secrets),
            r#"{"k":"********"}"#
        );
        assert_eq!(
            scrub_secret_representations("q=hunter2%22%26tail", &secrets),
            MASKED_VALUE
        );
    }

    #[test]
    fn unrelated_encoded_text_is_preserved() {
        let secrets = [SecretString::from("different secret")];
        let input = "safe%20text+and+symbols%2Fremain";

        assert_eq!(scrub_secret_representations(input, &secrets), input);
    }

    #[test]
    fn an_empty_or_whitespace_secret_scrubs_nothing() {
        for secret in ["", " ", "\t\n "] {
            let secrets = [SecretString::from(secret)];
            assert_eq!(
                scrub_secret_representations("some text\there", &secrets),
                "some text\there"
            );
            let mut value = serde_json::json!({"a b": "some text"});
            scrub_json_secrets(&mut value, &secrets);
            assert_eq!(value, serde_json::json!({"a b": "some text"}));
        }
    }

    #[test]
    fn object_keys_are_scrubbed() {
        let secrets = [SecretString::from("k3y")];
        let mut value = serde_json::json!({"k3y": 1, "x-k3y-y": {"k3y": "k3y"}});
        scrub_json_secrets(&mut value, &secrets);
        assert_eq!(
            value,
            serde_json::json!({"********": 1, "x-********-y": {"********": "********"}})
        );
    }

    #[test]
    fn json_strings_are_scrubbed_at_any_depth() {
        let secrets = [SecretString::from("k3y")];
        let mut value = serde_json::json!({"a": ["see k3y", {"b": "k3y"}], "c": 1});
        scrub_json_secrets(&mut value, &secrets);
        assert_eq!(
            value,
            serde_json::json!({"a": ["see ********", {"b": "********"}], "c": 1})
        );
    }
}
