//! Masks credentials in JSON presentation data.

use std::borrow::Cow;

use super::free_text::redact_free_text;
use super::{MASKED_VALUE, is_sensitive_object_key};

/// Recursively masks credentials embedded in JSON presentation data.
///
/// A non-null value under a credential-like key is replaced by
/// [`MASKED_VALUE`], whatever its type, and every other string gets the
/// free-text rules of [`redact_text`](super::redact_text), so JSON embedded in
/// a string is masked too.
pub(crate) fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json(value);
            }
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if is_sensitive_object_key(key) && !value.is_null() {
                    *value = serde_json::Value::String(MASKED_VALUE.to_string());
                } else {
                    redact_json(value);
                }
            }
        }
        serde_json::Value::String(string) => {
            let redacted = match redact_free_text(string) {
                Cow::Borrowed(_) => None,
                Cow::Owned(redacted) => Some(redacted),
            };
            if let Some(redacted) = redacted {
                *string = redacted;
            }
        }
        _ => {}
    }
}
