//! Masks credentials in JSON presentation data.

use std::borrow::Cow;
use std::collections::HashMap;

use super::free_text::redact_free_text;
use super::{MASKED_VALUE, is_sensitive_object_key};

/// Recursively masks credentials embedded in JSON presentation data.
///
/// A non-null value under a credential-like key is replaced by
/// [`MASKED_VALUE`], whatever its type, and every other string gets the
/// free-text rules of [`redact_text`](super::redact_text), so JSON embedded in
/// a string is masked too. Object keys get the free-text rules as well, so a
/// map keyed by URLs with user information is masked; see [`rename_keys`]
/// for keys that collide once masked.
pub(crate) fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json(value);
            }
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if is_sensitive_object_key(key) && !value.is_null() {
                    *value = serde_json::Value::String(MASKED_VALUE.to_string());
                } else {
                    redact_json(value);
                }
            }
            rename_keys(object, |key| match redact_free_text(key) {
                Cow::Borrowed(_) => None,
                Cow::Owned(redacted) => Some(redacted),
            });
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

/// Renames every key of `object` that `rename` changes, keeping every entry.
///
/// Keys that `rename` leaves alone keep their names. A renamed key that
/// collides with one of them, or with an earlier renamed key, gets the
/// first free suffix of ` (2)`, ` (3)`, …, so two keys that mask to the same
/// text both survive, as `https://u:********@h` and
/// `https://u:********@h (2)`. Renamed keys are visited in the map's order,
/// so the result is deterministic. A map with no key to rename is not
/// rebuilt.
pub(super) fn rename_keys(
    object: &mut serde_json::Map<String, serde_json::Value>,
    rename: impl Fn(&str) -> Option<String>,
) {
    if !object.keys().any(|key| rename(key).is_some()) {
        return;
    }
    let mut renamed = Vec::new();
    for (key, value) in std::mem::take(object) {
        match rename(&key) {
            Some(new_key) => renamed.push((new_key, value)),
            None => {
                let _kept = object.insert(key, value);
            }
        }
    }
    let mut next_suffix: HashMap<String, usize> = HashMap::new();
    for (key, value) in renamed {
        let mut candidate = key.clone();
        if object.contains_key(&candidate) {
            let suffix = next_suffix.entry(key.clone()).or_insert(2);
            loop {
                candidate = format!("{key} ({suffix})");
                *suffix = suffix.saturating_add(1);
                if !object.contains_key(&candidate) {
                    break;
                }
            }
        }
        let _kept = object.insert(candidate, value);
    }
}

#[cfg(test)]
mod tests {
    use super::{redact_json, rename_keys};

    #[test]
    fn keys_that_mask_alike_are_all_kept_in_order() {
        let mut value = serde_json::json!({
            "https://u:a@h": 1,
            "https://u:b@h": 2,
            "https://u:c@h": 3,
            "plain": 4
        });

        redact_json(&mut value);

        assert_eq!(
            value,
            serde_json::json!({
                "https://u:********@h": 1,
                "https://u:********@h (2)": 2,
                "https://u:********@h (3)": 3,
                "plain": 4
            })
        );
    }

    #[test]
    fn a_renamed_key_never_replaces_a_kept_one() {
        let mut object = serde_json::Map::new();
        let _old = object.insert("a".to_string(), serde_json::json!(1));
        let _old = object.insert("b".to_string(), serde_json::json!(2));
        let _old = object.insert("b (2)".to_string(), serde_json::json!(3));

        rename_keys(&mut object, |key| (key == "a").then(|| "b".to_string()));

        assert_eq!(
            serde_json::Value::Object(object),
            serde_json::json!({ "b": 2, "b (2)": 3, "b (3)": 1 })
        );
    }
}
