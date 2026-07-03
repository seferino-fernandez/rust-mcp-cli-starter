//! Optional helpers for masking secrets before returning data to the model.
//!
//! The example tools in this template wrap an API whose responses contain no
//! secrets, so nothing here is wired into the return path. If your API returns
//! secret fields (`apiKey`, `password`, `token`, …) or URLs with embedded
//! credentials (e.g. `https://host/dl?apikey=…`), call [`redact_secrets`] on the
//! serialized `serde_json::Value` before handing it back — the MCP layer is the
//! trust boundary to the LLM, so secrets must never reach the model context.

use serde_json::Value;

/// Placeholder substituted for a redacted secret value.
const REDACTED: &str = "********";

/// Object keys whose string value is always a secret and must be masked.
const SENSITIVE_KEYS: &[&str] = &[
    "apikey", "api_key", "apitoken", "token", "password", "passkey",
];

/// Query-string parameter names that carry secrets embedded in a URL.
const SENSITIVE_QUERY_KEYS: &[&str] = &["apikey", "api_key", "apitoken", "token", "passkey"];

/// Recursively masks secrets in a JSON value in place: string values that look
/// like URLs get their sensitive query parameters masked, and object entries
/// whose key names a secret have their string value replaced with `********`.
///
/// Exported as a ready-to-use helper for generated projects; unused by the
/// example tools, hence the `#[expect(dead_code)]` (template helper intended
/// for downstream generated projects).
///
/// This entry point is a thin, non-recursive wrapper around
/// [`redact_secrets_inner`]: `rustc`'s dead-code liveness check for
/// `#[expect(dead_code)]` cannot be satisfied on a function that calls
/// itself (the self-call makes the function look "used" to the fulfillment
/// check even when nothing external calls it), so the actual recursive walk
/// lives in a private helper and `redact_secrets` merely delegates to it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "template helper intended for downstream generated projects"
    )
)]
pub fn redact_secrets(value: &mut Value) {
    redact_secrets_inner(value);
}

/// Projects a JSON object down to the whitelisted `keys` (missing keys are
/// skipped); non-objects are returned unchanged. Use this to return compact
/// summary records for large collections instead of the full upstream payload —
/// gate the full object behind a `verbose` tool parameter.
///
/// Exported as a ready-to-use helper for generated projects; unused by the
/// example tools, hence the `#[expect(dead_code)]` (template helper intended
/// for downstream generated projects).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "template helper intended for downstream generated projects"
    )
)]
pub fn project_fields(value: Value, keys: &[&str]) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(v) = map.get(*key) {
                    out.insert((*key).to_string(), v.clone());
                }
            }
            Value::Object(out)
        }
        other => other,
    }
}

/// Recursive implementation backing [`redact_secrets`]; see its docs.
fn redact_secrets_inner(value: &mut Value) {
    match value {
        Value::String(s) => redact_query_params(s),
        Value::Array(items) => {
            for item in items {
                redact_secrets_inner(item);
            }
        }
        Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if is_sensitive_key(key) {
                    if let Value::String(s) = val {
                        *s = REDACTED.to_string();
                        continue;
                    }
                }
                redact_secrets_inner(val);
            }
        }
        _ => {}
    }
}

/// True when an object key names a secret (case-insensitive).
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEYS.contains(&lower.as_str())
}

/// True when a URL query-parameter name carries a secret (case-insensitive).
fn is_sensitive_query_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_QUERY_KEYS.contains(&lower.as_str())
}

/// Masks the value of every sensitive query parameter within `s` in place.
///
/// Splits on `?`, then on `&`, and for each `key=value` pair whose key is in
/// [`SENSITIVE_QUERY_KEYS`] replaces the value with `********`. A trailing
/// `#fragment` is preserved. Strings without a query are left as-is.
fn redact_query_params(s: &mut String) {
    let Some((base, rest)) = s.split_once('?') else {
        return;
    };
    let (query, fragment) = match rest.split_once('#') {
        Some((q, f)) => (q, Some(f)),
        None => (rest, None),
    };
    let mut changed = false;
    let new_query = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if is_sensitive_query_key(key) => {
                changed = true;
                format!("{key}={REDACTED}")
            }
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");
    if !changed {
        return;
    }
    let mut rebuilt = format!("{base}?{new_query}");
    if let Some(frag) = fragment {
        rebuilt.push('#');
        rebuilt.push_str(frag);
    }
    *s = rebuilt;
}

#[cfg(test)]
mod tests {
    use super::redact_secrets;
    use serde_json::json;

    #[test]
    fn redacts_apikey_query_param_in_url() {
        let mut value = json!({
            "data": { "downloadUrl": "http://host:9696/2/download?apikey=deadbeefsecret&link=abc" }
        });
        redact_secrets(&mut value);
        assert_eq!(
            value["data"]["downloadUrl"],
            json!("http://host:9696/2/download?apikey=********&link=abc")
        );
    }

    #[test]
    fn does_not_mask_substring_of_larger_param() {
        let mut value = json!({ "url": "https://x/y?notapikey=keepme" });
        redact_secrets(&mut value);
        assert_eq!(value["url"], json!("https://x/y?notapikey=keepme"));
    }

    #[test]
    fn masks_secret_named_object_keys() {
        let mut value = json!({ "apiKey": "topsecret", "name": "public" });
        redact_secrets(&mut value);
        assert_eq!(value["apiKey"], json!("********"));
        assert_eq!(value["name"], json!("public"));
    }

    #[test]
    fn project_fields_whitelists_keys() {
        use super::project_fields;
        let value = json!({ "id": 1, "name": "x", "overview": "long...", "images": [] });
        let projected = project_fields(value, &["id", "name"]);
        assert_eq!(projected, json!({ "id": 1, "name": "x" }));
    }

    #[test]
    fn project_fields_passes_non_objects_through() {
        use super::project_fields;
        let value = json!([1, 2, 3]);
        assert_eq!(project_fields(value.clone(), &["id"]), value);
    }
}
