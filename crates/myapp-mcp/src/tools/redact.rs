//! An opt-in helper for shrinking tool output before it is redacted.
//!
//! Redaction itself lives in `myapp_core::redact`: every tool returns
//! `Json<Redacted<T>>` built by `ApiClient::redact`, which masks secret keys,
//! credentials in URLs and free text, and the client's API key. Nothing here
//! masks anything.

use serde_json::Value;

/// Projects a JSON object down to the whitelisted `keys` (missing keys are
/// skipped); non-objects are returned unchanged.
///
/// Use it when an upstream record is much larger than what the model needs,
/// such as a list tool over a collection whose records carry long
/// descriptions or nested media: return compact summary records by default
/// and gate the full object behind a `verbose` tool parameter, so the result
/// stays within the response budget. It is not redaction: a whitelisted key
/// still holds whatever the upstream sent, so pass the projection through
/// `ApiClient::redact` like any other output. The result is an untyped
/// `Value`, so a tool that returns it should declare a typed summary struct
/// for its output schema instead of `Value`.
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

#[cfg(test)]
mod tests {
    use super::project_fields;
    use serde_json::json;

    #[test]
    fn project_fields_whitelists_keys() {
        let value = json!({ "id": 1, "name": "x", "overview": "long...", "images": [] });
        let projected = project_fields(value, &["id", "name"]);
        assert_eq!(projected, json!({ "id": 1, "name": "x" }));
    }

    #[test]
    fn project_fields_passes_non_objects_through() {
        let value = json!([1, 2, 3]);
        assert_eq!(project_fields(value.clone(), &["id"]), value);
    }
}
