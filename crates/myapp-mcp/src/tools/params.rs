//! Parameter structs for MCP tools. Each derives `JsonSchema` so rmcp can
//! advertise an input schema, plus `Deserialize` for argument parsing.
//!
//! Every struct denies unknown fields, so a misspelled argument fails the call
//! instead of silently falling back to a default.

use schemars::JsonSchema;
use serde::Deserialize;

/// Parameters for `myapp_list_items`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListItemsParams {
    /// 1-based page number.
    #[serde(default = "default_page")]
    #[schemars(range(min = 1))]
    pub page: u32,
    /// Page size (1–1000).
    #[serde(default = "default_page_size")]
    #[schemars(range(min = 1, max = 1000))]
    pub page_size: u32,
}

fn default_page() -> u32 {
    1
}
fn default_page_size() -> u32 {
    20
}

/// Parameters for `myapp_get_item` / `myapp_delete_item`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ItemIdParams {
    /// Item id.
    ///
    /// The `x-mcp-header` annotation (SEP-2243) asks clients negotiating
    /// 2026-07-28 to also send this value as the `Mcp-Param-Item-Id` HTTP
    /// header, so gateways and proxies can route, rate-limit, or audit by
    /// entity without parsing the JSON-RPC body. The server validates the
    /// header against the body and rejects mismatches.
    ///
    /// Promotion is limited to top-level, primitive-typed properties.
    #[schemars(extend("x-mcp-header" = "Item-Id"))]
    pub id: i64,
}

/// Parameters for `myapp_create_item`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateItemParams {
    /// Item name.
    pub name: String,
    /// Whether the item starts enabled.
    #[serde(default)]
    pub enabled: bool,
}

/// Decodes a free-form JSON request body (a `body: serde_json::Value`
/// parameter) into `T`, without including submitted content in the error.
///
/// serde's messages quote the offending value, which for a request body may
/// be a secret, so the error names only the parameter and the expected model.
/// rmcp decodes the typed params structs above itself; use this for any body
/// a tool decodes on its own.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "template helper for tools in generated projects that take a JSON body"
    )
)]
pub(crate) fn decode_body<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    parameter: &str,
    model: &str,
) -> Result<T, String> {
    serde_json::from_value(value).map_err(|_error| format!("invalid {parameter}: expected {model}"))
}

#[cfg(test)]
mod tests {
    use super::{CreateItemParams, ItemIdParams, ListItemsParams, decode_body};
    use schemars::schema_for;
    use serde_json::json;

    #[test]
    fn every_params_struct_denies_unknown_fields() {
        let unknown = |result: Result<(), serde_json::Error>| {
            let message = result.expect_err("an unknown field is refused").to_string();
            assert!(message.contains("unknown field `extra`"), "{message}");
        };
        unknown(serde_json::from_value::<ListItemsParams>(json!({ "extra": 1 })).map(drop));
        unknown(serde_json::from_value::<ItemIdParams>(json!({ "id": 1, "extra": 1 })).map(drop));
        unknown(
            serde_json::from_value::<CreateItemParams>(json!({ "name": "n", "extra": 1 }))
                .map(drop),
        );
    }

    #[test]
    fn decode_body_never_echoes_the_submitted_body() {
        let error = decode_body::<CreateItemParams>(
            json!({ "name": "hunter2-secret", "enabled": "hunter2-secret" }),
            "body",
            "an item",
        )
        .expect_err("a mistyped field is refused");
        assert_eq!(error, "invalid body: expected an item");
        assert!(!error.contains("hunter2"), "{error}");
    }

    #[test]
    fn decode_body_decodes_a_valid_body() {
        let params: CreateItemParams =
            decode_body(json!({ "name": "n", "enabled": true }), "body", "an item").unwrap();
        assert_eq!(params.name, "n");
        assert!(params.enabled);
    }

    #[test]
    fn list_items_params_bound_page_and_page_size() {
        let schema = serde_json::to_value(schema_for!(ListItemsParams)).expect("schema serializes");
        let props = &schema["properties"];
        assert_eq!(props["page"]["minimum"], serde_json::json!(1));
        assert_eq!(props["page_size"]["minimum"], serde_json::json!(1));
        assert_eq!(props["page_size"]["maximum"], serde_json::json!(1000));
    }
}
