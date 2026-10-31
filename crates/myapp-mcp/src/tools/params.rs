//! Parameter structs for MCP tools. Each derives `JsonSchema` so rmcp can
//! advertise an input schema, plus `Deserialize` for argument parsing.
//!
//! Every struct denies unknown fields, so a misspelled argument fails the call
//! instead of silently falling back to a default.

use rmcp::ErrorData;
use rmcp::handler::server::tool::parse_json_object;
use rmcp::model::{CallToolResult, ContentBlock, JsonObject};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::DeserializeOwned;

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

/// Decodes a tool call's arguments as its params type, exactly as rmcp does
/// when the tool runs, returning rmcp's own error on failure.
type ParamsCheck = fn(JsonObject) -> Result<(), ErrorData>;

fn decodes_as<T: DeserializeOwned>(arguments: JsonObject) -> Result<(), ErrorData> {
    parse_json_object::<T>(arguments).map(drop)
}

/// The params check of each tool that asks for confirmation and takes
/// params, by tool name.
///
/// rmcp decodes params only when the tool runs, after the confirmation
/// prompt, so without this check a mistyped argument would ask the user to
/// confirm a call that then fails. A schema test fails when a confirming tool
/// with params is missing here.
fn params_check(tool_name: &str) -> Option<ParamsCheck> {
    match tool_name {
        "myapp_delete_item" => Some(decodes_as::<ItemIdParams>),
        _ => None,
    }
}

/// Rejects a call whose arguments do not decode as the tool's params type,
/// for the tools [`params_check`] covers, with the same tool error rmcp
/// returns once the tool runs.
pub(super) fn params_rejection(
    tool_name: &str,
    arguments: Option<&JsonObject>,
) -> Option<CallToolResult> {
    let check = params_check(tool_name)?;
    let error = check(arguments.cloned().unwrap_or_default()).err()?;
    Some(CallToolResult::error(vec![ContentBlock::text(
        error.message,
    )]))
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
pub(crate) fn decode_body<T: DeserializeOwned>(
    value: serde_json::Value,
    parameter: &str,
    model: &str,
) -> Result<T, String> {
    serde_json::from_value(value).map_err(|_error| format!("invalid {parameter}: expected {model}"))
}

#[cfg(test)]
mod tests {
    use super::{
        CreateItemParams, ItemIdParams, ListItemsParams, decode_body, params_check,
        params_rejection,
    };
    use crate::tools::confirm::requires_confirmation;
    use crate::tools::test_support::tools_at;
    use myapp_core::Config;
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

    /// Every tool that asks for confirmation and takes params has a params
    /// check, and every check names such a tool.
    #[test]
    fn every_confirming_tool_with_params_has_a_params_check() {
        let tools = tools_at(Config::default().base_url, 1024)
            .router()
            .list_all();
        let mut checked = 0;
        for tool in &tools {
            let takes_params = tool
                .input_schema
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|properties| !properties.is_empty());
            let has_check = params_check(&tool.name).is_some();
            assert_eq!(
                has_check,
                requires_confirmation(tool) && takes_params,
                "{}",
                tool.name
            );
            checked += usize::from(has_check);
        }
        assert_eq!(checked, 1, "myapp_delete_item is checked");
    }

    #[test]
    fn params_rejection_matches_rmcp_and_passes_valid_arguments() {
        let object = |value: serde_json::Value| value.as_object().cloned().unwrap();
        let rejection = params_rejection("myapp_delete_item", Some(&object(json!({ "id": "x" }))))
            .expect("a mistyped id is rejected");
        assert_eq!(rejection.is_error, Some(true));
        let text = rejection
            .content
            .first()
            .and_then(|content| content.as_text())
            .map(|text| text.text.clone())
            .unwrap_or_default();
        assert!(
            text.starts_with("failed to deserialize parameters: invalid type"),
            "{text}"
        );
        assert!(
            params_rejection("myapp_delete_item", None).is_some(),
            "id is required"
        );
        assert!(params_rejection("myapp_delete_item", Some(&object(json!({ "id": 7 })))).is_none());
        assert!(params_rejection("myapp_get_item", Some(&object(json!({ "id": "x" })))).is_none());
    }
}
