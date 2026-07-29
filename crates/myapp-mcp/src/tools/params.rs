//! Parameter structs for MCP tools. Each derives `JsonSchema` so rmcp can
//! advertise an input schema, plus `Deserialize` for argument parsing.

use schemars::JsonSchema;
use serde::Deserialize;

/// Parameters for `list_items`.
#[derive(Debug, Deserialize, JsonSchema)]
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

/// Parameters for `get_item` / `delete_item`.
#[derive(Debug, Deserialize, JsonSchema)]
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

/// Parameters for `create_item`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateItemParams {
    /// Item name.
    pub name: String,
    /// Whether the item starts enabled.
    #[serde(default)]
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::ListItemsParams;
    use schemars::schema_for;

    #[test]
    fn list_items_params_bound_page_and_page_size() {
        let schema = serde_json::to_value(schema_for!(ListItemsParams)).expect("schema serializes");
        let props = &schema["properties"];
        assert_eq!(props["page"]["minimum"], serde_json::json!(1));
        assert_eq!(props["page_size"]["minimum"], serde_json::json!(1));
        assert_eq!(props["page_size"]["maximum"], serde_json::json!(1000));
    }
}
