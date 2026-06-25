//! Parameter structs for MCP tools. Each derives `JsonSchema` so rmcp can
//! advertise an input schema, plus `Deserialize` for argument parsing.

use schemars::JsonSchema;
use serde::Deserialize;

/// Parameters for `list_items`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListItemsParams {
    /// 1-based page number.
    #[serde(default = "default_page")]
    pub page: u32,
    /// Page size.
    #[serde(default = "default_page_size")]
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
