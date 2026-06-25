//! Shared helpers and result types for MCP tool handlers.

use myapp_core::Error;
use myapp_core::models::Item;
use schemars::JsonSchema;
use serde::Serialize;

/// Formats a core [`Error`] as a tool-call error string.
pub(crate) fn format_tool_error(error: &Error) -> String {
    error.to_string()
}

/// Structured result for `list_items`.
///
/// The MCP spec requires a tool's `outputSchema` to have an `object` root, so a
/// bare array is not allowed, so the page is wrapped in this envelope, which also
/// surfaces the pagination totals the model needs to fetch further pages.
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ListItemsResult {
    /// Items on the requested page.
    pub items: Vec<Item>,
    /// 1-based page index.
    pub page: u32,
    /// Number of items requested per page.
    pub page_size: u32,
    /// Total items available across all pages.
    pub total_records: u32,
}

/// Structured result for `delete_item`. The core delete endpoint returns no
/// body, so this small type gives the tool a typed `outputSchema` alongside the
/// other item tools.
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct DeleteResult {
    /// Always `true` on success (failures surface as a tool error instead).
    pub deleted: bool,
    /// Id of the deleted item.
    pub id: i64,
}
