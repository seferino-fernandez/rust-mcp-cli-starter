//! Shared helpers and result types for MCP tool handlers.

use myapp_core::Error;
use myapp_core::pagination::Page;
use schemars::JsonSchema;
use serde::Serialize;

/// Formats a core [`Error`] as a tool-call error string.
///
/// Maps the leak-prone cases to concise, actionable messages so tool errors
/// never expose internals to the model:
///
/// - A body-parse failure surfaces from `myapp_core` as an [`Error::Api`]
///   carrying the *success* status of the response it failed to decode, with a
///   message embedding serde line/column detail and the full request URL (which
///   may contain an API key). Both must be hidden.
/// - A bare 404 is unhelpful on its own, so it gets a hint toward the list tool.
///
/// Every other variant already has a clean, non-leaking `Display`.
pub(crate) fn format_tool_error(error: &Error) -> String {
    match error {
        Error::Api { status, .. } if (200..300).contains(status) => {
            "the upstream server returned a response this tool could not parse \
             (unexpected format or content type)"
                .to_string()
        }
        Error::Api { status: 404, .. } => {
            "not found (404): verify the id - use the corresponding list tool to find valid ids"
                .to_string()
        }
        other => other.to_string(),
    }
}

/// A list result: the items plus their count, and the page they came from
/// when the upstream endpoint is paginated.
///
/// The MCP spec requires a tool's `outputSchema` to have an `object` root, so
/// a bare array is not allowed; wrapping a `Vec<T>` as
/// `{ "items": [...], "count": N }` keeps list tools spec-compliant. A
/// paginated list also carries the totals the model needs to fetch further
/// pages.
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct Items<T> {
    /// The listed items.
    pub items: Vec<T>,
    /// The number of items in `items`.
    pub count: usize,
    /// 1-based page index, for a paginated list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
    /// Number of items requested per page, for a paginated list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// Total items available across all pages, for a paginated list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_records: Option<u32>,
}

impl<T> Items<T> {
    /// Wraps an unpaginated list, recording its length as `count`.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "template helper for unpaginated list tools in generated projects"
        )
    )]
    pub fn new(items: Vec<T>) -> Self {
        Self {
            count: items.len(),
            items,
            page: None,
            page_size: None,
            total_records: None,
        }
    }
}

impl<T> From<Page<T>> for Items<T> {
    /// Wraps one upstream page, keeping its pagination totals.
    fn from(page: Page<T>) -> Self {
        Self {
            count: page.records.len(),
            items: page.records,
            page: Some(page.page),
            page_size: Some(page.page_size),
            total_records: Some(page.total_records),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{Items, format_tool_error};
    use myapp_core::Error;
    use serde_json::json;

    #[test]
    fn unpaginated_items_omit_the_page_fields() {
        let items = Items::new(vec![1, 2, 3]);
        assert_eq!(
            serde_json::to_value(items).unwrap(),
            json!({ "items": [1, 2, 3], "count": 3 })
        );
    }

    #[test]
    fn parse_failure_is_generic_and_hides_url_and_serde_detail() {
        // handle_response wraps a decode failure as an Api error carrying the
        // response's success status; its message embeds the URL + serde detail.
        let err = Error::Api {
            status: 200,
            message: "Failed to parse response from \
                      http://application:9696/api?apikey=hunter2: \
                      invalid type: null, expected a string at line 65 column 22"
                .to_string(),
        };
        let msg = format_tool_error(&err);
        assert!(!msg.contains("line 65"), "leaked serde position: {msg}");
        assert!(!msg.contains("hunter2"), "leaked api key: {msg}");
        assert!(!msg.contains("application"), "leaked internal url: {msg}");
        assert!(msg.contains("could not parse"), "unexpected message: {msg}");
    }

    #[test]
    fn error_404_gets_hint() {
        let err = Error::Api {
            status: 404,
            message: String::new(),
        };
        let msg = format_tool_error(&err);
        assert!(msg.contains("list tool"), "expected a hint: {msg}");
    }

    #[test]
    fn genuine_api_error_uses_display() {
        let err = Error::Api {
            status: 500,
            message: "boom".to_string(),
        };
        assert_eq!(format_tool_error(&err), "API error (500): boom");
    }
}
