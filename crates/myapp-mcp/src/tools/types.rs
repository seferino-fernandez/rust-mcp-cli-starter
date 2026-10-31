//! Shared helpers and result types for MCP tool handlers.

use myapp_core::Error;
use myapp_core::pagination::Page;
use schemars::JsonSchema;
use serde::Serialize;

/// Formats a core [`Error`] as a tool-call error string.
///
/// A 404 gets a hint to look the id up with the matching list tool; every
/// other error uses [`Error::public_message`], so tool errors never expose
/// upstream bodies, URLs, or decoder internals to the model.
pub(crate) fn format_tool_error(error: &Error) -> String {
    if error.is_not_found() {
        return "not found (404): verify the id - use the corresponding list tool to find valid ids"
            .to_string();
    }
    error.public_message().into_owned()
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

    const SENTINEL: &str = "sentinel-secret";

    #[test]
    fn unpaginated_items_omit_the_page_fields() {
        let items = Items::new(vec![1, 2, 3]);
        assert_eq!(
            serde_json::to_value(items).unwrap(),
            json!({ "items": [1, 2, 3], "count": 3 })
        );
    }

    #[test]
    fn tool_error_is_the_public_message_with_a_404_hint() {
        let not_found = format_tool_error(&Error::api(404, ""));
        assert!(
            not_found.contains("list tool"),
            "expected a hint: {not_found}"
        );

        let source = serde_json::from_str::<String>("{")
            .expect_err("malformed JSON creates a decoder error");
        for (error, expected) in [
            (
                Error::api(
                    200,
                    &format!("http://application:9696/api?apikey={SENTINEL}"),
                ),
                "the upstream server returned an unexpected response",
            ),
            (
                Error::Deserialization {
                    endpoint: format!("/api/token/{SENTINEL}"),
                    source: source.into(),
                },
                "the upstream server returned an unexpected response",
            ),
            (
                Error::api(500, &format!("raw body containing {SENTINEL}")),
                "upstream API request failed with status 500",
            ),
        ] {
            let message = format_tool_error(&error);
            assert_eq!(message, error.public_message());
            assert_eq!(message, expected);
            assert!(!message.contains(SENTINEL), "leaked: {message}");
        }
    }
}
