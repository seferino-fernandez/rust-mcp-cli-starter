//! [`AppTools`]: the rmcp tool handler. Owns the API client and routes tool
//! calls through the combined `tool_router`.

use rmcp::handler::server::tool::ToolRouter;

use myapp_core::ApiClient;

/// MCP tool handler for the MYAPP API.
///
/// Cheap to clone (`ApiClient` is `Arc`-backed internally).
#[derive(Clone)]
pub struct AppTools {
    pub(super) client: ApiClient,
    pub tool_router: ToolRouter<Self>,
    /// Maximum serialized size (bytes) of a tool result before it is replaced
    /// with a bounded `response_too_large` error.
    pub(super) max_response_bytes: usize,
}

impl AppTools {
    /// Builds a handler around an already-constructed client.
    ///
    /// `max_response_bytes` caps the serialized size of each tool result; see
    /// [`McpConfig::max_response_bytes`](crate::config::McpConfig).
    pub fn new(client: ApiClient, max_response_bytes: usize) -> Self {
        Self {
            client,
            tool_router: Self::item_router(),
            max_response_bytes,
        }
    }
}
