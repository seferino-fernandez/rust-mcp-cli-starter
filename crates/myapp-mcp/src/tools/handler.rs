//! [`AppTools`]: the rmcp tool handler. Owns the API client and routes tool
//! calls through the combined tool router, built once per process.

use std::ops::Deref;
use std::sync::Arc;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::Tool;

use myapp_core::ApiClient;

use super::server::close_tool_schemas;

/// MCP tool handler for the MYAPP API.
///
/// A cheap handle: cloning it bumps one reference count, so every HTTP request
/// shares the client, the tool router and the advertised tools built by
/// [`AppTools::new`].
#[derive(Clone)]
pub struct AppTools(Arc<Inner>);

/// The state every [`AppTools`] handle shares.
#[derive(Clone)]
pub struct Inner {
    pub(super) client: ApiClient,
    /// Every tool route, with its input and output schemas already closed.
    pub(super) router: ToolRouter<AppTools>,
    /// The tools `tools/list` advertises: the router's tools, sorted by name.
    /// They share their schemas with the router.
    pub(super) advertised: Vec<Tool>,
    /// Maximum exact serialized size (bytes) of a tool result before it is
    /// replaced with a bounded `response_too_large` result or, when the limit
    /// cannot hold that diagnostic, a protocol error.
    pub(super) max_response_bytes: usize,
    /// Whether destructive tools ask capable clients for confirmation first.
    pub(crate) confirm_destructive: bool,
    /// Whether every call must carry OAuth [`Scopes`](crate::auth::Scopes).
    /// Set when the HTTP transport authenticates with OAuth, so a request
    /// that somehow reaches a tool without them is limited to read-only
    /// tools rather than allowed everything.
    pub(crate) require_scopes: bool,
}

impl AppTools {
    /// Builds a handler around an already-constructed client, with
    /// destructive-tool confirmation on and OAuth scopes not required.
    ///
    /// Combines every tool router and closes each tool's schemas once, so
    /// requests never rebuild routes or copy schemas. Build once per server
    /// and clone the result.
    ///
    /// `max_response_bytes` caps the serialized size of each tool result; see
    /// [`McpConfig::max_response_bytes`](crate::config::McpConfig).
    pub fn new(client: ApiClient, max_response_bytes: usize) -> Self {
        let mut router = Self::item_router();
        for route in router.map.values_mut() {
            close_tool_schemas(&mut route.attr);
        }
        let advertised = router.list_all();
        Self(Arc::new(Inner {
            client,
            router,
            advertised,
            max_response_bytes,
            confirm_destructive: true,
            require_scopes: false,
        }))
    }

    /// Enables or disables confirmation of destructive tools; see
    /// [`McpConfig::confirm_destructive`](crate::config::McpConfig).
    #[must_use]
    pub fn with_confirm_destructive(mut self, enabled: bool) -> Self {
        // Unshared right after `new`, so this updates in place.
        Arc::make_mut(&mut self.0).confirm_destructive = enabled;
        self
    }

    /// Requires OAuth scopes on every call, failing closed to read-only tools
    /// when a request carries none. Set for the HTTP transport's OAuth mode;
    /// stdio and the `token` and `none` modes leave it off.
    #[must_use]
    pub fn with_require_scopes(mut self, required: bool) -> Self {
        Arc::make_mut(&mut self.0).require_scopes = required;
        self
    }

    /// The shared tool router, schemas already closed.
    #[cfg(test)]
    pub(crate) fn router(&self) -> &ToolRouter<Self> {
        &self.0.router
    }

    /// Whether `self` and `other` share one [`Inner`].
    #[cfg(test)]
    pub(crate) fn shares_state_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Deref for AppTools {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}
