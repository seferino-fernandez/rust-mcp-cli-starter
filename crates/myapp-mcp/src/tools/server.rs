use std::sync::Arc;

use rmcp::handler::server::tool::ToolCallContext;
use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, Implementation, PaginatedRequestParams,
    ProtocolVersion, ServerCapabilities, Tool,
};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{ListToolsResult, ServerInfo},
    service::RequestContext,
};

use super::handler::AppTools;
use super::schema::{close_object_map, enforce_response_budget};

/// Hardens a tool's advertised schemas in place: closes the input schema and,
/// when present, the output schema (sets `additionalProperties: false` and an
/// explicit `required` on every object node). Shared by `list_tools` and
/// `get_tool` so the advertised and argument-validated schemas always match.
fn close_tool_schemas(tool: &mut Tool) {
    close_object_map(Arc::make_mut(&mut tool.input_schema));
    if let Some(output) = tool.output_schema.as_mut() {
        close_object_map(Arc::make_mut(output));
    }
}

impl ServerHandler for AppTools {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        // `ProtocolVersion::LATEST` still resolves to 2025-11-25
        // in rmcp 3.0 and will move in a later release.
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
            .with_description(env!("CARGO_PKG_DESCRIPTION"));
        info.instructions = Some(include_str!("instructions.md").to_string());
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = self.tool_router.list_all();
        for tool in &mut tools {
            close_tool_schemas(tool);
        }

        Ok(ListToolsResult::with_all_items(tools)
            .with_ttl_ms(300_000)
            .with_cache_scope(CacheScope::Private))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        tracing::info!(tool = %request.name, "call_tool");
        let tool_call_context = ToolCallContext::new(self, request, context);
        Ok(match self.tool_router.call(tool_call_context).await? {
            CallToolResponse::Complete(result) => {
                enforce_response_budget(result, self.max_response_bytes).into()
            }
            other => other,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        let mut tool = self.tool_router.get(name).cloned()?;
        close_tool_schemas(&mut tool);
        Some(tool)
    }
}
