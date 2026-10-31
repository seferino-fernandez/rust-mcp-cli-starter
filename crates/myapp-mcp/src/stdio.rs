//! Stdio transport: serves the MCP tools over stdin and stdout.

use rmcp::ServiceExt;

use crate::config::ServerConfig;
use crate::shared::create_api_client;
use crate::tools::AppTools;

/// Serves the MCP server over stdio.
pub async fn serve(config: &ServerConfig) -> anyhow::Result<()> {
    let api_client = create_api_client(config)?;
    let tools = AppTools::new(api_client, config.mcp.max_response_bytes)
        .with_confirm_destructive(config.mcp.confirm_destructive);
    let service = tools.serve(rmcp::transport::io::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
