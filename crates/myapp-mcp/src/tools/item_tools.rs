//! Example MCP tools mirroring the core endpoint methods.

use rmcp::{
    handler::server::wrapper::{Json, Parameters},
    tool, tool_router,
};

use super::handler::AppTools;
use super::params::{CreateItemParams, ItemIdParams, ListItemsParams};
use super::types::{DeleteResult, ListItemsResult, format_tool_error};
use myapp_core::models::{Item, NewItem, SystemStatus};

#[tool_router(router = item_router, vis = "pub(super)")]
impl AppTools {
    #[tool(
        name = "get_system_status",
        description = "Get server health/status",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_system_status(&self) -> Result<Json<SystemStatus>, String> {
        let status = self
            .client
            .system_status()
            .await
            .map_err(|error| format_tool_error(&error))?;
        Ok(Json(status))
    }

    #[tool(
        name = "list_items",
        description = "List items (paginated)",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_items(
        &self,
        Parameters(params): Parameters<ListItemsParams>,
    ) -> Result<Json<ListItemsResult>, String> {
        let page = self
            .client
            .list_items(params.page, params.page_size)
            .await
            .map_err(|error| format_tool_error(&error))?;
        Ok(Json(ListItemsResult {
            items: page.records,
            page: page.page,
            page_size: page.page_size,
            total_records: page.total_records,
        }))
    }

    #[tool(
        name = "get_item",
        description = "Get a single item by id",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_item(
        &self,
        Parameters(params): Parameters<ItemIdParams>,
    ) -> Result<Json<Item>, String> {
        let item = self
            .client
            .get_item(params.id)
            .await
            .map_err(|error| format_tool_error(&error))?;
        Ok(Json(item))
    }

    #[tool(
        name = "create_item",
        description = "Create an item",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn create_item(
        &self,
        Parameters(params): Parameters<CreateItemParams>,
    ) -> Result<Json<Item>, String> {
        let item = self
            .client
            .create_item(&NewItem {
                name: params.name,
                enabled: params.enabled,
            })
            .await
            .map_err(|error| format_tool_error(&error))?;
        Ok(Json(item))
    }

    #[tool(
        name = "delete_item",
        description = "Delete an item by id",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn delete_item(
        &self,
        Parameters(params): Parameters<ItemIdParams>,
    ) -> Result<Json<DeleteResult>, String> {
        self.client
            .delete_item(params.id)
            .await
            .map_err(|error| format_tool_error(&error))?;
        Ok(Json(DeleteResult {
            deleted: true,
            id: params.id,
        }))
    }
}
