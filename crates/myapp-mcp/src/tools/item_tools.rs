//! Example MCP tools mirroring the core endpoint methods.
//!
//! Every tool name carries the `myapp_` prefix, so a client running several
//! MCP servers can tell this server's tools apart.

use rmcp::{
    handler::server::wrapper::{Json, Parameters},
    tool, tool_router,
};

use super::handler::AppTools;
use super::params::{CreateItemParams, ItemIdParams, ListItemsParams};
use super::types::{DeleteResult, Items, format_tool_error};
use myapp_core::models::{Item, NewItem, SystemStatus};

#[tool_router(router = item_router, vis = "pub(super)")]
impl AppTools {
    #[tool(
        name = "myapp_get_system_status",
        description = "Get server health/status",
        annotations(
            title = "Get system status",
            read_only_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
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
        name = "myapp_list_items",
        description = "List items (paginated)",
        annotations(
            title = "List items",
            read_only_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn list_items(
        &self,
        Parameters(params): Parameters<ListItemsParams>,
    ) -> Result<Json<Items<Item>>, String> {
        let page = self
            .client
            .list_items(params.page, params.page_size)
            .await
            .map_err(|error| format_tool_error(&error))?;
        Ok(Json(page.into()))
    }

    #[tool(
        name = "myapp_get_item",
        description = "Get a single item by id",
        annotations(
            title = "Get item",
            read_only_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
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
        name = "myapp_create_item",
        description = "Create an item",
        annotations(
            title = "Create item",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
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
        name = "myapp_delete_item",
        description = "Delete an item by id",
        annotations(
            title = "Delete item",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
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

/// Each tool's exact upstream request and its structured result, called
/// through [`ServerHandler::call_tool`](rmcp::ServerHandler::call_tool) over
/// stdio.
#[cfg(test)]
mod tests {
    use crate::tools::test_support::{TEST_API_KEY, call_tool, first_text, structured, tools_for};
    use serde_json::{Value, json};
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    /// The one request `server` received.
    async fn only_request(server: &MockServer) -> Request {
        let mut requests = server
            .received_requests()
            .await
            .expect("request recording is on");
        assert_eq!(requests.len(), 1, "{requests:?}");
        requests.remove(0)
    }

    /// Asserts `request` is exactly `verb path_and_query` with the API key and,
    /// when `body` is `Some`, that JSON body (else an empty body).
    fn assert_request(request: &Request, verb: &str, path_and_query: &str, body: Option<Value>) {
        assert_eq!(request.method.as_str(), verb);
        let target = match request.url.query() {
            Some(query) => format!("{}?{query}", request.url.path()),
            None => request.url.path().to_string(),
        };
        assert_eq!(target, path_and_query);
        assert_eq!(
            request
                .headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok()),
            Some(TEST_API_KEY)
        );
        match body {
            Some(expected) => assert_eq!(
                serde_json::from_slice::<Value>(&request.body).expect("body is JSON"),
                expected
            ),
            None => assert!(request.body.is_empty(), "{:?}", request.body),
        }
    }

    #[tokio::test]
    async fn get_system_status_gets_the_status_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/system/status"))
            .and(header("X-Api-Key", TEST_API_KEY))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "appName": "MyApp", "version": "1.2.3" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let tools = tools_for(&server);

        let result = call_tool(&tools, "myapp_get_system_status", json!({})).await;

        assert_eq!(
            structured(result),
            json!({ "appName": "MyApp", "version": "1.2.3" })
        );
        assert_request(
            &only_request(&server).await,
            "GET",
            "/api/v3/system/status",
            None,
        );
    }

    #[tokio::test]
    async fn list_items_sends_the_page_and_returns_items_with_totals() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/item"))
            .and(query_param("page", "3"))
            .and(query_param("pageSize", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "page": 3,
                "pageSize": 2,
                "totalRecords": 6,
                "records": [
                    { "id": 5, "name": "five", "enabled": true },
                    { "id": 6, "name": "six", "enabled": false }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let tools = tools_for(&server);

        let result = call_tool(
            &tools,
            "myapp_list_items",
            json!({ "page": 3, "page_size": 2 }),
        )
        .await;

        assert_eq!(
            structured(result),
            json!({
                "items": [
                    { "id": 5, "name": "five", "enabled": true },
                    { "id": 6, "name": "six", "enabled": false }
                ],
                "count": 2,
                "page": 3,
                "page_size": 2,
                "total_records": 6
            })
        );
        assert_request(
            &only_request(&server).await,
            "GET",
            "/api/v3/item?page=3&pageSize=2",
            None,
        );
    }

    #[tokio::test]
    async fn list_items_defaults_to_the_first_page_of_twenty() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/item"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "page": 1, "pageSize": 20, "totalRecords": 0, "records": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let tools = tools_for(&server);

        let result = call_tool(&tools, "myapp_list_items", json!({})).await;

        assert_eq!(structured(result)["count"], 0);
        assert_request(
            &only_request(&server).await,
            "GET",
            "/api/v3/item?page=1&pageSize=20",
            None,
        );
    }

    #[tokio::test]
    async fn get_item_gets_the_item_by_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/item/42"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "id": 42, "name": "answer", "enabled": true })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let tools = tools_for(&server);

        let result = call_tool(&tools, "myapp_get_item", json!({ "id": 42 })).await;

        assert_eq!(
            structured(result),
            json!({ "id": 42, "name": "answer", "enabled": true })
        );
        assert_request(&only_request(&server).await, "GET", "/api/v3/item/42", None);
    }

    #[tokio::test]
    async fn get_item_404_points_at_the_list_tool() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/item/9"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        let tools = tools_for(&server);

        let result = call_tool(&tools, "myapp_get_item", json!({ "id": 9 })).await;

        assert_eq!(result.is_error, Some(true), "{result:?}");
        assert!(first_text(&result).contains("list tool"), "{result:?}");
    }

    #[tokio::test]
    async fn create_item_posts_the_new_item() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v3/item"))
            .and(body_json(json!({ "name": "new", "enabled": true })))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!({ "id": 7, "name": "new", "enabled": true })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let tools = tools_for(&server);

        let result = call_tool(
            &tools,
            "myapp_create_item",
            json!({ "name": "new", "enabled": true }),
        )
        .await;

        assert_eq!(
            structured(result),
            json!({ "id": 7, "name": "new", "enabled": true })
        );
        assert_request(
            &only_request(&server).await,
            "POST",
            "/api/v3/item",
            Some(json!({ "name": "new", "enabled": true })),
        );
    }

    #[tokio::test]
    async fn create_item_defaults_to_disabled() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v3/item"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!({ "id": 8, "name": "off", "enabled": false })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let tools = tools_for(&server);

        call_tool(&tools, "myapp_create_item", json!({ "name": "off" })).await;

        assert_request(
            &only_request(&server).await,
            "POST",
            "/api/v3/item",
            Some(json!({ "name": "off", "enabled": false })),
        );
    }

    /// Over stdio no protocol version is negotiated, so the destructive tool
    /// runs without a confirmation round.
    #[tokio::test]
    async fn delete_item_deletes_the_item_by_id() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v3/item/7"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let tools = tools_for(&server);

        let result = call_tool(&tools, "myapp_delete_item", json!({ "id": 7 })).await;

        assert_eq!(structured(result), json!({ "deleted": true, "id": 7 }));
        assert_request(
            &only_request(&server).await,
            "DELETE",
            "/api/v3/item/7",
            None,
        );
    }
}
