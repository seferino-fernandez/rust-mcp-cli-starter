//! The one test harness for calling MCP tools.
//!
//! Every tool test calls through [`ServerHandler::call_tool`], the path a real
//! request takes, so argument checks, destructive-tool
//! confirmation and the response budget apply exactly as they do in
//! production.

use super::handler::AppTools;
// template:begin oauth
use crate::auth::Scopes;
// template:end oauth
use myapp_core::{ApiClient, Config, SecretString};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ClientCapabilities, JsonObject,
    NumberOrString, ProtocolVersion,
};
use rmcp::service::{RequestContext, serve_directly};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde_json::Value;
use wiremock::MockServer;

/// The production default response budget, 1 MiB.
const DEFAULT_RESPONSE_BYTES: usize = 1024 * 1024;

/// The API key every test client sends as `X-Api-Key`.
pub(crate) const TEST_API_KEY: &str = "test-key";

/// How a request was authenticated, as the tool handler sees it.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Caller {
    /// A local client using standard input and output.
    Stdio,
    // template:begin http
    /// The static-token and `none` HTTP modes: request parts without scopes.
    UnrestrictedHttp,
    // template:end http
    // template:begin oauth
    /// An OAuth access token granted these scopes. Names that are not a
    /// recognised scope are dropped, as the OAuth middleware drops them.
    OAuth(&'static [&'static str]),
    // template:end oauth
}

/// Tools talking to the upstream mocked by `server`, with API key
/// [`TEST_API_KEY`], the 1 MiB budget and confirmation on: the production
/// defaults.
pub(crate) fn tools_for(server: &MockServer) -> AppTools {
    tools_with_budget(server, DEFAULT_RESPONSE_BYTES)
}

/// [`tools_for`] with a response budget of `max_response_bytes`.
pub(crate) fn tools_with_budget(server: &MockServer, max_response_bytes: usize) -> AppTools {
    tools_at(server.uri(), max_response_bytes)
}

/// Tools talking to the upstream at `base_url`. Building them performs no
/// I/O, so tests that never call a tool can pass any URL, such as
/// `Config::default().base_url`.
pub(crate) fn tools_at(base_url: String, max_response_bytes: usize) -> AppTools {
    let client = ApiClient::new(Config {
        base_url,
        api_key: Some(SecretString::from(TEST_API_KEY)),
        ..Config::default()
    })
    .expect("test client builds");
    AppTools::new(client, max_response_bytes)
}

/// A request context for the selected caller. Confirmation is skipped unless
/// [`confirmable`] marks it. The connection serving the peer closes on return.
pub(crate) fn context(tools: &AppTools, _caller: Caller) -> RequestContext<RoleServer> {
    let (server_transport, _client_transport) = tokio::io::duplex(4096);
    let running = serve_directly::<RoleServer, _, _, _, _>(tools.clone(), server_transport, None);
    let extensions = rmcp::model::Extensions::default();
    // template:begin http
    let extensions = with_request_parts(extensions, _caller);
    // template:end http
    let mut context = RequestContext::new(NumberOrString::Number(1), running.peer().clone());
    context.extensions = extensions;
    context
}

// template:begin http
fn with_request_parts(
    mut extensions: rmcp::model::Extensions,
    caller: Caller,
) -> rmcp::model::Extensions {
    if matches!(caller, Caller::Stdio) {
        return extensions;
    }
    let (parts, ()) = axum::http::Request::new(()).into_parts();
    // template:begin oauth
    let parts = {
        let mut parts = parts;
        if let Caller::OAuth(scopes) = caller {
            parts.extensions.insert(Scopes::parse(scopes));
        }
        parts
    };
    // template:end oauth
    extensions.insert(parts);
    extensions
}
// template:end http

/// Marks `context` as coming from a client that can answer a confirmation:
/// protocol 2026-07-28 with form elicitation.
pub(crate) fn confirmable(mut context: RequestContext<RoleServer>) -> RequestContext<RoleServer> {
    context
        .meta
        .set_protocol_version(ProtocolVersion::V_2026_07_28);
    context
        .meta
        .set_client_capabilities(ClientCapabilities::builder().enable_elicitation().build());
    context
}

/// `arguments` as the object a tool call carries.
pub(crate) fn arguments(arguments: Value) -> JsonObject {
    arguments
        .as_object()
        .expect("tool arguments are an object")
        .clone()
}

/// Calls tool `name` as `caller` through [`ServerHandler::call_tool`].
pub(crate) async fn call(
    tools: &AppTools,
    caller: Caller,
    name: &str,
    arguments: Value,
) -> Result<CallToolResponse, McpError> {
    ServerHandler::call_tool(
        tools,
        CallToolRequestParams::new(name.to_string()).with_arguments(self::arguments(arguments)),
        context(tools, caller),
    )
    .await
}

/// Calls tool `name` over stdio and returns its result, panicking on a
/// protocol error or a response that is not complete.
pub(crate) async fn call_tool(tools: &AppTools, name: &str, arguments: Value) -> CallToolResult {
    complete(call(tools, Caller::Stdio, name, arguments).await)
}

/// The result a [`call`] completed with, panicking on a protocol error or a
/// response that is not complete.
pub(crate) fn complete(response: Result<CallToolResponse, McpError>) -> CallToolResult {
    match response.unwrap_or_else(|error| panic!("tools/call is answered: {error:?}")) {
        CallToolResponse::Complete(result) => result,
        other => panic!("expected a complete response, got {other:?}"),
    }
}

/// The structured content of a successful tool result.
pub(crate) fn structured(result: CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "tool call failed: {result:?}");
    result
        .structured_content
        .expect("typed tools return structured content")
}

/// The text of a result's first content block.
pub(crate) fn first_text(result: &CallToolResult) -> &str {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map_or("", |text| text.text.as_str())
}

/// Asserts that `server` received no request at all.
pub(crate) async fn assert_no_requests(server: &MockServer) {
    let requests = server
        .received_requests()
        .await
        .expect("request recording is on");
    assert!(
        requests.is_empty(),
        "expected no upstream request, got {requests:?}"
    );
}

mod tests {
    use super::{call_tool, first_text, tools_with_budget};
    // template:begin oauth
    use super::{Caller, call, tools_for};
    use rmcp::model::CallToolResponse;
    // template:end oauth
    use serde_json::{Value, json};
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn harness_call_tool_applies_the_response_budget() {
        let server = MockServer::start().await;
        let records: Vec<Value> = (1..=20)
            .map(|id| json!({ "id": id, "name": format!("item-{id}"), "enabled": true }))
            .collect();
        Mock::given(method("GET"))
            .and(path("/api/v3/item"))
            .and(query_param("page", "1"))
            .and(query_param("pageSize", "20"))
            .and(header("X-Api-Key", super::TEST_API_KEY))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "page": 1, "pageSize": 20, "totalRecords": 20, "records": records
            })))
            .expect(1)
            .mount(&server)
            .await;
        let tools = tools_with_budget(&server, 300);

        let result = call_tool(&tools, "myapp_list_items", json!({})).await;

        let body: Value =
            serde_json::from_str(first_text(&result)).expect("the guard text is JSON");
        assert_eq!(body["error"], "response_too_large", "{body}");
        assert_eq!(body["limit"], 300, "{body}");
    }

    // template:begin oauth
    #[tokio::test]
    async fn harness_call_enforces_scopes() {
        let server = MockServer::start().await;
        let tools = tools_for(&server);

        let response = call(
            &tools,
            Caller::OAuth(&["read"]),
            "myapp_delete_item",
            json!({ "id": 7 }),
        )
        .await
        .expect("tools/call is answered");

        let CallToolResponse::Complete(result) = response else {
            panic!("expected an insufficient_scope result, got {response:?}");
        };
        assert_eq!(result.is_error, Some(true), "{result:?}");
        assert_eq!(
            first_text(&result),
            "insufficient_scope: tool 'myapp_delete_item' requires the 'write' scope"
        );
        super::assert_no_requests(&server).await;
    }
    // template:end oauth
}
