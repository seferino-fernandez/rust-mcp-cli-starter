use std::sync::Arc;

use rmcp::handler::server::tool::ToolCallContext;
use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
    Implementation, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, Tool,
};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{ListToolsResult, ServerConfig},
    service::RequestContext,
};
use serde_json::{Map, Value};

use super::handler::AppTools;
use super::schema::{close_object_map, enforce_response_budget};
use super::{confirm, params, scope};

/// Hardens a tool's advertised schemas in place: closes the input schema and,
/// when present, the output schema (sets `additionalProperties: false` and an
/// explicit `required` on every object node). Called once per tool by
/// [`AppTools::new`], so `list_tools`, `get_tool` and `call_tool` all read the
/// same closed schemas.
pub(super) fn close_tool_schemas(tool: &mut Tool) {
    close_object_map(Arc::make_mut(&mut tool.input_schema));
    if let Some(output) = tool.output_schema.as_mut() {
        close_object_map(Arc::make_mut(output));
    }
}

/// The properties a tool's input schema declares; empty for a tool that
/// takes no arguments.
fn declared_properties(tool: &Tool) -> Option<&Map<String, Value>> {
    tool.input_schema
        .get("properties")
        .and_then(Value::as_object)
}

/// Rejects a call that sends a top-level argument key the tool's input schema
/// does not declare, including any key at all for a tool that takes none.
///
/// rmcp never deserializes the arguments of a tool without a params type, so
/// `deny_unknown_fields` cannot catch a stray key there. For the others, rmcp
/// deserializes only when the tool runs, after the confirmation step, so
/// without this check a stray key on a destructive tool would prompt before
/// being rejected. The check is top-level only, which is enough while no tool
/// that requires confirmation takes a nested params object (pinned by a
/// schema test).
///
/// The result matches rmcp's own params deserialization failure: a tool error
/// whose text is `failed to deserialize parameters: ` plus serde's
/// unknown-field message. The expected fields are listed in schema order,
/// which may differ from serde's declaration order.
fn undeclared_argument_rejection(
    tool: &Tool,
    request: &CallToolRequestParams,
) -> Option<CallToolResult> {
    let declared = declared_properties(tool);
    let key = request
        .arguments
        .as_ref()?
        .keys()
        .find(|key| declared.is_none_or(|properties| !properties.contains_key(*key)))?;
    let expected: Vec<&String> = declared.into_iter().flat_map(Map::keys).collect();
    let expected = match expected.as_slice() {
        [] => "there are no fields".to_owned(),
        [only] => format!("expected `{only}`"),
        [first, second] => format!("expected `{first}` or `{second}`"),
        fields => {
            let fields: Vec<String> = fields.iter().map(|field| format!("`{field}`")).collect();
            format!("expected one of {}", fields.join(", "))
        }
    };
    Some(CallToolResult::error(vec![ContentBlock::text(format!(
        "failed to deserialize parameters: unknown field `{key}`, {expected}"
    ))]))
}

impl ServerHandler for AppTools {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::default();
        // Named explicitly rather than taken from `ProtocolVersion::LATEST`,
        // which follows the SDK and may move past what this server implements.
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
            .with_description(env!("CARGO_PKG_DESCRIPTION"));
        info.instructions = Some(include_str!("instructions.md").to_string());
        info
    }

    /// Advertises every tool to every caller. OAuth scopes restrict calls,
    /// not the list, so a `read` token sees the same tools as a `write` one.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.advertised.clone())
            .with_ttl_ms(300_000)
            .with_cache_scope(CacheScope::Private))
    }

    /// Runs a tool call through, in order: the OAuth scope check, the
    /// argument check, destructive-tool confirmation (after decoding the
    /// params, so a mistyped argument fails before the user is asked), the
    /// tool itself and the response budget. An unknown tool name skips the
    /// checks and gets the router's own error.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        tracing::info!(tool = %request.name, "call_tool");
        if let Some(tool) = self.router.get(&request.name) {
            if !scope::permits(&context, tool, self.require_scopes) {
                tracing::warn!(tool = %request.name, "call_tool: token lacks the write scope");
                return Ok(scope::insufficient_scope(&request.name).into());
            }
            if let Some(rejection) = undeclared_argument_rejection(tool, &request) {
                return Ok(rejection.into());
            }
            if self.confirm_destructive
                && confirm::requires_confirmation(tool)
                && confirm::client_supports_confirmation(&context)
            {
                if let Some(rejection) =
                    params::params_rejection(&request.name, request.arguments.as_ref())
                {
                    return Ok(rejection.into());
                }
                match request.request_state.as_deref() {
                    None => return Ok(confirm::confirmation_request(&request)?.into()),
                    Some(sealed) => {
                        if let confirm::Verdict::Declined(reason) = confirm::verify_confirmation(
                            sealed,
                            &request,
                            &self.consumed_confirmations,
                        )? {
                            return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                                "confirmation_declined: {reason}"
                            ))])
                            .into());
                        }
                    }
                }
            }
        }
        let tool_call_context = ToolCallContext::new(self, request, context);
        Ok(match self.router.call(tool_call_context).await? {
            CallToolResponse::Complete(result) => {
                enforce_response_budget(result, self.max_response_bytes)?.into()
            }
            other => other,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.router.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::AppTools;
    use crate::tools::test_support::{
        Caller, arguments as call_arguments, assert_no_requests, call, complete, confirmable,
        context, first_text, tools_at, tools_for, tools_with_budget,
    };
    use myapp_core::Config;
    use rmcp::model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ClientCapabilities,
        ElicitationCapability, ProtocolVersion, Tool, UrlElicitationCapability,
    };
    use rmcp::service::RequestContext;
    use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use wiremock::matchers::{any, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const READ: &[&str] = &["read"];
    const WRITE: &[&str] = &["write"];
    const READ_WRITE: &[&str] = &["read", "write"];

    /// A valid call for every tool, so a check that wrongly refuses a valid
    /// call cannot pass for one that refuses an invalid one.
    const VALID_CALLS: [(&str, &str); 5] = [
        ("myapp_create_item", r#"{"name":"new"}"#),
        ("myapp_delete_item", r#"{"id":7}"#),
        ("myapp_get_item", r#"{"id":7}"#),
        ("myapp_get_system_status", "{}"),
        ("myapp_list_items", "{}"),
    ];

    fn valid_arguments(name: &str) -> Value {
        let (_, raw) = VALID_CALLS
            .iter()
            .find(|(tool, _)| *tool == name)
            .unwrap_or_else(|| panic!("no valid call for {name}"));
        serde_json::from_str(raw).unwrap()
    }

    /// An upstream that answers every request the example tools make.
    async fn upstream() -> MockServer {
        let server = MockServer::start().await;
        let item = json!({ "id": 7, "name": "new", "enabled": false });
        for (verb, route, status, body) in [
            (
                "GET",
                "/api/v3/system/status",
                200,
                json!({ "appName": "MyApp", "version": "1" }),
            ),
            (
                "GET",
                "/api/v3/item",
                200,
                json!({ "page": 1, "pageSize": 20, "totalRecords": 0, "records": [] }),
            ),
            ("GET", "/api/v3/item/7", 200, item.clone()),
            ("POST", "/api/v3/item", 201, item),
        ] {
            Mock::given(method(verb))
                .and(path(route))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .mount(&server)
                .await;
        }
        Mock::given(method("DELETE"))
            .and(path("/api/v3/item/7"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        server
    }

    /// An upstream that fails the test if any request reaches it.
    async fn untouched_upstream() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        server
    }

    async fn request_count(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .expect("request recording is on")
            .len()
    }

    async fn listed_tools(tools: &AppTools, caller: Caller) -> Vec<Tool> {
        ServerHandler::list_tools(tools, None, context(tools, caller))
            .await
            .expect("tools/list succeeds")
            .tools
    }

    fn all_tool_names(tools: &AppTools) -> Vec<String> {
        tools
            .router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect()
    }

    fn is_read_only(tool: &Tool) -> bool {
        tool.annotations
            .as_ref()
            .and_then(|annotations| annotations.read_only_hint)
            == Some(true)
    }

    fn assert_refused(result: &CallToolResult, name: &str) {
        assert_eq!(result.is_error, Some(true), "{result:?}");
        assert_eq!(
            first_text(result),
            format!("insufficient_scope: tool '{name}' requires the 'write' scope"),
        );
    }

    fn assert_succeeded(result: &CallToolResult, label: &str) {
        assert_ne!(result.is_error, Some(true), "{label}: {result:?}");
        assert!(
            !first_text(result).starts_with("insufficient_scope"),
            "{label}"
        );
    }

    /// `name` called with `arguments` through `context`.
    async fn call_in(
        tools: &AppTools,
        name: &str,
        arguments: Value,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        ServerHandler::call_tool(
            tools,
            CallToolRequestParams::new(name.to_string()).with_arguments(call_arguments(arguments)),
            context,
        )
        .await
    }

    // ---- Unknown arguments ----

    /// Every listed tool rejects an argument key its input schema does not
    /// declare, before any request reaches the upstream, both for a client
    /// that could confirm (so a confirmation prompt cannot stand in for the
    /// error) and over stdio. The list comes from `tools/list`, so a new tool
    /// whose params accept unknown keys fails here without this test being
    /// edited.
    #[tokio::test]
    async fn every_listed_tool_rejects_an_unknown_key_without_contacting_the_upstream() {
        let server = untouched_upstream().await;
        let tools = tools_for(&server);
        let listed = listed_tools(&tools, Caller::Stdio).await;
        assert_eq!(listed.len(), VALID_CALLS.len());

        for tool in &listed {
            let name = tool.name.as_ref();
            let mut arguments = valid_arguments(name);
            arguments["unexpected_key"] = json!(true);
            for (label, context) in [
                ("stdio", context(&tools, Caller::Stdio)),
                ("confirmable", confirmable(context(&tools, Caller::Stdio))),
            ] {
                let result = complete(call_in(&tools, name, arguments.clone(), context).await);
                let text = first_text(&result);
                assert_eq!(result.is_error, Some(true), "{name} {label}: {result:?}");
                assert!(
                    text.starts_with("failed to deserialize parameters: ")
                        && text.contains("unknown field `unexpected_key`"),
                    "{name} {label}: {text}"
                );
            }
        }
        assert_no_requests(&server).await;
    }

    #[tokio::test]
    async fn zero_argument_tool_rejects_any_key_but_accepts_empty_or_absent_arguments() {
        let server = upstream().await;
        let tools = tools_for(&server);

        let result = complete(
            call(
                &tools,
                Caller::Stdio,
                "myapp_get_system_status",
                json!({ "foo": 1 }),
            )
            .await,
        );
        assert_eq!(
            first_text(&result),
            "failed to deserialize parameters: unknown field `foo`, there are no fields"
        );
        assert_no_requests(&server).await;

        let empty =
            complete(call(&tools, Caller::Stdio, "myapp_get_system_status", json!({})).await);
        let absent = complete(
            ServerHandler::call_tool(
                &tools,
                CallToolRequestParams::new("myapp_get_system_status"),
                context(&tools, Caller::Stdio),
            )
            .await,
        );
        assert_succeeded(&empty, "empty arguments");
        assert_succeeded(&absent, "absent arguments");
        assert_eq!(request_count(&server).await, 2);
    }

    #[tokio::test]
    async fn unknown_key_message_lists_the_declared_fields() {
        let server = untouched_upstream().await;
        let tools = tools_for(&server);

        for (name, arguments, expected) in [
            (
                "myapp_get_item",
                json!({ "id": 1, "ID": 1 }),
                "unknown field `ID`, expected `id`",
            ),
            (
                "myapp_list_items",
                json!({ "pageSize": 500 }),
                "unknown field `pageSize`, expected `page` or `page_size`",
            ),
        ] {
            let result = complete(call(&tools, Caller::Stdio, name, arguments).await);
            assert_eq!(
                first_text(&result),
                format!("failed to deserialize parameters: {expected}"),
                "{name}"
            );
        }
        assert_no_requests(&server).await;
    }

    // ---- OAuth scopes ----

    #[tokio::test]
    async fn read_scope_refuses_create_and_delete_without_contacting_the_upstream() {
        let server = untouched_upstream().await;
        let tools = tools_for(&server);

        for name in ["myapp_create_item", "myapp_delete_item"] {
            for scopes in [READ, &[][..], &["admin"][..]] {
                let result = complete(
                    call(&tools, Caller::OAuth(scopes), name, valid_arguments(name)).await,
                );
                assert_refused(&result, name);
            }
        }
        assert_no_requests(&server).await;
    }

    /// The scope check runs first: before the argument check, so a refused
    /// call learns nothing about the tool's parameters, and before
    /// confirmation, so a read token is never asked to confirm.
    #[tokio::test]
    async fn read_scope_refusal_comes_before_the_argument_check_and_confirmation() {
        let server = untouched_upstream().await;
        let tools = tools_for(&server);

        let bad_arguments = complete(
            call(
                &tools,
                Caller::OAuth(READ),
                "myapp_delete_item",
                json!({ "id": 7, "unexpected_key": 1 }),
            )
            .await,
        );
        assert_refused(&bad_arguments, "myapp_delete_item");

        let confirmable_read = complete(
            call_in(
                &tools,
                "myapp_delete_item",
                json!({ "id": 7 }),
                confirmable(context(&tools, Caller::OAuth(READ))),
            )
            .await,
        );
        assert_refused(&confirmable_read, "myapp_delete_item");
        assert_no_requests(&server).await;
    }

    #[tokio::test]
    async fn read_scope_is_allowed_every_read_only_tool() {
        let server = upstream().await;
        let tools = tools_for(&server);

        let mut reads = 0;
        for tool in tools
            .router()
            .list_all()
            .iter()
            .filter(|tool| is_read_only(tool))
        {
            let name = tool.name.as_ref();
            let result =
                complete(call(&tools, Caller::OAuth(READ), name, valid_arguments(name)).await);
            assert_succeeded(&result, name);
            reads += 1;
        }
        assert_eq!(reads, 3);
        assert_eq!(request_count(&server).await, 3);
    }

    #[tokio::test]
    async fn write_scope_and_callers_without_an_oauth_token_reach_every_tool() {
        for caller in [
            Caller::OAuth(WRITE),
            Caller::OAuth(READ_WRITE),
            Caller::NoOAuthToken,
            Caller::Stdio,
        ] {
            let server = upstream().await;
            let tools = tools_for(&server);
            for name in all_tool_names(&tools) {
                let result = complete(call(&tools, caller, &name, valid_arguments(&name)).await);
                assert_succeeded(&result, &format!("{name} as {caller:?}"));
            }
            assert_eq!(
                request_count(&server).await,
                VALID_CALLS.len(),
                "{caller:?}"
            );
        }
    }

    /// `tools/list` is the same for every caller: scopes restrict calls, not
    /// what the server advertises.
    #[tokio::test]
    async fn tools_list_is_identical_for_every_caller() {
        let server = untouched_upstream().await;
        let tools = tools_for(&server);
        let every_tool = listed_tools(&tools, Caller::Stdio).await;
        assert_eq!(every_tool.len(), VALID_CALLS.len());
        assert!(every_tool.iter().any(|tool| !is_read_only(tool)));

        for caller in [
            Caller::OAuth(READ),
            Caller::OAuth(WRITE),
            Caller::OAuth(READ_WRITE),
            Caller::OAuth(&[]),
            Caller::NoOAuthToken,
        ] {
            assert_eq!(listed_tools(&tools, caller).await, every_tool, "{caller:?}");
        }
    }

    /// Under OAuth the handler requires scopes, so a request that reaches it
    /// without them, with or without HTTP request parts, fails closed to the
    /// read-only tools. Without the requirement, the same requests reach
    /// every tool.
    #[tokio::test]
    async fn oauth_handler_without_scopes_is_limited_to_read_only_tools() {
        let server = upstream().await;
        let oauth = tools_for(&server).with_require_scopes(true);

        for caller in [Caller::NoOAuthToken, Caller::Stdio] {
            for tool in oauth.router().list_all() {
                let name = tool.name.as_ref();
                let result = complete(call(&oauth, caller, name, valid_arguments(name)).await);
                if is_read_only(&tool) {
                    assert_succeeded(&result, &format!("{name} as {caller:?}"));
                } else {
                    assert_refused(&result, name);
                }
            }
        }
        assert_eq!(request_count(&server).await, 2 * 3, "only the reads ran");

        let unrestricted = tools_for(&server);
        for name in ["myapp_create_item", "myapp_delete_item"] {
            let result = complete(
                call(
                    &unrestricted,
                    Caller::NoOAuthToken,
                    name,
                    valid_arguments(name),
                )
                .await,
            );
            assert_succeeded(&result, name);
        }
        assert_eq!(request_count(&server).await, 2 * 3 + 2);
    }

    #[tokio::test]
    async fn read_scope_leaves_the_unknown_tool_error_unchanged() {
        let server = untouched_upstream().await;
        let tools = tools_for(&server);

        let error = call(&tools, Caller::OAuth(READ), "myapp_no_such_tool", json!({}))
            .await
            .expect_err("an unknown tool is a protocol error");

        assert_eq!(error.message, "tool not found");
    }

    // ---- Destructive-tool confirmation ----

    /// The first round of a confirmable destructive call: its `requestState`,
    /// with nothing sent upstream.
    async fn first_round(tools: &AppTools, server: &MockServer, arguments: &Value) -> String {
        let response = call_in(
            tools,
            "myapp_delete_item",
            arguments.clone(),
            confirmable(context(tools, Caller::Stdio)),
        )
        .await
        .expect("first round succeeds");
        let CallToolResponse::InputRequired(result) = response else {
            panic!("expected an input-required response, got {response:?}");
        };
        let input_requests = result.input_requests.as_ref().expect("input requests");
        assert!(input_requests.contains_key("confirm"), "{input_requests:?}");
        assert_no_requests(server).await;
        result
            .request_state
            .expect("input-required result contains requestState")
    }

    /// The retry of a confirmation round with `state`, `arguments` and the
    /// elicitation `response`.
    async fn retry(
        tools: &AppTools,
        arguments: Value,
        state: String,
        response: Value,
    ) -> Result<CallToolResponse, McpError> {
        ServerHandler::call_tool(
            tools,
            CallToolRequestParams::new("myapp_delete_item")
                .with_arguments(call_arguments(arguments))
                .with_request_state(state)
                .with_input_responses(BTreeMap::from([("confirm".to_string(), response)])),
            confirmable(context(tools, Caller::Stdio)),
        )
        .await
    }

    #[tokio::test]
    async fn confirmed_destructive_tool_executes_upstream_once() {
        let server = upstream().await;
        let tools = tools_for(&server);
        let arguments = json!({ "id": 7 });

        let state = first_round(&tools, &server, &arguments).await;
        let result = complete(
            retry(
                &tools,
                arguments,
                state,
                json!({ "action": "accept", "content": { "confirm": true } }),
            )
            .await,
        );

        assert_succeeded(&result, "confirmed retry");
        assert_eq!(
            result.structured_content,
            Some(json!({ "deleted": true, "id": 7 }))
        );
        assert_eq!(request_count(&server).await, 1);
    }

    /// An accepted confirmation is spent: replaying it, even through another
    /// handle on the same handler, is refused and the upstream sees exactly
    /// one DELETE.
    #[tokio::test]
    async fn replayed_confirmation_runs_the_tool_once() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v3/item/7"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let tools = tools_for(&server);
        let arguments = json!({ "id": 7 });
        let accept = json!({ "action": "accept", "content": { "confirm": true } });

        let state = first_round(&tools, &server, &arguments).await;
        let first = complete(retry(&tools, arguments.clone(), state.clone(), accept.clone()).await);
        assert_succeeded(&first, "first confirmed retry");
        for handle in [tools.clone(), tools.clone().with_confirm_destructive(true)] {
            let replay = retry(&handle, arguments.clone(), state.clone(), accept.clone())
                .await
                .expect_err("a replayed confirmation is a protocol error");
            assert_eq!(
                replay.message,
                "confirmation already used; call the tool again"
            );
        }

        assert_eq!(request_count(&server).await, 1);
    }

    /// The params are decoded before the prompt, so a mistyped argument fails
    /// as rmcp would fail it, without asking the user or calling upstream.
    #[tokio::test]
    async fn mistyped_params_fail_before_the_confirmation_prompt() {
        let server = untouched_upstream().await;
        let tools = tools_for(&server);

        for arguments in [json!({ "id": "x" }), json!({})] {
            let response = call_in(
                &tools,
                "myapp_delete_item",
                arguments.clone(),
                confirmable(context(&tools, Caller::Stdio)),
            )
            .await
            .expect("tools/call is answered");
            let CallToolResponse::Complete(result) = response else {
                panic!("{arguments}: expected a tool error, not {response:?}");
            };
            assert_eq!(result.is_error, Some(true), "{arguments}: {result:?}");
            assert!(
                first_text(&result).starts_with("failed to deserialize parameters: "),
                "{arguments}: {result:?}"
            );
        }
        assert_no_requests(&server).await;
    }

    #[tokio::test]
    async fn declined_cancelled_or_unconfirmed_retries_are_refused_without_contacting_the_upstream()
    {
        let server = untouched_upstream().await;
        let tools = tools_for(&server);
        let arguments = json!({ "id": 7 });

        for (response, reason) in [
            (
                json!({ "action": "decline" }),
                "client returned the decline action",
            ),
            (
                json!({ "action": "cancel" }),
                "client returned the cancel action",
            ),
            (
                json!({ "action": "accept", "content": { "confirm": false } }),
                "accept response did not confirm the operation",
            ),
        ] {
            let state = first_round(&tools, &server, &arguments).await;
            let result = complete(retry(&tools, arguments.clone(), state, response).await);
            assert_eq!(result.is_error, Some(true), "{result:?}");
            assert_eq!(
                first_text(&result),
                format!("confirmation_declined: {reason}")
            );
        }
        assert_no_requests(&server).await;
    }

    #[tokio::test]
    async fn retry_with_changed_arguments_or_stale_state_is_refused() {
        let server = untouched_upstream().await;
        let tools = tools_for(&server);
        let accept = json!({ "action": "accept", "content": { "confirm": true } });

        let state = first_round(&tools, &server, &json!({ "id": 7 })).await;
        let changed = retry(&tools, json!({ "id": 8 }), state.clone(), accept.clone())
            .await
            .expect_err("changed arguments are a protocol error");
        assert_eq!(
            changed.message,
            "arguments changed between confirmation rounds"
        );

        let stale = retry(&tools, json!({ "id": 7 }), format!("{state}x"), accept)
            .await
            .expect_err("tampered state is a protocol error");
        assert_eq!(
            stale.message,
            "stale or invalid confirmation state; call the tool again"
        );
        assert_no_requests(&server).await;
    }

    /// Without form elicitation, on an older protocol, or with confirmation
    /// switched off, the destructive tool runs directly.
    #[tokio::test]
    async fn destructive_tool_runs_directly_when_confirmation_cannot_apply() {
        let server = upstream().await;
        let url_only = {
            let mut context = confirmable(context(&tools_for(&server), Caller::Stdio));
            let mut capabilities = ClientCapabilities::default();
            capabilities.elicitation =
                Some(ElicitationCapability::new().with_url(UrlElicitationCapability::new()));
            context.meta.set_client_capabilities(capabilities);
            context
        };
        let tools = tools_for(&server);
        let no_elicitation = {
            let mut context = context(&tools, Caller::Stdio);
            context
                .meta
                .set_protocol_version(ProtocolVersion::V_2026_07_28);
            context
                .meta
                .set_client_capabilities(ClientCapabilities::default());
            context
        };
        let legacy = {
            let mut context = confirmable(context(&tools, Caller::Stdio));
            context
                .meta
                .set_protocol_version(ProtocolVersion::V_2025_11_25);
            context
        };

        for (label, tools, context) in [
            ("url-only elicitation", tools.clone(), url_only),
            ("no elicitation", tools.clone(), no_elicitation),
            ("2025-11-25", tools.clone(), legacy),
            (
                "confirm_destructive = false",
                tools.clone().with_confirm_destructive(false),
                confirmable(context(&tools, Caller::Stdio)),
            ),
        ] {
            let result =
                complete(call_in(&tools, "myapp_delete_item", json!({ "id": 7 }), context).await);
            assert_succeeded(&result, label);
        }
        assert_eq!(request_count(&server).await, 4);
    }

    #[tokio::test]
    async fn non_destructive_tools_are_never_confirmed() {
        let server = upstream().await;
        let tools = tools_for(&server);

        for name in ["myapp_create_item", "myapp_get_item"] {
            let result = complete(
                call_in(
                    &tools,
                    name,
                    valid_arguments(name),
                    confirmable(context(&tools, Caller::Stdio)),
                )
                .await,
            );
            assert_succeeded(&result, name);
        }
        assert_eq!(request_count(&server).await, 2);
    }

    // ---- Shared handler state and the response budget ----

    #[test]
    fn with_confirm_destructive_leaves_the_original_handle_untouched() {
        let tools = tools_at(Config::default().base_url, 1024);
        let shared = tools.clone();
        let off = shared.clone().with_confirm_destructive(false);
        assert!(tools.confirm_destructive && shared.confirm_destructive);
        assert!(!off.confirm_destructive);
        assert!(tools.shares_state_with(&shared));
        assert!(!tools.shares_state_with(&off));
    }

    #[tokio::test]
    async fn list_and_get_tool_share_the_schemas_closed_at_construction() {
        let server = untouched_upstream().await;
        let tools = tools_for(&server);

        let listed = listed_tools(&tools, Caller::Stdio).await;
        assert_eq!(listed, tools.router().list_all());
        for tool in &listed {
            let fetched = ServerHandler::get_tool(&tools, &tool.name)
                .unwrap_or_else(|| panic!("{} is fetchable", tool.name));
            assert_eq!(*tool, fetched);
            assert!(Arc::ptr_eq(&tool.input_schema, &fetched.input_schema));
            match (&tool.output_schema, &fetched.output_schema) {
                (Some(listed), Some(fetched)) => assert!(Arc::ptr_eq(listed, fetched)),
                other => panic!("{} must advertise an output schema: {other:?}", tool.name),
            }
            assert_eq!(
                tool.input_schema.get("additionalProperties"),
                Some(&Value::Bool(false)),
                "{}",
                tool.name
            );
        }
    }

    #[tokio::test]
    async fn infeasibly_tiny_budget_propagates_as_a_protocol_error() {
        let server = upstream().await;
        let tools = tools_with_budget(&server, 1);

        let error = call(&tools, Caller::Stdio, "myapp_get_system_status", json!({}))
            .await
            .expect_err("the overflow diagnostic cannot fit a one-byte budget");

        assert_eq!(
            error.message,
            "tool response exceeds the configured response budget"
        );
        assert!(error.data.is_none());
    }

    // ---- Documentation contracts ----

    /// The prefix every tool name carries; renamed with the project.
    const TOOL_PREFIX: &str = "myapp_";

    fn registered_tool_names() -> BTreeSet<String> {
        all_tool_names(&tools_at(Config::default().base_url, 1024))
            .into_iter()
            .collect()
    }

    /// Every word in `text` that starts with [`TOOL_PREFIX`], where a word is
    /// a maximal run of `[a-z0-9_]`. The bare prefix, as prose naming it,
    /// is not a tool name.
    fn mentioned_words(text: &str) -> Vec<&str> {
        text.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            .filter(|word| word.starts_with(TOOL_PREFIX) && *word != TOOL_PREFIX)
            .collect()
    }

    /// Asserts that `text` names every registered tool exactly once and
    /// nothing else that looks like a tool name.
    fn assert_names_every_tool_once(document: &str, text: &str) {
        let mentioned = mentioned_words(text);
        let registered = registered_tool_names();
        for name in &registered {
            let count = mentioned.iter().filter(|word| **word == name).count();
            assert_eq!(count, 1, "{document} must name {name} exactly once");
        }
        let unknown: Vec<&&str> = mentioned
            .iter()
            .filter(|word| !registered.contains(**word))
            .collect();
        assert!(
            unknown.is_empty(),
            "{document} names tools that are not registered: {unknown:?}"
        );
    }

    #[test]
    fn mentioned_words_split_on_markdown_and_punctuation() {
        assert_eq!(
            mentioned_words("`myapp_a`: see **myapp_b_2**, (myapp_c). MYAPP_ENV, `myapp_`"),
            ["myapp_a", "myapp_b_2", "myapp_c"]
        );
    }

    #[test]
    fn instructions_name_every_registered_tool_exactly_once() {
        assert_names_every_tool_once("instructions.md", include_str!("instructions.md"));
    }

    /// The crate README, whose `## Example tools` section tables every tool.
    const README: &str = include_str!("../../README.md");

    /// The README's `## Example tools` section: the body after its heading,
    /// up to the next `## ` heading.
    fn readme_tools_section() -> &'static str {
        let (_, rest) = README
            .split_once("\n## Example tools\n")
            .expect("README has a `## Example tools` section");
        rest.split_once("\n## ")
            .map_or(rest, |(section, _)| section)
    }

    #[test]
    fn readme_tool_table_matches_the_registered_tools() {
        let section = readme_tools_section();
        assert_names_every_tool_once("README.md `## Example tools`", section);

        let tools = tools_at(Config::default().base_url, 1024);
        let mut rows = 0;
        for line in section.lines() {
            // Data rows only: | `name` | description | scope |
            let Some(row) = line.strip_prefix("| `") else {
                continue;
            };
            rows += 1;
            let name = row.split('`').next().unwrap_or_default();
            let tool = tools
                .router()
                .get(name)
                .unwrap_or_else(|| panic!("README row names unregistered tool {name}"));
            let scope = line
                .trim_end()
                .trim_end_matches('|')
                .rsplit('|')
                .next()
                .unwrap_or_default()
                .trim();
            let expected = if is_read_only(tool) {
                "`read`"
            } else {
                "`write`"
            };
            assert_eq!(scope, expected, "README scope cell for {name}");
        }
        assert_eq!(rows, VALID_CALLS.len(), "one README row per tool");
    }
}
