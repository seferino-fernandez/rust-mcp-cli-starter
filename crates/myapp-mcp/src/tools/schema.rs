//! Schema post-processing: close every object schema so MCP tool inputs reject
//! unexpected properties, and a response-size guard helper.

use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Map, Value};

/// Recursively sets `additionalProperties: false` on every object schema node
/// within a JSON Schema value: the root, nested `properties`, `items`, and any
/// `$defs`/`definitions`. Idempotent.
pub fn close_object_schemas(schema: &mut Value) {
    match schema {
        Value::Object(map) => {
            close_object_map(map);
        }
        Value::Array(items) => {
            for item in items {
                close_object_schemas(item);
            }
        }
        _ => {}
    }
}

/// Closes a single object schema map in place: for every object schema node it
/// sets `additionalProperties: false` and `required: []` when those keys are
/// absent, then recurses into nested values. Idempotent.
///
/// The empty `required: []` truthfully declares "no fields are required" for
/// parameterless/all-optional tools (schemars omits the key entirely when a
/// struct has no mandatory fields), satisfying scanners that require an explicit
/// `required` declaration. An existing `required` array is preserved verbatim.
pub fn close_object_map(map: &mut Map<String, Value>) {
    let is_object_schema =
        map.get("type").and_then(Value::as_str) == Some("object") || map.contains_key("properties");
    if is_object_schema {
        if !map.contains_key("additionalProperties") {
            map.insert("additionalProperties".to_string(), Value::Bool(false));
        }
        if !map.contains_key("required") {
            map.insert("required".to_string(), Value::Array(Vec::new()));
        }
    }
    for (_key, value) in map.iter_mut() {
        close_object_schemas(value);
    }
}

/// Replaces an oversized tool result with a valid, bounded JSON error.
///
/// Measures the exact serialized [`CallToolResult`]: `content`,
/// `structured_content` and every other field. If it exceeds `max_bytes`,
/// returns a small result describing the overflow so the model can narrow its
/// request. If even that diagnostic exceeds `max_bytes`, returns a protocol
/// error rather than break the configured cap. Returns the original result
/// otherwise.
pub fn enforce_response_budget(
    result: CallToolResult,
    max_bytes: usize,
) -> Result<CallToolResult, McpError> {
    let size = serialized_len(&result)?;
    if size <= max_bytes {
        return Ok(result);
    }
    // Preserve the original error flag: a tool returning `Err(String)` arrives
    // here as `Ok(CallToolResult { is_error: Some(true), .. })`, so relabeling it
    // as a success would silently hide the failure.
    let was_error = result.is_error;
    let body = serde_json::json!({
        "error": "response_too_large",
        "bytes": size,
        "limit": max_bytes,
        "hint": "narrow the query (smaller page size, fewer results, or a more specific filter)"
    });
    let mut replacement = CallToolResult::success(vec![ContentBlock::text(body.to_string())]);
    replacement.is_error = was_error;
    if serialized_len(&replacement)? <= max_bytes {
        Ok(replacement)
    } else {
        Err(McpError::internal_error(
            "tool response exceeds the configured response budget",
            None,
        ))
    }
}

/// The length of `result` serialized as JSON, as it goes on the wire.
fn serialized_len(result: &CallToolResult) -> Result<usize, McpError> {
    serde_json::to_vec(result)
        .map(|bytes| bytes.len())
        .map_err(|_error| McpError::internal_error("failed to measure tool response", None))
}

#[cfg(test)]
mod tests {
    use super::close_object_schemas;
    use serde_json::json;

    #[test]
    fn closes_top_level_object() {
        let mut schema = json!({"type": "object", "properties": {"a": {"type": "string"}}});
        close_object_schemas(&mut schema);
        assert_eq!(schema["additionalProperties"], json!(false));
        assert_eq!(schema["required"], json!([]));
    }

    #[test]
    fn closes_nested_object_and_defs() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type": "object", "properties": {"x": {"type": "number"}}}
                }
            },
            "$defs": {"Inner": {"type": "object", "properties": {"y": {"type": "string"}}}}
        });
        close_object_schemas(&mut schema);
        assert_eq!(schema["additionalProperties"], json!(false));
        assert_eq!(schema["required"], json!([]));
        assert_eq!(
            schema["properties"]["items"]["items"]["additionalProperties"],
            json!(false)
        );
        assert_eq!(
            schema["properties"]["items"]["items"]["required"],
            json!([])
        );
        assert_eq!(
            schema["$defs"]["Inner"]["additionalProperties"],
            json!(false)
        );
        assert_eq!(schema["$defs"]["Inner"]["required"], json!([]));
    }

    #[test]
    fn closes_empty_no_arg_object() {
        let mut schema = json!({"type": "object", "properties": {}});
        close_object_schemas(&mut schema);
        assert_eq!(schema["additionalProperties"], json!(false));
        assert_eq!(schema["required"], json!([]));
    }

    #[test]
    fn inserts_empty_required_when_absent() {
        // An object schema with no `required` key gets an explicit `required: []`.
        let mut schema = json!({"type": "object", "properties": {"a": {"type": "string"}}});
        assert!(schema.get("required").is_none());
        close_object_schemas(&mut schema);
        assert_eq!(schema["required"], json!([]));
    }

    #[test]
    fn preserves_existing_non_empty_required() {
        // A populated `required` (e.g. from schemars for a mandatory field) must
        // be preserved verbatim, never overwritten or emptied.
        let mut schema = json!({
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"]
        });
        close_object_schemas(&mut schema);
        assert_eq!(schema["required"], json!(["id"]));
        assert_eq!(schema["additionalProperties"], json!(false));
    }

    #[test]
    fn preserves_existing_additional_properties() {
        let mut schema = json!({"type": "object", "additionalProperties": true});
        close_object_schemas(&mut schema);
        assert_eq!(schema["additionalProperties"], json!(true));
    }
}

#[cfg(test)]
mod router_tests {
    use super::close_object_schemas;
    use crate::tools::confirm::requires_confirmation;
    use crate::tools::test_support::tools_at;
    use myapp_core::Config;
    use rmcp::ServerHandler;
    use rmcp::model::Tool;
    use serde_json::Value;
    use std::collections::HashSet;

    /// Every registered tool, from a handler that is never called.
    fn listed_tools() -> Vec<Tool> {
        tools_at(Config::default().base_url, 1024 * 1024)
            .router()
            .list_all()
    }

    #[test]
    fn every_listed_tool_schema_is_closed() {
        for tool in listed_tools() {
            let mut v = Value::Object((*tool.input_schema).clone());
            close_object_schemas(&mut v); // idempotent; asserts no panic
            assert_eq!(
                v["additionalProperties"],
                Value::Bool(false),
                "tool {} root schema must be closed",
                tool.name
            );
            // Every advertised tool's root schema must declare `required`
            // explicitly (either `[]` for all-optional/no-arg tools or a
            // populated array), so deterministic scanners don't flag a missing
            // `required` key.
            let required = v.get("required").unwrap_or_else(|| {
                panic!("tool {} root schema must declare `required`", tool.name)
            });
            assert!(
                required.is_array(),
                "tool {} root `required` must be an array, got {required}",
                tool.name
            );
        }
    }

    #[test]
    fn every_listed_tool_has_a_closeable_output_schema() {
        // Every tool returns `Json<T>`, so rmcp advertises an `outputSchema`.
        // The MCP spec requires an object root, and closing must produce at
        // least one `additionalProperties: false`.
        for tool in listed_tools() {
            let output = tool
                .output_schema
                .as_ref()
                .unwrap_or_else(|| panic!("tool {} must advertise an output schema", tool.name));
            let mut v = Value::Object((**output).clone());
            assert!(
                v.get("type").and_then(Value::as_str) == Some("object")
                    || v.get("properties").is_some(),
                "tool {} output schema must have an object root: {v}",
                tool.name
            );
            close_object_schemas(&mut v); // idempotent; asserts no panic
            let serialized = v.to_string();
            assert!(
                serialized.contains("\"additionalProperties\":false"),
                "tool {} output schema must have its object node(s) closed: {serialized}",
                tool.name
            );
        }
    }

    #[test]
    fn tool_annotations_are_complete() {
        let tools = listed_tools();
        let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        assert_eq!(
            names,
            [
                "myapp_create_item",
                "myapp_delete_item",
                "myapp_get_item",
                "myapp_get_system_status",
                "myapp_list_items",
            ]
        );
        for tool in &tools {
            assert!(
                tool.name.starts_with("myapp_"),
                "tool {} must carry the server prefix",
                tool.name
            );
            let ann = tool
                .annotations
                .as_ref()
                .unwrap_or_else(|| panic!("tool {} must have annotations", tool.name));
            assert!(
                ann.title.as_ref().is_some_and(|t| !t.is_empty()),
                "tool {} must have a non-empty title",
                tool.name
            );
            match tool.name.as_ref() {
                "myapp_get_system_status" | "myapp_list_items" | "myapp_get_item" => {
                    assert_eq!(
                        ann.idempotent_hint,
                        Some(true),
                        "{} must be marked idempotent",
                        tool.name
                    );
                    assert_eq!(
                        ann.read_only_hint,
                        Some(true),
                        "{} must be marked read-only",
                        tool.name
                    );
                }
                "myapp_create_item" => {
                    assert_eq!(
                        ann.read_only_hint,
                        Some(false),
                        "myapp_create_item must not be marked read-only"
                    );
                    assert_eq!(
                        ann.destructive_hint,
                        Some(false),
                        "myapp_create_item must not be marked destructive"
                    );
                    assert_eq!(
                        ann.idempotent_hint,
                        Some(false),
                        "myapp_create_item must not be marked idempotent"
                    );
                }
                "myapp_delete_item" => {
                    assert_eq!(
                        ann.read_only_hint,
                        Some(false),
                        "myapp_delete_item must not be marked read-only"
                    );
                    assert_eq!(
                        ann.destructive_hint,
                        Some(true),
                        "myapp_delete_item must be marked destructive"
                    );
                    assert_eq!(
                        ann.idempotent_hint,
                        Some(true),
                        "myapp_delete_item must be marked idempotent"
                    );
                }
                other => panic!("unexpected tool {other}"),
            }
        }
    }

    /// Pins the advertised protocol version. `ProtocolVersion::LATEST` follows
    /// the SDK and may move past what this server implements, so this server
    /// names its version explicitly.
    #[test]
    fn advertises_current_protocol_version() {
        use rmcp::model::ProtocolVersion;

        let tools = tools_at(Config::default().base_url, 1024 * 1024);
        assert_eq!(
            tools.get_info().protocol_version,
            ProtocolVersion::V_2026_07_28
        );
    }

    /// The server must identify itself, not the SDK. `Implementation::default()`
    /// and `from_build_env()` both expand `env!` inside rmcp, so they report
    /// `"rmcp"` at rmcp's version which would tell clients this server is
    /// version 3.0.0. Guards against a well-meaning revert to either.
    #[test]
    fn identifies_itself_rather_than_the_sdk() {
        let tools = tools_at(Config::default().base_url, 1024 * 1024);
        let server_info = tools.get_info().server_info;

        assert_eq!(server_info.name, env!("CARGO_PKG_NAME"));
        assert_eq!(server_info.version, env!("CARGO_PKG_VERSION"));
        assert_ne!(
            server_info.name, "rmcp",
            "server_info must not report the SDK's identity"
        );
    }

    /// The SEP-2243 `x-mcp-header` annotation must survive schema closing. The
    /// server looks the schema up through `get_tool` to validate inbound
    /// `Mcp-Param-*` headers against the request body, so if closing ever
    /// dropped the annotation, promotion would silently stop working.
    #[test]
    fn item_id_advertises_its_mcp_param_header() {
        let tools = tools_at(Config::default().base_url, 1024 * 1024);

        for name in ["myapp_get_item", "myapp_delete_item"] {
            let tool = tools
                .get_tool(name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            assert_eq!(
                tool.input_schema["properties"]["id"]["x-mcp-header"],
                Value::String("Item-Id".to_string()),
                "{name} must promote `id` to the Mcp-Param-Item-Id header",
            );
        }
    }

    /// Every `x-mcp-header` value is a valid HTTP header token, sits on a
    /// top-level primitive property, and names a header no other property of
    /// the same tool uses (header names compare case-insensitively).
    #[test]
    fn mcp_header_annotations_are_valid() {
        let mut annotated = 0;
        for tool in listed_tools() {
            let properties = tool
                .input_schema
                .get("properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let mut headers = HashSet::new();
            for (property_name, property) in &properties {
                let Some(header) = property.get("x-mcp-header") else {
                    continue;
                };
                annotated += 1;
                let header = header.as_str().unwrap_or_else(|| {
                    panic!(
                        "{} property {property_name} x-mcp-header must be a string",
                        tool.name
                    )
                });
                assert!(
                    !header.is_empty()
                        && header.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
                        }),
                    "{} property {property_name} has invalid x-mcp-header {header:?}",
                    tool.name
                );
                assert!(
                    matches!(
                        property.get("type").and_then(Value::as_str),
                        Some("string" | "integer" | "number" | "boolean")
                    ),
                    "{} property {property_name} with x-mcp-header must be primitive: {property}",
                    tool.name
                );
                assert!(
                    headers.insert(header.to_ascii_lowercase()),
                    "{} repeats x-mcp-header {header:?}",
                    tool.name
                );
            }
            let nested = Value::Object(properties).to_string();
            assert_eq!(
                nested.matches("\"x-mcp-header\"").count(),
                headers.len(),
                "{} has an x-mcp-header below the top level",
                tool.name
            );
        }
        assert!(
            annotated > 0,
            "the example tools promote at least one header"
        );
    }

    /// Whether `schema`, resolving `$ref` against `root`, is an object schema
    /// with its own `properties`, or an array (or `anyOf`/`oneOf`/`allOf`
    /// branch) of one.
    fn declares_nested_properties(schema: &Value, root: &Value) -> bool {
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            return reference
                .strip_prefix('#')
                .and_then(|pointer| root.pointer(pointer))
                .is_some_and(|target| declares_nested_properties(target, root));
        }
        if schema
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| !properties.is_empty())
        {
            return true;
        }
        if schema
            .get("items")
            .is_some_and(|items| declares_nested_properties(items, root))
        {
            return true;
        }
        ["anyOf", "oneOf", "allOf"].iter().any(|combinator| {
            schema
                .get(*combinator)
                .and_then(Value::as_array)
                .is_some_and(|branches| {
                    branches
                        .iter()
                        .any(|branch| declares_nested_properties(branch, root))
                })
        })
    }

    #[test]
    fn declares_nested_properties_sees_through_refs_arrays_and_combinators() {
        let root = serde_json::json!({
            "$defs": { "Inner": { "type": "object", "properties": { "x": {} } } },
            "properties": {
                "flat": { "type": "integer" },
                "direct": { "type": "object", "properties": { "y": {} } },
                "by_ref": { "$ref": "#/$defs/Inner" },
                "list": { "type": "array", "items": { "$ref": "#/$defs/Inner" } },
                "either": { "anyOf": [{ "type": "null" }, { "$ref": "#/$defs/Inner" }] }
            }
        });
        let properties = &root["properties"];
        assert!(!declares_nested_properties(&properties["flat"], &root));
        for nested in ["direct", "by_ref", "list", "either"] {
            assert!(
                declares_nested_properties(&properties[nested], &root),
                "{nested}"
            );
        }
    }

    /// `call_tool` rejects undeclared top-level keys before asking for
    /// confirmation, which covers every key `deny_unknown_fields` rejects only
    /// while no tool that requires confirmation takes a nested params object.
    /// Adding one must turn this test red, so the check is made recursive (or
    /// the tool is reconsidered) before a stray nested key can prompt for
    /// confirmation and then fail.
    #[test]
    fn no_confirmation_tool_takes_a_nested_params_object() {
        let mut confirming = 0;
        let mut nested = Vec::new();
        for tool in listed_tools() {
            if !requires_confirmation(&tool) {
                continue;
            }
            confirming += 1;
            let root = Value::Object((*tool.input_schema).clone());
            let properties = root["properties"].as_object().into_iter().flatten();
            for (name, property) in properties {
                if declares_nested_properties(property, &root) {
                    nested.push(format!("{}.{name}", tool.name));
                }
            }
        }
        assert!(confirming > 0, "myapp_delete_item requires confirmation");
        assert!(
            nested.is_empty(),
            "tools that require confirmation must not take nested params objects: {nested:?}"
        );
    }
}

#[cfg(test)]
mod budget_tests {
    use super::enforce_response_budget;
    use rmcp::model::{CallToolResult, ContentBlock};

    #[test]
    fn passes_small_results_through() {
        let original =
            CallToolResult::success(vec![ContentBlock::text("{\"ok\":true}".to_string())]);
        let guarded = enforce_response_budget(original, 1024).unwrap();
        let text = serde_json::to_string(&guarded.content).unwrap();
        assert!(text.contains("ok"));
    }

    #[test]
    fn replaces_oversized_results() {
        let big = "x".repeat(2048);
        let original = CallToolResult::success(vec![ContentBlock::text(big)]);
        let guarded = enforce_response_budget(original, 256).unwrap();
        assert!(serde_json::to_vec(&guarded).unwrap().len() <= 256);
        let text = serde_json::to_string(&guarded.content).unwrap();
        assert!(text.contains("response_too_large"), "got: {text}");
    }

    #[test]
    fn guards_oversized_structured_results() {
        let big = serde_json::json!({ "blob": "x".repeat(2048) });
        let original = CallToolResult::structured(big);
        let guarded = enforce_response_budget(original, 256).unwrap();
        assert!(serde_json::to_vec(&guarded).unwrap().len() <= 256);
        let text = serde_json::to_string(&guarded.content).unwrap();
        assert!(text.contains("response_too_large"), "got: {text}");
        assert_eq!(
            guarded.is_error,
            Some(false),
            "a successful structured result stays non-error after guarding"
        );
    }

    /// `CallToolResult::structured` carries the payload twice, as text content
    /// and as `structured_content`, plus the other result fields. The cap
    /// applies to all of it, not to `content` alone.
    #[test]
    fn budget_measures_the_whole_serialized_result() {
        let payload = serde_json::json!({ "blob": "x".repeat(200) });
        let original = CallToolResult::structured(payload);
        let content_size = serde_json::to_vec(&original.content).unwrap().len();
        let exact_size = serde_json::to_vec(&original).unwrap().len();
        assert!(exact_size > 2 * 200, "{exact_size}");

        let at_the_boundary = enforce_response_budget(original.clone(), exact_size).unwrap();
        assert_eq!(
            at_the_boundary, original,
            "a result of exactly the cap passes"
        );

        for cap in [content_size, exact_size - 1] {
            let guarded = enforce_response_budget(original.clone(), cap).unwrap();
            let text = serde_json::to_string(&guarded.content).unwrap();
            assert!(
                text.contains("response_too_large"),
                "the {exact_size}-byte result must not pass a {cap}-byte cap"
            );
        }
    }

    #[test]
    fn overflow_replacement_never_exceeds_even_a_tiny_configured_cap() {
        let original = CallToolResult::success(vec![ContentBlock::text("x".repeat(2048))]);
        let error = enforce_response_budget(original, 1)
            .expect_err("an infeasibly tiny cap must produce a protocol error");

        assert_eq!(
            error.message,
            "tool response exceeds the configured response budget"
        );
        assert!(error.data.is_none());
    }

    #[test]
    fn preserves_error_flag_on_replacement() {
        let mut original = CallToolResult::success(vec![ContentBlock::text("x".repeat(2048))]);
        original.is_error = Some(true);
        let guarded = enforce_response_budget(original, 256).unwrap();
        assert_eq!(
            guarded.is_error,
            Some(true),
            "a failed call must stay flagged as an error after guarding"
        );
        let text = serde_json::to_string(&guarded.content).unwrap();
        assert!(text.contains("response_too_large"), "got: {text}");
    }
}
