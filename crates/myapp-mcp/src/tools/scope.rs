//! Cross-cutting OAuth scope enforcement for tool calls.
//!
//! A request authenticated by an OAuth access token without the `write` scope
//! may call only tools annotated read-only. A token with `write` may call
//! every tool. The decision reads the tool annotations alone, so there is no
//! separate per-tool permission list to keep in sync.
//!
//! Only calls are checked: `tools/list` advertises every tool to every token,
//! so a client's view of the server does not change with its grant.
//!
//! Only the OAuth bearer middleware inserts [`Scopes`]; the static-token and
//! `none` HTTP modes and the stdio transport never do, because they grant no
//! scopes to restrict, so their requests keep full access. A handler serving
//! OAuth mode requires scopes instead: a request that reaches it without them,
//! which the middleware should make impossible, counts as read-only, so a
//! missing layer fails closed rather than open.

use axum::http::request::Parts;
use rmcp::RoleServer;
use rmcp::model::{CallToolResult, ContentBlock, Tool};
use rmcp::service::RequestContext;

use crate::auth::{Scope, Scopes};

/// Returns the scopes of the OAuth access token that authenticated the request,
/// or `None` when the request was not authenticated by one.
fn granted_scopes(context: &RequestContext<RoleServer>) -> Option<Scopes> {
    context
        .extensions
        .get::<Parts>()?
        .extensions
        .get::<Scopes>()
        .copied()
}

fn is_read_only(tool: &Tool) -> bool {
    tool.annotations
        .as_ref()
        .and_then(|annotations| annotations.read_only_hint)
        == Some(true)
}

/// Reports whether the request may call `tool`.
///
/// Fails closed for OAuth requests: a token without `write` is allowed only
/// tools whose `read_only_hint` is explicitly `true`. When `require_scopes`
/// is set, a request without scopes is treated as such a token; otherwise it
/// is unrestricted.
pub(super) fn permits(
    context: &RequestContext<RoleServer>,
    tool: &Tool,
    require_scopes: bool,
) -> bool {
    match granted_scopes(context) {
        Some(scopes) => scopes.contains(Scope::Write) || is_read_only(tool),
        None => !require_scopes || is_read_only(tool),
    }
}

/// Builds the tool error returned when the token lacks the `write` scope.
pub(super) fn insufficient_scope(tool_name: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(format!(
        "insufficient_scope: tool '{tool_name}' requires the '{}' scope",
        Scope::Write
    ))])
}

#[cfg(test)]
mod tests {
    use super::permits;
    use crate::auth::Scopes;
    use rmcp::model::{JsonObject, NumberOrString, Tool, ToolAnnotations};
    use rmcp::service::{RequestContext, serve_directly};
    use rmcp::{RoleServer, ServerHandler};

    /// A handler with no tools, needed only to give the context a peer.
    struct NoTools;

    impl ServerHandler for NoTools {}

    /// Builds a request context carrying what the OAuth bearer middleware
    /// attaches for a token granted `scopes`, or, for `None`, what the
    /// transport attaches for a request without an OAuth token.
    fn context_for(scopes: Option<&[&str]>) -> RequestContext<RoleServer> {
        let (server_transport, _client_transport) = tokio::io::duplex(4096);
        let running = serve_directly::<RoleServer, _, _, _, _>(NoTools, server_transport, None);
        let mut context = RequestContext::new(NumberOrString::Number(1), running.peer().clone());
        let (mut parts, ()) = axum::http::Request::new(()).into_parts();
        if let Some(scopes) = scopes {
            parts.extensions.insert(Scopes::parse(scopes));
        }
        context.extensions.insert(parts);
        context
    }

    fn tool_annotated(annotations: Option<ToolAnnotations>) -> Tool {
        let mut tool = Tool::new("scope_test_tool", "A hand-built tool.", JsonObject::new());
        tool.annotations = annotations;
        tool
    }

    /// The two ways a tool can leave `read_only_hint` unset.
    fn unannotated_tools() -> [(&'static str, Tool); 2] {
        [
            ("no annotations", tool_annotated(None)),
            (
                "annotations without read_only_hint",
                tool_annotated(Some(ToolAnnotations::new())),
            ),
        ]
    }

    /// Guards against `is_read_only` failing open (for example `!= Some(false)`):
    /// every shipped tool sets the hint, so only a hand-built tool can catch it.
    #[tokio::test]
    async fn read_token_is_refused_a_tool_without_a_read_only_hint() {
        let context = context_for(Some(&["read"]));
        for (case, tool) in unannotated_tools() {
            assert!(
                !permits(&context, &tool, false),
                "a tool with {case} must not count as read-only"
            );
        }
        assert!(!permits(
            &context,
            &tool_annotated(Some(ToolAnnotations::new().read_only(false))),
            false
        ));
    }

    /// Guards against failing closed too far: an unset hint must restrict only
    /// tokens without `write`, never `write` tokens or requests without a token.
    #[tokio::test]
    async fn write_token_and_requests_without_a_token_are_permitted_a_tool_without_a_read_only_hint()
     {
        for (caller, context) in [
            ("a write token", context_for(Some(&["write"]))),
            ("a request without a token", context_for(None)),
        ] {
            for (case, tool) in unannotated_tools() {
                assert!(
                    permits(&context, &tool, false),
                    "{caller} must be permitted a tool with {case}"
                );
            }
        }
    }

    /// Guards against the fail-closed check also refusing explicitly read-only
    /// tools, which would leave a `read` token with nothing to call.
    #[tokio::test]
    async fn read_token_is_permitted_a_tool_annotated_read_only() {
        let context = context_for(Some(&["read"]));
        assert!(permits(
            &context,
            &tool_annotated(Some(ToolAnnotations::new().read_only(true))),
            false
        ));
    }

    /// With scopes required, a request missing them, whether it lacks the
    /// HTTP request parts entirely or only the scopes, is limited to
    /// read-only tools, and an unset hint still fails closed.
    #[tokio::test]
    async fn required_scopes_fail_closed_when_missing() {
        let mut without_parts = context_for(None);
        without_parts.extensions = rmcp::model::Extensions::default();
        for (case, context) in [
            ("no request parts", without_parts),
            ("no scopes", context_for(None)),
        ] {
            assert!(
                permits(
                    &context,
                    &tool_annotated(Some(ToolAnnotations::new().read_only(true))),
                    true
                ),
                "{case}: read-only tools stay allowed"
            );
            for (hint, tool) in unannotated_tools() {
                assert!(!permits(&context, &tool, true), "{case}: {hint}");
            }
        }
        assert!(
            permits(&context_for(Some(&["write"])), &tool_annotated(None), true),
            "a write token is unaffected"
        );
    }
}
