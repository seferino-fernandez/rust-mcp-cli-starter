//! Cross-cutting confirmation of destructive tools through MRTR (multi-round
//! tool requests, protocol 2026-07-28).
//!
//! A tool annotated `destructive_hint: true`, called by a client that can
//! answer a form elicitation, first gets an input-required result asking the
//! user to confirm. The pending call travels with it as `requestState`, sealed
//! by [`RequestStateCodec`] under an in-process random key, bound to the tool
//! name and valid for [`SEAL_TTL`]. The retry must carry that state, the same
//! arguments and an accepted `confirm: true`; anything else is refused.
//!
//! This is a courtesy against a model acting on its own, not access control:
//! a client without form elicitation runs the tool directly, and the OAuth
//! `write` scope is what actually gates mutation.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, ElicitRequest, ElicitRequestParams, ElicitResult, ElicitationAction,
    ElicitationSchema, InputRequest, InputRequiredResult, JsonObject, ProtocolVersion,
    RequestStateCodec, SealOptions, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer};
use serde_json::{Value, json};
use uuid::Uuid;

/// The sealing key, drawn once per process. A restart invalidates every
/// pending confirmation, which only costs the client one more round.
static SEAL_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// The input-request key, and the boolean field the user sets to confirm.
const CONFIRM_KEY: &str = "confirm";

/// How long a pending confirmation stays valid.
const SEAL_TTL: Duration = Duration::from_secs(300);

/// The error every unusable `requestState` gets, without saying why.
const STALE_STATE: &str = "stale or invalid confirmation state; call the tool again";

fn codec() -> Result<RequestStateCodec, ErrorData> {
    let key = SEAL_KEY.get_or_init(|| {
        let first = *Uuid::new_v4().as_bytes();
        let second = *Uuid::new_v4().as_bytes();
        let mut key = [0_u8; 32];
        for (slot, byte) in key.iter_mut().zip(first.into_iter().chain(second)) {
            *slot = byte;
        }
        key
    });
    RequestStateCodec::try_new(key.to_vec()).map_err(|_error| {
        ErrorData::internal_error("failed to initialize confirmation state", None)
    })
}

/// Whether `tool` is annotated destructive, and so asks for confirmation.
pub(super) fn requires_confirmation(tool: &Tool) -> bool {
    tool.annotations
        .as_ref()
        .and_then(|annotations| annotations.destructive_hint)
        == Some(true)
}

/// Whether the client negotiated 2026-07-28 or later and supports form
/// elicitation. An elicitation capability naming neither mode means form, as
/// it did before URL elicitation existed.
pub(super) fn client_supports_confirmation(context: &RequestContext<RoleServer>) -> bool {
    let modern_protocol = context
        .protocol_version()
        .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28);
    let supports_form_elicitation = context
        .client_capabilities()
        .and_then(|capabilities| capabilities.elicitation)
        .is_some_and(|elicitation| {
            elicitation.form.is_some() || (elicitation.form.is_none() && elicitation.url.is_none())
        });
    modern_protocol && supports_form_elicitation
}

/// The input-required result asking the user to confirm `request`, with the
/// call sealed as its `requestState`.
pub(super) fn confirmation_request(
    request: &CallToolRequestParams,
) -> Result<InputRequiredResult, ErrorData> {
    let requested_schema = ElicitationSchema::builder()
        .required_bool_with(CONFIRM_KEY, |builder| {
            builder
                .title("Confirm destructive operation")
                .description(format!(
                    "Confirm execution of the destructive tool '{}'.",
                    request.name
                ))
        })
        .build()
        .map_err(|message| ErrorData::internal_error(message, None))?;
    let elicitation = InputRequest::Elicitation(ElicitRequest::new(
        ElicitRequestParams::FormElicitationParams {
            meta: None,
            message: format!(
                "Tool '{}' is destructive and cannot be undone. Confirm?",
                request.name
            ),
            requested_schema,
        },
    ));
    let input_requests = BTreeMap::from([(CONFIRM_KEY.to_string(), elicitation)]);
    let sealed = codec()?
        .seal_json_with(
            &json!({
                "tool": request.name,
                "args": request.arguments,
            }),
            &SealOptions::new()
                .ttl(SEAL_TTL)
                .associated_data(request.name.as_bytes()),
        )
        .map_err(|_error| ErrorData::internal_error("failed to seal confirmation state", None))?;

    Ok(InputRequiredResult::new(Some(input_requests), Some(sealed)))
}

/// What the user answered to a confirmation request.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// The user accepted with `confirm: true`; run the tool.
    Confirmed,
    /// Anything else, with the reason; refuse the call.
    Declined(String),
}

/// Checks a retry against the confirmation it answers.
///
/// A protocol error when the state is tampered with, expired, sealed for
/// another tool or for other arguments, or when the confirmation response is
/// missing or malformed. Otherwise the user's [`Verdict`].
pub(super) fn verify_confirmation(
    sealed: &str,
    request: &CallToolRequestParams,
) -> Result<Verdict, ErrorData> {
    let stale = || ErrorData::invalid_params(STALE_STATE, None);
    let state = codec()?
        .open_json_with::<Value>(sealed, request.name.as_bytes())
        .map_err(|_error| stale())?;
    let sealed_arguments = state
        .as_object()
        .and_then(|object| object.get("args"))
        .cloned()
        .ok_or_else(stale)?;
    let sealed_arguments =
        serde_json::from_value::<Option<JsonObject>>(sealed_arguments).map_err(|_error| stale())?;
    if sealed_arguments != request.arguments {
        return Err(ErrorData::invalid_params(
            "arguments changed between confirmation rounds",
            None,
        ));
    }

    let response = request
        .input_responses
        .as_ref()
        .and_then(|responses| responses.get(CONFIRM_KEY))
        .cloned()
        .ok_or_else(|| ErrorData::invalid_params("missing confirmation response", None))?;
    let elicitation = serde_json::from_value::<ElicitResult>(response)
        .map_err(|_error| ErrorData::invalid_params("invalid confirmation response", None))?;
    let confirmed = elicitation
        .content
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|content| content.get(CONFIRM_KEY))
        .and_then(Value::as_bool)
        == Some(true);

    Ok(match elicitation.action {
        ElicitationAction::Accept if confirmed => Verdict::Confirmed,
        ElicitationAction::Accept => {
            Verdict::Declined("accept response did not confirm the operation".to_string())
        }
        ElicitationAction::Decline => {
            Verdict::Declined("client returned the decline action".to_string())
        }
        ElicitationAction::Cancel => {
            Verdict::Declined("client returned the cancel action".to_string())
        }
        _ => Verdict::Declined("client returned an unsupported elicitation action".to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &'static str, arguments: Value, response: Value) -> CallToolRequestParams {
        CallToolRequestParams::new(name)
            .with_arguments(
                arguments
                    .as_object()
                    .expect("arguments are an object")
                    .clone(),
            )
            .with_input_responses(BTreeMap::from([(CONFIRM_KEY.to_string(), response)]))
    }

    fn sealed_for(request: &CallToolRequestParams) -> String {
        confirmation_request(request)
            .expect("confirmation request builds")
            .request_state
            .expect("confirmation state is present")
    }

    fn accept(confirm: bool) -> Value {
        json!({"action": "accept", "content": {"confirm": confirm}})
    }

    #[test]
    fn seal_and_verify_accept_round_trip() {
        let request = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let sealed = sealed_for(&request);

        assert_eq!(
            verify_confirmation(&sealed, &request).expect("confirmation verifies"),
            Verdict::Confirmed
        );
    }

    #[test]
    fn declined_and_cancelled_actions_are_declined() {
        for (action, reason) in [("decline", "decline"), ("cancel", "cancel")] {
            let request = request(
                "myapp_delete_item",
                json!({"id": 7}),
                json!({ "action": action }),
            );
            let sealed = sealed_for(&request);

            assert!(
                matches!(
                    verify_confirmation(&sealed, &request).expect("confirmation verifies"),
                    Verdict::Declined(text) if text.contains(reason)
                ),
                "{action}"
            );
        }
    }

    #[test]
    fn false_confirmation_is_declined() {
        let request = request("myapp_delete_item", json!({"id": 7}), accept(false));
        let sealed = sealed_for(&request);

        assert!(matches!(
            verify_confirmation(&sealed, &request).expect("confirmation verifies"),
            Verdict::Declined(reason) if reason.contains("accept")
        ));
    }

    #[test]
    fn tampered_sealed_state_is_rejected() {
        let request = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let mut sealed = sealed_for(&request);
        sealed.push('x');

        let error =
            verify_confirmation(&sealed, &request).expect_err("tampered state must be rejected");
        assert_eq!(error.message, STALE_STATE);
    }

    #[test]
    fn state_sealed_for_a_different_tool_is_rejected() {
        let original = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let retry = request("myapp_create_item", json!({"id": 7}), accept(true));

        let error = verify_confirmation(&sealed_for(&original), &retry)
            .expect_err("state must be bound to its tool name");
        assert_eq!(error.message, STALE_STATE);
    }

    #[test]
    fn changed_arguments_are_rejected() {
        let original = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let retry = request("myapp_delete_item", json!({"id": 8}), accept(true));

        let error = verify_confirmation(&sealed_for(&original), &retry)
            .expect_err("changed arguments must be rejected");
        assert_eq!(
            error.message,
            "arguments changed between confirmation rounds"
        );
    }

    #[test]
    fn missing_confirmation_response_is_rejected() {
        let original = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let retry = CallToolRequestParams::new("myapp_delete_item")
            .with_arguments(original.arguments.clone().unwrap_or_default());

        let error = verify_confirmation(&sealed_for(&original), &retry)
            .expect_err("a retry must carry the confirmation response");
        assert_eq!(error.message, "missing confirmation response");
    }

    #[test]
    fn confirmation_request_asks_for_a_required_boolean() {
        let request = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let result = confirmation_request(&request).expect("confirmation request builds");
        let wire = serde_json::to_value(&result).expect("result serializes");
        let elicitation = &wire["inputRequests"][CONFIRM_KEY];
        assert_eq!(elicitation["method"], "elicitation/create", "{wire}");
        assert_eq!(elicitation["params"]["mode"], "form", "{wire}");
        let schema = &elicitation["params"]["requestedSchema"];
        assert_eq!(
            schema["properties"][CONFIRM_KEY]["type"], "boolean",
            "{wire}"
        );
        assert_eq!(schema["required"], json!([CONFIRM_KEY]), "{wire}");
    }
}
