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
//! Each sealed state carries a random ID, and an accepted state is spent:
//! [`ConsumedConfirmations`] remembers the IDs already used, so replaying it
//! is refused and the tool runs at most once per confirmation.
//!
//! This is a courtesy against a model acting on its own, not access control:
//! a client without form elicitation runs the tool directly, and the OAuth
//! `write` scope is what actually gates mutation.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

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

/// The error a replayed, already accepted `requestState` gets.
const SPENT_STATE: &str = "confirmation already used; call the tool again";

/// The most spent confirmation IDs remembered at once.
const MAX_CONSUMED: usize = 4096;

/// The confirmations already accepted, by sealed-state ID.
///
/// Each ID is kept for [`SEAL_TTL`] after it is spent, by which time the state
/// carrying it has expired anyway, and dropped on the next insert. At most
/// [`MAX_CONSUMED`] are kept: past that, the oldest is forgotten early, so
/// under that much confirmation traffic a spent state could be replayed once
/// more, but only within its own TTL.
#[derive(Debug, Default)]
pub(crate) struct ConsumedConfirmations(Mutex<Consumed>);

#[derive(Debug, Default)]
struct Consumed {
    ids: HashSet<String>,
    /// `(forget_at, id)`, oldest first.
    order: VecDeque<(Instant, String)>,
}

impl ConsumedConfirmations {
    /// Spends `id`, reporting `false` when it was already spent.
    fn consume(&self, id: &str) -> bool {
        self.consume_at(id, Instant::now())
    }

    fn consume_at(&self, id: &str, now: Instant) -> bool {
        // A panic elsewhere cannot leave the set inconsistent: every update
        // below completes or never starts, so a poisoned lock is still usable.
        let mut consumed = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        while consumed
            .order
            .front()
            .is_some_and(|(forget_at, _)| *forget_at <= now)
        {
            consumed.forget_oldest();
        }
        if consumed.ids.contains(id) {
            return false;
        }
        while consumed.order.len() >= MAX_CONSUMED {
            consumed.forget_oldest();
        }
        let forget_at = now.checked_add(SEAL_TTL).unwrap_or(now);
        consumed.ids.insert(id.to_owned());
        consumed.order.push_back((forget_at, id.to_owned()));
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ids
            .len()
    }
}

impl Consumed {
    fn forget_oldest(&mut self) {
        if let Some((_, id)) = self.order.pop_front() {
            self.ids.remove(&id);
        }
    }
}

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
/// call sealed as its `requestState` for [`SEAL_TTL`].
pub(super) fn confirmation_request(
    request: &CallToolRequestParams,
) -> Result<InputRequiredResult, ErrorData> {
    confirmation_request_sealed_for(request, SEAL_TTL)
}

/// [`confirmation_request`] with its state valid for `ttl`.
fn confirmation_request_sealed_for(
    request: &CallToolRequestParams,
    ttl: Duration,
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
                "id": Uuid::new_v4().to_string(),
                "tool": request.name,
                "args": request.arguments,
            }),
            &SealOptions::new()
                .ttl(ttl)
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

/// Checks a retry against the confirmation it answers, spending the state in
/// `consumed` when the user confirmed.
///
/// A protocol error when the state is tampered with, expired, sealed for
/// another tool or for other arguments, already spent, or when the
/// confirmation response is missing or malformed. Otherwise the user's
/// [`Verdict`]. A declined state is not spent: it can only be declined again.
pub(super) fn verify_confirmation(
    sealed: &str,
    request: &CallToolRequestParams,
    consumed: &ConsumedConfirmations,
) -> Result<Verdict, ErrorData> {
    let stale = || ErrorData::invalid_params(STALE_STATE, None);
    let state = codec()?
        .open_json_with::<Value>(sealed, request.name.as_bytes())
        .map_err(|_error| stale())?;
    let state = state.as_object().ok_or_else(stale)?;
    let id = state.get("id").and_then(Value::as_str).ok_or_else(stale)?;
    let sealed_arguments = state.get("args").cloned().ok_or_else(stale)?;
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
        ElicitationAction::Accept if confirmed => {
            if !consumed.consume(id) {
                return Err(ErrorData::invalid_params(SPENT_STATE, None));
            }
            Verdict::Confirmed
        }
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
            verify_confirmation(&sealed, &request, &ConsumedConfirmations::default())
                .expect("confirmation verifies"),
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
                    verify_confirmation(&sealed, &request, &ConsumedConfirmations::default()).expect("confirmation verifies"),
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
            verify_confirmation(&sealed, &request, &ConsumedConfirmations::default()).expect("confirmation verifies"),
            Verdict::Declined(reason) if reason.contains("accept")
        ));
    }

    #[test]
    fn tampered_sealed_state_is_rejected() {
        let request = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let mut sealed = sealed_for(&request);
        sealed.push('x');

        let error = verify_confirmation(&sealed, &request, &ConsumedConfirmations::default())
            .expect_err("tampered state must be rejected");
        assert_eq!(error.message, STALE_STATE);
    }

    #[test]
    fn state_sealed_for_a_different_tool_is_rejected() {
        let original = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let retry = request("myapp_create_item", json!({"id": 7}), accept(true));

        let error = verify_confirmation(
            &sealed_for(&original),
            &retry,
            &ConsumedConfirmations::default(),
        )
        .expect_err("state must be bound to its tool name");
        assert_eq!(error.message, STALE_STATE);
    }

    #[test]
    fn changed_arguments_are_rejected() {
        let original = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let retry = request("myapp_delete_item", json!({"id": 8}), accept(true));

        let error = verify_confirmation(
            &sealed_for(&original),
            &retry,
            &ConsumedConfirmations::default(),
        )
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

        let error = verify_confirmation(
            &sealed_for(&original),
            &retry,
            &ConsumedConfirmations::default(),
        )
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

    #[test]
    fn an_accepted_state_is_spent_and_a_declined_one_is_not() {
        let consumed = ConsumedConfirmations::default();
        let declined = request(
            "myapp_delete_item",
            json!({"id": 7}),
            json!({"action": "decline"}),
        );
        let accepted = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let sealed = sealed_for(&accepted);

        for _ in 0..2 {
            assert!(matches!(
                verify_confirmation(&sealed, &declined, &consumed),
                Ok(Verdict::Declined(_))
            ));
        }
        assert_eq!(consumed.len(), 0, "a decline spends nothing");
        assert_eq!(
            verify_confirmation(&sealed, &accepted, &consumed).expect("first accept verifies"),
            Verdict::Confirmed
        );
        let replay = verify_confirmation(&sealed, &accepted, &consumed)
            .expect_err("a spent state must be refused");
        assert_eq!(replay.message, SPENT_STATE);

        let fresh = sealed_for(&accepted);
        assert_eq!(
            verify_confirmation(&fresh, &accepted, &consumed).expect("a new state verifies"),
            Verdict::Confirmed,
            "each sealed state has its own ID"
        );
    }

    #[test]
    fn consumed_ids_are_forgotten_after_the_ttl() {
        let consumed = ConsumedConfirmations::default();
        let start = Instant::now();
        assert!(consumed.consume_at("a", start));
        assert!(!consumed.consume_at("a", start + SEAL_TTL / 2));
        assert!(consumed.consume_at("b", start + SEAL_TTL));
        assert_eq!(consumed.len(), 1, "\"a\" is pruned on the next insert");
        assert!(consumed.consume_at("a", start + SEAL_TTL));
    }

    #[test]
    fn consumed_ids_are_capped_by_forgetting_the_oldest() {
        let consumed = ConsumedConfirmations::default();
        let now = Instant::now();
        for index in 0..=MAX_CONSUMED {
            assert!(consumed.consume_at(&index.to_string(), now));
        }
        assert_eq!(consumed.len(), MAX_CONSUMED);
        assert!(!consumed.consume_at(&MAX_CONSUMED.to_string(), now));
        assert!(
            consumed.consume_at("0", now),
            "the oldest ID was forgotten to make room"
        );
    }

    #[test]
    fn a_poisoned_lock_still_records_consumption() {
        let consumed = ConsumedConfirmations::default();
        assert!(consumed.consume("before"));
        std::thread::scope(|scope| {
            let poisoner = scope.spawn(|| {
                let _guard = consumed.0.lock().unwrap();
                panic!("poison the lock");
            });
            assert!(poisoner.join().is_err());
        });
        assert!(consumed.0.is_poisoned());
        assert!(!consumed.consume("before"));
        assert!(consumed.consume("after"));
    }

    /// A state sealed with a short TTL is refused once it passes, through the
    /// same sealing path the production TTL takes.
    #[test]
    fn expired_state_is_rejected() {
        let request = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let sealed = confirmation_request_sealed_for(&request, Duration::from_millis(1))
            .expect("confirmation request builds")
            .request_state
            .expect("confirmation state is present");
        std::thread::sleep(Duration::from_millis(20));

        let error = verify_confirmation(&sealed, &request, &ConsumedConfirmations::default())
            .expect_err("an expired state must be rejected");
        assert_eq!(error.message, STALE_STATE);
    }

    /// The production state expires [`SEAL_TTL`] after sealing. rmcp's `rs1`
    /// state is `rs1.<body>.<tag>`, its body starting with the big-endian
    /// expiry in Unix milliseconds; authenticated, not encrypted, so readable.
    #[test]
    fn production_state_expires_after_the_seal_ttl() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        assert_eq!(SEAL_TTL, Duration::from_secs(300));
        let unix_ms = || {
            i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
        };
        let request = request("myapp_delete_item", json!({"id": 7}), accept(true));
        let before = unix_ms();
        let sealed = sealed_for(&request);
        let after = unix_ms();

        let mut parts = sealed.split('.');
        assert_eq!(parts.next(), Some("rs1"), "{sealed}");
        let body = URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap();
        let expiry = i64::from_be_bytes(body[..8].try_into().unwrap());
        let ttl_ms = i64::try_from(SEAL_TTL.as_millis()).unwrap();
        assert!(
            (before + ttl_ms..=after + ttl_ms).contains(&expiry),
            "expiry {expiry} is not {ttl_ms} ms after sealing ({before}..={after})"
        );
    }
}
