//! Redacts credentials from data before it is shown.
//!
//! [`Redacted`] is the only way to build presentable output: its constructor
//! serializes a value once and masks every credential it can find in it.
//! Values under credential-like keys, the user information of `http` and
//! `https` URLs, and credentials in free text all become
//! [`MASKED_VALUE`](crate::secret::MASKED_VALUE).
//! [`redact_text`](crate::redact::redact_text) applies the free-text rules to
//! one string, and [`ApiClient::redact`] also masks the exact secrets the
//! client holds, such as its API key. Redaction does not zero the original
//! allocation.

use std::borrow::Cow;
use std::marker::PhantomData;

use serde::Serialize;

mod free_text;
mod json;
mod secrets;
mod url;

pub(crate) use self::json::redact_json;
pub(crate) use self::secrets::{scrub_json_secrets, scrub_secret_representations};
pub use crate::secret::MASKED_VALUE;
use crate::secret::SecretString;

/// Data of type `T` that has passed through redaction exactly once.
///
/// [`Redacted::new`] is the only constructor; [`ApiClient::redact`] calls the
/// same code with the client's secrets. It serializes the data and redacts the
/// resulting JSON, so a `Redacted<T>` can never hold unredacted data. It
/// serializes as that redacted JSON and, with the `schema` feature, has
/// exactly `T`'s JSON schema, so an MCP tool returning `Json<Redacted<T>>`
/// advertises `T`'s output schema.
///
/// [`ApiClient::redact`]: crate::ApiClient::redact
///
/// # Examples
///
/// ```
/// use myapp_core::redact::Redacted;
///
/// # fn main() -> Result<(), serde_json::Error> {
/// let data = serde_json::json!({
///     "apiKey": "test-key",
///     "url": "https://user:hunter2@example.test/feed?passkey=abc",
///     "username": "operator"
/// });
/// let redacted = Redacted::new(&data)?;
///
/// assert_eq!(redacted.as_value()["apiKey"], "********");
/// assert_eq!(
///     redacted.as_value()["url"],
///     "https://user:********@example.test/feed?passkey=********"
/// );
/// assert_eq!(redacted.as_value()["username"], "operator");
/// # Ok(())
/// # }
/// ```
pub struct Redacted<T> {
    value: serde_json::Value,
    _type: PhantomData<fn() -> T>,
}

impl<T: Serialize> Redacted<T> {
    /// Serializes `data` once and redacts the result once.
    ///
    /// A non-string value under a credential-like key becomes the string
    /// [`MASKED_VALUE`]; the result is never decoded back into `T`.
    ///
    /// # Errors
    ///
    /// Returns the [`serde_json::Error`] when `data` cannot be serialized to
    /// JSON, such as a map with non-string keys.
    pub fn new(data: &T) -> Result<Self, serde_json::Error> {
        Self::scrubbing(data, &[])
    }

    /// [`Redacted::new`], also masking every exact representation of
    /// `secrets`.
    ///
    /// Exact secrets are scrubbed before redaction as well as after it: a
    /// free-text rule that masks only the start of a secret holding a
    /// delimiter, as in `password=hunter2&tail`, would otherwise leave its
    /// tail for the exact match to miss.
    pub(crate) fn scrubbing(data: &T, secrets: &[SecretString]) -> Result<Self, serde_json::Error> {
        let mut value = serde_json::to_value(data)?;
        scrub_json_secrets(&mut value, secrets);
        redact_json(&mut value);
        scrub_json_secrets(&mut value, secrets);
        Ok(Self {
            value,
            _type: PhantomData,
        })
    }
}

impl<T> Redacted<T> {
    /// Borrows the redacted JSON.
    #[must_use]
    pub const fn as_value(&self) -> &serde_json::Value {
        &self.value
    }
}

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("Redacted")
            .field(&self.value)
            .finish()
    }
}

impl<T> Serialize for Redacted<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}

#[cfg(feature = "schema")]
impl<T: schemars::JsonSchema> schemars::JsonSchema for Redacted<T> {
    fn schema_name() -> Cow<'static, str> {
        T::schema_name()
    }

    fn schema_id() -> Cow<'static, str> {
        T::schema_id()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        T::json_schema(generator)
    }

    fn inline_schema() -> bool {
        T::inline_schema()
    }
}

/// Masks credentials in free text.
///
/// The value after a sensitive key, or a compound or header name ending in
/// one, and a `=`, `:` or `:=` separator is masked wherever the key starts a
/// word, in a query or `;` pair, a header, a `key: value` pair split by
/// whitespace or an embedded JSON string, and so is the credential after an
/// `Authorization` header, each path segment after a sensitive path segment,
/// and the user information of `http` and `https` URLs. Use it for messages
/// built from result fields; [`Redacted::new`] already applies it to every
/// string it holds. Text that nothing in it could mask is borrowed without
/// being copied, and the work is linear in the length of the text.
///
/// # Examples
///
/// ```
/// use myapp_core::redact::redact_text;
///
/// assert_eq!(redact_text("rejected apikey=test-key"), "rejected apikey=********");
/// assert_eq!(redact_text("nothing to hide"), "nothing to hide");
/// ```
#[must_use]
pub fn redact_text(text: &str) -> Cow<'_, str> {
    free_text::redact_free_text(text)
}

/// The sensitive keys, in lower case.
const SENSITIVE_KEYS: [&str; 10] = [
    "apikey",
    "api_key",
    "apitoken",
    "password",
    "passwordconfirmation",
    "sslcertpassword",
    "proxypassword",
    "passkey",
    "secret",
    "token",
];

/// The length of the longest of the [`SENSITIVE_KEYS`].
const LONGEST_SENSITIVE_KEY: usize = {
    let mut longest = 0;
    let mut rest = SENSITIVE_KEYS.as_slice();
    while let [key, after @ ..] = rest {
        if key.len() > longest {
            longest = key.len();
        }
        rest = after;
    }
    longest
};

/// Matches a sensitive key, compared in any case.
fn is_sensitive_key(key: &str) -> bool {
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| key.eq_ignore_ascii_case(sensitive))
}

/// Matches an object key whose value is a credential: a sensitive key or an
/// `Authorization` or `Proxy-Authorization` header name, compared in any case.
///
/// The header names are not [`SENSITIVE_KEYS`], because free text keeps the
/// scheme after `Authorization:` visible and masks only the credential.
fn is_sensitive_object_key(key: &str) -> bool {
    is_sensitive_key(key) || free_text::is_authorization_name(key)
}

/// Matches a sensitive key, or a compound or header name that ends in one, in free text.
///
/// A leading `x-` or `x_` is dropped and the name is split into parts at
/// `-` and `_`. The name matches when its parts, or some trailing run of
/// them, joined, are a sensitive key, compared in any case. So `X-Api-Key`
/// names `apikey`, and `access_token` and `X-Auth-Token` end in `token`, but
/// `mytoken` and `authtoken` have no part boundary before `token`.
///
/// The name is read backwards, without `-` and `_`, into a buffer as long as
/// the longest sensitive key, and each trailing run that starts a part is
/// compared as it is read, so nothing is allocated.
pub(crate) fn is_sensitive_free_text_key(key: &str) -> bool {
    let name = key
        .get(..2)
        .filter(|prefix| prefix.eq_ignore_ascii_case("x-") || prefix.eq_ignore_ascii_case("x_"))
        .and_then(|_| key.get(2..))
        .unwrap_or(key);
    let bytes = name.as_bytes();
    let mut tail = [0_u8; LONGEST_SENSITIVE_KEY];
    let mut tail_start = tail.len();
    for (index, &byte) in bytes.iter().enumerate().rev() {
        if free_text::is_part_separator(byte) {
            continue;
        }
        let Some(start) = tail_start.checked_sub(1) else {
            return false;
        };
        tail_start = start;
        if let Some(slot) = tail.get_mut(start) {
            *slot = byte;
        }
        let starts_part = index
            .checked_sub(1)
            .and_then(|before| bytes.get(before))
            .is_none_or(|&before| free_text::is_part_separator(before));
        if starts_part
            && tail.get(start..).is_some_and(|run| {
                SENSITIVE_KEYS
                    .iter()
                    .any(|sensitive| sensitive.as_bytes().eq_ignore_ascii_case(run))
            })
        {
            return true;
        }
    }
    false
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::time::{Duration, Instant};

    use serde::Serialize;

    use super::free_text::mask_free_text;
    use super::{MASKED_VALUE, Redacted, redact_json, redact_text};
    use crate::SecretString;

    const SENTINEL: &str = "sentinel-secret";

    fn redacted_value<T: Serialize>(data: &T) -> serde_json::Value {
        serde_json::to_value(Redacted::new(data).expect("redaction succeeds"))
            .expect("redacted data serializes")
    }

    #[test]
    fn redacted_new_masks_every_kind_of_secret() {
        let data = serde_json::json!({
            "apiKey": "S",
            "message": "apikey=S",
            "url": "https://u:S@h",
            "feed": "https://h/passkey/S/rss",
            "embedded": r#"{"password":"S"}"#
        });

        assert_eq!(
            redacted_value(&data),
            serde_json::json!({
                "apiKey": "********",
                "message": "apikey=********",
                "url": "https://u:********@h",
                "feed": "https://h/passkey/********/rss",
                "embedded": r#"{"password":"********"}"#
            })
        );
    }

    #[test]
    fn redacted_new_masks_every_sensitive_object_key_in_any_case() {
        for key in [
            "apikey",
            "apiKey",
            "API_KEY",
            "apitoken",
            "password",
            "passwordConfirmation",
            "sslCertPassword",
            "proxyPassword",
            "passkey",
            "secret",
            "token",
            "Authorization",
            "proxy-authorization",
        ] {
            let data = serde_json::json!({ key: SENTINEL, "name": "visible" });
            assert_eq!(
                redacted_value(&data),
                serde_json::json!({ key: MASKED_VALUE, "name": "visible" }),
                "{key}"
            );
        }
    }

    #[test]
    fn redacted_new_masks_a_non_string_sensitive_value() {
        #[derive(Serialize)]
        struct Probe {
            token: u32,
        }

        let redacted = Redacted::new(&Probe { token: 7_u32 }).expect("redaction succeeds");

        assert_eq!(
            serde_json::to_string(&redacted).expect("redacted data serializes"),
            r#"{"token":"********"}"#
        );
    }

    #[test]
    fn redacted_new_keeps_a_present_null() {
        let data = serde_json::json!({ "name": null, "token": null });

        assert_eq!(redacted_value(&data), data);
    }

    #[test]
    fn redacted_new_masks_sensitive_keys_and_urls_at_any_depth() {
        let data = serde_json::json!({
            "nested": { "token": SENTINEL, "list": [{ "password": SENTINEL }] },
            "url": format!("https://example.invalid/apikey/{SENTINEL}?passkey={SENTINEL}"),
        });

        let value = redacted_value(&data);

        assert_eq!(value["nested"]["token"], MASKED_VALUE);
        assert_eq!(value["nested"]["list"][0]["password"], MASKED_VALUE);
        assert_eq!(
            value["url"],
            "https://example.invalid/apikey/********?passkey=********"
        );
        assert!(!value.to_string().contains(SENTINEL));
    }

    #[test]
    fn redacted_new_masks_each_log_line_on_its_own() {
        let data = serde_json::json!({
            "lines": ["token: S", "Authorization:", "next", "password=S", "keep this"]
        });

        assert_eq!(
            redacted_value(&data),
            serde_json::json!({
                "lines": ["token: ********", "Authorization:", "next", "password=********", "keep this"]
            })
        );
    }

    #[test]
    fn scrubbing_masks_a_secret_holding_a_delimiter_whole() {
        // Free text stops a `password=` value at `&` or a space, so only the
        // exact scrub before redaction keeps the tail from leaking.
        for secret in ["hunter2&strandedtail", "hunter2 strandedtail"] {
            let data = serde_json::json!({ "message": format!("rejected password={secret}") });
            let redacted = Redacted::scrubbing(&data, &[SecretString::from(secret)])
                .expect("redaction succeeds");
            assert_eq!(
                redacted.as_value()["message"],
                "rejected password=********",
                "{secret:?}"
            );
            assert!(!redacted.as_value().to_string().contains("strandedtail"));
        }
    }

    #[test]
    fn scrubbing_masks_a_secret_in_unkeyed_text() {
        let data = serde_json::json!({ "note": format!("the key is {SENTINEL}") });
        let redacted = Redacted::scrubbing(&data, &[SecretString::from(SENTINEL)])
            .expect("redaction succeeds");
        assert_eq!(redacted.as_value()["note"], "the key is ********");
    }

    #[cfg(feature = "schema")]
    #[test]
    fn redacted_schema_is_the_inner_schema() {
        assert_eq!(
            schemars::schema_for!(Redacted<crate::models::Item>),
            schemars::schema_for!(crate::models::Item)
        );
    }

    #[test]
    fn error_json_masks_sensitive_named_keys() {
        let mut error = serde_json::json!({
            "detail": {
                "apiKey": SENTINEL,
                "password": SENTINEL,
                "name": "visible"
            }
        });

        redact_json(&mut error);

        let serialized = serde_json::to_string(&error).unwrap();
        assert!(!serialized.contains(SENTINEL));
        assert_eq!(error["detail"]["name"], "visible");
    }

    #[test]
    fn structural_header_name_key_is_not_a_sensitive_key() {
        let mut value = serde_json::json!({ "X-Api-Key": "S" });

        redact_json(&mut value);

        assert_eq!(value, serde_json::json!({ "X-Api-Key": "S" }));
    }

    #[test]
    fn redact_text_borrows_text_it_does_not_change() {
        for text in [
            "nothing to hide",
            "Some.Show.S01E01.1080p.WEB-DL",
            "2026-10-27T12:00:00Z",
            "token expired",
        ] {
            assert!(
                matches!(redact_text(text), Cow::Borrowed(_)),
                "{text:?} is borrowed"
            );
        }
    }

    /// Redacts `input` with every free-text rule, bypassing the shortcut for
    /// text without a key word, and returns how long that took.
    fn time_free_text_rules(input: &str) -> Duration {
        let start = Instant::now();
        let redacted = mask_free_text(input);
        let elapsed = start.elapsed();
        assert_eq!(redacted, input, "hostile input comes back unchanged");
        elapsed
    }

    #[test]
    fn free_text_redaction_is_linear_on_hostile_inputs() {
        let spaced_long_urls =
            vec![format!("https://h.invalid/{}", "a".repeat(4077)); 16].join(" ");
        let glued_query_urls = format!("https://h.invalid/?q={}", "a".repeat(43)).repeat(1024);
        let url_before_words = format!(
            "https://h.invalid/{} {}",
            "a".repeat(200),
            "word ".repeat(13_107)
        );

        for (name, input) in [
            ("A: 16 spaced 4 KiB URLs", spaced_long_urls),
            ("B: 1,024 glued query URLs", glued_query_urls),
            ("C: one URL before 64 KiB of words", url_before_words),
        ] {
            let elapsed = time_free_text_rules(&input);
            eprintln!("{name}: {} bytes in {elapsed:?}", input.len());
            assert!(
                elapsed < Duration::from_millis(500),
                "{name} took {elapsed:?}"
            );
            assert!(matches!(redact_text(&input), Cow::Borrowed(_)));
        }
    }

    #[test]
    fn search_sized_result_redacts_quickly() {
        let releases = (1..=100)
            .map(|release| {
                let download = format!(
                    "http://myapp:8080/1/download?apikey=k&link={}&file=Some.Show.S01E{release:02}",
                    "A".repeat(600)
                );
                let trackers = (1..=15)
                    .map(|tracker| format!("&tr=http://tracker{tracker}.example:80/announce"))
                    .collect::<String>();
                serde_json::json!({
                    "title": format!("Some.Show.S01E{release:02}.1080p.WEB-DL.x264-GROUP"),
                    "guid": download,
                    "downloadUrl": download,
                    "infoUrl": format!("https://tracker.example/details/{}", "A".repeat(600)),
                    "magnetUrl": format!("magnet:?xt=urn:btih:{}&dn=x{trackers}", "f".repeat(40)),
                })
            })
            .collect::<Vec<_>>();
        let releases = serde_json::Value::Array(releases);

        let start = Instant::now();
        let redacted = Redacted::new(&releases).expect("redaction succeeds");
        let elapsed = start.elapsed();

        eprintln!(
            "search result: {} bytes in {elapsed:?}",
            releases.to_string().len()
        );
        assert!(elapsed < Duration::from_secs(1), "took {elapsed:?}");
        let redacted = redacted.as_value().to_string();
        assert_eq!(redacted.matches("apikey=********").count(), 200);
        assert!(!redacted.contains("apikey=k"));
    }

    /// Free-text redaction cases: a name, an input and its expected output.
    const FREE_TEXT_CASES: &[(&str, &str, &str)] = &[
        (
            "redact_text_masks_a_pair_and_url_user_info",
            "rejected apikey=S and https://u:S@h",
            "rejected apikey=******** and https://u:********@h",
        ),
        (
            "url_query_value_after_a_sensitive_key_is_masked",
            "https://example.invalid/download?name=visible&ApiKey=sentinel-secret#fragment",
            "https://example.invalid/download?name=visible&ApiKey=********#fragment",
        ),
        (
            "url_path_segments_after_a_sensitive_segment_are_masked",
            "https://example.invalid/Token/sentinel-secret/release?name=visible#fragment",
            "https://example.invalid/Token/********/********?name=visible#fragment",
        ),
        (
            "url_query_key_containing_a_sensitive_key_is_unchanged",
            "https://example.invalid/download?notapikey=visible#fragment",
            "https://example.invalid/download?notapikey=visible#fragment",
        ),
        (
            "embedded_sensitive_query_url_preserves_delimited_diagnostic_prose",
            "request to \"https://example.invalid/check?name=visible&apiKey=sentinel-secret\" failed",
            "request to \"https://example.invalid/check?name=visible&apiKey=********\" failed",
        ),
        (
            "embedded_sensitive_path_url_preserves_delimited_diagnostic_prose",
            "request to (https://example.invalid/token/sentinel-secret), failed",
            "request to (https://example.invalid/token/********), failed",
        ),
        (
            "ambiguous_matched_punctuation_stays_in_sensitive_url_token",
            "request to (https://example.invalid/token/sentinel-secret)continued failed",
            "request to (https://example.invalid/token/******** failed",
        ),
        (
            "mixed_http_url_redacts_legacy_sensitive_prefix_and_suffix",
            "ftp://legacy.invalid/token/legacy-prefix-secret/before https://example.invalid/check?apiKey=http-query-secret after ftp://legacy.invalid/token/legacy-suffix-secret",
            "ftp://legacy.invalid/token/********/******** https://example.invalid/check?apiKey=******** after ftp://legacy.invalid/token/********",
        ),
        (
            "multiple_case_insensitive_http_urls_redact_legacy_interstitial_content",
            "HTTPS://one.invalid/check?ApiKey=first-http-secret then ftp://legacy.invalid/token/legacy-middle-secret/middle HtTp://two.invalid/Token/second-http-secret",
            "HTTPS://one.invalid/check?ApiKey=******** then ftp://legacy.invalid/token/********/******** HtTp://two.invalid/Token/********",
        ),
        (
            "adjacent_quoted_mixed_case_query_urls_are_redacted_independently",
            "\"https://one.invalid?name=visible\",\"HtTpS://two.invalid/check?apiKey=adjacent-query-secret\" failed",
            "\"https://one.invalid?name=visible\",\"HtTpS://two.invalid/check?apiKey=********\" failed",
        ),
        (
            "adjacent_matched_delimiter_path_urls_are_redacted_independently",
            "(https://one.invalid?name=visible);[HTTPS://two.invalid/token/adjacent-path-secret], failed",
            "(https://one.invalid?name=visible);[HTTPS://two.invalid/token/********], failed",
        ),
        (
            "adjacent_unquoted_query_urls_are_redacted_independently",
            "https://one.invalid/path?name=visible,https://two.invalid/check?apiKey=adjacent-query-secret failed",
            "https://one.invalid/path?name=visible,https://two.invalid/check?apiKey=******** failed",
        ),
        (
            "adjacent_unquoted_path_urls_are_redacted_independently",
            "https://one.invalid/path?name=visible;HTTPS://two.invalid/token/adjacent-path-secret failed",
            "https://one.invalid/path?name=visible;HTTPS://two.invalid/token/******** failed",
        ),
        (
            "nested_scheme_inside_sensitive_query_value_is_masked_as_one_value",
            "https://one.invalid?apiKey=prefixhttps://two.invalid?name=visible failed",
            "https://one.invalid?apiKey=******** failed",
        ),
        (
            "nested_scheme_inside_sensitive_path_value_masks_the_remaining_url",
            "https://one.invalid/token/prefixhttps://two.invalid?name=visible failed",
            "https://one.invalid/token/******** failed",
        ),
        (
            "unmatched_single_quote_stays_inside_a_sensitive_query_value",
            "request to https://example.invalid/check?apiKey=sentinel-secret'continued failed",
            "request to https://example.invalid/check?apiKey=******** failed",
        ),
        (
            "unmatched_double_quote_stays_inside_a_sensitive_query_value",
            "request to https://example.invalid/check?apiKey=sentinel-secret\"continued failed",
            "request to https://example.invalid/check?apiKey=******** failed",
        ),
        (
            "unmatched_backtick_stays_inside_a_sensitive_query_value",
            "request to https://example.invalid/check?apiKey=sentinel-secret`continued failed",
            "request to https://example.invalid/check?apiKey=******** failed",
        ),
        (
            "unmatched_less_than_sign_stays_inside_a_sensitive_query_value",
            "request to https://example.invalid/check?apiKey=sentinel-secret<continued failed",
            "request to https://example.invalid/check?apiKey=******** failed",
        ),
        (
            "unmatched_greater_than_sign_stays_inside_a_sensitive_query_value",
            "request to https://example.invalid/check?apiKey=sentinel-secret>continued failed",
            "request to https://example.invalid/check?apiKey=******** failed",
        ),
        (
            "unmatched_single_quote_stays_inside_a_sensitive_path_segment",
            "request to https://example.invalid/token/sentinel-secret'continued failed",
            "request to https://example.invalid/token/******** failed",
        ),
        (
            "unmatched_double_quote_stays_inside_a_sensitive_path_segment",
            "request to https://example.invalid/token/sentinel-secret\"continued failed",
            "request to https://example.invalid/token/******** failed",
        ),
        (
            "unmatched_backtick_stays_inside_a_sensitive_path_segment",
            "request to https://example.invalid/token/sentinel-secret`continued failed",
            "request to https://example.invalid/token/******** failed",
        ),
        (
            "unmatched_less_than_sign_stays_inside_a_sensitive_path_segment",
            "request to https://example.invalid/token/sentinel-secret<continued failed",
            "request to https://example.invalid/token/******** failed",
        ),
        (
            "unmatched_greater_than_sign_stays_inside_a_sensitive_path_segment",
            "request to https://example.invalid/token/sentinel-secret>continued failed",
            "request to https://example.invalid/token/******** failed",
        ),
        (
            "sensitive_key_after_a_question_mark_in_the_fragment_is_masked",
            "https://example.invalid/path#next?token=visible",
            "https://example.invalid/path#next?token=********",
        ),
        (
            "scheme_less_query_value_is_masked_without_dropping_the_rest_of_the_text",
            "[GET] /api/v1/system/status?apikey=(removed): 200.OK (3 ms)\nsecond line\nthird line",
            "[GET] /api/v1/system/status?apikey=******** 200.OK (3 ms)\nsecond line\nthird line",
        ),
        (
            "scheme_less_query_value_is_masked_and_the_prose_after_it_kept",
            "GET /api?apikey=SECRET1 returned 401 Unauthorized",
            "GET /api?apikey=******** returned 401 Unauthorized",
        ),
        (
            "scheme_less_query_value_is_masked_after_a_question_mark_on_an_earlier_line",
            "see ?x=1\nGET /api/v1/item?apikey=SECRET3&t=1",
            "see ?x=1\nGET /api/v1/item?apikey=********&t=1",
        ),
        (
            "scheme_less_query_value_is_masked_after_a_hash_on_an_earlier_line",
            "issue #12\nGET /api?apikey=SECRET4",
            "issue #12\nGET /api?apikey=********",
        ),
        (
            "scheme_less_query_value_is_masked_after_a_question_mark_on_the_same_line",
            "see ?x=1 then /api?apikey=SECRET5",
            "see ?x=1 then /api?apikey=********",
        ),
        (
            "scheme_less_path_segment_is_masked_after_an_earlier_question_mark",
            "what? GET /api/token/SECRET6",
            "what? GET /api/token/********",
        ),
        (
            "scheme_less_path_segment_is_masked_after_an_earlier_hash",
            "issue #12 GET /api/token/SECRET7",
            "issue #12 GET /api/token/********",
        ),
        (
            "scheme_less_path_segment_is_masked_and_the_prose_after_it_kept",
            "GET /api/token/SECRET8 failed for item Foo",
            "GET /api/token/******** failed for item Foo",
        ),
        (
            "scheme_less_query_value_before_an_http_url_is_masked_after_an_earlier_question_mark",
            "see ?x=1 /api?apikey=SECRET9 then https://example.invalid/ok",
            "see ?x=1 /api?apikey=******** then https://example.invalid/ok",
        ),
        (
            "http_url_query_value_is_masked_and_the_prose_after_it_kept",
            "GET https://h.invalid/api?apikey=SECRET10 returned 401",
            "GET https://h.invalid/api?apikey=******** returned 401",
        ),
        (
            "scheme_less_token_redaction_keeps_every_whitespace_character",
            " \tGET /api?apikey=SECRET1\r\n  /api/token/SECRET2\rnext\t\tline\n",
            " \tGET /api?apikey=********\r\n  /api/token/********\rnext\t\tline\n",
        ),
        (
            "sensitive_pair_after_whitespace_in_a_query_is_masked",
            "GET /api?q=a b&apikey=SECRETB1",
            "GET /api?q=a b&apikey=********",
        ),
        (
            "sensitive_pair_on_the_line_after_its_query_is_masked",
            "?x=1\n&apikey=SECRETB2",
            "?x=1\n&apikey=********",
        ),
        (
            "sensitive_pair_in_a_token_without_a_question_mark_is_masked",
            "see ?x=1 then GET /api&apikey=SECRETB3",
            "see ?x=1 then GET /api&apikey=********",
        ),
        (
            "sensitive_pair_before_a_later_question_mark_in_the_token_is_masked",
            "see ?a b&apikey=SECRETB4?y=1",
            "see ?a b&apikey=********",
        ),
        (
            "sensitive_pair_split_from_its_query_before_an_http_url_is_masked",
            "GET /api?q=a b&apikey=SECRETB5 then https://example.invalid/ok",
            "GET /api?q=a b&apikey=******** then https://example.invalid/ok",
        ),
        (
            "sensitive_pair_after_an_unencoded_space_in_a_search_query_is_masked",
            "GET /api/v1/search?query=hello world&apikey=SECRETB6&t=1",
            "GET /api/v1/search?query=hello world&apikey=********&t=1",
        ),
        (
            "sensitive_password_pair_split_from_its_query_is_masked",
            "?q=x y&password=SECRETB8",
            "?q=x y&password=********",
        ),
        (
            "question_mark_inside_a_split_off_sensitive_value_is_masked_with_it",
            "?q=a b&apikey=AB?SECRET",
            "?q=a b&apikey=********",
        ),
        (
            "question_mark_inside_a_split_off_password_is_masked_up_to_the_next_pair",
            "?q=a b&password=pa?SECRETss&t=1",
            "?q=a b&password=********&t=1",
        ),
        (
            "question_mark_inside_a_split_off_search_query_api_key_is_masked_with_it",
            "GET /api/v1/search?query=hello world&apikey=abc?SECRET",
            "GET /api/v1/search?query=hello world&apikey=********",
        ),
        (
            "split_off_sensitive_value_starting_with_a_question_mark_is_masked",
            "? &token=?SECRET",
            "? &token=********",
        ),
        (
            "sensitive_pairs_on_both_sides_of_a_hash_are_masked_and_the_fragment_kept",
            "a&apikey=S#frag&token=T",
            "a&apikey=********#frag&token=********",
        ),
        (
            "sensitive_pair_in_prose_is_masked_as_an_accepted_over_mask",
            "Q&A&token=notasecret",
            "Q&A&token=********",
        ),
        (
            "sensitive_pair_starting_a_token_is_masked",
            "apikey=SECRET&t=1",
            "apikey=********&t=1",
        ),
        (
            "both_sensitive_path_segments_after_other_free_text_are_masked",
            "GET token/apikey/SECRETA1",
            "GET token/********/********",
        ),
        (
            "both_sensitive_path_segments_in_a_path_are_masked",
            "/api/token/apikey/SECRETA2",
            "/api/token/********/********",
        ),
        (
            "sensitive_path_segment_ending_a_sensitive_pair_masks_the_next_pair_value",
            "a&apikey=k/token/&x=SECRETA3",
            "a&apikey=********&x=********",
        ),
        (
            "sensitive_path_segment_ending_a_leading_pair_masks_the_next_pair_with_it",
            "apikey=k/token/&SECRET=1",
            "apikey=********",
        ),
        (
            "sensitive_path_segment_ending_a_sensitive_value_masks_the_piece_after_it",
            "&token=/password/&SECRETA4",
            "&token=********",
        ),
        (
            "sensitive_path_segment_after_a_value_prefix_masks_the_piece_after_it",
            "a&token=x/apikey/&SECRETA5",
            "a&token=********",
        ),
        (
            "sensitive_pair_starting_the_free_text_is_masked",
            "apikey=SECRETB1&t=1",
            "apikey=********&t=1",
        ),
        (
            "sensitive_pair_after_free_text_ending_in_a_question_mark_is_masked",
            "what? apikey=SECRETB2",
            "what? apikey=********",
        ),
        (
            "sensitive_pair_inside_free_text_is_masked_and_the_rest_kept",
            "failed with apikey=SECRETB3 for item Foo",
            "failed with apikey=******** for item Foo",
        ),
        (
            "sensitive_key_spaced_from_its_equals_sign_is_masked",
            "apikey =SECRETB4",
            "apikey =********",
        ),
        (
            "sensitive_key_spaced_on_both_sides_of_its_equals_sign_is_masked",
            "apikey = SECRET",
            "apikey = ********",
        ),
        (
            "sensitive_header_name_spaced_on_both_sides_of_its_equals_sign_is_masked",
            "X-Api-Key = SECRET",
            "X-Api-Key = ********",
        ),
        (
            "sensitive_pair_after_an_html_escaped_ampersand_is_masked",
            "/api?x=1&amp;apikey=SECRETB5",
            "/api?x=1&amp;apikey=********",
        ),
        (
            "semicolon_inside_a_pair_value_after_an_html_escaped_ampersand_is_masked_with_it",
            "/api?x=1&amp;apikey=a;SECRET",
            "/api?x=1&amp;apikey=********",
        ),
        (
            "sensitive_pair_between_semicolons_is_masked_up_to_the_next_semicolon",
            "/api;apikey=SECRETB6;x=1",
            "/api;apikey=********;x=1",
        ),
        (
            "sensitive_pair_after_a_semicolon_in_a_query_is_masked",
            "/api?x=1;apikey=SECRETB7",
            "/api?x=1;apikey=********",
        ),
        (
            "sensitive_pair_introduced_by_a_semicolon_ends_at_the_next_semicolon",
            "/api;apikey=S;x=1",
            "/api;apikey=********;x=1",
        ),
        (
            "sensitive_pair_introduced_by_a_semicolon_after_a_query_runs_to_the_token_end",
            "/api?x=1;apikey=S",
            "/api?x=1;apikey=********",
        ),
        (
            "semicolon_inside_a_query_pair_value_is_masked_with_it",
            "?password=abc;def",
            "?password=********",
        ),
        (
            "semicolon_inside_a_leading_pair_value_is_masked_up_to_the_next_pair",
            "apikey=a;b&t=1",
            "apikey=********&t=1",
        ),
        (
            "semicolon_starting_a_query_pair_value_is_masked_with_it",
            "token?token=;:SECRET",
            "token?token=********",
        ),
        (
            "header_value_after_a_sensitive_header_name_is_masked",
            "X-Api-Key: SECRETC1",
            "X-Api-Key: ********",
        ),
        (
            "value_after_a_sensitive_key_and_colon_is_masked",
            "apikey: SECRETC2",
            "apikey: ********",
        ),
        (
            "authorization_credential_is_masked_and_its_scheme_kept",
            "Authorization: Bearer SECRETC3",
            "Authorization: Bearer ********",
        ),
        (
            "authorization_header_and_scheme_match_in_any_case",
            "authorization: bearer SECRET",
            "authorization: bearer ********",
        ),
        (
            "authorization_credential_after_basic_is_masked_and_the_scheme_kept",
            "Authorization: Basic SECRET",
            "Authorization: Basic ********",
        ),
        (
            "authorization_credential_after_digest_is_masked_and_the_scheme_kept",
            "Authorization: Digest SECRET",
            "Authorization: Digest ********",
        ),
        (
            "authorization_credential_after_token_is_masked_and_the_scheme_kept",
            "Authorization: token SECRET",
            "Authorization: token ********",
        ),
        (
            "authorization_value_without_a_scheme_is_masked",
            "Authorization: SECRET",
            "Authorization: ********",
        ),
        (
            "sensitive_header_name_pair_inside_free_text_is_masked",
            "header X-Api-Key=SECRETC4 rejected",
            "header X-Api-Key=******** rejected",
        ),
        (
            "sensitive_key_and_colon_in_one_token_is_masked",
            "apikey:SECRET",
            "apikey:********",
        ),
        (
            "sensitive_header_name_and_colon_in_one_token_is_masked_up_to_the_next_pair",
            "X-Api-Key:SECRET&t=1",
            "X-Api-Key:********&t=1",
        ),
        (
            "colon_after_a_sensitive_key_in_a_query_is_not_a_separator",
            "/api?apikey:x",
            "/api?apikey:x",
        ),
        (
            "compact_embedded_json_sensitive_value_is_masked",
            r#"{"apikey":"SECRETD1"}"#,
            r#"{"apikey":"********"}"#,
        ),
        (
            "spaced_embedded_json_sensitive_value_is_masked_and_the_rest_kept",
            r#"response body {"apiKey": "SECRETD2", "ok": false}"#,
            r#"response body {"apiKey": "********", "ok": false}"#,
        ),
        (
            "embedded_json_sensitive_value_with_an_escaped_quote_is_masked_whole",
            r#"{"apikey": "a\"SECRET", "ok": false}"#,
            r#"{"apikey": "********", "ok": false}"#,
        ),
        (
            "embedded_json_sensitive_value_ending_in_an_escaped_backslash_is_masked",
            r#"{"apikey": "S\\"}"#,
            r#"{"apikey": "********"}"#,
        ),
        (
            "embedded_json_escaped_backslash_before_a_quote_ends_the_masked_value",
            r#"{"apikey": "a\\"}, "ok": "S"}"#,
            r#"{"apikey": "********"}, "ok": "S"}"#,
        ),
        (
            "embedded_json_escaped_quote_inside_a_sensitive_value_is_masked_with_it",
            r#"{"apikey": "a\"b"}"#,
            r#"{"apikey": "********"}"#,
        ),
        (
            "embedded_json_quote_after_three_backslashes_is_masked_with_the_value",
            r#"{"apikey": "a\\\"SECRET"}"#,
            r#"{"apikey": "********"}"#,
        ),
        (
            "embedded_json_sensitive_key_matches_in_any_case",
            r#"response {"Token": "SECRET"} rejected"#,
            r#"response {"Token": "********"} rejected"#,
        ),
        (
            "unterminated_embedded_json_sensitive_value_is_unchanged",
            r#"{"apikey": "SECRET"#,
            r#"{"apikey": "SECRET"#,
        ),
        (
            "non_string_embedded_json_sensitive_value_is_unchanged",
            r#"{"apikey": 12345}"#,
            r#"{"apikey": 12345}"#,
        ),
        (
            "sensitive_pair_after_a_second_question_mark_in_a_token_is_masked",
            "/a?x=1,/b?apikey=SECRETE1",
            "/a?x=1,/b?apikey=********",
        ),
        (
            "sensitive_pair_in_a_nested_redirect_query_is_masked",
            "/x?redirect=/x?apikey=SECRETE2",
            "/x?redirect=/x?apikey=********",
        ),
        (
            "sensitive_pair_after_a_hash_in_a_token_is_masked",
            "see#/api?apikey=SECRETE3",
            "see#/api?apikey=********",
        ),
        (
            "sensitive_path_segment_after_a_question_mark_is_masked",
            "x?/api/token/SECRETE4",
            "x?/api/token/********",
        ),
        (
            "harmless_value_after_a_sensitive_key_and_equals_sign_is_masked",
            "token=abc processed 3 items",
            "token=******** processed 3 items",
        ),
        (
            "harmless_word_after_a_sensitive_key_and_colon_is_masked",
            "password: reset sent",
            "password: ******** sent",
        ),
        (
            "whitespace_around_a_masked_value_after_a_sensitive_key_is_kept",
            "apikey:\t SECRET\nnext line",
            "apikey:\t ********\nnext line",
        ),
        (
            "sensitive_key_without_a_separator_is_unchanged",
            "token expired",
            "token expired",
        ),
        (
            "colon_after_a_harmless_key_is_unchanged",
            "Item key: value pairs are fine",
            "Item key: value pairs are fine",
        ),
        (
            "free_text_with_an_ampersand_and_a_bare_sensitive_key_is_unchanged",
            "Q&A session, password reset sent",
            "Q&A session, password reset sent",
        ),
        (
            "path_split_by_a_newline_is_unchanged",
            "/api/token/\nS",
            "/api/token/\nS",
        ),
        (
            "empty_sensitive_query_value_before_whitespace_masks_only_up_to_the_whitespace",
            "?apikey= S",
            "?apikey=******** S",
        ),
        (
            "http_url_sensitive_pair_after_whitespace_in_its_query_is_masked",
            "https://h.invalid/api?q=a b&apikey=S",
            "https://h.invalid/api?q=a b&apikey=********",
        ),
        (
            "scheme_less_query_value_before_a_status_code_is_masked",
            "GET /api?apikey=S returned 401",
            "GET /api?apikey=******** returned 401",
        ),
        (
            "http_url_standing_alone_in_free_text_keeps_its_query_masking",
            "see https://h.invalid/api?apikey=SECRET now",
            "see https://h.invalid/api?apikey=******** now",
        ),
        (
            "http_url_value_glued_to_a_sensitive_key_is_masked",
            "token=https://h/SECRET",
            "token=********",
        ),
        (
            "http_url_value_glued_to_a_sensitive_key_after_a_newline_is_masked",
            "x\ntoken=https://h/SECRET",
            "x\ntoken=********",
        ),
        (
            "http_url_value_glued_to_a_sensitive_key_after_a_tab_is_masked",
            "x\ttoken=https://h/SECRET",
            "x\ttoken=********",
        ),
        (
            "http_url_value_glued_to_a_sensitive_key_is_masked_up_to_the_next_pair",
            "apikey=https://h.invalid/SECRET&t=1",
            "apikey=********&t=1",
        ),
        (
            "http_url_value_glued_to_a_sensitive_header_name_is_masked",
            "X-Api-Key=https://h/SECRET",
            "X-Api-Key=********",
        ),
        (
            "http_url_value_glued_to_a_sensitive_key_inside_free_text_is_masked",
            "failed with password=http://h/SECRET for item",
            "failed with password=******** for item",
        ),
        (
            "http_url_value_of_a_semicolon_pair_is_masked_up_to_the_next_semicolon",
            "/api;apikey=https://h/SECRET;x=1",
            "/api;apikey=********;x=1",
        ),
        (
            "http_url_value_glued_to_a_sensitive_key_and_colon_is_masked",
            "apikey:https://h/SECRET",
            "apikey:********",
        ),
        (
            "http_url_glued_after_a_sensitive_path_segment_is_masked",
            "/api/token/https://h/SECRET",
            "/api/token/********",
        ),
        (
            "url_user_info_password_is_masked_and_username_kept",
            "https://user:sentinel-secret@example.invalid/path",
            "https://user:********@example.invalid/path",
        ),
        (
            "url_user_info_bare_token_is_masked",
            "https://sentinel-secret@example.invalid",
            "https://********@example.invalid",
        ),
        (
            "url_user_info_is_masked_for_uppercase_scheme",
            "HTTPS://u:sentinel-secret@example.invalid",
            "HTTPS://u:********@example.invalid",
        ),
        (
            "url_user_info_is_masked_inside_diagnostic_prose",
            "request to https://user:sentinel-secret@example.invalid/check failed",
            "request to https://user:********@example.invalid/check failed",
        ),
        (
            "url_user_info_and_sensitive_query_are_both_masked",
            "https://user:sentinel-secret@example.invalid/check?name=visible&apikey=query-secret",
            "https://user:********@example.invalid/check?name=visible&apikey=********",
        ),
        (
            "at_signs_outside_the_url_authority_are_unchanged",
            "https://example.invalid/@name?x=a@b",
            "https://example.invalid/@name?x=a@b",
        ),
        (
            "url_user_info_ends_at_the_last_at_sign_of_the_authority",
            "https://u:p@ss@example.invalid",
            "https://u:********@example.invalid",
        ),
        (
            "compound_key_with_an_underscore_header_prefix_is_masked",
            "x_api_key=SECRET",
            "x_api_key=********",
        ),
        (
            "upper_case_compound_key_and_colon_in_one_token_is_masked",
            "X_API_KEY:SECRET",
            "X_API_KEY:********",
        ),
        (
            "header_name_ending_in_a_sensitive_key_is_masked",
            "X-Auth-Token: SECRET",
            "X-Auth-Token: ********",
        ),
        (
            "compound_key_ending_in_token_is_masked",
            "access_token=SECRET",
            "access_token=********",
        ),
        (
            "compound_key_ending_in_token_and_a_colon_is_masked",
            "refresh_token: SECRET",
            "refresh_token: ********",
        ),
        (
            "compound_key_ending_in_secret_is_masked",
            "client_secret=SECRET",
            "client_secret=********",
        ),
        (
            "header_name_api_key_is_masked",
            "X-Api-Key=SECRET",
            "X-Api-Key=********",
        ),
        (
            "header_name_ending_in_token_is_masked",
            "X-Auth-Token=SECRET",
            "X-Auth-Token=********",
        ),
        (
            "refresh_token_pair_is_masked",
            "refresh_token=SECRET",
            "refresh_token=********",
        ),
        (
            "proxy_password_pair_is_masked",
            "proxy_password=SECRET",
            "proxy_password=********",
        ),
        (
            "hyphenated_compound_api_key_is_masked",
            "my-apikey=SECRET",
            "my-apikey=********",
        ),
        (
            "compound_key_ending_in_a_sensitive_key_is_masked_as_an_accepted_over_mask",
            "next_page_token=2",
            "next_page_token=********",
        ),
        (
            "sensitive_key_glued_to_a_word_is_unchanged",
            "mytoken=x",
            "mytoken=x",
        ),
        (
            "sensitive_key_glued_to_another_key_is_unchanged",
            "authtoken=x",
            "authtoken=x",
        ),
        (
            "authorization_scheme_glued_to_its_colon_is_kept_and_the_credential_masked",
            "Authorization:Bearer SECRET",
            "Authorization:Bearer ********",
        ),
        (
            "authorization_colon_spaced_on_both_sides_masks_the_credential",
            "Authorization : Bearer SECRET",
            "Authorization : Bearer ********",
        ),
        (
            "authorization_colon_glued_to_the_scheme_after_a_space_masks_the_credential",
            "Authorization :Bearer SECRET",
            "Authorization :Bearer ********",
        ),
        (
            "authorization_colon_between_tabs_masks_the_credential",
            "Authorization\t:\t Bearer SECRET",
            "Authorization\t:\t Bearer ********",
        ),
        (
            "authorization_ntlm_scheme_is_kept_and_the_credential_masked",
            "Authorization: NTLM SECRET",
            "Authorization: NTLM ********",
        ),
        (
            "authorization_negotiate_scheme_is_kept_and_the_credential_masked",
            "Authorization: Negotiate SECRET",
            "Authorization: Negotiate ********",
        ),
        (
            "authorization_word_that_is_not_only_letters_is_masked_with_the_token_after_it",
            "Authorization: Bearer: SECRET",
            "Authorization: ******** ********",
        ),
        (
            "proxy_authorization_scheme_is_kept_and_the_credential_masked",
            "Proxy-Authorization: Basic SECRET",
            "Proxy-Authorization: Basic ********",
        ),
        (
            "embedded_json_authorization_value_is_masked_whole",
            r#"{"Authorization": "Bearer SECRET"}"#,
            r#"{"Authorization": "********"}"#,
        ),
        (
            "authorization_letters_only_credential_before_more_text_is_read_as_a_scheme",
            "Authorization: abcdef rejected",
            "Authorization: abcdef ********",
        ),
        (
            "authorization_word_with_the_token_after_it_on_the_next_line_masks_both",
            "Authorization: Bearer\nSECRET",
            "Authorization: ********\n********",
        ),
        (
            "authorization_word_with_the_token_after_it_past_a_carriage_return_masks_both",
            "Authorization: Bearer\r SECRET9",
            "Authorization: ********\r ********",
        ),
        (
            "authorization_credential_before_a_vertical_tab_masks_both",
            "Authorization: SECRET\u{0b}more",
            "Authorization: ********\u{0b}********",
        ),
        (
            "authorization_credential_before_a_form_feed_masks_both",
            "Authorization: SECRET\u{0c}more",
            "Authorization: ********\u{0c}********",
        ),
        (
            "authorization_credential_before_a_next_line_masks_both",
            "Authorization: SECRET\u{85}more",
            "Authorization: ********\u{85}********",
        ),
        (
            "authorization_credential_before_a_line_separator_masks_both",
            "Authorization: SECRET\u{2028}more",
            "Authorization: ********\u{2028}********",
        ),
        (
            "authorization_credential_before_a_paragraph_separator_masks_both",
            "Authorization: SECRET\u{2029}more",
            "Authorization: ********\u{2029}********",
        ),
        (
            "proxy_authorization_credential_before_a_line_separator_masks_both",
            "Proxy-Authorization: SECRET\u{2028}more",
            "Proxy-Authorization: ********\u{2028}********",
        ),
        (
            "authorization_credential_masks_the_first_token_of_the_next_line_too",
            "Authorization: SECRET\nnext line",
            "Authorization: ********\n******** line",
        ),
        (
            "authorization_credential_glued_to_its_colon_is_masked",
            "Authorization:SECRET",
            "Authorization:********",
        ),
        (
            "proxy_authorization_credential_glued_to_its_colon_is_masked",
            "Proxy-Authorization:SECRET",
            "Proxy-Authorization:********",
        ),
        (
            "authorization_after_an_opening_parenthesis_masks_the_credential",
            "(Authorization: Bearer SECRET)",
            "(Authorization: Bearer ********)",
        ),
        (
            "sensitive_key_after_an_opening_parenthesis_keeps_the_closing_one",
            "(apikey: SECRET)",
            "(apikey: ********)",
        ),
        (
            "sensitive_pair_after_an_opening_parenthesis_keeps_the_closing_one",
            "foo(apikey=S)",
            "foo(apikey=********)",
        ),
        (
            "sensitive_pair_after_a_comma_is_masked",
            "foo,apikey=SECRET",
            "foo,apikey=********",
        ),
        (
            "sensitive_pair_after_a_hash_glued_to_a_word_is_masked",
            "x#token=SECRET",
            "x#token=********",
        ),
        (
            "sensitive_pair_after_non_ascii_text_is_masked",
            "日本apikey=SECRET",
            "日本apikey=********",
        ),
        (
            "sensitive_pair_after_a_double_quote_is_masked",
            "x\"apikey=SECRET",
            "x\"apikey=********",
        ),
        (
            "sensitive_pair_after_a_single_quote_is_masked",
            "x'apikey=SECRET",
            "x'apikey=********",
        ),
        (
            "sensitive_pair_after_a_dot_is_masked",
            "x.apikey=SECRET",
            "x.apikey=********",
        ),
        (
            "sensitive_pair_after_a_slash_is_masked",
            "x/apikey=SECRET",
            "x/apikey=********",
        ),
        (
            "sensitive_pair_after_an_opening_bracket_is_masked",
            "x[apikey=SECRET",
            "x[apikey=********",
        ),
        (
            "sensitive_pair_after_a_comma_runs_past_a_semicolon_to_the_next_pair",
            "foo,apikey=a;b&t=1",
            "foo,apikey=********&t=1",
        ),
        (
            "colon_equals_spaced_from_a_sensitive_key_masks_the_next_token",
            "apikey := SECRET",
            "apikey := ********",
        ),
        (
            "colon_equals_after_a_sensitive_key_in_one_token_masks_the_value",
            "apikey:=S",
            "apikey:=********",
        ),
        (
            "empty_path_segments_after_a_sensitive_segment_are_skipped",
            "/api/token//SECRET",
            "/api/token//********",
        ),
        (
            "percent_encoded_equals_sign_after_a_sensitive_key_is_a_separator",
            "apikey%3DSECRET",
            "apikey%3D********",
        ),
        (
            "lower_case_percent_encoded_colon_after_a_sensitive_key_is_a_separator",
            "token%3aS",
            "token%3a********",
        ),
        (
            "json_escaped_inside_free_text_masks_the_sensitive_value",
            r#"{\"apikey\":\"SECRET\"}"#,
            r#"{\"apikey\":\"********\"}"#,
        ),
        (
            "json_escaped_inside_free_text_ends_the_masked_value_at_the_next_escaped_quote",
            r#"{\"apikey\": \"S\", \"ok\": \"visible\"}"#,
            r#"{\"apikey\": \"********\", \"ok\": \"visible\"}"#,
        ),
        (
            "embedded_json_header_name_ending_in_a_sensitive_key_is_masked",
            r#"{"X-Api-Key": "SECRET"}"#,
            r#"{"X-Api-Key": "********"}"#,
        ),
        (
            "compound_path_segment_ending_in_token_masks_the_next_segment",
            "/api/access_token/SECRET",
            "/api/access_token/********",
        ),
        (
            "header_name_path_segment_masks_the_next_segment_of_an_http_url",
            "https://h/api/x-api-key/SECRET",
            "https://h/api/x-api-key/********",
        ),
        (
            "compound_path_segment_ending_in_secret_masks_the_next_segment",
            "/api/client_secret/SECRET",
            "/api/client_secret/********",
        ),
        (
            "colon_equals_ending_a_sensitive_key_token_masks_the_next_token",
            "apikey:= SECRET",
            "apikey:= ********",
        ),
        (
            "percent_encoded_colon_ending_a_sensitive_key_token_masks_the_next_token",
            "apikey%3A SECRET",
            "apikey%3A ********",
        ),
        (
            "colon_after_a_key_starting_after_a_parenthesis_is_a_separator",
            "(apikey:SECRET)",
            "(apikey:********)",
        ),
        (
            "colon_after_a_key_starting_after_a_comma_is_a_separator",
            ",token:SECRET",
            ",token:********",
        ),
        (
            "lower_case_percent_encoded_equals_sign_after_a_sensitive_key_is_a_separator",
            "apikey%3dSECRET",
            "apikey%3d********",
        ),
        (
            "upper_case_percent_encoded_colon_after_a_sensitive_key_is_a_separator",
            "apikey%3ASECRET",
            "apikey%3A********",
        ),
        (
            "lower_case_percent_encoded_colon_ending_a_sensitive_key_token_masks_the_next_token",
            "apikey%3a SECRET",
            "apikey%3a ********",
        ),
        (
            "closing_parenthesis_without_an_opener_is_part_of_the_value",
            "apikey=SEC)",
            "apikey=********",
        ),
        (
            "url_host_that_is_a_sensitive_key_masks_the_port_and_path",
            "https://token:443/x",
            "https://token:********",
        ),
        (
            "prefilter_passes_a_secret_key_split_by_a_hyphen",
            "sec-ret=S",
            "sec-ret=********",
        ),
        (
            "prefilter_passes_a_token_key_split_by_an_underscore",
            "to_ken=S",
            "to_ken=********",
        ),
        (
            "prefilter_passes_a_token_key_split_by_hyphens_before_a_colon",
            "t-o-k-e-n: S",
            "t-o-k-e-n: ********",
        ),
        (
            "prefilter_passes_url_user_info",
            "https://u:p@h",
            "https://u:********@h",
        ),
    ];

    #[test]
    fn free_text_redaction_matches_every_case() {
        let failures = FREE_TEXT_CASES
            .iter()
            .filter_map(|&(name, input, expected)| {
                let actual = redact_text(input);
                (actual != expected).then(|| {
                    format!(
                        "{name}\n    input:    {input:?}\n    expected: {expected:?}\n    actual:   {actual:?}"
                    )
                })
            })
            .collect::<Vec<_>>();

        assert!(
            failures.is_empty(),
            "{} of {} free-text cases failed:\n{}",
            failures.len(),
            FREE_TEXT_CASES.len(),
            failures.join("\n")
        );
    }
}
