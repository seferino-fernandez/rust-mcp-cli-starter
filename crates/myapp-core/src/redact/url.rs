//! Finds `http` and `https` URLs in free text and masks their user information.
//!
//! Every check here looks at a bounded number of bytes, so finding the end
//! of a URL is linear in its length.

use super::{MASKED_VALUE, is_sensitive_key, starts_with_ignore_ascii_case};

/// Finds where the first `http://` or `https://` URL in `value` starts.
pub(super) fn find_http_url_start(value: &str) -> Option<usize> {
    value
        .char_indices()
        .find_map(|(index, _character)| starts_with_http_url(value.get(index..)?).then_some(index))
}

/// Whether `value` starts with `http://` or `https://`, in any case.
fn starts_with_http_url(value: &str) -> bool {
    starts_with_ignore_ascii_case(value, "https://")
        || starts_with_ignore_ascii_case(value, "http://")
}

pub(super) fn contains_http_scheme_marker(value: &str) -> bool {
    value.char_indices().any(|(index, _character)| {
        value.get(index..).is_some_and(|suffix| {
            starts_with_ignore_ascii_case(suffix, "https:")
                || starts_with_ignore_ascii_case(suffix, "http:")
        })
    })
}

pub(super) const fn matching_delimiter(character: char) -> Option<char> {
    match character {
        '(' => Some(')'),
        '[' => Some(']'),
        '{' => Some('}'),
        '<' => Some('>'),
        '\'' => Some('\''),
        '"' => Some('"'),
        '`' => Some('`'),
        _ => None,
    }
}

/// Finds where the URL that starts `value` ends.
///
/// The URL ends at whitespace, at the `closing_delimiter` matching the
/// opener before it when only punctuation, whitespace, the end of the text
/// or another delimited URL follows, or where another URL starts. A URL
/// whose last query parameter or path segment is a sensitive key never
/// ends at a delimiter or URL start, so its value stays inside it.
pub(super) fn find_http_url_end(value: &str, closing_delimiter: Option<char>) -> usize {
    let mut tail = UrlTail::default();
    for (index, character) in value.char_indices() {
        let ends_url = character.is_whitespace()
            || is_terminal_matched_delimiter(value, index, character, closing_delimiter, &tail)
            || is_safe_later_http_start(value, index, &tail);
        if ends_url {
            return index;
        }
        tail.push(index, character);
    }
    value.len()
}

fn is_safe_later_http_start(value: &str, index: usize, tail: &UrlTail) -> bool {
    index != 0
        && value.get(index..).is_some_and(starts_with_http_url)
        && !tail.ends_in_sensitive_component(value)
}

fn is_terminal_matched_delimiter(
    value: &str,
    index: usize,
    character: char,
    closing_delimiter: Option<char>,
    tail: &UrlTail,
) -> bool {
    if closing_delimiter != Some(character) {
        return false;
    }
    let Some(suffix) = value
        .get(index..)
        .and_then(|suffix| suffix.get(character.len_utf8()..))
    else {
        return false;
    };
    let suffix = suffix.trim_start_matches([',', '.', ';', ':', '!', '?']);
    suffix.is_empty()
        || suffix.chars().next().is_some_and(char::is_whitespace)
        || (starts_with_delimited_http_url(suffix) && !tail.ends_in_sensitive_component(value))
}

fn starts_with_delimited_http_url(value: &str) -> bool {
    let Some(opener) = value.chars().next() else {
        return false;
    };
    if matching_delimiter(opener).is_none() {
        return false;
    }
    value
        .get(opener.len_utf8()..)
        .is_some_and(starts_with_http_url)
}

/// The positions in a URL prefix that decide whether it ends in a sensitive
/// component, updated one character at a time.
///
/// A prefix with a `#` never ends in one. A prefix with a `?` ends in one
/// when the key of its last query parameter, the text after the `?` or the
/// last `&` up to the next `=`, is a sensitive key. Any other prefix ends in
/// one when the path segment before its last `/` is a sensitive key.
#[derive(Default)]
struct UrlTail {
    /// Whether the prefix holds a `#`.
    fragment: bool,
    /// Whether the prefix holds a `?`.
    query: bool,
    /// Where the last query parameter starts.
    parameter_start: usize,
    /// The first `=` of the last query parameter.
    parameter_equals: Option<usize>,
    /// The last `/`.
    last_slash: Option<usize>,
    /// The `/` before the last one.
    slash_before_last: Option<usize>,
}

impl UrlTail {
    /// Adds the `character` at byte `index` to the end of the prefix.
    fn push(&mut self, index: usize, character: char) {
        match character {
            '#' => self.fragment = true,
            '?' if !self.query => {
                self.query = true;
                self.start_parameter(index);
            }
            '&' if self.query => self.start_parameter(index),
            '=' if self.query && self.parameter_equals.is_none() => {
                self.parameter_equals = Some(index);
            }
            '/' => {
                self.slash_before_last = self.last_slash;
                self.last_slash = Some(index);
            }
            _ => {}
        }
    }

    fn start_parameter(&mut self, introducer: usize) {
        self.parameter_start = introducer.saturating_add(1);
        self.parameter_equals = None;
    }

    /// Whether the prefix of `url` pushed so far ends in a sensitive query
    /// parameter or path segment.
    fn ends_in_sensitive_component(&self, url: &str) -> bool {
        if self.fragment {
            return false;
        }
        if self.query {
            return self
                .parameter_equals
                .and_then(|equals| url.get(self.parameter_start..equals))
                .is_some_and(is_sensitive_key);
        }
        self.last_slash.is_some_and(|last_slash| {
            let segment_start = self
                .slash_before_last
                .map_or(0, |slash| slash.saturating_add(1));
            url.get(segment_start..last_slash)
                .is_some_and(is_sensitive_key)
        })
    }
}

/// Masks the user information of `url`, or returns `None` when it has none.
pub(super) fn redact_url_user_info(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, after_authority) = rest.split_at(authority_end);
    let (user_info, host) = authority.rsplit_once('@')?;
    if user_info.is_empty() {
        return None;
    }
    let masked = match user_info.split_once(':') {
        Some((username, _password)) => format!("{username}:{MASKED_VALUE}"),
        None => MASKED_VALUE.to_string(),
    };
    Some(format!("{scheme}://{masked}@{host}{after_authority}"))
}
