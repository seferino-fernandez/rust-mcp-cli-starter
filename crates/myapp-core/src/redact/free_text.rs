//! Masks credentials in free text.
//!
//! Each rule reads every byte of the text a bounded number of times, so
//! redaction is linear in the length of the text, and text that no rule can
//! touch is returned without being copied.

use std::borrow::Cow;
use std::ops::Range;

use super::url::{
    contains_http_scheme_marker, find_http_url_end, find_http_url_start, matching_delimiter,
    redact_url_user_info,
};
use super::{
    MASKED_VALUE, is_sensitive_free_text_key, percent_decoded, percent_escape_at,
    starts_with_ignore_ascii_case,
};

/// Masks credentials in free text, borrowing `text` when nothing is masked.
///
/// Text that holds no `@` or `%` and, ignoring `-`, `_` and ASCII case, none
/// of `key`, `pass`, `secret`, `token`, `authorization`, `credential` or
/// `cookie` is returned at once: every sensitive key and header name holds
/// one of those words, a percent-encoded key needs a `%`, and user
/// information needs an `@`, so no rule can mask it. Other text goes through
/// [`mask_free_text`].
pub(super) fn redact_free_text(text: &str) -> Cow<'_, str> {
    if may_hold_credentials(text) {
        mask_free_text(text)
    } else {
        Cow::Borrowed(text)
    }
}

/// Whether some free-text rule may mask part of `text`.
fn may_hold_credentials(text: &str) -> bool {
    text.contains(['@', '%']) || contains_key_word(text)
}

/// The words, in lower case, one of which every sensitive key and header
/// name holds once `-` and `_` are removed, each packed by
/// [`pack_key_word`].
const KEY_WORDS: [(u128, u128); 7] = [
    pack_key_word(b"key"),
    pack_key_word(b"pass"),
    pack_key_word(b"secret"),
    pack_key_word(b"token"),
    pack_key_word(b"authorization"),
    pack_key_word(b"credential"),
    pack_key_word(b"cookie"),
];

/// Packs up to 16 bytes into the low bytes of a `u128`, last byte lowest,
/// with the mask that covers them.
const fn pack_key_word(word: &[u8]) -> (u128, u128) {
    let mut packed = 0_u128;
    let mut mask = 0_u128;
    let mut rest = word;
    while let [byte, after @ ..] = rest {
        packed = packed.wrapping_shl(8) | *byte as u128;
        mask = mask.wrapping_shl(8) | 0xff;
        rest = after;
    }
    (packed, mask)
}

/// Whether `text`, with `-` and `_` removed and in lower case, holds one of
/// the [`KEY_WORDS`].
///
/// The last 16 bytes read are kept in a `u128`, so each byte is compared
/// once against each word.
fn contains_key_word(text: &str) -> bool {
    let mut window = 0_u128;
    for &byte in text.as_bytes() {
        if is_part_separator(byte) {
            continue;
        }
        window = window.wrapping_shl(8) | u128::from(byte.to_ascii_lowercase());
        if KEY_WORDS.iter().any(|&(word, mask)| window & mask == word) {
            return true;
        }
    }
    false
}

/// Whether `byte` separates the parts of a compound key: `-` or `_`.
pub(super) const fn is_part_separator(byte: u8) -> bool {
    matches!(byte, b'-' | b'_')
}

/// Masks credentials in free text, without the shortcut of [`redact_free_text`].
///
/// http(s) URLs are found first and their user information is masked; the
/// user information after any other `//` is masked by
/// [`mask_authority_user_info`]. The
/// other rules then mark byte ranges of that text as values to mask: the
/// per-token rules look at one whitespace-separated token at a time, with
/// each http(s) URL as a token of its own, and again together with the text
/// glued before it, so `token=https://…` masks the URL as `token`'s value.
/// URLs glued to each other share that text, so only the longest such token
/// is read: every value the shorter ones would mask lies inside a value it
/// masks. The cross-token and embedded-JSON rules look at the whole text.
/// Every rule reads the same text, so masking one value can never hide a key
/// from another rule.
/// Ranges that overlap or touch become one masked value, and every other
/// byte, whitespace included, is kept as is.
pub(super) fn mask_free_text(string: &str) -> Cow<'_, str> {
    let mut text = UrlMaskedText::new(string);
    let mut tokens = Vec::new();
    let mut glued_token: Option<Range<usize>> = None;
    let mut token_start = 0;
    let mut remaining = string;

    while let Some(start) = find_http_url_start(remaining) {
        let (prefix, url_and_suffix) = remaining.split_at(start);
        let closing_delimiter = prefix.chars().next_back().and_then(matching_delimiter);
        push_whitespace_tokens(&mut text, prefix, &mut tokens, &mut token_start);
        let end = find_http_url_end(url_and_suffix, closing_delimiter);
        let (url, suffix) = url_and_suffix.split_at(end);
        let url_start = text.len();
        text.push_url(url);
        tokens.push(url_start..text.len());
        if token_start < url_start {
            match &mut glued_token {
                Some(glued) if glued.start == token_start => glued.end = text.len(),
                _ => tokens.extend(glued_token.replace(token_start..text.len())),
            }
        }
        remaining = suffix;
    }
    push_whitespace_tokens(&mut text, remaining, &mut tokens, &mut token_start);
    tokens.extend(glued_token);

    let text = text.into_text();
    let mut masks = Vec::new();
    for token in tokens {
        mask_token_values(&text, token, &mut masks);
    }
    let whitespace_tokens = whitespace_tokens(&text);
    mask_values_after_key_tokens(&text, &whitespace_tokens, &mut masks);
    mask_authority_user_info(&text, &whitespace_tokens, &mut masks);
    mask_embedded_json_values(&text, &mut masks);
    if masks.is_empty() && text == string {
        return Cow::Borrowed(string);
    }
    let redacted = if masks.is_empty() {
        text.into_owned()
    } else {
        apply_masks(&text, masks)
    };
    if redacted == string {
        Cow::Borrowed(string)
    } else {
        Cow::Owned(redacted)
    }
}

/// The free text with the user information of its URLs masked, built from
/// consecutive pieces of the free text.
///
/// It borrows the free text until a URL's user information is masked.
struct UrlMaskedText<'text> {
    source: &'text str,
    /// How many bytes of `source` have been pushed.
    consumed: usize,
    /// The text, once it differs from the pushed part of `source`.
    owned: Option<String>,
}

impl<'text> UrlMaskedText<'text> {
    const fn new(source: &'text str) -> Self {
        Self {
            source,
            consumed: 0,
            owned: None,
        }
    }

    fn len(&self) -> usize {
        self.owned.as_ref().map_or(self.consumed, String::len)
    }

    /// Appends the next piece of the free text as it is.
    fn push(&mut self, piece: &str) {
        self.consumed = self.consumed.saturating_add(piece.len());
        if let Some(owned) = &mut self.owned {
            owned.push_str(piece);
        }
    }

    /// Appends the next piece of the free text, a URL, with its user
    /// information masked.
    fn push_url(&mut self, url: &str) {
        let Some(masked) = redact_url_user_info(url) else {
            self.push(url);
            return;
        };
        let source = self.source;
        let consumed = self.consumed;
        self.owned
            .get_or_insert_with(|| source.get(..consumed).unwrap_or_default().to_string())
            .push_str(&masked);
        self.consumed = consumed.saturating_add(url.len());
    }

    fn into_text(self) -> Cow<'text, str> {
        match self.owned {
            Some(owned) => Cow::Owned(owned),
            None => Cow::Borrowed(self.source.get(..self.consumed).unwrap_or_default()),
        }
    }
}

/// Appends `value` to `text` and records the ranges of its tokens.
///
/// `token_start` tracks where the token that ends `text` starts: after the
/// last whitespace of `text`, or at its start.
fn push_whitespace_tokens(
    text: &mut UrlMaskedText<'_>,
    value: &str,
    tokens: &mut Vec<Range<usize>>,
    token_start: &mut usize,
) {
    let offset = text.len();
    text.push(value);
    let mut start = None;
    for (index, character) in value.char_indices() {
        if character.is_whitespace() {
            let after = offset
                .saturating_add(index)
                .saturating_add(character.len_utf8());
            *token_start = after;
            if let Some(start) = start.take() {
                tokens.push(start..offset.saturating_add(index));
            }
        } else if start.is_none() {
            start = Some(offset.saturating_add(index));
        }
    }
    if let Some(start) = start {
        tokens.push(start..offset.saturating_add(value.len()));
    }
}

/// Finds the byte ranges of the whitespace-separated tokens in `value`.
fn whitespace_tokens(value: &str) -> Vec<Range<usize>> {
    let mut tokens = Vec::new();
    let mut start = None;
    for (index, character) in value.char_indices() {
        if character.is_whitespace() {
            if let Some(start) = start.take() {
                tokens.push(start..index);
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(start) = start {
        tokens.push(start..value.len());
    }
    tokens
}

/// Marks the values of the sensitive pairs and path segments in one token.
fn mask_token_values(text: &str, token: Range<usize>, masks: &mut Vec<Range<usize>>) {
    let Some(value) = text.get(token.clone()) else {
        return;
    };
    let pairs = sensitive_pair_values(value);
    let mut token_masks = sensitive_path_values(value, &pairs);
    token_masks.extend(pairs.into_iter().map(|pair| pair.value));
    masks.extend(
        token_masks.into_iter().map(|mask| {
            mask.start.saturating_add(token.start)..mask.end.saturating_add(token.start)
        }),
    );
}

/// The value of a sensitive pair in a token.
struct PairValue {
    value: Range<usize>,
    /// Whether a pair after a `?` or `&` has its value ended by the `&` of
    /// the next pair, as the query rules have always ended it.
    ends_at_next_pair: bool,
}

/// Finds the values of the sensitive `key=value` pairs in a token.
///
/// A key is one of the token's [`free_text_keys`] that matches a sensitive
/// key, so it starts the token or follows a `?`, `&`, `;`, `(`, `,`, `#` or
/// any other character that cannot be part of a key. A key followed by `=`,
/// `:=` or `%3D` may also be an `Authorization` header name, as in
/// `?authorization=Bearer%20x`. One `'`, `` ` `` or `"` may close the key
/// before its separator, as in `` `password`=x ``. The separator is `=` or
/// `:=`, or `:` when a value follows it and no `?`, `&` or `;` introduced the
/// key, as in `apikey:value`; `%3D` and `%3A` act as `=` and `:`. The value,
/// which may be empty, runs to the next `&` or `#`, so a `?` inside it is
/// masked with it. Only a pair introduced by a `;` that is not part of
/// `&amp;` has its value end at the next `;` too. A value that runs to the
/// end of the token leaves a `)`, `]` or `}` ending the token visible when
/// the key follows the matching opener, as in `foo(apikey=********)`.
///
/// Keys come in order, so the value ends and the brackets before each key
/// are found by scans that only move forward.
fn sensitive_pair_values(token: &str) -> Vec<PairValue> {
    let mut values = Vec::new();
    let mut query_value_end = NextByte::new(token, b"&#");
    let mut semicolon_value_end = NextByte::new(token, b"&;#");
    let mut brackets = BracketCounts::default();
    for key in free_text_keys(token) {
        let (Some(before_key), Some(after_key)) = (token.get(..key.start), token.get(key.end..))
        else {
            continue;
        };
        let quote_len = usize::from(after_key.starts_with(['\'', '`', '"']));
        let Some((separator, separator_len)) =
            after_key.get(quote_len..).and_then(leading_separator)
        else {
            continue;
        };
        let separator_len = separator_len.saturating_add(quote_len);
        let introducer = before_key.chars().next_back();
        let value_follows = after_key.len() > separator_len;
        let separated = match separator {
            Separator::Equals => true,
            Separator::ColonEquals => value_follows,
            Separator::Colon => value_follows && !matches!(introducer, Some('?' | '&' | ';')),
        };
        let key_text = token.get(key.clone()).unwrap_or_default();
        let sensitive = is_sensitive_free_text_key(key_text)
            || (!matches!(separator, Separator::Colon)
                && is_authorization_name(&percent_decoded(key_text)));
        if !separated || !sensitive {
            continue;
        }
        let value_start = key.end.saturating_add(separator_len);
        let introduced_by_semicolon = introducer == Some(';') && !before_key.ends_with("&amp;");
        let value_end = if introduced_by_semicolon {
            semicolon_value_end.at_or_after(value_start)
        } else {
            query_value_end.at_or_after(value_start)
        };
        let ends_at_next_pair = matches!(introducer, Some('?' | '&'))
            && token
                .get(value_end..)
                .is_some_and(|rest| rest.starts_with('&'));
        let value = if value_end == token.len() {
            without_closing_bracket(token, value_start..value_end, |opener, closer| {
                brackets.advance(token, key.start);
                brackets.is_open(opener, closer)
            })
        } else {
            value_start..value_end
        };
        let value = if quote_len == 1 {
            unquoted(token, value)
        } else {
            value
        };
        values.push(PairValue {
            value,
            ends_at_next_pair,
        });
    }
    values
}

/// Finds the first of a set of ASCII bytes at or after a position, for
/// positions that do not decrease, reading each byte at most once.
struct NextByte<'text> {
    text: &'text [u8],
    bytes: &'static [u8],
    /// The position searched from last and the first match at or after it,
    /// or the text's length.
    last: Option<(usize, usize)>,
}

impl<'text> NextByte<'text> {
    const fn new(text: &'text str, bytes: &'static [u8]) -> Self {
        Self {
            text: text.as_bytes(),
            bytes,
            last: None,
        }
    }

    /// Finds the first of the bytes at or after `position`, or the text's length.
    fn at_or_after(&mut self, position: usize) -> usize {
        if let Some((from, found)) = self.last
            && (from..=found).contains(&position)
        {
            return found;
        }
        let found = self
            .text
            .get(position..)
            .and_then(|rest| rest.iter().position(|byte| self.bytes.contains(byte)))
            .map_or(self.text.len(), |offset| position.saturating_add(offset));
        self.last = Some((position, found));
        found
    }
}

/// Counts the brackets in a prefix of a token that only grows.
#[derive(Default)]
struct BracketCounts {
    /// The length of the prefix counted so far.
    counted: usize,
    /// The counts of `(`, `)`, `[`, `]`, `{` and `}`.
    counts: [usize; 6],
}

impl BracketCounts {
    const BRACKETS: [u8; 6] = *b"()[]{}";

    /// Counts the brackets of `token` up to `end`; a smaller `end` than
    /// before recounts from the start.
    fn advance(&mut self, token: &str, end: usize) {
        if end < self.counted {
            *self = Self::default();
        }
        for &byte in token.as_bytes().get(self.counted..end).unwrap_or_default() {
            if let Some(index) = Self::BRACKETS.iter().position(|&bracket| bracket == byte)
                && let Some(count) = self.counts.get_mut(index)
            {
                *count = count.saturating_add(1);
            }
        }
        self.counted = end;
    }

    /// Whether the counted prefix opens more `opener`s than it closes `closer`s.
    fn is_open(&self, opener: char, closer: char) -> bool {
        self.count(opener) > self.count(closer)
    }

    fn count(&self, bracket: char) -> usize {
        Self::BRACKETS
            .iter()
            .position(|&byte| char::from(byte) == bracket)
            .and_then(|index| self.counts.get(index))
            .copied()
            .unwrap_or_default()
    }
}

/// Whether `byte` can be part of a free-text key: an ASCII letter or digit,
/// `-` or `_`.
const fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

/// The length of the key character at `index` of `bytes`: 1 for a key byte,
/// 3 for a `%` escape that decodes to one, as in `api%5Fkey`, and 0 for
/// anything else, so `%3D` ends a key.
fn key_character_len(bytes: &[u8], index: usize) -> usize {
    match bytes.get(index) {
        Some(&byte) if is_key_byte(byte) => 1,
        Some(b'%') if percent_escape_at(bytes, index).is_some_and(is_key_byte) => 3,
        _ => 0,
    }
}

/// Finds the keys in a token: each run of key characters, which starts the
/// token or follows a character that cannot be part of a key, so a key is
/// never matched from the middle of a word.
fn free_text_keys(token: &str) -> impl Iterator<Item = Range<usize>> {
    let bytes = token.as_bytes();
    let mut index = 0;
    std::iter::from_fn(move || {
        while index < bytes.len() && key_character_len(bytes, index) == 0 {
            index = index.saturating_add(1);
        }
        if index >= bytes.len() {
            return None;
        }
        let start = index;
        loop {
            let len = key_character_len(bytes, index);
            if len == 0 {
                break;
            }
            index = index.saturating_add(len);
        }
        Some(start..index)
    })
}

/// Finds where the key that ends `text` starts, or `text.len()` when no key
/// character ends it.
fn trailing_key_start(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut start = bytes.len();
    loop {
        if let Some(escape) = start.checked_sub(3)
            && percent_escape_at(bytes, escape).is_some_and(is_key_byte)
        {
            start = escape;
            continue;
        }
        match start.checked_sub(1) {
            Some(before) if bytes.get(before).copied().is_some_and(is_key_byte) => {
                start = before;
            }
            _ => return start,
        }
    }
}

/// `text` without one closing `'`, `` ` `` or `"`, so a quoted key such as
/// `'token'` is found by [`trailing_key_start`].
fn strip_closing_quote(text: &str) -> &str {
    text.strip_suffix(['\'', '`', '"']).unwrap_or(text)
}

/// A value separator after a free-text key.
#[derive(Clone, Copy)]
enum Separator {
    /// `=`, or its percent-encoded form `%3D`.
    Equals,
    /// `:`, or its percent-encoded form `%3A`.
    Colon,
    /// `:=`.
    ColonEquals,
}

/// Reads the value separator that starts `text`, and its length in bytes.
///
/// `%3D` and `%3A`, in any case, act as `=` and `:`.
fn leading_separator(text: &str) -> Option<(Separator, usize)> {
    if text.starts_with(":=") {
        Some((Separator::ColonEquals, 2))
    } else if text.starts_with('=') {
        Some((Separator::Equals, 1))
    } else if text.starts_with(':') {
        Some((Separator::Colon, 1))
    } else if starts_with_ignore_ascii_case(text, "%3D") {
        Some((Separator::Equals, 3))
    } else if starts_with_ignore_ascii_case(text, "%3A") {
        Some((Separator::Colon, 3))
    } else {
        None
    }
}

/// Finds where a `:`, `:=`, `=`, `%3A` or `%3D` separator that ends `token`
/// starts.
fn trailing_separator_start(token: &str) -> Option<usize> {
    [":=", ":", "=", "%3A", "%3D"]
        .into_iter()
        .find_map(|separator| {
            let start = token.len().checked_sub(separator.len())?;
            token
                .get(start..)?
                .eq_ignore_ascii_case(separator)
                .then_some(start)
        })
}

/// Leaves a `)`, `]` or `}` that ends `value` outside it when `is_open`
/// says that the text before the value's key, in the key's token, holds an
/// opener that it has not closed.
fn without_closing_bracket(
    text: &str,
    value: Range<usize>,
    is_open: impl FnOnce(char, char) -> bool,
) -> Range<usize> {
    let Some(closer) = text
        .get(value.clone())
        .and_then(|value| value.chars().next_back())
    else {
        return value;
    };
    let opener = match closer {
        ')' => '(',
        ']' => '[',
        '}' => '{',
        _ => return value,
    };
    if is_open(opener, closer) {
        value.start..value.end.saturating_sub(closer.len_utf8())
    } else {
        value
    }
}

/// Whether `before_key` opens more `opener`s than it closes `closer`s.
fn opens(before_key: &str) -> impl FnOnce(char, char) -> bool {
    move |opener, closer| before_key.matches(opener).count() > before_key.matches(closer).count()
}

/// Finds the path segments that follow a sensitive path segment in a token.
///
/// Segments end at `/`, `?` and `#`, so the rule applies after a `?` or a
/// `#` too. The first non-empty segment after a sensitive segment and its
/// `/` is masked, so empty segments as in `token//value` are skipped, and a
/// masked segment that is itself a sensitive key name masks the segment
/// after it in turn. A segment is sensitive when it is a sensitive key or a
/// compound or header name ending in one, as in
/// [`is_sensitive_free_text_key`]. A masked segment holding an `http:` or
/// `https:` marker masks the rest of the token. When the sensitive
/// segment ends the value of a `?` or `&` pair and an `&key=` pair follows,
/// the mask runs from that pair's value to the end of the path segment, so
/// the pair's key stays visible: `a&apikey=k/token/&x=S&t=1` becomes
/// `a&apikey=********&x=********`.
fn sensitive_path_values(token: &str, pairs: &[PairValue]) -> Vec<Range<usize>> {
    let mut values = Vec::new();
    let mut next_pair_starts = pairs
        .iter()
        .filter(|pair| pair.ends_at_next_pair)
        .map(|pair| pair.value.end)
        .collect::<Vec<_>>();
    next_pair_starts.sort_unstable();
    let mut follows_sensitive_segment = false;
    let mut start = 0;
    let delimiters = token
        .match_indices(['/', '?', '#'])
        .chain(std::iter::once((token.len(), "")));
    for (end, delimiter) in delimiters {
        let segment = token.get(start..end).unwrap_or_default();
        if follows_sensitive_segment && !segment.is_empty() {
            if contains_http_scheme_marker(segment) {
                values.push(start..token.len());
                break;
            }
            let starts_next_pair = next_pair_starts.binary_search(&start).is_ok();
            let value_start = starts_next_pair
                .then(|| leading_pair_value_start(segment))
                .flatten()
                .map_or(start, |offset| start.saturating_add(offset));
            values.push(value_start..end);
        }
        follows_sensitive_segment = delimiter == "/"
            && (is_sensitive_free_text_key(segment)
                || (follows_sensitive_segment && segment.is_empty()));
        start = end.saturating_add(delimiter.len());
    }
    values
}

/// Finds where the value starts in a segment that begins with an `&key=` pair.
fn leading_pair_value_start(segment: &str) -> Option<usize> {
    let pair = segment.strip_prefix('&')?;
    let separator = pair.find(['=', '&', ';'])?;
    pair.get(separator..)?
        .starts_with('=')
        .then(|| separator.saturating_add(2))
}

/// Marks the values after sensitive keys, `Authorization` headers and
/// `Cookie` headers that whitespace separates from their key.
///
/// See [`value_after_key_token`] and [`header_credentials`].
fn mask_values_after_key_tokens(
    text: &str,
    tokens: &[Range<usize>],
    masks: &mut Vec<Range<usize>>,
) {
    let line_breaks = text
        .char_indices()
        .filter(|&(_, character)| is_line_break(character))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let mut line_masked_to = 0;
    for index in 0..tokens.len() {
        masks.extend(value_after_key_token(text, tokens, index));
        masks.extend(header_credentials(
            text,
            tokens,
            index,
            &line_breaks,
            &mut line_masked_to,
        ));
    }
}

/// Whether `character` ends a line.
const fn is_line_break(character: char) -> bool {
    matches!(
        character,
        '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// Finds the value in the token after a sensitive key token and its separator.
///
/// The key ends the token and starts it or follows a character that cannot
/// be part of a key, as in [`free_text_keys`], and may be closed by one
/// quote, as in `'token':`. The token after a `key:`, `key=` or `key:=`
/// token, such as `apikey:`, `X-Api-Key:` or `(apikey:`, is masked. When a
/// key token is followed by a token starting with `=`, `:` or `:=`, the value
/// after that separator is masked, as in `apikey =value`, or the token after
/// a lone separator, as in `apikey := value`. `%3D` and `%3A` act as `=` and
/// `:`. A `)`, `]` or `}` ending the value stays visible when the key follows
/// the matching opener, as in `(apikey: ********)`.
fn value_after_key_token(
    text: &str,
    tokens: &[Range<usize>],
    index: usize,
) -> Option<Range<usize>> {
    let current = text.get(tokens.get(index)?.clone())?;
    let next = tokens.get(index.saturating_add(1))?;
    let (key, value) = match trailing_separator_start(current) {
        Some(separator_start) => (current.get(..separator_start)?, next.clone()),
        None => {
            let (_, separator_len) = leading_separator(text.get(next.clone())?)?;
            let value = if separator_len == next.len() {
                tokens.get(index.saturating_add(2))?.clone()
            } else {
                next.start.saturating_add(separator_len)..next.end
            };
            (current, value)
        }
    };
    let key = strip_closing_quote(key);
    let key_start = trailing_key_start(key);
    if !key.get(key_start..).is_some_and(is_sensitive_free_text_key) {
        return None;
    }
    Some(unquoted(
        text,
        without_closing_bracket(text, value, opens(key.get(..key_start)?)),
    ))
}

/// Narrows `value` to the inside of its quotes, so a quoted value masks as
/// `"********"`: after an opening `'`, `` ` `` or `"`, the value ends at the
/// first of the same quote in it that is not escaped, or runs to its end
/// when there is none, so `"S1","token":"S2"` leaves the second pair for its
/// own rule.
/// Without an opening quote, a closing quote before any `,` or `;` that ends
/// the value is left out when the value holds an odd number of that quote,
/// so it closes a string opened before the value, as in `S"` from
/// `"Bearer S"`, rather than one inside it, as in `response="S"`.
fn unquoted(text: &str, value: Range<usize>) -> Range<usize> {
    let Some(content) = text.get(value.clone()) else {
        return value;
    };
    if let Some(quote) = content
        .chars()
        .next()
        .filter(|&c| matches!(c, '\'' | '`' | '"'))
    {
        let inner = content.get(1..).unwrap_or_default();
        let start = value.start.saturating_add(1);
        return match closing_quote(inner, quote) {
            Some(end) => start..start.saturating_add(end),
            None => start..value.end,
        };
    }
    let kept = content.trim_end_matches([',', ';']);
    let kept = match kept.chars().next_back() {
        Some(quote @ ('\'' | '`' | '"')) if kept.matches(quote).count() % 2 == 1 => {
            kept.get(..kept.len().saturating_sub(1)).unwrap_or(kept)
        }
        _ => kept,
    };
    value.start..value.start.saturating_add(kept.len())
}

/// A header whose value is a credential.
#[derive(Clone, Copy)]
enum CredentialHeader {
    /// `Authorization` or `Proxy-Authorization`: a scheme, then credentials.
    Authorization,
    /// `Cookie` or `Set-Cookie`: credentials only.
    Cookie,
}

/// The credential header `name` names, compared in any case after percent
/// decoding.
fn credential_header(name: &str) -> Option<CredentialHeader> {
    let name = percent_decoded(name);
    if is_authorization_name(&name) {
        Some(CredentialHeader::Authorization)
    } else if name.eq_ignore_ascii_case("Cookie") || name.eq_ignore_ascii_case("Set-Cookie") {
        Some(CredentialHeader::Cookie)
    } else {
        None
    }
}

/// Finds the credentials after an `Authorization`, `Proxy-Authorization`,
/// `Cookie` or `Set-Cookie` header name.
///
/// The name matches in any case and starts a word, as a key does in
/// [`free_text_keys`], and may be closed by one quote. Its separator, `:`,
/// `=`, `:=`, `%3A` or `%3D`, may have whitespace on either side or be glued
/// to the next word, as in `Authorization:Bearer` or `Authorization=Bearer`.
///
/// After a `Cookie` or `Set-Cookie` name, everything from the next word to
/// the end of its line is masked. After an `Authorization` name, the next
/// word is a scheme when it is made only of ASCII letters and another token
/// follows it on the same line: the scheme stays visible. After a `Bearer`
/// scheme the token that follows is masked; after any other scheme, such as
/// `Basic` or `Digest`, everything after the scheme to the end of its line
/// is. When the next word is not a scheme, it is masked, and so is the token
/// after it when one follows, on the same line or a later one. So
/// `Authorization: Bearer: value` masks both, and so does
/// `Authorization: Bearer` with `value` on the next line.
///
/// A value masked to the end of its line moves `line_masked_to` to its end,
/// and a later one that would start before it is already inside it and is
/// skipped, so those values never overlap and the work stays linear.
fn header_credentials(
    text: &str,
    tokens: &[Range<usize>],
    index: usize,
    line_breaks: &[usize],
    line_masked_to: &mut usize,
) -> Vec<Range<usize>> {
    let Some((header, before_name, word, word_token)) = header_word(text, tokens, index) else {
        return Vec::new();
    };
    let word = unquoted(text, word);
    let follow = tokens.get(word_token.saturating_add(1)).cloned();
    let follows_on_the_same_line = follow.as_ref().is_some_and(|follow| {
        !text
            .get(word.end..follow.start)
            .is_some_and(|gap| gap.contains(is_line_break))
    });
    let word_text = text.get(word.clone()).unwrap_or_default();
    let scheme = follows_on_the_same_line
        && word_text
            .chars()
            .all(|character| character.is_ascii_alphabetic());
    let mut rest_of_line = |start: usize| {
        (start >= *line_masked_to).then(|| {
            let value = to_line_end(text, line_breaks, start);
            *line_masked_to = value.end;
            value
        })
    };
    let mut credentials = Vec::new();
    match header {
        CredentialHeader::Cookie => credentials.extend(rest_of_line(word.start)),
        CredentialHeader::Authorization if scheme => {
            if let Some(follow) = follow {
                if word_text.eq_ignore_ascii_case("Bearer") {
                    credentials.push(follow);
                } else {
                    credentials.extend(rest_of_line(follow.start));
                }
            }
        }
        CredentialHeader::Authorization => {
            credentials.push(word);
            credentials.extend(follow);
        }
    }
    if let Some(last) = credentials.pop() {
        credentials.push(unquoted(
            text,
            without_closing_bracket(text, last, opens(before_name)),
        ));
    }
    credentials
}

/// The range from `start` to the end of its line, without trailing
/// whitespace. `line_breaks` holds the position of every line break in
/// `text`, in order.
fn to_line_end(text: &str, line_breaks: &[usize], start: usize) -> Range<usize> {
    let next_break = line_breaks.partition_point(|&line_break| line_break < start);
    let end = line_breaks.get(next_break).copied().unwrap_or(text.len());
    let kept = text.get(start..end).map_or(0, |line| line.trim_end().len());
    start..start.saturating_add(kept)
}

/// Finds the word after a credential header name in token `index`.
///
/// Returns the header, the token's text before the name, the word's range
/// and the index of the token that the word ends.
fn header_word<'text>(
    text: &'text str,
    tokens: &[Range<usize>],
    index: usize,
) -> Option<(CredentialHeader, &'text str, Range<usize>, usize)> {
    let token = tokens.get(index)?;
    let current = text.get(token.clone())?;
    let named_separator = current.char_indices().find_map(|(position, _)| {
        let (separator, separator_len) = leading_separator(current.get(position..)?)?;
        let name = strip_closing_quote(current.get(..position)?);
        let name_start = trailing_key_start(name);
        let introducer = name.get(..name_start)?.chars().next_back();
        if !matches!(separator, Separator::Colon) && matches!(introducer, Some('?' | '&')) {
            // A query parameter: the pair rules mask its whole value.
            return None;
        }
        let header = credential_header(name.get(name_start..)?)?;
        Some((
            header,
            name_start,
            token.start.saturating_add(position),
            separator_len,
        ))
    });
    let (header, name_start, separator, separator_len, separator_token) = match named_separator {
        Some((header, name_start, separator, separator_len)) => {
            (header, name_start, separator, separator_len, index)
        }
        None => {
            let name = strip_closing_quote(current);
            let name_start = trailing_key_start(name);
            let header = credential_header(name.get(name_start..)?)?;
            let next_index = index.saturating_add(1);
            let next = tokens.get(next_index)?;
            let (_, separator_len) = leading_separator(text.get(next.clone())?)?;
            (header, name_start, next.start, separator_len, next_index)
        }
    };
    let separator_end = tokens.get(separator_token)?.end;
    let word_start = separator.saturating_add(separator_len);
    let (word, word_token) = if word_start < separator_end {
        (word_start..separator_end, separator_token)
    } else {
        let word_token = separator_token.saturating_add(1);
        (tokens.get(word_token)?.clone(), word_token)
    };
    Some((header, current.get(..name_start)?, word, word_token))
}

pub(super) fn is_authorization_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("Authorization") || name.eq_ignore_ascii_case("Proxy-Authorization")
}

/// Masks the user information after every `//` in `text`.
///
/// The authority runs from the `//` to the next `/`, `?`, `#` or whitespace,
/// so `postgres://admin:pw@db`, `ftp://u:p@h` and the scheme-relative
/// `//u:pw@h` are all found. When the authority holds an `@`, the user
/// information before its last `@` is masked, keeping a username before a
/// `:` visible. When it holds none, the authority may have been cut, as in
/// `https://u:p/w@host` for a password holding a `/`: if the whitespace
/// token holds exactly one `@` after the `//`, everything between them is
/// masked, which over-masks a URL with an `@` in its path rather than leave
/// a password in clear.
///
/// The `//`s are visited in order with cursors that only move forward, so
/// the work is linear in the length of the text.
fn mask_authority_user_info(text: &str, tokens: &[Range<usize>], masks: &mut Vec<Range<usize>>) {
    let mut next_at = NextByte::new(text, b"@");
    let mut token_index = 0;
    let mut last_at_in_token: Option<(usize, Option<usize>)> = None;
    for (slashes, _) in text.match_indices("//") {
        let start = slashes.saturating_add(2);
        let rest = text.get(start..).unwrap_or_default();
        let authority_len = rest
            .find(|character: char| {
                matches!(character, '/' | '?' | '#') || character.is_whitespace()
            })
            .unwrap_or(rest.len());
        let authority = rest.get(..authority_len).unwrap_or_default();
        if let Some(at) = authority.rfind('@') {
            let user_info = authority.get(..at).unwrap_or_default();
            let masked_from = user_info
                .find(':')
                .map_or(0, |colon| colon.saturating_add(1));
            if masked_from < at {
                masks.push(start.saturating_add(masked_from)..start.saturating_add(at));
            }
            continue;
        }
        while tokens
            .get(token_index)
            .is_some_and(|token| token.end <= start)
        {
            token_index = token_index.saturating_add(1);
        }
        let Some(token) = tokens.get(token_index).filter(|token| token.start <= start) else {
            continue;
        };
        let first_at = next_at.at_or_after(start);
        if first_at >= token.end || first_at == start {
            continue;
        }
        let last_at = match last_at_in_token {
            Some((cached, last_at)) if cached == token_index => last_at,
            _ => {
                let last_at = text
                    .get(token.clone())
                    .and_then(|token_text| token_text.rfind('@'))
                    .map(|at| token.start.saturating_add(at));
                last_at_in_token = Some((token_index, last_at));
                last_at
            }
        };
        if last_at == Some(first_at) {
            masks.push(start..first_at);
        }
    }
}

/// Marks the content of a quoted string after a quoted sensitive key in embedded JSON.
///
/// The key is a sensitive key, a compound or header name ending in one, or
/// an `Authorization` or `Proxy-Authorization` header name, quoted with `"`,
/// with `'` as in Python or JavaScript literals, or, for JSON escaped inside
/// a string, with `\"`. It is followed by optional whitespace, `:` and
/// optional whitespace, as in `{"apiKey": "value"}`, `{'token': 'value'}` or
/// `{\"apiKey\":\"value\"}`, and the string's whole content is masked. A `"`
/// or `'` string ends at the first quote that is not escaped and a `\"`
/// string at the next `\"`. An unterminated string is left as it is. The
/// text is not parsed, so values that are not strings are unchanged.
fn mask_embedded_json_values(text: &str, masks: &mut Vec<Range<usize>>) {
    mask_quoted_json_values(text, "\"", |content| closing_quote(content, '"'), masks);
    mask_quoted_json_values(text, "'", |content| closing_quote(content, '\''), masks);
    mask_quoted_json_values(text, "\\\"", |content| content.find("\\\""), masks);
}

fn mask_quoted_json_values(
    text: &str,
    quote: &str,
    closing_quote: impl Fn(&str) -> Option<usize>,
    masks: &mut Vec<Range<usize>>,
) {
    for (start, _) in text.match_indices(quote) {
        let Some(after_quote) = text.get(start.saturating_add(quote.len())..) else {
            continue;
        };
        let Some((key, after_key)) = after_quote.split_once(quote) else {
            continue;
        };
        if !is_sensitive_free_text_key(key) && !is_authorization_name(key) {
            continue;
        }
        let Some(content) = after_key
            .trim_start()
            .strip_prefix(':')
            .and_then(|value| value.trim_start().strip_prefix(quote))
        else {
            continue;
        };
        let Some(content_end) = closing_quote(content) else {
            continue;
        };
        let content_start = text.len().saturating_sub(content.len());
        masks.push(content_start..content_start.saturating_add(content_end));
    }
}

/// Finds the first `quote` in `content` that is not escaped.
///
/// As in JSON, a quote is escaped only when an odd number of consecutive
/// backslashes comes right before it, so `\\"` closes the string.
fn closing_quote(content: &str, quote: char) -> Option<usize> {
    content
        .match_indices(quote)
        .map(|(index, _)| index)
        .find(|&index| {
            let backslashes = content.get(..index).map_or(0, |before| {
                before
                    .len()
                    .saturating_sub(before.trim_end_matches('\\').len())
            });
            backslashes.is_multiple_of(2)
        })
}

/// Replaces each run of overlapping or touching ranges with one masked value.
fn apply_masks(text: &str, mut masks: Vec<Range<usize>>) -> String {
    masks.sort_by_key(|mask| (mask.start, mask.end));
    let mut merged: Vec<Range<usize>> = Vec::new();
    for mask in masks {
        match merged.last_mut() {
            Some(last) if mask.start <= last.end => last.end = last.end.max(mask.end),
            _ => merged.push(mask),
        }
    }
    let mut redacted = String::with_capacity(text.len());
    let mut kept = 0;
    for mask in merged {
        redacted.push_str(text.get(kept..mask.start).unwrap_or_default());
        redacted.push_str(MASKED_VALUE);
        kept = mask.end;
    }
    redacted.push_str(text.get(kept..).unwrap_or_default());
    redacted
}
