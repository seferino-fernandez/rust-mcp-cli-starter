//! Environment variable source abstraction used by the config loader.
//!
//! Splitting the "where does an env var come from?" question behind a trait
//! lets production code read from the process environment while tests pass
//! an in-memory [`MapEnv`](crate::env::MapEnv). The config module never calls
//! `std::env::var` directly; every env read goes through an
//! [`&impl Env`](crate::env::Env).
//!
//! [`env_non_empty`](crate::env::env_non_empty) treats an empty string as
//! unset. The typed parsers [`env_parse`](crate::env::env_parse) and
//! [`env_parse_bool`](crate::env::env_parse_bool) trim the value first, treat
//! an empty or whitespace-only value as unset, and fail with
//! [`Error::Config`] naming the variable and its raw value when the value does
//! not parse, so a typo never silently falls back to a lower layer.

use crate::Result;
use crate::error::Error;
use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;

/// Source of configuration environment variables.
///
/// The production impl ([`SystemEnv`]) reads from the real process
/// environment. Test fakes ([`MapEnv`]) hold an in-memory map.
pub trait Env {
    /// Returns the raw value for `key`, or `None` if unset.
    ///
    /// Mirrors `std::env::var(key).ok()`: empty strings round-trip as
    /// `Some("")`. Call sites that want to treat empty as missing should
    /// layer [`env_non_empty`] on top.
    fn get(&self, key: &str) -> Option<String>;
}

/// Production [`Env`] backed by `std::env::var`. Zero state.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnv;

impl Env for SystemEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// In-memory [`Env`] for tests. Keys absent from the map return `None`;
/// empty-string values round-trip as `Some("")` to match [`SystemEnv`].
///
/// Construct with [`MapEnv::new`] (empty) or [`MapEnv::default`], then
/// chain [`MapEnv::with`] to insert keys.
#[derive(Debug, Default, Clone)]
pub struct MapEnv {
    vars: HashMap<String, String>,
}

impl MapEnv {
    /// Returns a new empty `MapEnv`. Equivalent to [`MapEnv::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `key` → `value`, returning `self` so calls chain.
    pub fn with<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.vars.insert(key.into(), value.into());
        self
    }
}

impl Env for MapEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }
}

/// Returns the value of `key` from `env` if it is set and non-empty.
///
/// Treats empty strings as "unset" so a `FOO=` line in a `.env` file or a
/// cleared-but-not-unset shell variable does not clobber a value coming from
/// TOML or defaults.
pub fn env_non_empty(env: &impl Env, key: &str) -> Option<String> {
    env.get(key).filter(|value| !value.is_empty())
}

/// Parses the value of `key` from `env` as `T`, if set.
///
/// Trims the value first. An unset, empty, or whitespace-only value returns
/// `Ok(None)`, leaving the caller's current value untouched.
///
/// # Errors
///
/// Returns [`Error::Config`] with the message
/// `invalid <KEY> value "<raw>": <reason>` when the trimmed value does not
/// parse as `T`. `<raw>` is the value as set, before trimming.
///
/// # Examples
///
/// ```
/// use myapp_core::env::{MapEnv, env_parse};
///
/// let env = MapEnv::new()
///     .with("TIMEOUT", " 30 ")
///     .with("BLANK", "  ")
///     .with("INVALID", "soon");
/// assert_eq!(env_parse::<u64>(&env, "TIMEOUT").unwrap(), Some(30));
/// assert_eq!(env_parse::<u64>(&env, "BLANK").unwrap(), None);
/// assert_eq!(env_parse::<u64>(&env, "UNSET").unwrap(), None);
///
/// let err = env_parse::<u64>(&env, "INVALID").unwrap_err();
/// assert!(err.to_string().contains(r#"invalid INVALID value "soon""#));
/// ```
pub fn env_parse<T>(env: &impl Env, key: &str) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: Display,
{
    parse_trimmed(env, key, |value| {
        value.parse::<T>().map_err(|err| err.to_string())
    })
}

/// Parses the value of `key` from `env` as a boolean, if set.
///
/// Trims the value first, then accepts `1`/`true`/`yes`/`on` as `true` and
/// `0`/`false`/`no`/`off` as `false`, case-insensitively. An unset, empty, or
/// whitespace-only value returns `Ok(None)`, leaving the caller's current value
/// untouched.
///
/// # Errors
///
/// Returns [`Error::Config`] with the message
/// `invalid <KEY> value "<raw>": <reason>` for any other value, where
/// `<reason>` lists the accepted spellings.
///
/// # Examples
///
/// ```
/// use myapp_core::env::{MapEnv, env_parse_bool};
///
/// let env = MapEnv::new()
///     .with("ENABLED", "yes")
///     .with("DISABLED", " OFF ")
///     .with("TYPO", "flase");
/// assert_eq!(env_parse_bool(&env, "ENABLED").unwrap(), Some(true));
/// assert_eq!(env_parse_bool(&env, "DISABLED").unwrap(), Some(false));
/// assert_eq!(env_parse_bool(&env, "UNSET").unwrap(), None);
///
/// let err = env_parse_bool(&env, "TYPO").unwrap_err();
/// assert!(err.to_string().contains(r#"invalid TYPO value "flase""#));
/// ```
pub fn env_parse_bool(env: &impl Env, key: &str) -> Result<Option<bool>> {
    parse_trimmed(env, key, |value| {
        match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err("expected one of 1, true, yes, on, 0, false, no, off".to_string()),
        }
    })
}

/// Applies `parse` to the trimmed value of `key`, treating blank as unset.
fn parse_trimmed<T>(
    env: &impl Env,
    key: &str,
    parse: impl FnOnce(&str) -> std::result::Result<T, String>,
) -> Result<Option<T>> {
    let Some(raw) = env.get(key) else {
        return Ok(None);
    };
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    parse(value)
        .map(Some)
        .map_err(|reason| Error::Config(format!("invalid {key} value {raw:?}: {reason}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_accepts_every_spelling_trimmed_and_in_any_case() {
        for (raw, expected) in [
            (" 1 ", true),
            ("TRUE", true),
            ("\tYes", true),
            ("oN\n", true),
            (" 0\t", false),
            ("False ", false),
            (" nO", false),
            ("OFF", false),
        ] {
            let env = MapEnv::new().with("FLAG", raw);
            assert_eq!(
                env_parse_bool(&env, "FLAG").unwrap(),
                Some(expected),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn bool_rejects_unrecognized_value_naming_variable_and_value() {
        let env = MapEnv::new().with("FLAG", "maybe");
        let err = env_parse_bool(&env, "FLAG").unwrap_err();
        assert!(matches!(err, Error::Config(_)), "{err:?}");
        assert!(
            err.to_string().contains(r#"invalid FLAG value "maybe""#),
            "{err}"
        );
    }

    #[test]
    fn unset_and_blank_values_are_none() {
        let env = MapEnv::new().with("EMPTY", "").with("BLANK", " \t ");
        for key in ["UNSET", "EMPTY", "BLANK"] {
            assert_eq!(env_parse_bool(&env, key).unwrap(), None, "{key}");
            assert_eq!(env_parse::<u64>(&env, key).unwrap(), None, "{key}");
        }
    }

    #[test]
    fn parse_trims_and_reports_the_untrimmed_raw_value() {
        let env = MapEnv::new().with("PORT", " 8080\n").with("BAD", " 1.5 ");
        assert_eq!(env_parse::<u16>(&env, "PORT").unwrap(), Some(8080));
        let err = env_parse::<u64>(&env, "BAD").unwrap_err();
        assert!(
            err.to_string().contains(r#"invalid BAD value " 1.5 ""#),
            "{err}"
        );
    }

    #[test]
    fn parse_rejects_out_of_range_values() {
        let env = MapEnv::new().with("PORT", "70000");
        let err = env_parse::<u16>(&env, "PORT").unwrap_err();
        assert!(
            err.to_string()
                .contains(r#"invalid PORT value "70000": number too large"#),
            "{err}"
        );
    }
}
