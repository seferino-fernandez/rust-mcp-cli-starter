//! Transport and endpoint authentication vocabulary.

use std::fmt::{Display, Formatter};

// template:begin http
use serde::Deserialize;
/// How the HTTP transport authenticates requests to the MCP endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AuthMode {
    /// A static bearer token.
    #[default]
    Token,
    // template:begin oauth
    /// OAuth 2.1 with PKCE.
    #[value(name = "oauth")]
    OAuth,
    // template:end oauth
    /// No authentication; allowed on loopback addresses only.
    None,
}

impl AuthMode {
    /// Returns the name used in config, env and on the command line.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            // template:begin oauth
            Self::OAuth => "oauth",
            // template:end oauth
            Self::None => "none",
        }
    }
}

impl Display for AuthMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// template:end http
/// How the server talks to its MCP client, chosen with `--transport`.
// template:begin http
///
/// `stdio` serves one local client over stdin/stdout; `http` serves the
/// streamable HTTP transport.
// template:end http
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Transport {
    /// Standard input and output, for a local client.
    #[default]
    Stdio,
    // template:begin http
    /// Streamable HTTP, for a network service.
    Http,
    // template:end http
}

impl Display for Transport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Stdio => "stdio",
            // template:begin http
            Self::Http => "http",
            // template:end http
        })
    }
}

// template:begin oauth
/// A single OAuth scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Permits only tools annotated read-only.
    Read,
    /// Permits every tool.
    Write,
}

impl Scope {
    /// Every scope, in canonical order.
    pub(crate) const ALL: [Self; 2] = [Self::Read, Self::Write];

    /// Returns the scope's wire name.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    /// Parses a wire name, returning `None` for an unknown scope.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == name)
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Read => 1,
            Self::Write => 1 << 1,
        }
    }
}

impl Display for Scope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of OAuth scopes, displayed space-separated in canonical order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Scopes(u8);

impl Scopes {
    /// Every supported scope: what the bearer challenge advertises.
    pub(crate) const ALL: Self = Self(Scope::Read.bit() | Scope::Write.bit());

    /// Adds `scope` to the set.
    pub(crate) const fn insert(&mut self, scope: Scope) {
        self.0 |= scope.bit();
    }

    /// Reports whether `scope` is in the set.
    pub(crate) const fn contains(self, scope: Scope) -> bool {
        self.0 & scope.bit() != 0
    }

    /// Iterates the scopes in the set in canonical order.
    pub(crate) fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL
            .into_iter()
            .filter(move |scope| self.contains(*scope))
    }

    /// The scopes among `names` that are recognised; unknown names are
    /// dropped.
    pub(crate) fn parse<S: AsRef<str>>(names: &[S]) -> Self {
        names
            .iter()
            .filter_map(|name| Scope::parse(name.as_ref()))
            .collect()
    }
}

impl FromIterator<Scope> for Scopes {
    fn from_iter<I: IntoIterator<Item = Scope>>(iter: I) -> Self {
        let mut scopes = Self::default();
        for scope in iter {
            scopes.insert(scope);
        }
        scopes
    }
}

impl Display for Scopes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (index, scope) in self.iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }
            f.write_str(scope.as_str())?;
        }
        Ok(())
    }
}

// template:end oauth
#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

    // template:begin http
    #[test]
    fn auth_mode_names_round_trip_through_clap_and_serde() {
        for mode in AuthMode::value_variants() {
            let name = mode.as_str();
            assert_eq!(AuthMode::from_str(name, false), Ok(*mode), "{name}");
            assert_eq!(mode.to_string(), name);
            let parsed: AuthMode = serde_json::from_value(serde_json::json!(name)).unwrap();
            assert_eq!(parsed, *mode, "{name}");
        }
    }
    // template:end http

    // template:begin oauth
    #[test]
    fn kebab_cased_oauth_is_never_accepted() {
        AuthMode::from_str("o-auth", false).unwrap_err();
        serde_json::from_value::<AuthMode>(serde_json::json!("o-auth")).unwrap_err();
    }
    // template:end oauth

    #[test]
    fn transport_names_round_trip_through_clap() {
        for transport in Transport::value_variants() {
            let name = transport.to_string();
            assert_eq!(Transport::from_str(&name, false), Ok(*transport), "{name}");
        }
        assert_eq!(Transport::default(), Transport::Stdio);
    }

    // template:begin oauth
    #[test]
    fn scopes_display_in_canonical_order() {
        let mut scopes = Scopes::default();
        scopes.insert(Scope::Write);
        scopes.insert(Scope::Read);
        assert_eq!(scopes.to_string(), "read write");
        assert_eq!(scopes, Scopes::ALL);
    }
    #[test]
    fn scope_names_round_trip() {
        for scope in Scope::ALL {
            assert_eq!(Scope::parse(scope.as_str()), Some(scope));
            assert_eq!(scope.to_string(), scope.as_str());
        }
        assert_eq!(Scope::parse("admin"), None);
        assert_eq!(Scope::parse("READ"), None);
    }
    #[test]
    fn scopes_contain_only_parsed_scopes() {
        let read = Scopes::parse(&["read", "admin"]);
        assert!(read.contains(Scope::Read));
        assert!(!read.contains(Scope::Write));
        assert_eq!(read.to_string(), "read");
        assert_eq!(Scopes::parse::<&str>(&[]).iter().count(), 0);
        assert_eq!(Scopes::default().to_string(), "");
    }
    // template:end oauth
}
