//! Typed vocabulary for how the server is reached and authenticated.
//!
//! - [`AuthMode`]: how the HTTP transport authenticates requests.
//! - [`Transport`]: how the server talks to its MCP client.
//! - [`Scope`] and [`Scopes`]: the OAuth scopes granted to an access token.
//!
//! The first two are clap [`ValueEnum`](clap::ValueEnum)s, so the command
//! line, the `MYAPP_MCP_AUTH_MODE` env var and the `[mcp] auth_mode` TOML key
//! accept exactly the same names, and an unknown name fails at load.
//!
//! The OAuth bearer middleware inserts [`Scopes`] into the request extensions
//! and the tool handler reads them back, so neither layer depends on the other.

use std::fmt::{Display, Formatter};

use serde::Deserialize;

/// How the HTTP transport authenticates requests to the MCP endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// A static bearer token.
    #[default]
    Token,
    /// OAuth 2.1 with PKCE.
    #[value(name = "oauth")]
    OAuth,
    /// No authentication; allowed on loopback addresses only.
    None,
}

impl AuthMode {
    /// Returns the name used in config, env and on the command line.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::OAuth => "oauth",
            Self::None => "none",
        }
    }
}

impl Display for AuthMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the server talks to its MCP client, chosen with `--transport`.
///
/// `stdio` serves one local client over stdin/stdout; `http` serves the
/// streamable HTTP transport, the only one that reads the bearer `token` and
/// `oauth_pin`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Transport {
    /// Standard input and output, for a local client.
    #[default]
    Stdio,
    /// Streamable HTTP, for a network service.
    Http,
}

impl Display for Transport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Stdio => "stdio",
            Self::Http => "http",
        })
    }
}

/// A single OAuth scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Permits only tools annotated read-only.
    Read,
    /// Permits every tool.
    Write,
}

impl Scope {
    /// Every scope, in canonical order.
    pub const ALL: [Self; 2] = [Self::Read, Self::Write];

    /// Returns the scope's wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    /// Parses a wire name, returning `None` for an unknown scope.
    pub fn parse(name: &str) -> Option<Self> {
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
pub struct Scopes(u8);

impl Scopes {
    /// Every supported scope: what the bearer challenge advertises.
    pub const ALL: Self = Self(Scope::Read.bit() | Scope::Write.bit());

    /// Adds `scope` to the set.
    pub const fn insert(&mut self, scope: Scope) {
        self.0 |= scope.bit();
    }

    /// Reports whether `scope` is in the set.
    pub const fn contains(self, scope: Scope) -> bool {
        self.0 & scope.bit() != 0
    }

    /// Iterates the scopes in the set in canonical order.
    pub fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL
            .into_iter()
            .filter(move |scope| self.contains(*scope))
    }

    /// The scopes among `names` that are recognised; unknown names are
    /// dropped.
    pub fn parse<S: AsRef<str>>(names: &[S]) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;

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

    #[test]
    fn kebab_cased_oauth_is_never_accepted() {
        AuthMode::from_str("o-auth", false).unwrap_err();
        serde_json::from_value::<AuthMode>(serde_json::json!("o-auth")).unwrap_err();
    }

    #[test]
    fn transport_names_round_trip_through_clap() {
        for transport in Transport::value_variants() {
            let name = transport.to_string();
            assert_eq!(Transport::from_str(&name, false), Ok(*transport), "{name}");
        }
        assert_eq!(Transport::default(), Transport::Stdio);
    }

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
}
