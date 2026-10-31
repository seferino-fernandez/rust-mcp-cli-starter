//! Typed vocabulary for how the server is reached and authenticated.
//!
//! - [`AuthMode`]: how the HTTP transport authenticates requests.
//! - [`Transport`]: how the server talks to its MCP client.
//!
//! Both are clap [`ValueEnum`](clap::ValueEnum)s, so the command line, the
//! `MYAPP_MCP_AUTH_MODE` env var and the `[mcp] auth_mode` TOML key accept
//! exactly the same names, and an unknown name fails at load.

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
}
