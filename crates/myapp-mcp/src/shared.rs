//! Command-line arguments and the helpers both transports share.

use clap::{Parser, Subcommand};
use clap_verbosity_flag::Verbosity;

use crate::auth::{AuthMode, Transport};
use crate::commands::completions::CompletionShell;

use crate::config::{ServerConfig, ServerOverrides};
use myapp_core::{ConfigOverrides, SecretString};

/// CLI arguments for the MCP server.
#[derive(Parser)]
#[command(
    name = "myapp-mcp",
    about = "MCP server exposing the MYAPP API",
    version
)]
pub struct Args {
    /// Optional subcommand. When omitted, the MCP server runs.
    #[command(subcommand)]
    pub command: Option<Command>,

    #[expect(
        clippy::doc_markdown,
        reason = "clap renders this doc comment verbatim as --help text, so backticks would show"
    )]
    /// Path to config.toml [env: MYAPP_CONFIG]. A path named here or by
    /// MYAPP_CONFIG must exist.
    #[arg(long, value_name = "PATH")]
    pub config: Option<std::path::PathBuf>,

    /// Transport to serve the MCP protocol over.
    #[arg(long, value_enum, default_value_t = Transport::Stdio)]
    pub transport: Transport,

    /// Logging verbosity: `-v` warn, `-vv` info, `-vvv` debug, `-vvvv` trace;
    /// `-q` silences output. When passed, overrides `MYAPP_LOG_LEVEL` and
    /// `[log] level`; with none of them set, the default is info. `RUST_LOG`
    /// still overrides everything.
    #[command(flatten)]
    pub verbosity: Verbosity,

    /// Override the upstream base URL.
    #[arg(long)]
    pub base_url: Option<String>,

    /// Override the API key.
    #[arg(long)]
    pub api_key: Option<String>,

    #[expect(
        clippy::doc_markdown,
        rustdoc::broken_intra_doc_links,
        reason = "clap renders this doc comment verbatim as --help text, so backticks or an escaped `[::1]` would show"
    )]
    /// Bind host for HTTP transport: an IP address literal such as 127.0.0.1,
    /// ::1 or [::1].
    #[arg(long)]
    pub host: Option<String>,

    /// Bind port for HTTP transport.
    #[arg(long)]
    pub port: Option<u16>,

    #[expect(
        clippy::doc_markdown,
        reason = "clap renders this doc comment verbatim as --help text, so backticks would show"
    )]
    /// Static bearer token for auth_mode=token; an empty or whitespace-only
    /// token is refused at startup [env: MYAPP_MCP_TOKEN].
    #[arg(long)]
    pub token: Option<String>,

    #[expect(
        clippy::doc_markdown,
        reason = "clap renders this doc comment verbatim as --help text, so backticks would show"
    )]
    /// External base URL for OAuth metadata [env: MYAPP_MCP_BASE_URL].
    #[arg(long)]
    pub mcp_base_url: Option<String>,

    #[expect(
        clippy::doc_markdown,
        reason = "clap renders this doc comment verbatim as --help text, so backticks would show"
    )]
    /// Auth mode for the HTTP transport [env: MYAPP_MCP_AUTH_MODE].
    #[arg(long, value_enum)]
    pub auth_mode: Option<AuthMode>,

    #[expect(
        clippy::doc_markdown,
        reason = "clap renders this doc comment verbatim as --help text, so backticks would show"
    )]
    /// PIN required on the OAuth consent screen [env: MYAPP_MCP_OAUTH_PIN].
    #[arg(long)]
    pub oauth_pin: Option<String>,
}

/// Subcommands for the MCP server binary.
#[derive(Subcommand)]
pub enum Command {
    /// Generate a shell completion script (bash, elvish, fish, nushell,
    /// powershell, zsh).
    Completions {
        /// Shell to generate the completion script for.
        shell: CompletionShell,
    },
    #[expect(
        clippy::doc_markdown,
        reason = "clap renders this doc comment verbatim as --help text, so backticks would show"
    )]
    /// Generate man pages for the server and all subcommands into <OUT_DIR>.
    Man {
        /// Directory to write the generated man pages into (created if missing).
        out_dir: std::path::PathBuf,
    },
}

impl Args {
    /// Returns the CLI flags as the loader's top layer.
    pub fn overrides(&self) -> ServerOverrides {
        let secret = |value: &Option<String>| value.clone().map(SecretString::from);
        ServerOverrides {
            core: ConfigOverrides {
                base_url: self.base_url.clone(),
                api_key: secret(&self.api_key),
            },
            host: self.host.clone(),
            port: self.port,
            token: secret(&self.token),
            base_url: self.mcp_base_url.clone(),
            auth_mode: self.auth_mode,
            oauth_pin: secret(&self.oauth_pin),
        }
    }
}

/// Resolves the external base URL for OAuth metadata, warning on plain HTTP
/// over a non-loopback address.
pub fn resolve_base_url(config: &ServerConfig, addr: &std::net::SocketAddr) -> String {
    let base_url = config
        .mcp
        .base_url
        .clone()
        .unwrap_or_else(|| format!("http://{addr}"));
    if !base_url.starts_with("https://") && !addr.ip().is_loopback() {
        tracing::warn!(%base_url, "OAuth base_url uses plain HTTP on a non-loopback address");
    }
    base_url
}

/// Builds an authenticated [`ApiClient`](myapp_core::ApiClient) from config (eager; no login flow).
pub fn create_api_client(config: &ServerConfig) -> anyhow::Result<myapp_core::ApiClient> {
    Ok(myapp_core::ApiClient::new(config.core.clone())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_defaults_to_stdio_and_rejects_unknown_names() {
        let args = Args::try_parse_from(["myapp-mcp"]).unwrap();
        assert_eq!(args.transport, Transport::Stdio);
        let args = Args::try_parse_from(["myapp-mcp", "--transport", "http"]).unwrap();
        assert_eq!(args.transport, Transport::Http);
        let parsed = Args::try_parse_from(["myapp-mcp", "--transport", "sse"]);
        assert_eq!(
            parsed.err().map(|err| err.kind()),
            Some(clap::error::ErrorKind::InvalidValue)
        );
    }
}
