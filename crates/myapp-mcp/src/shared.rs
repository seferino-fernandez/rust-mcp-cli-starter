use clap::{Parser, Subcommand};
use clap_verbosity_flag::Verbosity;

use crate::commands::completions::CompletionShell;

use crate::config::ServerConfig;

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

    /// Path to config.toml.
    #[arg(long, value_name = "PATH")]
    pub config: Option<std::path::PathBuf>,

    /// Transport: "stdio" or "http".
    #[arg(long, default_value = "stdio", value_parser = ["stdio", "http"])]
    pub transport: String,

    /// Logging verbosity. Default reports only errors; `-v` warn, `-vv` info,
    /// `-vvv` debug, `-vvvv` trace; `-q` silences output. When passed, overrides
    /// the configured `log.level`; `RUST_LOG` still overrides everything.
    #[command(flatten)]
    pub verbosity: Verbosity,

    /// Override the upstream base URL.
    #[arg(long)]
    pub base_url: Option<String>,

    /// Override the API key.
    #[arg(long)]
    pub api_key: Option<String>,

    /// Bind host for HTTP transport.
    #[arg(long)]
    pub host: Option<String>,

    /// Bind port for HTTP transport.
    #[arg(long)]
    pub port: Option<u16>,

    /// Static bearer token for auth_mode=token [env: MYAPP_MCP_TOKEN].
    #[arg(long)]
    pub token: Option<String>,

    /// External base URL for OAuth metadata [env: MYAPP_MCP_BASE_URL].
    #[arg(long)]
    pub mcp_base_url: Option<String>,

    /// Auth mode: "token", "oauth", or "none".
    #[arg(long, value_parser = ["token", "oauth", "none"])]
    pub auth_mode: Option<String>,

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
    /// Generate man pages for the server and all subcommands into <OUT_DIR>.
    Man {
        /// Directory to write the generated man pages into (created if missing).
        out_dir: std::path::PathBuf,
    },
}

/// Applies CLI overrides onto a loaded [`ServerConfig`](crate::config::ServerConfig).
pub fn apply_cli_overrides(config: &mut crate::config::ServerConfig, args: &Args) {
    if let Some(url) = &args.base_url {
        config.core.base_url = url.clone();
    }
    if let Some(key) = &args.api_key {
        config.core.api_key = Some(myapp_core::SecretString::from(key.clone()));
    }
    if let Some(host) = &args.host {
        config.mcp.host.clone_from(host);
    }
    if let Some(port) = args.port {
        config.mcp.port = port;
    }
    if let Some(token) = &args.token {
        config.mcp.token = Some(myapp_core::SecretString::from(token.clone()));
    }
    if let Some(url) = &args.mcp_base_url {
        config.mcp.base_url = Some(url.clone());
    }
    if let Some(mode) = &args.auth_mode {
        config.mcp.auth_mode.clone_from(mode);
    }
    if let Some(pin) = &args.oauth_pin {
        config.mcp.oauth_pin = Some(myapp_core::SecretString::from(pin.clone()));
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

/// Builds an authenticated [`ApiClient`] from config (eager; no login flow).
pub fn create_api_client(config: &ServerConfig) -> anyhow::Result<myapp_core::ApiClient> {
    Ok(myapp_core::ApiClient::new(config.core.clone())?)
}
