//! `myapp-mcp`: Model Context Protocol server exposing the MYAPP API as tools
//! an LLM client can call.
//!
//! Two transports are supported: `stdio` (recommended for local agent
//! integrations like Claude Desktop, Claude Code, Cursor) and `http`
//! (for remote deployments). Authentication can be configured via OAuth
//! 2.1 with PKCE, a static bearer token, or no authentication at all,
//! controlled by the `[mcp].auth_mode` config field.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod config;
mod http;
mod middleware;
mod oauth;
mod shared;
mod stdio;
mod tools;

use std::io::stderr;

use clap::{CommandFactory, Parser};
use clap_complete::{CompleteEnv, generate};
use shared::{Args, Command};

use crate::config::ServerConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Dynamic completions: `COMPLETE=<shell> myapp-mcp`. A no-op for normal runs; exits
    // the process when handling a completion request, so it must precede any stdout use.
    CompleteEnv::with_factory(Args::command).complete();

    let args = Args::parse();

    // Static completion scripts need no config, so emit and return early.
    if let Some(Command::Completions { shell }) = &args.command {
        let mut cmd = Args::command();
        let bin_name = cmd.get_name().to_string();
        generate(*shell, &mut cmd, bin_name, &mut std::io::stdout());
        return Ok(());
    }

    let mut config = ServerConfig::load(args.config.as_deref())?;

    // Default level precedence: explicit `-v`/`-q` overrides config `log.level`;
    // `RUST_LOG` (via `try_from_default_env`) still overrides everything.
    let level = if args.verbosity.is_present() {
        args.verbosity.tracing_level_filter().to_string()
    } else {
        config.core.log.level.clone()
    };
    tracing_subscriber::fmt()
        .with_writer(stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(format!(
                    "myapp_core={level},myapp_mcp={level},rmcp={level}"
                ))
            }),
        )
        .init();

    shared::apply_cli_overrides(&mut config, &args);

    tracing::info!(
        transport = %args.transport,
        auth_mode = %config.mcp.auth_mode,
        host = %config.mcp.host,
        port = %config.mcp.port,
        "myapp-mcp starting"
    );

    match args.transport.as_str() {
        "stdio" => stdio::serve(&config).await?,
        "http" => http::serve(&config).await?,
        other => anyhow::bail!("Unknown transport: {other}"),
    }

    Ok(())
}
