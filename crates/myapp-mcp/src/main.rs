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

mod auth;
mod commands;
mod config;
mod http;
mod middleware;
mod oauth;
mod secret_digest;
mod shared;
mod stdio;
mod tools;

use std::io::stderr;

use clap::{CommandFactory, Parser};
use clap_complete::CompleteEnv;
use shared::{Args, Command};
use tracing::level_filters::LevelFilter;

use crate::auth::Transport;
use crate::commands::{completions, man};

use crate::config::ServerConfig;

/// Applies when neither `-v`/`-q`, `MYAPP_LOG_LEVEL` nor `[log] level` sets one.
const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::INFO;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Dynamic completions: `COMPLETE=<shell> myapp-mcp`. A no-op for normal runs; exits
    // the process when handling a completion request, so it must precede any stdout use.
    CompleteEnv::with_factory(Args::command).complete();

    let args = Args::parse();

    // Static completion scripts need no config, so emit and return early.
    if let Some(Command::Completions { shell }) = &args.command {
        completions::run(*shell, Args::command());
        return Ok(());
    }

    // Man pages need no config, so emit and return early.
    if let Some(Command::Man { out_dir }) = &args.command {
        man::run(Args::command(), out_dir)?;
        return Ok(());
    }

    let config = ServerConfig::load(args.config.as_deref(), &args.overrides(), args.transport)?;

    // Default level precedence: explicit `-v`/`-q` overrides config `log.level`,
    // which overrides `info`; `RUST_LOG` (via `try_from_default_env`) still
    // overrides everything.
    let flag = args
        .verbosity
        .is_present()
        .then(|| args.verbosity.tracing_level_filter());
    let (level, warning) = config.core.log.resolve_level(flag, DEFAULT_LOG_LEVEL);
    if let Some(warning) = warning {
        eprintln!("myapp-mcp: warning: {warning}");
    }
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

    tracing::info!(
        transport = %args.transport,
        auth_mode = %config.mcp.auth_mode,
        host = %config.mcp.host,
        port = %config.mcp.port,
        "myapp-mcp starting"
    );

    match args.transport {
        Transport::Stdio => stdio::serve(&config).await?,
        Transport::Http => http::serve(&config).await?,
    }

    Ok(())
}
