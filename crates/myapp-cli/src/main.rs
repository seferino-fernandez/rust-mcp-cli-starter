//! `myapp`: terminal CLI for the MYAPP API.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod commands;
mod output;
mod utils;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{CompleteEnv, Shell, generate};
use clap_verbosity_flag::Verbosity;
use output::OutputFormat;
use std::path::PathBuf;

use crate::commands::{item, status};
use crate::utils::client;

#[derive(Parser)]
#[command(name = "myapp", about = "MYAPP from the terminal", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Output format.
    #[arg(long, global = true, default_value = "table")]
    output: OutputFormat,

    /// Path to config.toml.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Override the upstream base URL.
    #[arg(long, global = true)]
    base_url: Option<String>,

    /// Override the API key.
    ///
    /// Prefer MYAPP_API_KEY or config to avoid exposing the key in process
    /// listings (e.g. `ps`).
    #[arg(long, global = true)]
    api_key: Option<String>,

    /// Logging verbosity. Default reports only errors; `-v` warn, `-vv` info,
    /// `-vvv` debug, `-vvvv` trace; `-q` silences output. Place before the
    /// subcommand: `myapp -v status`. `RUST_LOG` overrides these flags.
    #[command(flatten)]
    verbosity: Verbosity,
}

#[derive(Subcommand)]
enum Command {
    /// Show server status.
    Status,
    /// Manage items.
    Item {
        #[command(subcommand)]
        command: item::ItemCommand,
    },
    /// Generate a shell completion script (bash, zsh, fish, elvish, powershell).
    Completions {
        /// Shell to generate the completion script for.
        shell: Shell,
    },
}

#[tokio::main]
async fn main() {
    // Dynamic completions: `COMPLETE=<shell> myapp`. A no-op for normal runs; exits
    // the process when handling a completion request, so it must precede any stdout use.
    CompleteEnv::with_factory(Cli::command).complete();

    if let Err(error) = try_main().await {
        eprintln!("myapp: {error:#}");
        std::process::exit(1);
    }
}

async fn try_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Static completion scripts need no config or API client, so emit and return early.
    if let Command::Completions { shell } = &cli.command {
        let mut cmd = Cli::command();
        let bin_name = cmd.get_name().to_string();
        generate(*shell, &mut cmd, bin_name, &mut std::io::stdout());
        return Ok(());
    }

    // `-v`/`-q` set the default level; `RUST_LOG` still overrides when set.
    let level = cli.verbosity.tracing_level_filter();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(format!("myapp_core={level}"))
            }),
        )
        .with_writer(std::io::stderr)
        .init();

    let client = client::build_client(
        cli.config.as_deref(),
        cli.base_url.as_deref(),
        cli.api_key.as_deref(),
    )?;

    match &cli.command {
        Command::Status => status::run(&client, cli.output).await,
        Command::Item { command } => item::run(command, &client, cli.output).await,
        // Handled by the early return above; the client is never built for it.
        Command::Completions { .. } => Ok(()),
    }
}
