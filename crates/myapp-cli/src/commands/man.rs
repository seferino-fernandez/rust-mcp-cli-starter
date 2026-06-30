//! `myapp man`: generate man pages for the CLI and all subcommands.

use std::fs;
use std::path::Path;

use clap::Command;

/// Generates man pages for `cmd` and all subcommands into `out_dir`, creating
/// the directory if it does not exist.
///
/// Needs no config or API client, so this can run before any client is built.
pub fn run(cmd: Command, out_dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(out_dir)?;
    clap_mangen::generate_to(cmd, out_dir)?;
    Ok(())
}
