//! `myapp completions`: generate a static shell completion script.

use std::io;

use clap::Command;
use clap_complete::{Shell, generate};

/// Writes a static shell completion script for `cmd` to stdout.
///
/// Static completion scripts need no config or API client, so this can run
/// before any client is built.
pub fn run(shell: Shell, mut cmd: Command) {
    let bin_name = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin_name, &mut io::stdout());
}
