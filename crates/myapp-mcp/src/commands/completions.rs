//! `myapp-mcp completions`: generate a static shell completion script.

use std::io;

use clap::{Command, ValueEnum};
use clap_complete::{Shell, generate};
use clap_complete_nushell::Nushell;

/// Shells a static completion script can be generated for.
///
/// Extends clap_complete's built-in [`Shell`] set with Nushell (via
/// `clap_complete_nushell`), which clap_complete does not ship.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Elvish,
    Fish,
    Nushell,
    #[value(name = "powershell")]
    PowerShell,
    Zsh,
}

/// Writes a static shell completion script for `cmd` to stdout.
///
/// Static completion scripts need no config, so this can run before the server
/// loads any configuration.
pub fn run(shell: CompletionShell, mut cmd: Command) {
    let name = cmd.get_name().to_string();
    let mut out = io::stdout();
    match shell {
        CompletionShell::Bash => generate(Shell::Bash, &mut cmd, name, &mut out),
        CompletionShell::Elvish => generate(Shell::Elvish, &mut cmd, name, &mut out),
        CompletionShell::Fish => generate(Shell::Fish, &mut cmd, name, &mut out),
        CompletionShell::PowerShell => generate(Shell::PowerShell, &mut cmd, name, &mut out),
        CompletionShell::Zsh => generate(Shell::Zsh, &mut cmd, name, &mut out),
        CompletionShell::Nushell => generate(Nushell, &mut cmd, name, &mut out),
    }
}
