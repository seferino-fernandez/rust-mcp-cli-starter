//! Static shell completions and man pages for the workspace binaries.
//!
//! Both binaries offer `completions` and `man` subcommands; this module holds
//! the one implementation they share. Neither needs config or an API client,
//! so callers can run them before loading any configuration.

use std::io;
use std::path::Path;

use clap::{Command, ValueEnum};
use clap_complete::{Shell, generate};
use clap_complete_nushell::Nushell;

/// Shells a static completion script can be generated for.
///
/// Extends `clap_complete`'s built-in [`Shell`] set with Nushell (via
/// `clap_complete_nushell`), which `clap_complete` does not ship.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CompletionShell {
    /// Bash.
    Bash,
    /// Elvish.
    Elvish,
    /// Fish.
    Fish,
    /// Nushell.
    Nushell,
    /// `PowerShell`.
    #[value(name = "powershell")]
    PowerShell,
    /// Zsh.
    Zsh,
}

/// Writes a static shell completion script for `cmd` to stdout.
pub fn write_completions(shell: CompletionShell, mut cmd: Command) {
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

/// Generates man pages for `cmd` and all subcommands into `out_dir`, creating
/// the directory if it does not exist.
///
/// # Errors
///
/// Returns an I/O error if `out_dir` cannot be created or a page cannot be
/// written.
pub fn write_man_pages(cmd: Command, out_dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(out_dir)?;
    clap_mangen::generate_to(cmd, out_dir)
}
