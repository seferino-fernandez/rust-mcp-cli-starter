//! MCP server default log level tests via `assert_cmd`.

#![expect(clippy::unwrap_used, reason = "unwrap is fine in test helpers")]

use assert_cmd::Command;
use predicates::Predicate;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

const STARTUP_LINE: &str = "myapp-mcp starting";

/// Runs the stdio server against a config file holding `toml` and returns its
/// stderr. The startup line is logged before the transport starts; with no API
/// key configured the server exits right after it, so the run cannot hang.
/// Empty stdin backs this up. The exit status is not asserted: only the
/// startup log matters.
fn startup_stderr(toml: &str, configure: impl FnOnce(&mut Command)) -> String {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, toml).unwrap();
    let mut command = Command::cargo_bin("myapp-mcp").unwrap();
    command
        .env_clear()
        .env("NO_COLOR", "1")
        .arg("--config")
        .arg(&config)
        .write_stdin("");
    configure(&mut command);
    let output = command.output().unwrap();
    String::from_utf8(output.stderr).unwrap()
}

#[test]
fn unset_log_level_defaults_to_info() {
    let stderr = startup_stderr("", |_| {});
    assert!(contains(STARTUP_LINE).eval(&stderr), "stderr: {stderr}");
}

#[test]
fn quiet_flag_silences_startup_line() {
    let stderr = startup_stderr("", |command| {
        command.arg("-q");
    });
    assert!(
        contains(STARTUP_LINE).not().eval(&stderr),
        "stderr: {stderr}"
    );
}

#[test]
fn log_level_env_warn_hides_startup_line() {
    let stderr = startup_stderr("", |command| {
        command.env("MYAPP_LOG_LEVEL", "warn");
    });
    assert!(
        contains(STARTUP_LINE).not().eval(&stderr),
        "stderr: {stderr}"
    );
}

#[test]
fn toml_log_level_warn_hides_startup_line() {
    let stderr = startup_stderr("[log]\nlevel = \"warn\"\n", |_| {});
    assert!(
        contains(STARTUP_LINE).not().eval(&stderr),
        "stderr: {stderr}"
    );
}

#[test]
fn verbosity_flag_beats_configured_level() {
    // `-vv` is info, which shows the startup line the configured `warn` hides.
    let stderr = startup_stderr("[log]\nlevel = \"warn\"\n", |command| {
        command.arg("-vv");
    });
    assert!(contains(STARTUP_LINE).eval(&stderr), "stderr: {stderr}");
}

#[test]
fn invalid_log_level_warns_and_falls_back_to_info() {
    let stderr = startup_stderr("", |command| {
        command.env("MYAPP_LOG_LEVEL", "loud");
    });
    assert!(
        contains("myapp-mcp: warning: ignoring invalid log level \"loud\"")
            .and(contains("using info"))
            .eval(&stderr),
        "stderr: {stderr}"
    );
    assert!(contains(STARTUP_LINE).eval(&stderr), "stderr: {stderr}");
}
