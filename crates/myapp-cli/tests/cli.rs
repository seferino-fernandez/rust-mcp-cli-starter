//! CLI smoke tests via `assert_cmd`.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

#[test]
fn help_lists_subcommands() {
    Command::cargo_bin("myapp")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("status").and(contains("item")));
}

#[test]
fn completions_generates_static_script() {
    Command::cargo_bin("myapp")
        .unwrap()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(contains("myapp"));
}

#[test]
fn dynamic_completion_registration() {
    // With COMPLETE set and no completion args, the binary prints its registration script.
    Command::cargo_bin("myapp")
        .unwrap()
        .env("COMPLETE", "bash")
        .assert()
        .success()
        .stdout(contains("COMPLETE"));
}

#[test]
fn missing_api_key_errors_clearly() {
    // No key from any source → build_client fails with a clear message.
    Command::cargo_bin("myapp")
        .unwrap()
        .env_clear()
        .env("MYAPP_CONFIG", "/nonexistent/config.toml")
        .args(["status"])
        .assert()
        .failure()
        .stderr(contains("no API key configured"));
}
