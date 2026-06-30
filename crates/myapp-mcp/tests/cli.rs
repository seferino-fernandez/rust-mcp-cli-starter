//! MCP server CLI smoke tests via `assert_cmd`.

use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn completions_generates_static_script() {
    Command::cargo_bin("myapp-mcp")
        .unwrap()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(contains("myapp-mcp"));
}

#[test]
fn dynamic_completion_registration() {
    // With COMPLETE set and no completion args, the binary prints its registration script.
    Command::cargo_bin("myapp-mcp")
        .unwrap()
        .env("COMPLETE", "bash")
        .assert()
        .success()
        .stdout(contains("COMPLETE"));
}
