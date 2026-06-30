//! MCP server CLI smoke tests via `assert_cmd`.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

#[test]
fn help_lists_verbosity_flags() {
    Command::cargo_bin("myapp-mcp")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("--verbose").and(contains("--quiet")));
}

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
fn completions_generates_nushell_script() {
    Command::cargo_bin("myapp-mcp")
        .unwrap()
        .args(["completions", "nushell"])
        .assert()
        .success()
        .stdout(contains("export extern myapp-mcp"));
}

#[test]
fn man_generates_pages() {
    let dir = std::env::temp_dir().join(format!("myapp-mcp-man-test-{}", std::process::id()));
    Command::cargo_bin("myapp-mcp")
        .unwrap()
        .args(["man", dir.to_str().unwrap()])
        .assert()
        .success();
    assert!(dir.join("myapp-mcp.1").exists());
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
