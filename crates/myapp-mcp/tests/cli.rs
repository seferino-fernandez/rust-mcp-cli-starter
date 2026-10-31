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

#[test]
fn missing_explicit_config_file_is_an_error() {
    let missing = std::env::temp_dir().join(format!(
        "myapp-mcp-missing-config-{}/config.toml",
        std::process::id()
    ));
    Command::cargo_bin("myapp-mcp")
        .unwrap()
        .env_clear()
        .arg("--config")
        .arg(&missing)
        .write_stdin("")
        .assert()
        .failure()
        .stderr(contains(format!(
            "config file {} does not exist",
            missing.display()
        )));
}

#[test]
fn missing_env_config_file_is_an_error_naming_the_variable() {
    Command::cargo_bin("myapp-mcp")
        .unwrap()
        .env_clear()
        .env("MYAPP_CONFIG", "/nonexistent/myapp/config.toml")
        .write_stdin("")
        .assert()
        .failure()
        .stderr(contains(
            "config file /nonexistent/myapp/config.toml set by MYAPP_CONFIG does not exist",
        ));
}

#[test]
fn kebab_cased_auth_mode_is_rejected() {
    Command::cargo_bin("myapp-mcp")
        .unwrap()
        .args(["--auth-mode", "o-auth"])
        .assert()
        .failure()
        .stderr(contains("invalid value 'o-auth'"));
}

#[test]
fn http_refuses_a_whitespace_token_at_startup() {
    let config =
        std::env::temp_dir().join(format!("myapp-mcp-blank-token-{}.toml", std::process::id()));
    std::fs::write(&config, "").unwrap();
    let assert = Command::cargo_bin("myapp-mcp")
        .unwrap()
        .env_clear()
        .arg("--config")
        .arg(&config)
        .args(["--transport", "http", "--port", "0", "--token", "   "])
        .assert();
    std::fs::remove_file(&config).unwrap();
    assert
        .failure()
        .stderr(contains("requires a non-empty token").and(contains("MYAPP_MCP_TOKEN_FILE")));
}
