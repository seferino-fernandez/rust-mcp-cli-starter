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
fn completions_generates_nushell_script() {
    Command::cargo_bin("myapp")
        .unwrap()
        .args(["completions", "nushell"])
        .assert()
        .success()
        .stdout(contains("export extern myapp"));
}

#[test]
fn man_generates_pages() {
    let dir = std::env::temp_dir().join(format!("myapp-man-test-{}", std::process::id()));
    Command::cargo_bin("myapp")
        .unwrap()
        .args(["man", dir.to_str().unwrap()])
        .assert()
        .success();
    assert!(dir.join("myapp.1").exists());
}

#[test]
fn help_lists_verbosity_flags() {
    Command::cargo_bin("myapp")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("--verbose").and(contains("--quiet")));
}

#[test]
fn verbosity_flag_parses() {
    // `-v` parses on the top-level command; completions short-circuit before any client.
    Command::cargo_bin("myapp")
        .unwrap()
        .args(["-v", "completions", "bash"])
        .assert()
        .success();
}

/// Writes `contents` to a per-test config file under the temp dir and returns
/// its path, so no test reads the real user config.
#[expect(clippy::unwrap_used, reason = "unwrap is fine in test helpers")]
fn config_file(test: &str, contents: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("myapp-cli-{test}-{}.toml", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn missing_api_key_errors_clearly() {
    // No key from any source → build_client fails with a clear message.
    let config = config_file("missing-api-key", "");
    Command::cargo_bin("myapp")
        .unwrap()
        .env_clear()
        .env("MYAPP_CONFIG", &config)
        .args(["status"])
        .assert()
        .failure()
        .stderr(contains("no API key configured"));
    std::fs::remove_file(&config).unwrap();
}

#[test]
fn missing_explicit_config_file_errors_naming_the_path() {
    Command::cargo_bin("myapp")
        .unwrap()
        .env_clear()
        .args(["--config", "/nonexistent/myapp/config.toml", "status"])
        .assert()
        .failure()
        .stderr(contains(
            "config file /nonexistent/myapp/config.toml does not exist",
        ));
}

#[test]
fn missing_env_config_file_errors_naming_the_variable() {
    Command::cargo_bin("myapp")
        .unwrap()
        .env_clear()
        .env("MYAPP_CONFIG", "/nonexistent/myapp/config.toml")
        .args(["status"])
        .assert()
        .failure()
        .stderr(contains(
            "config file /nonexistent/myapp/config.toml set by MYAPP_CONFIG does not exist",
        ));
}

#[test]
fn invalid_env_value_errors_naming_the_variable() {
    let config = config_file("invalid-env", "");
    Command::cargo_bin("myapp")
        .unwrap()
        .env_clear()
        .env("MYAPP_CONFIG", &config)
        .env("MYAPP_HTTP_REQUEST_TIMEOUT_SECS", "soon")
        .args(["status"])
        .assert()
        .failure()
        .stderr(contains(
            r#"invalid MYAPP_HTTP_REQUEST_TIMEOUT_SECS value "soon""#,
        ));
    std::fs::remove_file(&config).unwrap();
}

#[test]
fn toml_error_does_not_echo_a_secret() {
    let config = config_file("toml-secret", "api_key = \"SENTINEL-SECRET\" junk\n");
    Command::cargo_bin("myapp")
        .unwrap()
        .env_clear()
        .env("MYAPP_CONFIG", &config)
        .args(["status"])
        .assert()
        .failure()
        .stderr(contains("line 1, column").and(contains("SENTINEL").not()));
    std::fs::remove_file(&config).unwrap();
}

#[test]
fn invalid_log_level_warns_and_falls_back_to_errors_only() {
    let config = config_file("invalid-log-level", "[log]\nlevel = \"loud\"\n");
    Command::cargo_bin("myapp")
        .unwrap()
        .env_clear()
        .env("MYAPP_CONFIG", &config)
        .args(["status"])
        .assert()
        .failure()
        .stderr(
            contains("myapp: warning: ignoring invalid log level \"loud\"")
                .and(contains("using error"))
                .and(contains("no API key configured")),
        );
    std::fs::remove_file(&config).unwrap();
}
