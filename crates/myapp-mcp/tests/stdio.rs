//! Exercise the binary through the pipes used by real MCP clients.

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[tokio::test]
async fn stdio_protocol_exchange_and_eof_exit() {
    // Covers startup, the exchange, and shutdown; kill_on_drop also cleans up
    // the subprocess if a protocol assertion fails or the deadline expires.
    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.toml");
        std::fs::write(&config, "").unwrap();
        let mut child = Command::new(assert_cmd::cargo::cargo_bin("myapp-mcp"))
            .env_clear()
            .env("MYAPP_API_KEY", "stdio-test-key")
            .arg("--config")
            .arg(config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let initialize = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "stdio-test", "version": "0"}
            }
        });
        stdin
            .write_all(format!("{initialize}\n").as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).await.unwrap();
        let initialize_response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(initialize_response["id"], 1);
        assert_eq!(
            initialize_response["result"]["protocolVersion"],
            "2025-11-25"
        );
        assert!(initialize_response["result"]["capabilities"]["tools"].is_object());

        let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
        stdin
            .write_all(format!("{initialized}\n{list}\n").as_bytes())
            .await
            .unwrap();
        line.clear();
        stdout.read_line(&mut line).await.unwrap();
        let list_response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(list_response["id"], 2);
        let tools = list_response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 5);
        assert!(tools.iter().any(|tool| tool["name"] == "myapp_list_items"));

        drop(stdin);
        let mut remaining = String::new();
        stdout.read_to_string(&mut remaining).await.unwrap();
        assert!(remaining.is_empty(), "unexpected stdout: {remaining}");
        let output = child.wait_with_output().await.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    })
    .await
    .expect("stdio exchange and EOF shutdown must finish within the deadline");
}
