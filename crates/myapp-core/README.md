# myapp-core

Async Rust client library for the MYAPP API.

This is the core crate of a [`cargo-generate`](https://cargo-generate.github.io/cargo-generate/) starter template for building three-crate Rust API wrappers (library + CLI + MCP server) around a single long-lived API key. Generate a new project from it to get a working client you can adapt to your own API.

It powers the `myapp-cli` terminal app and the `myapp-mcp` Model Context Protocol server.

## Features

- Authenticated HTTP client (`ApiClient`) that sends the configured API key as the `X-Api-Key` header on every request.
- Layered [`Config`] loading: CLI flag → `MYAPP_*` env → `MYAPP_*_FILE` secret files → `config.toml` → defaults.
- Typed error model (`Error`) covering transport failures, API errors, and rate limiting (HTTP 429).
- A generic pagination envelope (`Page<T>`) and example endpoint methods you replace with your own.

## Example

```rust,no_run
use myapp_core::{ApiClient, Config};

# async fn run() -> myapp_core::Result<()> {
let config = Config::load(None)?;
let client = ApiClient::new(config)?;

let status = client.system_status().await?;
println!("{} v{}", status.app_name, status.version);
# Ok(())
# }
```

Set the API key via `MYAPP_API_KEY`, `MYAPP_API_KEY_FILE`, or `api_key` in `config.toml`.

## License

[MIT](../../LICENSE.md)
