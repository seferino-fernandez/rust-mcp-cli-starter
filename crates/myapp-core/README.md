# myapp-core

Async Rust client library for the MYAPP API.

This is the core crate of a [`cargo-generate`](https://cargo-generate.github.io/cargo-generate/) starter template for building three-crate Rust API wrappers (library + CLI + MCP server) around a single long-lived API key. Generate a new project from it to get a working client you can adapt to your own API.

It powers the `myapp-cli` terminal app and the `myapp-mcp` Model Context Protocol server.

## Features

- Authenticated HTTP client (`ApiClient`) that sends the configured API key as the `X-Api-Key` header on every request.
- Layered [`Config`] loading: CLI flag (as `ConfigOverrides`) → `MYAPP_*` env → `MYAPP_*_FILE` secret files → `config.toml` → defaults. A losing layer's secret file is never read; a bad env value, a missing `--config` / `MYAPP_CONFIG` file, or invalid TOML is an error naming its source.
- Typed error model (`Error`) covering transport failures, API errors, redirects, decode failures, configuration errors (`ConfigError`), and rate limiting (HTTP 429). Each cause prints once in a cause chain, and `Error::public_message()` is the one message safe to show a user: it never holds an upstream body, a request URL, a header, or a secret.
- Redirects are never followed, so the API key is never sent on to another host; a 3xx response is `Error::Redirected`. Upstream error bodies are redacted and capped at 8 KiB, and transport errors have the secrets in their URL masked.
- Output redaction as a type: `Redacted<T>` (built by `Redacted::new` or `ApiClient::redact`) masks secret-named keys, secret query values and path segments (`/passkey/<x>/`), URL user information, `Authorization` headers, and JSON embedded in strings, in linear time, while keeping `T`'s JSON schema. `ApiClient::redact` also masks the exact API key, before and after the other rules.
- A generic pagination envelope (`Page<T>`) and example endpoint methods you replace with your own.

## Example

```rust,no_run
use myapp_core::{ApiClient, Config, ConfigOverrides};

# async fn run() -> myapp_core::Result<()> {
let config = Config::load(None, &ConfigOverrides::default())?;
let client = ApiClient::new(config)?;

let status = client.system_status().await?;
println!("{} v{}", status.app_name, status.version);
# Ok(())
# }
```

Set the API key via `MYAPP_API_KEY`, `MYAPP_API_KEY_FILE`, or `api_key` in `config.toml`.

## License

[MIT](../../LICENSE.md)
