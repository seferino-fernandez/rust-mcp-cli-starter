# Rust MCP + CLI Template

A [`cargo-generate`](https://cargo-generate.github.io/cargo-generate/) starter
template for wrapping an HTTP API as three Rust crates: a library, a CLI, and an
MCP server. It targets the common case of an API authenticated with a single
long-lived API key sent as an `X-Api-Key` header against a configurable base URL.

## Crates

| Crate        | Description                              |
| ------------ | ---------------------------------------- |
| `myapp-core` | Async API client library                 |
| `myapp-cli`  | Terminal CLI (`myapp`)                   |
| `myapp-mcp`  | MCP server (`myapp-mcp`) for LLM clients |

The CLI and the MCP server both depend on the core library, so the request,
auth, config, and error handling live in one place:

```text
            myapp-core  (ApiClient, Config, models, errors)
              /     \
       myapp-cli   myapp-mcp
     (clap CLI)   (rmcp: stdio + streamable HTTP)
```

## Use this template

```bash
cargo generate --git https://github.com/seferino-fernandez/rust-mcp-cli-starter --name acme-tools --allow-commands
```

This renames everything (`myapp` → `acme-tools`, `MYAPP_` → `ACME_TOOLS_`).

`--allow-commands` is required because the generation hook runs `sed`/`cargo fmt`
to rename the project; without it, cargo-generate prompts for confirmation
(interactive) or fails (with `--silent`).

## Quick start (after generating)

```bash
cargo build
cargo test
MYAPP_BASE_URL=http://localhost:8080 MYAPP_API_KEY=xxxx cargo run -p myapp-cli -- status
```

Configuration is layered, highest precedence first:
CLI flag, then `MYAPP_*` env, then `MYAPP_*_FILE` env, then `config.toml`, then
built-in defaults. See [`config.toml.example`](config.toml.example) for every setting.

## MCP server

`myapp-mcp` exposes the same API to LLM clients over two transports:

- `stdio`: for local clients such as Claude Desktop.
- `http` (streamable HTTP): for networked clients, with a choice of auth mode:
  - `token`: static bearer token (constant-time compared).
  - `oauth`: OAuth 2.1 authorization-code flow with PKCE.
  - `none`: no auth (loopback only).

Tool input schemas are closed (`additionalProperties: false`) and tool results
are capped to a configurable byte budget. See the
[`myapp-mcp` README](crates/myapp-mcp/README.md) for details.

## License

[MIT](LICENSE.md)
