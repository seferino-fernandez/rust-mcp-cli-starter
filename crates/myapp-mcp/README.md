# myapp-mcp

MCP server exposing the MYAPP API as tools for LLM clients.

Built on [rmcp](https://github.com/modelcontextprotocol/rust-sdk) 3.x and [myapp-core](../myapp-core/).

Implements the MCP [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
specification, and negotiates down to every earlier version `rmcp` supports.

## Transports

- `stdio` for Claude Desktop, Claude Code, and other local MCP clients
- `http` (streamable HTTP) for remote deployments

### Sessions and the 2026-07-28 boundary

SEP-2567 removed sessions from the 2026-07-28 protocol, so the transport runs in
dual mode:

| Negotiated version     | Behavior                                                                                                                                                  |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `2026-07-28`           | Stateless. No `Mcp-Session-Id`, no GET/DELETE, no resumption. Results carry `resultType`, and `tools/list` carries SEP-2549 `ttlMs` / `cacheScope` hints. |
| `2025-11-25` and older | Session-based, with SSE priming and resumability. Legacy wire shape preserved - no `resultType`.                                                          |

Controlled by `legacy_session_mode` in `http.rs`; it only affects pre-2026-07-28
clients, since modern requests are always stateless.

### Host validation

The streamable HTTP transport rejects requests whose `Host` header is not in
`[mcp] allowed_hosts` (a DNS-rebinding guard), which defaults to loopback only.
**Deploying to a non-loopback address requires setting it**, via TOML or
`MYAPP_MCP_ALLOWED_HOSTS` (comma-separated). An empty list disables the check
entirely.

### SEP-2243 routing headers

Clients negotiating 2026-07-28 send `Mcp-Method` and `Mcp-Name` alongside the
JSON-RPC body so gateways can route without parsing it. A tool can promote a
top-level primitive argument to an `Mcp-Param-*` header with the `x-mcp-header`
schema annotation; `ItemIdParams::id` does this as a worked example, surfacing
as `Mcp-Param-Item-Id`. The server validates these headers against the body and
rejects mismatches.

## Authentication modes

| Mode    | Flag                | Description                                         |
| ------- | ------------------- | --------------------------------------------------- |
| `token` | `--auth-mode token` | Static bearer token (default)                       |
| `oauth` | `--auth-mode oauth` | OAuth 2.1 with PKCE and dynamic client registration |
| `none`  | `--auth-mode none`  | No auth (loopback-only, local development)          |

## Quick start

stdio transport:

```bash
myapp-mcp --transport stdio
```

HTTP with static token

```shell
myapp-mcp --transport http --auth-mode token --token my-secret
```

HTTP with OAuth:

```shell
myapp-mcp --transport http --auth-mode oauth --port 8080
```

## Logging verbosity

`-v`/`--verbose` and `-q`/`--quiet` adjust the log level (`-q` silent; `-v` warn,
`-vv` info, `-vvv` debug, `-vvvv` trace). Default level precedence, highest first:

`RUST_LOG` → `-v`/`-q` (when passed) → `MYAPP_LOG_LEVEL` / config `log.level` → default (`info`)

So `myapp-mcp -q --transport stdio` quiets a run without touching config, while
config / `MYAPP_LOG_LEVEL` still apply when no flag is given.

## Example tools

| Tool                | Description                                 |
| ------------------- | ------------------------------------------- |
| `get_system_status` | Server health/status                        |
| `list_items`        | List items (paginated: `page`, `page_size`) |
| `get_item`          | Fetch one item by `id`                      |
| `create_item`       | Create an item (`name`, `enabled`)          |
| `delete_item`       | Delete an item by `id`                      |

## Shell completions

`myapp-mcp` supports static completions for bash, elvish, fish, nushell,
powershell, and zsh, plus dynamic completions for every shell except nushell.

Static: generate a script and install it where your shell looks for it

```shell
myapp-mcp completions zsh > ~/.zsh/completions/_myapp-mcp
```

```shell
myapp-mcp completions nushell > ~/.config/nushell/completions/myapp-mcp.nu
```

Dynamic: let the binary drive completions at runtime (re-source after upgrades)

```shell
echo 'source <(COMPLETE=zsh myapp-mcp)' >> ~/.zshrc
```

Running `myapp-mcp` with no subcommand still starts the server as usual.

## Man pages

Generate ROFF man pages for the server and every subcommand into a directory
(created if missing):

```shell
myapp-mcp man ./man
man -l ./man/myapp-mcp.1
```

## Configuration

Config file default: `~/.config/myapp/config.toml` (or `--config` / `MYAPP_CONFIG`).

| Variable                            | Description                          |
| ----------------------------------- | ------------------------------------ |
| `MYAPP_BASE_URL`                    | Upstream API base URL                |
| `MYAPP_API_KEY`                     | API key sent as `X-Api-Key`          |
| `MYAPP_MCP_HOST`                    | Bind address                         |
| `MYAPP_MCP_PORT`                    | Bind port                            |
| `MYAPP_MCP_AUTH_MODE`               | Authentication mode                  |
| `MYAPP_MCP_TOKEN`                   | Static bearer token                  |
| `MYAPP_MCP_TOKEN_FILE`              | Path to file containing bearer token |
| `MYAPP_MCP_BASE_URL`                | External base URL for OAuth          |
| `MYAPP_MCP_OAUTH_PIN`               | OAuth consent screen PIN             |
| `MYAPP_MCP_OAUTH_TOKEN_EXPIRY_SECS` | OAuth token lifetime (default: 3600) |

See [config.toml.example](../../config.toml.example) for all available fields.
