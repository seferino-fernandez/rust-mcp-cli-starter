# myapp-mcp

MCP server exposing the MYAPP API as tools for LLM clients.

Built on [rmcp](https://github.com/modelcontextprotocol/rust-sdk) and [myapp-core](../myapp-core/).

## Transports

- `stdio` for Claude Desktop, Claude Code, and other local MCP clients
- `http` (streamable HTTP with session management) for remote deployments

## Authentication modes

| Mode    | Flag                | Description                                         |
| ------- | ------------------- | --------------------------------------------------- |
| `token` | `--auth-mode token` | Static bearer token (default)                       |
| `oauth` | `--auth-mode oauth` | OAuth 2.1 with PKCE and dynamic client registration |
| `none`  | `--auth-mode none`  | No auth (loopback-only, local development)          |

## Quick start

```bash
# stdio transport
myapp-mcp --transport stdio

# HTTP with static token
myapp-mcp --transport http --auth-mode token --token my-secret

# HTTP with OAuth
myapp-mcp --transport http --auth-mode oauth --port 8080
```

## Example tools

| Tool                | Description                                 |
| ------------------- | ------------------------------------------- |
| `get_system_status` | Server health/status                        |
| `list_items`        | List items (paginated: `page`, `page_size`) |
| `get_item`          | Fetch one item by `id`                      |
| `create_item`       | Create an item (`name`, `enabled`)          |
| `delete_item`       | Delete an item by `id`                      |

## Shell completions

`myapp-mcp` supports both static and dynamic shell completions (bash, zsh, fish,
elvish, powershell).

```bash
# Static: generate a script and install it where your shell looks for it
myapp-mcp completions zsh > ~/.zsh/completions/_myapp-mcp

# Dynamic: let the binary drive completions at runtime (re-source after upgrades)
echo 'source <(COMPLETE=zsh myapp-mcp)' >> ~/.zshrc
```

Running `myapp-mcp` with no subcommand still starts the server as usual.

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
