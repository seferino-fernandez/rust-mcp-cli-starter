# myapp-cli

Terminal CLI for the MYAPP API, built on [myapp-core](../myapp-core/).

## Build

```bash
cargo build --release -p myapp-cli
```

The binary is written to `target/release/myapp`. Add it to your `PATH` or invoke it directly.

## Commands

| Command       | Description                                     |
| ------------- | ----------------------------------------------- |
| `status`      | Show upstream server health.                    |
| `item list`   | List items (paginated, `--page`/`--page-size`). |
| `item get`    | Fetch a single item by id.                      |
| `item create` | Create an item (`<name>`, `--enabled`).         |
| `item delete` | Delete an item by id.                           |

```bash
# Server health
myapp status

# List the first page of items
myapp item list --page 1 --page-size 20

# Fetch / create / delete
myapp item get 42
myapp item create "my item" --enabled
myapp item delete 42
```

## Output formats

`--output table|json|csv` (default: `table`) is a global flag accepted by every command.
Logs go to stderr, so stdout carries only structured data when `--output json` or
`--output csv` is active, which makes it safe to pipe.

```bash
myapp --output json item list | jq '.[] | {id, name}'
myapp --output csv item list > items.csv
```

## Configuration

Config file default location: `~/.config/myapp/config.toml`
(override with `--config <PATH>` or `MYAPP_CONFIG`).

Resolution precedence (highest first): CLI flag, then `MYAPP_*` env, then `MYAPP_*_FILE` env, then `config.toml`, then built-in defaults.

| Flag / Env                      | Description                                           |
| ------------------------------- | ----------------------------------------------------- |
| `--base-url` / `MYAPP_BASE_URL` | Upstream API base URL.                                |
| `--api-key` / `MYAPP_API_KEY`   | API key sent as the `X-Api-Key` header.               |
| `MYAPP_API_KEY_FILE`            | Path to a file containing the API key.                |
| `--config` / `MYAPP_CONFIG`     | Path to `config.toml`.                                |
| `MYAPP_LOG_LEVEL`               | Log level: `trace`, `debug`, `info`, `warn`, `error`. |

Prefer `MYAPP_API_KEY` or config over `--api-key` to avoid exposing the key in
process listings (e.g. `ps`).

See [config.toml.example](../../config.toml.example) for all fields and defaults.
