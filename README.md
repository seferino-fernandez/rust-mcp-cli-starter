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

cargo-generate also prompts for `github_org`, the GitHub user or organization
that will host the repository (default `your-org`). It fills in the
`repository`/`homepage` URLs in `Cargo.toml` and the image path in
`deploy/compose.yaml`. Pass it up front with `--define github_org=acme-corp`.

The generated project gets its own `README.md` (from
[`README.generated.md`](README.generated.md)) and an MIT `LICENSE.md` naming
you (from your git `user.name`) with the current year.

`--allow-commands` is required because the generation hook runs `sed`/`cargo fmt`
to rename the project; without it, cargo-generate prompts for confirmation
(interactive) or fails (with `--silent`).

## Quick start (after generating)

Build the project:

```shell
cargo build
```

Run the project's tests:

```shell
cargo test
```

Run a command from the CLI module:

```shell
MYAPP_BASE_URL=http://localhost:8080 MYAPP_API_KEY=xxxx cargo run -p myapp-cli -- status
```

Configuration is layered, highest precedence first:
CLI flag, then `MYAPP_*` env, then `MYAPP_*_FILE` env, then `config.toml`, then
built-in defaults. See [`config.toml.example`](config.toml.example) for every setting.
Only the winning layer of a secret is read, so a `*_FILE` behind a higher layer
is never opened, and the MCP server's stdio transport never reads the
HTTP-only `token` and `oauth_pin`. Mistakes fail at startup: an env value that
does not parse is an error naming the variable, a config file named by
`--config` or `MYAPP_CONFIG` must exist, and a TOML error reports the line and
column without echoing the line.

## Logging and verbosity flag

Both binaries take `-v`/`--verbose` and `-q`/`--quiet` flags: `-q` silent;
`-v` warn, `-vv` info, `-vvv` debug, `-vvvv` trace. Default level precedence,
highest first:

`RUST_LOG` → `-v`/`-q` (when passed) → `MYAPP_LOG_LEVEL` / `[log] level` → built-in default

The built-in default is `error` for the `myapp` CLI and `info` for the
`myapp-mcp` server. An invalid configured level prints a warning and falls back
to that default. Place the flag before the subcommand: `myapp -v status`.
`RUST_LOG` overrides everything (e.g. `RUST_LOG=myapp_core=trace,reqwest=debug`).

## Shell completions

The `myapp` CLI supports static completions for bash, elvish, fish, nushell,
powershell, and zsh, plus dynamic completions for every shell except nushell.

**Static** - generate a script once and install it where your shell looks for it:

```shell
myapp completions zsh     > ~/.zsh/completions/_myapp
```

```shell
myapp completions bash    | sudo tee /usr/share/bash-completion/completions/myapp
```

```shell
myapp completions fish    > ~/.config/fish/completions/myapp.fish
```

```shell
myapp completions nushell > ~/.config/nushell/completions/myapp.nu
```

**Dynamic** - let the binary drive completions at runtime via the `COMPLETE`
environment variable. Add one line to your shell startup file:

```shell
echo 'source <(COMPLETE=zsh myapp)'  >> ~/.zshrc
```

```shell
echo 'source <(COMPLETE=bash myapp)' >> ~/.bashrc
```

```shell
echo 'COMPLETE=fish myapp | source'  >> ~/.config/fish/completions/myapp.fish
```

## Man pages

The `myapp` CLI generates ROFF man pages for itself and every subcommand into a
directory (created if missing):

```bash
myapp man ~/.local/share/man/man1
```

## MCP server

`myapp-mcp` implements MCP **2026-07-28** (`rmcp 3.x`) and exposes the same API to
LLM clients over two transports:

- `stdio`: for local clients such as Claude Desktop.
- `http` (streamable HTTP): for networked clients, with a choice of auth mode:
    - `token`: static bearer token (constant-time compared).
    - `oauth`: OAuth 2.1 authorization-code flow with PKCE, public clients,
      a server-rendered consent page, and a consent PIN (required off loopback).
    - `none`: no auth (loopback only).

Older clients still negotiate down: the server accepts every protocol version
rmcp knows, so a 2025-11-25 client keeps its session and resumability while a
2026-07-28 client is served statelessly.

Tool names carry a `myapp_` prefix. Tool input schemas are closed
(`additionalProperties: false`) and unknown arguments are refused, tool results
are capped to a configurable byte budget, OAuth tokens without the `write`
scope may call only read-only tools, and destructive tools ask capable clients
for confirmation (`confirm_destructive`). Tool results pass through
`Redacted<T>`, which masks the credential forms listed in the
[`myapp-core` README](crates/myapp-core/README.md#redaction) and the configured API key;
it is pattern-based, so a secret in a shape it does not recognize is not
masked. Both the CLI and the MCP server show errors only through
`Error::public_message()`, never an upstream body or URL. See the
[`myapp-mcp` README](crates/myapp-mcp/README.md) for details.

## License

[MIT](LICENSE.md)
