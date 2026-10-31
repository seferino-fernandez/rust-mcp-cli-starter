# myapp-core

Async Rust client library for the MYAPP API.

This is the core crate of a [`cargo-generate`](https://cargo-generate.github.io/cargo-generate/) starter template for building three-crate Rust API wrappers (library + CLI + MCP server) around a single long-lived API key. Generate a new project from it to get a working client you can adapt to your own API.

It powers the `myapp-cli` terminal app and the `myapp-mcp` Model Context Protocol server.

## Features

- Authenticated HTTP client (`ApiClient`) that sends the configured API key as the `X-Api-Key` header on every request.
- Layered [`Config`] loading: CLI flag (as `ConfigOverrides`) → `MYAPP_*` env → `MYAPP_*_FILE` secret files → `config.toml` → defaults. A losing layer's secret file is never read; a bad env value, a missing `--config` / `MYAPP_CONFIG` file, or invalid TOML is an error naming its source.
- Typed error model (`Error`) covering transport failures, API errors, redirects, decode failures, configuration errors (`ConfigError`), and rate limiting (HTTP 429). Each cause prints once in a cause chain, and `Error::public_message()` is the one message safe to show a user: it never holds an upstream body, a request URL, a header, or a secret.
- Redirects are never followed, so the API key is never sent on to another host; a 3xx response is `Error::Redirected`. Upstream error bodies are redacted and capped at 8 KiB, and transport errors have the secrets in their URL masked.
- Output redaction as a type: `Redacted<T>` (built by `Redacted::new` or `ApiClient::redact`) masks the forms listed under [Redaction](#redaction), in time linear in the text, and keeps `T`'s JSON schema.
- A generic pagination envelope (`Page<T>`) and example endpoint methods you replace with your own.

## Redaction

Redaction is pattern-based: it masks the forms below as `********`, and a secret in a shape it does not recognize is shown as is.

- **Sensitive keys.** A key is sensitive when it, or a trailing run of its parts, is `apikey`, `api_key`, `apitoken`, `accesskey`, `password`, `passwordconfirmation`, `sslcertpassword`, `proxypassword`, `passwd`, `pwd`, `passphrase`, `passkey`, `secret`, `token`, `privatekey`, `credential` or `cookie`, in any case. Any of these but `token` may also end in `s` (`apiKeys`, `secrets`); `tokens` is left alone because it is nearly always a count. Parts split at `-`, `_` and camelCase boundaries, a leading `x-` or `x_` is dropped, and percent escapes are decoded first. So `X-Api-Key`, `client_secret`, `accessToken`, `refresh_token`, `AWS_SECRET_ACCESS_KEY`, `Set-Cookie` and `api%5Fkey` are sensitive, while `mytoken`, `authtoken`, `maxTokens`, `keyboard` and bare `key`, `pass` or `auth` are not. `Authorization` and `Proxy-Authorization` are sensitive too.
- **Object values.** Under a sensitive object key, a string, and every string inside an array or object there. Numbers, booleans and null are never changed, so `maxTokens: 4096`, `hasPassword: true` and a numeric `token` stay as they are and the output still matches its schema. A secret stored as a number is therefore not masked.
- **Pairs in text.** The value after a sensitive key and `=`, `:`, `:=`, `%3D` or `%3A`, in a query string, a `;` list, a header line, or a `key: value` pair split by whitespace. The key may be quoted (`'token': x`, `` `password`=x ``, `"secret"=x`). A quoted value keeps its quotes (`'********'`) only when its closing quote ends the value or is followed only by `,`, `;`, `}`, `]` or `)`; otherwise the whole value is masked, as in `token=********` for `token='abc'def`.
- **Percent-encoded text.** A `%` escape that decodes to a letter, digit, `-` or `_` is part of a key; any other escape ends one, so `%3Fapikey=x` masks. A token holding `%3A%2F%2F`, `%26`, `%3D` or `%3F` is also read percent-decoded once, and what the pair, path, header and user-information rules mask there is masked in the original, so `?url=https%3A%2F%2Fh%2Fdl%3Fapikey%3Dx` and `url=https%3A%2F%2Fu%3Ax%40h` mask `x`. A doubly encoded value is decoded only once.
- **Path segments.** The segment after a sensitive path segment, as in `/passkey/<x>/`.
- **User information.** After any `//`, for every scheme (`https://u:p@h`, `postgres://admin:pw@db`) and scheme-relative `//u:p@h`, the password, or the whole user information when it has no `:`. When the authority holds no `@`, as when a `/` in a password cut it short (`https://u:p/w@host`), everything from `//` up to the only `@` before the next whitespace is masked if a `:` comes between them; `medium.com/@user` and `?email=a@b.com` stay readable.
- **Header credentials.** After `Authorization` or `Proxy-Authorization` and `:`, `:=`, `=`, `%3A` or `%3D`: the token after `Bearer`; everything after any other all-letter scheme (`Basic`, `Digest`) to the end of the line; and, when the next word is anything else (`AWS4-HMAC-SHA256`, a bare credential), everything from that word to the end of the line. After `Cookie` or `Set-Cookie`, everything to the end of the line. As a query parameter (`?authorization=Bearer%20x`) the whole value is masked, and when another token follows on the same line (`?authorization=Bearer x`) the header rules apply to it too.
- **Embedded JSON.** The string after a quoted sensitive key in JSON or Python-style text, quoted with `"`, `'` or `\"`.
- **Object keys.** Keys get the text rules too, so a map keyed by a URL with user information is masked. Keys that become equal once masked are all kept, the later ones suffixed ` (2)`, ` (3)`, and so on.
- **The API key.** `ApiClient::redact` and every error built from a response also mask the configured API key itself, in raw, JSON-escaped and form-encoded forms, in string values and keys, before and after the rules above. An empty or whitespace-only key is refused at load. A very short key is still masked wherever it appears, which can mangle unrelated output.

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
