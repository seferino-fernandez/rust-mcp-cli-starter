# AGENTS.md

This repository is a `cargo-generate` template. `pre-script.rhai` turns it into a project: it selects the MCP transport variant, renames `myapp`/`MYAPP` to the project name, and swaps in `README.generated.md` and `AGENTS.generated.md` as the project's `README.md` and `AGENTS.md`.

The rules in [AGENTS.generated.md](AGENTS.generated.md) apply here too. On top of them:

1. Keep HTTP-only and OAuth-only code, dependencies and docs inside `template:begin http` / `template:end http` (or `oauth`) comment markers, so the `stdio` and `http` variants generate without it. Markers nest, and a mismatched pair fails generation. `tombi.toml` turns off Cargo.toml key sorting so formatting never moves an entry across a marker.
2. A change is done when `just verify` passes here **and** in all three generated variants, each also passing `scripts/check-generated.sh` (check: `.github/workflows/template.yml`). To generate a variant locally from a clean checkout:

   ```sh
   cargo generate --path . --name acme-tools --allow-commands --silent \
     --define github_org=acme-corp --define 'authors=Template CI <ci@example.com>' \
     --define mcp_transport=stdio --destination "$(mktemp -d)"   # or http, http-oauth
   ```

3. A file that belongs only to the template goes in `ignore` in `cargo-generate.toml` and in the "not shipped" checks of `scripts/check-generated.sh`.
