# AGENTS.md

`myapp-core` owns the MYAPP API client: requests, configuration, models and errors. `myapp-cli` and `myapp-mcp` adapt it to a terminal and to MCP, so API behaviour changes land in core.

## Quality gates

Each rule names the check that enforces it. [docs/quality-guardrails.md](docs/quality-guardrails.md) lists every tool and what it catches.

1. Run `just verify` before finishing, and finish only when it passes (check: `just verify`, mirrored by `.github/workflows/pull-request-validation.yml`).
2. Fix the code a lint flags. When the code is right as written, put `#[expect(lint, reason = "…")]` on the item and name the invariant that makes it right; `#[allow]`, module-level `#![expect]` and `cfg(not(clippy))` fail the gate (check: Clippy `allow_attributes` and `allow_attributes_without_reason`; ast-grep `no-inner-lint-suppression` and `no-not-clippy`).
3. Leave `[workspace.lints]` in `Cargo.toml`, `clippy.toml`, `rustfmt.toml`, `deny.toml`, `rust-toolchain.toml`, `tombi.toml`, `_typos.toml`, `sgconfig.yml`, `.ast-grep/`, `.cargo/` and `.github/` as they are unless the task is about them. When a change touches one, or adds `#[expect]` or `#[mutants::skip]`, list each in the PR body with why (check: review).
4. Keep every test meaningful: when a test looks wrong, stop and say so instead of deleting, ignoring or weakening it. Every `#[ignore]` carries a reason string (check: ast-grep `ignore-requires-reason`; `just mutants-diff` reports changed code whose tests let a mutant survive).
5. Add a dependency only with a PR-body sentence on why std or an existing dependency can't do the job (check: `cargo deny check` and `cargo shear`; the sentence in review).
6. Pin each workflow action to a full commit SHA followed by a `# vX` comment (check: ast-grep `actions-pinned-by-sha`).
