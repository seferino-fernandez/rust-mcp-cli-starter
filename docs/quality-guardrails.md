# Quality guardrails

What checks this project, and what each check is for. `just verify` runs everything except the PR-only duplicate check; CI runs the same tools in `.github/workflows/pull-request-validation.yml`.

| Tool | What it's for | Run with | In CI |
| --- | --- | --- | --- |
| rustfmt (`rustfmt.toml`) | One code format | `cargo fmt --all --check` | `lint` job |
| Clippy (`[workspace.lints]`, `clippy.toml`) | Strict lints: the pedantic group, no panicking shortcuts (`unwrap`, indexing, `todo!`), no silent `#[allow]`, and size and complexity budgets per function | `just lint` | `lint` job |
| `unsafe_code = "forbid"` | No `unsafe` in any workspace crate | part of Clippy and `cargo check` | `lint`, `test` jobs |
| rustdoc (`[workspace.lints.rustdoc]`) | Docs build without broken links or warnings | `just doc` | `test` job |
| cargo-nextest and doctests | Unit, integration and doc tests, with all features and with defaults | `just test` | `test` job |
| `rust-toolchain.toml` | The same pinned Rust locally and in CI; Dependabot bumps it | automatic | every job |
| cargo-deny (`deny.toml`) | Known-vulnerable crates, allowed licenses, crates.io as the only source | `cargo deny check` | `dependencies` job |
| cargo-shear | Unused dependencies | `cargo shear` | `dependencies` job |
| typos (`_typos.toml`) | Spelling in code and docs | `typos` | `hygiene` job |
| Tombi (`tombi.toml`) | TOML formatting and schema lint | `tombi format --check`, `tombi lint` | `hygiene` job |
| ast-grep (`sgconfig.yml`, `.ast-grep/`) | Project rules Clippy can't express: no module-level lint suppression, no `cfg(not(clippy))`, `#[ignore]` needs a reason, no `todo!` in tests, actions pinned by SHA | `ast-grep scan`, `ast-grep test` | `hygiene` job |
| jscpd | Code duplicated by a pull request; existing clones never fail | `just dupes` | `dupes` job (PRs only) |
| cargo-mutants (`.cargo/mutants.toml`) | Tests that pass even when the changed code is broken | `just mutants-diff` | local only |
| prek (`.pre-commit-config.yaml`) | Runs the fast checks on each commit | `prek install` once | — |
| cargo-audit | Known vulnerabilities in the built release binaries | `just audit` | local only |

Each `[workspace.lints]` and `clippy.toml` entry is a deliberate choice: when a lint flags correct code, put `#[expect(lint, reason = "…")]` on that item instead of loosening the configuration.
