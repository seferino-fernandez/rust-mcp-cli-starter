// Pre-generation hook: rename the concrete template identity (myapp / MYAPP)
// to the user's chosen project name, then rename the crate directories.
//
// Requires a POSIX sh (find/grep/sed) and a `cargo` binary in PATH at
// generation time: standard on Linux/macOS dev environments. In-place edits
// use a portable temp-file rewrite (no `sed -i`), because GNU sed (Linux) and
// BSD sed (macOS) parse `-i` incompatibly. So the script runs unmodified on
// both, with no `gsed` install required. Windows users: run under WSL.
//
// cargo-generate 0.23+ API used here:
//   variable::get(name): read an injected/placeholder variable
//   to_shouty_snake_case(s): free-standing heck fn registered by the engine
//   system::command(cmd): runs `sh -c <cmd>` in the generated project dir
//   file::rename(from, to): portable dir/file rename inside the sandbox
//
// NOTE: cargo-generate.toml's `ignore` list excludes `pre-script.rhai` and
// `cargo-generate.toml` from generated projects, so no file::delete needed.

let kebab = variable::get("project-name");   // e.g. acme-tools  (kebab)
let snake  = variable::get("crate_name");    // e.g. acme_tools  (snake)

// Compute SCREAMING_SNAKE env-var prefix.
// to_upper() is NOT a built-in rhai string method; use the heck helper
// registered by cargo-generate: to_shouty_snake_case(&str) -> String.
// For input "acme_tools" this yields "ACME_TOOLS".
let upper = to_shouty_snake_case(snake);     // e.g. ACME_TOOLS

// -------------------------------------------------------------------------
// Token replacement across all text files.
// Replacement ORDER matters: longest/most-specific first to avoid
// partial clobbers:
//   1. MYAPP  (env-var prefix, all-caps)
//   2. myapp_ (snake identifier fragment)
//   3. myapp- (kebab fragment used in paths/dep names)
//   4. myapp  (bare word, prose)
//
// We exclude only `target` and `.git`. 
//
// system::command(cmd) in cargo-generate 0.23 runs `sh -c cmd` (POSIX sh).
// We do NOT use `set -o pipefail` as that is a bash extension.
// -------------------------------------------------------------------------
let replace_script = `
set -eu
files=$(grep -rIl \
  --exclude-dir=target \
  --exclude-dir=.git \
  -e 'myapp' -e 'MYAPP' \
  . 2>/dev/null || true)
# GNU sed (Linux) and BSD sed (macOS) parse the -i flag incompatibly, so we
# avoid it entirely: rewrite each file through a temp copy. POSIX-portable.
if [ -n "$files" ]; then
  printf '%s\n' "$files" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    sed \
      -e 's/MYAPP/` + upper + `/g' \
      -e 's/myapp_/` + snake + `_/g' \
      -e 's/myapp-/` + kebab + `-/g' \
      -e 's/myapp/` + kebab + `/g' \
      "$f" > "$f.cgtmp" && mv "$f.cgtmp" "$f"
  done
fi
# Cargo.lock will regenerate on first build; drop it to avoid stale crate names.
rm -f Cargo.lock
`;

system::command(replace_script);

// -------------------------------------------------------------------------
// Rename crate directories to reflect the new project name.
// file::rename is sandboxed to the generated project directory.
// -------------------------------------------------------------------------
file::rename("crates/myapp-core", "crates/" + kebab + "-core");
file::rename("crates/myapp-cli",  "crates/" + kebab + "-cli");
file::rename("crates/myapp-mcp",  "crates/" + kebab + "-mcp");

// -------------------------------------------------------------------------
// Re-format all Rust source. This normalises any rustfmt divergence that
// arises from the rename (e.g. #[command(...)] attribute line-length,
// import sort order). Must run AFTER file::rename so Cargo resolves the
// workspace correctly.
// -------------------------------------------------------------------------
system::command("cargo fmt --all");
