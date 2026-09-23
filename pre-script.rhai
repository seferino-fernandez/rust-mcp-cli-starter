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
//   system::date(): current date (`.year`, `.month`, `.day`)
//   file::rename(from, to): portable dir/file rename inside the sandbox
//   file::delete(path), file::write(path, s): sandboxed file edits
//
// NOTE: cargo-generate.toml's `ignore` list excludes `pre-script.rhai`,
// `cargo-generate.toml`, and the template's own CI workflow from generated
// projects, so no file::delete is needed for those.
//
// SECURITY: only the kebab project name and the regex-validated `github_org`
// placeholder are interpolated into shell commands. Free-form values (such as
// `authors`) must never reach system::command; use file::write instead.

let kebab = variable::get("project-name");   // e.g. acme-tools  (kebab)
let snake  = variable::get("crate_name");    // e.g. acme_tools  (snake)
let org    = variable::get("github_org");    // e.g. acme-corp   (regex-validated)

// Compute SCREAMING_SNAKE env-var prefix.
// to_upper() is NOT a built-in rhai string method; use the heck helper
// registered by cargo-generate: to_shouty_snake_case(&str) -> String.
// For input "acme_tools" this yields "ACME_TOOLS".
let upper = to_shouty_snake_case(snake);     // e.g. ACME_TOOLS

// -------------------------------------------------------------------------
// Swap in the generated project's README. The template's README.md documents
// the template itself; README.generated.md is the project README, written
// with myapp tokens so the rename pass below applies to it.
// -------------------------------------------------------------------------
file::delete("README.md");
file::rename("README.generated.md", "README.md");

// -------------------------------------------------------------------------
// Token replacement across all text files.
// Replacement ORDER matters: longest/most-specific first to avoid
// partial clobbers:
//   1. MYAPP  (env-var prefix, all-caps)
//   2. myapp_ (snake identifier fragment)
//   3. myapp- (kebab fragment used in paths/dep names)
//   4. myapp  (bare word, prose)
//
// We exclude only `target` and `.git`. Cargo.lock is rewritten too, which
// keeps it in sync with the renamed crates, so `cargo check --locked` passes
// in the generated project.
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
`;

system::command(replace_script);

// -------------------------------------------------------------------------
// Point the repository/homepage URLs and the container image comment at the
// user's GitHub org. `org` matches the placeholder regex
// ^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$ and `kebab` is a kebab-case crate name,
// so both are safe to interpolate into sed. GHCR image names must be
// lowercase, so the org is lowercased for the image path.
// -------------------------------------------------------------------------
let url_script = `
set -eu
image_org=$(printf '%s' '` + org + `' | tr 'A-Z' 'a-z')
sed -e 's#github.com/your-org/your-project#github.com/` + org + `/` + kebab + `#g' \
  Cargo.toml > Cargo.toml.cgtmp && mv Cargo.toml.cgtmp Cargo.toml
sed -e "s#ghcr.io/your-org/#ghcr.io/$image_org/#g" \
  deploy/compose.yaml > deploy/compose.yaml.cgtmp \
  && mv deploy/compose.yaml.cgtmp deploy/compose.yaml
`;

system::command(url_script);

// -------------------------------------------------------------------------
// Write the MIT license naming the generating user. `authors` is either
// "name <email>" or "name"; keep only the name. It is free-form text, so it
// is written with file::write and never passed through a shell. Runs after
// the rename pass so an author name containing "myapp" stays untouched.
// -------------------------------------------------------------------------
let author = variable::get("authors");
let email_at = author.index_of(" <");
if email_at >= 0 {
    author = author.sub_string(0, email_at);
}
author.trim();
if author == "" {
    author = "The " + kebab + " authors";
}
let year = system::date().year;

file::write("LICENSE.md", `MIT License

Copyright (c) ` + year + ` ` + author + `

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
`);

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
