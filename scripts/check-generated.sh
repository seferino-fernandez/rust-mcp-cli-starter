#!/usr/bin/env bash
# Check the generated product, including absence of unselected capabilities.
set -euo pipefail

project_dir=${1:?generated project directory}
profile=${2:?stdio, http, or http-oauth}
phase=${3:-source}
case "$profile" in stdio|http|http-oauth) ;; *) exit 2 ;; esac
cd "$project_dir"
mcp_dir=crates/acme-tools-mcp
test -d "$mcp_dir"

absent() {
    for file in "$@"; do
        if [[ -e "$file" ]]; then
            echo "Unexpected file in $profile project: $file" >&2
            exit 1
        fi
    done
}

reject_matches() {
    local pattern=$1
    shift
    if grep -nEr "$pattern" "$@"; then
        echo "Unexpected content in $profile project: $pattern" >&2
        exit 1
    else
        local status=$?
        if [[ "$status" != 1 ]]; then exit "$status"; fi
    fi
}

if [[ "$phase" == source ]]; then
    absent pre-script.rhai cargo-generate.toml README.generated.md \
        .github/workflows/template.yml scripts/check-generated.sh
    test -f Cargo.lock
    reject_matches 'template:(begin|end)' crates Cargo.toml README.md config.toml.example justfile
    if [[ "$profile" == stdio ]]; then
        absent "$mcp_dir/src/http.rs" "$mcp_dir/src/middleware" \
            "$mcp_dir/src/secret_digest.rs" Dockerfile .dockerignore deploy
        reject_matches 'axum|transport-streamable-http|^tower[. -]|^sha2[. ]|^subtle[. ]|^tokio-util[. ]' \
            Cargo.toml "$mcp_dir/Cargo.toml"
        reject_matches 'Transport::Http|--transport http|ACME_TOOLS_MCP_(HOST|PORT|TOKEN|AUTH_MODE|ALLOWED_HOSTS)|x-mcp-header' \
            "$mcp_dir" README.md config.toml.example justfile
    else
        test -f "$mcp_dir/src/http.rs"
        test -f "$mcp_dir/src/middleware/static_bearer_auth.rs"
        test -f Dockerfile
        test -f deploy/compose.yaml
        grep -q 'ghcr.io/acme-corp/acme-tools-mcp' deploy/compose.yaml
    fi
    if [[ "$profile" != http-oauth ]]; then
        absent "$mcp_dir/src/oauth" "$mcp_dir/src/tools/scope.rs" \
            "$mcp_dir/src/middleware/oauth.rs" "$mcp_dir/src/middleware/cors.rs"
        reject_matches '[Oo][Aa][Uu][Tt][Hh]|require_scopes|insufficient_scope' \
            "$mcp_dir" README.md config.toml.example justfile
        reject_matches 'serde_urlencoded|urlencoding|tower-http' Cargo.toml "$mcp_dir/Cargo.toml"
    else
        test -f "$mcp_dir/src/oauth/mod.rs"
        test -f "$mcp_dir/src/tools/scope.rs"
    fi
elif [[ "$phase" == cli ]]; then
    help=$(cargo run --locked --quiet -p acme-tools-mcp -- --help)
    if [[ "$profile" == stdio ]]; then
        if grep -Eq -- '--host|--port|--token|--auth-mode|--oauth-pin|--mcp-base-url' <<< "$help"; then
            echo "Stdio help advertises HTTP settings" >&2
            exit 1
        fi
        if output=$(cargo run --locked --quiet -p acme-tools-mcp -- --transport http 2>&1); then
            echo "Stdio project accepted HTTP" >&2
            exit 1
        fi
        grep -q "invalid value 'http'" <<< "$output"
    else
        grep -q -- '--auth-mode' <<< "$help"
        grep -q -- '--token' <<< "$help"
    fi
    if [[ "$profile" == http-oauth ]]; then
        grep -q -- '--oauth-pin' <<< "$help"
    else
        if grep -Eq -- 'oauth|--mcp-base-url' <<< "$help"; then
            echo "Help advertises unselected OAuth settings" >&2
            exit 1
        fi
        if output=$(cargo run --locked --quiet -p acme-tools-mcp -- --auth-mode oauth 2>&1); then
            echo "Project without OAuth accepted OAuth" >&2
            exit 1
        fi
        grep -Eq "unexpected argument '--auth-mode'|invalid value 'oauth'" <<< "$output"
    fi
else
    echo "Unknown check phase: $phase" >&2
    exit 2
fi
