#!/usr/bin/env bash
# The scheduler's native binary and WASM hydration build are separate targets.
set -euo pipefail
cd "$(dirname "$0")/.."
target_dir="$(cargo metadata --locked --no-deps --format-version 1 | jq -r .target_directory)"
output_dir="$target_dir/scheduler-dashboard/pkg"
version="$(awk '/^name = "wasm-bindgen"$/{getline; gsub(/"/,"",$3); print $3; exit}' Cargo.lock)"
test -n "$version"
if ! command -v wasm-bindgen >/dev/null || [[ "$(wasm-bindgen --version)" != "wasm-bindgen $version" ]]; then
    printf 'Install the matching hydration tool: cargo install wasm-bindgen-cli --version %s --locked\n' "$version" >&2
    exit 1
fi
cargo build --locked -p sccache-dashboard --no-default-features --features hydrate --release --target wasm32-unknown-unknown
mkdir -p "$output_dir"
wasm-bindgen --target web --no-typescript --out-dir "$output_dir" --out-name sccache-dashboard \
    "$target_dir/wasm32-unknown-unknown/release/sccache_dashboard.wasm"
printf 'Dashboard assets: %s\n' "$output_dir"
