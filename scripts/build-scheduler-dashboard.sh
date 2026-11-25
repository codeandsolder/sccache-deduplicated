#!/usr/bin/env bash
# Build the SSR-compatible WASM and Stylance assets without invoking another
# Cargo build from build.rs or writing generated artifacts into the source tree.
set -euo pipefail
cd "$(dirname "$0")/.."
if (( $# > 2 )); then
    echo "usage: $0 [wasm-bindgen executable] [stylance executable]" >&2
    exit 2
fi
bindgen="${1:-wasm-bindgen}"
stylance="${2:-stylance}"
target_dir="$(cargo metadata --locked --no-deps --format-version 1 | jq -r .target_directory)"
output_dir="$target_dir/scheduler-dashboard/pkg"
locked_version() {
    awk -v package="$1" '$0 == "name = \"" package "\"" {getline; gsub(/"/,"",$3); print $3; exit}' Cargo.lock
}
wasm_version="$(locked_version wasm-bindgen)"
css_version="$(locked_version stylance)"
if [[ -z "$wasm_version" ]] || ! command -v "$bindgen" >/dev/null || [[ "$("$bindgen" --version)" != "wasm-bindgen $wasm_version" ]]; then
    printf 'Install the matching hydration tool: cargo install wasm-bindgen-cli --version %s --locked\n' "$wasm_version" >&2
    exit 1
fi
if [[ -z "$css_version" ]] || ! command -v "$stylance" >/dev/null || [[ "$("$stylance" --version)" != *" $css_version" ]]; then
    printf 'Install the matching stylesheet tool: cargo install stylance-cli --version %s --locked\n' "$css_version" >&2
    exit 1
fi
cargo build --locked -p sccache-dashboard --no-default-features --features hydrate --release --target wasm32-unknown-unknown
mkdir -p "$(dirname "$output_dir")"
stage="$(mktemp -d "$(dirname "$output_dir")/pkg.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT
"$bindgen" --target web --no-typescript --out-dir "$stage" --out-name sccache-dashboard \
    "$target_dir/wasm32-unknown-unknown/release/sccache_dashboard.wasm"
"$stylance" crates/scheduler-dashboard --output-file "$stage/sccache-dashboard.css"
for asset in sccache-dashboard.js sccache-dashboard_bg.wasm sccache-dashboard.css; do
    test -s "$stage/$asset"
done
# Only replace an existing generation after all build steps have succeeded.
rm -rf "$output_dir"
mv "$stage" "$output_dir"
printf 'Dashboard assets: %s\n' "$output_dir"
