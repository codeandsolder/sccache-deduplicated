#!/usr/bin/env bash
# Build the SSR-compatible WASM and Stylance assets without invoking another
# Cargo build from build.rs or writing generated artifacts into the source tree.
set -euo pipefail
cd "$(dirname "$0")/.."
source contrib/codeandsolder/release-protocol.env
if (( $# > 2 )); then
    echo "usage: $0 [wasm-bindgen executable] [stylance executable]" >&2
    exit 2
fi
bindgen="${1:-wasm-bindgen}"
stylance="${2:-stylance}"
# The release toolchain can differ from the caller's CI toolchain. Clear
# explicit compiler overrides, not the managed rustc wrapper or cache.
release_cargo=(env -u RUSTC -u RUSTDOC cargo +"$rust_toolchain")
target_dir="$("${release_cargo[@]}" metadata --locked --no-deps --format-version 1 | jq -r .target_directory)"
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
"${release_cargo[@]}" build --locked -p sccache-dashboard --no-default-features --features hydrate --release --target wasm32-unknown-unknown
mkdir -p "$(dirname "$output_dir")"
stage="$(mktemp -d "$(dirname "$output_dir")/pkg.XXXXXXXX")"
trap 'rm -rf "$stage"; rm -f "$stage.sha256sums"' EXIT
"$bindgen" --target web --no-typescript --out-dir "$stage" --out-name sccache-dashboard \
    "$target_dir/wasm32-unknown-unknown/release/sccache_dashboard.wasm"
"$stylance" crates/scheduler-dashboard --output-file "$stage/sccache-dashboard.css"
for asset in sccache-dashboard.js sccache-dashboard_bg.wasm sccache-dashboard.css; do
    test -s "$stage/$asset"
done
# Hash every generated file before publishing; the scheduler verifies the
# full manifest and the fingerprint embedded in the WASM itself.
(cd "$stage" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "$stage.sha256sums")
mv "$stage.sha256sums" "$stage/SHA256SUMS"
# The installed scheduler runs under a separate service account. The build
# directory remains private, but the published asset tree must be readable.
find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
# Only replace an existing generation after all build steps have succeeded.
scripts/publish-dashboard-assets.sh "$stage" "$output_dir"
printf 'Dashboard assets: %s\n' "$output_dir"
