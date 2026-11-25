#!/usr/bin/env bash
# Install exact upstream release tools into the requested directory.
# Supports the Linux x86_64 runners and managed Linux development hosts.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# == 1 ]] || { echo "usage: $0 <tool directory>" >&2; exit 2; }
destination="$1"
mkdir -p "$destination"
destination="$(realpath "$destination")"
locked_version() {
    awk -v package="$1" '$0 == "name = \"" package "\"" {getline; gsub(/"/,"",$3); print $3; exit}' Cargo.lock
}
wasm_version="$(locked_version wasm-bindgen)"
css_version="$(locked_version stylance)"
[[ "$wasm_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$css_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
    echo "Install wasm-bindgen-cli $wasm_version and stylance-cli $css_version using cargo on this platform." >&2
    exit 1
fi
stage="$(mktemp -d "$destination/tools.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT
download_tool() {
    local repository="$1" tag="$2" archive="$3" checksum_suffix="$4" executable="$5" prefix="$6"
    local base="https://github.com/$repository/releases/download/$tag" expected
    curl --retry 2 -fLsS --max-time 120 -o "$stage/$archive" "$base/$archive"
    curl --retry 2 -fLsS --max-time 30 -o "$stage/$archive.$checksum_suffix" "$base/$archive.$checksum_suffix"
    expected="$(cut -d ' ' -f1 "$stage/$archive.$checksum_suffix" | head -1)"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]]
    (cd "$stage"; printf '%s  %s\n' "$expected" "$archive" | sha256sum --check)
    tar -xf "$stage/$archive" -C "$stage"
    install -m 0755 "$stage/$prefix/$executable" "$destination/$executable"
}
wasm_prefix="wasm-bindgen-$wasm_version-x86_64-unknown-linux-musl"
css_prefix="stylance-cli-x86_64-unknown-linux-musl"
download_tool wasm-bindgen/wasm-bindgen "$wasm_version" "$wasm_prefix.tar.gz" sha256sum wasm-bindgen "$wasm_prefix"
download_tool basro/stylance-rs "v$css_version" "$css_prefix.tar.xz" sha256 stylance "$css_prefix"
"$destination/wasm-bindgen" --version
"$destination/stylance" --version
