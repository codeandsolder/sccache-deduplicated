#!/usr/bin/env bash
# Real compiled executable and optimized WASM; no fake binary or sidecar.
set -euo pipefail
(( $# == 2 )) || { echo "usage: $0 <scheduler> <pkg>" >&2; exit 2; }
binary="$(realpath "$1")"
assets="$(realpath "$2")"
cd "$(dirname "$0")/.."
root="$(mktemp -d "$(dirname "$assets")/package-test.XXXXXXXX")"
trap 'rm -rf "$root"' EXIT
reject() {
    if "$@"; then echo "unexpected acceptance: $*" >&2; exit 1; fi
}
generation="$("$binary" verify-dashboard --assets "$assets" --source "$PWD")"
[[ "$generation" =~ ^sccache-dashboard-generation-v1:[0-9a-f]{64}$ ]]
scripts/package-scheduler-dashboard.sh "$binary" "$assets" "$root/dashboard.tar.gz"
mkdir "$root/unpacked"
tar -xzf "$root/dashboard.tar.gz" -C "$root/unpacked"
(cd "$root/unpacked" && sha256sum --strict -c SHA256SUMS)
test "$("$root/unpacked/sccache-dist" verify-dashboard --assets "$root/unpacked/pkg")" = "$generation"

cp -a "$assets" "$root/corrupt"
printf '\ncorruption' >> "$root/corrupt/sccache-dashboard.css"
reject "$binary" verify-dashboard --assets "$root/corrupt"
reject scripts/package-scheduler-dashboard.sh "$binary" "$root/corrupt" "$root/bad.tar.gz"
test ! -e "$root/bad.tar.gz"

# Replace exactly one byte of the embedded identity and recompute the full
# checksum manifest: an internally consistent but mismatched WASM generation.
cp -a "$assets" "$root/stale"
wasm="$root/stale/sccache-dashboard_bg.wasm"
mapfile -t offsets < <(LC_ALL=C rg --text --byte-offset --only-matching -F "$generation" "$wasm" | cut -d: -f1)
(( ${#offsets[@]} > 0 ))
# The first byte is always 's'; alter it without changing module structure.
for offset in "${offsets[@]}"; do
    printf x | dd of="$wasm" bs=1 seek="$offset" conv=notrunc status=none
done
(cd "$root/stale" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "$root/stale.sha256sums")
mv "$root/stale.sha256sums" "$root/stale/SHA256SUMS"
reject "$binary" verify-dashboard --assets "$root/stale"
reject scripts/package-scheduler-dashboard.sh "$binary" "$root/stale" "$root/mixed.tar.gz"
test ! -e "$root/mixed.tar.gz"

# Even a mutually matching pair from another source revision is rejected.
mkdir "$root/source"
git archive HEAD -- Cargo.toml Cargo.lock rust-toolchain.toml src crates scripts/build-scheduler-dashboard.sh scripts/publish-dashboard-assets.sh contrib/codeandsolder/release-protocol.env | tar -xf - -C "$root/source"
test "$("$binary" verify-dashboard --assets "$assets" --source "$root/source")" = "$generation"
printf '\n/* changed source */\n' >> "$root/source/crates/scheduler-dashboard/src/styles.module.css"
reject "$binary" verify-dashboard --assets "$assets" --source "$root/source"

# Interrupted/failed preparation preserves the existing directory; a valid
# exchange installs the entire new generation and leaves the old one staged.
mkdir "$root/active" "$root/stage"
printf old > "$root/active/payload"
printf new > "$root/stage/payload"
(cd "$root/active" && sha256sum ./payload > SHA256SUMS)
(cd "$root/stage" && sha256sum ./payload > SHA256SUMS)
printf broken >> "$root/stage/payload"
reject scripts/publish-dashboard-assets.sh "$root/stage" "$root/active"
test "$(cat "$root/active/payload")" = old
printf new > "$root/stage/payload"
scripts/publish-dashboard-assets.sh "$root/stage" "$root/active"
test "$(cat "$root/active/payload")" = new
test "$(cat "$root/stage/payload")" = old
echo "Dashboard package generation, corruption and atomic exchange tests passed."
