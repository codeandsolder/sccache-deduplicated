#!/usr/bin/env bash
# Package the scheduler executable and matching frontend generation.
set -euo pipefail
if (( $# != 3 )); then
    echo "usage: $0 <scheduler binary> <dashboard pkg directory> <output.tar.gz>" >&2
    exit 2
fi
binary="$(realpath "$1")"
assets="$(realpath "$2")"
output="$(realpath -m "$3")"
[[ -x "$binary" && -d "$assets" && ! -e "$output" && ! -e "$output.sha256" ]]
cd "$(dirname "$0")/.."
source_sha="$(git rev-parse HEAD)"
source_epoch="$(git show -s --format=%ct "$source_sha")"
version="$("$binary" --version)"
[[ "$version" == *"($source_sha)" ]] || { echo "dashboard scheduler revision mismatch" >&2; exit 1; }
stage="$(mktemp -d "$(dirname "$output")/.dashboard-package.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/bundle/pkg"
install -m 0755 "$binary" "$stage/bundle/sccache-dist"
for asset in sccache-dashboard.js sccache-dashboard_bg.wasm sccache-dashboard.css; do
    test -s "$assets/$asset"
done
# Verify the staged files, using the staged executable (not a sidecar claim).
# The current source fingerprint must also match both actual compilations.
# wasm-bindgen may generate additional snippet modules; retain the entire pkg.
cp -a "$assets/." "$stage/bundle/pkg/"
if [[ -n "$(find "$stage/bundle/pkg" ! -type f ! -type d -print -quit)" ]]; then
    echo "dashboard assets contain non-regular entries" >&2
    exit 1
fi
# Validate against the immutable commit tree whose SHA will be recorded,
# rather than trusting the mutable working directory.
mkdir "$stage/source"
git archive "$source_sha" | tar -xf - -C "$stage/source"
# Metadata describes that same immutable source revision, never local edits.
# shellcheck source=contrib/codeandsolder/release-protocol.env
source "$stage/source/contrib/codeandsolder/release-protocol.env"
generation="$("$stage/bundle/sccache-dist" verify-dashboard --assets "$stage/bundle/pkg" --source "$stage/source")"
[[ "$generation" =~ ^sccache-dashboard-generation-v1:[0-9a-f]{64}$ ]]
{
    printf 'dashboard_generation=%s\n' "$generation"
    printf 'source_sha=%s\nrust_toolchain=%s\ndist_protocol=%s\nrollout_epoch=%s\n' "$source_sha" "$rust_toolchain" "$dist_protocol" "$rollout_epoch"
    printf 'build_kind=portable-dashboard-scheduler\n'
} > "$stage/bundle/build.txt"
(
    cd "$stage/bundle"
    find sccache-dist build.txt pkg -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
    sha256sum --strict -c SHA256SUMS
)
tar --sort=name --mtime="@$source_epoch" --owner=0 --group=0 --numeric-owner \
    -czf "$stage/archive.tar.gz" -C "$stage/bundle" .
mv "$stage/archive.tar.gz" "$output"
(cd "$(dirname "$output")" && sha256sum "$(basename "$output")" > "$(basename "$output").sha256")
