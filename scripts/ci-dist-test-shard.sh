#!/usr/bin/env bash
# Each shard runs the same compiled test subject on an independent VM.
set -euo pipefail
shard="${1:?missing distributed CI shard}"
archive="${2:?missing test archive}"
stage="$(mktemp -d "$RUNNER_TEMP/dist-ci-test.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT
tar -xf "$archive" -C "$stage"
(cd "$stage" && sha256sum -c SHA256SUMS)
[[ "$(cat "$stage/sccache-test-bundle.sha")" == "$(git rev-parse HEAD)" ]]
[[ "$(cat "$stage/rustc-version")" == "$(rustc -vV)" ]]
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends bubblewrap binutils-mingw-w64-x86-64 gcc g++ clang
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
bwrap --ro-bind / / -- /usr/bin/true
unset SCCACHE_SERVER_UDS SCCACHE_SERVER_PORT
# Match the previous Cargo test runtime environment for direct compiler probes.
RUSTUP_TOOLCHAIN="$(rustup show active-toolchain | cut -d " " -f1)"
export RUSTUP_TOOLCHAIN
RUSTC="$(rustup which rustc)"
RUSTDOC="$(rustup which rustdoc)"
export RUSTC RUSTDOC
classify() {
    case "$1" in
        *test_dist_c_*) echo c ;;
        *test_dist_namespace_broker*|*test_dist_rust_observed_environment*|*test_dist_transport_*) echo infrastructure ;;
        *test_dist_rust_warm_cargo) echo cargo ;;
        *test_dist_rust_warm_clippy) echo clippy ;;
        *test_dist_rust_warm_dependencies) echo dependencies ;;
        *test_dist_rust_warm_metadata) echo metadata ;;
        *test_dist_rust_*) echo "Unassigned distributed Rust regression: $1" >&2; return 2 ;;
        *) echo unselected ;;
    esac
}
# Derive exact filters from the compiled inventory. Never succeed with an
# empty shard or silently omit a new test in the old continuous test scopes.
inventory="$("$stage/dist-tests" --list)"
selected=()
while IFS= read -r line; do
    [[ "$line" == *": test" ]] || continue
    name="${line%: test}"
    group="$(classify "$name")"
    if [[ "$group" == "$shard" ]]; then selected+=("$name"); fi
done <<< "$inventory"
(( ${#selected[@]} > 0 ))
printf 'Executing %s: %s\n' "$shard" "${selected[*]}"
if [[ "$shard" == infrastructure ]]; then
    "$stage/lib-tests" test_job_token_verification streaming_tests
fi
"$stage/dist-tests" --test-threads 1 --exact "${selected[@]}"
