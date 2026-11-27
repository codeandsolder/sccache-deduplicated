#!/usr/bin/env bash
# Package the real Cargo-built test executables and their matching subjects.
set -euo pipefail
archive="${1:?missing output archive path}"
stage="$(mktemp -d "$RUNNER_TEMP/dist-ci-build.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/bundle"
cargo test --locked --target x86_64-unknown-linux-gnu --no-default-features --features=dist-tests \
    --lib --test dist --no-run --message-format=json --target-dir "$RUNNER_TEMP/cargo-target" \
    --config "build.build-dir='$RUNNER_TEMP/cargo-target'" > "$stage/artifacts.jsonl"
install_artifact() {
    local target="$1" kind="$2" is_test="$3" output="$4" executable
    executable="$(jq -ser --arg target "$target" --arg kind "$kind" --argjson is_test "$is_test" '
        [ .[] | select(.reason == "compiler-artifact" and .executable != null
            and .target.name == $target and (.target.kind | index($kind)) != null
            and .profile.test == $is_test) | .executable ]
        | unique | if length == 1 then .[0] else error("missing or ambiguous executable: " + $target) end
    ' "$stage/artifacts.jsonl")"
    install -m 0755 "$executable" "$stage/bundle/$output"
}
install_artifact sccache lib true lib-tests
install_artifact dist test true dist-tests
install_artifact sccache bin false sccache
install_artifact sccache-dist bin false sccache-dist
git rev-parse HEAD > "$stage/bundle/sccache-test-bundle.sha"
rustc -vV > "$stage/bundle/rustc-version"
(
    cd "$stage/bundle"
    sha256sum lib-tests dist-tests sccache sccache-dist sccache-test-bundle.sha rustc-version > SHA256SUMS
    tar -cf "$archive" .
)
