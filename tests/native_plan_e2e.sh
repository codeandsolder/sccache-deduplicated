#!/usr/bin/env bash
# Requires an already-configured managed sccache endpoint and the matching
# cargo-ephemeral native-planner build. Never starts a new cache server.
set -euo pipefail
if (( $# != 2 )); then
    echo "usage: $0 /absolute/path/to/sccache /absolute/path/to/cargo-planner" >&2
    exit 2
fi
executor=$(realpath "$1")
planner=$(realpath "$2")
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
cp -a "$(dirname "$0")/fixtures/native-plan/." "$root"
cd "$root"
"$executor" --execute-planner "$planner" --leased-intermediates -- build --native-build-plan --locked --offline
test "$(./target/debug/native-plan-fixture)" = native-plan-ok
"$executor" --execute-planner "$planner" --leased-intermediates -- build --native-build-plan --locked --offline
test "$(./target/debug/native-plan-fixture)" = native-plan-ok
"$executor" --execute-planner "$planner" --leased-intermediates -- check --native-build-plan --locked --offline --all-targets
printf '%s\n' 'native-plan build, warm rebuild, and all-target check passed'
