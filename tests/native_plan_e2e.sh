#!/usr/bin/env bash
set -euo pipefail
if (( $# != 1 )); then
    echo "usage: $0 /absolute/path/to/managed-native-sccache" >&2
    exit 2
fi
executor=$(realpath "$1")
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
cp -a "$(dirname "$0")/fixtures/native-plan/." "$root"
cd "$root"
"$executor" build --locked --offline
test "$(./target/debug/native-plan-fixture)" = native-plan-ok
"$executor" build --locked --offline
test "$(./target/debug/native-plan-fixture)" = native-plan-ok
"$executor" check --locked --offline --all-targets
"$executor" test --locked --offline --test executable
# Same-length rewrite while explicitly restoring the original mtime.
# The build must derive a different result solely from content changes.
cp -p src/main.rs "$root/reference"
sed -i 's/native-plan-ok/native-plan-OK/' src/main.rs
touch -r "$root/reference" src/main.rs
"$executor" build --locked --offline
test "$(./target/debug/native-plan-fixture)" = native-plan-OK
mv "$root/reference" src/main.rs
"$executor" build --locked --offline
test "$(./target/debug/native-plan-fixture)" = native-plan-ok
# Generate a new lock with no external Cargo executable.
rm Cargo.lock
"$executor" build --offline
test -s Cargo.lock
"$executor" build --locked --offline
test "$(./target/debug/native-plan-fixture)" = native-plan-ok
printf '%s\n' 'native build, warm rebuild, all-target check, content invalidation and native lock generation passed'
