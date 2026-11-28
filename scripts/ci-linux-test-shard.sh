#!/usr/bin/env bash
# Separate VMs isolate test-owned daemons without changing test semantics.
set -euo pipefail
# Compile with the canonical CI sccache daemon on its isolated Unix socket.
# Run test executables without that socket variable: the sccache system
# tests must manage their own independent test daemon.
test_runner="$RUNNER_TEMP/sccache-test-runner"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'unset SCCACHE_SERVER_UDS SCCACHE_SERVER_PORT' 'exec "$@"' > "$test_runner"
chmod +x "$test_runner"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="$test_runner"
case "${1:?missing Linux CI shard}" in
    legacy)
        # Native fixture integration tests preserve serial_test execution semantics.
        cargo test --locked --target x86_64-unknown-linux-gnu --features dist-tests --test system --test sccache_cargo --test cache_hit_rate --test logging --test server --test sccache_rustc --test oauth --test rust_link_replay
        ;;
    native)
        cargo test --locked --target x86_64-unknown-linux-gnu --no-default-features --features=dist-client,dist-server --test native_dist -- --ignored --exact shared_daemon_credential_isolation
        ;;
    dashboard)
        cargo test --locked --target x86_64-unknown-linux-gnu -p sccache-dashboard --features ssr
        cargo test --locked --target x86_64-unknown-linux-gnu --no-default-features --features=scheduler-dashboard --bin sccache-dist scheduler_status
        cargo test --locked --target x86_64-unknown-linux-gnu --no-default-features --features=scheduler-dashboard --bin sccache-dist status_counts_assignment_rpc_reservations
        rustup target add wasm32-unknown-unknown
        env -u RUSTFLAGS cargo check --locked -p sccache-dashboard --no-default-features --features hydrate --target wasm32-unknown-unknown
        source contrib/codeandsolder/release-protocol.env
        rustup toolchain install "$rust_toolchain" --profile minimal --target wasm32-unknown-unknown
        target_dir="$(cargo metadata --locked --no-deps --format-version 1 | jq -r .target_directory)"
        scripts/install-scheduler-dashboard-tools.sh "$target_dir/dashboard-tools"
        env -u RUSTFLAGS scripts/build-scheduler-dashboard.sh "$target_dir/dashboard-tools/wasm-bindgen" "$target_dir/dashboard-tools/stylance"
        cargo build --locked --target x86_64-unknown-linux-gnu --no-default-features --features=scheduler-dashboard --bin sccache-dist
        cargo build --locked --target x86_64-unknown-linux-gnu -p sccache-dashboard --features ssr --example browser-fixture
        scripts/test-scheduler-dashboard-package.sh "$target_dir/x86_64-unknown-linux-gnu/debug/sccache-dist" "$target_dir/scheduler-dashboard/pkg"
        scripts/test-scheduler-dashboard-browser.sh "$target_dir/x86_64-unknown-linux-gnu/debug/sccache-dist" "$target_dir/scheduler-dashboard/pkg" "$target_dir/x86_64-unknown-linux-gnu/debug/examples/browser-fixture"
        ;;
    core) ;;
    *) echo "Unknown Linux CI shard: $1" >&2; exit 2 ;;
esac
