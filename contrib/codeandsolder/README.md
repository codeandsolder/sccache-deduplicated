# codeandsolder host wrappers

These are the source-of-truth copies of the machine-wide Cargo/sccache wrappers, release updater, and service provisioning templates used on the codeandsolder build nodes.

## Contract

- `cargo-wrapper` exports `SCCACHE_MIN_JOBS` (default 12). The managed cargo-ephemeral binary clamps the resolved build job count to this floor, preserving higher values and inherited jobservers. Set it to 0 to disable the floor.
- `cargo-wrapper` preserves Cargo's own target-directory semantics. It never invents or exports `CARGO_TARGET_DIR` merely for cache normalization.
- `cargo-wrapper` exports `EPHEMERAL_CARGO_WRAPPER`/`CARGO` so nested Cargo invocations return through the site launcher instead of exposing the underlying Cargo binary.
- `rustup-wrapper` is a narrow policy guard: `rustup run <toolchain> cargo ...` is translated to the equivalent site `cargo +<toolchain> ...` path, while non-Cargo rustup commands pass through untouched. `CODEANDSOLDER_RUSTUP_STOCK_CARGO=1` explicitly restores stock Cargo for compatibility testing.
- For compilation subcommands it resolves the effective target root with Cargo precedence (`--target-dir`, existing `CARGO_TARGET_DIR`, then `cargo metadata`) and exports only `SCCACHE_CANONICAL_TARGET_ROOT` for child compiler processes. Wrapper-derived roots are marked and recomputed by nested Cargo invocations so a child build cannot inherit a stale parent target root.
- `sccache-client` is also the public `/usr/local/bin/sccache` router (install as a symlink). The root-owned plain key/value `/etc/sccache/wrapper.conf` selects one managed TCP or Unix endpoint for all users and configures the daemon UID. Clients running as a different UID compile in namespace mode, so their compiler and output materialization stay under their own identity while storage and distributed scheduling remain shared. Explicit caller endpoints always take precedence. Automatically selected endpoints wait for service readiness for compilations, never administrative commands. Both entrypoints disable implicit daemon starts in the actual client. Compiler-wrapper mode only opts into experimental canonical Rust when target-layout context is available (`SCCACHE_CANONICAL_TARGET_ROOT`, `CARGO_TARGET_DIR`, or `OUT_DIR`). Direct rustc without Cargo target context remains ordinary sccache.
- Native Cargo dependencies use the actual build-script `OUT_DIR` and shared Cargo root discovery, not a guessed temporary-directory naming pattern. With canonical Cargo context and a supported Linux GCC/Clang compiler, sccache applies real compiler `-ffile-prefix-map` options to both preprocessing and local/distributed compilation. The per-package output root has stable identity independent of the temporary build directory or Cargo fingerprint. Generated map options do not leak their physical paths into the object-cache key: genuine preprocessor filename directives and compiler-visible paths are hashed with the corresponding canonical identity; source literals remain data.
- The native path policy always fully preprocesses the source before cache lookup, generating dependency files with the actual local paths on both hits and misses. It does not use the filename-sensitive direct preprocessor cache or directives-only worker reprocessing. Explicit compiler path mappings/compilation-directory overrides remain authoritative, and profiling/coverage and PCH generation retain their ordinary compiler semantics. Ordinary non-Cargo cache keys are unchanged.
- Canonical Rust inside sccache is fail-open: if the discovered cwd, output, source, extern, staticlib, or target-JSON path cannot be represented safely by the canonical map, that compilation uses ordinary sccache instead of failing the build.
- The core compiler owns assembler dependency discovery, including literal `.incbin`/`.include`; there is no separate public-router regexp-based compiler policy. Unresolvable assembly inputs use the core safe fallback.
- `sccache-cmake-launcher` avoids double wrapping strict launchers; explicit compiler aliases must be attested in the daemon configuration using the installed wrapper digest.
- The maintenance-drain marker remains `/dev/shm/sccache-maintenance-drain`; a marker older than 15 minutes is ignored.
- `sccache-release-update` validates release metadata against `sccache --capabilities` and requires `direct-metrics` by default, so a canonical rollout cannot silently remove production telemetry again.
- The updater connects to the primary managed daemon over the default `SCCACHE_AUTOUPDATE_CLIENT_UDS` or, for TCP-managed nodes, `SCCACHE_AUTOUPDATE_CLIENT_PORT`; the selected endpoint is used consistently for restart readiness, stats, and smoke tests.
- Verified same-protocol releases are applied immediately, including when local compiler clients or remote jobs are active. Existing requests may be interrupted and restarted. The local admission marker covers the client replacement only; once endpoints are ready it is removed before telemetry and distributed smoke checks. Worker-only updates do not gate clients. A stopped worker stays stopped.
- Scheduler socket activation is stopped before the scheduler and restored afterward, including on rollback. The updater does not query distributed queue occupancy before restarting. A different or unknown installed protocol requires a coordinated migration even when the queue is empty. `sccache-release-update --plan-only` verifies the candidate and displays the restart decision without changing services.
- Canonical bundles also carry a `rollout_epoch`. The updater requires it to match `SCCACHE_AUTOUPDATE_EXPECTED_ROLLOUT_EPOCH` (default `2`) before touching live binaries. Increment the release epoch for any change that needs coordinated host-side migration; old hosts then refuse the release until the migration is performed and their expected epoch is advanced.

## Acer installation

The live paths are:

```text
/usr/local/bin/cargo
/usr/local/bin/rustup
/usr/local/libexec/sccache-client
/usr/local/bin/sccache -> ../libexec/sccache-client
/usr/local/libexec/sccache-cmake-launcher
/etc/sccache/wrapper.conf
/usr/local/libexec/sccache-release-update
```

Install atomically as root after validating these repository copies. The shared-endpoint router and config replace the old `user_endpoint`/`root_endpoint` and `user_service`/`root_service` settings; apply them together. Install the tracked `wrapper.conf` as the host-specific configuration (change endpoint/service/server_uid explicitly on other hosts). Do not install the new wrapper until the matching binary supports no-autostart. Keep the prior live files as timestamped backups; binary rollouts are handled by the tracked `sccache-release-update`.

## Shared multi-user daemon rollout

The normal cache-storage and distributed-scheduling daemon runs as the
configured `server_uid` (Acer: jan, UID 1000). The managed wrapper routes
all identities to its single socket. For clients with a different UID it
activates namespace/client-side mode; the caller itself opens source files,
runs any local compiler, and writes output files. The daemon retains cache
and worker-scheduling state. Root can connect to Acer's existing jan-owned
socket; other unprivileged users need an explicitly authorized Unix-socket
group/ACL, including permission to traverse its parent directory. Do not
make the socket world-writable.

The current production binary predates the namespace distributed broker.
Only activate the shared router after installing a matching native
`sccache`/dist bundle with compatible namespace IPC and the coordinated
fleet protocol migration. Respect the existing fleet deployment hold.
Replace the router and `wrapper.conf` together; their configuration keys
are intentionally not backwards-compatible. Test root and jan C/Rust
compilation, output ownership, shared hit counters, and distributed jobs
through the same socket before disabling the redundant
`sccache-local-root.service` (TCP 4227). Retain
`sccache-native-root.service` and `sccache-strict-local.service` until
their distinct execution policies are handled by the shared broker.
The release updater already handles an inactive root-local service.

## Service provisioning

Install the release updater service and timer from this directory under
`/etc/systemd/system/`. Use systemd drop-ins for host-specific settings such
as managed endpoints; keep the service and timer templates shared.

On hosts that need the distributed-client startup preflight, install
`sccache-dist-client-preflight` under `/usr/local/libexec/` and call it as an
`ExecStartPre` for the managed local daemon with the same
`SCCACHE_DIST_CLIENT_CACHE_DIR` as the service. The preflight only removes
the disposable `client/toolchain_tmp` directory documented by
`ClientToolchains::new`; it rejects unexpected files and symlinks. Run
`test-dist-client-preflight` for the filesystem contract. Do not invoke
the preflight against a running daemon.

## Host-native release policy

The portable GitHub release is the source-revision and protocol authority.
Run the checked-out revision's build-host-native as the normal managed
build user, with the existing sccache wrappers (never as an unmanaged
root Cargo invocation). This stages both binaries with native Rust and
C/C++ code generation, the machine/CPU fingerprint and checksums.

After verifying the build, an administrator copies its four regular files
(sccache, sccache-dist, build.txt, SHA256SUMS) into a root-owned,
non-group/world-writable directory /var/lib/sccache-native-bundles/<full source SHA>.
Install host-native-metadata beside the managed sccache-release-update.
Set SCCACHE_AUTOUPDATE_NATIVE_BUNDLE_ROOT=/var/lib/sccache-native-bundles
in the updater service environment, and coordinate the protocol epoch separately.
The updater waits for a matching native build rather than reverting to
the portable binary. It checks the local checksum manifest, source SHA,
protocol, toolchain, feature set, capabilities and machine/CPU identity
against the published release before using its immediate restart/rollback logic.
Build provisioning is separate from the root updater: no automatic root
compilation and no extra cache daemons.


## Full native-cache acceptance

`test-native-cache-reuse` is an operator regression test for the actual native
stage of `boring-sys`. Supply the patched BoringSSL source tree copied by the
build script, an existing dedicated scratch workspace, the expected number of
compiled objects, and the real CMake compiler/launcher/flags options. Export the
original Cargo manifest/target environment (`CARGO_MANIFEST_DIR`,
`SCCACHE_CANONICAL_TARGET_ROOT`, and where used `CARGO_HOME`, `CARGO_TARGET_DIR`,
`TARGET`). Use the production compiler wrappers; the existing managed daemon
must be available over its Unix socket. Example for the x86-64 BoringSSL 5.5.0
workload (407 objects; flags should match the real build):

```sh
flags=' -ffunction-sections -fdata-sections -fPIC -m64 -march=x86-64 -w'
contrib/codeandsolder/test-native-cache-reuse "$copied_boringssl" "$scratch" 407 \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_COMPILER=/usr/local/libexec/sccache-strict-wrappers/cc \
  -DCMAKE_CXX_COMPILER=/usr/local/libexec/sccache-strict-wrappers/c++ \
  -DCMAKE_ASM_COMPILER=/usr/local/libexec/sccache-strict-wrappers/cc \
  -DCMAKE_C_COMPILER_LAUNCHER=/usr/local/libexec/sccache-cmake-launcher \
  -DCMAKE_CXX_COMPILER_LAUNCHER=/usr/local/libexec/sccache-cmake-launcher \
  -DCMAKE_C_FLAGS="$flags" -DCMAKE_CXX_FLAGS="$flags" -DCMAKE_ASM_FLAGS="$flags"
```

The harness creates two independent Cargo build-unit roots, compiles every
object in the real CMake crypto/fipsmodule/ssl targets, and records each
managed-cache lookup separately using the client-side IPC protocol and `strace`.
The first build may hit or miss; the second must hit every object with exactly
the same key. It verifies byte-identical objects/archives and actual dependency
paths, then forces a fresh compile in normal managed mode and compares all
artifacts. A real source mutation must produce a new key and symbol.
The lookup parser deliberately fails on unexpected protocol frames. This needs
Linux, GNU Make, CMake, strace, ripgrep, awk, sha256sum and nm. No daemon or
additional cache directory is started, and shared hit counters are not reset.
The full forced-recache stage consumes production compilation capacity; run it
when doing acceptance, not periodically. The harness removes its own copied
source/build trees and keeps the compact lookup and SHA-256 manifests and logs
in its unique scratch directory.
