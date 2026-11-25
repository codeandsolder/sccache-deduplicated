# codeandsolder host wrappers

These are the source-of-truth copies of the machine-wide Cargo/sccache wrappers, release updater, and service provisioning templates used on the codeandsolder build nodes.

## Contract

- `cargo-wrapper` invokes the native Linux sccache launcher with `--cargo-final` and passes Cargo arguments unchanged. The launcher uses the unmodified upstream Cargo selected by rustup, and leases a unique temporary build directory via Cargo's standard `CARGO_BUILD_BUILD_DIR` workspace template. Final Cargo target-directory semantics remain unchanged. Explicit command-line Cargo configuration takes precedence; use `sccache --cargo-all -- <Cargo arguments>` for normal persistent intermediate retention and project build-dir configuration.
- The scratch lease is held across the Cargo process tree and reclaimed after exit or on a subsequent invocation after an interrupted build. Physical paths need not be deterministic: the distributed compiler maps the actual output tree to canonical paths. External Cargo subcommands inherit the standard build-dir configuration.
- Configure upstream Cargo's `build.jobs` (site default 16) and managed `rustc-wrapper` in Cargo configuration. The launcher does not alter Cargo's resolver, explicit job settings or inherited jobserver. Remove the fork-only `ephemeral-intermediates` setting when migrating hosts.
- `rustup-wrapper` routes `rustup run <toolchain> cargo ...` to the site Cargo launcher; non-Cargo commands remain ordinary rustup behavior.
- `sccache-client` is also the public `/usr/local/bin/sccache` router (install as a symlink). The root-owned plain key/value `/etc/sccache/wrapper.conf` selects managed TCP or Unix endpoints by EUID; explicit caller endpoints always take precedence. Automatically selected endpoints wait for service readiness for compilations, never administrative commands. Both entrypoints disable implicit daemon starts in the actual client. Compiler-wrapper mode only opts into canonical Rust when target-layout context is available (`SCCACHE_CANONICAL_TARGET_ROOT`, `CARGO_TARGET_DIR`, `CARGO_BUILD_BUILD_DIR`, or `OUT_DIR`). Direct rustc without Cargo target context remains ordinary sccache.
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

## Fleet release promotion

Ordinary commits to `main` and pull requests are tested but **never published
as fleet releases**. After the CI, Strict Rust, duplicate-code and distributed-runtime push checks pass for
current `main`, explicitly run:

```sh
gh workflow run publish-ci-client.yml \
  --repo codeandsolder/sccache-deduplicated \
  --ref main -f ref=main
```

The workflow rechecks all four gates against the exact current `main` revision,
then builds and verifies the Linux client and worker bundle. A successful
promotion creates an immutable `sccache-ci-<full source SHA>` GitHub Release.
The existing `sccache-release-update` service (invoked by `random-utils-update`)
installs only releases with that prefix, subject to protocol, rollout epoch,
ABI, health, and host-native bundle checks. `v*` source tags have a separate
upstream release workflow and do not promote the fleet bundle by themselves.

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

Install atomically as root after validating these repository copies. Install the tracked `wrapper.conf` as the host-specific configuration (change endpoint/service settings explicitly on TCP-only hosts). Do not install the new wrapper until the matching binary supports no-autostart. Keep the prior live files as timestamped backups; binary rollouts are handled by the tracked `sccache-release-update`.

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

## Shared multi-UID daemon (Linux)

The opt-in shared daemon serves normal compiler requests from multiple local
UIDs using one cache and one distributed-client connection authority. The
public client never executes the compiler: the daemon launches a private
executor, reproduces the caller's mount view, root, supplementary groups and
umask, and drops to the kernel-authenticated caller credentials before
compiler detection, preprocessing, local compilation or materialization.
The executor uses a private IPC channel for cache and scheduler operations.
The creation mask is part of both legacy and native Linux cache identity,
and is carried to isolated remote execution. Cache hits do not reuse
outputs captured with a different creation mask.

The server requires Linux 6.5+ (SO_PEERPIDFD), a root-owned non-setuid binary,
a pathname Unix socket under canonical root-owned non-writable directories,
and a service with the namespace/credential/ptrace capabilities required
for its authorized users. Initial support is restricted to the daemon's user
namespace; a separate mount namespace is supported. Remapped user namespaces
fail closed. Do not enable native local execution in the root daemon: local
fallback must execute in the credential-isolated helper instead.

Example service configuration (replace both numbers with the actual local
authorized UID and socket-access group):

```toml
[shared_daemon]
socket_gid = 1000
allowed_uids = [1000]
```

Run the managed server as root with a root-owned runtime directory such as
`/run/sccache-shared` (mode 0755), and its existing cache/distribution
configuration and service startup policy. The socket is created root:group
with mode 0660. Root is implicitly authorized; other users must pass both
filesystem access and the explicit UID allowlist. Only root can reset
statistics, cancel arbitrary jobs, enumerate active compile details or shut
down the daemon. Neither root nor ordinary public clients can use the raw
cache broker or caller-owned compilation mode.

Configure both routes in the host-specific wrapper configuration:

```ini
user_endpoint=unix:/run/sccache-shared/sccache.sock
root_endpoint=unix:/run/sccache-shared/sccache.sock
user_service=sccache-local.service
root_service=sccache-local.service
readiness_seconds=300
```

Retain verified compiler aliases for installed strict compiler launchers;
they are resolved within the requester's filesystem and apply to uncached
fallback too. The old per-root service must be stopped/disabled as part of
the coordinated migration; do not start another persistent daemon. Verify
cross-UID cache reuse, ownership, local fallback and distributed execution
before removing its previous configuration or restoring automatic updates.
The isolated root regression in `tests/native_dist.rs` is for disposable CI
only, not for starting test daemons in the managed fleet.

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
