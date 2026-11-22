# codeandsolder host wrappers

These are the source-of-truth copies of the machine-wide Cargo/sccache wrappers, release updater, and service provisioning templates used on the codeandsolder build nodes.

## Contract

- `cargo-wrapper` exports `SCCACHE_MIN_JOBS` (default 12). The managed cargo-ephemeral binary clamps the resolved build job count to this floor, preserving higher values and inherited jobservers. Set it to 0 to disable the floor.
- `cargo-wrapper` preserves Cargo's own target-directory semantics. It never invents or exports `CARGO_TARGET_DIR` merely for cache normalization.
- `cargo-wrapper` exports `EPHEMERAL_CARGO_WRAPPER`/`CARGO` so nested Cargo invocations return through the site launcher instead of exposing the underlying Cargo binary.
- `rustup-wrapper` is a narrow policy guard: `rustup run <toolchain> cargo ...` is translated to the equivalent site `cargo +<toolchain> ...` path, while non-Cargo rustup commands pass through untouched. `CODEANDSOLDER_RUSTUP_STOCK_CARGO=1` explicitly restores stock Cargo for compatibility testing.
- For compilation subcommands it resolves the effective target root with Cargo precedence (`--target-dir`, existing `CARGO_TARGET_DIR`, then `cargo metadata`) and exports only `SCCACHE_CANONICAL_TARGET_ROOT` for child compiler processes. Wrapper-derived roots are marked and recomputed by nested Cargo invocations so a child build cannot inherit a stale parent target root.
- `sccache-client` selects the managed daemon by EUID and only opts into experimental canonical Rust when target-layout context is available (`SCCACHE_CANONICAL_TARGET_ROOT`, `CARGO_TARGET_DIR`, or `OUT_DIR`). Direct rustc without Cargo target context remains ordinary sccache.
- Native Cargo dependencies use the actual build-script `OUT_DIR` and shared Cargo root discovery, not a guessed temporary-directory naming pattern. With canonical Cargo context and a supported Linux GCC/Clang compiler, sccache applies real compiler `-ffile-prefix-map` options to both preprocessing and local/distributed compilation. The per-package output root has stable identity independent of the temporary build directory or Cargo fingerprint. Generated map options do not leak their physical paths into the object-cache key: genuine preprocessor filename directives and compiler-visible paths are hashed with the corresponding canonical identity; source literals remain data.
- The native path policy always fully preprocesses the source before cache lookup, generating dependency files with the actual local paths on both hits and misses. It does not use the filename-sensitive direct preprocessor cache or directives-only worker reprocessing. Explicit compiler path mappings/compilation-directory overrides remain authoritative, and profiling/coverage and PCH generation retain their ordinary compiler semantics. Ordinary non-Cargo cache keys are unchanged.
- Canonical Rust inside sccache is fail-open: if the discovered cwd, output, source, extern, staticlib, or target-JSON path cannot be represented safely by the canonical map, that compilation uses ordinary sccache instead of failing the build.
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
/usr/local/libexec/sccache-release-update
```

Install atomically as root after validating these repository copies. Keep the prior live files as timestamped backups; binary rollouts are handled by the tracked `sccache-release-update`.

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
