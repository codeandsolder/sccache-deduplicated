# codeandsolder host wrappers

These are the source-of-truth copies of the machine-wide Cargo/sccache wrappers used on the codeandsolder build nodes.

## Contract

- `cargo-wrapper` preserves Cargo's own target-directory semantics. It never invents or exports `CARGO_TARGET_DIR` merely for cache normalization.
- For compilation subcommands it resolves the effective target root with Cargo precedence (`--target-dir`, existing `CARGO_TARGET_DIR`, then `cargo metadata`) and exports only `SCCACHE_CANONICAL_TARGET_ROOT` for child compiler processes. Wrapper-derived roots are marked and recomputed by nested Cargo invocations so a child build cannot inherit a stale parent target root.
- `sccache-client` selects the managed daemon by EUID and only opts into experimental canonical Rust when target-layout context is available (`SCCACHE_CANONICAL_TARGET_ROOT`, `CARGO_TARGET_DIR`, or `OUT_DIR`). Direct rustc without Cargo target context remains ordinary sccache.
- Canonical Rust inside sccache is fail-open: if the discovered cwd, output, source, extern, staticlib, or target-JSON path cannot be represented safely by the canonical map, that compilation uses ordinary sccache instead of failing the build.
- The maintenance-drain marker remains `/dev/shm/sccache-maintenance-drain`; a marker older than 15 minutes is ignored.

## Acer installation

The live paths are:

```text
/usr/local/bin/cargo
/usr/local/libexec/sccache-client
```

Install atomically as root after validating these repository copies. Keep the prior live files as timestamped backups; binary rollouts are handled separately by `sccache-release-update`.
