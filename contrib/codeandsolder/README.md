# codeandsolder host wrappers

These are the source-of-truth copies of the machine-wide Cargo/sccache wrappers and release updater used on the codeandsolder build nodes.

## Contract

- `cargo-wrapper` preserves Cargo's own target-directory semantics. It never invents or exports `CARGO_TARGET_DIR` merely for cache normalization.
- `cargo-wrapper` exports `EPHEMERAL_CARGO_WRAPPER`/`CARGO` so nested Cargo invocations return through the site launcher instead of exposing the underlying Cargo binary.
- `rustup-wrapper` is a narrow policy guard: `rustup run <toolchain> cargo ...` is translated to the equivalent site `cargo +<toolchain> ...` path, while non-Cargo rustup commands pass through untouched. `CODEANDSOLDER_RUSTUP_STOCK_CARGO=1` explicitly restores stock Cargo for compatibility testing.
- For compilation subcommands it resolves the effective target root with Cargo precedence (`--target-dir`, existing `CARGO_TARGET_DIR`, then `cargo metadata`) and exports only `SCCACHE_CANONICAL_TARGET_ROOT` for child compiler processes. Wrapper-derived roots are marked and recomputed by nested Cargo invocations so a child build cannot inherit a stale parent target root.
- `sccache-client` selects the managed daemon by EUID and only opts into experimental canonical Rust when target-layout context is available (`SCCACHE_CANONICAL_TARGET_ROOT`, `CARGO_TARGET_DIR`, or `OUT_DIR`). Direct rustc without Cargo target context remains ordinary sccache.
- Canonical Rust inside sccache is fail-open: if the discovered cwd, output, source, extern, staticlib, or target-JSON path cannot be represented safely by the canonical map, that compilation uses ordinary sccache instead of failing the build.
- The maintenance-drain marker remains `/dev/shm/sccache-maintenance-drain`; a marker older than 15 minutes is ignored.
- `sccache-release-update` validates release metadata against `sccache --capabilities` and requires `direct-metrics` by default, so a canonical rollout cannot silently remove production telemetry again.
- The updater connects to the primary managed daemon over the default `SCCACHE_AUTOUPDATE_CLIENT_UDS` or, for TCP-managed nodes, `SCCACHE_AUTOUPDATE_CLIENT_PORT`; the selected endpoint is used consistently for drain detection, restart readiness, stats, and smoke tests.
- Canonical bundles carry an explicit `dist_protocol` version. When the live dist binary is hash-bound to the same protocol version, the updater may roll the client ahead under the local maintenance drain while distributed jobs remain active; the full `release_tag` advances only after client and dist halves converge on the same immutable bundle. A protocol-version change still requires the old all-at-once idle window. `sccache-release-update --plan-only` runs this decision logic without changing services.

## Acer installation

The live paths are:

```text
/usr/local/bin/cargo
/usr/local/bin/rustup
/usr/local/libexec/sccache-client
/usr/local/libexec/sccache-release-update
```

Install atomically as root after validating these repository copies. Keep the prior live files as timestamped backups; binary rollouts are handled by the tracked `sccache-release-update`.
