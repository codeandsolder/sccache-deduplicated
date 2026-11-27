# Native Rust workspace builds

The native Rust build frontend is part of sccache, not an external Cargo
planner. It reads Rust ecosystem manifests and lockfiles directly and
submits compiler requests through the managed compiler session. The
existing scheduler, workers, package store, action cache and intermediate
artifact leases remain the execution and storage authorities.

## Invocation

On Linux with the managed native client and daemon configured:

```sh
sccache build --workspace --locked
sccache check --all-targets --locked
sccache test --workspace --locked
sccache clippy --all-targets --locked -- -D warnings
sccache +nightly-2026-11-23 build --release --locked
sccache build --toolchain-root /path/to/immutable/toolchain --locked
sccache run --bin my-program -- arg1 arg2
sccache doc --no-deps
sccache generate-lockfile
sccache update
sccache metadata --format-version 1
sccache metadata --no-deps --format-version 1
sccache fmt --workspace -- --check
sccache clean
```

The fleet wrapper forwards build arguments to this frontend. Cargo is not
invoked during native workspace execution. Existing compiler-wrapper
invocations remain supported by the compiler cache itself. Bootstrapping
the development branch still uses the installed Rust build toolchain.

## Execution

* Workspace discovery reads manifests, inherited dependency declarations,
  target declarations, profiles and configuration.
* The resolver consumes existing v3/v4 lockfiles or resolves registry,
  path and Git dependencies. An unlocked manifest mismatch may trigger
  atomic lockfile replacement. New registry selections respect the
  configured 72-hour release-age policy. Locked acquisition is concurrent
  (`--source-jobs`, default 16), deduplicated per source identity, and advances
  as individual dependencies become ready. Unlocked version backtracking
  uses a mutation journal rather than cloning the graph.
* The resolved host/target units, feature sets, build scripts, compilation,
  rustdoc, tests and publication form one readiness graph. Build-script
  directives are interpreted only after the producing action completes.
  Dispatch restricts work to the requested prerequisite closure. Link-time
  optimization requirements propagate backwards through consumers, so host
  tooling and ordinary links do not unnecessarily produce LLVM bitcode.
* Compiler actions use the existing managed compiler session. The local
  frontend does not choose distributed workers. The common dispatch
  runtime bounds outstanding requests, not the cluster's CPU capacity.
* One build-scoped lease protects intermediate artifacts. Final output
  publication uses the declared binary name and an atomic replacement;
  competing publishers of the same target directory are serialized.

## Content identities

Compiler cache identity uses file contents, arguments, relevant environment,
toolchain identities and the captured input closure. Compiler discovery,
rlib dependency discovery, C/C++ include validation and compiler-helper
discovery must not accept mtime or ctime as freshness evidence. Immutable
fs-verity files and genuine read-only ZFS snapshot files can reuse a verified
digest; mutable files are rehashed. Snapshot recognition uses descriptor-based
kernel mount metadata, including the unique mount ID and snapshot source.
Ordinary read-only mounts and unsupported kernels do not qualify.
Rust key schema 13 binds canonical source paths and extern aliases to their
contents, and hashes actual installed host/target runtime files rather than
trusting rustup installation manifests. Git checkouts use a canonical root
covering all sibling crates. Select a pinned installation with
`--toolchain-root` or `[build] toolchain-root` in project configuration.
The compiler and companion tools must resolve inside that installation,
and the compiler must report the same sysroot. Snapshot provisioning and
retention remain the administrator's responsibility.

Native compiler sandbox input timestamps are normalized. Metadata checks
that detect a concurrent modification during capture are race guards, not
cache keys or freshness shortcuts. Release age is a dependency-selection
policy, not a filesystem timestamp heuristic. Time macros remain subject
to their compiler semantics.

## Registry package delivery

The scheduler verifies the archive checksum and imports the package tree
once. The daemon pins that tree under the existing build retention group
and sends its manifest to the frontend. The build filesystem exposes
individual files as authenticated CAS references and retrieves bytes only
when read. Source hashing can reuse verified content IDs; compilation
input trees use the same content store. No original archive needs to be
retained for this delivery mode. A pre-existing ecosystem archive cache
can be imported read-only on an offline miss; no second persistent package
cache is created. Git
sources use pinned isolated checkouts. The resolved metadata command emits
separate host and target units and stable source-relative paths for leased
external sources; it does not pretend ephemeral checkout paths remain valid
once the lease ends.

Alternate registries use the ecosystem index identifier and a named scheduler
upstream with a relative archive template, for example:

```toml
[registries.internal]
index = "sparse+https://registry.example/index/"
sccache-upstream = "internal"
sccache-archive-path = "crates/{crate}/{crate}-{version}.crate"
# Optional existing absolute offline index directory:
# sccache-index-cache = "/path/to/index"
```

Configure the corresponding upstream origin on the scheduler. The scheduler
never accepts a requester-supplied arbitrary archive origin.

This branch requires namespace protocol 9 and the matching scheduler
package-tree endpoint. Configure a crates.io upstream:

```toml
[native_cache.package_upstreams.crates]
origin = "https://static.crates.io/"
timeout_secs = 180
```

Use the managed fleet configuration generator for deployment. Do not mix
namespace protocol versions. Offline requests must not fetch new archives.

## Validation and remaining work

The independent planner library can be tested without building the TLS
stack. From the repository, using the existing managed compiler wrapper:

```sh
cargo test --locked -p sccache-rust-build --lib
cargo test --locked -p sccache-rust-build --lib managed_planner_execution -- --ignored --nocapture
```

The second test exercises a local workspace with generated build-script
source, dependency metadata, a procedural macro, integration-test binary
publication and a same-length edit with its original mtime restored.
It uses the already configured sccache for actual compiler requests.

The read-only offline planner inspector accepts a source-cache root and
one or more manifest paths. It constructs and traverses the actual graph
without executing project builds or changing their files:

```sh
cargo run --offline --locked -p sccache-rust-build --example inspect -- \
    /path/to/import-cache /path/to/workspace/Cargo.toml
```

The branch is not yet a validated complete Cargo replacement. Broader
workspace/platform/profile semantics, authenticated private registry
integration, remaining CLI operations, hermetic build-script result caching,
fleet snapshot provisioning and coordinated protocol-9 integration require
further work.
Build scripts, rustdoc and test execution are explicit local actions,
not claimed to be independently cacheable arbitrary processes.
