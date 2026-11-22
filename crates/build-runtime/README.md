# Native build runtime (experimental)

This crate is the foundation of the scheduler-owned build environment and
content store. It does not change the existing distributed wire protocol or
activate the native backend in a deployed daemon yet.

## Storage and identities

- BLAKE3 digests identify immutable raw file bytes.
- Complete result manifests identify compiler outputs, their modes and
  diagnostic contents independently of action fingerprints.
- Versioned action fingerprints record named component digests. Different
  actions can reference the same result without aliasing their keys.
- Trees and result manifests share one content index. The redb index tracks
  all durable references, and the last reference schedules physical deletion.
- Staging is verified before publication; file contents and directory entries
  precede the durable index transaction. Incomplete publication can leave
  unreferenced files, which are removed on reopening the store.
- Active result/tree leases prevent eviction; upload leases protect already
  present blobs between missing-content negotiation and commit.
- Garbage collection is bounded and retryable. Logical live and pending
  deletion byte counters are maintained transactionally. Physical accounting,
  quota-aware eviction selection, and remote admission are separate scheduler
  policy concerns.

On ZFS, files remain ordinary uncompressed byte streams at the API boundary.
The dataset handles transparent compression, and private materialized views
attempt block cloning before copying. Native ZFS deduplication is not needed.
Never expose writable hardlinks of CAS files to builds.

## Packages and build environments

Upstream tar, gzip and XZ packages are verified against their expected SHA-256
and size before decompression. The importer stages the compressed bytes only
temporarily, and publishes a normalized directory tree referencing individual
content blobs. The package identity index allows a subsequent request to skip
the upload and extraction entirely. A package recipe selects and combines
subtrees by metadata, preserves file/symlink content and link topology, and
rejects conflicting entries. It does not reconstruct or repack an archive.

The Linux sandbox runner uses Bubblewrap and an explicit logical mount plan.
It starts without the host environment, presents immutable trees as read-only,
isolates namespaces, disables networking and accepts explicit process inputs.
Invocation and layout fingerprints are independent of host materialization
paths. A caller must still identify every mounted tree, initial writable state
and other observable platform inputs before treating an action as shareable.
The normalized tree contract covers paths, permissions, mtime and links, not
arbitrary host ownership, ACLs or extended attributes.

The build coordinator reserves one in-flight compilation per full action key.
Equivalent-result auditing compares actions whose remaining input components
are identical after a candidate field is removed. It counts contradictory as
well as matching results; it never weakens the cache key automatically.

## Validation

Run the isolated crate tests with the existing managed compiler cache:

```sh
cargo test --locked -p sccache-build
# Linux worker with Bubblewrap and enabled user namespaces:
cargo test --locked -p sccache-build -- --include-ignored
```

Filesystem probes accept a scratch parent and real input files as positional
arguments, and clean their temporary stores on exit:

```sh
cargo run --locked -p sccache-build --example zfs_probe -- /path/on/zfs /path/to/file
cargo run --locked -p sccache-build --example package_probe -- /path/on/zfs /path/to/package SHA256 gzip
```

The next integration boundary is scheduler/worker transport, binding compile
permits to authenticated jobs and using the native store for direct result
publication. The existing cache protocol must not be switched until the full
sandbox/toolchain identity and local/distributed equivalence contract is in use.
