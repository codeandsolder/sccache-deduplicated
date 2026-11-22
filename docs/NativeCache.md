# Native scheduler cache (experimental)

The native runtime in `crates/build-runtime` is a separate explicit action
protocol. It does not reinterpret the archive compiler protocol's keys and
is not yet the default compiler frontend. Neither enabling the scheduler
listener nor enabling a worker changes ordinary archive assignments.

## Action and storage contract

A client captures a quiescent filesystem snapshot (or imports verified
upstream packages and composes a tree) into a local native store. Tree
manifests preserve byte paths, executable modes, timestamps, symbolic links
and hardlink topology. Source capture uses descriptor-relative no-follow
traversal and before/after stat checks; it is not a substitute for a
filesystem snapshot if the source can change during capture.

An `ExecutionSpec` declares an immutable root, immutable tree mounts, exact
command bytes and environment, a platform contract, and named required or
optional output paths. The scheduler derives the action fingerprint from
this declaration and the worker verifies the same specification before
execution. There is no translation from an old compiler cache key.

The client pushes constituent trees by manifest and missing blobs, then
admits an action containing the exact root composition recipe and any
additional independent mounts. Every source tree is pinned by the action.
Workers compose the recipe directly in memory from the pinned package
manifests, including their selected subtrees and logical destinations.
The combined root is neither uploaded nor published to either CAS index.
Conflicting file entries are rejected, directory metadata normalization
is explicit in the recipe, and the recipe fingerprint is part of the
native action identity. A hit has a result delivery ticket; an in-flight action
can be observed by retrying admission; a miss reserves a compilation.
Scheduling a miss selects a worker whose advertised platform contract
matches and accounts for capacity in the same pool as ordinary jobs.
Repeating scheduling for the same pending ticket replays the allocation.

On the worker, each tree location is independently block-cloned (or copied)
into a private view. Bubblewrap binds views read-only except for declared
output parent directories and private `/tmp`. The command and its output
paths need not be rewritten into a special `/out` directory. Every output
parent and mount destination must be a real declared directory; an output
cannot replace an input entry, mount root, or namespace device/proc path.
Output parents can contain input files; modifications affect only the
per-execution private view. Multiple mounts of the same tree never share
a mutable view. The root declares `/tmp`, `/dev` and `/proc` directories.
Outputs and diagnostics are captured via descriptors rooted in the correct
backing view, rejecting symlink traversal, hashed, negotiated
against the scheduler's content store, and transferred directly only if
missing. The scheduler commits the manifest and a client delivery pin
atomically. Successful worker HTTPS responses contain no output bytes.
Failed processes return diagnostics and exit status without committing a
successful action.

The platform contract is an administrator-supplied compatibility declaration,
not automatic hardware attestation. Equal contracts must imply compatible
observable hardware, kernel, sandbox and execution behavior; the compiler
frontend must only admit cacheable actions. Current time, randomness and
other nondeterministic process behavior are not automatically normalized.

## Configuration

Both sections below are opt-in. Use an authenticated private transport for
the dedicated HTTP cache listener (e.g. the managed private network);
the listener does not terminate TLS itself. Worker job claiming uses the
existing HTTPS job service with the scheduler-provided certificate and job
capability. The cache listener uses the scheduler's existing client and
worker authentication. Do not expose it as a public cache endpoint.

Scheduler configuration example (illustrative resource limits):

```toml
[native_cache]
public_addr = "127.0.0.1:10502"
directory = "/var/lib/sccache-native/scheduler"
idle_timeout_secs = 120
max_sessions = 128
max_result_bytes = 1073741824
max_result_blobs = 1024
max_tree_bytes = 21474836480
max_tree_blobs = 200000
max_concurrent_uploads = 4
max_total_uploads = 16
http_threads = 32
max_metadata_bytes = 67108864

[native_cache.space]
min_available_bytes = 536870912
target_available_bytes = 2147483648
max_evictions_per_pass = 32
gc_batch = 1024
```

Linux native-only worker configuration example (use the reachable scheduler
cache address, not necessarily the example loopback address). Select
`builder.type = "native"` in the main worker configuration and omit archive
`cache_dir` and archive sources. This worker never constructs the legacy
overlay builder or archive cache, and cannot be scheduled for archive jobs.
A worker with a legacy builder and a native worker section supports both
protocols, sharing its advertised capacity.

```toml
[builder]
type = "native"

[native_worker]
cache_url = "http://127.0.0.1:10502"
directory = "/var/lib/sccache-native/worker"
scratch = "/var/lib/sccache-native/scratch"
bubblewrap = "/usr/bin/bwrap"
platform_contract = "site-defined-linux-execution-contract-v1"
renewal_interval_secs = 15
request_timeout_secs = 120
execution_timeout_secs = 600
max_result_bytes = 1073741824
max_metadata_bytes = 67108864

[native_worker.space]
min_available_bytes = 536870912
target_available_bytes = 2147483648
max_evictions_per_pass = 32
gc_batch = 1024
```

The worker advertises the BLAKE3 digest of the exact platform contract.
Clients use the same digest in `ExecutionSpec.platform`. The renewal
interval must be shorter than the scheduler idle timeout.

Place store and scratch on appropriate quota-controlled dedicated filesystems.
The application currently bounds sessions, transfer sizes and concurrent
uploads. Store admission uses allocatable filesystem bytes (statvfs), not
logical blob lengths, so compressed and block-cloned ZFS content is not
mistaken for physical allocation. Below the configured low watermark it
reclaims pending garbage and evicts unpinned least-recently-used action
and tree roots in bounded passes, rechecking actual free space rather than
assuming deleted logical lengths were reclaimed. Active writers reserve a
conservative uncompressed upper bound until staged bytes are synced.
Recency is in-memory and unknown roots after restart rank oldest.
The external dataset quota remains the hard limit; snapshots, open files,
clone extents, delayed accounting and other writers can prevent reclaim.
A separate quota-controlled scratch filesystem is still required; per-job
scratch limits and fleet-level capacity policy remain outstanding. The native store is not
an additional production sccache cache tier.

## Toolchain discovery and mapped trees

The Linux C and Rust toolchain packagers share their existing dependency and
path discovery between archive emission and native mapping. Native mapping
reads selected files into verified CAS staging, normalizes toolchain modes
and timestamps, and rebases both symlink names and targets when a logical
sysroot mapping is applied. No archive or intermediate materialized root is
created. Mappings also support generated file bytes and explicit directories.
The caller must keep sources stable during capture; per-file stat checks
detect changes but are not a filesystem snapshot. This API is available when
the distributed client and native store features are enabled.

### Compiler inputs

C and Rust use one input discovery plan for logical paths, traversal
directories and physical symlink topology. Native capture consumes the
preprocessed C bytes directly and retains complete Rust dependency
artifacts rather than generating another, metadata-only variant of each
rlib. The archive emitter still supports per-file trimming and streams
ordinary files instead of collecting them into a buffer. The native
input and toolchain trees use the same explicit directory normalization.

## Validation

The runtime crate has focused tests for identity, import, tree capture,
reference accounting, publication, session leases and isolated execution.
The native HTTP tests exercise actual wire transfers and a Bubblewrap
execution with a captured shell root and a separate mounted source tree.
The scheduler unit test checks platform matching and shared capacity.
A subprocess integration test uses real assembler dependency discovery, direct CAS transfer, the scheduler, HTTPS job claiming and a native-only Bubblewrap worker; it compares object bytes against local assembly and verifies cache reuse and failed-action handling.
The ordinary compiler frontend, production deployment, real multi-host
benchmarking and hard scratch quotas remain separate integration work.
