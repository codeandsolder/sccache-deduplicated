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

The client pushes trees by manifest and missing blobs, then obtains an
action admission. A hit has a result delivery ticket; an in-flight action
can be observed by retrying admission; a miss reserves a compilation.
Scheduling a miss selects a worker whose advertised platform contract
matches and accounts for capacity in the same pool as ordinary jobs.
Repeating scheduling for the same pending ticket replays the allocation.

On the worker, immutable tree views are materialized from the local store
and bound read-only in Bubblewrap with private writable `/out` and tmpfs
`/tmp`. The root must declare real directories for every mount point and
the fixed `/out`, `/tmp`, `/dev` and `/proc` mounts. Outputs and
diagnostics are captured as regular file descriptors, hashed, negotiated
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
```

Linux worker configuration example (use the reachable scheduler cache
address, not necessarily the example loopback address):

```toml
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
```

The worker advertises the BLAKE3 digest of the exact platform contract.
Clients use the same digest in `ExecutionSpec.platform`. The renewal
interval must be shorter than the scheduler idle timeout.

Place store and scratch on appropriate quota-controlled dedicated filesystems.
The application currently bounds sessions, transfer sizes and concurrent
uploads, but does not yet implement physical-usage-based eviction admission
or per-job scratch quotas. Worker-side tree retention and fleet-level
capacity policy are still required before rollout. The native store is not
an additional production sccache cache tier.

## Validation

The runtime crate has focused tests for identity, import, tree capture,
reference accounting, publication, session leases and isolated execution.
The native HTTP tests exercise actual wire transfers and a Bubblewrap
execution with a captured shell root and a separate mounted source tree.
The scheduler unit test checks platform matching and shared capacity.
The ordinary compiler frontend, production deployment, real multi-host
benchmarking and physical quota management remain separate integration work.
