# Native scheduler cache (experimental)

The native runtime in `crates/build-runtime` is a separate explicit action
protocol. It does not reinterpret the archive compiler protocol's keys and
is not yet the default compiler frontend. Neither enabling the scheduler
listener nor enabling a worker changes ordinary archive assignments.

## Action and storage contract

A client describes quiescent files directly, or a store imports verified
upstream packages and composes a tree. Tree
manifests preserve byte paths, executable modes, timestamps, symbolic links
and hardlink topology. Source capture uses descriptor-relative no-follow
traversal and before/after stat checks; it is not a substitute for a
filesystem snapshot if the source can change during capture.

An `ExecutionSpec` declares an immutable root, immutable tree mounts, exact
command bytes and environment, a platform contract, and named required or
optional output paths. The scheduler derives the action fingerprint from
this declaration and the worker verifies the same specification before
execution. There is no translation from an old compiler cache key.

The client prepares manifests directly from mapped source files and generated
bytes without a local CAS. File metadata is checked before and after hashing
and again when a missing blob is opened; the scheduler verifies its exact
digest and length. Sources must remain quiescent across the operation.
Admission precedes upload: a cache hit does not require input trees to still
exist, and a miss requests only unknown constituent manifests. Admission
validates the complete immutable input identities without requiring the
scheduler to hold their payloads. The scheduler retains the admitted manifests
for the action and uses a bounded manifest cache across actions.
The submitting client keeps its input provider available until the action
finishes; it uploads bytes only in response to an explicit content demand.

Assignments include the exact input blob identities and lengths. The worker
pins resident input content at assignment, including partial trees, and
acquires only missing content before taking a compiler slot. The scheduler
serves available blobs directly; a missing blob registers a shared backfill
flight and returns HTTP 202 while a source is selected. A bounded peer-source
pool first tries workers whose latest residency summary predicts the blob.
The peer uses a separate expiring HTTPS capability bound to the exact digest
and length (not a compilation job token), with its registered certificate.
A short discovery window and bounded source-probe deadlines prevent a stale
hint or a busy peer service from indefinitely delaying the original client.
If no peer provides the bytes, the scheduler requests them from an active
submitting client; claims share the global upload budget. An origin that
cannot reopen its source can decline the demand, allowing another declared
source tree, live origin, or another peer lookup to satisfy the same flight.
Neither peer lookup nor backfill consumes a compiler slot.

All incoming bytes are length- and digest-verified before publication.
Individual verified acquisitions survive failures of other blobs, use the
same deduplicated store, and remain pinned during staging. Interrupted or
truncated input downloads retry that blob under the existing deadline.
Indexed trees with missing payloads are repaired rather than requiring an
entirely new tree; pending-GC content remains usable until actually removed.
A stale residency prediction therefore requires only acquisition of the
missing content, not a new assignment. Results still publish to the scheduler
CAS; action-result discovery from peer caches is a separate operation.

Workers compose the recipe directly in memory from the leased constituent
manifests, including their selected subtrees and logical destinations.
The combined root is neither uploaded nor published to either CAS index.
Conflicting file entries are rejected, directory metadata normalization
is explicit in the recipe. The native action identity (schema
`native-linux-bwrap-v4`) hashes the composed root manifest rather than the
recipe fingerprint or constituent tree IDs. Mount identities remain bound to
their exact destination paths. The scheduler independently composes and
verifies the declared root digest before admitting a miss, applies tree
limits to the composed root, and binds the exact delivery recipe to the
ticket. The worker also verifies the resolved root before execution.
Equivalent layer orderings or flattened trees therefore reuse a cached
result without publishing a new tree, but a different file or metadata
entry requires a different action. The old experimental action schema is
not reused. A hit has a result delivery ticket; an in-flight action
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

The native scheduler, worker and compiler client are opt-in. Use an authenticated private transport for
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
max_resident_bytes = 274877906944
target_resident_bytes = 257698037760
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
max_resident_bytes = 4294967296
target_resident_bytes = 3221225472
max_evictions_per_pass = 32
gc_batch = 1024
```

The native store uses one transactional index, lease/GC implementation, and
usage-aware eviction policy on scheduler, worker and local executor. The
resident budget counts uncompressed live blobs and queued garbage conservatively;
ZFS separately compresses them and the filesystem free-space watermarks still
apply. For actual physical cache isolation, place each store on a quota-managed
dataset. Worker replicas are persistent and reuse the same verified blobs and
package trees, fetching missing inputs only. Access frequency and recency are
buffered and checkpointed at most once per minute during maintenance,
plus on orderly shutdown, without write I/O on cache hits. Staged files
hold admission reservations through publication; their releases are applied
atomically without taking the admission lock, preventing lock-order cycles
with concurrent eviction and index publication.

Under cache pressure, eviction ranks roots by the expected reuse cost per
byte that deleting them could actually reclaim. It follows the transactional
reverse-reference index: multiple action aliases for one result are not
counted as independent copies, content shared between trees or results is
not double-counted, and original package archives are included with their
own tree's eviction. Active content pins cannot free their underlying inode
immediately and are excluded from reclaim estimates. Under logical budget
pressure the score uses exclusive logical bytes; under filesystem free-space
pressure it uses the existing file's allocated blocks (`st_blocks`) so
transparent ZFS compression influences ranking. Snapshots or block clones
can still retain blocks; only post-GC `statvfs` confirms real free space.
A root that frees no content by itself can be evicted later if needed to
remove the last remaining shared reference. Candidate selection runs only
under pressure, holds at most the configured eviction batch in memory,
and takes no pin mutex over filesystem metadata I/O.

Native workers advertise an advisory Bloom summary of the live content index
(12 bits per blob, at most 1 MiB, refreshed every 15 seconds). This includes
produced artifacts and partial overlap between different immutable trees.
An oversized inventory is reported as unknown rather than saturated.
The scheduler uses the union of verified action input blobs and outstanding
worker reservations to estimate missing bytes. The heartbeat also carries
measured transfer throughput, request overhead and execution duration.
Native placement minimizes estimated completion time among eligible healthy
workers, with queue waiting and input staging overlapping; platform and
capacity constraints remain mandatory. Actual retrieval still verifies every
input. Update scheduler, worker and client binaries together after protocol changes.

Native blob downloads negotiate Zstandard independently from the immutable
blob representation. The scheduler samples at most 128 KiB of each requested
blob; for files at least 32 KiB long it streams a level-1 Zstandard frame
only when the sample predicts at least 15% transfer savings. Otherwise the
file is streamed raw. Clients decode before BLAKE3 and exact-length checks.
Neither path leaves a second compressed copy in the store, and the underlying
ZFS dataset retains transparent compression. These request paths are bounded
by existing session and concurrency limits.

### Native canary trace and budget replay

Only when the `native_cas_replay` log target is at **trace** level,
a worker emits structured JSON events for every resolved execution input tree:
`tree_access` with its immutable tree ID, verified unique blob IDs/lengths,
and a local-tree-hit flag; `tree_transfer` with the raw logical missing
content bytes after any original-package reconstruction. The latter describes
**decoded content** downloaded, not Zstd HTTP bytes. These events omit paths,
environment, source text and credentials. When trace logging is disabled,
workers do not enumerate blobs or serialize JSON for this instrumentation.

On an **isolated, coordinated native canary**, opt into the existing
`sccache-dist server --syslog trace` logging mode for a **short** window.
This mode enables other trace targets too, so avoid doing so on the busy
production workers. Extract the two native events from the canary journal
into a working directory, then compare candidate logical budgets:

```sh
journalctl -u sccache-dist-worker --since '30 minutes ago' -o cat |
  rg '"kind":"(tree_access|tree_transfer)"' > /home/jan/build/sccache-native-cache-retention-20261123/native-trace.jsonl

cargo +nightly-2026-11-22 run --locked -p sccache-build   --example cache_budget_replay -- 1073741824 2147483648 4294967296 8589934592   < /home/jan/build/sccache-native-cache-retention-20261123/native-trace.jsonl
```

The replay is an **offline deduplicated LRU baseline**, not a claim to
implement the production frequency/recency and exclusive-reclaim ranking
exactly. For each budget it reports tree-hit rate, logical missing-content
bytes, evictions and peak unique resident bytes. It counts a shared content ID
once across all retained trees, handles trees too large to admit, and uses a
75%-of-maximum hysteresis target. The same run separately prints the
**actual** canary tree-hit count and raw logical download bytes for comparison.
Empty/non-native log lines are ignored; malformed matching event records are
rejected. Run representative cold and warm sequences with their real ordering;
counterfactual results do not include ZFS block compression, original-package
decode CPU, cache admission stalls, concurrent pinning or external snapshots.

The worker advertises the BLAKE3 digest of the exact platform contract.
Clients use the same digest in `ExecutionSpec.platform`. The renewal
interval must be shorter than the scheduler idle timeout.

Place store and scratch on appropriate quota-controlled dedicated filesystems.
The application currently bounds sessions, transfer sizes and concurrent
uploads. Store admission uses allocatable filesystem bytes (statvfs), not
logical blob lengths, so compressed and block-cloned ZFS content is not
mistaken for physical allocation. Below the configured low watermark it
reclaims pending garbage and evicts unpinned action/tree roots using
persistent reuse statistics and uniquely reclaimable-content estimates in
bounded passes, rechecking actual free space rather than assuming deleted
logical lengths were reclaimed. Active writers reserve a
conservative uncompressed upper bound until staged bytes are synced.
Recency is in-memory and unknown roots after restart rank oldest.
The external dataset quota remains the hard limit; snapshots, open files,
clone extents, delayed accounting and other writers can prevent reclaim.
A separate quota-controlled scratch filesystem is still required; per-job
scratch limits and fleet-level capacity policy remain outstanding. The native store is not
an additional production sccache cache tier.

### Ordinary compiler client

On a supported Linux client built with the distributed-client feature,
select native mode in the normal sccache configuration:

```toml
[dist]
scheduler_url = "http://127.0.0.1:10500"

[dist.auth]
type = "token"
token = "<scheduler client token>"

[dist.native]
endpoint = "http://127.0.0.1:10502"
platform_contract = "site-defined-linux-execution-contract-v1"
request_timeout_secs = 120
build_timeout_secs = 600
renewal_interval_secs = 15
max_metadata_bytes = 67108864
max_result_bytes = 1073741824
```

The contract must match an eligible worker. Native mode bypasses archive
cache initialization, lookup and publication; it also bypasses the archive
toolchain cache. The existing compiler frontend still performs cacheability
analysis and source discovery. Cacheable supported commands produce an
exact native execution specification. Dependency files remain locally
generated; the worker's private Rust dep-info emission is retained where
needed for identical rlib metadata.

Unavailable native execution, unsupported custom toolchains, non-cacheable
commands and force-no-cache requests execute locally without archive caching.
For eligible native actions, forced recache reserves a fresh compilation of
the same action key and replaces its result only upon successful publication.
Normal readers may keep using the prior result during refresh; existing
delivery leases protect the old content even after replacement. Failed
or cancelled refreshes leave the previous publication intact, subject to
ordinary eviction. Cache-policy variables are consumed at compile-request
ingress, not included in the compiler environment or action identity.
Decomposed subcommands inherit the invocation's policy.
In client-side mode, the caller needs only
`client_side_mode = true` and access to the existing managed daemon's socket.
The daemon supplies the platform and resource policy in its namespace
handshake; endpoint URLs, authentication and job capabilities remain private.
The native action transaction runs in the daemon, requesting manifests and
missing blobs over a connection-owned bounded byte stream. A blob request is
authorized against the caller's prepared manifest even when the scheduler
already knows that manifest; a source availability reply precedes its bytes.
The caller alone discovers sources and installs outputs. The daemon verifies scheduler result
streams, the caller independently verifies them, and final completion
precedes publication. No client or daemon archive staging is required.
The stream has bounded queues, frame limits and an absolute deadline;
disconnect releases or expires the native action pins.

## Local exact-sandbox execution

Opt in on the managed sccache daemon (or a directly configured compiler
service) using the same native client configuration and platform contract:

```toml
[dist.native.local_execution]
preference = "remote_first" # or "local"
max_jobs = 4
directory = "/path/to/native-local-input-store"
scratch = "/path/to/native-local-scratch"
bubblewrap = "/usr/bin/bwrap"

[dist.native.local_execution.space]
min_available_bytes = 2147483648
target_available_bytes = 4294967296
max_evictions_per_pass = 128
gc_batch = 1024
```

The local executor owns an explicit quota-managed input CAS and private
scratch directory. It uses the same execution specification, verified root
composition, Bubblewrap runner, output capture, scheduler ticket and atomic
publication as a remote worker. Ordinary hits bypass execution. With the
local preference, missing input trees are first staged from the caller;
only missing content goes to the scheduler from those exact verified files.
With remote-first, local execution is selected only on an explicit unavailable
allocation, never after an ambiguous or successful remote assignment.
The local executor imports missing input bytes directly from caller-provided
sources, including through the scoped networkless namespace stream. Local
misses publish to the scheduler and deliver the captured descriptors directly
to the caller; they do not download the just-published result or populate a
second local action cache. A bounded local job pool renews the action lease
while waiting. Both local and worker execution require an administrator-
attested matching platform contract. Unconstrained local fallbacks remain
uncached. Native control and result publication work even when no compatible
remote worker is available, provided the scheduler cache service is reachable.

## Toolchain discovery and mapped trees

The Linux C and Rust toolchain packagers share their existing dependency and
path discovery between archive emission and native mapping. Native mapping
hashes selected files without staging, normalizes toolchain modes
and timestamps, and rebases both symlink names and targets when a logical
sysroot mapping is applied. No archive or intermediate materialized root is
created. Mappings also support generated file bytes and explicit directories.
Rust compiler discovery and mapped toolchain preparation share a bounded,
process-local digest memo for installed toolchain files. Inventory discovery still runs on each preparation.
A matching device, inode, mode, link count, size, mtime and ctime allow
a toolchain digest to be reused without reading file contents. Concurrent
preparations of the same path share a slot. The memo retains no bytes,
does not survive daemon restart, and is not used for project sources.
The caller must keep sources stable during capture; per-file stat checks
detect changes but are not a filesystem snapshot. This API is available when
the distributed client enables the mapping feature, even without a local store.

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
Real GCC and Rust compiler-plan tests compare native sandbox outputs
byte-for-byte against direct compiler invocations, including local dep-info
generation. A subprocess integration additionally runs real GCC and Rust through an
in-process sccache IPC service, real scheduler and native worker, both
directly and through a networkless Bubblewrap caller whose source files
differ from the daemon's files at the same paths. All four misses must
execute remotely, all four repeated calls must hit, and artifacts must
match the direct compiler byte-for-byte. The service never creates either
legacy cache. Production deployment, multi-host benchmarking and hard
scratch quotas remain separate integration work.

### Inspecting key relevance

The scheduler's index records component names and digests, not the original
environment values. Inspect a closed native index (or a consistent offline
snapshot supported by redb) without opening a writable store:

```sh
sccache-dist native-audit --index /path/to/index.redb
sccache-dist native-audit --index /path/to/index.redb \
  --schema native-linux-bwrap-v4 --without environment/CARGO_SOME_SETTING
```

Repeat `--without` to evaluate a group jointly. The report counts pairs of
distinct actions whose remaining components coincide, distinguishing identical
complete result manifests from conflicting results. The inventory reports
schema and component coverage. The comparison does not ignore components in
actual admission, change the cache, or justify discarding a component on its
own: inputs that have never varied provide no evidence. The report includes
diagnostics and output metadata in the result identity. The audit deliberately
uses a read-only offline index rather than adding an expensive enumeration
endpoint to the scheduler's compilation listener.

### Provisioning original Rust distribution packages

An exclusive offline store can be preseeded with original Rust installer v3
archives without running their install scripts or constructing toolchain tarballs:

```sh
sccache-dist native-import-rust --store /path/to/scheduler-store \
  --archive rustc-nightly-x86_64-unknown-linux-gnu.tar.xz \
  --sha256 CHECKSUM_FROM_RELEASE_MANIFEST --size COMPRESSED_BYTE_LENGTH \
  --compression xz
```

The upstream SHA-256 and codec identify the original archive; its compressed
length is checked separately. Component manifests
select installed paths; the command emits the verified package and normalized
installation tree IDs as JSON. The component trees reuse the original file
blobs, and can be placed as layers in a root recipe. Repeating the command
without `--archive` uses an already indexed original package. The offline command requires exclusive access to the store. Both offline and
online provisioning use a verified-package lease through component projection.
Preseeded content is also available to ordinary mapped-tree upload negotiation. A release name alone does not attest an installed local sysroot;
regular compiler discovery still hashes its observed installed contents.


### Live original-package provisioning

Enable original-package imports explicitly in the scheduler configuration.
Limits here are owned by the scheduler, not supplied by build clients:

```toml
[native_cache.package_import]
retain_original = true
max_concurrent_imports = 2
max_archive_bytes = 1073741824
max_entries = 100000
max_expanded_bytes = 8589934592
max_tar_bytes = 9663676416
max_metadata_bytes = 67108864
decoder_memory_bytes = 536870912
decoder_timeout_secs = 600
```

With a client configuration specifying the native cache endpoint and
token authentication, provision the same archive while the scheduler runs:

```sh
sccache-dist native-provision-rust --client-config /path/to/client.toml \
  --archive rustc-nightly-x86_64-unknown-linux-gnu.tar.xz \
  --sha256 CHECKSUM_FROM_RELEASE_MANIFEST --size COMPRESSED_BYTE_LENGTH \
  --compression xz --manifest-output rustc.manifest
```

The CLI first performs an authenticated lookup by upstream SHA-256 and codec, without an upstream length query.
On a hit it needs no archive; on a miss it streams the original bytes.
The owner verifies the compressed size and SHA-256 before decoding.
Per-package import reservations share global upload admission. The explicit
concurrency limit bounds simultaneous archive imports and decoder processes. Compressed input,
expanded file contents, decoded tar bytes (including padding), member count,
and path metadata are bounded separately. A memory-limited subprocess
decodes packages with a wall-clock deadline, streaming length-delimited
entries and raw file bytes into the owner. No generated toolchain archive or complete decoded tar is persisted.
With `retain_original` enabled, the verified upstream archive is preserved
as a separate content-addressed transport blob in addition to its decoded
files. The archive reference shares the lifecycle of the package root and
is accounted for and reclaimed by ordinary reference-aware eviction.
The same content, component and package identities are used whether
imported offline or live.

The decoder subprocess is a resource-isolation boundary, not a separate
security principal. Use the authenticated native listener and a trusted
release checksum. The decoder deadline starts after compressed-input
verification; transport timeouts are controlled by the client and the
HTTP transport.

### Generic system and tool archives

The scheduler can also retain verified original tar archives without Rust
installer component metadata. For example, after verifying a distro package
against the package manager's trusted release checksum or signature:

```sh
sccache-dist native-provision-package --client-config /path/to/client.toml \
  --sha256 "$trusted_sha256" --size "$archive_size" --compression zstd \
  --archive /path/to/gcc-<version>-<arch>.pkg.tar.zst
```

The command outputs the original source identity, normalized archive tree
ID, and whether it reused an existing entry. Omit the archive for a warm
lookup with the same checksum, codec and length. Tar, gzip, XZ and Zstandard
share the same bounded decoder and archive index. Zstandard accepts
concatenated frames and has a 128 MiB maximum decompression window, in
addition to the service decoder's address-space and time limits. The
generic archive metadata is transport provenance, not a declaration of an
installed root. No package scripts execute. Exact discovered compiler files
and their installed metadata still determine the build semantics; matching
content IDs can be covered wherever those files are mounted. Archive
members must satisfy the build tree representation (regular files,
directories and links; no set-ID modes or device nodes).

### Installed system package discovery (pacman)

Provision releases from the files actually selected by a compiler or
toolchain closure, using the package manager's installed ownership and
synchronized repository SHA-256 metadata:

```sh
sccache-dist native-sync-system --client-config /path/to/client.toml \
  --path /usr/bin/gcc --path /usr/bin/as --path /usr/include/stdio.h \
  --jobs 2
```

For each distinct owner, the command checks its installed version against
the selected repository release and reads the release's SHA-256, repository
name and original archive filename. It reuses existing verified packages,
imports exact cached originals from /var/cache/pacman/pkg when present,
otherwise requests direct acquisition from a named upstream. Repository
names must match the configured scheduler prefixes. A custom cache path
can be provided with `--cache-dir`. It reports unowned paths and release
version mismatches explicitly rather than fabricating package provenance.
This does not replace the compiler's actual source discovery or hash
validation: locally modified files remain distinct semantic inputs. The
command is opt-in and is intended for provisioning the toolchain closure,
not automatically importing the entire installed operating system.

### Compressed original delivery to workers

Enable original-package reconstruction on workers with explicit decoder
and transfer limits. For example:

```toml
[native_worker.package_import]
retain_original = false
max_concurrent_imports = 2
max_archive_bytes = 1073741824
max_entries = 100000
max_expanded_bytes = 8589934592
max_tar_bytes = 9663676416
max_metadata_bytes = 67108864
decoder_memory_bytes = 536870912
decoder_timeout_secs = 600
```

The optional worker `[native_worker.package_transfer]` table controls
the initial transfer-cost estimate. The default models a 128 MiB/s raw
download path, a 2 ms raw-blob request overhead and four parallel raw
downloads per worker, full-package Zstandard expansion at 64 MiB/s, XZ at
24 MiB/s, Gzip at 128 MiB/s and uncompressed tar at 512 MiB/s,
plus 20 microseconds per archive entry and 75 ms of fixed work.
These are **starting estimates, not measured universal rates**. The worker
smooths raw download+staging throughput, small-file request overhead,
and successful full-package reconstruction throughput across jobs to adjust its future choices. Large verified transfers update throughput, while small-file samples update
request overhead. Original archive throughput is tracked separately from
logical blob goodput; actual archive transfer time is subtracted from its
measured reconstruction time before updating the codec's decode rate. Override initial values for the network and hardware:

```toml
[native_worker.package_transfer]
download_bytes_per_second = 20971520
archive_download_bytes_per_second = 20971520
raw_request_nanoseconds = 2000000
raw_parallelism = 4
decode_tar_bytes_per_second = 536870912
decode_gzip_bytes_per_second = 134217728
decode_xz_bytes_per_second = 25165824
decode_zstd_bytes_per_second = 67108864
per_entry_nanoseconds = 20000
startup_nanoseconds = 75000000
```

When a worker needs new content, the scheduler consults a reverse index
from missing content IDs to retained original packages. It greedily selects
up to eight originals only when the worker's estimated download-time
saving exceeds the cost of decoding *every* file in that archive,
indexing its entries and starting the decoder. Fast connections can
therefore use direct file delivery even when an archive is smaller. Previously selected overlapping
content is counted only once. Each selected package remains pinned by the
authorized tree-delivery session. The worker verifies the original SHA-256
and size before isolated decoding, verifies the reconstructed package tree,
and renegotiates the exact missing content. Files not present in the
original (custom, generated, modified or host libraries) still follow the
ordinary verified blob protocol. Failed archive reconstruction falls
back to verified raw content. Independent selected originals download and decode concurrently, bounded by
`max_concurrent_imports`. Concurrent worker jobs share per-package
import reservations and the same global import limit. The worker retains decoded content but discards
the compressed input after import, so subsequent builds can use any of
its files without another download.

This is a transport optimization: package provenance, codec, and whether
the original was retained do not alter the composed filesystem or action
identity. A full original may contain more files than a specific build
uses. Enable retained originals only for packages intended to be shared
with all workers on this authenticated private fleet. Retention adds the
compressed original's physical storage expense on the scheduler; it
is optional and governs new ingestion. Recreate earlier draft stores
because the package index layout has changed.

### Direct upstream acquisition

To let the scheduler acquire original archives without client uploads, configure
named repositories with their allowed URL prefix and request deadline:

```toml
[native_cache.package_upstreams.rust]
origin = "https://static.rust-lang.org/"
timeout_secs = 180

[native_cache.package_upstreams.distro]
origin = "https://mirror.example.org/repository/"
timeout_secs = 180
```

Generic archives use a named repository and a relative path from trusted
package metadata (the mirror above is illustrative):

```sh
sccache-dist native-provision-package --client-config /path/to/client.toml \
  --sha256 "$trusted_sha256" --compression zstd \
  --upstream distro --path "core/gcc-<version>-<arch>.pkg.tar.zst"
```

An optional --size provides an exact compressed-length expectation. The
server resolves independently validated path segments beneath the configured
prefix, disables redirects, and does not forward client authorization upstream. Concurrent acquisitions of the same checksum and codec share one reservation;
independent packages may progress within configured concurrency limits. Warm
lookups do not wait for unrelated downloads. Clients retry busy replies
within their configured request deadline.
The scheduler streams compressed content into staging, enforces its archive
byte limit even without Content-Length, verifies the release SHA-256, and
decodes into the existing CAS. Verified hits do not contact the origin.

### Automatic Rustup provisioning

Rustup uses the repository named rust and paths beneath dist/. On each
Rustup installation host, run:

```sh
sccache-dist native-sync-rust --root /path/to/installed/sysroot \
  --client-config /path/to/client.toml \
  --output /path/to/installation.catalog \
  --recipe-output /path/to/installation.recipe --jobs 2
```

This reads the installed Rustup component inventory and channel manifest
(v1 config, v2 release metadata), not a guessed toolchain version. By default
it selects every installed component with declared bin/lib payload, matching
the current compiler toolchain discovery scope; installed cross-target
standard libraries and target-independent components are included. Use
`--full` to include documentation and other non-build components. Component
names and target variants are resolved against the original installer
metadata. Conflicting component trees or changed installation inventory
abort publication.

The portable recipe contains exact package provenance and selected
component trees, validates composition, and can be used for offline
reattestation:

```sh
sccache-dist native-attest-installation --root /path/to/installed/sysroot \
  --recipe /path/to/installation.recipe --output /path/to/installation.catalog
```

On the same kernel boot, reattestation reuses a previous matching catalog
entry only when the expected upstream digest and the currently opened
file's version agree; stale records are rehashed. The catalog and recipe
are each written atomically. These files can be retained across compiler
processes, but the recipe does not pin the scheduler's contents indefinitely.
The normal compiler still discovers and hashes the actual local input
closure, including custom and modified tools; the catalog avoids repeated
reads, and package content eliminates duplicate uploads.

The draft native package index and portable installation manifest have
changed format to store the verified archive length separately from the
upstream identity. Recreate earlier experimental native stores; there is
no production-store migration or compatibility path.

### Verified installation catalogs

Export portable component metadata while importing a verified archive:

```sh
sccache-dist native-import-rust --store /path/to/scheduler-store \
  --archive rustc-nightly-x86_64-unknown-linux-gnu.tar.xz \
  --sha256 CHECKSUM_FROM_RELEASE_MANIFEST --size COMPRESSED_BYTE_LENGTH \
  --compression xz --manifest-output rustc.manifest
```

On the installation host, verify the manifests against its actual local
sysroot, including all needed installed components:

```sh
sccache-dist native-attest-installation --root /path/to/installed/sysroot \
  --manifest rustc.manifest --manifest rust-std.manifest \
  --manifest rustfmt.manifest --output /path/to/installation.catalog
```

Configure the local client (or the direct-mode daemon) with the catalog:

```toml
[dist]
native_installation_catalogs = ["/path/to/installation.catalog"]
```

The namespace caller reads its own catalog, not a daemon-side substitute.
Only files whose bytes verified against the expected BLAKE3 digest and whose
current stat version matches the attestation reuse that digest. The catalog
is scoped to the current Linux boot; reattest after reboot or installation
changes. Missing, stale, changed and uncovered files use ordinary content
hashing. Treat the catalog as trusted local installation metadata and store
it with the same ownership and write controls as the installation. The
command publishes it atomically. The compiler still discovers exact
libraries, executable paths, symlinks, target files and host dependencies.
No action identity or sandbox tree identity changes solely because a catalog
is present. Preseeding the scheduler with original package bytes lets the
same content-addressed tree negotiation avoid uploads of already-known
files. The catalog alone does not place a package in the scheduler.

### Worker execution and protected artifact residency

The worker uses a bounded FIFO ready queue shared by native and legacy
execution, with compiler slots derived from available logical CPUs. Native
inputs are staged and leased before acquiring a compiler slot; publication
does not consume a compiler slot. Already cached input trees and partial resident blobs are pinned when
the assignment is accepted, and released on completion or reconciliation.
Heartbeats use actual occupied execution slots for CPU restoration, separately
from active HTTP requests that maintain job liveness. The scheduler includes
the input blobs of outstanding assignments in the transfer backlog before
those transfers complete (counting shared content once).
Concurrent acquisitions of an identical missing tree share one transfer and
its verified lease. If the producer fails or is cancelled, a waiting consumer
may retry using its own authorized action; other consumers remain independent.

Newly generated native outputs are also retained in the same worker CAS
with a default 300-second grace lease. The optional native worker settings
`artifact_grace_secs` and `artifact_grace_bytes` control the lease lifetime
and a separate logical byte budget. The default budget is the larger of twice
the maximum result size and 25% of the worker resident budget, capped by that resident
budget. Shared output content is charged only once. Expiry releases the
lease, not the content itself; ordinary eviction can then reclaim it.
Before staging a build, the worker reserves its configured maximum result size
in both the grace and CAS staging budgets. A full grace tier delays admission
without consuming compiler slots, up to the execution timeout. Insufficient
CAS headroom rejects the build before staging. Output publication converts
reserved bytes directly into verified staged content and then actual unique
resident bytes; no second capacity charge or silent retention bypass occurs.
Failed or cancelled jobs release reservations. Grace expiry never releases
independent consumer leases. The maximum-result bound is deliberately
conservative until output sizes can be predicted with a reliable upper bound.

### Measured worker placement

The worker sends its latest exponentially smoothed transfer and execution
estimates in each heartbeat. Large raw downloads measure effective logical
bytes per second including verification/staging and negotiated decompression;
small requests estimate setup latency. Original archives measure transfer
separately from their subsequent package decoder. Successful sandbox
executions update the occupied-slot duration without including queue waits or
input transfers. These estimates are checkpointed atomically to
`worker-timing.json` under the worker CAS directory when changed, at most once
per minute. Restart uses a validated checkpoint no older than 24 hours, scoped
to the cache endpoint and platform; a new route starts from configuration.

For each candidate the scheduler estimates raw transfer duration from unique
missing bytes and batches of missing requests, adds the outstanding transfer
backlog (also deduplicated), and overlaps that with estimated compiler queue
wait. A fully resident job need not wait for unrelated transfers. A native
job goes to the eligible worker with the lowest estimated completion time.
Legacy archive admission retains its existing capacity-weighted selection.
The residency summary and timing estimates are advisory; neither changes
content identity or bypasses verification. The model currently uses raw
delivery cost for placement (package reconstruction is optimized separately)
and one average slot duration per worker, not per-action compute forecasts.

### Directional shared-network estimation

The native cache listener meters encoded HTTP payload bytes before delivery
to the transport or after reception from it; logical lengths are tracked
separately. Authenticated worker addresses, client source IPs, and upstream
package traffic have separate counters in each direction. A dedicated
250 ms sampler aggregates overlapping streams without a global lock in
the body read path. Long observations include transport backpressure and
may also reflect endpoint processing or storage limitations: these are
effective service-rate estimates, not physical interface line rates.

Sustained per-peer observations provide lower bounds on available bandwidth.
A group becomes a shared effective constraint after at least three aligned
windows in which all members remain active, every member runs below its
previous sustained rate, and the group total remains near a plateau.
Unsaturated or nonoverlapping windows do not establish a ceiling. A higher
subsequent observed group total invalidates the constraint. Peer and group
evidence expires after 30 minutes; the scheduler atomically checkpoints
fresh measurements to `network-timing.json` each minute, scoped to the native
listener address. Active requests and their remaining bytes are not restored
after restart.

Native placement converts predicted missing logical bytes to encoded demand
using measured per-peer compression ratios and uses sustained aggregate
goodput in addition to the worker's per-request estimates. Outstanding
worker input closures are deduplicated before estimating demand; currently
active client downloads participate in the same model. Progressive max-min
sharing allocates bandwidth across overlapping shared-resource constraints
and reallocates capacity when a peer finishes. Placement includes the
marginal completion delay imposed on other peers, not only the selected job's
estimated finish time.

Workers learn expected missing result-upload bytes, request counts, upload
throughput and request overhead from successful publications. These estimates
join the existing worker timing checkpoint and heartbeat. Placement advances
current incoming traffic to predicted compiler completion before adding the
new upload demand. Send and receive constraints are independent. The
forecast does not yet predict the arrival of other not-yet-produced results.

### Workload-only network calibration

There is no synthetic probe protocol, speculative probe payload, idle poll,
or calibration-only download. All observations come from authenticated
ordinary CAS traffic. Aligned directional body samples are taken every
250 ms. Per-peer isolated throughput is recorded separately from aggregate
effective goodput; three sustained concurrent windows are needed to infer
contention or demonstrate no observed contention at the measured rates.
Concurrent-only observations cannot establish isolated capacity. Successful
no-contention observations can also answer subset questions at the same or
lower measured rates. Higher isolated rates or conflicting shared-resource
observations invalidate the relevant evidence. Fresh isolated and concurrent
evidence persists in the normal network timing checkpoint.

The scheduler first predicts the normal fastest compatible placement. If
that placement naturally provides a useful unresolved overlap, it is used
unchanged. Otherwise it may choose another already admissible worker to
learn an unanswered directional concurrency relationship, subject to:

- The existing transfer and the new required transfer are predicted to
  overlap for at least 1.25 seconds. Every involved peer has a recent
  isolated baseline. Uploads are evaluated at predicted compiler completion.
- The alternative must require a subset of the baseline's additional input
  content IDs, no additional predicted encoded input bytes, and no larger
  estimated result upload. These are advisory estimates, not promises about
  future Bloom-filter misses or transfer outcomes.
- The alternative must have a predicted total completion time within both
  1% and 20 ms of the normal best placement. No job or transfer waits for an
  experiment, and known shared constraints still affect the ETA.
- An intentionally explored directional cohort has a one-minute cooldown;
  unanswered questions may be revisited later only if useful work offers an
  opportunity.

Workers also start the largest already-required missing blobs first within
a tree staging batch, retaining the existing bounded request concurrency
and content verification. This reduces straggler transfers and provides
longer useful measurement windows. No extra files are fetched for it.

The only learning action is a choice among real placements, or a reordering
of real input fetches. If there is no useful opportunity, the system simply
uses the fastest predicted placement. New jobs can always proceed normally.
