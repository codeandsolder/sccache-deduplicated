# Native scheduler cache

The native runtime in `crates/build-runtime` is a separate explicit action
protocol. It does not reinterpret the archive compiler protocol's keys and
is not yet the default compiler frontend. Neither enabling the scheduler
listener nor enabling a worker changes ordinary archive assignments.

## Content identity and lookup contract

The native store uses a **BLAKE3-256 content identity** over the exact bytes of
each logical blob. This identity is independent of read chunk boundaries,
file paths, permissions, output names, execution actions and storage encoding.
Compression or decompression never changes the identity of the decoded bytes;
an original compressed package is a separate blob whose contents are its
compressed source bytes. Tree manifests carry content identities and file
metadata separately.

The scheduler indexes **semantic action keys to result identities**, and
result manifests then identify their output blobs. Identical bytes are stored
once even when independently produced by different actions or used in
multiple trees. Leases and reverse references prevent eviction while any
result or tree still needs the blob. Ingest computes the digest while staging
each new byte stream; receivers independently verify advertised digests and
lengths before publication, including across worker/client trust boundaries.

BLAKE3-256 is the existing identity format, not a configurable algorithm.
The considered XXH3-128 and GxHash-128 alternatives hash warm memory faster,
but bulk hash throughput is not the observed import bottleneck, and their use
would change the content-verification contract. GxHash's incremental API
also produces different identities for different write chunk boundaries.
Do not shrink or replace the stored hash without an explicit format
revision and measured end-to-end benefit.

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

Metadata-only source digest reuse is restricted to mature file versions:
rapid same-size rewrites can leave both ctime and mtime unchanged within one
filesystem clock tick (reproduced on Acer ZFS). Fresh files are hashed rather
than retained in the digest memo or installation attestation catalog. Original
package verification and tree capture still hash exact bytes. The catalog
identity is versioned so previously attested fresh files are never silently
trusted after this policy change.

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
and length (not a compilation job token), with its enrolled mTLS identity.
A short discovery window and bounded source-probe deadlines prevent a stale
hint or a busy peer service from indefinitely delaying the original client.
If no peer provides the bytes, the scheduler requests them from an active
submitting client; claims share the global upload budget. An origin that
cannot reopen its source can decline the demand, allowing another declared
source tree, live origin, or another peer lookup to satisfy the same flight.
Neither peer lookup nor backfill consumes a compiler slot. Peer transfers
leave one shared upload slot available for direct uploads when the configured
budget permits. Once the executor has pinned every input, it acknowledges
staging completion before waiting for CPU capacity. That releases unconsumed
origin claims and ends the origin's demand polling, including for long-running
compilations.

All incoming bytes are length- and digest-verified before publication.
Individual verified acquisitions survive failures of other blobs, use the
same deduplicated store, and remain pinned during staging. Interrupted or
truncated input downloads retry that blob under the existing deadline.
Indexed trees with missing payloads are repaired rather than requiring an
entirely new tree; pending-GC content remains usable until actually removed.
Prepared origins retain alternate verified file locators for identical bytes,
prefer immutable generated bytes, and can decline a particular source tree
idempotently. If all available origin locators are declined, the shared demand
periodically rechecks peer residency until the existing action deadline.
Interrupted origin uploads release the claim and are retried by polling;
namespace clients drain an interrupted blob frame before requesting another.
Only complete digest mismatches or overlong bodies reject the source locator
(HTTP 422); short streams and storage failures are retryable (HTTP 503).
A stale residency prediction therefore requires only acquisition of the
missing content, not a new assignment.

Successful results still publish to the scheduler CAS for verified delivery.
Evicting an action retains its exact authoritative result manifest in a
separate durable, FIFO-bounded receipt index (logical metadata budget equal
to the configured maximum metadata size). Receipts do not retain any payload
reference or prevent ordinary content eviction. The configured limit and
receipts survive restart, including offline eviction. Publication replaces
or removes the receipt atomically with the new action mapping; an explicit
refresh never recovers a previous result.

On reuse admission, a known receipt with absent payloads enters a bounded
recovery queue under the normal exclusive action permit. A dedicated
recovery worker reserves resident content and fetches only missing digest
and length pairs through the same authenticated peer-blob route, without
allocating a compiler job or blocking HTTP admission threads. Positive
residency hints are preferred, but result recovery can ask other live native
workers for an exact blob if the hint is stale. Every candidate is verified
before selection, and concurrent peer acquisitions share the same CAS
retention-root flight. Successfully recovered partial content survives
later source misses. The scheduler publishes the complete verified result
under the original action key and returns an ordinary cache hit, pinning
it briefly until delivery admission. Failed recovery releases the exclusive
permit and applies a bounded negative cooldown before attempting another
peer recovery; a fresh compilation is then admissible. Physically missing
indexed result content is also treated as a recoverable miss and can be
repaired without changing its logical accounting.

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

On ZFS workers, each immutable tree is materialized **once per cached
TreeId** as ordinary files backed by native CoW block clones and reused
through read-only Bubblewrap binds. ZFS owns compression and the compressed
ARC, without application-level FUSE decoding. Each action block-clones only
the directory subtrees that it can modify; cross-boundary hardlink groups
instead use a complete private CoW tree so POSIX inode identity and write
visibility remain correct. On non-ZFS workers, independently Zstd-compressed
CAS objects are exposed through a cached read-only FUSE view with separate
writable output scratch. Bubblewrap binds both types of immutable views
read-only except for declared output parents and private `/tmp`. The command and its output
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

Each worker owns one resident native runtime within its existing CAS instance.
Assignment, admission and execution share verified indexed tree leases;
warm input lookup does not reread the manifest or rescan its blobs while
the lease is alive. Assignment reserves only blobs not covered by complete
resident tree leases, avoiding redundant per-blob index and filesystem probes. Composed recipes memoize their verified identity and
retain constituent leases. A bounded LRU of 16 immutable filesystem views
preserves the filesystem backing across actions, while weak per-identity
memo entries do not independently pin storage. Eviction retires idle views
of the requested tree, including views composed from that tree. Concurrent
preparations of one identity share construction; unrelated identities do
not serialize filesystem work under a global cache mutex.

Each action still launches a fresh Bubblewrap namespace and allocates only
its required private writable scratch. There is no separate runtime cache,
Docker daemon, or mutable sandbox state shared between compiler jobs.
Linux pidfd readiness detects child exit immediately;
a bounded 50 ms interval is retained for lease renewal and cancellation
checks, not for detecting normal completion. Execution phase diagnostics
report preparation, child process wall time (including namespace startup),
and capture separately.

The platform contract is an administrator-supplied compatibility declaration,
not automatic hardware attestation. Equal contracts must imply compatible
observable hardware, kernel, sandbox and execution behavior; the compiler
frontend must only admit cacheable actions. Current time, randomness and
other nondeterministic process behavior are not automatically normalized.

## Configuration

The native scheduler, worker and compiler client are opt-in. All distributed
RPCs and the dedicated native cache listener use native mutual TLS with the
scheduler-owned cluster CA (see [Distributed.md](Distributed.md)). Bootstrap
authorization enrolls a persistent public-key identity. Job and exact-content
capabilities still scope operations. Configured reliable endpoints are retained
as fallbacks; authenticated alternate interface addresses are probed and
selected automatically.

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
max_concurrent_uploads = 64
max_total_uploads = 128
http_threads = 256
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
Legacy archive builders and their configuration fields have been removed.
Workers require Bubblewrap with `--json-status-fd` support. A launch or
namespace failure is a distinct infrastructure failure, with its bounded
diagnostic delivered to the caller; compiler exit failures remain ordinary
failed compilation results.

```toml
[builder]
type = "native"

[native_worker]
cache_url = "https://127.0.0.1:10502"
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
usage-aware eviction policy on scheduler and worker. The
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

On ZFS workers, the native CAS directory and execution scratch **must be
on the same ZFS dataset** for block cloning. The worker verifies this at
startup: a different dataset, including another ZFS dataset in the same pool,
does not support `FICLONE` and is rejected instead of silently copying
input content. Use dataset quotas plus store/scratch capacity policies to
control these shared resources. Non-ZFS workers retain the independent
Zstd-chunk CAS with a FUSE input view.

Generated CAS content is stored as ordinary plaintext files on ZFS, whose
native compression and compressed ARC manage data residency. Compressed
Zstd chunks are still used on the wire, with verified decoding at a ZFS
receiver. Original upstream package archives remain byte-for-byte.
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
A separate scratch *filesystem* is not appropriate for native ZFS cloning:
scratch must share the CAS dataset. Per-job scratch limits and fleet-level
capacity policy remain outstanding. The native store is not an additional
production sccache cache tier.

### Ordinary compiler client

On a supported Linux client built with the distributed-client feature,
select native mode in the normal sccache configuration:

```toml
[dist]
scheduler_url = "https://127.0.0.1:10500"

[dist.auth]
type = "token"
token = "<scheduler client token>"

[dist.cluster]
directory = "/home/user/.local/state/sccache-cluster"
ca_certificate = "/etc/sccache/cluster-ca.pem"
scheduler_id = "<64-digit scheduler peer ID>"

[dist.native]
endpoint = "https://127.0.0.1:10502"
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

### Sealed filesystem discovery replay

The runtime supports read-only discovery filesystems with separate metadata,
directory enumeration and content operations. Live discovery fetches content
only on the first read, through ordinary CAS verification and retention.
Directory listings record names, types and inode equivalence without hashing
the files they enumerate. The origin seals the complete observation set,
including negative results. Host device and inode numbers are canonicalized
to observable equivalence classes.

A sealed discovery bundle is an ordinary CAS tree containing the canonical
transcript and references to its unique read content blobs. An
`ExecutionSpec.discovery` declaration identifies this tree and its logical
mountpoints, contributes to the exact action fingerprint, and uses the
standard input admission and delivery protocol. Workers mount the admitted
bundle through FUSE inside Bubblewrap. Replay cannot query the origin.
An unobserved operation or incomplete replay prevents result publication,
even if the compiler ignored the filesystem error and exited successfully.

Live observation is a unique, refresh-only action. Its discovery declaration
contains logical roots and a nonce; it returns the reserved discovery tree
artifact, not a reusable compiler result. The assigned worker uses a
sequenced scheduler mailbox to request logical observations. Only the
originating authenticated client can respond. Content delivery is authorized
by a recorded file observation and uses the ordinary verified CAS tree
transfer. The scheduler verifies the origin seal and the resulting bundle
manifest before accepting publication. No origin credentials or physical
paths enter the compiler namespace.

Discovery mounts currently require disjoint, empty mountpoints in the
immutable root. Writable output and scratch regions remain separate.
The direct native client can service live discovery; namespace IPC, compiler
planner integration, and indexing previously sealed transcripts for refresh
are still under development. The ordinary compiler planner does not yet
request live bundles.

## Validation

The runtime crate has focused tests for identity, import, tree capture,
reference accounting, publication, session leases and isolated execution.
The native HTTP tests exercise actual wire transfers and a Bubblewrap
execution with a captured shell root and a separate mounted source tree.
The scheduler unit test checks platform matching and shared capacity.
A subprocess integration test uses real assembler dependency discovery, direct CAS transfer, the scheduler, HTTPS job status and a native-only Bubblewrap worker; it compares object bytes against local assembly and verifies cache reuse and failed-action handling.
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

### Native directory results

The execution declaration assigns every named output a kind: regular file,
complete directory tree, or generated-only tree. The output kind is part of
the action key and checked against the result manifest. Directory outputs
reuse the same portable tree metadata and content references as input trees;
the scheduler's normal result lease retains all referenced blobs. No result
archives or client-side persistent CAS are needed.

A generated-only output may occupy an existing logical input directory,
as required by Rust's codegen stage. The worker records the immutable
private view's input topology and inode metadata before execution, without
rehashing the already verified input blobs. After execution it verifies the
existing regular files are unchanged and the original input topology and
permissions are retained. Only newly generated entries and their required
parent directories are returned. A modification or deletion of an immutable
input, or a generated hardlink to an input inode, is rejected. Actions
intending to transform the input directory instead declare a complete tree.

Both worker capture and client delivery account for logical file bytes
independently of content deduplication. All staged directory contents are
validated and materialized before publication at a previously absent
destination. Rust linking is a dependent native action, not a local replay. Codegen's
result is retained by the scheduler and used as a recipe layer in the
link action. Its owned files can be consumed or replaced by the link
stage; all external inputs are still immutable. The worker constructs
the filesystem with Bubblewrap from verified CAS content. There is no
requirement that the worker has the same installed linker or libraries.
The final generated tree, rather than the intermediate codegen tree,
is delivered to the caller. Each stage has its own action key and
cache/worker statistics.

The compiler client requires a native scheduler; an unavailable worker,
unsupported compile or failed remote command returns an error. Only
explicit compiler information queries and input discovery are executed
in the caller namespace.

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
raw_parallelism = 64
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

The namespace executor reads its own catalog, not a daemon-side substitute.
The shared supervisor additionally retains a bounded metadata-only digest memo
across credential-isolated executors. The key is the authenticated UID, GID,
supplementary groups and mount/root identity plus the actual opened file's
mature version. The root daemon inspects descriptor metadata without reading
file content or opening a caller path. A miss is hashed under the caller's
credentials; publication revalidates the descriptor and version. A conflicting
digest disables reuse for that version. Public clients cannot use this private
memo channel.
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

The native dispatcher owns independent bounded staging, compiler and
publication pools. Compiler capacity is shared with legacy execution, derived
from available logical CPUs; a full ready queue waits with cancellation
rather than failing a build. All admitted jobs may progress through staging and publication independently;
waiting for a tree, storage or another producer consumes no extra admission
slot. Resource-specific transfer semaphores and store admission bound the actual work.
The optional native worker setting `max_inflight_jobs` (default four times
compiler width) bounds reservations across assignments, staging, ready jobs,
execution, publication and unacknowledged terminal responses.

Already cached input trees and partial resident blobs are pinned when the
assignment is accepted. Assignment protocol v5 enqueues the job immediately
and acknowledges it without waiting for staging, authorization or execution.
The staging pool verifies its immutable execution declaration against the
scheduler's delegated session before reporting Started or acquiring missing
inputs. This verification waits for the scheduler to finish allocation and
delegate the publisher; a rejected or cancelled allocation cannot start
compilation. The prepared job owns its verified input leases and lease renewal through
the ready queue and execution. Input pins are released after output capture,
before remote publication; captured descriptors and the lease remain owned
until completion or cancellation. Successful
and failed compiler outcomes leave the compiler pool before publication or
remote cleanup.

Native run protocol v5 returns short, idempotent, observational status replies
(queued, staging, ready, executing, awaiting publication or publishing).
Polling never initiates a job. A terminal result is replayable until the
client acknowledges it or the five-minute retention expires. The native
session retains the original allocation and exact declaration digest even
after successful or failed execution, so a lost schedule response can be
retried without assigning another job. The scheduler's verified result
remains authoritative if the worker's terminal reply is unavailable.
Heartbeats report active dispatched jobs separately from actual occupied
compiler slots. Reconciliation signals cancellation of abandoned active
jobs without prematurely releasing their reservation. The scheduler includes
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
Compilation does not reserve speculative result bytes. Output capture
reserves actual bytes in the managed CAS as they are captured, and can use
private temporary descriptors for authoritative scheduler delivery if optional
local retention cannot fit. A full grace tier declines new unique content
immediately; it never parks an input-staging or publication task until expiry.
Existing protected results keep their full grace period. Output delivery to the
scheduler remains mandatory and verified, and the worker only advertises a
grace deadline for content actually retained. Failed or cancelled jobs release
their temporary descriptors and staging reservations.

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

Heartbeat protocol v4 includes the dispatcher reservation limit, staging,
compiler and publication widths, occupied shared compiler slots, and a
bounded job-ID map of phase, phase age and remaining unverified input bytes
and blob count. Initial remaining counts come from the assignment's exact
partial-residency pin; verified raw batches and completed trees remove their blobs once,
even when trees overlap. Full input closures are known from scheduler
reservations and can override a stale Bloom inventory. Terminal responses
and scheduler reservations not yet observed both consume admission headroom,
but publication-only work is excluded from compiler admission. Legacy jobs
share compiler capacity without consuming the native reservation limit.

Placement forecasts separate staging, compiler and publication timelines.
Staging considers occupied staging slots, aggregate directional bandwidth,
unique future input availability and request overhead. Shared pending content
is charged once; consumers wait for its predicted availability. Verified
progress limits residual input work. Warm candidates bypass unrelated wire
work if a staging slot is available. Ready jobs use predicted compiler release
times, including elapsed service for already executing work. Publication-only
jobs and terminal replies do not occupy compiler slots; forecast publication
pool availability affects output-transfer start time. Candidate outputs then
use the existing directional shared-link simulation. Legacy archive selection
remains capacity-weighted, without charging its jobs to native publication.

All predictions are advisory; they never authorize bytes or change action
identity. The aggregate input-delivery timeline is approximate rather than
a per-stream packet simulation. Partial progress reports counts rather than
exact blob deltas. Placement uses raw delivery costs and mean worker service
times; package-specific placement and per-action output/compute estimates
remain separate improvements.

### Immediate producer-output residency

The native cache protocol v5 records recently published worker outputs without
waiting for the periodic residency heartbeat. After successful local CAS
publication, the worker knows its actual grace-lease deadline. The existing
authenticated result negotiation establishes a scheduler-local monotonic time
anchor before the response is sent. The worker measures the remaining local
grace time when that response arrives, and includes that duration in the
existing result commit request. Consequently the scheduler's predicted expiry
is conservative even without synchronized host clocks, and a long upload
does not extend the original grace lease. No additional transfer or RPC is
introduced.

Only a successfully committed, verified result for a currently assigned native
job contributes exact digest/length hints. Each worker incarnation has an
independent bounded index (8192 distinct blobs, at most 30 minutes of retained
hint lifetime). Shared output IDs retain the longest unexpired deadline;
repeated commits do not slide their expiry. Worker replacement discards all
previous hints. Expiration or metadata pressure merely removes a prediction,
not the worker's data. The real worker grace and consumer input leases govern
eviction.

Placement, pending input forecasting, transfer exploration and peer backfill
use the same exact recent-output evidence in addition to the Bloom inventory.
Exact retained outputs are preferred to probabilistic inventory matches when
choosing peer sources. Every transfer still uses the ordinary content
verification and assignment pinning mechanisms. As soon as a consumer's
manifest names a just-produced blob, the scheduler can exploit the producer's
retained copy; unknown future hashes still require explicit producer/output
dependencies from a build graph.


Verified acquisition and publication events also refresh a separate bounded
recent-input index (65,536 unique digests per worker, 20-second expiry).
The existing authenticated inputs_staged notification marks the active
reservation ready immediately, before the next heartbeat. Monotonic phase
lower bounds prevent delayed heartbeats from undoing verified staging or
publication transitions. Active verified closures are exact placement and
peer-source evidence. The input closure was pinned and verified for that action, but its leases
can be released after publication. These short-lived positive hints bridge
the 15-second Bloom refresh interval; they do not claim grace retention.
The real assignment pinning and exact content validation still apply.
Peer recovery prefers grace-retained outputs, then recently acquired inputs,
then Bloom matches. Worker replacement discards all residency evidence.

### Measured command-family costs and placement traces

Successful verified result commits carry the worker's measured compiler-slot
service time and the actual bytes, requests and elapsed time of its negotiated
output uploads. This does not require any extra RPC or synthetic transfer.
Only the first valid observation for the assigned job trains the scheduler.
The worker's overall timing estimate remains the cold-start prior.

Each worker address and platform maintains up to 4096 command-family records, expiring
after 24 hours without observations. Families are hashed from platform,
canonical executable, working directory and argument shape; Rust metadata and
extra-filename hashes and dependency artifact paths are normalized while
dependency names, features, target, crate name, emit mode and optimization
flags remain distinct. This is an advisory cost key, never a cache identity.
Samples are smoothed with a quarter-weight moving average; one through four
observations progressively replace the host-wide prior. The scheduler keeps at most 32 such histories and checkpoints them atomically
every 60 seconds when observations change, in action-costs.bin under its native
cache directory (16 MiB maximum). The checkpoint is scoped to the cache listener,
worker address and platform; expired samples and mismatched or invalid checkpoints
are discarded. Residency and reservations are not persisted in this history.

Unseen or sparsely observed command families can use measurements from other
workers with the same platform. Peer execution times are adjusted by the median
service-time ratio of at least two other common command families, each observed
at least twice on both workers. A calibrated peer prior receives three quarters
of the weight; uncalibrated peers receive only one quarter. Peer output traffic
provides a half-weight prior because negotiated uploads also depend on scheduler
CAS state. Local observations progressively replace these priors. The host-wide
mean is not treated as a hardware speed ratio.

Candidate estimates use the learned service duration and negotiated output
traffic. Each admitted native reservation carries its own predicted cost
through the staging, compiler and publication forecasts, rather than applying
a candidate's cost to unrelated queued work. Unseen commands use the host
prior. Upload size here means negotiated missing payload. Separately, the scheduler
records the peak verified unique logical result size for each fresh command
family across compatible workers. The assignment's peak estimate remains advisory, not a reservation or
admission gate. Actual captured bytes drive CAS admission and the optional
grace tier charges only the unique union of committed content. Existing grace
leases never expire early; new content that does not fit is delivered to the
scheduler without a grace claim. The persistent history format is version 6.

The opt-in `native_placement_replay` trace target logs JSON assignment records
with job ID, hashed command family, selected worker, all eligible workers'
predicted completion and contention-penalized scores, and healthy candidates.
Assignment records also include the selected worker's contemporaneous host-wide
prior. Verified completion records contain the predicted publication timestamp,
predicted client completion, scheduler assignment-to-commit elapsed time,
predicted cost, actual execution time, total result bytes and negotiated
upload measurements. The replay report compares publication against actual
publication, not against client completion, and uses stable worker public-key
identities. A successful remote receiver piggybacks a delivery receipt on its
existing result-lease close. The scheduler validates the original authenticated
requester, committed manifest bounds, and one receipt per allocation. It logs
elapsed scheduler-monotonic time from allocation start to receipt (including
allocation overhead, delivery and the close RPC), staging time, and unique
logical content bytes split by successful direct or scheduler source. The
selected unique result closure includes diagnostics; its difference from
received unique bytes measures local reuse, and its difference from the full
manifest measures omitted outputs. Source plans are restricted to the selected
closure in both direct and namespace clients. The allocation carries the selected output names,
and the receipt is validated against their exact committed unique closure.
The scheduler learns the selected and remotely delivered fractions of full
result size per authenticated receiver, command family, and selection.
Four observations replace the full-result prior; recent reuse estimates
expire after one hour and are checkpointed with the service history.
Only the client-side forecast is scaled; publication remains independent.
The overlap with missing scheduler content is estimated proportionally. Local
installation after the broker's Done frame is outside this measurement. The
replay separately evaluates end-to-end delivery forecasts using these receipts;
missing receipts are not interpreted as zero-duration delivery. Join by job ID within
the scheduler epoch. This supports evaluating prediction error and selection
behavior on genuine compilation workloads. Counterfactual worker timings
are forecasts, not measured speedups; a full causal trace replay requires
additional queue and residency state. Evaluate the matched actual observations
with:

```sh
cargo run --locked -p sccache-build --example placement_trace_report < placement-trace.jsonl
```

Assignment traces include the predicted input-ready and publication-slot
arrival times. Completion traces carry actual first authenticated input-staged
and result-negotiation arrival times relative to assignment. These scheduler
clock observations include control overhead, queueing and local CAS work;
result negotiation occurs after the worker has staged its result locally.
The phase error is a forecast residual, not a pure decoder or network rate.

Successful worker observations also report warm staging service (including
authorization, input pinning and staged notification, but only if every tree
was immediately resident) and local
publication setup (result verification, retention and negotiation, excluding
newly written local result blobs). The scheduler maintains independently expiring
worker-local quarter-weight EWMAs, persisted in action-cost checkpoint v3.
Every action pays the warm preparation baseline even if it adds no network
bytes. Publication setup consumes a publication slot and delays upload arrival
in the shared-link forecast, without consuming a compiler slot. These
observations are never transferred to different workers as machine-speed
priors. Native service protocol v5 carries the two optional samples.

Successful worker commits carry a coherent, revisioned timing snapshot
from the same tracker used by live transfer and package negotiation.
The scheduler adopts it immediately after verification; a delayed
heartbeat or out-of-order completion cannot overwrite a newer revision.
The worker's process nonce scopes the revision, and restored timing
checkpoints initialize the new incarnation at revision zero. All
successful observed compilers update the host prior immediately,
rather than leaving new command families shrunk toward the stale
initial one-second estimate until the next heartbeat. No separate
telemetry request or synthetic payload is required.

The JSON report includes unmatched counts, per-worker and overall timing
errors for completion, input readiness and result negotiation (signed bias, MAE, median and p90 absolute error, weighted absolute
percentage error), learned versus host-prior execution/upload prediction
errors and the predicted score gap to the best eligible candidate. Unmatched
assignments are not counted as compiler failures or as zero-duration jobs.

### Package-aware input staging forecasts

The scheduler queries the verified original-package reverse content index
once per admitted action. The bounded advisory catalog retains at most
256 candidates and 262,144 coverage references, plus the covered digest
memberships in the actual admitted input-tree order. It does not reserve or
transfer any originals. Excessively large or unavailable catalogs fall back
to the raw-blob forecast. Each queued assignment retains its catalog for
future staging forecasts.

Heartbeat protocol v4 advertises the worker's reconstruction limits.
Placement and real package negotiation share the same positive-savings
greedy archive selector. For each new input closure the forecast removes
resident and previously scheduled digests, chooses covering archives per
input tree, and counts uncovered raw payload only once. It never subtracts
raw transfers needed by an earlier tree merely because a later archive
contains the same content. Each selected archive contributes its full
compressed wire size and complete decoder/entry/startup service, even
when only a subset of its files is needed. Worker decoder parallelism
bounds the expansion service approximation. Partial progress without
exact remaining identities uses the raw remainder instead.

The shared-link model uses encoded raw bytes plus actual compressed archive
bytes, not uncompressed expansion bytes. Trace records distinguish
missing_input_union_bytes, input_wire_bytes and archive_bytes. All wire
transfers remain real workload demands; optional placement exploration
is skipped for archive-bearing forecasts until exact package-aware
extra-traffic proofs are available. Actual reconstruction still validates
limits, content and availability and may fall back to raw delivery.
Catalogs and forecasts are advisory; no change to content identity.

### Directional shared-network estimation

### Receiver-directed content transfer

The scheduler authorizes content delivery, but it does not need to relay all
payloads. Workers and clients negotiate bounded batches of exact digest/length
pairs against their live input-tree or committed-result lease. The scheduler
reports whether each blob is already present and advertises likely resident
workers, their current authenticated routes, and short-lived source capabilities
bound to the receiving principal and exact content. The same worker CAS
endpoint serves scheduler recovery, worker-to-worker inputs, and client result
delivery. Bloom-filter residency is advisory; an opened immutable descriptor
and successful content verification are what establish a usable source.

Worker heartbeats additionally carry up to 32 recent verified logical
peer-download service rates, keyed by source principal and actual endpoint
pair. Only a complete verified peer acquisition supplies this sample.
Scheduler forecasts intersect these measurements with source residency and
the exact remaining input union. Package reconstruction is forecast first,
then direct raw transfers and scheduler raw transfers are accounted separately;
scheduler shared-link contention does not automatically inflate direct
transfer time. Per-worker aggregate staging remains serialized in the
forecast; cross-worker direct-link contention is not yet inferred globally.

Placement also distinguishes learned full unique logical result size from
missing scheduler upload bytes. The authenticated client sends bounded fresh
receiver-side scheduler and peer delivery rates during allocation; this
telemetry is not forwarded to the worker or part of the action identity.
The forecast overlaps direct delivery and publication, accounts for already
resident scheduler output separately from missing output, and models
scheduler fallback using its measured shared-link capacity. Before an exact
result manifest exists, the full logical size is an advisory estimate
(independent of selective output materialization or local reuse). Histories
retain both sizes across scheduler restarts.

### Multi-interface measurement and route selection

The transport tests reachability using authenticated lightweight probes;
bandwidth exploration uses ordinary required CAS bodies, never a synthetic
bulk payload. On Linux each directly reachable destination can have several
source-bound transport candidates, with separate pooled connections per
source address and destination. Explicit on-link candidates bind both the
source address and interface; the unbound kernel-policy route remains the
fallback for routed, VPN, unavailable and unsupported paths. Advertisements
prioritize interface coverage before additional addresses; hot-plugged
interfaces enter bounded probing without waiting for a full route refresh.

Local RX/TX counters come from the complete interface, not just sccache.
Bulk body accounting distinguishes managed bytes from estimated external
traffic and tracks concurrent streams; completed real transfers are classified
as clean, busy or unknown using endpoint counter deltas and overlap
generations. Slow busy/unknown samples do not erase or indefinitely extend
a recent clean rate. Contemporaneous total load and active reservations
influence actual path costs. Only known physical full-duplex Ethernet links
supply nominal line capacity; wireless and virtual interfaces are not
assumed independent physical resources. Socket-local addresses are used for
receiver measurements where exposed by the transport; unbound uploads use
a prior actual upload source as an advisory hint, and a changed source
invalidates its classification.

Worker heartbeat and client allocation include bounded per-interface
total/external RX/TX service and address inventory. Verified peer downloads
also report encoded/logical size ratio. Placement caps measured wire rates
at available known Ethernet endpoint capacity, translates direct logical
service using its encoded ratio, and accounts for the combined wire
demand when concurrent scheduler publication and direct client delivery
share the worker's same known sender interface. Separate interface addresses
on one device are grouped. Distinct devices are not proof of independent
end-to-end paths; shared router, switch and Wi-Fi airtime constraints beyond
the endpoint are learned from synchronized real body windows at an
endpoint. A directed path is indexed by its local and remote IP pair plus
send/receive direction. The learner observes aligned local-monotonic windows,
requires isolated baselines for both paths and three consistent uncontaminated
overlap windows, and reports bounded effective aggregate service for that
exact pair. It expires evidence after ten minutes and invalidates a
contradicted ceiling. Local route scoring uses it only when the matching
competing flow is active; the scheduler includes learned sender-side
publication/direct result overlap even across different interfaces. The
observation is effective transport service, not a proof of physical topology.
Unbound outgoing uploads without a known actual source are not used for
overlap learning. No extra bulk traffic is generated. The scheduler's existing directional
meter also compares its aggregate body deltas by local interface against
independently aligned total interface counter deltas. Contaminated windows
cannot establish isolated service, shared ceilings or independence. Fresh
scheduler interface capacity and learned same-direction path constraints
are injected into the placement simulator for both active and predicted
candidate routes, including the requesting client. Both endpoints cap
scheduler-path service when known wired headroom is available.

The receiver compares authenticated route latency and directional effective
goodput, using the scheduler as the durable fallback for committed results.
An absent scheduler input can be obtained from a reachable worker without
requesting origin backfill or populating the scheduler solely to relay it.
Worker-side tree acquisition still verifies and pins all required content
before compilation. A failed peer attempt falls back to the ordinary scheduler
download/backfill path. Receivers stage and verify each attempted payload
before publishing it; partial, corrupt or expired peer responses cannot
contaminate a subsequent delivery. Loopback candidates are advertised only
when bound and authenticated just like all other routes.

Result publication retains the existing manifest and unique missing-content
negotiation: the producing worker only uploads blobs absent from the scheduler
CAS, then commits the durable result. Once the worker negotiates its validated
manifest, the client can stage requested blobs concurrently with the scheduler
upload, from the worker or already verified scheduler CAS files. Missing
scheduler fallback content waits for commit. No successful result is exposed
until the scheduler confirms the same complete manifest durably committed;
the namespace broker withholds its final Done frame until confirmation.
Cache hits can also use resident workers. Selective output materialization
is orthogonal to source selection; receivers request only selected content.

The native cache listener meters encoded HTTP payload bytes before delivery
to the transport or after reception from it; logical lengths are tracked
separately. Authenticated worker and client principals, their actual IP endpoint pairs,
and upstream package routes have separate counters in each direction. A dedicated
250 ms sampler aggregates overlapping streams without a global lock in
the body read path. Long observations include transport backpressure and
may also reflect endpoint processing or storage limitations: these are
effective service-rate estimates, not physical interface line rates.

Sustained per-path observations provide lower bounds on available bandwidth.
A group becomes a shared effective constraint after at least three aligned
windows in which all members remain active, every member runs below its
previous sustained rate, and the group total remains near a plateau.
Unsaturated or nonoverlapping windows do not establish a ceiling. A higher
subsequent observed group total invalidates the constraint. Peer and group
evidence expires after 30 minutes; the scheduler atomically checkpoints
fresh measurements to `network-path-timing.json` each minute, scoped to the native
listener address. Active requests and their remaining bytes are not restored
after restart. The directional capacity model attributes sustained
transfer observations to the actual scheduler/member IP endpoint pair (excluding
ephemeral ports), not just the member identity. Shared and independent capacity
cohorts therefore remain specific to the measured routes. Worker heartbeats
carry the current measured download/upload path and rate; existing demand on
other paths stays on those paths in forecasts. An unknown path is not assigned
a historical contention ceiling from a different route.

Native placement converts predicted missing logical bytes to encoded demand
using measured per-path compression ratios and uses sustained aggregate
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

### Build-scoped Cargo intermediate retention

On Linux, the managed Cargo launcher can use `sccache --cargo-final -- <cargo arguments>`.
It invokes stock rustup-selected Cargo, with a private per-invocation build directory
mounted through FUSE (requires access to `/dev/fuse` and `fusermount3`).
The Cargo target directory is unchanged; durable final outputs are installed normally.
`sccache --cargo-all -- <cargo arguments>` instead uses the regular Cargo build
directory and retains materialized intermediates.

The scheduler pins exact committed result manifests in a build-wide lease,
independent of individual compilation tickets. The launcher holds the lease
through the managed local daemon connection and its inherited scratch lock.
Only immutable content references and caller-scoped tokens are exposed to the
mount; the daemon retains remote credentials. A reference is installed on a
private staging inode only after the result is committed and retained.
The compiler's input manifest uses the same content ID as a materialized input,
so a resident artifact does not need to pass through the launcher or compiler
client. Locally executed build scripts, linkers, proc macros, and other readers
receive verified bytes on demand. Mutable operations detach from the immutable
content, preserving hardlinks and ordinary file metadata; truncation need not
read the old bytes. Multiple local reads share one verified private spool per
content identity. Spools and namespace data are temporary, not another cache.

An expired or unavailable lease fails the affected operation rather than
exposing an empty placeholder or inventing a new content identity. Scratch
reclamation respects inherited process ownership. The full Cargo graph and
cross-user/namespace acceptance tests must pass before promoting this mode
to the managed fleet.
