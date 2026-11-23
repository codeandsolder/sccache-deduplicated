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
exist, and a miss reports only the missing tree identities. The client
offers those constituent manifests and uploads missing blobs directly.
A successful miss admission pins every source tree in the action's root
recipe and independent mounts.
Workers compose the recipe directly in memory from the pinned package
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
missing blobs over a connection-owned bounded byte stream. The caller alone
discovers sources and installs outputs. The daemon verifies scheduler result
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
download path, full-package Zstandard expansion at 64 MiB/s, XZ at
24 MiB/s, Gzip at 128 MiB/s and uncompressed tar at 512 MiB/s,
plus 20 microseconds per archive entry and 75 ms of fixed work.
These are **starting estimates, not measured universal rates**. The worker
smooths real raw download+staging throughput and successful full-package
reconstruction throughput across jobs to adjust its future choices. Samples
below 1 MiB are ignored, and a package's predicted transfer time is
subtracted from its measured reconstruction time before updating the
codec's decode rate. Override initial values for the network and hardware:

```toml
[native_worker.package_transfer]
download_bytes_per_second = 20971520
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
