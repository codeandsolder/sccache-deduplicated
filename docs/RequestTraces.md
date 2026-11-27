# Request latency traces

Request traces measure elapsed latency, not CPU utilization. A compile request
has a unique trace identity independent of its cache action key. The daemon
records monotonic phase transitions and jobserver/child intervals. Namespace
executors report their bounded history on completion as well as on heartbeats.
The native scheduler and worker propagate the same trace context across
assignment, staging, compiler queue, sandbox preparation, compiler process, output capture and publication. Coalesced waiters link to the current producer via OTLP span links. Result recovery without a compiler owner is reported as an unlinked wait.

## Configuration

Use the following settings in the client daemon, scheduler and standalone
worker TOML configuration files, substituting the actual host identity:

```toml
[traces]
endpoint = "http://100.73.74.69:10428/insert/opentelemetry/v1/traces"
instance = "cachyasus"
# Unique private directory for this daemon (not its CAS).
spool_directory = "/var/lib/sccache/trace-spool/client"
max_spool_bytes = 134217728 # 128 MiB
```

A worker colocated with the scheduler shares its exporter. Use the same
configuration or omit its traces table. To enable queries in the existing
scheduler dashboard, set its existing dashboard table's `traces_url`:

```toml
[dashboard]
traces_url = "http://127.0.0.1:10428"
```

Other dashboard settings remain as before. No additional HTTP collector is
required. The endpoint accepts OTLP protobuf, not arbitrary request logs.
The compiler path submits to a bounded, nonblocking memory queue (256
submissions, 16 MiB estimated allocation budget). A dedicated writer batches
for up to 100 ms and persists checksummed, immutable OTLP records with
atomic publication and fsync. A separate transport thread retries unavailable
or ambiguous delivery with exponential backoff from 250 ms to 30 s. A record
is removed only after successful delivery or explicit permanent rejection.
The spool has one owner and retains the original FIFO across restart. Up to
4096 records and the configured byte budget are retained; when full, new
submissions are dropped with warning counts rather than evicting accepted
records. A reduced budget prevents new writes until existing records drain.
There is no synchronous compiler-path disk or network I/O; abrupt process
termination can still lose the not-yet-persisted memory queue. Graceful client
shutdown waits up to five seconds for disk persistence, not remote delivery.

Set a distinct absolute private (0700) spool directory for each standalone
daemon, writable by its service account, outside cache eviction. A colocated
worker uses the scheduler's spool. On Unix both file and directory are synced;
filesystem policy must honor fsync for power-loss durability. Windows flushes
the record file before publication. No separate cache or additional collector
is used. Transport retries preserve exact protobuf bytes, including trace/span
IDs and the originating build revision. OTLP is at-least-once, so the dashboard
deduplicates before sorting, limits and phase aggregates. Permanent rejection
and partial acceptance are reported without retransmitting accepted spans. Compiler arguments, environments and working directories
are not exported. Compiler/output labels and action IDs are exported; restrict
the receiver and dashboard to the trusted fleet.

The deployment on Asus uses VictoriaTraces 0.13.0 with
`-retentionPeriod=7d -retention.maxDiskSpaceUsageBytes=5GiB
-storage.minFreeDiskSpaceBytes=1GiB -memory.allowedBytes=256MiB`.
Disk retention removes older daily partitions; the independent 10 GiB ZFS
dataset quota provides a hard upper bound. The service listens only on
loopback and the private Tailscale address.

## Dashboard

Open Traces for recent or slow completed requests, filtering by exact
host/revision/compiler/output/outcome. Select an individual request or paste its trace ID.
The timeline aligns spans by wall-clock start times and uses monotonic duration
measurements within each host. Cross-host clock disagreement can make spans
appear outside the root; the UI flags that instead of changing measurements.
Overlapping spans are not additive. The detail view shows the request's
exact source revision, action key and outcome. Ranked latency attribution
partitions each client request and each worker job independently from
explicit host-local phase spans. Repeated overlapping spans for the same
phase count once; conflicting phases are reported as ambiguous overlap;
unrecorded gaps and instrumenter omissions remain visible. Parallel
diagnostic intervals and other hosts are excluded from this accounting.
A producer link opens its separate trace. The browser regression exercises
live row identity, trace selection, producer navigation and revision search. The fleet table reports histogram-based estimates of p50/p95/p99 and
cumulative elapsed time by phase, service, host and exact source revision.
Searches freeze the requested time range and split it into disjoint windows
of at most 100,000 raw spans before replay deduplication. The dashboard merges
bucket counts across windows rather than averaging local percentiles.
Percentiles are conservative bucket upper bounds, clamped to the observed
minimum and maximum. Counts and cumulative elapsed time use deduplicated
observations. Queries are bounded to 128 nonempty windows, 512 count probes,
2,048 phase groups and 30 seconds; an exhausted budget reports an error
rather than publishing a partial aggregate. Request and aggregate failures
are reported separately. As ingestion is concurrent, a search is not a
transactional snapshot of the database.
The binary embeds the full Git SHA at build time (including commit-expanded
Git archives); dirty compilation inputs carry a `-dirty-<SHA256>` fingerprint, archives with
no provenance report `unknown`. Both binary `--version` and OTLP
`service.version` identify the executing build, independently of deployment
metadata. `sccache.package_version` retains the package version.
Publishers verify the embedded revision against the release SHA. Live native client requests and distributed jobs come from the scheduler, not
VictoriaTraces ingestion. Active clients send a compact snapshot every two
seconds through the existing authenticated native service. Snapshots expire
after ten seconds and empty reports clear prior observations. The reporter
selects at most 256 requests and the scheduler retains at most 128 reporters,
displaying up to 2048 longest requests while reporting the total. Non-native
clients can still inspect live requests locally via `sccache --active-compiles`.

## Rollout

The trace-aware request and assignment envelopes change distributed protocol
and namespace IPC versions. Upgrade the scheduler, workers and clients
together under the new release epoch. This is not a cache-key or storage-format
change. Do not mix the trace-aware binaries with the previous protocol.

The database can be installed before the coordinated rollout. No synthetic
benchmark records should be imported into production.
