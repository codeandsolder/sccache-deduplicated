# Request latency traces

Request traces measure elapsed latency, not CPU utilization. A compile request
has a unique trace identity independent of its cache action key. The daemon
records monotonic phase transitions and jobserver/child intervals. Namespace
executors report their bounded history on completion as well as on heartbeats.
The native scheduler and worker propagate the same trace context across
assignment, staging, compiler queue, execution and publication.

## Configuration

Use the following settings in the client daemon, scheduler and standalone
worker TOML configuration files, substituting the actual host identity:

```toml
[traces]
endpoint = "http://100.73.74.69:10428/insert/opentelemetry/v1/traces"
instance = "cachyasus"
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
The exporter batches in a bounded nonblocking queue. During backend
unavailability trace data can be dropped, with explicit warning counts; builds
do not wait for export. Compiler arguments, environments and working directories
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
host/compiler/output/outcome. Select an individual request or paste its trace ID.
The timeline aligns spans by wall-clock start times and uses monotonic duration
measurements within each host. Cross-host clock disagreement can make spans
appear outside the root; the UI flags that instead of changing measurements.
Overlapping spans are not additive. The fleet table reports p50/p95/p99 and
cumulative elapsed time by phase, service, host and version. Active distributed
jobs come from the scheduler's live snapshot, not VictoriaTraces ingestion;
client-only active requests remain available via `sccache --show-active-compiles`.

## Rollout

The trace-aware request and assignment envelopes change distributed protocol
and namespace IPC versions. Upgrade the scheduler, workers and clients
together under the new release epoch. This is not a cache-key or storage-format
change. Do not mix the trace-aware binaries with the previous protocol.

The database can be installed before the coordinated rollout. No synthetic
benchmark records should be imported into production.
