# Distributed sccache

Background:

 - You should read about JSON Web Tokens - https://jwt.io/.
   - HS256 in short: you can sign a piece of (typically unencrypted)
     data with a key. Verification involves signing the data again
     with the same key and comparing the result. As a result, if you
     want two parties to verify each others messages, the key must be
     shared beforehand.
 - Secure token's referenced below should be generated with a CSPRNG
   (your OS random number generator should suffice).
   For example, on Linux this is accessible with: `openssl rand -hex 64`.
 - When relying on random number generators (for generating keys or
   tokens), be aware that a lack of entropy is possible in cloud or
   virtualized environments in some scenarios.

## Managed release native portability

The managed Linux x86-64-v2 release includes distributed worker TLS support.
BoringSSL is statically linked through btls-fast, independent of the host's
libssl/libcrypto SONAME. The immutable release validator rejects external
OpenSSL dependencies and requires GLIBC no newer than 2.39; the release
metadata records `tls_backend=boringssl-static`. The older published protocol-v2
canary e266a04e demonstrated why both checks matter: it passed GLIBC
verification but required OpenSSL 4 on an OpenSSL 3 worker host.

## Native CPU is the requesting host, not the worker

For a compilation with `native` CPU or tuning settings, the requesting
machine's **compiler-visible CPU profile** defines the output, even if the
distributed scheduler chooses a different worker. Do not substitute the
worker's CPU, and do not silently replace `native` with the oldest CPU in the
fleet. Build artifacts intended for multiple machines should use an explicit,
separately selected portable target, such as `x86-64-v2`.

Rust `-C target-cpu=native` is resolved by the initiating rustc into an
explicit baseline CPU and feature selection before dispatch, preserving masked
CPU features in virtual machines; `-Z tune-cpu=native` uses the initiating
host's tuning model. Native CPU identity also enters the Rust cache key.
Where native resolution is unproven, the compilation remains local.

For GCC and Clang, the initiating compiler's `-###` frontend expansion is
used to resolve the **complete final CPU target state**, including named CPU
options, ISA feature masks and tuning options interleaved with `native`.
The compiler-specific target flags are shipped explicitly in the distributed
compile command, without an unresolved `native`. The original local command
retains the user-provided options. The native-specific cache supplement hashes
the initiating compiler's **complete observed frontend invocation**, including
its compilation directory: debug information can depend on that path even
when the preprocessed source is identical. The driver probe uses the actual
source language (including C++/Objective-C++) and requesting working directory
to preserve frontend options and relative driver paths.
Clang's cc1 target-feature settings are forwarded after the normal options to
preserve precedence of explicit `-mno-*` flags; GCC receives its observed
`-m*` options and cache-size parameters. If the
compiler cannot resolve or expose its native frontend settings, sccache does
not distribute an unproven native request or store it in the cache.
The worker's own detection must never decide codegen for the initiator's
`native` request. Sandboxed `/proc/cpuinfo` spoofing is not used: CPUID
and other hardware probes would disagree.

For deliberate builds targeting another machine, use the explicit destination
CPU profile exporter in `tools/cpu-target-profile`; this is distinct from
the implicit `native` CPU at the compilation request's origin.

## Execution and communication

Distributed compilation uses the native scheduler-owned content store.
The Linux client declares immutable inputs and executable identity, the
scheduler selects a compatible Linux worker, and the worker executes the
declared task in a bubblewrap namespace. Code generation and linking are
separately scheduled and cacheable. There is no local compilation or
archive execution fallback.

See [NativeCache.md](NativeCache.md) for the action, storage, transport,
provisioning and placement contracts. The scheduler's control plane retains
worker route discovery, status, job state updates and native allocation.
Heartbeat protocol v5 advertises native execution capacity only. Deploy
scheduler and worker binaries together while the cluster is drained.

There are three axes of security in this setup:

1. Can the scheduler trust the servers?
2. Is the client permitted to submit and run jobs?
3. Can third parties see and/or modify traffic?

### Server Trust

If a server is malicious, they can return malicious compilation output to a user.
To protect against this, servers must be authenticated to the scheduler. You have three
means for doing this, and the scheduler and all servers must use the same mechanism.

Once a server has registered itself using the selected authentication, the scheduler
will trust the enrolled public-key identity and authenticate each candidate route before use.

#### JWT HS256 (preferred)

This method creates an enrollment token bound to the worker public-key identity.
The worker must prove possession of the corresponding private key during enrollment.

You *must* keep the secret key safe.

*To use it*:

Create a scheduler key with `sccache-dist auth generate-jwt-hs256-key` (which will
use your OS random number generator) and put it in your scheduler config file as
follows:

```
server_auth = { type = "jwt_hs256", secret_key = "YOUR_KEY_HERE" }
```

First initialize the persistent worker key on the worker, as its service account. Then generate an enrollment token for its reported public-key ID:

```
sccache-dist auth generate-jwt-hs256-server-token \
    --secret-key YOUR_KEY_HERE \
    --server "$WORKER_ID"
```

*or:*

```
sccache-dist auth generate-jwt-hs256-server-token \
    --config /path/to/scheduler-config.toml \
    --server "$WORKER_ID"
```

This will output a token (you can examine it with https://jwt.io if you're
curious) that you should add to your server config file as follows:

```
scheduler_auth = { type = "jwt_token", token = "YOUR_TOKEN_HERE" }
```

Done!

#### Token

This method simply shares a token between the scheduler and all servers. A token
leak from anywhere allows any attacker to participate as a server.

*To use it*:

Choose a 'secure token' you can share between your scheduler and all servers. The token must be a valid HTTP header value.

Put the following in your scheduler config file:

```
server_auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Put the following in your server config file:

```
scheduler_auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Done!

#### Insecure (bad idea)

*This route is not recommended*

This method uses a hardcoded token that effectively disables authentication and
provides no security at all.

*To use it*:

Put the following in your scheduler config file:

```
server_auth = { type = "DANGEROUSLY_INSECURE" }
```

Put the following in your server config file:

```
scheduler_auth = { type = "DANGEROUSLY_INSECURE" }
```

Done!

### Client Trust

If a client is malicious, they can cause a DoS of distributed sccache servers or
explore ways to escape the build sandbox. To protect against this, clients must
be authenticated.

Each client will use an authentication token for the initial job allocation request
to the scheduler. A successful allocation will return a job token that is used
to authorise requests to the appropriate server for that specific job.

This job token is a JWT HS256 token of the job id, signed with a server key.
The key for each server is randomly generated on server startup and given to
the scheduler during registration. This means that the server can verify users
without either a) adding client authentication to every server or b) needing
secret transfer between scheduler and server on every job allocation.

#### OAuth2

This is a group of similar methods for achieving the same thing - the client
retrieves a token from an OAuth2 service, and then submits it to the scheduler
which has a few different options for performing validation on that token.

*To use it*:

Put one of the following settings in your scheduler config file to determine how
the scheduler will validate tokens from the client:

```
# Use the known settings for Mozilla OAuth2 token validation
client_auth = { type = "mozilla" }

# Will forward the valid JWT token onto another URL in the `Bearer` header, with a
# success response indicating the token is valid. Optional `cache_secs` how long
# to cache successful authentication for.
client_auth = { type = "proxy_token", url = "...", cache_secs = 60 }
```

Additionally, each client should set up an OAuth2 configuration in the with one of
the following settings (as appropriate for your OAuth service):

```
# Use the known settings for Mozilla OAuth2 authentication
auth = { type = "mozilla" }

# Use the Authorization Code with PKCE flow. This requires a client id,
# an initial authorize URL (which may have parameters like 'audience' depending
# on your service) and the URL for retrieving a token after the browser flow.
auth = { type = "oauth2_code_grant_pkce", client_id = "...", auth_url = "...", token_url = "..." }

# Use the Implicit flow (typically not recommended due to security issues). This requires
# a client id and an authorize URL (which may have parameters like 'audience' depending
# on your service).
auth = { type = "oauth2_implicit", client_id = "...", auth_url = "..." }
```

The client should then run `sccache --dist-auth` and follow the instructions to retrieve
a token. This will be automatically cached locally for the token expiry period (manual
revalidation will be necessary after expiry).

#### Token

This method simply shares a token between the scheduler and all clients. A token
leak from anywhere allows any attacker to participate as a client.

*To use it*:

Choose a 'secure token' you can share between your scheduler and all clients. The token must be a valid HTTP header value.

Put the following in your scheduler config file:

```
client_auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Put the following in your client config file:

```
auth = { type = "token", token = "YOUR_TOKEN_HERE" }
```

Done!

#### Insecure (bad idea)

*This route is not recommended*

This method uses a hardcoded token that effectively disables authentication and
provides no security at all.

*To use it*:

Put the following in your scheduler config file:

```
client_auth = { type = "DANGEROUSLY_INSECURE" }
```

Remove any `auth =` setting under the `[dist]` heading in your client config file
(it will default to this insecure mode).

Done!

### Eavesdropping and Tampering Protection

If third parties can see traffic to the servers, source code can be leaked. If third
parties can modify traffic to and from the servers or the scheduler, they can cause
the client to receive malicious compiled objects.

Protocol 5 uses native mutual TLS for scheduler RPCs, worker RPCs and the
native cache. The scheduler acts as the local CA. Bootstrap tokens authorize
initial enrollment and recovery of expired leaves only; subsequent requests
authenticate the role-bound leaf. A still-valid persisted identity does not
require a bootstrap token. Existing clusters refuse to start without their
durable enrollment registry; restore it from a consistent backup rather than
creating an empty registry under an established CA.
Each peer's persistent P-256 public-key SHA-256 digest is its identity, not its
address or current leaf. Leaves renew with the same key, and TLS contexts reload
without stopping in-flight transfers. Job and exact-content capabilities still
authorize individual operations.

Initialize the scheduler directory as the scheduler service account:

```sh
sccache-dist cluster-init --directory /var/lib/sccache-cluster/scheduler
```

Distribute only its generated `ca.pem` and the printed scheduler peer ID using
an independently authenticated provisioning channel. Never distribute the CA
private key. Members use separate absolute identity directories and the
provisioned CA and scheduler ID. For key-bound worker JWT enrollment, create the
worker identity with `sccache-dist cluster-id --directory /var/lib/sccache-cluster/worker`
before generating the JWT.

The configured scheduler URL and worker public address are reliable fallback
endpoints. Workers advertise interface candidates in authenticated heartbeats.
Native CAS similarly advertises its listener interfaces. Candidates are
validated by mTLS and ranked by measured request latency; unreachable or stale
candidates fall back to the configured route. There is no mDNS dependency.
Explicit bind addresses restrict the listener; by default non-loopback workers
and native cache listeners bind the configured address family on all interfaces.

For offline administration, `sccache-dist cluster-revoke --directory /var/lib/sccache-cluster/scheduler --peer PEER_ID`
requires the scheduler to be stopped (exclusive registry lock). The scheduler
rejects revoked peers and distributes permanent revocations in heartbeats.
Workers reject new peer requests if their scheduler revocation snapshot becomes
stale, without interrupting authorized transfers already in progress.
`sccache-dist cluster-status --client-config /path/to/client.toml` provides
authenticated JSON status for token-configured clients.

Protocol 5 / rollout epoch 6 is incompatible with the previous transport; do
not mix binaries or use the old HTTP health endpoint. The managed fleet's
`fleet/prepare-host ROLE CA_PEM SCHEDULER_ID` stages the new trust configuration
before the coordinated cutover. The scheduler host requires a native bundle
built with `--scheduler-dashboard`, including the matching WASM/JS/CSS assets.
The held release timers resume only after all hosts have committed the cutover.

## Configuration

Use the `--config` argument to pass the path to its configuration file to `sccache-dist`.


### scheduler.toml

```toml
# The scheduler terminates TLS directly on this reliable endpoint.
public_addr = "127.0.0.1:10600"
cluster_directory = "/var/lib/sccache-cluster/scheduler"

# Optional maintenance admission gate. While this file exists, the scheduler
# keeps heartbeats and job-state updates working but refuses new allocations.
# Existing distributed jobs can therefore drain without being interrupted.
maintenance_drain_file = "/run/sccache-scheduler-maintenance-drain"

[job_slack]
static_jobs = 0
percent = 200.0

[client_auth]
type = "token"
token = "my client token"

[server_auth]
type = "jwt_hs256"
secret_key = "my secret key"
```


#### Admission policy

The `[job_slack]` section is required. For a worker advertising `C` CPUs,
the limit on outstanding assignments is `max(1, ceil(C)) + static_jobs + floor(C * percent / 100)`.
A worker advertising zero effective CPUs can still accept at least one job. The
example admits three assignments per advertised CPU, including assignments
waiting for toolchain transfer and assignment RPCs. It does not change the
worker's execution width. Negative or nonfinite percentages are rejected.

Status reports `max_jobs` (the sum of individual worker limits) and
`available_jobs` (the sum of each worker's remaining slots, or zero while
draining). When a worker reduces its advertised width, its existing jobs
are not cancelled. Consequently available slots need not equal the fleet
limit minus aggregate in-progress jobs.

Upgrade all clients and the scheduler together for protocol 5, adding the
required configuration before starting the new scheduler. Remove the former
scheduler slack environment variables; they no longer participate in admission.

#### Maintenance drain

If `maintenance_drain_file` is configured, creating that file makes the scheduler refuse new job allocations with the normal allocation-failure response while continuing to accept worker heartbeats and job-state transitions for already assigned jobs. Clients therefore fall back to local compilation while the existing distributed queue drains. Removing the file immediately restores allocations. The additive `GET /api/v1/scheduler/drain_status` endpoint returns `1` while draining and `0` otherwise; the scheduler status reports zero available admission slots while draining.

The drain file path must be absolute. The scheduler only checks for its existence; a privileged service manager or deployment tool should create and remove it.

#### [client_auth]

The `[client_auth]` section can be one of (sorted by authentication method):
```toml
# OAuth2
[client_auth]
type = "mozilla"

client_auth = { type = "proxy_token", url = "...", cache_secs = 60 }

# JWT
[client_auth]
type = "jwt_validate"
audience = "audience"
issuer = "issuer"
jwks_url = "..."

# Token
[client_auth]
type = "token"
token = "preshared token"

# None
[client_auth]
type = "DANGEROUSLY_INSECURE"
```


#### [server_auth]

The `[server_auth]` section can be can be one of:
```toml
[server_auth]
type = "jwt_hs256"
secret_key = "my secret key"

[server_auth]
type = "token"
token = "preshared token"

[server_auth]
type = "DANGEROUSLY_INSECURE"
```

### server.toml

Use the native worker configuration in [NativeCache.md](NativeCache.md#configuration),
with the cluster identity, public address, scheduler URL and scheduler
authentication specified here. The only supported builder is native.
Archive cache directories, archive sources and extracted-toolchain
cache settings are rejected.

#### [scheduler_auth]

The `[scheduler_auth]` section can be can be one of:
```toml
[scheduler_auth]
type = "jwt_token"
token = "my server's token"

[scheduler_auth]
type = "token"
token = "preshared token"

[scheduler_auth]
type = "DANGEROUSLY_INSECURE"
```


# Building the Distributed Server Binaries

Until these binaries [are included in releases](https://github.com/mozilla/sccache/issues/393) I've put together a Docker container that can be used to easily build a release binary:
```
docker run -ti --rm -v $PWD:/sccache luser/sccache-musl-build:0.1 /bin/bash -c "cd /sccache; cargo build --release --target x86_64-unknown-linux-musl --features=dist-server && strip target/x86_64-unknown-linux-musl/release/sccache-dist && cd target/x86_64-unknown-linux-musl/release/ && tar czf sccache-dist.tar.gz sccache-dist"
```

## Local scheduler status dashboard

The dashboard opens on Overview. The remaining tabs are Workers, Jobs, CAS,
Cache hits, Cache storage, Topology, Network and Fleet metrics. Only the active tab is rendered, with filters, pagination and topology selection
kept outside its view lifetime. Updates retain keyed table cells and fixed column
widths instead of rebuilding rows. The optional fleet metrics stream disconnects
when leaving its tabs, avoiding inactive query and rendering load. Native SSE
updates invalidate only their affected projections; job updates do not clone
history or cache telemetry. Overview tiles and keyed chart paths update in place.
Percentage charts retain a 0–100% baseline; series colors remain stable as
other series appear or disappear.

### Live network topology

The dashboard's **Topology** view projects authenticated scheduler, worker,
client, and observed upstream identities. Enrolled but idle or revoked
identities remain visible, while candidate routes, verified measured routes,
and active scheduler transfers have distinct evidence states. The selectable
host detail exposes all reported interface addresses, nominal wired capacity,
and total/external RX and TX rates. Directional path rows distinguish encoded
wire service from verified logical peer delivery. Several addresses belonging
to one authenticated member do not create several host nodes. Separate
client and worker identities on one physical machine are not merged without
evidence. The graph is a logical directed transport graph, not a physical
traceroute reconstruction.

Host and link upserts/removals share the native revisioned SSE stream with
workers and jobs; reconnect resets reconstruct the complete topology. The
WASM graph has deterministic keyed SVG nodes and edges, so traffic changes
do not recreate the layout. No browser polling or graph-specific HTTP endpoint
is used. The dashboard remains scheduler-local and read-only.

The optional `scheduler-dashboard` feature adds a read-only Axum listener
inside the scheduler process. The UI follows rust-web-fullstack: Leptos 0.8
SSR/WASM hydration, typed Rust server functions, scoped Stylance styles and
Server-Sent Events. Model-only workspace builds and ordinary worker builds
do not require the UI dependencies. The distributed wire protocol is unchanged.

Build the native scheduler and matching browser assets from the same revision:

```sh
rustup target add wasm32-unknown-unknown
# Linux x86-64: exact lockfile tool versions with upstream checksums.
scripts/install-scheduler-dashboard-tools.sh target/dashboard-tools
scripts/build-scheduler-dashboard.sh target/dashboard-tools/wasm-bindgen target/dashboard-tools/stylance
cargo build --locked --release --no-default-features --features scheduler-dashboard --bin sccache-dist
```

On other platforms install the versions of wasm-bindgen-cli and stylance-cli
specified by Cargo.lock and call the build script with their executable paths
(or put the matching tools on PATH). The generated package is under the Cargo
target directory at `scheduler-dashboard/pkg`; install the complete directory
alongside the corresponding scheduler release. The asset manifest and
content-derived generation identity are mandatory. The build requires
ripgrep, and replacing an existing generated directory requires GNU
coreutils with atomic `mv --exchange --no-copy` support. Initial publication
uses a same-directory atomic rename. The old directory is retained until
the complete new generation is ready.

The native executable and optimized WASM embed the same source identity
independently; generated JS and CSS carry that identity as well. The
packager verifies the actual staged binary and full asset set against the
source checkout. Validate an installed pair before activation:

```sh
sccache-dist verify-dashboard --assets /opt/sccache/dashboard/pkg
```

Add `--source /path/to/checkout` to validate the source inputs as well.
At startup the scheduler verifies and loads all assets into an immutable
in-memory generation, served under generation-scoped URLs. A filesystem
replacement cannot mix assets in a running scheduler. Configure its absolute path:

```toml
[dashboard]
bind_address = "127.0.0.1:10604"
assets = "/opt/sccache/dashboard/pkg"
# Optional Prometheus-compatible data source, e.g. Liberta:
# metrics_url = "http://127.0.0.1:8428"
# Exact Certifex virtual host for the ingress panels:
# metrics_ingress_host = "sccache.example.org"
```

The dashboard is read-only and loopback-only. Access it locally or through an
SSH port forward. Do not publish it through an unauthenticated reverse proxy.
A configured dashboard fails startup for missing assets, invalid addresses or
invalid metrics URLs. Builds without the feature reject dashboard configuration.

### Live scheduler data

The initial typed SSR snapshot hydrates once. `GET /api/events` then streams
a full reset followed by ordered deltas. Worker and job rows are keyed by
identity; unchanged rows are not retransmitted just to update their age.
Scheduler mutations wake the sampler while a native SSE client is connected,
coalesced to at most ten projections per second. Without viewers only the
two-second periodic sample runs. The dashboard never waits for the scheduler's
jobs, servers or recent-client locks; a contended intermediate observation is
skipped. A failed periodic scheduler observation leaves a gap in its activity
series but does not discard independently sampled CAS/admission telemetry.
History retains up to 900 samples and resets on scheduler restart or a
backward wall-clock step. Stale CAS counters retain their own last-successful
timestamp. Reconnection and broadcast lag both
produce a fresh reset; revision gaps cannot be silently ignored.

The UI includes worker heartbeat age, capacity, errors, reservations and
native phases, job state, input backlog and assignment-time predictions,
CAS logical accounting, garbage collection and directional network estimates, including shared bottleneck and observed
concurrent-capacity groups. CAS/network samples have their own cadence and
are not recomputed in response to scheduler mutations.
All scheduler-owned reservations, including assignment RPCs in flight, are
available through a searchable, paginated table. Native admission headroom is shown directly. CAS execution describes the
transport/execution protocol, not the compiler's target architecture. Native job rows include the executable basename,
Rust crate name or declared output basename, explicit target when present,
requester identity and total/remaining input bytes and blob counts. The Jobs
tab supports multi-term search, a phase filter, sorting by age, input backlog,
worker or phase, and a declared-input availability bar (not network transfer
progress). Unknown ages and backlog sizes are sorted after known values. The dashboard
does not retain full command lines, environment variables or authorization data.
No thousand-job truncation. Expired workers are excluded without
mutating scheduling state. logical CAS bytes are not physical filesystem usage; measured transport
goodput is not physical link capacity.

### Cache hit statistics

The Cache hits tab includes native scheduler admissions independently of the
fleet metrics backend. Counts are available since scheduler start and for
observed rolling one-, five- and fifteen-minute windows. One- and five-minute
native hit-rate histories are charted directly from the scheduler samples. The admission hit rate is
hits divided by hits plus reuse-mode compile admissions. Forced refreshes,
in-flight requests, missing-input responses, busy responses and errors are
reported separately rather than counted as cache misses. Admissions are not
completed compilations or guarantees of successful result delivery.
An idle denominator or unavailable window is displayed as unavailable.

Fleet metrics separately report completed client cache outcomes over the selected
range and rolling windows, broken down by client and compiler/language, plus
legacy tier operations, bypasses and errors. The two sources are not summed.
Counter increases account for restarts; absent samples remain absent.

### Fleet history

If configured, Liberta supplies the existing Grafana dashboard plus cache-tier analytics (50 query
panels total: 20 cache-result, 10 cache-storage and 20 fleet panels).
Only the selected category is queried and transmitted; the category is part
of the shared metrics-feed key. Select an exact client or all clients and a range from 15 minutes
to seven days. Requests use fixed server-side PromQL templates; user labels
are escaped as literal regular expressions. Linux host-wide panels include monitored Linux hosts rather than claiming all
are workers. Ingress panels require an explicit Certifex virtual host. Range-dependent resolution is 5–1800 seconds;
rates span at least five minutes.

`GET /api/metrics/events` has one shared producer for each selected view.
At most eight active distinct views and four concurrent queries globally
bound backend load. Inactive views stop querying. Normal queries refresh the trailing five minutes or four buckets, whichever
is longer; a full reconciliation runs every ten minutes or four buckets,
whichever is longer. Failed panels retain previous samples inside the range
and retry a full range at the next grid. Rolling changes and corrections are
delivered as point-level patches. Stat, time-series, distribution gauge and
version table presentation are preserved. Both streams expose errors and resynchronize
after connection loss. Native telemetry works independently of Liberta.
Liberta's existing retention and data producers are unchanged.

### Native service and CAS pressure

The dashboard reports ticket populations (including unobserved/contended tickets),
upload slots, manifest-cache usage and result-recovery queue occupancy. Session
telemetry never renews leases or takes service slots. A contended session or
resource is explicitly unavailable in that sample; observations do not wait
behind long-running I/O or trigger eviction. The CAS view shows physical free
space separately from logical resident bytes, staging reservations and both
physical and logical budget watermarks. Headroom estimates exclude prospective
reclamation and are advisory, not admission guarantees.

### Cache analytics

The scheduler and each native worker run a separate five-minute sampler.
The scheduler GUI reports the distribution of distinct live CAS blobs by size,
last root touch and cumulative root touches. Shared content is counted once in
storage; touches are attributed to each distinct referencing action or tree.
Publications are touches, so the curve is not a request-hit rate. Unknown
usage is distinct from zero. Cumulative reuse percentiles give bucket bounds
rather than pretending to know the ordering within a bucket.

Logical/reference, stored-file and allocated-block sizes are distinct.
Measured ratios use measured bytes only; allocated blocks do not establish
exclusive space consumption on ZFS (snapshots, clones and compression).
Eviction distributions use root reuse utility divided by independently
reclaimable bytes; pinned and shared content cannot be reclaimed by a single
root. The read-only scan is best effort for concurrent filesystem changes and
does not invoke eviction. Per-worker summaries accompany existing heartbeats;
do not sum replicated host content to infer cluster-wide uniqueness.

With direct metrics enabled, the client samples each legacy cache tier every
five minutes independently of compilation. Disk reports indexed serialized
objects and LRU modification times; persistent hit frequency is not available.
Managed S3 reports serialized object sizes, metadata age, decayed milli-hit heat,
and the age adjusted by eviction policy. One shared lease limits namespace
scans to a 30-minute cadence; a failed refresh retains the prior timestamped
report. Its two internal analytics metadata objects are excluded from pruning.
The fleet metrics UI exposes capacity for all clients, and bounded histogram
and percentile panels for the selected client. Shared remote tiers can repeat
across clients. Managed-heat percentiles are heat proxies, not observed hits.

### Portable release package

The CI release workflow additionally publishes
`sccache-scheduler-dashboard-linux-x86_64-v2.tar.gz` and its SHA-256 file.
The archive contains the dashboard-enabled scheduler executable, matching
`pkg/` assets, build revision/protocol metadata and internal SHA-256 checksums.
It is built from the same revision as the ordinary fleet binaries and subject
to the same native ABI checks. Worker/client bundles and the existing automatic
fleet updater continue to use the ordinary binaries; installing the separate
scheduler package and switching the scheduler service are explicit deployment
operations, not an automatic protocol rollout.
