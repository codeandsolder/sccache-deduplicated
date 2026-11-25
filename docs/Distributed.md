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
Build it with the vendored-openssl Cargo feature so the worker embeds
OpenSSL rather than depending on a particular host's libssl/libcrypto
SONAME. The immutable release validator rejects all external OpenSSL
dependencies and requires GLIBC no newer than 2.39; the release metadata
records openssl_linkage=vendored-static. The older published protocol-v2
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

## Distributed compression backend

Input transport uses the direct fallible zlib-rs-fast streaming API.
Toolchains use standard multi-member gzip with fixed-size members and the
fork's bounded parallel batch compressor. Decoders are created on the
consuming thread, and cached archives can be read in either single-member or
multi-member gzip form. No flate2 compatibility adapter is required. Compiler output is Zstandard, as described below.

For host-local builds use `contrib/codeandsolder/build-host-native`;
it compiles the client and worker specifically for the executing CPU.
Both builds use the pinned nightly Rust toolchain required by zlib-rs-fast's portable SIMD implementation. Published shared fleet bundles retain their portable x86-64-v2 ABI.

## Distributed output transport and cache storage

Protocol 3 / rollout epoch 4 sends each compiler output as a checksummed
Zstandard frame and its original byte length. The client supplies its cache
compression level in the run-job request. The frame is validated during
the single decompression needed to materialize the output file. The same
compressed bytes are inserted verbatim into the cache ZIP's stored entry,
rather than reading the output file and compressing it again. Local outputs
such as preprocessor dependency files still use ordinary cache compression.
If another output has overwritten or replaced a materialized file, only
that file is compressed again. Local and remote cache entries use the same
checksummed Zstandard encoder.
The cache entry format is unchanged, including support for reading already
stored Zstandard entries. The run-job endpoint is versioned separately to
reject the old wire format; upgrade clients and workers together.

## Overview

Distributed sccache consists of three parts:

 - the client, an sccache binary that wishes to perform a compilation on
   remote machines
 - the scheduler (`sccache-dist` binary), responsible for deciding where
   a compilation job should run
 - the server (`sccache-dist` binary), responsible for actually executing
   a build

All servers are required to be a 64-bit Linux or a FreeBSD install. Clients
may request compilation from Linux, Windows or macOS. Linux compilations will
attempt to automatically package the compiler in use, while Windows and macOS
users will need to specify a toolchain for cross-compilation ahead of time.

## Communication

The HTTP implementation of sccache has the following API, where all HTTP body content is encoded using [`bincode`](http://docs.rs/bincode):

 - scheduler
   - `POST /api/v1/scheduler/alloc_job`
      - Called by a client to submit a compilation request.
      - Returns information on where the job is allocated it should run.
   - `GET /api/v1/scheduler/server_certificate`
      - Called by a client to retrieve the (dynamically created) HTTPS
        certificate for a server, for use in communication with that server.
      - Returns a digest and PEM for the temporary server HTTPS certificate.
   - `POST /api/v4/scheduler/heartbeat_server`
      - Called (repeatedly) by servers to register as available for jobs.
      - Every five seconds, advertises fractional effective CPU capacity from
        host idle CPU time plus the worker's currently executing jobs (capped
        at the available CPU count). Admission counts assignments still
        requiring compiler capacity, including newly reserved jobs not yet
        visible in the heartbeat; native publication and terminal replies
        use separate bounded dispatcher capacity. Legacy selection weights
        healthy workers by remaining compiler capacity. Native selection
        predicts staging, execution and publication completion from the
        queue snapshot and measured transfer costs (see NativeCache.md).
      - Includes active legacy `run_job` IDs and native dispatcher phases. A `Started` job absent for a full
        heartbeat timeout is released, while long compilations remain
        assigned as long as the worker reports them running.
      - The response includes the scheduler's assigned-job IDs, including
        in-flight assignment reservations. Workers discard obsolete local
        Pending/Ready assignments while retaining jobs received after the
        heartbeat request started.
   - `POST /api/v1/scheduler/job_state`
      - Called by servers to inform the scheduler of the state of the job.
      - Repeated state updates are idempotent. A terminal completion may be
        acknowledged again for the same worker if the scheduler already
        completed that job, within its bounded acknowledgment retry window.
   - `GET /api/v1/scheduler/status`
      - Returns information about the scheduler, including total outstanding-job
        capacity and currently available admission slots. Capacity is computed
        per worker from its current advertised CPU count and the scheduler's
        `[job_slack]` configuration; a fully busy worker retains a minimum
        admission slot.
      - Protocol 4 / rollout epoch 5 adds these fields to the status wire format.
 - `server`
   - `POST /api/v1/distserver/assign_job`
      - Called by the scheduler to inform of a new job being assigned to this server.
      - Returns whether the toolchain is already on the server or needs submitting.
   - `POST /api/v1/distserver/submit_toolchain`
      - Called by the client to submit a toolchain.
   - `POST /api/v1/distserver/run_job`
      - Called by the client to run a job.
      - Returns the compilation stdout along with files created.

The heartbeat body uses a binary protocol shared by schedulers and workers.
Changes to the active-job inventory therefore require deploying compatible
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
will trust the registered server address and use it for builds.

#### JWT HS256 (preferred)

This method uses secret key to create a per-IP-and-port token for each server.
Acquiring a token will only allow participation as a server if the attacker can
additionally impersonate the IP and port the token was generated for.

You *must* keep the secret key safe.

*To use it*:

Create a scheduler key with `sccache-dist auth generate-jwt-hs256-key` (which will
use your OS random number generator) and put it in your scheduler config file as
follows:

```
server_auth = { type = "jwt_hs256", secret_key = "YOUR_KEY_HERE" }
```

Now generate a token for the server, giving the IP and port the scheduler and clients can
connect to the server on (address `192.168.1.10:10501` here):

```
sccache-dist auth generate-jwt-hs256-server-token \
    --secret-key YOUR_KEY_HERE \
    --server 192.168.1.10:10501
```

*or:*

```
sccache-dist auth generate-jwt-hs256-server-token \
    --config /path/to/scheduler-config.toml \
    --server 192.168.1.10:10501
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

Securing communication with the scheduler is the responsibility of the sccache cluster
administrator - it is recommended to put a webserver with a HTTPS certificate in front
of the scheduler and instruct clients to configure their `scheduler_url` with the
appropriate `https://` address. The scheduler will verify the server's IP in this
configuration by inspecting the `X-Real-IP` header's value, if present. The webserver
used in this case should be configured to set this header to the appropriate value.

Securing communication with the server is performed automatically - HTTPS certificates
are generated dynamically on server startup and communicated to the scheduler during
the heartbeat. If a client does not have the appropriate certificate for communicating
securely with a server (after receiving a job allocation from the scheduler), the
certificate will be requested from the scheduler.

## Configuration

Use the `--config` argument to pass the path to its configuration file to `sccache-dist`.


### scheduler.toml

```toml
# The socket address the scheduler will listen on. It's strongly recommended
# to listen on localhost and put a HTTPS server in front of it.
public_addr = "127.0.0.1:10600"

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

Upgrade all clients and the scheduler together for protocol 4, adding the
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


```toml
# This is where client toolchains will be stored.
cache_dir = "/tmp/toolchains"
# Optional Linux same-filesystem archive sources (the source cache's tc/).
# Archives are reflink-cloned and digest-verified before use; misses fall
# back to an ordinary upload. Never share writable cache directories.
# toolchain_archive_sources = ["/var/cache/sccache-client-dist/client/tc"]
# The maximum size of the toolchain cache, in bytes.
# If unspecified the default is 10GB.
#toolchain_cache_size = 10737418240
# A public IP address and port that clients will use to connect to this builder.
public_addr = "192.168.1.1:10501"
# The socket address the builder will listen on. Falls back to public_addr.
#bind_address = "0.0.0.0:10501"
# The URL used to connect to the scheduler (should use https, given an ideal
# setup of a HTTPS server in front of the scheduler)
scheduler_url = "https://192.168.1.1"

[builder]
type = "overlay"
# The directory under which a sandboxed filesystem will be created for builds.
build_dir = "/tmp/build"
# The path to the bubblewrap version 0.3.0+ `bwrap` binary.
bwrap_path = "/usr/bin/bwrap"
# Maximum retained extracted-toolchain logical bytes (default 8 GiB).
# Active builds may exceed the limit; idle extractions are reclaimed in
# LRU order, while compressed archives remain cached.
# extracted_toolchain_cache_size = 8589934592

[scheduler_auth]
type = "jwt_token"
# This will be generated by the `generate-jwt-hs256-server-token` command or
# provided by an administrator of the sccache cluster.
token = "my server's token"
```


#### [builder]

The `[builder]` section can be can be one of:
```toml
[builder]
type = "docker"

[builder]
type = "overlay"
# The directory under which a sandboxed filesystem will be created for builds.
build_dir = "/tmp/build"
# The path to the bubblewrap version 0.3.0+ `bwrap` binary.
bwrap_path = "/usr/bin/bwrap"
# Maximum retained extracted-toolchain logical bytes (default 8 GiB).
# Active builds may exceed the limit; idle extractions are reclaimed in
# LRU order, while compressed archives remain cached.
# extracted_toolchain_cache_size = 8589934592

[builder]
type = "pot"
# Pot filesystem root
#pot_fs_root = "/opt/pot"
# Reference pot cloned when creating containers
#clone_from = "sccache-template"
# Command to invoke when calling pot
#pot_cmd = "pot"
# Arguments passed to `pot clone` command
#pot_clone_args = ["-i", "lo0|127.0.0.2"]

```


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
alongside the corresponding scheduler release. Configure its absolute path:

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
Scheduler mutations wake the sampler, coalesced to at most ten projections
per second. The periodic two-second sample covers time-based state changes
and CAS/network observations and appends one history point (900 retained).
History resets with the scheduler. Reconnection and broadcast lag both
produce a fresh reset; revision gaps cannot be silently ignored.

The UI includes worker heartbeat age, capacity, errors, reservations and
native phases, job state, input backlog and assignment-time predictions,
CAS logical accounting, garbage collection and directional network estimates, including shared bottleneck and observed
concurrent-capacity groups. CAS/network samples have their own cadence and
are not recomputed in response to scheduler mutations.
All scheduler-owned reservations, including assignment RPCs in flight, are
available through a searchable, paginated table. Archive and native admission
headroom are shown separately; they share compiler capacity and must not be added.
No thousand-job truncation. Expired workers are excluded without
mutating scheduling state. Native compiler slots are not legacy allocations;
logical CAS bytes are not physical filesystem usage; measured transport
goodput is not physical link capacity.

### Fleet history

If configured, Liberta supplies the existing Grafana dashboard's 33 query
panels. Select an exact client or all clients and a range from 15 minutes
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
