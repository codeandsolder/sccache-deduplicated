# Available Configuration Options

## file

```toml
# If specified, wait this long for the server to start up.
server_startup_timeout_ms = 10000

# Base directories to strip from source paths during cache key
# computation.
#
# Similar to ccache's CCACHE_BASEDIR, but supports multiple paths.
#
# 'basedirs' enables cache hits across different absolute root
# paths when compiling the same source code, such as between
# parallel checkouts of the same project, Git worktrees, or different
# users in a shared environment.
# When multiple matching paths are provided, the longest prefix
# is used.
#
# Path matching is case-insensitive on Windows and case-sensitive on other OSes.
#
# Applies to the preprocessed source and to the compiler arguments
# alike, so that a flag naming the tree, such as
# -ffile-prefix-map=/home/user/project=., does not tie the cache
# entry to one checkout. In an argument only the places expected to
# spell a pathname are considered: the whole argument, the value of
# an =-separated option, and the value glued to a short option.
#
# Example:
#   basedir = ["/home/user/project"] results in the path prefix rewrite:
#   "/home/user/project/src/main.c" -> "src/main.c"
basedirs = ["/home/user/project"]
# basedirs = ["/home/user/project", "/home/user/workspace"]

[dist]
# where to find the scheduler
scheduler_url = "https://1.2.3.4:10600"

[dist.auth]
type = "token"
token = "secrettoken"

[dist.cluster]
directory = "/home/user/.local/state/sccache-cluster"
ca_certificate = "/etc/sccache/cluster-ca.pem"
scheduler_id = "<64-digit scheduler peer ID>"

[dist.native]
endpoint = "https://1.2.3.4:10502"
platform_contract = "site-defined-linux-execution-contract-v1"
request_timeout_secs = 120
build_timeout_secs = 600
renewal_interval_secs = 15
max_metadata_bytes = 67108864
max_result_bytes = 1073741824

```

The native scheduler and CAS endpoint are required for compilation. Legacy
`[cache]` tables, per-backend settings, direct preprocessor caching and local
fallback are not supported. The scheduler owns admission and result storage;
workers consume verified CAS trees and publish results under native action keys.
See [native CAS](NativeCache.md) for storage and worker configuration.

sccache looks for its configuration file at the path indicated by env variable `SCCACHE_CONF`.

If no such env variable is set, sccache looks at default locations as below:
- Linux: `~/.config/sccache/config`
- macOS: `~/Library/Application Support/Mozilla.sccache/config`
- Windows: `%APPDATA%\Mozilla\sccache\config\config`


## env

Whatever is set by a file based configuration, it is overruled by the env
configuration variables

Note that some env variables may need sccache server restart to take effect.

### misc

* `SCCACHE_ALLOW_CORE_DUMPS` to enable core dumps by the server
* `SCCACHE_CONF` configuration file path
* `SCCACHE_BASEDIRS` base directory (or directories) to strip from paths for cache key computation. This is similar to ccache's `CCACHE_BASEDIR` and enables cache hits across different absolute paths when compiling the same source code. Multiple directories can be separated by `;` on Windows hosts and by `:` on any other operating system. When multiple directories are specified, the longest matching prefix is used. Path matching is **case-insensitive** on Windows and **case-sensitive** on other operating systems. Environment variable takes precedence over file configuration. Only absolute paths are supported; relative paths will cause an error and prevent the server from start.
* `SCCACHE_CACHED_CONF`
* `SCCACHE_DIST_WORKER_NAME` stable distributed worker display name used by client statistics and telemetry. Workers default to their OS hostname. Named workers register this metadata through an additive scheduler side channel; legacy workers remain fully compatible and continue to appear by transport address until upgraded.
* `SCCACHE_MIN_JOBS` minimum local compiler jobserver capacity, default `12`. Higher detected CPU counts are preserved; `0` disables the floor. Restart an existing daemon to change its capacity. Set upstream Cargo build.jobs in the managed Cargo configuration to supply sufficient work; sccache cannot increase the number of requests submitted by an external build tool.
* `SCCACHE_IDLE_TIMEOUT` how long the local daemon process waits for more client requests before exiting, in seconds. Set to `0` to run sccache permanently
* `SCCACHE_STARTUP_NOTIFY` specify a path to a socket which will be used for server completion notification
* `SCCACHE_MAX_FRAME_LENGTH` how much data can be transferred between client and server
* `SCCACHE_NO_DAEMON` set to `1` to disable putting the server to the background
* `SCCACHE_CLIENT_SIDE` set to `1` to discover inputs in the client process and use the daemon as a gateway to the native scheduler (see [the architecture doc](Architecture.md#client-side-mode-sccache_client_side)). This mode is forbidden on a shared multi-UID daemon. Managed shared hosts use server-owned credential-isolated execution; their private executor alone uses the cache broker.
* `SCCACHE_CACHE_MULTIARCH` to disable caching of multi architecture builds.
* `SCCACHE_LOG_MILLIS` when set (to any value), enables millisecond precision timestamps in log output instead of the default second precision.
* `SCCACHE_ERROR_LOG` path to a file where sccache will log errors
* `SCCACHE_LOG` log level, accepting standard env_logger values, see [env_logger documentation](https://docs.rs/env_logger/latest/env_logger/#enabling-logging) for details

### Transparent compiler launchers

A wrapper that only executes a known compiler with the original arguments can be
declared explicitly in the daemon configuration. A compiler alias is an
administrator assertion about the wrapper's semantics, not a general shell
script parser. Use absolute executable paths and the BLAKE3 digest of the
wrapper file:

```toml
[compiler_aliases."/usr/local/libexec/compiler-wrap/cc"]
compiler = "/usr/bin/cc"
blake3 = "<64 hexadecimal digits from b3sum of the wrapper>"
```

The launcher is verified before compiler detection and cache key generation.
Editing the wrapper requires updating or removing its alias configuration.
Unlisted wrappers are not automatically unwrapped; Linux script compilers
cannot use automatic ELF toolchain packaging, and must be explicitly declared or provisioned as native inputs. Aliases cannot point to other configured aliases.
