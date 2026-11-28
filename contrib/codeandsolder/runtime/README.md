# Resident managed build runtime

The runtime is an immutable local OCI image, shared by build sessions on a
host. There is no permanently running container, second sccache daemon or
compiler cache. Only one small container is launched for a whole build, not
for each compiler invocation. The host's existing shared daemon joins the
authenticated caller's mount and PID namespaces. Its native CAS, compiler
identity, worker scheduling and result delivery are unchanged.

Use one image per architecture, compiler/runtime version and selected
toolchain inventory. Build it on one trusted host and distribute the exact
image ID; independently building a floating distro tag or changing installed
Rustup components is not equivalent. The compiler key still binds the
actual runtime libraries, toolchain closure and input bytes, not a claimed
image label.

## Build and distribute

Install the intended complete Rustup toolchain on the image-building host
using the normal verified installation process, with all selected targets
and components. Do not modify that installation during the image build.
The base starts with an explicitly pinned Debian 13 slim image and includes
GCC/G++, Clang/LLD, CMake, Ninja, Git, Rustup, bubblewrap and FUSE. The
resolved Debian package inventory is stored inside the image at
`/usr/share/sccache-runtime/packages.txt`. A later build can select newer
apt packages; the resulting image must be treated as a new immutable
runtime, not as the same environment.

```sh
contrib/codeandsolder/runtime/build-image \
    local/sccache-runtime-base:20261127 \
    nightly-2026-11-23-x86_64-unknown-linux-gnu \
    local/sccache-runtime:nightly-2026-11-23
```

Copy the exact image to other hosts using an authenticated registry or
`docker image save --platform linux/amd64` and `docker image load`.
Compare the resulting full platform image ID before using it. Do not use
floating tags to launch builds. The base layers are shared by future
toolchain-specific images in the existing image store.

On each host (administrator):

```sh
install -m 0755 contrib/codeandsolder/runtime/run /usr/local/bin/sccache-runtime
docker image inspect --format '{{.Id}}' local/sccache-runtime:nightly-2026-11-23 \
    > /etc/sccache/runtime-image
chmod 0644 /etc/sccache/runtime-image
```

The runner accepts an explicit `--image sha256:...` as the first option
for testing a different local image. It never pulls an image during a
build. This initial implementation is for Linux rootful Docker and the
existing shared Unix-socket daemon. A remapped user namespace is not
supported.

## Run

From the repository to build:

```sh
sccache-runtime --leased-intermediates -- cargo build --locked
sccache-runtime --leased-intermediates -- cargo test --locked
sccache-runtime -- sccache --cargo-all -- build --locked
sccache-runtime -- sccache /usr/bin/clang -c source.c -o source.o
```

Use `--offline` to remove container networking (the host daemon still
has its normal authenticated scheduler connection). `--report-actions`
emits the existing verified native action reports for diagnostics.
`--bind DIR` repeats for additional workspace directories or path
dependencies, at their original absolute paths. The working repository
and existing Cargo home are bound at their original paths; the root
filesystem is read-only. Protected system/toolchain paths cannot be
shadowed with writable project binds. The host's installed managed client,
wrappers and daemon socket directory are mounted read-only. No host
compiler libraries are imported. The process uses the caller's real
UID/GID, supplementary groups and umask; a minimal per-session NSS account
mapping supports FUSE. Temporary session scratch resides on the host's
existing temporary filesystem and is reclaimed on exit.

`--leased-intermediates` supplies the FUSE device and SYS_ADMIN capability
bounding set for the image's setuid fusermount3 helper. Use it for the
normal Cargo launcher; omit it for full-export or ordinary C/C++ builds.
The rootful build runtime is intended for trusted build work, not as a
security boundary for untrusted code. It does not expose the Docker socket
inside the container.

The managed Cargo launcher uses the common runtime by default, mounting
the original installed Rustup toolchain read-only. Native system packages
and the compiler execution environment are supplied by the immutable
image. CUDA, unusual cross-compilers and arbitrary host-only toolchains
are not silently injected; additional system packages belong in an immutable package profile, not
in the common base or host library mounts.

## Acceptance

Run the exact image from the same absent output directory on two hosts:

```sh
contrib/codeandsolder/runtime/test-runtime sha256:FULL_IMAGE_ID /home/jan/benchmarks/runtime-acceptance
```

The test uses the real managed daemon, compiles C, C++ and a Rust library,
records exact native action reports and artifact SHA256s, and exercises
leased Cargo with a proc macro, C build script, linked binary, unit test and
Clippy. The second host must report matching keys and hits for the three
plain compiler actions, and matching artifact hashes. Build outputs are
removed after the test; sources, reports and logs are retained. The CLI
regression `test-run` does not require Docker or managed services.

## Default managed Cargo execution

Install the runtime runner, its immutable image ID and the managed
`cargo-wrapper` on each build-submitting host. Every top-level managed
Cargo invocation uses this runtime, with the original Rustup selection.
Nested Cargo invocations recognize the mounted runtime marker and use
the existing lease launcher directly. A missing runtime is a provisioning
error, not a reason to fall back to host-native compilation.

The build data mounts cover the caller's home and the managed CI tree
`/srv/ci`, preserving campaign Rustup aliases, sibling worktrees, path
dependencies and external Cargo targets in those trees. Additional
data roots can be explicitly bound when using the runtime runner.
The selected Rustup home is read-only. The image's system PATH precedes
project and CI helper directories; host system libraries are not imported.


## Project-native package provisioning

Declare concrete Debian binary package names in `.sccache-runtime-packages`
at the repository root (or standalone project directory outside Git), one
name per line. Comments and whitespace are ignored and order/duplicates do
not change the request identity. For example:

```text
# PDF rasterization and test commands
poppler-utils
ripgrep
```

The managed Cargo launcher selects the repository containing an explicit
`--manifest-path` or `-C` directory as well as ordinary in-tree builds. A
non-Cargo command can select its declaration with `--project-dir DIR`.
Nested Cargo processes may use the enclosing runtime; if they declare a
nonempty, different request they fail rather than silently use wrong native
libraries. Missing/empty declarations use the shared base. A nonempty
request **must** have a registered image; there is no host-native fallback,
implicit package download, or mutable runtime during execution.

Each canonical request is identified by SHA-256, independently of repository
name and checkout path. The catalog layout is
`/etc/sccache/runtime-profiles/<base-image-id-without-sha256-prefix>/<request-digest>`;
each regular file contains one full immutable image ID. Equal package sets
share one image; all profiles share OCI base layers. The base ID is part of
the lookup, so a new base cannot silently inherit a profile resolved for an
old base. The runner checks the actual local image ID and request/base labels.
An explicit `--image` is a test override, but still must match a nonempty
project declaration. The native compiler action identity remains based on
actual compiler, toolchain, library and input bytes, not the profile ID.

On one trusted builder, resolve any number of manifests together (the tool
must run from the reviewed source directory):

```sh
base=$(cat /etc/sccache/runtime-image)
contrib/codeandsolder/runtime/sccache-runtime-profile provision "$base" \
    /path/to/staging-catalog \
    /path/to/ocr/.sccache-runtime-packages \
    /path/to/gui/.sccache-runtime-packages
```

`provision` validates all requests, groups them by content, builds only
unregistered sets, and prints tab-separated request digest and image ID.
Existing mappings are verified, not resolved again. Each image starts from
the exact local base; APT resolves the complete dependency closure in a
single transaction using the base's signed repositories. No package removal
or downgrade is permitted. Some development packages require newer versions
of existing libraries; the derived layer records every changed version,
without altering the common base or other profiles. Inspect the complete
installed inventory in `/usr/share/sccache-runtime/packages.txt`, additions
and new versions in `profile-packages.txt`, and replaced base versions in
`profile-replaced-packages.txt`. The immutable image itself is the resolved
lock: don't independently rebuild it on other hosts from floating APT
metadata. Re-resolving a set under new repository state requires explicit
coordinated catalog rotation (or a new base), not an implicit tag update.

Distribute the exact resulting image(s) using an authenticated registry or
`docker image save` / `docker image load`. Docker shares layers and can
export multiple profile images together. Check the full local image ID on
each submitting host before registration. On each host, the administrator
installs the runner and profile tool together and registers each request:

```sh
install -m 0755 contrib/codeandsolder/runtime/run /usr/local/bin/sccache-runtime
install -m 0755 contrib/codeandsolder/runtime/sccache-runtime-profile \
    /usr/local/bin/sccache-runtime-profile
sccache-runtime-profile register "$base" /path/to/project/.sccache-runtime-packages \
    sha256:FULL_PROFILE_IMAGE_ID /etc/sccache/runtime-profiles
```

Registration verifies actual image ancestry and both labels, atomically
creates a new catalog record, and refuses to replace an existing record with
a different image. Repeated registration of the same image is idempotent.
Catalog directories are administrator-managed and readable by build users.
`fleet/prepare-host` and `fleet/activate-host` stage, install and roll back
the runner and profile helper as a pair. This needs neither a daemon restart
nor another compiler cache. Site-specific tools unavailable as Debian
packages should be published as reviewed versioned packages through a trusted
signed APT repository configured in the base, rather than mounting host
`/usr` or executing arbitrary repository install scripts at build time.

Use `test-profile` for Docker-free catalog/selection regression. For real
acceptance, run the declared tools in the immutable profile with
`--offline`, then run normal managed Cargo tests on each host using the
registered profile.
