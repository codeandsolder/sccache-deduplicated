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

The runtime provides the pinned Rustup toolchain; a project that requires
another Rust version or additional native system packages needs a separate
explicitly built, pinned image. CUDA, unusual cross-compilers and arbitrary
host-only toolchains are not silently injected. The site host-native
launcher remains independent until the relevant projects have passed
runtime acceptance.

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

## Site workspace profiles

A verified workspace can use the installed common runtime automatically
through the managed Cargo launcher. Add the absolute workspace directory
(or a deliberately selected parent containing its worktrees) as one line
in the administrator-maintained `/etc/sccache/runtime-workspaces`. Match
is on directory boundaries, not arbitrary string prefixes. Install the
matching `cargo-wrapper` and runtime runner. Nested Cargo runs inside the
runtime do not start a second container.

This mode mounts the caller's existing Rustup home read-only and retains
the caller-selected installed toolchain, including an explicit
`+toolchain` or workspace override. It inherits the ordinary build
environment except for host runtime paths and managed transport settings.
The image controls the system runtime and native toolchain. Verify all
required native packages, path dependencies and externally configured
output locations before enabling a workspace profile. Workspaces not
listed continue to run host-native. An opted-in workspace fails normally
if its configured runtime is unavailable; it does not silently change
execution identity by falling back to the host.
