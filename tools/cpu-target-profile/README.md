# Destination CPU profiles

This standalone Rust tool exports an explicit destination CPU target, independent
of the host invoking Cargo and the sccache worker running the compiler. It uses
Archspec's CPU model database and compiler-version mappings.

## Capture or define a destination

Capture the CPU model on the machine where the output will run:

~~~sh
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- capture --target x86_64-unknown-linux-gnu --output cpu.json
~~~

Or describe a known target CPU without access to the actual machine:

~~~sh
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- model --target x86_64-unknown-linux-gnu --cpu x86_64_v4 --output cpu.json
~~~

Version 2 of the exported profile records capture provenance: a named model,
Archspec's host detector on systems without independent processor-topology
inspection, or a Linux per-processor capability intersection with logical
processor count and an explicit heterogeneous flag. The Linux
`hypervisor_flag_seen` field records only whether the kernel exposed a
hypervisor hint; `false` does not prove the destination is non-virtualized.
The provenance fields are descriptive and are never extra compiler cache keys.
Version 1 profiles are intentionally rejected rather than silently interpreted.

The exported versioned JSON distinguishes a detected CPU from a named model.
For Linux x86/x86-64 and AArch64 detection, the feature set is the
**intersection of kernel-exposed, OS-usable flags across all visible cores**,
with aliases derived from Archspec's own database. Mixed CPU models downgrade
the explicitly exported CPU *selection* to an ISA-proven common baseline:
for x86 it is the best compatible generic x86-64 level, and for AArch64 the
ARMv8-A baseline (because Archspec's ARMv9 version markers alone do not prove
instruction support). Missing core reports cause capture to fail. For PowerPC
and RISC-V, nonuniform or unidentifiable per-core processor identities fail
rather than trusting CPU0. Other operating systems currently rely on Archspec
host detection; use an explicit named CPU profile for heterogeneous machines
whose common ISA cannot be established by that API.

## Native requests versus explicit destination profiles

A plain compiler `native` request means the machine **initiating the
compilation**, not whichever worker receives the job. The profile exported
here is a deliberate, explicit destination selection and can target
different hardware; `capture` is run on the intended destination, and
`model` names a CPU directly. Do not interpret the distributed worker's
CPU as the default destination. For portable fleet binaries choose an
explicit baseline rather than changing the meaning of `native`.

The current sccache implementation resolves Rust native CPU requests before
remote dispatch; unresolved GCC/Clang native requests execute locally and
include the initiating compiler's CPU expansion in their cache key. See
[distributed native behavior](../../docs/Distributed.md#native-cpu-is-the-requesting-host-not-the-worker).

## Render only the settings consumed by each compiler

Execute the tool on any build host, using the actual compiler binary:

~~~sh
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format cargo --compiler /usr/bin/rustc --output cargo-target.toml
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format gcc --compiler /usr/bin/gcc --output gcc.flags
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format clang --compiler /usr/bin/clang --output clang.flags
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format cmake --c-compiler gcc --compiler /usr/bin/gcc --output cmake-target.cmake
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format meson --c-compiler clang --compiler /usr/bin/clang --output meson-target.ini
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format cc-rs --c-compiler gcc --compiler /usr/bin/gcc --output target_cpu_cc.json
~~~

Apply Cargo's configuration with an explicit target to avoid targeting build
scripts and proc macros at an incompatible ISA:

~~~sh
cargo --config cargo-target.toml build --target x86_64-unknown-linux-gnu
~~~

C output validates the actual compiler against the destination ABI:
GCC must report a compatible architecture/OS/environment via `-dumpmachine`
(the vendor field can differ), and Clang receives an explicit
`--target=DESTINATION_TRIPLE` argument. Both backends are checked with a
syntax-only compiler invocation (`-fsyntax-only -x c -`) using the
generated optimization flags. This validates CPU flag support without
compiling client-side code, linking or producing artifacts. This rejects native GCC for foreign
architectures, instead of silently generating unusable configurations.
The cross-toolchain and any required sysroot are selected independently.

C flags are used only by native C/C++ invocations. For an editable Cargo
package using [cc-rs](https://docs.rs/cc/latest/cc/), generate the `cc-rs`
flags data file *alongside* the Rust-only Cargo config. Use a stable `build.rs`
to read the JSON at build-script **runtime**, then pass only those arguments to
the native compiler:

~~~rust
fn main() {
    println!("cargo:rerun-if-changed=target_cpu_cc.json");
    let flags: Vec<String> = serde_json::from_slice(
        &std::fs::read("target_cpu_cc.json").expect("native CPU flags")
    ).expect("valid native CPU flags");
    let mut native = cc::Build::new();
    native.file("src/native.c");
    for flag in &flags {
        native.flag(flag);
    }
    native.compile("native");
}
~~~

This requires `cc` and `serde_json` as **build dependencies**. Cargo reruns
the build script when the native flags data changes, but does not need to
recompile the build script itself: GCC flags do not enter that host Rust
compilation's source/hash identity. Only the specific `cc::Build` receiving
the arguments changes; unrelated Rust crates remain unaffected. Use the actual
C compiler/launcher matching the one probed by the exporter, and invoke Cargo
with an explicit `--target`. This requires no `CFLAGS` environment variables
and does not modify global Cargo rustflags. Uneditable third-party native build
scripts must be configured through their existing supported native compiler
interfaces.

CMake and Meson outputs only configure C/C++ codegen;
configure the linker, sysroot and ABI separately for cross-toolchain builds.

To deliberately target a compatible baseline of a captured destination, use
emit --cpu x86_64_v2. A target requiring features absent from a detected
destination is rejected; the model subcommand can describe another machine.

## Cache identity

The profile JSON and flags for other compiler families are **never** added
to sccache keys. The existing sccache compiler-specific keying sees only the
effective arguments of each compiler invocation, alongside its normal
source, toolchain, dependency and relevant environment inputs. Rustc receives
explicit target-cpu flags, GCC/Clang receive their own explicit architecture
flags, and the worker's own CPU is not used for target selection. No
client-side compilation or native CPU fallback is introduced.

Unsupported target/compiler/version combinations produce errors, not silent
architecture downgrades.
