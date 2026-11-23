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

The exported versioned JSON distinguishes a detected CPU from a named model.
The feature set is Archspec's model capability data, not an independent survey
of all cores on a heterogeneous machine. For heterogeneous destinations,
choose a CPU model compatible with every core that will run the output.

## Render only the settings consumed by each compiler

Execute the tool on any build host, using the actual compiler binary:

~~~sh
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format cargo --compiler /usr/bin/rustc --output cargo-target.toml
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format gcc --compiler /usr/bin/gcc --output gcc.flags
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format clang --compiler /usr/bin/clang --output clang.flags
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format cmake --c-compiler gcc --compiler /usr/bin/gcc --output cmake-target.cmake
cargo run --manifest-path tools/cpu-target-profile/Cargo.toml -- emit --profile cpu.json --format meson --c-compiler clang --compiler /usr/bin/clang --output meson-target.ini
~~~

Apply Cargo's configuration with an explicit target to avoid targeting build
scripts and proc macros at an incompatible ISA:

~~~sh
cargo --config cargo-target.toml build --target x86_64-unknown-linux-gnu
~~~

C flags are used only by native C/C++ invocations. For Cargo packages that
compile C through build scripts, separately configure the actual C compiler
using its generated flags; this tool deliberately does not inject GCC flags
into the Cargo/rustc config. CMake and Meson outputs only configure C/C++ codegen;
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
