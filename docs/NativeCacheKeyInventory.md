# Native compiler cache identity

## Result identity (v2, protocol 8)

The compiler frontend owns the meaning of its result. The native action
fingerprint contains exactly two components: `compiler/semantic` (the frontend
digest) and `native/output-contract` (required/optional artifact roles and
types). The schema separates incompatible key interpretations.

Platform admission, the composed root, mounts, toolchain package, input tree,
command environment, umask and output delivery paths are execution and transport
data, not additional compiler cache-key components. Generic non-compiler
execution retains its exact execution identity. There is no proc-macro or
dynamic-library exception that switches compiler results to exact identity.

## C / C++

Hash the compiler, language/driver mode, semantic options, preprocessed program
(including expanded macros), selected auxiliary inputs and assembler. For GCC,
hash the actual selected frontend and specs file, not its installation tree.
Native GCC/Clang results use driver bytes, actual loaded compiler-code shared
libraries, and the assembler selected by this invocation, rather than a version
banner or the default assembler discovered for an unrelated invocation. The
managed system runtime is not an additional compiler identity. Distribution
compiler-code libraries (including split Clang/LLVM and GCC numeric libraries)
and private installation dependencies remain actual compiler inputs.
Native CPU identity uses the actual lowered target flags in the worker argument
list, without a separate expansion fingerprint or original native request. Source basenames remain where they identify object contents.
Hash declared environment dependencies as effective name/value assignments;
ordering and overridden assignments are not semantic inputs. Darwin SDK and
deployment variables are removed before discovery and execution on non-Darwin
targets, including Linux-targeted Clang cross compilers. GCC does not consume
Clang driver overrides. Query the actual target only when those settings are
present. Arbitrary custom
cache-buster environment values are not inputs; forced recache is a cache
operation, not a distinct result identity.

Do not hash native debug compilation directories, directory spellings in line
markers, debug/file/macro prefix-map operands, or independent output destinations.
Actual expanded string literals remain inputs, including date/time macro
expansions from `SOURCE_DATE_EPOCH`. That setting is not a separate result
fingerprint for ordinary preprocessed C and is not passed to its worker. Ordinary single-object outputs
use the same execution destination. Multi-artifact output relationships and
runtime profiling destinations remain meaningful inputs.

## Rust

Hash the actual compiler driver and loader-selected compiler libraries, target and
semantic arguments (effective codegen fields, emission sets and deduplicated
cfg predicates), selected source and binary dependencies (including selected
standard libraries), extern name-to-content bindings, auxiliary inputs,
static libraries, custom target contents and explicitly observed environment.
Native nightly dep-info reports binary dependencies; stable compilers and
proc-macro compilations discover successful file reads in the dependency probe,
rather than treating a package tree as a dependency. The trace tool is part of
the managed runtime. Fixed system runtime files and probe scratch are not
project dependencies. The compiler version banner is discovery data, not an
additional digest input. Resolve the actual ELF dependency closure, including
versioned LLVM shared libraries, not every file with a shared-library suffix
in the installation. Managed system runtime libraries do not contribute to
private toolchain identity. Native execution does not compute an archive
transport key or read target installation ledgers. Explicit externs are keyed once by name, modifiers
and content, independently of filename ordering or repeated discovery.
An originating CPU profile is only hashed if the effective invocation still
requests native CPU or tuning; successfully lowered explicit target arguments
already identify the worker compilation. Normalize rustc codegen option aliases,
static defaults, overwritten scalar assignments and independent field order.
Preserve append order for metadata salts and linker/LLVM arguments, the
frame-pointer ratchet, and distinct raw versus effective optimization/debug
settings when a short flag overrides a long option.
Native nightly metadata-only and rlib-only results key the binary operands
selected by rustc, not all explicit extern candidate files. A separate rlib
supplied alongside selected rmeta contributes no digest; an entirely unused
extern contributes its name and modifiers, not file contents. Reuse the
already-computed selected dependency digests. Native-linking results retain
linkable inputs, and the execution packager can still deliver siblings.
Bundled native archives are resolved per library request using the compiler-reported
target filename convention and ordered native search directories. Shadowed
archives, unrelated filename conventions, and archives not used by metadata-only
compilation do not participate. Selected archive digests retain the request
order, including missing slots; archive locations do not identify results.
Ordered member names and content digests are framed independently, without
archive timestamps, ownership, or index offsets. Thin archives contribute the
actual external member bytes and their embedded names; those members are also
packaged as compiler inputs. A Mach-O fat archive contributes only the first
matching architecture slice when rustc selects that slice for bundling. Native
linker consumption retains the complete architecture-to-content association.

Standard Cargo build paths used by compiler environment observations are
normalized for both key and execution. The build-script output root is
`/generated`. The dispatch validator uses the identical realized environment.
Rustc embeds the physical working directory even without debug information;
native commands normalize it with a default prefix map to `/sccache/cwd`.
Only an explicit restricted remap scope retains cwd identity. Do not hash
all Cargo environment variables. Retain the actual package identity where ordinary proc macros use it,
compiler switches supplied through the environment, and Clippy policy and flags.
Resolve duplicate environment assignments before discovery, hashing or execution;
explicit observations are not repeated in the native compiler or Clippy environment
group. Dep-info preserves unset versus empty values as a typed observation;
key only the observed value, not a second copy of the caller environment.
Managed build-path observations use the realized canonical environment,
including synthesized Cargo build-directory defaults.
Normalize unobserved Rust bootstrap permissions to the effective scope of the
current crate; unrelated crate names do not affect either execution or identity.
Global bootstrap and crate-specific permission remain distinct. The obsolete
`RUSTC_FORCE_UNSTABLE` setting is not an implicit compiler input. Preserve
`SOURCE_DATE_EPOCH` when explicitly observed, consumed by opaque macros, or
needed by an unsplit native linker; ordinary Rust codegen does not key it.
Keep Rust metadata/output-name salts: changing `-C extra-filename` was verified
to change both rlib and rmeta contents even with identical metadata salt.

## Execution

Forward ordinary caller build variables to compiler discovery rather than
stripping them before they can be observed. Process-local instrumentation and
jobserver state remain transport concerns.

Use the resident shared compiler runtime. Allowlist compiler execution variables,
preserve explicit observations, normalize locale and scratch, and set native
umask to 022. Packaging may still select different files for different languages
and compiler features; it does not select a different key algorithm. Filesystem
manifests and output destinations still verify and deliver actual bytes. Installed
file memo validity and transport tree IDs are not result fingerprints.

The scope is ordinary compiler workloads, not arbitrary plugins engineered to
observe orchestration state or system runtime files. Build-specific semantic
inputs must be discovered or supplied through the frontend, never approximated
by adding the entire execution envelope to the result key.

Protocol 8 / rollout epoch 9 changes the compiler-result wire structure and
requires a coordinated client/scheduler/worker upgrade.
