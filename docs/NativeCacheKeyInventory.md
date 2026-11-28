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
Native CPU identity uses the actual lowered target flags in the worker argument
list, without a separate expansion fingerprint or original native request. Source basenames remain where they identify object contents.
Hash declared environment dependencies as effective name/value assignments;
ordering and overridden assignments are not semantic inputs.

Do not hash native debug compilation directories, directory spellings in line
markers, debug/file/macro prefix-map operands, or independent output destinations.
Actual expanded string literals remain inputs. Ordinary single-object outputs
use the same execution destination. Multi-artifact output relationships and
runtime profiling destinations remain meaningful inputs.

## Rust

Hash the actual compiler driver and loader-selected compiler libraries, target and
semantic arguments, selected source and binary dependencies (including selected
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
already identify the worker compilation.
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

Standard Cargo build paths used by compiler environment observations are
normalized for both key and execution. The build-script output root is
`/generated`. Do not hash the native working directory or all Cargo environment
variables. Retain the actual package identity where ordinary proc macros use it,
compiler switches supplied through the environment, and Clippy policy and flags.
Resolve duplicate environment assignments before discovery, hashing or execution;
explicit observations are not repeated in the native compiler environment group.
Keep Rust metadata/output-name salts: changing `-C extra-filename` was verified
to change both rlib and rmeta contents even with identical metadata salt.

## Execution

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
