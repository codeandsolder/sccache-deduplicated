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
Native CPU identity uses the resolved target flags instead of the full driver
transcript. Source basenames remain where they identify object contents.
Hash declared environment dependencies as effective name/value assignments;
ordering and overridden assignments are not semantic inputs.

Do not hash native debug compilation directories, directory spellings in line
markers, debug/file/macro prefix-map operands, or independent output destinations.
Actual expanded string literals remain inputs. Ordinary single-object outputs
use the same execution destination. Multi-artifact output relationships and
runtime profiling destinations remain meaningful inputs.

## Rust

Hash the actual compiler driver and compiler library contents, target and
semantic arguments, selected source and binary dependencies (including selected
standard libraries), extern name-to-content bindings, auxiliary inputs,
static libraries, custom target contents and explicitly observed environment.
Native nightly dep-info reports binary dependencies; stable compilers and
proc-macro compilations discover successful file reads in the dependency probe,
rather than treating a package tree as a dependency. The trace tool is part of
the managed runtime. Fixed system runtime files and probe scratch are not
project dependencies. The compiler version banner is discovery data, not an
additional digest input. Explicit externs are keyed once by name, modifiers
and content, independently of filename ordering or repeated discovery.
An originating CPU profile is only hashed if the effective invocation still
requests native CPU or tuning; successfully lowered explicit target arguments
already identify the worker compilation.
Metadata-only results do not depend on unselected linkable siblings of rmeta
inputs; the execution packager can still deliver those siblings.

Standard Cargo build paths used by compiler environment observations are
normalized for both key and execution. The build-script output root is
`/generated`. Do not hash the native working directory or all Cargo environment
variables. Retain the actual package identity where ordinary proc macros use it,
compiler switches supplied through the environment, and Clippy policy and flags.
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
