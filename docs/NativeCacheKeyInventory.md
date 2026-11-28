# Native compiler cache identity

## Result identity (v2, protocol 8)

The compiler frontend owns the meaning of its result. The native action
fingerprint for independent compiler files contains exactly two components: `compiler/semantic` (the frontend
digest) and `native/output-contract` (required/optional artifact roles and
types). The schema separates incompatible key interpretations.

Platform admission, the composed root, mounts, toolchain package, input tree,
command environment, umask and output delivery paths are execution and transport
data, not additional independent-file cache-key components. Generated codegen trees retain their logical output root because rlink artifacts embed logical object paths. Link planning and final linking are independent scheduler-owned actions keyed by their actual generated and selected linker inputs. Generic non-compiler execution retains its exact execution identity. There is no proc-macro or
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
cfg predicates and effective check-cfg expectation sets), selected source and binary dependencies (including selected
standard libraries), extern name-to-content bindings, auxiliary inputs,
static libraries, custom target contents and explicitly observed environment.
Dependency files are generated in the receiving checkout from the discovery
records. The compiler action does not emit them. `--emit=dep-info`, the
`-Zdep-info-omit-d-target` delivery policy and the `artifacts` JSON notification
flag do not contribute to native result identity. Generate artifact notifications
for the actual receiving paths on hits and misses; preserve other diagnostic
controls. Parse rustc's unambiguous per-file prerequisite rules and validate
the combined target rule rather than splitting on ambiguous escaped spaces.
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
settings when a short flag overrides a long option. Rustc merges repeated
check-cfg declarations by name and value; any-value dominates finite sets,
and any-name disables exhaustive names without disabling value checking.
Use the parsed sets, not their CLI order, grouping, or literal spelling.
Retain distinct enabled/disabled checking, empty value sets and bare cfg
predicates. The original options still go to rustc for validation/diagnostics. An
omitted target and explicit host target identify the same compiler result.
Explicit JSON targets use the canonical file stem and selected file contents,
not the path spelling. Named targets use the compiler-reported built-in list,
then the first matching `RUST_TARGET_PATH` file or installed target spec;
only the selected specification participates. Preserve observed search-path
environment values, otherwise retain only the selected directory for execution.
Physical input layout preserves JSON aliases whose resolved names lack the
`.json` suffix. Target specifications discovered again by tracing are not
hashed a second time.
Native nightly metadata-only and rlib-only results key the binary operands
selected by rustc, not all explicit extern candidate files. A separate rlib
supplied alongside selected rmeta contributes no digest; an entirely unused
extern contributes its name and modifiers, not file contents. Reuse the
already-computed selected dependency digests. Native-linking results retain
linkable inputs, and the execution packager can still deliver siblings.
Native library declarations are discovered in the managed nightly compiler's
expanded dependency pass, including source attributes produced by macros and
conditional compilation. Apply command-line kind and rename overrides in rustc
order. Resolve selected archives using the compiler-reported target filename
convention and ordered native search directories; metadata-only compilations,
shadowed archives and unrelated files do not contribute identity. Preserve
request order and missing slots. Ordinary bundling keys framed ordered member
names and actual contents; the compiler's selected Mach-O slice is sufficient.
Packed or directly linked archives are normalized before worker execution,
not just in the key: GNU archives are reserialized deterministically with
ordered members, symbol-to-member associations and recomputed index offsets.
Packed thin archives become self-contained regular archives. Other recognized
archive layouts normalize creation metadata without rewriting their index or
layout; unsupported layouts retain exact bytes. When source/proc macros observe
the raw archive, retain the original bytes instead of substituting normalized
ones. Normalized bytes are the input to both the digest and worker packaging.
Unmaterialized thin archives key and package the actual external members.
Source-aware archive discovery requires the managed nightly; narrow structured
compiler-native dependency output would eliminate expanded-source serialization
cost (tracked in #538).

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
