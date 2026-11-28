# Native compiler cache identity inventory

Baseline: production client a83d0a2294054b26480d99a9c7fb843013af68b0,
scheduler 50454954; managed runtime wrapper 50d90ef2. Audited 2026-11-28.
Distinguish a result key, a transport tree ID, a preprocessor index key,
and an installation-digest memo: these are not interchangeable.

## Final action key

The BLAKE3 typed hash of the schema and ordered map of component names to
content digests, in build-runtime's ActionFingerprint::key. The selected
result fingerprint replaces the exact execution fingerprint when available.
The wire layer adds native/output-contract in either case.

| Component | Purpose |
| --- | --- |
| schema | Version the interpretation of the components |
| compiler/semantic | Compiler frontend identity |
| compiler/toolchain | Actual packaged compiler, helpers and runtime |
| compiler/environment | Residual compiler environment |
| compiler/input-closure (Rust) | Transitive filesystem input identity |
| platform | Configured execution platform contract digest, not a worker ID |
| command/umask | Output file creation permissions |
| output/path/NAME (generated trees) | Logical output root, potentially embedded in generated artifacts |
| native/output-contract | Sorted required/optional named artifact roles and kinds |

Schema native-compiler-result-v1 is used for eligible ordinary compiler
results. Exact execution (native-linux-bwrap-v4) instead hashes:
command/executable, command/arguments (ordered vector), command/cwd,
command/umask, each supplied environment name/value, platform, every
mount path and tree ID, every named output path, composed root/tree and
native/output-contract. This is used for opaque extensions, proc macros,
and compilation without a result-identity policy. The composed filesystem
rather than the transport recipe is the root identity. Scheduler job IDs,
worker IDs, admission times, quotas, transfer statistics and leases are not
independent key fields.

## C / C++ frontend

src/compiler/c.rs, HashKeyParams::compute, CACHE_VERSION 15:
compiler executable digest (combined with compiler version string if known);
C++ driver flag; version; language; ordered common and architecture
arguments; auxiliary content digests (extra hash files, resolved native CPU
probe, Cargo path context), external assembler digest; source basename
presence marker and basename if applicable; selected environment; effective
debug compilation directory when debug output observes it; entire
preprocessed stream. Compiler source bytes, expanded headers, macros and
source line markers determine the compiled program and debug information.
The source basename can occur in ELF STT_FILE. Auxiliary files include
assembler .incbin/.include dependencies and plugin inputs. Native CPU
resolution currently hashes the complete compiler -### cc1 response, not
just the target features. This can unnecessarily retain incidental paths.

Selected environment: SCCACHE_C_CUSTOM_CACHE_BUSTER (explicit partition),
MACOSX_DEPLOYMENT_TARGET, IPHONEOS_DEPLOYMENT_TARGET, TVOS_DEPLOYMENT_TARGET,
WATCHOS_DEPLOYMENT_TARGET, SDKROOT (target SDK), CCC_OVERRIDE_OPTIONS
(compiler override arguments).

Cargo canonical path-context: domain; mapped cwd; mapped input filename;
named non-dependency output paths; physical and canonical prefix-map pairs
when relevant to source literals, flags or assembler directives. The
assembly heuristic treats any .file or numeric escape as possibly observing
all maps. It has not been demonstrated that each such dependency is necessary.
Dependency file destinations are not compiler result fields. Split DWARF,
coverage and other linked artifacts can observe destination paths.

## Rust frontend

src/compiler/rust.rs generate_hash_key, CACHE_VERSION 10:
version; conditional native-library-input, Clippy execution, external
Clippy config, selected-binary-dependency, Cargo-manifest, proc-macro package
tree, metadata-only-output markers; sorted immediate sysroot lib shared
library content digests (plus configured archive if any); canonical-layout
marker; optional dlltool closure; ordered argument pairs (sorted cfg
entries, excluding extern, library search and output directory; target JSON
pathname replaced with its contents; local linker-only args excluded for
split link); resolved native CPU profile; source and selected binary
dependency content digests; extern name/content bindings; static-library
digests; target JSON digest; observed environment names, values and
presence; broad Cargo environment for opaque or nonprecise discovery;
Clippy environment; mapped cwd; full compiler verbose version string.

The arguments and input hashes determine code, metadata and diagnostics.
Extern bindings distinguish otherwise identical dependency sets used under
different names. DLL tool and target CPU inputs affect code generation and
import libraries. Observed environment includes env!/option_env! and
explicitly tracked macro inputs. Broad Cargo and proc-macro-tree rules
are conservative fallbacks, not proven dependencies. Sources can include
generated files, manifests, Clippy configs, and the full package tree for
opaque macros (excluding known output and VCS directories). Whole-package
enumeration must eventually be replaced with actual dependency discovery.

## Native environment

src/compiler/native.rs compiler_environment hashes each selected name and
value, length framed. Common: LANG, LANGUAGE, TZ, TERM, SOURCE_DATE_EPOCH,
PATH, LC_*, LD_*. C: GCC_*, CLANG_*, CCC_*, COMPILER_PATH, LIBRARY_PATH,
CPATH, C_INCLUDE_PATH, CPLUS_INCLUDE_PATH, OBJC_INCLUDE_PATH,
DEPENDENCIES_OUTPUT, SUNPRO_DEPENDENCIES. Rust: RUSTC_*, RUST_MIN_STACK,
RUST_BACKTRACE, RUST_LIB_BACKTRACE, RUSTFLAGS. Exact mode hashes the full
supplied environment instead. Ordinary native C normalizes locale, removes
consumed include paths and selects a private compiler search path; ordinary
Rust normalizes locale, selects a package-owned PATH and normalizes loader
selection where applicable. These are execution changes, not merely
exclusions from the digest. Preserve explicit observations; do not hash
the pre-resolution search path again if its only effect is resolved content.

Rust control-variable filtering excludes orchestration prefixes SCCACHE_,
CODEANDSOLDER_, RUST_SKILLS2_, CARGO_TERM_, CARGO_PROFILE_, CARGO_BUILD_
(except CARGO_BUILD_BUILD_DIR), CARGO_REGISTRIES_, CARGO_HTTP_, CARGO_NET_,
GITHUB_, RUNNER_, ACTIONS_, RUSTUP_; specific driver, jobserver, shell and
systemd control variables. Explicitly observed variables take precedence.
See compiler_control_environment and compiler_execution_environment for
the authoritative predicate. CLIPPY_* is retained for Clippy.

## Trees and storage identity

Tree ID is the typed BLAKE3 hash of root metadata and ordered relative
paths and entries. Directory: mode and mtime (seconds, nanoseconds).
Regular file: content hash, logical length, mode, mtime. Symlink: raw
target bytes and mtime. Hardlink: target tree path. Ownership, ACLs and
extended attributes are excluded. The tree describes actual sandbox
contents, not only compiler semantics. Installed toolchain timestamps and
modes are normalized; Rust inputs normalize timestamps, ordinary Rust
closure additionally zeros timestamps. Exact C still includes input
metadata. These mtime fields must not be mistaken for content hashes.

Result ID is separate: artifact roles, types, content/tree digests and
metadata, stdout and stderr. Identical artifacts alone (especially Clippy
metadata) do not prove identical complete results. The result is not hashed
into its own lookup key.

## Other lookup keys

C direct preprocessor index (not used by ordinary native compilation):
compiler digest, C++ driver bit, format 3, ignore-time-macro policy,
language, preprocessor/common/architecture arguments, auxiliary hashes,
assembler digest, input-basename-presence, SCCACHE_C_CUSTOM_CACHE_BUSTER,
CPATH, C_INCLUDE_PATH, CPLUS_INCLUDE_PATH, OBJC_INCLUDE_PATH,
OBJCPLUS_INCLUDE_PATH, encoded input pathname and source content digest.
The selected include files are subsequently validated. This is an index
to a result key, not the result key.

Weak toolchain archive lookup: C executable pathname + executable digest;
Rust package schema, shared-library hashes, target triple, physical sysroot
when noncanonical, target std installation-manifest presence/digest and
optional dlltool closure. Native uses the actual tree ID instead.
Installed-file digest memo additionally checks file identity, size and
mtime/ctime, with namespace/credential scope; these are local memo validity
checks, not separately supplied native action fields. Mutable source content
is hashed. Timestamp-based local memo validity is still a separate concern.

## Reproduced defect and candidate

On the deployed client the BoringSSL md5-586-apple.S source compiled to
identical SHA256 d3810d7d99d615d619ae3a56e4d023dde070df6a27f672bae6de83f5c0fdfa7a
for every tested destination and lease, but changing only output filename
missed with and without debug flags. Changing the Cargo lease alone hit.
Evidence: Asus /home/jan/build/sccache-key-audit-20261128/assembly-probe.log.
The source is conditionally empty on Linux. These data prove the delivery
filename defect, not the attribution of all same-name production duplicates.

Candidate: native canonical ordinary single-object compilation uses one
stable sandbox output path and a relocatable artifact policy. Required
multi-output relationships, profiling, recorded compiler invocations and
opaque extensions retain their path identity. The physical delivery path
is preserved for publication. The policy changes affected keys, so do not
deploy repeatedly without validation.

New diagnostic instrumentation captures component hashes of the actual
serialized bytes entering C frontend, C path context, Rust frontend and
final native action keys, using existing request traces without raw values.
The instrumentation itself is key-neutral; it allows comparing the otherwise
opaque frontend digest of actual duplicate results. Regressions cover
destination renaming, independent sandbox execution and evidence transfer
from executor to daemon. No claim of production recovery until measured
against real workload.
