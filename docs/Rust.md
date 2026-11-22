sccache includes support for caching Rust compilation. This includes many caveats, and is primarily focused on caching rustc invocations as produced by cargo. A (possibly-incomplete) list follows:
* `--emit` is required.
* `--crate-name` is required.
* Only `link`, `metadata` and `dep-info` are supported as `--emit` values, and `link` must be present.
* `--out-dir` is required.
* `-o file` is not supported.
* Compilation from stdin is not supported, a source file must be provided.
* Values from `env!` require Rust >= 1.46 to be tracked in caching.
* Procedural macros that read files from the filesystem may not be cached properly.
* `rustc`'s incremental compilation needs to be disabled. See [The Cargo Book](https://doc.rust-lang.org/cargo/reference/profiles.html#incremental)
* Crates that invoke the system linker cannot be cached. Examples are `bin`, `dylib`, `cdylib`, and `proc-macro` crates.

If you are using Rust 1.18 or later, you can ask cargo to wrap all compilation with sccache by setting `RUSTC_WRAPPER=sccache` in your build environment.

## Observed environment and distributed execution

Rust's dependency-information pass reports environment variables consumed by
`env!` and `option_env!`. Their values (including absence versus an empty
string) are program inputs, not relocatable path metadata. When canonical
path normalization would change an observation, use the physical input
layout for that compilation. On Unix, the ordinary distributed package
preserves source/input paths, including files read through an observed
absolute path by `include_str!` or `include_bytes!`. The cache key retains
the actual observation; artifacts embedding distinct paths are not
interchangeable.

Validate observed values after distributed toolchain selection. If a required
toolchain/path transformation cannot preserve an observation, perform the
compile locally rather than producing different program data. Workers begin
with an empty environment and add the command's supplied variables; worker
service variables must not leak into `option_env!`. Deploy the client and
worker changes together for this contract. This does not extend the
supported linked crate types or change Cargo's runtime environment.
