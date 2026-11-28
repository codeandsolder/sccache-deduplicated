// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
mod args;
mod c;
mod canonical_native;
pub mod canonical_paths;
#[macro_use]
mod cicc;
mod clang;
#[path = "compiler.rs"]
#[macro_use]
mod core;
mod cudafe;
mod diab;
#[cfg(target_os = "linux")]
pub mod dynamic_dependencies;
mod gcc;
mod msvc;
#[cfg(all(feature = "dist-client", target_os = "linux"))]
mod native;
#[cfg(all(feature = "dist-client", target_os = "linux"))]
pub use native::{NativeCompilerClient, ResultIdentityPolicy};
mod nvcc;
mod nvhpc;
mod ptxas;
mod response_files;
mod rust;
mod rust_dlltool;
#[cfg(target_os = "linux")]
pub mod rust_link;
mod rust_response;
mod tasking_vx;
#[macro_use]
mod counted_array;

pub use crate::compiler::c::CCompilerKind;
pub use crate::compiler::core::*;

/// Only compiler information queries and explicit preprocessing may run in
/// the caller namespace. Unsupported compilation/link commands are not queries.
pub(crate) fn is_compiler_query(
    kind: &CompilerKind,
    args: &[std::ffi::OsString],
    cwd: &std::path::Path,
) -> bool {
    match kind {
        CompilerKind::Rust => rust::is_compiler_query(args, cwd),
        CompilerKind::C(_) => {
            if args.len() == 1 {
                let arg = args[0].to_string_lossy();
                return matches!(
                    arg.as_ref(),
                    "--version"
                        | "-v"
                        | "--help"
                        | "-dumpmachine"
                        | "-dumpversion"
                        | "-dumpfullversion"
                ) || arg.starts_with("-print-")
                    || arg.starts_with("--help=");
            }
            // Only a preprocessing command with an explicit standalone -E
            // option and no response files may use the local query path.
            // Ambiguous arguments (including options consuming -E as a value)
            // are rejected here rather than accidentally starting codegen.
            args.first().is_some_and(|arg| arg == "-E")
                && !args
                    .iter()
                    .any(|arg| arg.to_string_lossy().starts_with('@'))
        }
    }
}

#[test]
fn unsupported_compilation_is_not_a_query() {
    use std::{ffi::OsString, path::Path};
    let cwd = Path::new("/");
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    assert!(is_compiler_query(
        &CompilerKind::Rust,
        &args(&["--print", "cfg"]),
        cwd
    ));
    assert!(!is_compiler_query(
        &CompilerKind::Rust,
        &args(&["--print", "native-static-libs", "main.rs"]),
        cwd
    ));
    assert!(!is_compiler_query(
        &CompilerKind::Rust,
        &args(&["--emit=asm", "main.rs"]),
        cwd
    ));
    assert!(!is_compiler_query(
        &CompilerKind::C(CCompilerKind::Gcc),
        &args(&["main.c", "-o", "main"]),
        cwd
    ));
}
