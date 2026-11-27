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

#![deny(rust_2018_idioms)]
#![recursion_limit = "256"]

#[macro_use]
extern crate log;
// To get macros in scope, this has to be first.
#[cfg(test)]
#[macro_use]
mod test;

#[macro_use]
pub mod errors;

pub use sccache_build as build_runtime;
pub mod cache;
#[cfg(target_os = "linux")]
mod cargo_launcher;
mod client;
mod cmdline;
mod commands;
mod compiler;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use compiler::rust_link;
pub mod compression;
pub mod config;
pub mod dist;
#[cfg(feature = "http-client")]
pub mod http_client;
mod jobserver;
pub mod latency_trace;
pub mod lru_disk_cache;
mod mock_command;
mod net;
mod protocol;
pub mod server;
#[cfg(feature = "direct-metrics")]
mod telemetry;
#[doc(hidden)]
pub mod util;

/// Machine-readable capabilities compiled into this binary.
///
/// Keep this list tied to the modules that implement each capability so release
/// tooling can reject binaries that silently lose required production features.
pub static BUILD_CAPABILITIES: &[&str] = &[
    #[cfg(feature = "direct-metrics")]
    telemetry::CAPABILITY,
];
// For benches/preprocessor_cache_bench.rs.
#[doc(hidden)]
pub use compiler::PreprocessorCacheEntry;

use std::env;

/// VERSION is the pkg version of sccache.
///
/// This version is safe to be used in cache services to indicate the version
/// that sccache ie.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Used to denote the environment variable that controls
/// logging for sccache, and sccache-dist.
pub const LOGGING_ENV: &str = "SCCACHE_LOG";

pub fn main() {
    #[cfg(target_os = "linux")]
    if let Some(result) = server::shared::run_if_requested() {
        std::process::exit(match result {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("sccache shared executor: {error:#}");
                1
            }
        });
    }
    #[cfg(target_os = "linux")]
    if let Some(result) = rust_link::capture_if_relay() {
        std::process::exit(match result {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("sccache link capture: {error:#}");
                1
            }
        });
    }

    init_logging();

    #[cfg(target_os = "linux")]
    if let Some(result) = cargo_launcher::run_if_requested() {
        std::process::exit(match result {
            Ok(status) => status,
            Err(error) => {
                eprintln!("sccache Cargo launcher: {error:#}");
                2
            }
        });
    }

    let command = match cmdline::try_parse() {
        Ok(cmd) => cmd,
        Err(e) => match e.downcast::<clap::error::Error>() {
            // If the error is from clap then let them handle formatting and exiting
            Ok(clap_err) => clap_err.exit(),
            Err(some_other_err) => {
                println!("sccache: {some_other_err}");
                for source in some_other_err.chain().skip(1) {
                    println!("sccache: caused by: {source}");
                }
                std::process::exit(1);
            }
        },
    };

    std::process::exit(match commands::run_command(command) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sccache: error: {e}");
            for e in e.chain().skip(1) {
                eprintln!("sccache: caused by: {e}");
            }
            2
        }
    });
}

fn init_logging() {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::new().filter_or(LOGGING_ENV, "warn"));
    // Enable millisecond precision timestamps if SCCACHE_LOG_MILLIS is set.
    if env::var("SCCACHE_LOG_MILLIS").is_ok() {
        builder.format_timestamp_millis();
    }
    if let Err(error) = builder.try_init() {
        eprintln!("sccache: failed to initialize logging: {error}");
    }
}
