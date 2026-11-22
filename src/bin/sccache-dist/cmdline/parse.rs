// Copyright 2022 <LovecraftianHorror@pm.me>
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

use std::{env, ffi::OsString, fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, anyhow, bail};
use clap::{Arg, ArgGroup, Command as ClapCommand, ValueEnum};
use sccache::{config, dist::ServerId};
use syslog::Facility;

use crate::cmdline::{AuthSubcommand, Command};

#[derive(Debug, Clone)]
struct TokenLength(usize);

impl TokenLength {
    fn as_bytes(&self) -> usize {
        self.0 / 8
    }

    fn from_bits(bits: &str) -> anyhow::Result<Self> {
        let bits: usize = bits.parse()?;

        if bits & 0x7 != 0 {
            Err(anyhow!("Number of bits must be divisible by 8"))
        } else if bits < 64 {
            Err(anyhow!(
                "Number of bits must be greater than or equal to 64"
            ))
        } else if bits > 4_096 {
            Err(anyhow!("Number of bits must be less than or equal to 4096"))
        } else {
            Ok(Self(bits))
        }
    }
}

impl fmt::Display for TokenLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl FromStr for LogLevel {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let variant = match s {
            "error" => Self::Error,
            "warn" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => bail!("Unknown log level: {:?}", s),
        };

        Ok(variant)
    }
}

impl From<LogLevel> for log::LevelFilter {
    fn from(log_level: LogLevel) -> Self {
        match log_level {
            LogLevel::Error => Self::Error,
            LogLevel::Warn => Self::Warn,
            LogLevel::Info => Self::Info,
            LogLevel::Debug => Self::Debug,
            LogLevel::Trace => Self::Trace,
        }
    }
}

fn flag_infer_long(name: &'static str) -> Arg {
    Arg::new(name).long(name)
}

fn get_clap_command() -> ClapCommand {
    let syslog = flag_infer_long("syslog")
        .help("Log to the syslog with LEVEL")
        .value_name("LEVEL")
        .value_parser(clap::value_parser!(LogLevel));
    let config_with_help_message = |help: &'static str| {
        flag_infer_long("config")
            .help(help)
            .value_name("PATH")
            .value_parser(clap::value_parser!(PathBuf))
    };

    let command = ClapCommand::new(env!("CARGO_PKG_NAME"));
    #[cfg(target_os = "linux")]
    let command = command.subcommand(
        ClapCommand::new("native-sync-rust")
            .about("Acquire original packages for an installed Rustup sysroot and emit its recipe and verified catalog")
            .arg(flag_infer_long("root").value_parser(clap::value_parser!(PathBuf)).required(true))
            .arg(flag_infer_long("client-config").value_parser(clap::value_parser!(PathBuf)).required(true))
            .arg(flag_infer_long("output").value_parser(clap::value_parser!(PathBuf)).required(true))
            .arg(flag_infer_long("recipe-output").value_parser(clap::value_parser!(PathBuf)).required(true))
            .arg(flag_infer_long("full").action(clap::ArgAction::SetTrue).help("Include installed non-build components such as documentation"))
            .arg(flag_infer_long("jobs").value_parser(clap::value_parser!(std::num::NonZeroUsize)).default_value("2").help("Maximum parallel package acquisitions")),
    ).subcommand(
        ClapCommand::new("native-attest-installation")
            .about("Verify installed files against original package manifests for reuse by compiler clients")
            .arg(flag_infer_long("root").value_parser(clap::value_parser!(PathBuf)).required(true))
            .arg(flag_infer_long("manifest").value_parser(clap::value_parser!(PathBuf)).action(clap::ArgAction::Append))
            .arg(flag_infer_long("recipe").value_parser(clap::value_parser!(PathBuf)))
            .group(ArgGroup::new("installation_input").args(["manifest", "recipe"]).required(true))
            .arg(flag_infer_long("output").value_parser(clap::value_parser!(PathBuf)).required(true)),
    );
    command
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .subcommand(
            ClapCommand::new("auth")
                .about("Helper commands to generate authentication tokens")
                .subcommand_required(true)
                .subcommand(ClapCommand::new("generate-jwt-hs256-key"))
                .subcommand(
                    ClapCommand::new("generate-jwt-hs256-server-token")
                        .args(&[
                            flag_infer_long("server")
                                .help("Generate a key for the specified server")
                                .value_name("SERVER_ADDR")
                                .value_parser(clap::value_parser!(SocketAddr))
                                .required(true),
                            flag_infer_long("secret-key")
                                .help("Use specified key to create the token")
                                .value_name("KEY"),
                            config_with_help_message(
                                "Use the key from the scheduler config file at PATH",
                            ),
                        ])
                        .group(
                            ArgGroup::new("key_source_mutual_exclusion")
                                .args(["config", "secret-key"])
                                .required(true),
                        ),
                )
                .subcommand(
                    ClapCommand::new("generate-shared-token").arg(
                        flag_infer_long("bits")
                            .help("Use the specified number of bits of randomness")
                            .value_name("BITS")
                            .default_value("256")
                            .value_parser(TokenLength::from_bits),
                    ),
                ),
        )
        .subcommand(
            ClapCommand::new("native-decode-package").hide(true)
                .arg(flag_infer_long("compression").value_parser(["xz", "gzip", "tar"]).required(true))
                .arg(flag_infer_long("max-tar-bytes").value_parser(clap::value_parser!(u64)).required(true))
                .arg(flag_infer_long("memory-bytes").value_parser(clap::value_parser!(u64)).required(true))
        )
        .subcommand(
            package_args(ClapCommand::new("native-import-rust"))
                .about("Verify an original Rust installer archive in an exclusive offline store")
                .arg(flag_infer_long("store").value_parser(clap::value_parser!(PathBuf)).required(true))
                .arg(flag_infer_long("max-entries").value_parser(clap::value_parser!(usize)).default_value("100000"))
                .arg(flag_infer_long("max-expanded-bytes").value_parser(clap::value_parser!(u64)).default_value("8589934592"))
                .arg(flag_infer_long("max-tar-bytes").value_parser(clap::value_parser!(u64)).default_value("9663676416"))
        )
        .subcommand(
            package_args(ClapCommand::new("native-provision-rust"))
                .about("Provision or resolve an original Rust installer through a live scheduler")
                .arg(flag_infer_long("client-config").value_parser(clap::value_parser!(PathBuf)).required(true))
        )
        .subcommand(
            ClapCommand::new("native-audit")
                .about("Inspect a closed native index or consistent offline snapshot without changing it")
                .arg(flag_infer_long("index").value_parser(clap::value_parser!(PathBuf)).required(true))
                .arg(flag_infer_long("schema").requires("without"))
                .arg(flag_infer_long("without").action(clap::ArgAction::Append).requires("schema")),
        )
        .subcommand(
            ClapCommand::new("scheduler")
                .about(
                    "Launch as a scheduler, to dispatch distributed builds across multiple servers",
                )
                .args(&[
                    config_with_help_message("Use the scheduler config file at PATH")
                        .required(true),
                    syslog.clone(),
                ]),
        )
        .subcommand(
            ClapCommand::new("server")
                .about("Launch as a server, to handle distributed builds assigned by the scheduler")
                .args(&[
                    config_with_help_message("Use the server config file at PATH").required(true),
                    syslog,
                ]),
        )
}

fn check_init_syslog(name: &str, log_level: LogLevel) {
    let level = log::LevelFilter::from(log_level);
    drop(syslog::init(Facility::LOG_DAEMON, level, Some(name)));
}

/// Parse commandline `args` into a `Result<Command>` to execute.
pub fn try_parse_from(
    args: impl IntoIterator<Item = impl Into<OsString> + Clone>,
) -> anyhow::Result<Command> {
    let matches = get_clap_command().try_get_matches_from(args)?;

    Ok(match matches.subcommand() {
        Some(("auth", matches)) => Command::Auth(match matches.subcommand() {
            // Size based on https://briansmith.org/rustdoc/ring/hmac/fn.recommended_key_len.html
            Some(("generate-jwt-hs256-key", _)) => AuthSubcommand::Base64 { num_bytes: 256 / 8 },
            Some(("generate-jwt-hs256-server-token", matches)) => {
                let server_addr = matches
                    .get_one("server")
                    .context("clap did not provide required `server` value")?;
                let server_id = ServerId::new(*server_addr);

                let secret_key = if matches.contains_id("config") {
                    let config_path = matches
                        .get_one::<PathBuf>("config")
                        .context("clap did not provide required `config` value")?;
                    if let Some(config) = config::scheduler::from_path(config_path)? {
                        match config.server_auth {
                            config::scheduler::ServerAuth::JwtHS256 { secret_key } => secret_key,
                            config::scheduler::ServerAuth::Insecure
                            | config::scheduler::ServerAuth::Token { .. } => {
                                bail!("Scheduler not configured with JWT HS256")
                            }
                        }
                    } else {
                        bail!("Could not load config")
                    }
                } else {
                    matches
                        .get_one::<String>("secret-key")
                        .context("clap did not provide required `secret-key` value")?
                        .to_string()
                };

                AuthSubcommand::JwtHS256ServerToken {
                    secret_key,
                    server_id,
                }
            }
            Some(("generate-shared-token", matches)) => {
                let token_bits = matches
                    .get_one::<TokenLength>("bits")
                    .context("clap did not provide default `bits` value")?;

                AuthSubcommand::Base64 {
                    num_bytes: token_bits.as_bytes(),
                }
            }
            _ => unreachable!("Subcommand is enforced by clap"),
        }),
        Some(("native-decode-package", matches)) => Command::NativeDecodePackage {
            compression: package_compression(matches)?,
            max_tar_bytes: *matches
                .get_one::<u64>("max-tar-bytes")
                .context("missing decoded tar limit")?,
            memory_bytes: *matches
                .get_one::<u64>("memory-bytes")
                .context("missing memory limit")?,
        },
        Some(("native-provision-rust", matches)) => Command::NativeProvisionRust {
            client_config: matches
                .get_one::<PathBuf>("client-config")
                .context("missing client configuration")?
                .clone(),
            archive: matches.get_one::<PathBuf>("archive").cloned(),
            source: package_source(matches)?,
            manifest_output: matches.get_one::<PathBuf>("manifest-output").cloned(),
        },
        Some(("native-import-rust", matches)) => {
            let source = package_source(matches)?;
            Command::NativeImportRust {
                store: matches
                    .get_one::<PathBuf>("store")
                    .context("missing store path")?
                    .clone(),
                archive: matches.get_one::<PathBuf>("archive").cloned(),
                source,
                max_entries: *matches
                    .get_one::<usize>("max-entries")
                    .context("missing entry limit")?,
                max_expanded_bytes: *matches
                    .get_one::<u64>("max-expanded-bytes")
                    .context("missing expansion limit")?,
                max_tar_bytes: *matches
                    .get_one::<u64>("max-tar-bytes")
                    .context("missing decoded tar limit")?,
                manifest_output: matches.get_one::<PathBuf>("manifest-output").cloned(),
            }
        }
        #[cfg(target_os = "linux")]
        Some(("native-sync-rust", matches)) => Command::NativeSyncRust {
            root: matches
                .get_one::<PathBuf>("root")
                .context("missing installation root")?
                .clone(),
            client_config: matches
                .get_one::<PathBuf>("client-config")
                .context("missing client configuration")?
                .clone(),
            output: matches
                .get_one::<PathBuf>("output")
                .context("missing catalog output")?
                .clone(),
            recipe_output: matches
                .get_one::<PathBuf>("recipe-output")
                .context("missing recipe output")?
                .clone(),
            full: matches.get_flag("full"),
            jobs: *matches
                .get_one::<std::num::NonZeroUsize>("jobs")
                .context("missing acquisition concurrency")?,
        },
        #[cfg(target_os = "linux")]
        Some(("native-attest-installation", matches)) => Command::NativeAttestInstallation {
            root: matches
                .get_one::<PathBuf>("root")
                .context("missing installation root")?
                .clone(),
            manifests: matches
                .get_many::<PathBuf>("manifest")
                .into_iter()
                .flatten()
                .cloned()
                .collect(),
            recipe: matches.get_one::<PathBuf>("recipe").cloned(),
            output: matches
                .get_one::<PathBuf>("output")
                .context("missing catalog output")?
                .clone(),
        },
        Some(("native-audit", matches)) => Command::NativeAudit {
            index: matches
                .get_one::<PathBuf>("index")
                .context("missing native index path")?
                .clone(),
            schema: matches.get_one::<String>("schema").cloned(),
            without: matches
                .get_many::<String>("without")
                .into_iter()
                .flatten()
                .cloned()
                .collect(),
        },
        Some(("scheduler", matches)) => {
            if matches.contains_id("syslog") {
                let log_level = matches
                    .get_one::<LogLevel>("syslog")
                    .context("clap reported `syslog` present without a value")?;
                check_init_syslog("sccache-scheduler", *log_level);
            }

            let config_path = matches
                .get_one::<PathBuf>("config")
                .context("clap did not provide required `config` value")?;
            if let Some(config) = config::scheduler::from_path(config_path)? {
                Command::Scheduler(config)
            } else {
                bail!("Could not load config")
            }
        }
        Some(("server", matches)) => {
            if matches.contains_id("syslog") {
                let log_level = matches
                    .get_one::<LogLevel>("syslog")
                    .context("clap reported `syslog` present without a value")?;
                check_init_syslog("sccache-buildserver", *log_level);
            }

            let config_path = matches
                .get_one::<PathBuf>("config")
                .context("clap did not provide required `config` value")?;
            if let Some(config) = config::server::from_path(config_path)? {
                Command::Server(config)
            } else {
                bail!("Could not load config")
            }
        }
        _ => unreachable!("Subcommand is enforced by clap"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = "sccache-dist";

    fn auth_generate_shared_tokens_bits(bit_val: &'static str) -> Vec<&'static str> {
        vec![EXE, "auth", "generate-shared-token", "--bits", bit_val]
    }

    fn auth_generate_jwt_hs256_server_token(subcommand_args: &[&'static str]) -> Vec<&'static str> {
        let mut args = vec![EXE, "auth", "generate-jwt-hs256-server-token"];
        args.extend_from_slice(subcommand_args);
        args
    }

    #[test]
    fn debug_assert() {
        get_clap_command().debug_assert()
    }

    #[test]
    fn missing_required_subcommands_fails() {
        let args_sets = &[vec![EXE], vec![EXE, "auth"]];

        for args in args_sets {
            assert!(try_parse_from(args).is_err());
        }
    }

    #[test]
    fn invalid_token_bits_fails() {
        let invalid_vals = vec!["not_a_num", "58", "8000", "70"];

        for invalid_val in invalid_vals {
            let args = auth_generate_shared_tokens_bits(invalid_val);
            assert!(try_parse_from(args).is_err());
        }
    }

    #[test]
    fn auth_generate_server_token_needs_key_source() {
        let server_args = &["--server", "127.0.0.1:4321"];

        let no_key = auth_generate_jwt_hs256_server_token(server_args);
        assert!(try_parse_from(no_key).is_err());

        let mut too_many_keys = auth_generate_jwt_hs256_server_token(server_args);
        too_many_keys.extend_from_slice(&["--secret-key", "secret", "--config", "some/path.toml"]);
        assert!(try_parse_from(too_many_keys).is_err());
    }

    // This is all just to work around `PartialEq` not being on some of the values used in variants
    // for `Command` yet
    fn assert_args_parse_to_auth(args: Vec<&'static str>, ideal_auth: AuthSubcommand) {
        match try_parse_from(&args) {
            Ok(Command::Auth(auth)) => assert_eq!(auth, ideal_auth),
            _ => panic!("Bad parsing for: {:#?}", args),
        }
    }

    #[test]
    fn auth_generate_jwt_hs256_key_good() {
        let args = vec![EXE, "auth", "generate-jwt-hs256-key"];

        assert_args_parse_to_auth(args, AuthSubcommand::Base64 { num_bytes: 256 / 8 });
    }

    #[test]
    fn auth_generate_jwt_hs256_server_token_good() {
        let base = auth_generate_jwt_hs256_server_token(&["--server", "127.0.0.1:4321"]);
        let server_socket: SocketAddr = "127.0.0.1:4321".parse().unwrap();
        let server_id = ServerId::new(server_socket);

        let mut secret_key = base.clone();
        secret_key.extend_from_slice(&["--secret-key", "very secret"]);
        assert_args_parse_to_auth(
            secret_key,
            AuthSubcommand::JwtHS256ServerToken {
                server_id,
                secret_key: "very secret".to_owned(),
            },
        );
    }

    #[test]
    fn auth_generate_shared_token_good() {
        let raw_to_expected_bit_vals = &[
            ("64", 64 / 8),
            ("128", 128 / 8),
            ("136", 136 / 8),
            ("4000", 4_000 / 8),
        ];

        for (raw, expected) in raw_to_expected_bit_vals {
            let args = auth_generate_shared_tokens_bits(raw);
            assert_args_parse_to_auth(
                args,
                AuthSubcommand::Base64 {
                    num_bytes: *expected,
                },
            );
        }
    }
}

fn package_compression(
    matches: &clap::ArgMatches,
) -> anyhow::Result<sccache::build_runtime::PackageCompression> {
    use sccache::build_runtime::PackageCompression;
    Ok(
        match matches.get_one::<String>("compression").map(String::as_str) {
            Some("xz") => PackageCompression::Xz,
            Some("gzip") => PackageCompression::Gzip,
            Some("tar") => PackageCompression::Tar,
            _ => anyhow::bail!("invalid package compression"),
        },
    )
}

fn package_args(command: ClapCommand) -> ClapCommand {
    command
        .arg(flag_infer_long("archive").value_parser(clap::value_parser!(PathBuf)))
        .arg(flag_infer_long("sha256").required(true))
        .arg(
            flag_infer_long("size")
                .value_parser(clap::value_parser!(u64))
                .required(true),
        )
        .arg(
            flag_infer_long("compression")
                .value_parser(["xz", "gzip", "tar"])
                .required(true),
        )
        .arg(flag_infer_long("manifest-output").value_parser(clap::value_parser!(PathBuf)))
}

fn package_source(
    matches: &clap::ArgMatches,
) -> anyhow::Result<sccache::build_runtime::PackageSource> {
    Ok(sccache::build_runtime::PackageSource {
        identity: sccache::build_runtime::PackageIdentity::from_sha256_hex(
            matches
                .get_one::<String>("sha256")
                .context("missing SHA-256")?,
            package_compression(matches)?,
        )?,
        size: *matches
            .get_one::<u64>("size")
            .context("missing package size")?,
    })
}
