#[macro_use]
extern crate log;

use anyhow::{Context, Result, bail};
use base64::Engine;
use sccache::build_runtime::{NetworkSnapshot, Peer};
use sccache::config::{
    INSECURE_DIST_CLIENT_TOKEN,
    scheduler::{self as scheduler_config, JobSlackConfig},
    server as server_config,
};
use sccache::dist::{
    self, AllocJobResult, AssignJobResult, BuilderIncoming, CompileCommand, HeartbeatServerResult,
    InputsReader, JobAlloc, JobAssignment, JobAuthorizer, JobComplete, JobId, JobState,
    NativeAssignment, OutputRequest, RunJobResult, SchedulerIncoming, SchedulerOutgoing,
    SchedulerStatusResult, ServerId, ServerIncoming, ServerNonce, ServerOutgoing,
    StagedToolchainArchive, SubmitToolchainResult, TcCache, Toolchain, ToolchainReader,
    UpdateJobStateResult,
};
use sccache::util::BASE64_URL_SAFE_ENGINE;
use sccache::util::daemonize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque, btree_map};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg_attr(target_os = "freebsd", path = "build_freebsd.rs")]
mod build;

mod cmdline;
mod command_helpers;
mod job_telemetry;
mod placement;
use placement::{Exploration, NativeTransferPlan, choose_worker, native_estimate};
#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
mod native_dispatch;
#[cfg(target_os = "linux")]
mod rustup;
#[cfg(target_os = "linux")]
mod system_packages;
mod token_check;
#[cfg(target_os = "linux")]
use native::NativeWorker;
#[cfg(target_os = "linux")]
use native_dispatch::NativeDispatcher;

use cmdline::{AuthSubcommand, Command};

pub const INSECURE_DIST_SERVER_TOKEN: &str = "dangerously_insecure_server";
const DIST_WORKER_NAME_ENV: &str = "SCCACHE_DIST_WORKER_NAME";

fn validate_worker_name(name: String) -> Result<String> {
    if name.is_empty() {
        bail!("distributed worker name must not be empty")
    }
    if name.len() > 253 {
        bail!("distributed worker name must be at most 253 bytes")
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("distributed worker name may contain only ASCII letters, digits, '.', '-' and '_'")
    }
    Ok(name)
}

fn dist_worker_name() -> Result<String> {
    if let Some(name) = env::var_os(DIST_WORKER_NAME_ENV) {
        let name = name
            .into_string()
            .map_err(|_| anyhow::anyhow!("{DIST_WORKER_NAME_ENV} is not valid UTF-8"))?;
        return validate_worker_name(name);
    }

    let name = hostname::get()
        .context("could not read distributed worker hostname")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("distributed worker hostname is not valid UTF-8"))?;
    validate_worker_name(name)
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    target_os = "freebsd"
)))]
fn main() {
    compile_error!("Distributed compilation is only supported on Linux/x86_64 and FreeBSD!");
}

// Only supported on x86_64 Linux machines and on FreeBSD
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    target_os = "freebsd"
))]
fn main() {
    init_logging();

    let incr_env_strs = ["CARGO_BUILD_INCREMENTAL", "CARGO_INCREMENTAL"];
    incr_env_strs
        .iter()
        .for_each(|incr_str| match env::var(incr_str) {
            Ok(incr_val) if incr_val == "1" => {
                println!(
                    "sccache: incremental compilation is prohibited: Unset {} to continue.",
                    incr_str
                );
                std::process::exit(1);
            }
            _ => (),
        });

    let command = match cmdline::try_parse_from(env::args()) {
        Ok(cmd) => cmd,
        Err(e) => match e.downcast::<clap::error::Error>() {
            Ok(clap_err) => clap_err.exit(),
            Err(some_other_err) => {
                println!("sccache-dist: {some_other_err}");
                for source_err in some_other_err.chain().skip(1) {
                    println!("sccache-dist: caused by: {source_err}");
                }
                std::process::exit(1);
            }
        },
    };

    std::process::exit(match run(command) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sccache-dist: error: {}", e);

            for e in e.chain().skip(1) {
                eprintln!("sccache-dist: caused by: {}", e);
            }
            2
        }
    });
}

fn create_server_token(server_id: ServerId, auth_token: &str) -> String {
    format!("{} {}", server_id, auth_token)
}
fn check_server_token(server_token: &str, auth_token: &str) -> Option<ServerId> {
    let mut split = server_token.splitn(2, ' ');
    let server_id = split.next().and_then(|id| id.parse().ok())?;
    match split.next() {
        Some(t) if t == auth_token => Some(server_id),
        Some(_) | None => None,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerJwt {
    exp: u64,
    server_id: ServerId,
}
fn create_jwt_server_token(
    server_id: ServerId,
    header: &jwt::Header,
    key: &[u8],
) -> Result<String> {
    anyhow::ensure!(key.len() == 256 / 8, "Size of secret key incorrect");
    let key = jwt::EncodingKey::from_secret(key)?;
    jwt::encode(header, &ServerJwt { exp: 0, server_id }, &key).map_err(Into::into)
}
fn dangerous_insecure_extract_jwt_server_token(server_token: &str) -> Result<ServerId> {
    jwt::dangerous::insecure_decode::<ServerJwt>(server_token)
        .map(|res| res.claims.server_id)
        .map_err(Into::into)
}
fn check_jwt_server_token(
    server_token: &str,
    key: &jwt::DecodingKey,
    validation: &jwt::Validation,
) -> Option<ServerId> {
    jwt::decode::<ServerJwt>(server_token, key, validation)
        .map(|res| res.claims.server_id)
        .ok()
}

/// Install metadata as one atomic file. Readers always see either the
/// complete old or complete new document, never a partial catalog.
fn write_installation_metadata(
    path: &Path,
    write: impl FnOnce(&mut std::fs::File) -> Result<()>,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    write(temp.as_file_mut())?;
    temp.as_file().sync_all()?;
    temp.persist(path)?;
    Ok(())
}

fn package_client(client_config: &Path) -> Result<sccache::dist::native::NativeCacheClient> {
    use sccache::{
        config::{DistAuth, FileConfig, try_read_config_file},
        dist::native::NativeCacheClient,
    };
    let config: FileConfig =
        try_read_config_file(client_config)?.context("client configuration unavailable")?;
    let native = config
        .dist
        .native
        .context("missing native client configuration")?;
    let DistAuth::Token { token } = config.dist.auth else {
        bail!("original-package provisioning requires token authentication");
    };
    let peer = dist::cluster::open_peer(
        config
            .dist
            .cluster
            .context("cluster trust configuration required")?,
        &config
            .dist
            .scheduler_url
            .context("scheduler endpoint required")?
            .to_url(),
        sccache_cluster_identity::Role::Client,
        &token,
    )?;
    NativeCacheClient::new(
        &native.endpoint.to_url(),
        peer,
        Duration::from_secs(native.request_timeout_secs),
        native.max_metadata_bytes,
    )
}

fn provision_rust_package(
    client_config: &Path,
    archive: Option<&Path>,
    source: sccache::build_runtime::PackageSource,
    manifest_output: Option<&Path>,
) -> Result<()> {
    let client = package_client(client_config)?;
    let (manifest, reused) = if let Some(manifest) = client.lookup_rust_package(source.identity)? {
        anyhow::ensure!(
            manifest.source == source,
            "original package length differs from verified source"
        );
        (manifest, true)
    } else {
        let archive = archive.context("upstream package unavailable; supply --archive")?;
        (
            client.import_rust_package(source, std::fs::File::open(archive)?)?,
            false,
        )
    };
    if let Some(path) = manifest_output {
        write_installation_metadata(path, |file| manifest.write(file))?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&package_report(source, &manifest, reused)?)?
    );
    Ok(())
}

fn package_report(
    source: sccache::build_runtime::PackageSource,
    manifest: &sccache::build_runtime::InstallationManifest,
    reused: bool,
) -> Result<serde_json::Value> {
    let components = manifest
        .components
        .iter()
        .map(|(name, tree)| Ok((name, tree.id()?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(serde_json::json!({
        "source": source,
        "package": manifest.package,
        "components": components,
        "reused_original_package": reused,
    }))
}

fn run(command: Command) -> Result<i32> {
    match command {
        Command::NativeDecodePackage {
            compression,
            max_tar_bytes,
            memory_bytes,
        } => {
            sccache::build_runtime::decode_package_process(
                compression,
                max_tar_bytes,
                memory_bytes,
            )?;
            Ok(0)
        }
        Command::NativeProvisionPackage {
            client_config,
            archive,
            identity,
            expected_size,
            locator,
        } => {
            use sccache::build_runtime::PackageSource;
            let client = package_client(&client_config)?;
            let (receipt, reused) = if let Some(receipt) = client.lookup_package(identity)? {
                (receipt, true)
            } else if let Some(locator) = locator {
                let acquired = client.acquire_package(&locator)?;
                (acquired.package, acquired.reused)
            } else {
                let archive = std::fs::File::open(archive.context(
                    "upstream package unavailable; supply --archive or --upstream and --path",
                )?)?;
                let size = archive.metadata()?.len();
                anyhow::ensure!(
                    expected_size.is_none_or(|expected| expected == size),
                    "original package length differs from supplied size"
                );
                (
                    client.import_package(PackageSource { identity, size }, archive)?,
                    false,
                )
            };
            anyhow::ensure!(
                expected_size.is_none_or(|expected| expected == receipt.source.size),
                "original package length differs from supplied size"
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "source": receipt.source, "package": receipt.tree, "reused_original_package": reused,
                }))?
            );
            Ok(0)
        }
        Command::NativeProvisionRust {
            client_config,
            archive,
            source,
            manifest_output,
        } => {
            provision_rust_package(
                &client_config,
                archive.as_deref(),
                source,
                manifest_output.as_deref(),
            )?;
            Ok(0)
        }
        Command::NativeImportRust {
            store,
            archive,
            source,
            max_entries,
            max_expanded_bytes,
            max_tar_bytes,
            manifest_output,
        } => {
            use sccache::build_runtime::{ArchiveLength, NativeStore, PackagePolicy};
            let mut policy = PackagePolicy::normalized_archive(
                max_entries,
                max_expanded_bytes,
                max_tar_bytes,
                64 * 1024 * 1024,
            )?;
            policy.retain_original = true;
            let store = NativeStore::open(&store)?;
            let (package, reused) = if let Some(existing) =
                store.lookup_package(source.identity, policy)?
            {
                anyhow::ensure!(
                    existing.source() == source,
                    "original package length differs from verified source"
                );
                (existing, true)
            } else {
                let archive = archive.context("upstream package unavailable; supply --archive")?;
                (
                    store.import_package(
                        source.identity,
                        ArchiveLength::Exact(source.size),
                        policy,
                        std::fs::File::open(archive)?,
                        sccache::build_runtime::PackageDecoder::Isolated {
                            executable: &std::env::current_exe()?,
                            memory_bytes: 512 * 1024 * 1024,
                            timeout: Duration::from_secs(600),
                        },
                    )?,
                    false,
                )
            };
            let before = store.stats()?;
            let manifest = store.publish_rust_installer(&package, policy.directory)?;
            if let Some(path) = manifest_output {
                write_installation_metadata(&path, |file| manifest.write(file))?;
            }
            let after = store.stats()?;
            anyhow::ensure!(
                before.logical_bytes == after.logical_bytes && before.blobs == after.blobs,
                "installer projection unexpectedly created content"
            );
            let mut report = package_report(source, &manifest, reused)?;
            report["logical_bytes"] = after.logical_bytes.into();
            report["blobs"] = after.blobs.into();
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(0)
        }
        #[cfg(target_os = "linux")]
        Command::NativeSyncSystem {
            client_config,
            paths,
            cache_dir,
            jobs,
        } => {
            let client = package_client(&client_config)?;
            let report = system_packages::sync_packages(&client, &paths, &cache_dir, jobs)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(0)
        }
        Command::NativeSyncRust {
            root,
            client_config,
            output,
            recipe_output,
            full,
            jobs,
        } => {
            rustup::sync(&root, &client_config, &output, &recipe_output, full, jobs)?;
            Ok(0)
        }
        #[cfg(target_os = "linux")]
        Command::NativeAttestInstallation {
            root,
            manifests,
            recipe,
            output,
        } => {
            use sccache::build_runtime::{
                InstallationCatalog, InstallationManifest, InstallationRecipe,
            };
            let manifests = if let Some(recipe) = recipe {
                InstallationRecipe::read(std::fs::File::open(recipe)?)?.selected_manifests()?
            } else {
                manifests
                    .iter()
                    .map(|path| InstallationManifest::read(std::fs::File::open(path)?))
                    .collect::<Result<Vec<_>>>()?
            };
            let (catalog, report) = InstallationCatalog::attest(&root, &manifests, Some(&output))?;
            write_installation_metadata(&output, |file| catalog.write(file))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(0)
        }
        Command::NativeAudit {
            index,
            schema,
            without,
        } => {
            let audit = sccache::build_runtime::NativeIndexAudit::open(&index)?;
            if let Some(schema) = schema {
                let comparison = audit.compare(&schema, &without)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "schema": schema,
                        "without": without,
                        "comparison": comparison,
                    }))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&audit.inventory()?)?);
            }
            Ok(0)
        }
        Command::ClusterInit { directory } => {
            anyhow::ensure!(
                directory.is_absolute(),
                "cluster directory must be absolute"
            );
            std::fs::create_dir_all(&directory)?;
            let ca = sccache_cluster_identity::ClusterCa::open(&directory.join("ca-key.pem"))?;
            let identity = sccache_cluster_identity::Identity::open(&directory.join("key.pem"))?;
            sccache_cluster_identity::publish_trust_anchor(
                ca.certificate(),
                &directory.join("ca.pem"),
            )?;
            println!("{}", identity.id()?);
            Ok(0)
        }
        Command::ClusterId { directory } => {
            anyhow::ensure!(directory.is_absolute(), "member directory must be absolute");
            std::fs::create_dir_all(&directory)?;
            println!(
                "{}",
                sccache_cluster_identity::Identity::open(&directory.join("key.pem"))?.id()?
            );
            Ok(0)
        }
        Command::ClusterRevoke { directory, peer } => {
            anyhow::ensure!(
                directory.is_absolute(),
                "cluster directory must be absolute"
            );
            let registry =
                sccache_cluster_identity::Registry::open(&directory.join("registry.bin"))?;
            registry.revoke(peer)?;
            Ok(0)
        }
        Command::ClusterStatus { client_config } => {
            use sccache::config::{DistAuth, FileConfig, try_read_config_file};
            use sccache_cluster_identity::Role;
            let config: FileConfig = try_read_config_file(&client_config)?
                .context("client configuration unavailable")?;
            let DistAuth::Token { token } = config.dist.auth else {
                bail!("cluster status requires token authentication")
            };
            let peer = dist::cluster::open_peer(
                config.dist.cluster.context("cluster trust required")?,
                &config
                    .dist
                    .scheduler_url
                    .context("scheduler endpoint required")?
                    .to_url(),
                Role::Client,
                &token,
            )?;
            let routes = dist::cluster::BlockingRoutes::for_peer(std::sync::Arc::clone(&peer));
            let (http, base) = routes.endpoint(
                peer.scheduler_id(),
                Role::Scheduler,
                peer.scheduler_address(),
            )?;
            let status: dist::SchedulerStatusResult = http
                .get(dist::http::urls::scheduler_status(&base)?)
                .header("Accept", "application/json")
                .timeout(Duration::from_secs(5))
                .send()?
                .error_for_status()?
                .json()?;
            println!("{}", serde_json::to_string(&status)?);
            Ok(0)
        }

        Command::Auth(AuthSubcommand::Base64 { num_bytes }) => {
            let mut bytes = vec![0; num_bytes];
            rand::fill(&mut bytes);
            // As long as it can be copied, it doesn't matter if this is base64 or hex etc
            println!("{}", BASE64_URL_SAFE_ENGINE.encode(bytes));
            Ok(0)
        }
        Command::Auth(AuthSubcommand::JwtHS256ServerToken {
            secret_key,
            server_id,
        }) => {
            let header = jwt::Header::new(jwt::Algorithm::HS256);
            let secret_key = BASE64_URL_SAFE_ENGINE.decode(secret_key)?;
            let token = create_jwt_server_token(server_id, &header, &secret_key)
                .context("Failed to create server token")?;
            println!("{}", token);
            Ok(0)
        }

        Command::Scheduler(scheduler_config::Config {
            cluster_directory,
            public_addr,
            client_auth,
            server_auth,
            maintenance_drain_file,
            job_slack,
            native_cache,
        }) => {
            let check_client_auth: Box<dyn dist::http::ClientAuthCheck> = match client_auth {
                scheduler_config::ClientAuth::Insecure => Box::new(token_check::EqCheck::new(
                    INSECURE_DIST_CLIENT_TOKEN.to_owned(),
                )),
                scheduler_config::ClientAuth::Token { token } => {
                    Box::new(token_check::EqCheck::new(token))
                }
                scheduler_config::ClientAuth::JwtValidate {
                    audience,
                    issuer,
                    jwks_url,
                } => Box::new(
                    token_check::ValidJWTCheck::new(audience, issuer, &jwks_url)
                        .context("Failed to create a checker for valid JWTs")?,
                ),
                scheduler_config::ClientAuth::ProxyToken { url, cache_secs } => {
                    Box::new(token_check::ProxyTokenCheck::new(url, cache_secs)?)
                }
            };

            let check_server_auth: dist::http::ServerAuthCheck = match server_auth {
                scheduler_config::ServerAuth::Insecure => {
                    warn!("Scheduler starting with DANGEROUSLY_INSECURE server authentication");
                    let token = INSECURE_DIST_SERVER_TOKEN;
                    Box::new(move |server_token| check_server_token(server_token, token))
                }
                scheduler_config::ServerAuth::Token { token } => {
                    Box::new(move |server_token| check_server_token(server_token, &token))
                }
                scheduler_config::ServerAuth::JwtHS256 { secret_key } => {
                    let secret_key = BASE64_URL_SAFE_ENGINE
                        .decode(secret_key)
                        .context("Secret key base64 invalid")?;
                    if secret_key.len() != 256 / 8 {
                        bail!("Size of secret key incorrect")
                    }
                    let key = jwt::DecodingKey::from_secret(&secret_key)
                        .context("Invalid JWT verification key")?;
                    let validation = {
                        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
                        validation.leeway = 0;
                        validation.validate_exp = false;
                        validation.validate_nbf = false;
                        validation
                    };
                    Box::new(move |server_token| {
                        check_jwt_server_token(server_token, &key, &validation)
                    })
                }
            };

            if maintenance_drain_file
                .as_deref()
                .is_some_and(|path| !path.is_absolute())
            {
                bail!("scheduler maintenance_drain_file must be absolute")
            }
            daemonize(&[])?;
            info!(
                "Distributed scheduler job slack: static={} percent={}%",
                job_slack.static_jobs, job_slack.percent
            );
            let scheduler =
                Scheduler::new_with_job_slack_and_drain(job_slack, maintenance_drain_file);
            if let Some(config) = &native_cache {
                config.session_limits()?;
                placement::start_checkpoint(
                    &scheduler.cost_book,
                    config.directory.join("action-costs.bin"),
                    config.public_addr,
                )?;
            }
            let http_scheduler = dist::http::Scheduler::new(
                cluster_directory,
                public_addr,
                scheduler,
                check_client_auth,
                check_server_auth,
                native_cache,
            );
            // A running server never exits successfully (Result<Infallible>).
            match http_scheduler.start()? {}
        }

        Command::Server(server_config::Config {
            cluster,
            builder,
            cache_dir,
            public_addr,
            bind_address,
            scheduler_url,
            scheduler_auth,
            toolchain_cache_size,
            toolchain_archive_sources,
            native_worker,
        }) => {
            let builder: Option<Box<dyn dist::BuilderIncoming>> = match builder {
                server_config::BuilderType::Native => None,
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Docker => Some(Box::new(
                    build::DockerBuilder::new().context("Docker builder failed to start")?,
                )),
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Overlay {
                    bwrap_path,
                    build_dir,
                    extracted_toolchain_cache_size,
                } => Some(Box::new(
                    build::OverlayBuilder::new(
                        bwrap_path,
                        build_dir,
                        extracted_toolchain_cache_size,
                    )
                    .context("Overlay builder failed to start")?,
                )),
                #[cfg(target_os = "freebsd")]
                server_config::BuilderType::Pot {
                    pot_fs_root,
                    clone_from,
                    pot_cmd,
                    pot_clone_args,
                } => Some(Box::new(
                    build::PotBuilder::new(pot_fs_root, clone_from, pot_cmd, pot_clone_args)
                        .context("Pot builder failed to start")?,
                )),
                _ => bail!("Builder type not supported on this platform: {builder:?}"),
            };
            if builder.is_none() {
                anyhow::ensure!(
                    native_worker.is_some(),
                    "native builder requires native_worker configuration"
                );
                anyhow::ensure!(
                    cache_dir.is_none() && toolchain_archive_sources.is_empty(),
                    "native-only worker cannot configure archive cache paths"
                );
            }
            let archive = builder
                .map(|builder| {
                    ArchiveWorker::new(
                        builder,
                        cache_dir
                            .as_deref()
                            .context("archive builder requires cache_dir")?,
                        toolchain_cache_size,
                        toolchain_archive_sources,
                    )
                })
                .transpose()?;

            let server_id = sccache_cluster_identity::open_identity(&cluster)?.id()?;
            let scheduler_auth = match scheduler_auth {
                server_config::SchedulerAuth::Insecure => {
                    warn!("Server starting with DANGEROUSLY_INSECURE scheduler authentication");
                    create_server_token(server_id, INSECURE_DIST_SERVER_TOKEN)
                }
                server_config::SchedulerAuth::Token { token } => {
                    create_server_token(server_id, &token)
                }
                server_config::SchedulerAuth::JwtToken { token } => {
                    let token_server_id: ServerId =
                        dangerous_insecure_extract_jwt_server_token(&token)
                            .context("Could not decode scheduler auth jwt")?;
                    if token_server_id != server_id {
                        bail!(
                            "JWT server id ({:?}) did not match configured server id ({:?})",
                            token_server_id,
                            server_id
                        )
                    }
                    token
                }
            };

            let peer = dist::cluster::open_peer(
                cluster,
                &scheduler_url.to_url(),
                sccache_cluster_identity::Role::Worker,
                &scheduler_auth,
            )?;
            #[cfg(target_os = "linux")]
            let native_worker = native_worker
                .map(|config| NativeWorker::new(config, std::sync::Arc::clone(&peer)))
                .transpose()?;
            #[cfg(not(target_os = "linux"))]
            if native_worker.is_some() {
                bail!("native worker requires Linux");
            }
            let server = Server::new(archive);
            #[cfg(target_os = "linux")]
            let server = Server {
                native_worker: native_worker
                    .map(|worker| {
                        NativeDispatcher::new(
                            worker,
                            std::sync::Arc::clone(&server.execution_queue),
                        )
                    })
                    .transpose()?,
                ..server
            };
            let worker_name = dist_worker_name()?;
            let http_server =
                dist::http::Server::new(public_addr, bind_address, peer, Some(worker_name), server)
                    .context("Failed to create sccache HTTP server instance")?;
            // A running server never exits successfully (Result<Infallible>).
            match http_server.start()? {}
        }
    }
}

fn init_logging() {
    // Job/PID mappings are only useful after a fatal worker failure if they
    // are in the journal by default; do not require an opt-in debug setting.
    let mut builder = env_logger::Builder::new();
    // Keep third-party dependencies quiet; the binary's job/scheduler
    // lifecycle is the information needed for postmortem reconstruction.
    builder.filter_level(log::LevelFilter::Warn);
    builder.filter_module(module_path!(), log::LevelFilter::Info);
    if let Ok(filters) = env::var(sccache::LOGGING_ENV) {
        builder.parse_filters(&filters);
    }
    if env::var("SCCACHE_LOG_MILLIS").is_ok() {
        builder.format_timestamp_millis();
    }
    if let Err(error) = builder.try_init() {
        eprintln!("sccache-dist: failed to initialize logging: {error}");
        std::process::exit(2);
    }
}

const SERVER_REMEMBER_ERROR_TIMEOUT: Duration = Duration::from_secs(300);
// Temporary fleet relief for slow input staging and toolchain uploads.
// Track progress explicitly instead of holding unclaimed reservations in #333.
const UNCLAIMED_PENDING_TIMEOUT: Duration = Duration::from_secs(900);
const UNCLAIMED_READY_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Copy, Clone)]
struct JobDetail {
    server_id: ServerId,
    state: JobState,
    // Time spent in the current phase, not the total time since allocation.
    state_since: Instant,
    // First heartbeat that did not report this Started job as executing.
    missing_since: Option<Instant>,
    inputs_staged_at: Option<Instant>,
    publication_began_at: Option<Instant>,
    assigned_at: Instant,
    prediction: Option<placement::PlacementEstimate>,
    observed_result: bool,
}

impl JobDetail {
    fn is_stale_unclaimed(self, now: Instant) -> bool {
        let age = now.duration_since(self.state_since);
        match self.state {
            JobState::Pending => age > UNCLAIMED_PENDING_TIMEOUT,
            JobState::Ready => age >= UNCLAIMED_READY_TIMEOUT,
            // Started jobs are owned by execution, not the unclaimed-job timeout.
            JobState::Started | JobState::Complete => false,
        }
    }

    fn transition_to(&mut self, state: JobState, now: Instant) {
        self.state = state;
        self.state_since = now;
        self.missing_since = None;
    }
}

const COMPLETION_ACK_RETRY_WINDOW: Duration = Duration::from_secs(600);
const MAX_COMPLETION_ACKS: usize = 16_384;

// Keep only terminal acknowledgments, not a second copy of active job state.
// A lost response to Complete can be retried, but an arbitrary unknown job
// must never be accepted as having completed.
#[derive(Default)]
struct CompletedJobAcks {
    recent: VecDeque<(JobId, ServerId, Instant)>,
}

impl CompletedJobAcks {
    fn prune(&mut self, now: Instant) {
        while self
            .recent
            .front()
            .is_some_and(|&(_, _, when)| now.duration_since(when) > COMPLETION_ACK_RETRY_WINDOW)
        {
            self.recent.pop_front();
        }
    }

    fn record(&mut self, job_id: JobId, server_id: ServerId, now: Instant) {
        self.prune(now);
        if self.recent.len() == MAX_COMPLETION_ACKS {
            self.recent.pop_front();
        }
        self.recent.push_back((job_id, server_id, now));
    }

    fn reconcile_native_queue(
        &mut self,
        owner: ServerId,
        queue: &mut dist::NativeQueueSnapshot,
        now: Instant,
    ) {
        use sccache::build_runtime::wire::NativeJobPhase;
        self.prune(now);
        // A known completed reservation may still have a replayable terminal
        // response on the worker. Preserve occupancy but never charge CPU
        // work from a snapshot captured before its completion.
        for &(id, server, completed) in &self.recent {
            if server == owner && queue.jobs.contains_key(&id) {
                placement::Milestone::reached(NativeJobPhase::Terminal, completed)
                    .apply(queue, id, now);
            }
        }
    }

    fn contains(&mut self, job_id: JobId, server_id: ServerId, now: Instant) -> bool {
        self.prune(now);
        self.recent
            .iter()
            .any(|&(id, owner, _)| id == job_id && owner == server_id)
    }
}

// To avoid deadlicking, make sure to do all locking at once (i.e. no further locking in a downward scope),
// in alphabetical order
pub struct Scheduler {
    // Job IDs are only meaningful inside a scheduler epoch. Build servers may
    // survive a scheduler restart and retain pending job IDs, so a restarted
    // scheduler must not begin again at JobId(0).
    job_id_base: u64,
    job_count: AtomicUsize,
    job_slack: JobSlackConfig,
    maintenance_drain_file: Option<PathBuf>,

    // Currently running jobs, can never be Complete
    jobs: Mutex<BTreeMap<JobId, JobDetail>>,
    servers: Mutex<HashMap<ServerId, ServerDetails>>,
    completed_acks: Mutex<CompletedJobAcks>,
    exploration: Mutex<Exploration>,
    cost_book: std::sync::Arc<Mutex<placement::CostBook>>,
}

struct ServerDetails {
    // Native input closures are reserved with the assignment, even before transfer.
    jobs_assigned: HashMap<JobId, Option<placement::AssignedNative>>,
    // Reservations for assignment RPCs still in flight. Once assigned,
    // the state and unclaimed timeout are owned exclusively by JobDetail.
    jobs_assigning: HashMap<JobId, Instant>,
    last_seen: Instant,
    last_error: Option<Instant>,
    cpu_capacity: f64,
    server_nonce: ServerNonce,
    worker_name: Option<String>,
    capabilities: dist::WorkerCapabilities,
    recent_residency: placement::RecentResidency,
    job_authorizer: Box<dyn JobAuthorizer>,
}

impl ServerDetails {
    fn apply_milestones(&mut self, now: Instant) {
        if let Some(placement) = &mut self.capabilities.native_placement {
            for (&id, assigned) in &self.jobs_assigned {
                if let Some(milestone) = assigned.as_ref().and_then(|job| job.milestone) {
                    milestone.apply(&mut placement.queue, id, now);
                }
            }
        }
    }

    fn native_milestone(
        &mut self,
        id: JobId,
        phase: sccache::build_runtime::wire::NativeJobPhase,
        now: Instant,
    ) {
        if let Some(assigned) = self.jobs_assigned.get_mut(&id).and_then(Option::as_mut) {
            placement::Milestone::advance(&mut assigned.milestone, phase, now);
            if let Some(milestone) = assigned.milestone
                && let Some(placement) = &mut self.capabilities.native_placement
            {
                milestone.apply(&mut placement.queue, id, now);
            }
        }
    }

    fn compiler_demand(&self) -> usize {
        self.capabilities.native_placement.as_ref().map_or_else(
            || self.jobs_assigned.len(),
            |placement| {
                placement
                    .queue
                    .compiler_demand(self.jobs_assigned.keys().copied())
            },
        )
    }

    fn native_headroom(&self) -> usize {
        if self.capabilities.archive {
            return usize::MAX;
        }
        self.capabilities
            .native_placement
            .as_ref()
            .map_or(0, |placement| {
                placement.queue.available_reservations(
                    self.jobs_assigned
                        .iter()
                        .filter_map(|(&id, inputs)| inputs.is_some().then_some(id)),
                )
            })
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Self::new_with_job_slack(JobSlackConfig::default())
    }

    fn new_with_job_slack(job_slack: JobSlackConfig) -> Self {
        Self::new_with_job_slack_and_drain(job_slack, None)
    }

    fn new_with_job_slack_and_drain(
        job_slack: JobSlackConfig,
        maintenance_drain_file: Option<PathBuf>,
    ) -> Self {
        let mut bytes = [0u8; size_of::<u64>()];
        rand::fill(&mut bytes);
        Self::with_job_id_base_and_slack_and_drain(
            u64::from_le_bytes(bytes),
            job_slack,
            maintenance_drain_file,
        )
    }

    #[cfg(test)]
    fn with_job_id_base(job_id_base: u64) -> Self {
        Self::with_job_id_base_and_slack(job_id_base, JobSlackConfig::default())
    }

    #[cfg(test)]
    fn with_job_id_base_and_slack(job_id_base: u64, job_slack: JobSlackConfig) -> Self {
        Self::with_job_id_base_and_slack_and_drain(job_id_base, job_slack, None)
    }

    fn with_job_id_base_and_slack_and_drain(
        job_id_base: u64,
        job_slack: JobSlackConfig,
        maintenance_drain_file: Option<PathBuf>,
    ) -> Self {
        Scheduler {
            job_id_base,
            job_count: AtomicUsize::new(0),
            job_slack,
            maintenance_drain_file,
            jobs: Mutex::new(BTreeMap::new()),
            servers: Mutex::new(HashMap::new()),
            completed_acks: Mutex::new(CompletedJobAcks::default()),
            exploration: Mutex::new(Exploration::default()),
            cost_book: std::sync::Arc::new(Mutex::new(placement::CostBook::default())),
        }
    }

    fn is_draining(&self) -> bool {
        let Some(path) = self.maintenance_drain_file.as_deref() else {
            return false;
        };
        match path.try_exists() {
            Ok(exists) => exists,
            Err(error) => {
                error!(
                    "Could not inspect scheduler maintenance drain file {}: {error}; failing closed",
                    path.display()
                );
                true
            }
        }
    }

    fn next_job_id(&self) -> JobId {
        let job_count = self.job_count.fetch_add(1, Ordering::Relaxed) as u64;
        JobId(self.job_id_base.wrapping_add(job_count))
    }

    fn prune_servers(
        &self,
        servers: &mut MutexGuard<HashMap<ServerId, ServerDetails>>,
        jobs: &mut MutexGuard<BTreeMap<JobId, JobDetail>>,
    ) {
        let now = Instant::now();

        let mut dead_servers = Vec::new();

        for (&server_id, details) in servers.iter_mut() {
            if now.duration_since(details.last_seen) > dist::http::HEARTBEAT_TIMEOUT {
                dead_servers.push(server_id);
            }
        }

        for server_id in dead_servers {
            warn!(
                "Server {} appears to be dead, pruning it in the scheduler",
                server_id
            );
            let Some(server_details) = servers.remove(&server_id) else {
                error!("server {server_id:?} disappeared while pruning");
                continue;
            };
            for job_id in server_details.jobs_assigned.into_keys() {
                warn!(
                    "dist_job_lost job_id={job_id} worker={} reason=heartbeat_timeout previous_state={:?}",
                    server_id,
                    jobs.get(&job_id).map(|detail| detail.state)
                );
                // A job may be missing here if it failed to allocate
                // initially, so just warn if it's not present.
                if jobs.remove(&job_id).is_none() {
                    warn!(
                        "Non-terminated job {} assignment originally failed.",
                        job_id
                    );
                }
            }
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

fn admission_weight(job_count: usize, cpu_capacity: f64, job_slack: JobSlackConfig) -> Option<f64> {
    (job_count < job_slack.max_jobs(cpu_capacity))
        .then_some((cpu_capacity - job_count as f64).max(0.0) + 0.5)
}

fn weighted_server(candidates: &[(ServerId, f64)], draw: f64) -> Option<ServerId> {
    let total: f64 = candidates.iter().map(|(_, weight)| weight).sum();
    let mut ticket = draw * total;
    for &(server_id, weight) in candidates {
        if weight > 0.0 {
            if ticket < weight {
                return Some(server_id);
            }
            ticket -= weight;
        }
    }
    candidates
        .iter()
        .rev()
        .find(|(_, weight)| *weight > 0.0)
        .map(|(id, _)| *id)
}

impl Scheduler {
    fn allocate_job(
        &self,
        requester: &dyn SchedulerOutgoing,
        mut assignment: JobAssignment,
        network: &NetworkSnapshot,
        packages: std::sync::Arc<sccache::build_runtime::PackageCatalog>,
    ) -> Result<AllocJobResult> {
        if self.is_draining() {
            return Ok(AllocJobResult::Fail {
                msg: "scheduler is draining for maintenance".to_owned(),
            });
        }
        let native = match &assignment {
            JobAssignment::Archive(_) => None,
            JobAssignment::Native(native) => Some(native.as_ref()),
        };
        let native_platform = native.map(|assignment| assignment.spec.platform);
        let native_inputs = native.map(|assignment| &assignment.input_blobs);
        let class = native
            .map(|assignment| placement::ActionClass::from_spec(&assignment.spec))
            .transpose()?;
        let assigned_at = Instant::now();
        let (job_id, server_id, auth, prediction, estimated_result_bytes) = {
            // LOCKS
            let mut servers = self
                .servers
                .lock()
                .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;

            let cost_book = self
                .cost_book
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let transfer_plan = native_inputs
                .as_ref()
                .map(|_| NativeTransferPlan::new(network, &servers, Some(&packages)));
            let res = {
                let mut healthy = Vec::new();
                let mut retry = Vec::new();
                let mut predictions = BTreeMap::new();
                let now = Instant::now();
                for (&server_id, details) in servers.iter_mut() {
                    let compatible = match native_platform {
                        Some(platform) => details.capabilities.native_platform == Some(platform),
                        None => details.capabilities.archive,
                    };
                    if !compatible {
                        continue;
                    }
                    let Some(weight) = admission_weight(
                        details.compiler_demand(),
                        details.cpu_capacity,
                        self.job_slack,
                    ) else {
                        continue;
                    };
                    let weight = if let (Some(inputs), Some(plan)) =
                        (native_inputs, transfer_plan.as_ref())
                    {
                        let Some(placement) = details.capabilities.native_placement.as_ref() else {
                            continue;
                        };
                        if !placement.queue.has_capacity(
                            details
                                .jobs_assigned
                                .iter()
                                .filter_map(|(&id, inputs)| inputs.is_some().then_some(id)),
                        ) {
                            continue;
                        }
                        let learned = class.zip(native_platform).map(|(class, platform)| {
                            cost_book.predict(
                                placement::WorkerScope {
                                    peer: server_id,
                                    platform,
                                },
                                class,
                                placement,
                                now,
                            )
                        });
                        let Some(forecast) = placement::WorkerForecast::new(details, learned)
                        else {
                            continue;
                        };
                        let estimate =
                            native_estimate(forecast, inputs, Peer::Worker(server_id), plan);
                        predictions.insert(server_id, estimate);
                        estimate.seconds
                    } else {
                        weight
                    };
                    if details.last_error.is_some_and(|when| {
                        now.duration_since(when) > SERVER_REMEMBER_ERROR_TIMEOUT
                    }) {
                        details.last_error = None;
                    }
                    if details.last_error.is_some() {
                        retry.push((server_id, weight));
                    } else {
                        healthy.push((server_id, weight));
                    }
                }
                let estimated_result_bytes =
                    class.zip(native_platform).and_then(|(class, platform)| {
                        cost_book.result_reservation(platform, class, now)
                    });
                drop(cost_book);
                let selected = [&healthy, &retry].into_iter().find_map(|candidates| {
                    if let (Some(inputs), Some(plan)) =
                        (native_inputs.as_ref(), transfer_plan.as_ref())
                    {
                        let mut history = self
                            .exploration
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        choose_worker(
                            candidates,
                            &servers,
                            inputs,
                            &predictions,
                            plan,
                            &mut history,
                            now,
                        )
                    } else {
                        weighted_server(candidates, rand::random::<f64>())
                    }
                });
                if let Some(server_id) = selected {
                    let server_details = servers.get_mut(&server_id).ok_or_else(|| {
                        anyhow::anyhow!("selected worker disappeared while scheduler lock held")
                    })?;
                    let job_id = self.next_job_id();
                    // Unique while holding the servers lock: every allocation
                    // advances job_count, including assignments that later fail.
                    // Token generation may fail. Never reserve worker capacity
                    // until an auth token is ready to send.
                    let auth = server_details
                        .job_authorizer
                        .generate_token(job_id)
                        .context("Could not create an auth token for this job")?;
                    let prediction = predictions.get(&server_id).copied();
                    if let Some(class) = class {
                        trace!(target: "native_placement_replay", "{}", serde_json::json!({
                            "kind": "assigned", "job": job_id.0, "worker": server_id, "class": class,
                            "candidates": predictions,
                            "estimated_result_bytes": estimated_result_bytes,
                            "host_prior": server_details.capabilities.native_placement.as_ref().map(placement::ActionCost::baseline),
                            "healthy": healthy.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
                        }));
                    }
                    let assigned = native_inputs.map(|inputs| placement::AssignedNative {
                        packages: std::sync::Arc::clone(&packages),
                        inputs: inputs.clone(),
                        class,
                        cost: predictions.get(&server_id).map(|estimate| estimate.cost),
                        milestone: None,
                    });
                    assert!(
                        server_details
                            .jobs_assigned
                            .insert(job_id, assigned)
                            .is_none()
                    );
                    assert!(
                        server_details
                            .jobs_assigning
                            .insert(job_id, Instant::now())
                            .is_none()
                    );

                    info!(
                        "Job {} created and will be assigned to server {:?}",
                        job_id, server_id
                    );
                    Some((job_id, server_id, auth, prediction, estimated_result_bytes))
                } else {
                    None
                }
            };

            if let Some(res) = res {
                res
            } else {
                let msg = format!(
                    "Insufficient capacity across {} available servers",
                    servers.len()
                );
                return Ok(AllocJobResult::Fail { msg });
            }
        };
        if let JobAssignment::Native(native) = &mut assignment {
            native.estimated_result_bytes = estimated_result_bytes;
        }
        let AssignJobResult {
            state,
            need_toolchain,
        } = requester
            .do_assign_job(server_id, job_id, assignment, auth.clone())
            .with_context(|| {
                // LOCKS
                let Ok(mut servers) = self.servers.lock() else {
                    return "assign job failed and server state mutex is poisoned";
                };
                if let Some(entry) = servers.get_mut(&server_id) {
                    entry.last_error = Some(Instant::now());
                    entry.jobs_assigning.remove(&job_id);
                    if entry.jobs_assigned.remove(&job_id).is_none() {
                        "assign job failed and job not known to the server"
                    } else {
                        "assign job failed, job un-assigned from the server"
                    }
                } else {
                    "assign job failed and server not known"
                }
            })?;
        {
            // LOCKS
            let mut jobs = self
                .jobs
                .lock()
                .map_err(|_| anyhow::anyhow!("jobs mutex poisoned"))?;
            let mut servers = self
                .servers
                .lock()
                .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;

            let Some(details) = servers.get_mut(&server_id) else {
                let msg = format!("Job {job_id} assignment completed after server disappeared");
                warn!("{msg}");
                return Ok(AllocJobResult::Fail { msg });
            };
            if !details.jobs_assigned.contains_key(&job_id)
                || !details.jobs_assigning.contains_key(&job_id)
            {
                let msg = format!(
                    "Job {job_id} assignment reservation was cleaned up before allocation completed"
                );
                warn!("{msg}");
                return Ok(AllocJobResult::Fail { msg });
            }

            // Publish the job and retire its reservation under both locks.
            // A heartbeat can never see an assigned job with neither owner.
            assert!(
                jobs.insert(
                    job_id,
                    JobDetail {
                        server_id,
                        state,
                        state_since: Instant::now(),
                        missing_since: None,
                        inputs_staged_at: None,
                        publication_began_at: None,
                        assigned_at,
                        prediction,
                        observed_result: false,
                    }
                )
                .is_none()
            );
            details.jobs_assigning.remove(&job_id);
            info!(
                "Job {} successfully assigned and saved with state {:?}",
                job_id, state
            );
        }
        let job_alloc = JobAlloc {
            auth,
            job_id,
            server_id,
        };
        Ok(AllocJobResult::Success {
            job_alloc,
            need_toolchain,
        })
    }
}

impl SchedulerIncoming for Scheduler {
    fn handle_alloc_job(
        &self,
        requester: &dyn SchedulerOutgoing,
        tc: Toolchain,
    ) -> Result<AllocJobResult> {
        self.allocate_job(
            requester,
            JobAssignment::Archive(tc),
            &NetworkSnapshot::default(),
            Default::default(),
        )
    }

    fn handle_alloc_native_job(
        &self,
        requester: &dyn SchedulerOutgoing,
        assignment: NativeAssignment,
        network: &NetworkSnapshot,
        packages: std::sync::Arc<sccache::build_runtime::PackageCatalog>,
    ) -> Result<AllocJobResult> {
        assignment.spec.validate()?;
        self.allocate_job(
            requester,
            JobAssignment::Native(Box::new(assignment)),
            network,
            packages,
        )
    }

    fn observe_native_lifecycle(
        &self,
        server_id: ServerId,
        job: JobId,
        event: dist::NativeLifecycleEvent<'_>,
    ) {
        let now = Instant::now();
        // Same lock order as assignment and heartbeat processing. The
        // scheduler-epoch job ID ties the receipt to the current worker
        // incarnation even if the address is reused after a restart.
        let (Ok(mut jobs), Ok(mut servers)) = (self.jobs.lock(), self.servers.lock()) else {
            warn!("Native output locality update skipped: scheduler state poisoned");
            return;
        };
        let Some(detail) = jobs.get_mut(&job) else {
            return;
        };
        let Some(server) = servers.get_mut(&server_id) else {
            return;
        };
        if detail.server_id != server_id
            || !server.jobs_assigned.get(&job).is_some_and(Option::is_some)
        {
            return;
        }
        use sccache::build_runtime::wire::NativeJobPhase;
        match event {
            dist::NativeLifecycleEvent::InputsStaged => {
                detail.inputs_staged_at.get_or_insert(now);
                server.native_milestone(job, NativeJobPhase::Ready, now);
            }
            dist::NativeLifecycleEvent::Negotiated => {
                server.native_milestone(job, NativeJobPhase::Publishing, now);
                if detail.publication_began_at.is_none() {
                    detail.publication_began_at = Some(now);
                    if let Some(assigned) = server.jobs_assigned.get(&job).and_then(Option::as_ref)
                    {
                        server.recent_residency.record_inputs(&assigned.inputs, now);
                    }
                }
            }
            dist::NativeLifecycleEvent::Committed {
                manifest,
                retained_after_begin,
                observation,
            } => {
                if let Some(anchor) = detail.publication_began_at
                    && let Err(error) =
                        server
                            .recent_residency
                            .record(manifest, anchor, retained_after_begin, now)
                {
                    warn!("Native output locality update failed: {error:#}");
                }
                if !detail.observed_result && detail.publication_began_at.is_some() {
                    detail.observed_result = true;
                    server.native_milestone(job, NativeJobPhase::Terminal, now);
                    if let Some(assigned) = server.jobs_assigned.get(&job).and_then(Option::as_ref)
                    {
                        server.recent_residency.record_inputs(&assigned.inputs, now);
                    }
                    if let Some(assigned) = server.jobs_assigned.get(&job).and_then(Option::as_ref)
                        && let (Some(class), Some(observed)) = (
                            assigned.class,
                            observation.filter(|sample| {
                                sample.valid()
                                    && manifest.blobs().is_ok_and(|blobs| {
                                        sample.upload_bytes
                                            <= blobs.values().copied().fold(0, u64::saturating_add)
                                            && sample.upload_requests
                                                <= u64::try_from(blobs.len()).unwrap_or(u64::MAX)
                                    })
                            }),
                        )
                    {
                        if let Some(timing) = observed.worker_timing
                            && let Some(placement) = server.capabilities.native_placement.as_mut()
                        {
                            placement.timing.adopt(timing);
                        }
                        if let Some(platform) = server.capabilities.native_platform {
                            self.cost_book
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .observe(
                                    placement::WorkerScope {
                                        peer: server_id,
                                        platform,
                                    },
                                    class,
                                    observed,
                                    manifest.blobs().map_or(0, |blobs| {
                                        blobs.values().copied().fold(0, u64::saturating_add)
                                    }),
                                    now,
                                );
                        }
                        trace!(target: "native_placement_replay", "{}", serde_json::json!({
                            "kind": "completed", "job": job.0, "worker": server_id,
                            "class": class, "predicted_seconds": detail.prediction.map(|prediction| prediction.completion_seconds),
                            "actual_inputs_ready_seconds": detail.inputs_staged_at.map(|staged| staged.saturating_duration_since(detail.assigned_at).as_secs_f64()),
                            "actual_result_negotiation_seconds": detail.publication_began_at.map(|began| began.saturating_duration_since(detail.assigned_at).as_secs_f64()),
                            "actual_staging_start_seconds": (detail.state == JobState::Started).then(|| detail.state_since.saturating_duration_since(detail.assigned_at).as_secs_f64()),
                            "actual_seconds": now.saturating_duration_since(detail.assigned_at).as_secs_f64(),
                            "result_bytes": manifest.blobs().ok().map(|blobs| blobs.values().copied().fold(0_u64, u64::saturating_add)),
                            "execution_nanoseconds": observed.execution_nanoseconds,
                            "worker_timing": observed.worker_timing,
                            "warm_staging_nanoseconds": observed.warm_staging_nanoseconds,
                            "publication_setup_nanoseconds": observed.publication_setup_nanoseconds,
                            "upload_bytes": observed.upload_bytes, "upload_requests": observed.upload_requests,
                            "upload_nanoseconds": observed.upload_nanoseconds, "predicted_cost": assigned.cost,
                        }));
                    }
                }
            }
        }
        drop(servers);
        drop(jobs);
    }

    fn native_blob_sources(
        &self,
        blob: sccache::build_runtime::BlobRef,
        requester: Option<ServerId>,
    ) -> Result<Vec<dist::NativeBlobSource>> {
        let servers = self
            .servers
            .lock()
            .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;
        // Result receipts may name a just-produced blob that has not yet
        // appeared in a heartbeat. For result recovery prefer positive
        // inventory hints, but allow other native workers to answer exactly.
        let mut candidates = servers
            .iter()
            .filter_map(|(id, details)| {
                let placement = details.capabilities.native_placement.as_ref()?;
                let now = Instant::now();
                let pinned = details.jobs_assigned.iter().any(|(id, assigned)| {
                    placement
                        .queue
                        .jobs
                        .get(id)
                        .is_some_and(|progress| progress.phase.inputs_ready())
                        && assigned
                            .as_ref()
                            .is_some_and(|job| job.inputs.get(&blob.id) == Some(&blob.size))
                });
                let locality =
                    if pinned || details.recent_residency.retained(blob.id, blob.size, now) {
                        3_u8
                    } else if details.recent_residency.contains(blob.id, blob.size, now) {
                        2_u8
                    } else {
                        u8::from(
                            placement
                                .residency
                                .as_ref()
                                .is_some_and(|residency| residency.may_contain(blob.id)),
                        )
                    };
                (Some(*id) != requester
                    && details.last_seen.elapsed() < Duration::from_secs(20)
                    && details.last_error.is_none()
                    && (requester.is_none() || locality > 0))
                    .then_some((id, details, locality))
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable_by(|(a, left, left_predicted), (b, right, right_predicted)| {
            right_predicted
                .cmp(left_predicted)
                .then_with(|| right.last_seen.cmp(&left.last_seen))
                .then_with(|| a.cmp(b))
        });
        candidates
            .into_iter()
            .map(|(&server, details, _)| {
                Ok(dist::NativeBlobSource {
                    server,
                    token: details.job_authorizer.generate_blob_token(blob)?,
                })
            })
            .collect()
    }

    fn handle_heartbeat_server(
        &self,
        server_id: ServerId,
        server_nonce: ServerNonce,
        cpu_capacity: f64,
        active_job_ids: &[JobId],
        job_authorizer: Box<dyn JobAuthorizer>,
        mut capabilities: dist::WorkerCapabilities,
    ) -> Result<HeartbeatServerResult> {
        // LOCKS
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| anyhow::anyhow!("jobs mutex poisoned"))?;
        let mut servers = self
            .servers
            .lock()
            .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;

        self.prune_servers(&mut servers, &mut jobs);

        if !cpu_capacity.is_finite() || cpu_capacity < 0.0 {
            bail!("invalid worker CPU capacity {cpu_capacity}");
        }
        anyhow::ensure!(
            capabilities.archive || capabilities.native_platform.is_some(),
            "worker advertises no build engine"
        );
        anyhow::ensure!(
            capabilities.native_platform.is_some() == capabilities.native_placement.is_some(),
            "native worker telemetry must match advertised engine"
        );
        if let Some(placement) = &capabilities.native_placement {
            anyhow::ensure!(
                placement.timing.valid()
                    && placement.cache_path_rates.valid()
                    && placement.queue.valid()
                    && placement
                        .package_limits
                        .is_none_or(sccache::build_runtime::PackageDeliveryLimits::valid),
                "invalid native result or queue telemetry"
            );
            anyhow::ensure!(
                placement
                    .residency
                    .as_ref()
                    .is_none_or(sccache::build_runtime::BlobResidency::valid),
                "invalid native placement telemetry"
            );
        }
        match servers.get_mut(&server_id) {
            Some(ref mut details) if details.server_nonce == server_nonce => {
                let now = Instant::now();
                details.last_seen = now;
                details.cpu_capacity = cpu_capacity;
                if details.capabilities.native_platform == capabilities.native_platform
                    && let (Some(previous), Some(incoming)) = (
                        details.capabilities.native_placement.as_ref(),
                        capabilities.native_placement.as_mut(),
                    )
                {
                    incoming.timing.adopt(previous.timing);
                }
                details.capabilities = capabilities;
                details.apply_milestones(now);
                if let Some(placement) = &mut details.capabilities.native_placement {
                    self.completed_acks
                        .lock()
                        .map_err(|_| anyhow::anyhow!("completion acknowledgment mutex poisoned"))?
                        .reconcile_native_queue(server_id, &mut placement.queue, now);
                }
                details.recent_residency.reap(now);

                // Executing jobs and transfers with recent byte progress have
                // live request owners. A Started job missing from one heartbeat
                // can be an in-flight snapshot; require a full timeout of absence.
                let active: HashSet<JobId> = active_job_ids.iter().copied().collect();
                let stale_jobs: Vec<_> = details
                    .jobs_assigned
                    .keys()
                    .copied()
                    .filter(|job_id| match jobs.get_mut(job_id) {
                        Some(detail) if detail.server_id == server_id => {
                            if detail.state == JobState::Started {
                                if active.contains(job_id) {
                                    detail.missing_since = None;
                                    false
                                } else {
                                    let since = detail.missing_since.get_or_insert(now);
                                    now.duration_since(*since) >= dist::http::HEARTBEAT_TIMEOUT
                                }
                            } else if active.contains(job_id) {
                                // Renew the inactivity lease, not the maximum
                                // duration of a progressing toolchain transfer.
                                detail.state_since = now;
                                false
                            } else {
                                detail.is_stale_unclaimed(now)
                            }
                        }
                        Some(_) => false,
                        None => details.jobs_assigning.get(job_id).is_some_and(|&since| {
                            now.duration_since(since) > UNCLAIMED_PENDING_TIMEOUT
                        }),
                    })
                    .collect();

                if !stale_jobs.is_empty() {
                    warn!(
                        "The following stale jobs will be de-allocated: {:?}",
                        stale_jobs
                    );
                    for job_id in stale_jobs {
                        warn!(
                            "dist_job_lost job_id={job_id} worker={} reason=stale_assignment previous_state={:?}",
                            server_id,
                            jobs.get(&job_id).map(|detail| detail.state)
                        );
                        if details.jobs_assigned.remove(&job_id).is_none() {
                            warn!(
                                "Stale job for server {} not assigned: {}",
                                server_id, job_id
                            );
                        }
                        details.jobs_assigning.remove(&job_id);
                        jobs.remove(&job_id);
                    }
                }

                let mut assigned_job_ids: Vec<_> = details.jobs_assigned.keys().copied().collect();
                assigned_job_ids.sort_unstable();
                return Ok(HeartbeatServerResult {
                    is_new: false,
                    assigned_job_ids,
                });
            }
            Some(ref mut details) if details.server_nonce != server_nonce => {
                for job_id in details.jobs_assigned.keys() {
                    warn!(
                        "dist_job_lost job_id={job_id} worker={} reason=worker_restarted previous_state={:?}",
                        server_id,
                        jobs.get(job_id).map(|detail| detail.state)
                    );
                    if jobs.remove(job_id).is_none() {
                        warn!(
                            "Unknown job found when replacing server {}: {}",
                            server_id, job_id
                        );
                    }
                }
            }
            _ => (),
        }
        info!("Registered new server {:?}", server_id);
        servers.insert(
            server_id,
            ServerDetails {
                last_seen: Instant::now(),
                last_error: None,
                jobs_assigned: HashMap::new(),
                jobs_assigning: HashMap::new(),
                cpu_capacity,
                server_nonce,
                worker_name: None,
                capabilities,
                recent_residency: placement::RecentResidency::default(),
                job_authorizer,
            },
        );
        Ok(HeartbeatServerResult {
            is_new: true,
            assigned_job_ids: Vec::new(),
        })
    }

    fn handle_update_worker_name(
        &self,
        server_id: ServerId,
        server_nonce: ServerNonce,
        worker_name: String,
    ) -> Result<()> {
        let worker_name = validate_worker_name(worker_name)?;
        // Match heartbeat lock ordering so a stale named worker cannot reserve
        // a display name after it has stopped heartbeating.
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| anyhow::anyhow!("jobs mutex poisoned"))?;
        let mut servers = self
            .servers
            .lock()
            .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;
        self.prune_servers(&mut servers, &mut jobs);
        drop(jobs);
        let details = servers.get(&server_id).ok_or_else(|| {
            anyhow::anyhow!("worker name update from unknown server {}", server_id)
        })?;
        if details.server_nonce != server_nonce {
            bail!("worker name update from stale server epoch {}", server_id)
        }
        if let Some(existing) = details.worker_name.as_ref() {
            if existing == &worker_name {
                return Ok(());
            }
            bail!(
                "distributed worker {} changed name from {:?} to {:?} without restarting",
                server_id,
                existing,
                worker_name
            )
        }
        if servers.iter().any(|(&id, details)| {
            id != server_id && details.worker_name.as_ref() == Some(&worker_name)
        }) {
            bail!(
                "distributed worker name {worker_name:?} is already registered by another active server"
            )
        }
        servers
            .get_mut(&server_id)
            .ok_or_else(|| anyhow::anyhow!("server disappeared while scheduler lock held"))?
            .worker_name = Some(worker_name.clone());
        info!(
            "Server {:?} registered worker name {:?}",
            server_id, worker_name
        );
        Ok(())
    }

    fn handle_get_worker_name(&self, server_id: ServerId) -> Result<Option<String>> {
        Ok(self
            .servers
            .lock()
            .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?
            .get(&server_id)
            .and_then(|details| details.worker_name.clone()))
    }

    fn handle_update_job_state(
        &self,
        job_id: JobId,
        server_id: ServerId,
        job_state: JobState,
    ) -> Result<UpdateJobStateResult> {
        // LOCKS
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| anyhow::anyhow!("jobs mutex poisoned"))?;
        let mut servers = self
            .servers
            .lock()
            .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;

        if let btree_map::Entry::Occupied(mut entry) = jobs.entry(job_id) {
            let job_detail = entry.get();
            if job_detail.server_id != server_id {
                bail!(
                    "Job id {} is not registered on server {:?}",
                    job_id,
                    server_id
                )
            }

            let details = servers.get_mut(&server_id).ok_or_else(|| {
                anyhow::anyhow!("Job state updated, but server is not known to scheduler")
            })?;
            if !details.jobs_assigned.contains_key(&job_id) {
                bail!("job {job_id} was not assigned to server {server_id:?}");
            }

            let now = Instant::now();
            details.last_seen = now;

            match (job_detail.state, job_state) {
                (current, requested) if current == requested => {}
                (JobState::Pending, JobState::Ready) | (JobState::Ready, JobState::Started) => {
                    entry.get_mut().transition_to(job_state, now);
                }
                (from, JobState::Complete)
                    if from == JobState::Started
                        || details
                            .jobs_assigned
                            .get(&job_id)
                            .is_some_and(Option::is_some) =>
                {
                    let mut acks = self
                        .completed_acks
                        .lock()
                        .map_err(|_| anyhow::anyhow!("completion acknowledgment mutex poisoned"))?;
                    // The worker has drained the assignment. Remember its verified
                    // inputs even if compilation itself failed.
                    if let Some(assigned) =
                        details.jobs_assigned.get(&job_id).and_then(Option::as_ref)
                        && assigned.milestone.is_some()
                    {
                        details
                            .recent_residency
                            .record_inputs(&assigned.inputs, now);
                    }
                    details.native_milestone(
                        job_id,
                        sccache::build_runtime::wire::NativeJobPhase::Terminal,
                        now,
                    );
                    details.jobs_assigned.remove(&job_id);
                    entry.remove_entry();
                    acks.record(job_id, server_id, now);
                }
                (from, to) => bail!("Invalid job state transition from {} to {}", from, to),
            }
            info!("Job {} updated state to {:?}", job_id, job_state);
        } else if job_state == JobState::Complete
            && self
                .completed_acks
                .lock()
                .map_err(|_| anyhow::anyhow!("completion acknowledgment mutex poisoned"))?
                .contains(job_id, server_id, Instant::now())
        {
            // The scheduler applied a prior completion, but its reply was lost.
            info!("Job {job_id} completion acknowledged again");
        } else {
            bail!("Unknown job {job_id} for server {server_id:?}")
        }
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_is_draining(&self) -> bool {
        self.is_draining()
    }

    fn handle_status(&self) -> Result<SchedulerStatusResult> {
        // LOCKS
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| anyhow::anyhow!("jobs mutex poisoned"))?;
        let mut servers = self
            .servers
            .lock()
            .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;

        self.prune_servers(&mut servers, &mut jobs);

        Ok(SchedulerStatusResult {
            num_servers: servers.len(),
            num_cpus: servers
                .values()
                .map(|v| v.cpu_capacity.ceil() as usize)
                .sum(),
            // Reservations are already consuming capacity while the assignment
            // RPC runs. Count them too, especially for maintenance drain checks.
            in_progress: servers.values().map(|v| v.jobs_assigned.len()).sum(),
            max_jobs: servers
                .values()
                .map(|v| self.job_slack.max_jobs(v.cpu_capacity))
                .fold(0, usize::saturating_add),
            available_jobs: if self.is_draining() {
                0
            } else {
                servers
                    .values()
                    .map(|v| {
                        self.job_slack
                            .max_jobs(v.cpu_capacity)
                            .saturating_sub(v.compiler_demand())
                            .min(v.native_headroom())
                    })
                    .fold(0, usize::saturating_add)
            },
        })
    }
}

struct LocalAssignment {
    assignment: JobAssignment,
    // Local time of receipt, not the scheduler's assignment timestamp.
    accepted_at: Instant,
}

#[cfg(target_os = "linux")]
struct NativeInputPins {
    _trees: Vec<sccache::build_runtime::TreeLease>,
    _blobs: sccache::build_runtime::UploadReservation,
}

struct ArchiveWorker {
    builder: Box<dyn BuilderIncoming>,
    cache: Mutex<TcCache>,
    staging_dir: PathBuf,
    toolchain_cache_size: u64,
    #[cfg(target_os = "linux")]
    toolchain_archive_sources: Vec<PathBuf>,
}

impl ArchiveWorker {
    fn new(
        builder: Box<dyn BuilderIncoming>,
        cache_dir: &Path,
        toolchain_cache_size: u64,
        toolchain_archive_sources: Vec<PathBuf>,
    ) -> Result<Self> {
        if toolchain_archive_sources
            .iter()
            .any(|path| !path.is_absolute())
        {
            bail!("toolchain archive sources must be absolute paths");
        }
        #[cfg(not(target_os = "linux"))]
        if !toolchain_archive_sources.is_empty() {
            bail!("local toolchain archive reflinks require Linux");
        }
        let cache = TcCache::new(&cache_dir.join("tc"), toolchain_cache_size)
            .context("Failed to create toolchain cache")?;
        Ok(Self {
            builder,
            cache: Mutex::new(cache),
            staging_dir: cache_dir.join("tc"),
            toolchain_cache_size,
            #[cfg(target_os = "linux")]
            toolchain_archive_sources,
        })
    }

    fn has_cached_toolchain(&self, tc: &Toolchain) -> Result<bool> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("toolchain cache mutex poisoned"))?;
        match cache.get_file(tc) {
            Ok(_) => Ok(true),
            Err(sccache::lru_disk_cache::Error::FileNotInCache) => Ok(false),
            Err(error) => Err(error).context("checking worker toolchain cache"),
        }
    }

    /// Try local archive sources before asking the client to upload. The
    /// cache mutex is not held while cloning or verifying archive contents.
    fn has_or_reuse_toolchain(&self, tc: &Toolchain) -> Result<bool> {
        if self.has_cached_toolchain(tc)? {
            return Ok(true);
        }
        #[cfg(target_os = "linux")]
        for source in &self.toolchain_archive_sources {
            match StagedToolchainArchive::clone_verified(
                &self.staging_dir,
                source,
                tc.clone(),
                self.toolchain_cache_size,
            ) {
                Ok(staged) => {
                    let mut cache = self
                        .cache
                        .lock()
                        .map_err(|_| anyhow::anyhow!("toolchain cache mutex poisoned"))?;
                    match cache.insert_staged(staged) {
                        Ok(()) => {
                            debug!("Reused local toolchain archive {}", tc.archive_id);
                            return Ok(true);
                        }
                        Err(error) => debug!("Could not install cloned archive: {error:#}"),
                    }
                }
                Err(error) => trace!(
                    "Local archive source {} unavailable: {error:#}",
                    source.display()
                ),
            }
        }
        self.has_cached_toolchain(tc)
    }
}

pub struct Server {
    archive: Option<ArchiveWorker>,
    execution_queue: std::sync::Arc<dist::execution_queue::ExecutionQueue>,
    job_toolchains: Mutex<HashMap<JobId, LocalAssignment>>,
    #[cfg(target_os = "linux")]
    native_worker: Option<NativeDispatcher>,
}

impl Server {
    fn new(archive: Option<ArchiveWorker>) -> Self {
        Self {
            archive,
            execution_queue: std::sync::Arc::new(dist::execution_queue::ExecutionQueue::new(
                std::num::NonZeroUsize::new(sccache::util::num_cpus())
                    .unwrap_or(std::num::NonZeroUsize::MIN),
            )),
            job_toolchains: Mutex::new(HashMap::new()),
            #[cfg(target_os = "linux")]
            native_worker: None,
        }
    }
}

impl Server {
    fn begin_execution(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
    ) -> Result<Option<LocalAssignment>> {
        let assigned = {
            let mut jobs = self
                .job_toolchains
                .lock()
                .map_err(|_| anyhow::anyhow!("job toolchain mutex poisoned"))?;
            match jobs.entry(job_id) {
                std::collections::hash_map::Entry::Occupied(entry) => Some(entry.remove()),
                _ => None,
            }
        };
        let Some(assigned) = assigned else {
            return Ok(None);
        };
        let transition = requester
            .do_update_job_state(job_id, JobState::Started)
            .and_then(|reply| match reply {
                UpdateJobStateResult::Success => Ok(()),
                UpdateJobStateResult::Fail { msg } => {
                    Err(anyhow::anyhow!("scheduler rejected start: {msg}"))
                }
            });
        if let Err(error) = transition {
            let mut jobs = self
                .job_toolchains
                .lock()
                .map_err(|_| anyhow::anyhow!("job toolchain mutex poisoned"))?;
            if jobs.insert(job_id, assigned).is_some() {
                bail!("job {job_id} reappeared while restoring failed start transition");
            }
            return Err(error).context("Updating job state failed");
        }
        Ok(Some(assigned))
    }
}

impl ServerIncoming for Server {
    fn executing_jobs(&self) -> usize {
        self.execution_queue.active()
    }

    fn handle_reconcile_assignments(
        &self,
        assigned_job_ids: &[JobId],
        heartbeat_started_at: Instant,
    ) -> Result<usize> {
        let known: HashSet<_> = assigned_job_ids.iter().copied().collect();
        let mut local = self
            .job_toolchains
            .lock()
            .map_err(|_| anyhow::anyhow!("job toolchain mutex poisoned"))?;
        let before = local.len();
        local.retain(|id, assignment| {
            // A scheduler reservation precedes receipt by the worker. Do not
            // prune assignments received after the heartbeat request began.
            assignment.accepted_at >= heartbeat_started_at || known.contains(id)
        });
        let removed = before - local.len();
        drop(local);
        #[cfg(target_os = "linux")]
        let removed = removed
            + self.native_worker.as_ref().map_or(0, |dispatcher| {
                dispatcher.reconcile(&known, heartbeat_started_at)
            });
        Ok(removed)
    }

    fn capabilities(&self) -> dist::WorkerCapabilities {
        #[cfg(target_os = "linux")]
        let native_platform = self
            .native_worker
            .as_ref()
            .map(|dispatcher| dispatcher.worker().policy.platform);
        #[cfg(not(target_os = "linux"))]
        let native_platform = None;
        #[cfg(target_os = "linux")]
        let native_placement = self.native_worker.as_ref().map(NativeDispatcher::placement);
        #[cfg(not(target_os = "linux"))]
        let native_placement = None;
        dist::WorkerCapabilities {
            archive: self.archive.is_some(),
            native_platform,
            native_placement,
        }
    }

    fn native_metadata_limit(&self) -> Option<usize> {
        #[cfg(target_os = "linux")]
        {
            self.native_worker
                .as_ref()
                .map(|dispatcher| dispatcher.worker().metadata_limit)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    fn handle_native_blob(
        &self,
        blob: sccache::build_runtime::BlobRef,
    ) -> Result<Option<(std::fs::File, sccache::build_runtime::BlobEncoding)>> {
        #[cfg(target_os = "linux")]
        {
            self.native_worker
                .as_ref()
                .context("native worker unavailable")?
                .worker()
                .open_blob(blob)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = blob;
            Ok(None)
        }
    }

    fn handle_assign_native_job(
        &self,
        requester: std::sync::Arc<dyn ServerOutgoing>,
        job_id: JobId,
        assignment: NativeAssignment,
    ) -> Result<AssignJobResult> {
        #[cfg(target_os = "linux")]
        {
            self.native_worker
                .as_ref()
                .context("native worker unavailable")?
                .assign(job_id, assignment, requester)?;
            Ok(AssignJobResult {
                state: JobState::Ready,
                need_toolchain: false,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (requester, job_id, assignment);
            bail!("native worker requires Linux")
        }
    }

    fn handle_run_native_job(
        &self,
        job_id: JobId,
        request: sccache::build_runtime::wire::NativeRunRequest,
    ) -> Result<sccache::build_runtime::wire::NativeRunResult> {
        #[cfg(target_os = "linux")]
        {
            self.native_worker
                .as_ref()
                .context("native worker unavailable")?
                .poll(job_id, request)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (job_id, request);
            bail!("native worker requires Linux")
        }
    }

    fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = !self
            .archive
            .as_ref()
            .context("archive worker disabled")?
            .has_or_reuse_toolchain(&tc)?;
        let mut assignments = self
            .job_toolchains
            .lock()
            .map_err(|_| anyhow::anyhow!("job toolchain mutex poisoned"))?;
        match assignments.entry(job_id) {
            std::collections::hash_map::Entry::Occupied(_) => {
                bail!("duplicate assignment for job {job_id}")
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(LocalAssignment {
                    assignment: JobAssignment::Archive(tc),
                    accepted_at: Instant::now(),
                });
            }
        }
        drop(assignments);
        let state = if need_toolchain {
            JobState::Pending
        } else {
            // TODO: can start prepping the build environment now
            JobState::Ready
        };
        Ok(AssignJobResult {
            state,
            need_toolchain,
        })
    }
    fn handle_submit_toolchain(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        tc_rdr: ToolchainReader,
    ) -> Result<SubmitToolchainResult> {
        let archive = self.archive.as_ref().context("archive worker disabled")?;
        let tc = match self
            .job_toolchains
            .lock()
            .map_err(|_| anyhow::anyhow!("job toolchain mutex poisoned"))?
            .get(&job_id)
        {
            Some(LocalAssignment {
                assignment: JobAssignment::Archive(tc),
                ..
            }) => tc.clone(),
            Some(_) => return Ok(SubmitToolchainResult::JobNotFound),
            None => return Ok(SubmitToolchainResult::JobNotFound),
        };
        // Streaming and hashing large archives must not hold the cache mutex:
        // other toolchains still need to be assigned while uploads are slow.
        let staged = match StagedToolchainArchive::receive(
            &archive.staging_dir,
            tc,
            tc_rdr,
            archive.toolchain_cache_size,
        ) {
            Ok(staged) => staged,
            Err(error) => {
                warn!("Could not receive or verify toolchain archive: {error:#}");
                return Ok(SubmitToolchainResult::CannotCache);
            }
        };
        let inserted = archive
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("toolchain cache mutex poisoned"))?
            .insert_staged(staged);
        if let Err(error) = inserted {
            warn!("Could not install verified toolchain archive: {error:#}");
            return Ok(SubmitToolchainResult::CannotCache);
        }
        // Uploads can outlive a scheduler-side timeout. Never publish Ready
        // for a job that has since been removed by heartbeat reconciliation.
        if !self
            .job_toolchains
            .lock()
            .map_err(|_| anyhow::anyhow!("job toolchain mutex poisoned"))?
            .contains_key(&job_id)
        {
            return Ok(SubmitToolchainResult::JobNotFound);
        }
        requester
            .do_update_job_state(job_id, JobState::Ready)
            .context("Updating job state failed")?;
        Ok(SubmitToolchainResult::Success)
    }
    fn handle_run_job(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        command: CompileCommand,
        outputs: OutputRequest,
        inputs_rdr: InputsReader,
    ) -> Result<RunJobResult> {
        let Some(assigned) = self.begin_execution(requester, job_id)? else {
            return Ok(RunJobResult::JobNotFound);
        };
        let JobAssignment::Archive(toolchain) = assigned.assignment else {
            bail!("archive job assignment type changed");
        };

        let (crate_name, command_fingerprint) = job_telemetry::identity(&command);
        info!(
            "dist_job_start job_id={job_id} compiler={:?} crate_name={:?} command_fingerprint={command_fingerprint:016x} argument_count={}",
            command.executable,
            crate_name,
            command.arguments.len()
        );
        let started = Instant::now();
        let archive = self.archive.as_ref().context("archive worker disabled")?;
        let res = self
            .execution_queue
            .acquire(|| Ok(()))
            .and_then(|_permit| {
                archive
                    .builder
                    .run_build(job_id, toolchain, command, outputs, inputs_rdr, &archive.cache)
            })
            .map(|res| {
                info!(
                    "dist_job_result job_id={job_id} result=complete exit_code={} output_count={} elapsed_ms={}",
                    res.output.code,
                    res.outputs.len(),
                    started.elapsed().as_millis()
                );
                RunJobResult::Complete(JobComplete {
                    output: res.output,
                    outputs: res.outputs,
                })
            })
            .map_err(|error| {
                warn!(
                    "dist_job_result job_id={job_id} result=error elapsed_ms={} error={error:#}",
                    started.elapsed().as_millis()
                );
                error.context("run build failed")
            });
        requester
            .do_update_job_state(job_id, JobState::Complete)
            .context("Updating job state failed")?;
        res
    }
}

#[cfg(test)]
mod scheduler_tests {
    use super::*;

    fn test_toolchain(marker: char) -> Toolchain {
        Toolchain {
            archive_id: sccache::dist::ArchiveId::try_from(marker.to_string().repeat(64)).unwrap(),
        }
    }

    #[test]
    fn scheduler_instances_namespace_job_ids() {
        let scheduler0 = Scheduler::with_job_id_base(0x1000);
        let scheduler1 = Scheduler::with_job_id_base(0x2000);

        assert_eq!(scheduler0.next_job_id(), JobId(0x1000));
        assert_eq!(scheduler0.next_job_id(), JobId(0x1001));
        assert_eq!(scheduler1.next_job_id(), JobId(0x2000));
    }

    #[test]
    fn default_job_slack_preserves_historical_threshold() {
        let slack = JobSlackConfig::default();

        for cores in [1, 2, 7, 8, 12, 16, 64] {
            assert_eq!(slack.max_jobs(cores as f64), cores + 1 + cores / 8);
        }
        assert!(admission_weight(13, 12.0, slack).is_some());
        assert!(admission_weight(14, 12.0, slack).is_none());
    }

    #[test]
    fn configured_job_slack_can_queue_well_beyond_worker_width() {
        let slack = JobSlackConfig {
            static_jobs: 0,
            percent: 200.0,
        };

        assert_eq!(slack.max_jobs(12.0), 36);
        assert!(admission_weight(35, 12.0, slack).is_some());
        assert!(admission_weight(36, 12.0, slack).is_none());
        assert_eq!(slack.max_jobs(0.0), 1);
        assert_eq!(JobSlackConfig::default().max_jobs(0.0), 2);
    }

    #[test]
    fn free_cpu_weight_accounts_for_reservations_and_capacity_changes() {
        let slack = JobSlackConfig {
            static_jobs: 0,
            percent: 400.0,
        };
        assert_eq!(admission_weight(0, 2.5, slack), Some(3.0));
        assert_eq!(admission_weight(0, 0.01, slack), Some(0.51));
        assert_eq!(admission_weight(1, 2.5, slack), Some(2.0));
        assert_eq!(admission_weight(2, 2.5, slack), Some(1.0));
        assert_eq!(admission_weight(3, 2.5, slack), Some(0.5));
        assert_eq!(admission_weight(0, 0.0, slack), Some(0.5));
        assert!(admission_weight(1, 0.0, slack).is_none());
        assert!(admission_weight(0, f64::NAN, slack).is_none());
        let a: ServerId = ServerId::from_digest([1; 32]);
        let b: ServerId = ServerId::from_digest([2; 32]);
        let c: ServerId = ServerId::from_digest([3; 32]);
        let choices = [(a, 1.5), (b, 3.5), (c, 0.5)];
        assert_eq!(weighted_server(&choices, 0.0), Some(a));
        assert_eq!(weighted_server(&choices, 0.27), Some(a));
        assert_eq!(weighted_server(&choices, 0.28), Some(b));
        assert_eq!(weighted_server(&choices, 0.999), Some(c));
        assert_eq!(weighted_server(&[(c, 0.0)], 0.0), None);
    }

    pub(super) struct TestJobAuthorizer;

    impl JobAuthorizer for TestJobAuthorizer {
        fn generate_token(&self, _job_id: JobId) -> Result<String> {
            Ok(String::new())
        }

        fn verify_token(&self, _job_id: JobId, _token: &str) -> Result<()> {
            Ok(())
        }

        fn generate_blob_token(&self, _blob: sccache::build_runtime::BlobRef) -> Result<String> {
            Ok(String::new())
        }

        fn verify_blob_token(
            &self,
            _blob: sccache::build_runtime::BlobRef,
            _token: &str,
        ) -> Result<()> {
            Ok(())
        }
    }

    fn register_test_server(scheduler: &Scheduler, server_id: ServerId, nonce: ServerNonce) {
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce,
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
    }

    fn assert_no_assigned_jobs(scheduler: &Scheduler, server_id: &ServerId) {
        assert!(scheduler.jobs.lock().unwrap().is_empty());
        let servers = scheduler.servers.lock().unwrap();
        let details = servers.get(server_id).unwrap();
        assert!(details.jobs_assigned.is_empty());
        assert!(details.jobs_assigning.is_empty());
    }

    struct AcceptAssign;

    impl SchedulerOutgoing for AcceptAssign {
        fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _assignment: JobAssignment,
            _auth: String,
        ) -> Result<AssignJobResult> {
            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    #[test]
    fn native_eta_uses_transfer_speed_residency_and_queued_input_union() {
        use sccache::build_runtime::{BlobResidency, ContentId};
        let a = ContentId::of(b"a");
        let b = ContentId::of(b"b");
        let mut fast = dist::NativePlacement::default();
        fast.timing.transfer.download_bytes_per_second = 100_000_000;
        fast.timing.transfer.raw_request_nanoseconds = 0;
        let mut slow = fast.clone();
        slow.timing.transfer.download_bytes_per_second = 1_000_000;
        let inputs = BTreeMap::from([(a, 100_000_000), (b, 1_000_000)]);
        let empty = HashMap::new();
        let network = NetworkSnapshot::default();
        let plan = NativeTransferPlan::new(&network, &HashMap::new(), None);
        let peer = Peer::Worker(ServerId::from_digest([1; 32]));
        let eta = |capacity, assigned: &HashMap<_, _>, placement: &dist::NativePlacement| {
            native_estimate(
                placement::WorkerForecast {
                    capacity,
                    assigned,
                    placement,
                    recent: &placement::RecentResidency::default(),
                    cost: placement::ActionCost::baseline(placement),
                },
                &inputs,
                peer,
                &plan,
            )
            .seconds
        };
        assert!(eta(4.0, &empty, &fast) < eta(4.0, &empty, &slow));
        let mut filter = BlobResidency::for_count(2).unwrap();
        filter.insert(a);
        slow.residency = Some(filter);
        assert!(eta(4.0, &empty, &slow) < eta(4.0, &empty, &fast));
        let queued = HashMap::from([
            (
                JobId(1),
                Some(placement::AssignedNative {
                    packages: Default::default(),
                    inputs: inputs.clone(),
                    class: None,
                    cost: None,
                    milestone: None,
                }),
            ),
            (
                JobId(2),
                Some(placement::AssignedNative {
                    packages: Default::default(),
                    inputs: inputs.clone(),
                    class: None,
                    cost: None,
                    milestone: None,
                }),
            ),
        ]);
        assert_eq!(eta(4.0, &queued, &fast), eta(4.0, &empty, &fast));
        assert!(eta(1.0, &queued, &fast) > eta(4.0, &empty, &fast));
    }

    #[test]
    fn peer_blob_sources_exclude_requester_and_do_not_reserve_jobs() -> Result<()> {
        use sccache::build_runtime::{BlobRef, BlobResidency, ContentId};
        let scheduler = Scheduler::new();
        let requester: ServerId = ServerId::from_digest([1; 32]);
        let peer: ServerId = ServerId::from_digest([2; 32]);
        let empty: ServerId = ServerId::from_digest([3; 32]);
        let blob = BlobRef {
            id: ContentId::of(b"shared"),
            size: 6,
        };
        for (server, resident) in [(requester, true), (peer, true), (empty, false)] {
            let mut filter = BlobResidency::for_count(1).context("residency allocation")?;
            if resident {
                filter.insert(blob.id);
            }
            let placement = dist::NativePlacement {
                residency: Some(filter),
                ..Default::default()
            };
            scheduler.handle_heartbeat_server(
                server,
                ServerNonce::new(),
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities {
                    archive: false,
                    native_platform: Some(ContentId::of(server.to_string().as_bytes())),
                    native_placement: Some(placement),
                },
            )?;
        }
        let sources = scheduler.native_blob_sources(blob, Some(requester))?;
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].server, peer);
        let recovery = scheduler.native_blob_sources(blob, None)?;
        assert_eq!(recovery.len(), 3);
        assert_eq!(recovery[2].server, empty);
        for server in [requester, peer, empty] {
            assert_no_assigned_jobs(&scheduler, &server);
        }
        Ok(())
    }

    fn native_test_assignment(
        platform: sccache::build_runtime::ContentId,
        input_blobs: dist::NativeInputBlobs,
    ) -> Result<NativeAssignment> {
        use sccache::build_runtime::{
            BuildPath, CommandSpec, ExecutionRoot, ExecutionSpec, TreeId, TreeMetadata, TreeRecipe,
            TreeTimestamp, wire::Ticket,
        };
        Ok(NativeAssignment {
            ticket: Ticket([42; 32]),
            input_blobs,
            estimated_result_bytes: None,
            spec: ExecutionSpec {
                platform,
                root: ExecutionRoot {
                    id: TreeId([0; 32]),
                    recipe: TreeRecipe::union(
                        TreeMetadata {
                            mode: 0o755,
                            modified: TreeTimestamp {
                                seconds: 1,
                                nanoseconds: 0,
                            },
                        },
                        [TreeId([0; 32])],
                    ),
                },
                mounts: BTreeMap::new(),
                command: CommandSpec {
                    umask: 0o022,
                    executable: BuildPath::new(b"/bin/tool".to_vec())?,
                    arguments: Vec::new(),
                    cwd: BuildPath::new(b"/".to_vec())?,
                    environment: BTreeMap::new(),
                },
                outputs: BTreeMap::new(),
            },
        })
    }

    #[test]
    fn native_staged_closure_survives_stale_heartbeat_and_failed_compilation() -> Result<()> {
        use sccache::build_runtime::{BlobRef, ContentId, wire::NativeJobPhase};
        let scheduler = Scheduler::new();
        let worker: ServerId = ServerId::from_digest([1; 32]);
        let peer: ServerId = ServerId::from_digest([2; 32]);
        let platform = ContentId::of(b"native-staging-test");
        let nonce = ServerNonce::new();
        let capabilities = dist::WorkerCapabilities {
            archive: false,
            native_platform: Some(platform),
            native_placement: Some(dist::NativePlacement::default()),
        };
        let heartbeat = |active: &[JobId]| {
            scheduler.handle_heartbeat_server(
                worker,
                nonce.clone(),
                4.0,
                active,
                Box::new(TestJobAuthorizer),
                capabilities.clone(),
            )
        };
        heartbeat(&[])?;
        let blob = BlobRef {
            id: ContentId::of(b"input"),
            size: 512 << 20,
        };
        let AllocJobResult::Success { job_alloc, .. } = scheduler.handle_alloc_native_job(
            &AcceptAssign,
            native_test_assignment(platform, BTreeMap::from([(blob.id, blob.size)]))?,
            &NetworkSnapshot::default(),
            Default::default(),
        )?
        else {
            bail!("worker unavailable");
        };
        let id = job_alloc.job_id;
        assert!(scheduler.native_blob_sources(blob, Some(peer))?.is_empty());
        scheduler.observe_native_lifecycle(peer, id, dist::NativeLifecycleEvent::InputsStaged);
        assert!(scheduler.native_blob_sources(blob, Some(peer))?.is_empty());
        scheduler.observe_native_lifecycle(worker, id, dist::NativeLifecycleEvent::InputsStaged);
        heartbeat(&[id])?;
        assert_eq!(scheduler.native_blob_sources(blob, Some(peer))?.len(), 1);
        {
            let servers = scheduler.servers.lock().unwrap();
            let queue = &servers[&worker]
                .capabilities
                .native_placement
                .as_ref()
                .context("missing placement")?
                .queue;
            assert_eq!(queue.jobs[&id].phase, NativeJobPhase::Ready);
            assert_eq!(queue.jobs[&id].remaining_input_bytes, 0);
            assert_eq!(servers[&worker].compiler_demand(), 1);
        }
        scheduler.handle_update_job_state(id, worker, JobState::Complete)?;
        assert_eq!(scheduler.native_blob_sources(blob, Some(peer))?.len(), 1);
        assert_eq!(
            scheduler.servers.lock().unwrap()[&worker].compiler_demand(),
            0
        );
        // A heartbeat captured before completion can arrive after the
        // scheduler has removed the assignment. Its obsolete CPU charge
        // must not resurrect a completed job.
        let mut stale = capabilities.clone();
        let queue = &mut stale
            .native_placement
            .as_mut()
            .context("missing placement")?
            .queue;
        queue.compiler_active = 1;
        queue.jobs.insert(
            id,
            dist::NativeJobProgress {
                phase: NativeJobPhase::Executing,
                phase_nanoseconds: 0,
                remaining_input_bytes: 0,
                remaining_input_blobs: 0,
            },
        );
        scheduler.handle_heartbeat_server(
            worker,
            nonce,
            4.0,
            &[id],
            Box::new(TestJobAuthorizer),
            stale,
        )?;
        let servers = scheduler.servers.lock().unwrap();
        let details = &servers[&worker];
        let queue = &details
            .capabilities
            .native_placement
            .as_ref()
            .context("missing placement")?
            .queue;
        assert_eq!(queue.jobs[&id].phase, NativeJobPhase::Terminal);
        assert_eq!(queue.compiler_active, 0);
        assert_eq!(details.compiler_demand(), 0);
        assert_eq!(
            queue.available_reservations(std::iter::empty()),
            queue.capacity as usize - 1
        );
        drop(servers);
        Ok(())
    }

    #[test]
    fn native_completed_timing_supersedes_heartbeat_until_worker_restart() -> Result<()> {
        use sccache::build_runtime::{
            ContentId, ResultManifest,
            wire::{ActionObservation, WorkerTiming},
        };
        let scheduler = Scheduler::new();
        let worker: ServerId = ServerId::from_digest([1; 32]);
        let platform = ContentId::of(b"timing-platform");
        let nonce = ServerNonce::new();
        let capabilities = dist::WorkerCapabilities {
            archive: false,
            native_platform: Some(platform),
            native_placement: Some(dist::NativePlacement::default()),
        };
        let heartbeat = |nonce, caps, active: &[JobId]| {
            scheduler.handle_heartbeat_server(
                worker,
                nonce,
                4.0,
                active,
                Box::new(TestJobAuthorizer),
                caps,
            )
        };
        heartbeat(nonce.clone(), capabilities.clone(), &[])?;
        let AllocJobResult::Success { job_alloc, .. } = scheduler.handle_alloc_native_job(
            &AcceptAssign,
            native_test_assignment(platform, BTreeMap::new())?,
            &NetworkSnapshot::default(),
            Default::default(),
        )?
        else {
            bail!("worker unavailable");
        };
        let id = job_alloc.job_id;
        let timing = WorkerTiming {
            revision: 7,
            execution_nanoseconds: 50_000_000,
            ..Default::default()
        };
        let manifest = ResultManifest {
            outputs: BTreeMap::new(),
            stdout: None,
            stderr: None,
        };
        let observation = ActionObservation {
            worker_timing: Some(timing),
            warm_staging_nanoseconds: None,
            publication_setup_nanoseconds: None,
            execution_nanoseconds: 50_000_000,
            upload_bytes: 0,
            upload_requests: 0,
            upload_nanoseconds: 0,
        };
        scheduler.observe_native_lifecycle(worker, id, dist::NativeLifecycleEvent::Negotiated);
        scheduler.observe_native_lifecycle(
            worker,
            id,
            dist::NativeLifecycleEvent::Committed {
                manifest: &manifest,
                retained_after_begin: Duration::ZERO,
                observation: Some(observation),
            },
        );
        let current = || {
            scheduler.servers.lock().unwrap()[&worker]
                .capabilities
                .native_placement
                .as_ref()
                .unwrap()
                .timing
        };
        assert_eq!(current(), timing);
        heartbeat(nonce.clone(), capabilities.clone(), &[id])?;
        assert_eq!(current(), timing);
        let mut newer = capabilities.clone();
        let fresh = WorkerTiming {
            revision: 8,
            execution_nanoseconds: 60_000_000,
            ..timing
        };
        newer
            .native_placement
            .as_mut()
            .context("missing worker placement")?
            .timing = fresh;
        heartbeat(nonce, newer, &[id])?;
        assert_eq!(current(), fresh);
        heartbeat(ServerNonce::new(), capabilities, &[])?;
        assert_eq!(current(), WorkerTiming::default());
        Ok(())
    }

    #[test]
    fn native_producer_receipt_places_consumer_before_next_heartbeat() -> Result<()> {
        use sccache::build_runtime::{Artifact, BlobRef, ContentId, ResultManifest};
        let scheduler = Scheduler::new();
        let producer: ServerId = ServerId::from_digest([1; 32]);
        let other: ServerId = ServerId::from_digest([2; 32]);
        let platform = ContentId::of(b"test");
        let register = |id, execution_nanoseconds| {
            scheduler.handle_heartbeat_server(
                id,
                ServerNonce::new(),
                4.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities {
                    archive: false,
                    native_platform: Some(platform),
                    native_placement: Some(dist::NativePlacement {
                        timing: sccache::build_runtime::wire::WorkerTiming {
                            execution_nanoseconds,
                            ..Default::default()
                        },
                        ..Default::default()
                    }),
                },
            )
        };
        register(producer, 2_000_000_000)?;
        let network = NetworkSnapshot::default();
        let AllocJobResult::Success { job_alloc, .. } = scheduler.handle_alloc_native_job(
            &AcceptAssign,
            native_test_assignment(platform, BTreeMap::new())?,
            &network,
            Default::default(),
        )?
        else {
            bail!("producer not allocated")
        };
        assert_eq!(job_alloc.server_id, producer);
        let job = job_alloc.job_id;
        let blob = BlobRef {
            id: ContentId::of(b"result"),
            size: 512 << 20,
        };
        let manifest = ResultManifest {
            outputs: BTreeMap::from([("obj".into(), Artifact::File { blob, mode: None })]),
            stdout: None,
            stderr: None,
        };
        let committed = || dist::NativeLifecycleEvent::Committed {
            manifest: &manifest,
            retained_after_begin: Duration::from_secs(300),
            observation: None,
        };
        register(other, 1_000_000_000)?;
        scheduler.observe_native_lifecycle(producer, job, committed());
        assert!(scheduler.native_blob_sources(blob, Some(other))?.is_empty());
        scheduler.observe_native_lifecycle(producer, job, dist::NativeLifecycleEvent::Negotiated);
        scheduler.observe_native_lifecycle(other, job, committed());
        assert!(scheduler.native_blob_sources(blob, Some(other))?.is_empty());
        scheduler.observe_native_lifecycle(producer, job, committed());
        let sources = scheduler.native_blob_sources(blob, Some(other))?;
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].server, producer);
        scheduler.handle_update_job_state(job, producer, JobState::Complete)?;
        let AllocJobResult::Success { job_alloc, .. } = scheduler.handle_alloc_native_job(
            &AcceptAssign,
            native_test_assignment(platform, BTreeMap::from([(blob.id, blob.size)]))?,
            &network,
            Default::default(),
        )?
        else {
            bail!("consumer not allocated")
        };
        // Producer is slower but avoids fetching a 512 MiB dependency.
        assert_eq!(job_alloc.server_id, producer);
        // Worker incarnation changes invalidate the hints and prior job IDs.
        register(producer, 2_000_000_000)?;
        scheduler.observe_native_lifecycle(producer, job, dist::NativeLifecycleEvent::Negotiated);
        scheduler.observe_native_lifecycle(producer, job, committed());
        assert!(scheduler.native_blob_sources(blob, Some(other))?.is_empty());
        let AllocJobResult::Success { job_alloc, .. } = scheduler.handle_alloc_native_job(
            &AcceptAssign,
            native_test_assignment(platform, BTreeMap::from([(blob.id, blob.size)]))?,
            &network,
            Default::default(),
        )?
        else {
            bail!("consumer not allocated after restart")
        };
        assert_eq!(job_alloc.server_id, other);
        Ok(())
    }

    #[test]
    fn native_jobs_select_compatible_workers_using_shared_capacity() -> Result<()> {
        use sccache::build_runtime::ContentId;
        let scheduler = Scheduler::new_with_job_slack(JobSlackConfig {
            static_jobs: 0,
            percent: 0.0,
        });
        let a: ServerId = ServerId::from_digest([1; 32]);
        let b: ServerId = ServerId::from_digest([2; 32]);
        let nonce_a = ServerNonce::new();
        let nonce_b = ServerNonce::new();
        let platform = ContentId::of(b"native-test");
        scheduler.handle_heartbeat_server(
            a,
            nonce_a,
            1.0,
            &[],
            Box::new(TestJobAuthorizer),
            dist::WorkerCapabilities {
                archive: false,
                native_platform: Some(platform),
                native_placement: Some(dist::NativePlacement::default()),
            },
        )?;
        scheduler.handle_heartbeat_server(
            b,
            nonce_b,
            1.0,
            &[],
            Box::new(TestJobAuthorizer),
            dist::WorkerCapabilities {
                archive: true,
                native_platform: Some(ContentId::of(b"other")),
                native_placement: Some(dist::NativePlacement::default()),
            },
        )?;
        let assignment =
            native_test_assignment(platform, BTreeMap::from([(ContentId([1; 32]), 10)]))?;
        let AllocJobResult::Success { job_alloc, .. } = scheduler.handle_alloc_native_job(
            &AcceptAssign,
            assignment.clone(),
            &NetworkSnapshot::default(),
            Default::default(),
        )?
        else {
            bail!("compatible worker unavailable");
        };
        assert_eq!(job_alloc.server_id, a);
        assert_eq!(
            scheduler.servers.lock().unwrap()[&a].jobs_assigned[&job_alloc.job_id]
                .as_ref()
                .map(|job| &job.inputs),
            Some(&BTreeMap::from([(ContentId([1; 32]), 10)]))
        );
        assert!(matches!(
            scheduler.handle_alloc_native_job(
                &AcceptAssign,
                assignment,
                &NetworkSnapshot::default(),
                Default::default(),
            )?,
            AllocJobResult::Fail { .. }
        ));
        let AllocJobResult::Success { job_alloc, .. } =
            scheduler.handle_alloc_job(&AcceptAssign, test_toolchain('a'))?
        else {
            bail!("archive worker unavailable");
        };
        assert_eq!(job_alloc.server_id, b);
        Ok(())
    }

    #[test]
    fn scheduler_status_tracks_per_worker_admission_and_capacity_changes() {
        let scheduler = Scheduler::new_with_job_slack(JobSlackConfig {
            static_jobs: 0,
            percent: 200.0,
        });
        let ids: [ServerId; 3] = [
            ServerId::from_digest([1; 32]),
            ServerId::from_digest([2; 32]),
            ServerId::from_digest([3; 32]),
        ];
        let nonce = ServerNonce::new();
        for (id, cpus) in ids.into_iter().zip([1.0, 3.0, 0.0]) {
            scheduler
                .handle_heartbeat_server(
                    id,
                    nonce.clone(),
                    cpus,
                    &[],
                    Box::new(TestJobAuthorizer),
                    dist::WorkerCapabilities::ARCHIVE,
                )
                .unwrap();
        }
        let status = scheduler.handle_status().unwrap();
        assert_eq!(
            (status.num_cpus, status.max_jobs, status.available_jobs),
            (4, 13, 13)
        );
        for _ in 0..13 {
            assert!(matches!(
                scheduler
                    .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
                    .unwrap(),
                AllocJobResult::Success { .. }
            ));
        }
        assert!(matches!(
            scheduler
                .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
                .unwrap(),
            AllocJobResult::Fail { .. }
        ));
        let status = scheduler.handle_status().unwrap();
        assert_eq!(
            (status.in_progress, status.max_jobs, status.available_jobs),
            (13, 13, 0)
        );
        scheduler
            .handle_heartbeat_server(
                ids[0],
                nonce.clone(),
                0.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        scheduler
            .handle_heartbeat_server(
                ids[1],
                nonce,
                4.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        let status = scheduler.handle_status().unwrap();
        // Three jobs remain assigned to the now-busy worker; the other worker
        // can admit three more despite the fleet's nominal capacity being full.
        assert_eq!(
            (status.in_progress, status.max_jobs, status.available_jobs),
            (13, 14, 3)
        );
    }

    struct StatusDuringAssign<'a>(&'a Scheduler);

    impl SchedulerOutgoing for StatusDuringAssign<'_> {
        fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _assignment: JobAssignment,
            _auth: String,
        ) -> Result<AssignJobResult> {
            // Status must include reservations even before a JobDetail exists.
            let status = self.0.handle_status()?;
            assert_eq!(status.in_progress, 1);
            assert_eq!(status.available_jobs, status.max_jobs - 1);
            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    struct SnapshotDuringAssign<'a> {
        scheduler: &'a Scheduler,
        nonce: ServerNonce,
    }

    impl SchedulerOutgoing for SnapshotDuringAssign<'_> {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            _assignment: JobAssignment,
            _auth: String,
        ) -> Result<AssignJobResult> {
            let snapshot = self.scheduler.handle_heartbeat_server(
                server_id,
                self.nonce.clone(),
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )?;
            assert_eq!(snapshot.assigned_job_ids, vec![job_id]);
            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    #[test]
    fn heartbeat_reports_inflight_and_accepted_assignments() -> Result<()> {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } = scheduler.handle_alloc_job(
            &SnapshotDuringAssign {
                scheduler: &scheduler,
                nonce: nonce.clone(),
            },
            test_toolchain('c'),
        )?
        else {
            panic!("expected job allocation");
        };
        let snapshot = scheduler.handle_heartbeat_server(
            server_id,
            nonce.clone(),
            1.0,
            &[],
            Box::new(TestJobAuthorizer),
            dist::WorkerCapabilities::ARCHIVE,
        )?;
        assert_eq!(snapshot.assigned_job_ids, vec![job_alloc.job_id]);
        for state in [JobState::Ready, JobState::Started, JobState::Complete] {
            scheduler.handle_update_job_state(job_alloc.job_id, server_id, state)?;
        }
        let snapshot = scheduler.handle_heartbeat_server(
            server_id,
            nonce,
            1.0,
            &[],
            Box::new(TestJobAuthorizer),
            dist::WorkerCapabilities::ARCHIVE,
        )?;
        assert!(snapshot.assigned_job_ids.is_empty());
        Ok(())
    }

    #[test]
    fn status_counts_assignment_rpc_reservations() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        register_test_server(&scheduler, server_id, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&StatusDuringAssign(&scheduler), test_toolchain('c'))
            .unwrap()
        else {
            panic!("worker should accept job");
        };
        assert_eq!(scheduler.handle_status().unwrap().in_progress, 1);
        for state in [JobState::Ready, JobState::Started, JobState::Complete] {
            scheduler
                .handle_update_job_state(job_alloc.job_id, server_id, state)
                .unwrap();
        }
        assert_eq!(scheduler.handle_status().unwrap().in_progress, 0);
    }

    #[test]
    fn idle_workers_receive_jobs_proportional_to_cpu_capacity() {
        let scheduler = Scheduler::new();
        let ids: Vec<ServerId> = [1, 2, 3]
            .into_iter()
            .map(|i| ServerId::from_digest([i; 32]))
            .collect();

        for (&id, capacity) in ids.iter().zip([1.0, 3.0, 0.0]) {
            scheduler
                .handle_heartbeat_server(
                    id,
                    ServerNonce::new(),
                    capacity,
                    &[],
                    Box::new(TestJobAuthorizer),
                    dist::WorkerCapabilities::ARCHIVE,
                )
                .unwrap();
        }

        let mut observed = Vec::new();
        for _ in 0..1024 {
            let result = scheduler
                .handle_alloc_job(&AcceptAssign, test_toolchain('b'))
                .unwrap();
            let AllocJobResult::Success { job_alloc, .. } = result else {
                panic!("eligible idle workers must accept a job");
            };
            observed.push(job_alloc.server_id);
            for state in [JobState::Ready, JobState::Started, JobState::Complete] {
                scheduler
                    .handle_update_job_state(job_alloc.job_id, job_alloc.server_id, state)
                    .unwrap();
            }
        }

        let first = observed
            .iter()
            .filter(|&&selected| selected == ids[0])
            .count();
        assert!(
            (210..=350).contains(&first),
            "first worker received {first} jobs"
        );
        let busy = observed
            .iter()
            .filter(|&&selected| selected == ids[2])
            .count();
        assert!(
            (40..=150).contains(&busy),
            "busy worker received {busy} jobs"
        );
    }

    #[test]
    fn maintenance_drain_refuses_new_allocations_without_creating_job_state() {
        let dir = tempfile::tempdir().unwrap();
        let drain = dir.path().join("scheduler-drain");
        let scheduler =
            Scheduler::new_with_job_slack_and_drain(JobSlackConfig::default(), Some(drain.clone()));
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        register_test_server(&scheduler, server_id, ServerNonce::new());

        std::fs::write(&drain, b"drain").unwrap();
        assert!(scheduler.handle_is_draining());
        assert_eq!(scheduler.handle_status().unwrap().available_jobs, 0);
        let allocation = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
            .unwrap();
        assert!(matches!(allocation, AllocJobResult::Fail { .. }));
        assert_no_assigned_jobs(&scheduler, &server_id);

        std::fs::remove_file(&drain).unwrap();
        assert!(!scheduler.handle_is_draining());
        let allocation = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
            .unwrap();
        assert!(matches!(allocation, AllocJobResult::Success { .. }));
    }

    #[test]
    fn maintenance_drain_fails_closed_when_marker_lookup_errors() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_directory = dir.path().join("not-a-directory");
        std::fs::write(&not_a_directory, b"file").unwrap();
        let scheduler = Scheduler::new_with_job_slack_and_drain(
            JobSlackConfig::default(),
            Some(not_a_directory.join("drain")),
        );

        assert!(scheduler.handle_is_draining());
    }

    struct ReapDuringAssign<'a> {
        scheduler: &'a Scheduler,
        server_id: ServerId,
        server_nonce: ServerNonce,
    }

    impl SchedulerOutgoing for ReapDuringAssign<'_> {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            _assignment: JobAssignment,
            _auth: String,
        ) -> Result<AssignJobResult> {
            assert_eq!(server_id, self.server_id);

            {
                let mut servers = self.scheduler.servers.lock().unwrap();
                let details = servers.get_mut(&server_id).unwrap();
                *details.jobs_assigning.get_mut(&job_id).unwrap() = Instant::now()
                    .checked_sub(UNCLAIMED_PENDING_TIMEOUT + Duration::from_secs(1))
                    .unwrap();
            }

            let heartbeat = self.scheduler.handle_heartbeat_server(
                server_id,
                self.server_nonce.clone(),
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )?;
            assert!(!heartbeat.is_new);

            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    #[test]
    fn ready_transition_starts_its_own_unclaimed_timeout() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());

        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
            .unwrap()
        else {
            panic!("worker should accept job");
        };
        let job_id = job_alloc.job_id;
        {
            let mut jobs = scheduler.jobs.lock().unwrap();
            jobs.get_mut(&job_id).unwrap().state_since = Instant::now()
                .checked_sub(UNCLAIMED_PENDING_TIMEOUT + Duration::from_secs(1))
                .unwrap();
        }

        scheduler
            .handle_update_job_state(job_id, server_id, JobState::Ready)
            .unwrap();
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert_eq!(
            scheduler.jobs.lock().unwrap().get(&job_id).unwrap().state,
            JobState::Ready
        );
        {
            let mut jobs = scheduler.jobs.lock().unwrap();
            jobs.get_mut(&job_id).unwrap().state_since = Instant::now()
                .checked_sub(UNCLAIMED_READY_TIMEOUT + Duration::from_secs(1))
                .unwrap();
        }
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce,
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[test]
    fn progressing_pending_upload_renews_lease_but_inactive_upload_expires() -> Result<()> {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } =
            scheduler.handle_alloc_job(&AcceptAssign, test_toolchain('c'))?
        else {
            bail!("worker should accept job");
        };
        let job_id = job_alloc.job_id;
        let backdate = |scheduler: &Scheduler| {
            scheduler
                .jobs
                .lock()
                .unwrap()
                .get_mut(&job_id)
                .unwrap()
                .state_since = Instant::now()
                .checked_sub(UNCLAIMED_PENDING_TIMEOUT + Duration::from_secs(1))
                .unwrap();
        };
        backdate(&scheduler);
        scheduler.handle_heartbeat_server(
            server_id,
            nonce.clone(),
            1.0,
            &[job_id],
            Box::new(TestJobAuthorizer),
            dist::WorkerCapabilities::ARCHIVE,
        )?;
        assert!(
            !scheduler
                .jobs
                .lock()
                .unwrap()
                .get(&job_id)
                .unwrap()
                .is_stale_unclaimed(Instant::now())
        );
        // A later snapshot without progress cannot renew that lease.
        backdate(&scheduler);
        scheduler.handle_heartbeat_server(
            server_id,
            nonce,
            1.0,
            &[],
            Box::new(TestJobAuthorizer),
            dist::WorkerCapabilities::ARCHIVE,
        )?;
        assert_no_assigned_jobs(&scheduler, &server_id);
        Ok(())
    }

    #[test]
    fn pending_jobs_expire_but_started_jobs_remain_owned_by_execution() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());

        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
            .unwrap()
        else {
            panic!("worker should accept job");
        };
        {
            let mut jobs = scheduler.jobs.lock().unwrap();
            jobs.get_mut(&job_alloc.job_id).unwrap().state_since = Instant::now()
                .checked_sub(UNCLAIMED_PENDING_TIMEOUT + Duration::from_secs(1))
                .unwrap();
        }
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);

        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
            .unwrap()
        else {
            panic!("worker should accept another job");
        };
        for state in [JobState::Ready, JobState::Started] {
            scheduler
                .handle_update_job_state(job_alloc.job_id, server_id, state)
                .unwrap();
        }
        {
            let mut jobs = scheduler.jobs.lock().unwrap();
            jobs.get_mut(&job_alloc.job_id).unwrap().state_since = Instant::now()
                .checked_sub(UNCLAIMED_PENDING_TIMEOUT + Duration::from_secs(1))
                .unwrap();
        }
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce,
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert_eq!(
            scheduler
                .jobs
                .lock()
                .unwrap()
                .get(&job_alloc.job_id)
                .unwrap()
                .state,
            JobState::Started
        );
        scheduler
            .handle_update_job_state(job_alloc.job_id, server_id, JobState::Complete)
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    struct RejectToken;

    impl JobAuthorizer for RejectToken {
        fn generate_token(&self, _job_id: JobId) -> Result<String> {
            bail!("synthetic authorization failure")
        }

        fn verify_token(&self, _job_id: JobId, _token: &str) -> Result<()> {
            Ok(())
        }

        fn generate_blob_token(&self, _blob: sccache::build_runtime::BlobRef) -> Result<String> {
            bail!("synthetic authorization failure")
        }

        fn verify_blob_token(
            &self,
            _blob: sccache::build_runtime::BlobRef,
            _token: &str,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn failed_token_generation_never_reserves_capacity() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        scheduler
            .handle_heartbeat_server(
                server_id,
                ServerNonce::new(),
                1.0,
                &[],
                Box::new(RejectToken),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert!(
            scheduler
                .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
                .is_err()
        );
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[test]
    fn completion_without_assignment_does_not_discard_job() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        register_test_server(&scheduler, server_id, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
            .unwrap()
        else {
            panic!("worker should accept job");
        };
        for state in [JobState::Ready, JobState::Started] {
            scheduler
                .handle_update_job_state(job_alloc.job_id, server_id, state)
                .unwrap();
        }
        {
            let mut servers = scheduler.servers.lock().unwrap();
            servers
                .get_mut(&server_id)
                .unwrap()
                .jobs_assigned
                .remove(&job_alloc.job_id);
        }
        assert!(
            scheduler
                .handle_update_job_state(job_alloc.job_id, server_id, JobState::Complete)
                .is_err()
        );
        assert_eq!(
            scheduler
                .jobs
                .lock()
                .unwrap()
                .get(&job_alloc.job_id)
                .unwrap()
                .state,
            JobState::Started
        );
        {
            let mut servers = scheduler.servers.lock().unwrap();
            servers
                .get_mut(&server_id)
                .unwrap()
                .jobs_assigned
                .insert(job_alloc.job_id, None);
        }
        scheduler
            .handle_update_job_state(job_alloc.job_id, server_id, JobState::Complete)
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[test]
    fn started_jobs_reconcile_against_worker_running_inventory() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('d'))
            .unwrap()
        else {
            panic!("expected scheduler job allocation");
        };
        let job_id = job_alloc.job_id;
        for state in [JobState::Ready, JobState::Started] {
            scheduler
                .handle_update_job_state(job_id, server_id, state)
                .unwrap();
        }
        {
            let mut jobs = scheduler.jobs.lock().unwrap();
            jobs.get_mut(&job_id).unwrap().state_since = Instant::now()
                .checked_sub(UNCLAIMED_PENDING_TIMEOUT + Duration::from_secs(1))
                .unwrap();
        }
        // Running compilation can exceed every unclaimed-job timeout.
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                1.0,
                &[job_id],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert!(scheduler.jobs.lock().unwrap().contains_key(&job_id));

        // A single omitted heartbeat snapshot must not terminate a job.
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert!(scheduler.jobs.lock().unwrap().contains_key(&job_id));
        {
            let mut jobs = scheduler.jobs.lock().unwrap();
            jobs.get_mut(&job_id).unwrap().missing_since = Some(
                Instant::now()
                    .checked_sub(dist::http::HEARTBEAT_TIMEOUT + Duration::from_secs(1))
                    .unwrap(),
            );
        }
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce,
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);
        // Reconciliation is not a successful completion. A late terminal
        // message must not be disguised as a replayed acknowledgment.
        assert!(
            scheduler
                .handle_update_job_state(job_id, server_id, JobState::Complete)
                .is_err()
        );
    }

    #[test]
    fn only_the_completing_worker_can_retry_a_known_completion() -> Result<()> {
        let scheduler = Scheduler::new();
        let owner: ServerId = ServerId::from_digest([1; 32]);
        let other: ServerId = ServerId::from_digest([2; 32]);
        register_test_server(&scheduler, owner, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } =
            scheduler.handle_alloc_job(&AcceptAssign, test_toolchain('f'))?
        else {
            panic!("expected job");
        };
        let id = job_alloc.job_id;
        assert!(
            scheduler
                .handle_update_job_state(id, owner, JobState::Complete)
                .is_err()
        );
        assert!(
            scheduler
                .handle_update_job_state(JobId(id.0.wrapping_add(1)), owner, JobState::Complete)
                .is_err()
        );

        for state in [JobState::Ready, JobState::Started, JobState::Complete] {
            scheduler.handle_update_job_state(id, owner, state)?;
        }
        assert!(matches!(
            scheduler.handle_update_job_state(id, owner, JobState::Complete)?,
            UpdateJobStateResult::Success
        ));
        assert!(
            scheduler
                .handle_update_job_state(id, other, JobState::Complete)
                .is_err()
        );
        assert_no_assigned_jobs(&scheduler, &owner);
        Ok(())
    }

    #[test]
    fn recent_completion_acknowledgments_expire_and_are_bounded() -> Result<()> {
        let now = Instant::now();
        let owner: ServerId = ServerId::from_digest([1; 32]);
        let mut acks = CompletedJobAcks::default();
        for id in 0..MAX_COMPLETION_ACKS as u64 {
            acks.record(JobId(id), owner, now);
        }
        assert_eq!(acks.recent.len(), MAX_COMPLETION_ACKS);
        acks.record(JobId(MAX_COMPLETION_ACKS as u64), owner, now);
        assert_eq!(acks.recent.len(), MAX_COMPLETION_ACKS);
        assert!(!acks.contains(JobId(0), owner, now));
        assert!(acks.contains(JobId(1), owner, now));

        let expired = now + COMPLETION_ACK_RETRY_WINDOW + Duration::from_secs(1);
        assert!(!acks.contains(JobId(1), owner, expired));
        assert!(acks.recent.is_empty());
        Ok(())
    }

    #[test]
    fn returned_running_job_resets_missing_heartbeat_grace() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('d'))
            .unwrap()
        else {
            panic!("expected scheduler job allocation");
        };
        let job_id = job_alloc.job_id;
        for state in [JobState::Ready, JobState::Started] {
            scheduler
                .handle_update_job_state(job_id, server_id, state)
                .unwrap();
        }
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert!(
            scheduler
                .jobs
                .lock()
                .unwrap()
                .get(&job_id)
                .unwrap()
                .missing_since
                .is_some()
        );
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                1.0,
                &[job_id],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert!(
            scheduler
                .jobs
                .lock()
                .unwrap()
                .get(&job_id)
                .unwrap()
                .missing_since
                .is_none()
        );
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce,
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert!(scheduler.jobs.lock().unwrap().contains_key(&job_id));
        scheduler
            .handle_update_job_state(job_id, server_id, JobState::Complete)
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[test]
    fn state_acknowledgments_are_idempotent() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        register_test_server(&scheduler, server_id, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('d'))
            .unwrap()
        else {
            panic!("expected scheduler job allocation");
        };
        for state in [
            JobState::Ready,
            JobState::Ready,
            JobState::Started,
            JobState::Started,
            JobState::Complete,
            JobState::Complete,
        ] {
            assert!(matches!(
                scheduler
                    .handle_update_job_state(job_alloc.job_id, server_id, state)
                    .unwrap(),
                UpdateJobStateResult::Success
            ));
        }
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[test]
    fn worker_name_side_channel_is_optional_and_epoch_bound() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                8.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert_eq!(scheduler.handle_get_worker_name(server_id).unwrap(), None);

        scheduler
            .handle_update_worker_name(server_id, nonce.clone(), "worker-a".to_owned())
            .unwrap();
        assert_eq!(
            scheduler
                .handle_get_worker_name(server_id)
                .unwrap()
                .as_deref(),
            Some("worker-a")
        );
        scheduler
            .handle_update_worker_name(server_id, nonce, "worker-a".to_owned())
            .unwrap();

        let replacement_nonce = ServerNonce::new();
        let heartbeat = scheduler
            .handle_heartbeat_server(
                server_id,
                replacement_nonce,
                8.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        assert!(heartbeat.is_new);
        assert_eq!(scheduler.handle_get_worker_name(server_id).unwrap(), None);
    }

    #[test]
    fn duplicate_active_worker_names_are_rejected() {
        let scheduler = Scheduler::new();
        let first: ServerId = ServerId::from_digest([1; 32]);
        let second: ServerId = ServerId::from_digest([2; 32]);
        let first_nonce = ServerNonce::new();
        let second_nonce = ServerNonce::new();
        for (server_id, nonce) in [(first, first_nonce.clone()), (second, second_nonce.clone())] {
            scheduler
                .handle_heartbeat_server(
                    server_id,
                    nonce,
                    8.0,
                    &[],
                    Box::new(TestJobAuthorizer),
                    dist::WorkerCapabilities::ARCHIVE,
                )
                .unwrap();
        }
        scheduler
            .handle_update_worker_name(first, first_nonce, "worker-a".to_owned())
            .unwrap();
        let error = scheduler
            .handle_update_worker_name(second, second_nonce, "worker-a".to_owned())
            .unwrap_err();
        assert!(error.to_string().contains("already registered"));
    }

    #[test]
    fn worker_name_is_stable_within_server_epoch() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                8.0,
                &[],
                Box::new(TestJobAuthorizer),
                dist::WorkerCapabilities::ARCHIVE,
            )
            .unwrap();
        scheduler
            .handle_update_worker_name(server_id, nonce.clone(), "worker-a".to_owned())
            .unwrap();
        let error = scheduler
            .handle_update_worker_name(server_id, nonce, "worker-b".to_owned())
            .unwrap_err();
        assert!(error.to_string().contains("changed name"));
    }

    #[test]
    fn allocation_fails_if_assignment_is_cleaned_up() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let server_nonce = ServerNonce::new();

        register_test_server(&scheduler, server_id, server_nonce.clone());

        let requester = ReapDuringAssign {
            scheduler: &scheduler,
            server_id,
            server_nonce,
        };
        let allocation = scheduler
            .handle_alloc_job(&requester, test_toolchain('c'))
            .unwrap();

        assert!(matches!(allocation, AllocJobResult::Fail { .. }));
        assert_no_assigned_jobs(&scheduler, &server_id);
    }
}

#[cfg(test)]
mod server_upload_tests {
    use super::*;
    use sccache::util::Digest;
    use std::io::{self, Cursor, Read};
    use std::sync::{Arc, mpsc};
    use std::thread;

    struct NoopBuilder;

    impl BuilderIncoming for NoopBuilder {
        fn run_build(
            &self,
            _job_id: JobId,
            _toolchain: Toolchain,
            _command: CompileCommand,
            _outputs: OutputRequest,
            _inputs_rdr: InputsReader<'_>,
            _cache: &Mutex<TcCache>,
        ) -> Result<sccache::dist::BuildResult> {
            unreachable!("upload tests must never execute a compile");
        }
    }

    struct RecordingRequester(Mutex<Vec<JobState>>);

    impl ServerOutgoing for RecordingRequester {
        fn do_update_job_state(
            &self,
            _job_id: JobId,
            state: JobState,
        ) -> Result<UpdateJobStateResult> {
            self.0.lock().unwrap().push(state);
            Ok(UpdateJobStateResult::Success)
        }
    }

    fn test_server() -> Result<(tempfile::TempDir, Arc<Server>)> {
        let dir = tempfile::tempdir()?;
        let server = Server::new(Some(ArchiveWorker::new(
            Box::new(NoopBuilder),
            dir.path(),
            1024 * 1024,
            vec![],
        )?));
        Ok((dir, Arc::new(server)))
    }

    fn tc(contents: &[u8]) -> Result<Toolchain> {
        Ok(Toolchain {
            archive_id: sccache::dist::ArchiveId::try_from(Digest::reader_sync(contents)?)?,
        })
    }

    struct PausingReader {
        sent: bool,
        started: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
        inner: Cursor<Vec<u8>>,
    }

    impl Read for PausingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.sent {
                self.sent = true;
                self.started.send(()).unwrap();
                self.resume.recv().unwrap();
            }
            self.inner.read(buf)
        }
    }

    #[test]
    fn reconcile_removes_only_stale_unclaimed_assignments() -> Result<()> {
        let (_dir, server) = test_server()?;
        for id in [JobId(41), JobId(42)] {
            server.handle_assign_job(id, tc(b"older toolchain")?)?;
        }
        let heartbeat_started_at = Instant::now();
        // This assignment arrived after the heartbeat began and may be
        // legitimately absent from the scheduler's earlier snapshot.
        server.handle_assign_job(JobId(43), tc(b"new toolchain")?)?;

        assert_eq!(
            server.handle_reconcile_assignments(&[JobId(42)], heartbeat_started_at)?,
            1
        );
        {
            let jobs = server.job_toolchains.lock().unwrap();
            assert!(!jobs.contains_key(&JobId(41)));
            assert!(jobs.contains_key(&JobId(42)));
            assert!(jobs.contains_key(&JobId(43)));
        }
        let next_heartbeat = Instant::now();
        assert_eq!(
            server.handle_reconcile_assignments(&[JobId(43)], next_heartbeat)?,
            1
        );
        let jobs = server.job_toolchains.lock().unwrap();
        assert!(!jobs.contains_key(&JobId(42)));
        assert!(jobs.contains_key(&JobId(43)));
        Ok(())
    }

    #[test]
    fn removed_job_does_not_publish_ready_after_upload_finishes() -> Result<()> {
        let (_dir, server) = test_server()?;
        let job_id = JobId(71);
        let bytes = b"toolchain still uploading";
        server.handle_assign_job(job_id, tc(bytes)?)?;

        let (started_tx, started_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let uploader = Arc::clone(&server);
        let upload = thread::spawn(move || {
            let requester = RecordingRequester(Mutex::new(Vec::new()));
            let reader = PausingReader {
                sent: false,
                started: started_tx,
                resume: resume_rx,
                inner: Cursor::new(bytes.to_vec()),
            };
            let outcome = uploader.handle_submit_toolchain(
                &requester,
                job_id,
                ToolchainReader::new(Box::new(reader)),
            );
            (outcome, requester.0.lock().unwrap().clone())
        });
        started_rx.recv_timeout(Duration::from_secs(5))?;

        let removed = server.handle_reconcile_assignments(&[], Instant::now())?;
        // Always release the upload, even if the expected cleanup failed.
        resume_tx.send(())?;
        let (outcome, published) = upload.join().unwrap();
        assert_eq!(removed, 1);
        assert!(matches!(outcome?, SubmitToolchainResult::JobNotFound));
        assert!(published.is_empty());
        Ok(())
    }

    #[test]
    fn unknown_run_does_not_publish_any_job_state() -> Result<()> {
        let (_dir, server) = test_server()?;
        let requester = RecordingRequester(Mutex::new(Vec::new()));
        let result = server.handle_run_job(
            &requester,
            JobId(999),
            CompileCommand {
                umask: Some(0o022),
                executable: "cc".to_owned(),
                arguments: Vec::new(),
                env_vars: Vec::new(),
                cwd: "/tmp".to_owned(),
            },
            OutputRequest {
                paths: Vec::new(),
                compression_level: 3,
            },
            InputsReader::new(Box::new(Cursor::new(Vec::new()))),
        )?;
        assert!(matches!(result, RunJobResult::JobNotFound));
        assert!(requester.0.lock().unwrap().is_empty());
        Ok(())
    }

    struct RejectStartRequester;
    impl ServerOutgoing for RejectStartRequester {
        fn do_update_job_state(
            &self,
            _job_id: JobId,
            _state: JobState,
        ) -> Result<UpdateJobStateResult> {
            bail!("synthetic failure to acknowledge Started")
        }
    }

    #[test]
    fn failed_started_ack_restores_unclaimed_local_job() -> Result<()> {
        let (_dir, server) = test_server()?;
        let job_id = JobId(42);
        let toolchain = tc(b"custom toolchain")?;
        server.handle_assign_job(job_id, toolchain.clone())?;
        let failed = server.handle_run_job(
            &RejectStartRequester,
            job_id,
            CompileCommand {
                umask: Some(0o022),
                executable: "cc".to_owned(),
                arguments: Vec::new(),
                env_vars: Vec::new(),
                cwd: "/tmp".to_owned(),
            },
            OutputRequest {
                paths: Vec::new(),
                compression_level: 3,
            },
            InputsReader::new(Box::new(Cursor::new(Vec::new()))),
        );
        assert!(failed.is_err());
        assert_eq!(
            server
                .job_toolchains
                .lock()
                .unwrap()
                .get(&job_id)
                .and_then(|assigned| match &assigned.assignment {
                    JobAssignment::Archive(toolchain) => Some(toolchain),
                    JobAssignment::Native(_) => None,
                }),
            Some(&toolchain)
        );
        Ok(())
    }

    #[test]
    fn assignments_are_not_blocked_by_in_progress_toolchain_uploads() -> Result<()> {
        let (_dir, server) = test_server()?;
        let first = b"first valid toolchain archive";
        server.handle_assign_job(JobId(41), tc(first)?)?;
        let (started_tx, started_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let uploader = Arc::clone(&server);
        let upload = thread::spawn(move || {
            let requester = RecordingRequester(Mutex::new(Vec::new()));
            let reader = PausingReader {
                sent: false,
                started: started_tx,
                resume: resume_rx,
                inner: Cursor::new(first.to_vec()),
            };
            let outcome = uploader.handle_submit_toolchain(
                &requester,
                JobId(41),
                ToolchainReader::new(Box::new(reader)),
            );
            (outcome, requester.0.lock().unwrap().clone())
        });
        started_rx.recv_timeout(Duration::from_secs(5))?;

        let second_server = Arc::clone(&server);
        let (assignment_tx, assignment_rx) = mpsc::channel();
        let assignment = thread::spawn(move || {
            let result =
                second_server.handle_assign_job(JobId(42), tc(b"second toolchain").unwrap());
            assignment_tx.send(result).unwrap();
        });
        // Release the upload after checking the other assignment, even when
        // the assertion fails, so the test never leaves a blocked thread.
        let not_blocked = assignment_rx.recv_timeout(Duration::from_secs(2));
        resume_tx.send(())?;
        assignment.join().unwrap();
        let (upload_result, states) = upload.join().unwrap();
        assert!(
            not_blocked.is_ok(),
            "assignment was blocked by another toolchain's upload"
        );
        assert!(matches!(upload_result?, SubmitToolchainResult::Success));
        assert_eq!(states, vec![JobState::Ready]);
        Ok(())
    }

    #[test]
    fn missing_cached_archive_requires_fresh_upload_on_assignment() -> Result<()> {
        let (dir, server) = test_server()?;
        let contents = b"verified archive removed after publication";
        let toolchain = tc(contents)?;
        let root = dir.path().join("tc");
        let staged = StagedToolchainArchive::receive(
            &root,
            toolchain.clone(),
            contents.as_slice(),
            1024 * 1024,
        )?;
        let archive = server.archive.as_ref().context("archive worker disabled")?;
        archive.cache.lock().unwrap().insert_staged(staged)?;

        let first = server.handle_assign_job(JobId(45), toolchain.clone())?;
        assert!(!first.need_toolchain);
        assert!(matches!(first.state, JobState::Ready));

        let key = toolchain.archive_id.as_str();
        std::fs::remove_file(root.join(&key[..1]).join(&key[1..2]).join(key))?;

        let next = server.handle_assign_job(JobId(46), toolchain.clone())?;
        assert!(next.need_toolchain);
        assert!(matches!(next.state, JobState::Pending));
        assert!(!archive.has_cached_toolchain(&toolchain)?);
        Ok(())
    }

    #[test]
    fn corrupt_toolchain_is_not_published_as_ready_or_cached() -> Result<()> {
        let (_dir, server) = test_server()?;
        let expected = tc(b"expected")?;
        server.handle_assign_job(JobId(43), expected.clone())?;
        let requester = RecordingRequester(Mutex::new(Vec::new()));
        let result = server.handle_submit_toolchain(
            &requester,
            JobId(43),
            ToolchainReader::new(Box::new(Cursor::new(b"wrong".to_vec()))),
        )?;
        assert!(matches!(result, SubmitToolchainResult::CannotCache));
        assert!(requester.0.lock().unwrap().is_empty());
        assert!(
            !server
                .archive
                .as_ref()
                .unwrap()
                .cache
                .lock()
                .unwrap()
                .contains_toolchain(&expected)
        );
        Ok(())
    }

    #[test]
    fn oversized_archive_is_rejected_without_publishing_ready() -> Result<()> {
        let (_dir, server) = test_server()?;
        let bytes = vec![7; 1024 * 1024 + 1];
        let expected = tc(&bytes)?;
        server.handle_assign_job(JobId(44), expected.clone())?;
        let requester = RecordingRequester(Mutex::new(Vec::new()));
        let result = server.handle_submit_toolchain(
            &requester,
            JobId(44),
            ToolchainReader::new(Box::new(Cursor::new(bytes))),
        )?;
        assert!(matches!(result, SubmitToolchainResult::CannotCache));
        assert!(requester.0.lock().unwrap().is_empty());
        assert!(
            !server
                .archive
                .as_ref()
                .unwrap()
                .cache
                .lock()
                .unwrap()
                .contains_toolchain(&expected)
        );
        Ok(())
    }
}
