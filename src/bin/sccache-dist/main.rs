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
    self, AllocJobResult, AssignJobResult, HeartbeatServerResult, JobAlloc, JobAuthorizer, JobId,
    JobState, NativeAssignment, SchedulerIncoming, SchedulerOutgoing, SchedulerStatusResult,
    ServerId, ServerIncoming, ServerNonce, ServerOutgoing, UpdateJobStateResult,
};
use sccache::util::BASE64_URL_SAFE_ENGINE;
use sccache::util::daemonize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque, btree_map};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

mod cmdline;
#[cfg(feature = "scheduler-dashboard")]
mod dashboard;
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
    for incr_str in incr_env_strs {
        match env::var(incr_str) {
            Ok(incr_val) if incr_val == "1" => {
                println!(
                    "sccache: incremental compilation is prohibited: Unset {incr_str} to continue."
                );
                std::process::exit(1);
            }
            _ => (),
        }
    }

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
            eprintln!("sccache-dist: error: {e}");

            for e in e.chain().skip(1) {
                eprintln!("sccache-dist: caused by: {e}");
            }
            2
        }
    });
}

fn create_server_token(server_id: ServerId, auth_token: &str) -> String {
    format!("{server_id} {auth_token}")
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
    jsonwebtoken_btls::install()?;
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
    jsonwebtoken_btls::install().ok()?;
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
        move || Ok(token.clone()),
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
        #[cfg(feature = "scheduler-dashboard")]
        Command::VerifyDashboard { assets, source } => {
            sccache_dashboard::server::verify_assets(&assets, source.as_deref())?;
            println!("{}", sccache_dashboard::GENERATION);
            Ok(0)
        }
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
        } => provision_package(&client_config, archive, identity, expected_size, locator),
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
        } => import_rust_package(
            &store,
            archive,
            source,
            max_entries,
            max_expanded_bytes,
            max_tar_bytes,
            manifest_output,
        ),
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
        } => attest_installation(&root, &manifests, recipe, &output),
        Command::NativeAudit {
            index,
            schema,
            without,
            action_key,
        } => audit_index(&index, schema.as_deref(), &without, action_key.as_deref()),
        Command::ClusterInit { directory } => cluster_init(&directory),
        Command::ClusterId { directory } => cluster_id(&directory),
        Command::ClusterRevoke { directory, peer } => cluster_revoke(&directory, peer),
        Command::ClusterStatus { client_config } => cluster_status(&client_config),

        Command::Auth(auth) => run_auth(auth),
        Command::Scheduler(config) => start_scheduler(*config),
        Command::Server(config) => start_worker(*config, None),
    }
}

fn cluster_id(directory: &Path) -> Result<i32> {
    anyhow::ensure!(directory.is_absolute(), "member directory must be absolute");
    std::fs::create_dir_all(directory)?;
    println!(
        "{}",
        sccache_cluster_identity::Identity::open(&directory.join("key.pem"))?.id()?
    );
    Ok(0)
}

fn cluster_revoke(directory: &Path, peer: ServerId) -> Result<i32> {
    anyhow::ensure!(
        directory.is_absolute(),
        "cluster directory must be absolute"
    );
    let registry = sccache_cluster_identity::Registry::open(&directory.join("registry.bin"))?;
    registry.revoke(peer)?;
    Ok(0)
}

fn run_auth(auth: AuthSubcommand) -> Result<i32> {
    match auth {
        AuthSubcommand::Base64 { num_bytes } => {
            let mut bytes = vec![0; num_bytes];
            rand::fill(&mut bytes);
            // As long as it can be copied, it doesn't matter if this is base64 or hex etc
            println!("{}", BASE64_URL_SAFE_ENGINE.encode(bytes));
        }
        AuthSubcommand::JwtHS256ServerToken {
            secret_key,
            server_id,
        } => {
            let header = jwt::Header::new(jwt::Algorithm::HS256);
            let secret_key = BASE64_URL_SAFE_ENGINE.decode(secret_key)?;
            let token = create_jwt_server_token(server_id, &header, &secret_key)
                .context("Failed to create server token")?;
            println!("{token}");
        }
    }
    Ok(0)
}

fn provision_package(
    client_config: &Path,
    archive: Option<PathBuf>,
    identity: sccache::build_runtime::PackageIdentity,
    expected_size: Option<u64>,
    locator: Option<dist::native::PackageLocator>,
) -> Result<i32> {
    use sccache::build_runtime::PackageSource;
    let client = package_client(client_config)?;
    let (receipt, reused) = if let Some(receipt) = client.lookup_package(identity)? {
        (receipt, true)
    } else if let Some(locator) = locator {
        let acquired = client.acquire_package(&locator)?;
        (acquired.package, acquired.reused)
    } else {
        let archive =
            std::fs::File::open(archive.context(
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

fn import_rust_package(
    store: &Path,
    archive: Option<PathBuf>,
    source: sccache::build_runtime::PackageSource,
    max_entries: usize,
    max_expanded_bytes: u64,
    max_tar_bytes: u64,
    manifest_output: Option<PathBuf>,
) -> Result<i32> {
    use sccache::build_runtime::{ArchiveLength, NativeStore, PackagePolicy};
    let mut policy = PackagePolicy::normalized_archive(
        max_entries,
        max_expanded_bytes,
        max_tar_bytes,
        64 * 1024 * 1024,
    )?;
    policy.retain_original = true;
    let store = NativeStore::open(store)?;
    let (package, reused) = if let Some(existing) = store.lookup_package(source.identity, policy)? {
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
fn attest_installation(
    root: &Path,
    manifests: &[PathBuf],
    recipe: Option<PathBuf>,
    output: &Path,
) -> Result<i32> {
    use sccache::build_runtime::{InstallationCatalog, InstallationManifest, InstallationRecipe};
    let manifests = if let Some(recipe) = recipe {
        InstallationRecipe::read(std::fs::File::open(recipe)?)?.selected_manifests()?
    } else {
        manifests
            .iter()
            .map(|path| InstallationManifest::read(std::fs::File::open(path)?))
            .collect::<Result<Vec<_>>>()?
    };
    let (catalog, report) = InstallationCatalog::attest(root, &manifests, Some(output))?;
    write_installation_metadata(output, |file| catalog.write(file))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(0)
}

fn audit_index(
    index: &Path,
    schema: Option<&str>,
    without: &[String],
    action_key: Option<&str>,
) -> Result<i32> {
    let audit = sccache::build_runtime::NativeIndexAudit::open(index)?;
    if let Some(key) = action_key {
        let digest = blake3::Hash::from_hex(key)?;
        let result = audit.action_result(sccache::build_runtime::ActionKey(*digest.as_bytes()))?;
        println!(
            "{}",
            serde_json::json!({
                "action_key": key,
                "result": result.map(|id| blake3::Hash::from_bytes(id.0).to_hex().to_string()),
            })
        );
    } else if let Some(schema) = schema {
        let comparison = audit.compare(schema, without)?;
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

fn cluster_status(client_config: &Path) -> Result<i32> {
    use sccache::config::{DistAuth, FileConfig, try_read_config_file};
    use sccache_cluster_identity::Role;
    let config: FileConfig =
        try_read_config_file(client_config)?.context("client configuration unavailable")?;
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
        move || Ok(token.clone()),
    )?;
    let routes = dist::cluster::ClusterRoutes::for_peer(std::sync::Arc::clone(&peer));
    let (http, base) = routes.endpoint(
        peer.scheduler_id(),
        Role::Scheduler,
        sccache::dist::cluster::Route::unbound(peer.scheduler_address()),
    )?;
    let status: dist::SchedulerStatusResult =
        sccache::http_client::io_runtime()?.block_on(async {
            let response = http
                .get(dist::http::urls::scheduler_status(&base)?.as_str())
                .header("Accept", "application/json")
                .timeout(Duration::from_secs(5))
                .send()
                .await?
                .error_for_status()?;
            let body = sccache::http_client::read_bounded_bytes_async(
                response,
                dist::http::CONTROL_RESPONSE_LIMIT,
            )
            .await?;
            serde_json::from_slice(&body).context("decode scheduler status")
        })?;
    println!("{}", serde_json::to_string(&status)?);
    Ok(0)
}

fn cluster_init(directory: &Path) -> Result<i32> {
    anyhow::ensure!(
        directory.is_absolute(),
        "cluster directory must be absolute"
    );
    std::fs::create_dir_all(directory)?;
    let _registry = sccache_cluster_identity::scheduler_registry(directory)?;
    let ca = sccache_cluster_identity::ClusterCa::open(&directory.join("ca-key.pem"))?;
    let identity = sccache_cluster_identity::Identity::open(&directory.join("key.pem"))?;
    sccache_cluster_identity::publish_trust_anchor(ca.certificate(), &directory.join("ca.pem"))?;
    println!("{}", identity.id()?);
    Ok(0)
}

fn start_scheduler(config: scheduler_config::Config) -> Result<i32> {
    let scheduler_config::Config {
        cluster_directory,
        dashboard,
        public_addr,
        client_auth,
        server_auth,
        maintenance_drain_file,
        job_slack,
        native_cache,
        local_worker,
        traces,
    } = config;

    let check_client_auth: Box<dyn dist::http::ClientAuthCheck> = match client_auth {
        scheduler_config::ClientAuth::Insecure => Box::new(token_check::EqCheck::new(
            INSECURE_DIST_CLIENT_TOKEN.to_owned(),
        )),
        scheduler_config::ClientAuth::Token { token } => Box::new(token_check::EqCheck::new(token)),
        scheduler_config::ClientAuth::JwtValidate {
            audience,
            issuer,
            jwks_url,
        } => Box::new(
            token_check::ValidJWTCheck::new(audience, issuer, &jwks_url)
                .context("Failed to create a checker for valid JWTs")?,
        ),
        scheduler_config::ClientAuth::ProxyToken { url, cache_secs } => {
            Box::new(token_check::ProxyTokenCheck::new(&url, cache_secs)?)
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
            Box::new(move |server_token| check_jwt_server_token(server_token, &key, &validation))
        }
    };

    if maintenance_drain_file
        .as_deref()
        .is_some_and(|path| !path.is_absolute())
    {
        bail!("scheduler maintenance_drain_file must be absolute")
    }
    daemonize(&[])?;
    sccache::latency_trace::configure(traces.as_ref())?;
    info!(
        "Distributed scheduler job slack: static={} percent={}%",
        job_slack.static_jobs, job_slack.percent
    );
    let scheduler = Scheduler::new_with_job_slack_and_drain(job_slack, maintenance_drain_file);
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
        dashboard,
    );
    // A running server never exits successfully (Result<Infallible>).
    let local_worker = local_worker.map(colocated_worker_start);
    match http_scheduler.start(local_worker)? {}
}

fn colocated_worker_start(config: Box<server_config::Config>) -> dist::http::LocalWorkerStart {
    Box::new(move |store| {
        std::thread::Builder::new()
            .name("colocated-native-worker".into())
            .spawn(move || match start_worker(*config, Some(store)) {
                Ok(code) => {
                    error!("colocated worker unexpectedly returned {code}");
                    std::process::exit(1);
                }
                Err(error) => {
                    error!("colocated worker failed: {error:#}");
                    std::process::exit(1);
                }
            })?;
        Ok(())
    })
}

fn worker_bootstrap_token(
    server_id: ServerId,
    scheduler_auth: &server_config::SchedulerAuth,
) -> Result<String> {
    Ok(match scheduler_auth {
        server_config::SchedulerAuth::Insecure => {
            warn!("Server starting with DANGEROUSLY_INSECURE scheduler authentication");
            create_server_token(server_id, INSECURE_DIST_SERVER_TOKEN)
        }
        server_config::SchedulerAuth::Token { token } => create_server_token(server_id, token),
        server_config::SchedulerAuth::JwtToken { token } => {
            let token_server_id: ServerId = dangerous_insecure_extract_jwt_server_token(token)
                .context("Could not decode scheduler auth jwt")?;
            if token_server_id != server_id {
                bail!(
                    "JWT server id ({token_server_id:?}) did not match configured server id ({server_id:?})"
                )
            }
            token.clone()
        }
    })
}

fn start_worker(
    config: server_config::Config,
    shared_store: Option<sccache::build_runtime::NativeStore>,
) -> Result<i32> {
    let server_config::Config {
        cluster,
        builder,
        public_addr,
        bind_address,
        scheduler_url,
        scheduler_auth,
        native_worker,
        traces,
    } = config;
    sccache::latency_trace::configure(traces.as_ref())?;

    anyhow::ensure!(
        native_worker.is_some(),
        "native_worker configuration required"
    );
    let _ = builder;
    let server_id = sccache_cluster_identity::open_identity(&cluster)?.id()?;

    let peer = dist::cluster::open_peer(
        cluster,
        &scheduler_url.to_url(),
        sccache_cluster_identity::Role::Worker,
        move || worker_bootstrap_token(server_id, &scheduler_auth),
    )?;
    #[cfg(target_os = "linux")]
    let native_worker = native_worker
        .map(|config| NativeWorker::new(config, std::sync::Arc::clone(&peer), shared_store))
        .transpose()?;
    #[cfg(not(target_os = "linux"))]
    if native_worker.is_some() || shared_store.is_some() {
        bail!("native worker requires Linux");
    }
    let server = Server::new();
    #[cfg(target_os = "linux")]
    let server = Server {
        native_worker: native_worker
            .map(|worker| {
                NativeDispatcher::new(worker, std::sync::Arc::clone(&server.execution_queue))
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
const UNCLAIMED_PENDING_TIMEOUT: Duration = Duration::from_mins(15);
const UNCLAIMED_READY_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Copy, Clone)]
struct JobDetail {
    #[cfg(feature = "scheduler-dashboard")]
    trace: Option<sccache::latency_trace::TraceContext>,
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

fn log_lost_job(job_id: JobId, server_id: ServerId, reason: &str, detail: Option<&JobDetail>) {
    let previous_state = detail.map(|detail| detail.state);
    warn!(
        "dist_job_lost job_id={job_id} worker={server_id} reason={reason} previous_state={previous_state:?}"
    );
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

    const fn transition_to(&mut self, state: JobState, now: Instant) {
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
    #[cfg(feature = "scheduler-dashboard")]
    dashboard_waker: std::sync::OnceLock<std::sync::mpsc::SyncSender<()>>,
    #[cfg(feature = "scheduler-dashboard")]
    dashboard_clients:
        Mutex<BTreeMap<ServerId, (Instant, sccache::build_runtime::wire::ClientDeliveryRates)>>,
    job_slack: JobSlackConfig,
    maintenance_drain_file: Option<PathBuf>,
    queue_changed: tokio::sync::Notify,

    // Currently running jobs, can never be Complete
    jobs: Mutex<BTreeMap<JobId, JobDetail>>,
    servers: Mutex<HashMap<ServerId, ServerDetails>>,
    completed_acks: Mutex<CompletedJobAcks>,
    exploration: Mutex<Exploration>,
    cost_book: std::sync::Arc<Mutex<placement::CostBook>>,
}

#[cfg(feature = "scheduler-dashboard")]
struct DashboardChange<'a>(&'a Scheduler);

#[cfg(feature = "scheduler-dashboard")]
impl Drop for DashboardChange<'_> {
    fn drop(&mut self) {
        self.0.dashboard_changed();
    }
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
    fn reserve(&mut self, job_id: JobId, assigned: Option<placement::AssignedNative>) {
        assert!(self.jobs_assigned.insert(job_id, assigned).is_none());
        assert!(self.jobs_assigning.insert(job_id, Instant::now()).is_none());
    }

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
        self.capabilities
            .native_placement
            .as_ref()
            .map_or(self.jobs_assigned.len(), |placement| {
                placement
                    .queue
                    .compiler_demand(self.jobs_assigned.keys().copied())
            })
    }

    fn max_jobs(&self, _job_slack: JobSlackConfig) -> usize {
        self.capabilities
            .native_placement
            .as_ref()
            .map_or(0, |placement| placement.queue.capacity as usize)
    }

    fn available_jobs(&self, _job_slack: JobSlackConfig) -> usize {
        self.native_headroom()
    }

    fn native_headroom(&self) -> usize {
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
    #[cfg(feature = "scheduler-dashboard")]
    fn dashboard_changed(&self) {
        if let Some(sender) = self.dashboard_waker.get() {
            let _ = sender.try_send(());
        }
    }

    #[must_use = "the scheduler owns its worker and job state"]
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
        Self {
            job_id_base,
            job_count: AtomicUsize::new(0),
            #[cfg(feature = "scheduler-dashboard")]
            dashboard_waker: std::sync::OnceLock::new(),
            #[cfg(feature = "scheduler-dashboard")]
            dashboard_clients: Mutex::default(),
            job_slack,
            maintenance_drain_file,
            queue_changed: tokio::sync::Notify::new(),
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
            warn!("Server {server_id} appears to be dead, pruning it in the scheduler");
            let Some(server_details) = servers.remove(&server_id) else {
                error!("server {server_id:?} disappeared while pruning");
                continue;
            };
            for job_id in server_details.jobs_assigned.into_keys() {
                log_lost_job(job_id, server_id, "heartbeat_timeout", jobs.get(&job_id));
                // A job may be missing here if it failed to allocate
                // initially, so just warn if it's not present.
                if jobs.remove(&job_id).is_none() {
                    warn!("Non-terminated job {job_id} assignment originally failed.");
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

#[expect(
    clippy::cast_precision_loss,
    reason = "Worker admission weights are approximate floating-point CPU capacity estimates"
)]
fn admission_weight(job_count: usize, cpu_capacity: f64, job_slack: JobSlackConfig) -> Option<f64> {
    (job_count < job_slack.max_jobs(cpu_capacity))
        .then_some((cpu_capacity - job_count as f64).max(0.0) + 0.5)
}

struct Reservation {
    #[cfg(feature = "scheduler-dashboard")]
    trace: Option<sccache::latency_trace::TraceContext>,
    job_id: JobId,
    server_id: ServerId,
    auth: String,
    prediction: Option<placement::PlacementEstimate>,
    estimated_result_bytes: Option<u64>,
}

// An assignment owns capacity from reservation until publication. Dropping an
// unfinished RPC (including a cancelled spawn_blocking result) releases it.
struct AssignmentGuard {
    scheduler: Arc<Scheduler>,
    server_id: ServerId,
    job_id: JobId,
}

impl Drop for AssignmentGuard {
    fn drop(&mut self) {
        if let Ok(mut servers) = self.scheduler.servers.lock()
            && let Some(entry) = servers.get_mut(&self.server_id)
            && entry.jobs_assigning.remove(&self.job_id).is_some()
        {
            entry.jobs_assigned.remove(&self.job_id);
            entry.last_error = Some(Instant::now());
        }
        self.scheduler.queue_changed.notify_waiters();
        #[cfg(feature = "scheduler-dashboard")]
        self.scheduler.dashboard_changed();
    }
}

struct NoCapacity {
    servers: usize,
    saturated_native: bool,
}

struct CandidateSet {
    saturated_native: bool,
    healthy: Vec<(ServerId, f64)>,
    retry: Vec<(ServerId, f64)>,
    predictions: BTreeMap<ServerId, placement::PlacementEstimate>,
}

fn trace_native_assignment(
    job_id: JobId,
    server_id: ServerId,
    class: Option<placement::ActionClass>,
    candidates: &CandidateSet,
    estimated_result_bytes: Option<u64>,
    server_details: &ServerDetails,
) {
    if let Some(class) = class {
        trace!(target: "native_placement_replay", "{}", serde_json::json!({
            "kind": "assigned", "job": job_id.0, "worker": server_id, "class": class,
            "candidates": candidates.predictions,
            "estimated_result_bytes": estimated_result_bytes,
            "host_prior": server_details.capabilities.native_placement.as_ref().map(placement::ActionCost::baseline),
            "healthy": candidates.healthy.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        }));
    }
}

impl CandidateSet {
    const fn no_capacity(&self, servers: usize) -> NoCapacity {
        NoCapacity {
            servers,
            saturated_native: self.saturated_native,
        }
    }
}

fn collect_candidates(
    servers: &mut HashMap<ServerId, ServerDetails>,
    native: &NativeAssignment,
    class: placement::ActionClass,
    transfer_plan: &NativeTransferPlan<'_>,
    cost_book: &placement::CostBook,
    _job_slack: JobSlackConfig,
    now: Instant,
) -> CandidateSet {
    let platform = native.spec.platform;
    let mut healthy = Vec::new();
    let mut retry = Vec::new();
    let mut predictions = BTreeMap::new();
    let mut saturated_native = false;
    for (&server_id, details) in servers {
        if details.capabilities.native_platform != Some(platform) {
            continue;
        }
        let Some(placement) = details.capabilities.native_placement.as_ref() else {
            continue;
        };
        if details.native_headroom() == 0 {
            saturated_native = true;
            continue;
        }
        let learned = cost_book.predict(
            placement::WorkerScope {
                peer: server_id,
                platform,
            },
            class,
            placement,
            now,
        );
        let Some(forecast) = placement::WorkerForecast::new(details, Some(learned)) else {
            continue;
        };
        let estimate = native_estimate(
            forecast,
            &native.input_blobs,
            Peer::Worker(server_id),
            transfer_plan,
        );
        predictions.insert(server_id, estimate);
        let weight = estimate.seconds;
        if details
            .last_error
            .is_some_and(|when| now.duration_since(when) > SERVER_REMEMBER_ERROR_TIMEOUT)
        {
            details.last_error = None;
        }
        if details.last_error.is_some() {
            retry.push((server_id, weight));
        } else {
            healthy.push((server_id, weight));
        }
    }

    CandidateSet {
        saturated_native,
        healthy,
        retry,
        predictions,
    }
}

impl Scheduler {
    fn select_candidate(
        &self,
        native_inputs: &dist::NativeInputBlobs,
        transfer_plan: &NativeTransferPlan<'_>,
        servers: &HashMap<ServerId, ServerDetails>,
        candidates: &CandidateSet,
        now: Instant,
    ) -> Option<ServerId> {
        [&candidates.healthy, &candidates.retry]
            .into_iter()
            .find_map(|group| {
                let mut history = self
                    .exploration
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                choose_worker(
                    group,
                    servers,
                    native_inputs,
                    &candidates.predictions,
                    transfer_plan,
                    &mut history,
                    now,
                )
            })
    }

    fn reserve_job(
        &self,
        assignment: &NativeAssignment,
        network: &NetworkSnapshot,
        packages: &std::sync::Arc<sccache::build_runtime::PackageCatalog>,
        assigned_at: Instant,
    ) -> Result<std::result::Result<Reservation, NoCapacity>> {
        let platform = assignment.spec.platform;
        let inputs = &assignment.input_blobs;
        let class = placement::ActionClass::from_spec(&assignment.spec)?;
        #[cfg(feature = "scheduler-dashboard")]
        let description = Some(dashboard::describe_native(assignment));
        // LOCKS
        let mut servers = self
            .servers
            .lock()
            .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;

        {
            let mut compatible = false;
            let mut ready = false;
            for details in servers.values() {
                if details.capabilities.native_platform == Some(platform) {
                    compatible = true;
                    ready |= details.native_headroom() != 0;
                }
            }
            if !ready {
                return Ok(Err(NoCapacity {
                    servers: servers.len(),
                    saturated_native: compatible,
                }));
            }
        }

        let cost_book = self
            .cost_book
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remote_fraction = assignment
            .receiver
            .as_ref()
            .zip(assignment.delivery_profile)
            .map_or(1_000_000, |((requester, _), profile)| {
                cost_book.delivery_fraction(*requester, profile, assigned_at)
            });
        let transfer_plan = NativeTransferPlan::new(
            network,
            &servers,
            Some(packages),
            Some(inputs),
            assignment.receiver.as_ref(),
        )
        .with_remote_fraction(remote_fraction);
        let now = Instant::now();
        let candidates = collect_candidates(
            &mut servers,
            assignment,
            class,
            &transfer_plan,
            &cost_book,
            self.job_slack,
            now,
        );
        let estimated_result_bytes = cost_book.result_reservation(platform, class, now);
        drop(cost_book);
        let selected = self.select_candidate(inputs, &transfer_plan, &servers, &candidates, now);
        let Some(server_id) = selected else {
            return Ok(Err(candidates.no_capacity(servers.len())));
        };
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
        let prediction = candidates.predictions.get(&server_id).copied();
        trace_native_assignment(
            job_id,
            server_id,
            Some(class),
            &candidates,
            estimated_result_bytes,
            server_details,
        );
        let assigned = Some(placement::AssignedNative {
            #[cfg(feature = "scheduler-dashboard")]
            dashboard: description,
            packages: std::sync::Arc::clone(packages),
            inputs: inputs.clone(),
            class: Some(class),
            cost: prediction.map(|estimate| estimate.cost),
            milestone: None,
        });
        server_details.reserve(job_id, assigned);
        drop(servers);
        info!("Job {job_id} created and will be assigned to server {server_id:?}");
        Ok(Ok(Reservation {
            #[cfg(feature = "scheduler-dashboard")]
            trace: assignment.trace,
            job_id,
            server_id,
            auth,
            prediction,
            estimated_result_bytes,
        }))
    }
}

impl Scheduler {
    async fn allocate_job(
        self: Arc<Self>,
        requester: &dyn SchedulerOutgoing,
        mut assignment: NativeAssignment,
        network: &NetworkSnapshot,
        packages: &Arc<sccache::build_runtime::PackageCatalog>,
    ) -> Result<AllocJobResult> {
        let (assignment, reservation, _guard, assigned_at) = loop {
            // Register before observing capacity to avoid losing a heartbeat
            // or completion between the failed reservation and the wait.
            let changed = self.queue_changed.notified();
            tokio::pin!(changed);
            let _ = changed.as_mut().enable();
            if self.is_draining() {
                return Ok(AllocJobResult::Fail {
                    msg: "scheduler is draining for maintenance".to_owned(),
                });
            }
            let scheduler = Arc::clone(&self);
            let network = network.clone();
            let packages = Arc::clone(packages);
            let prepared = tokio::task::spawn_blocking(move || -> Result<_> {
                let assigned_at = Instant::now();
                match scheduler.reserve_job(&assignment, &network, &packages, assigned_at)? {
                    Ok(reservation) => {
                        let guard = AssignmentGuard {
                            scheduler: Arc::clone(&scheduler),
                            server_id: reservation.server_id,
                            job_id: reservation.job_id,
                        };
                        #[cfg(feature = "scheduler-dashboard")]
                        scheduler.dashboard_changed();
                        assignment.estimated_result_bytes = reservation.estimated_result_bytes;
                        Ok(Ok((assignment, reservation, guard, assigned_at)))
                    }
                    Err(reason) => Ok(Err((assignment, reason))),
                }
            })
            .await??;
            match prepared {
                Ok(reservation) => break reservation,
                Err((
                    pending,
                    NoCapacity {
                        saturated_native: true,
                        ..
                    },
                )) => {
                    // The admitted session owns the queued request. Do not
                    // reject work merely because the bounded worker queues
                    // are full. Wake on a released reservation or heartbeat;
                    // a short timer also observes the maintenance drain.
                    assignment = pending;
                    let _ = tokio::time::timeout(Duration::from_secs(1), changed).await;
                }
                Err((_, NoCapacity { servers: count, .. })) => {
                    return Ok(AllocJobResult::Fail {
                        msg: format!(
                            "No available capacity on compatible workers across {count} servers"
                        ),
                    });
                }
            }
        };
        let result = requester
            .do_assign_job(
                reservation.server_id,
                reservation.job_id,
                assignment,
                reservation.auth.clone(),
            )
            .await
            .context("assign job failed")?;
        self.complete_reservation(reservation, &result, assigned_at)
    }

    fn complete_reservation(
        &self,
        reservation: Reservation,
        result: &AssignJobResult,
        assigned_at: Instant,
    ) -> Result<AllocJobResult> {
        let Reservation {
            #[cfg(feature = "scheduler-dashboard")]
            trace,
            job_id,
            server_id,
            auth,
            prediction,
            ..
        } = reservation;
        let AssignJobResult { state } = *result;
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
                        #[cfg(feature = "scheduler-dashboard")]
                        trace,
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
            drop(servers);
            drop(jobs);
            info!("Job {job_id} successfully assigned and saved with state {state:?}");
        }
        let job_alloc = JobAlloc {
            auth,
            job_id,
            server_id,
        };
        Ok(AllocJobResult::Success { job_alloc })
    }
}

#[derive(Clone, Copy)]
struct CommitObservation<'a> {
    manifest: &'a sccache::build_runtime::ResultManifest,
    retained_after_begin: Duration,
    observation: Option<sccache::build_runtime::wire::ActionObservation>,
}

impl Scheduler {
    fn observe_commit(
        &self,
        server: &mut ServerDetails,
        detail: &mut JobDetail,
        job: JobId,
        commit: CommitObservation<'_>,
        now: Instant,
    ) {
        use sccache::build_runtime::wire::NativeJobPhase;
        let CommitObservation {
            manifest,
            retained_after_begin,
            observation,
        } = commit;
        let server_id = detail.server_id;
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
            let Some(assigned) = server.jobs_assigned.get(&job).and_then(Option::as_ref) else {
                return;
            };
            server.recent_residency.record_inputs(&assigned.inputs, now);
            let Ok(blobs) = manifest.blobs() else {
                return;
            };
            let result_bytes = blobs.values().copied().fold(0_u64, u64::saturating_add);
            if let (Some(class), Some(observed)) = (
                assigned.class,
                observation.filter(|sample| {
                    sample.valid()
                        && sample.upload_bytes <= result_bytes
                        && sample.upload_requests <= u64::try_from(blobs.len()).unwrap_or(u64::MAX)
                }),
            ) {
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
                            result_bytes,
                            now,
                        );
                }
                trace!(target: "native_placement_replay", "{}", serde_json::json!({
                    "kind": "completed", "job": job.0, "worker": server_id,
                    "class": class, "predicted_publication_seconds": detail.prediction.map(|prediction| prediction.publication_at),
                    "predicted_client_completion_seconds": detail.prediction.map(|prediction| prediction.completion_seconds),
                    "actual_inputs_ready_seconds": detail.inputs_staged_at.map(|staged| staged.saturating_duration_since(detail.assigned_at).as_secs_f64()),
                    "actual_result_negotiation_seconds": detail.publication_began_at.map(|began| began.saturating_duration_since(detail.assigned_at).as_secs_f64()),
                    "actual_staging_start_seconds": (detail.state == JobState::Started).then(|| detail.state_since.saturating_duration_since(detail.assigned_at).as_secs_f64()),
                    "actual_publication_seconds": now.saturating_duration_since(detail.assigned_at).as_secs_f64(),
                    "result_bytes": result_bytes,
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

fn reconcile_stale_assignments(
    details: &mut ServerDetails,
    jobs: &mut BTreeMap<JobId, JobDetail>,
    server_id: ServerId,
    active_job_ids: &[JobId],
    now: Instant,
) {
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
            None => details
                .jobs_assigning
                .get(job_id)
                .is_some_and(|&since| now.duration_since(since) > UNCLAIMED_PENDING_TIMEOUT),
        })
        .collect();

    if !stale_jobs.is_empty() {
        warn!("The following stale jobs will be de-allocated: {stale_jobs:?}");
        for job_id in stale_jobs {
            log_lost_job(job_id, server_id, "stale_assignment", jobs.get(&job_id));
            if details.jobs_assigned.remove(&job_id).is_none() {
                warn!("Stale job for server {server_id} not assigned: {job_id}");
            }
            details.jobs_assigning.remove(&job_id);
            jobs.remove(&job_id);
        }
    }
}

fn validate_heartbeat(
    server_id: ServerId,
    cpu_capacity: f64,
    capabilities: &dist::WorkerCapabilities,
) -> Result<()> {
    if !cpu_capacity.is_finite() || cpu_capacity < 0.0 {
        bail!("invalid worker CPU capacity {cpu_capacity}");
    }
    anyhow::ensure!(
        capabilities.native_platform.is_some(),
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
                && placement.interfaces.valid()
                && sccache::build_runtime::wire::peer_download_rates_valid(
                    &placement.peer_download_rates
                )
                && placement
                    .peer_download_rates
                    .iter()
                    .all(|rate| rate.source != server_id)
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
    Ok(())
}

#[async_trait::async_trait]
impl SchedulerIncoming for Scheduler {
    async fn handle_alloc_native_job(
        self: Arc<Self>,
        requester: &dyn SchedulerOutgoing,
        assignment: NativeAssignment,
        network: &NetworkSnapshot,
        packages: std::sync::Arc<sccache::build_runtime::PackageCatalog>,
    ) -> Result<AllocJobResult> {
        #[cfg(feature = "scheduler-dashboard")]
        if let Some((id, rates)) = &assignment.receiver {
            let mut clients = self
                .dashboard_clients
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = Instant::now();
            clients.retain(|_, (seen, _)| {
                now.saturating_duration_since(*seen) <= dist::http::HEARTBEAT_TIMEOUT
            });
            clients.insert(*id, (now, rates.clone()));
            drop(clients);
            self.dashboard_changed();
        }

        assignment.spec.validate()?;
        self.allocate_job(requester, assignment, network, &packages)
            .await
    }

    fn observe_native_lifecycle(
        &self,
        server_id: ServerId,
        job: JobId,
        event: dist::NativeLifecycleEvent<'_>,
    ) {
        use sccache::build_runtime::wire::NativeJobPhase;
        #[cfg(feature = "scheduler-dashboard")]
        let _dashboard_change = DashboardChange(self);
        let now = Instant::now();
        // Delivery receipts outlive the worker's job record. The session
        // authenticated the original requester and validated the exact closure.
        if let dist::NativeLifecycleEvent::Delivered(receipt) = event {
            self.cost_book
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .observe_delivery(receipt, now);
            return;
        }
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
        match event {
            dist::NativeLifecycleEvent::Delivered(_) => (),
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
                self.observe_commit(
                    server,
                    detail,
                    job,
                    CommitObservation {
                        manifest,
                        retained_after_begin,
                        observation,
                    },
                    now,
                );
            }
        }
        drop(servers);
        drop(jobs);
    }

    fn native_blob_sources(
        &self,
        blob: sccache::build_runtime::BlobRef,
        requester: Option<ServerId>,
        recipient: sccache::build_runtime::wire::BlobRecipient,
        producer: Option<ServerId>,
        recovery_network: Option<&NetworkSnapshot>,
    ) -> Result<Vec<dist::NativeBlobSource>> {
        let servers = self
            .servers
            .lock()
            .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;
        // Result receipts may name a just-produced blob that has not yet
        // appeared in a heartbeat. For result recovery prefer positive
        // inventory hints, but allow other native workers to answer exactly.
        let receiver_rates = requester
            .and_then(|id| servers.get(&id))
            .and_then(|details| details.capabilities.native_placement.as_ref())
            .map_or_default(|placement| placement.peer_download_rates.as_slice());
        let rate = |source: ServerId| {
            receiver_rates
                .binary_search_by_key(&source, |rate| rate.source)
                .ok()
                .map_or(0, |index| receiver_rates[index].logical_bytes_per_second)
        };
        let recovery =
            recovery_network.map(|network| placement::PeerRecoveryPlan::new(network, &servers));
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
                let locality = if producer == Some(*id) {
                    4_u8
                } else if pinned || details.recent_residency.retained(blob.id, blob.size, now) {
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
                    && (matches!(
                        recipient,
                        sccache::build_runtime::wire::BlobRecipient::Scheduler
                    ) && requester.is_none()
                        || locality > 0))
                    .then(|| {
                        let score = recovery.as_ref().map_or(0.0, |plan| {
                            plan.score(*id, blob.size, placement.timing.result)
                        });
                        (id, details, locality, score)
                    })
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable_by(
            |(a, left, left_predicted, left_score), (b, right, right_predicted, right_score)| {
                right_predicted
                    .cmp(left_predicted)
                    .then_with(|| left_score.total_cmp(right_score))
                    .then_with(|| rate(**b).cmp(&rate(**a)))
                    .then_with(|| right.last_seen.cmp(&left.last_seen))
                    .then_with(|| a.cmp(b))
            },
        );
        let limit = if matches!(
            recipient,
            sccache::build_runtime::wire::BlobRecipient::Scheduler
        ) {
            usize::MAX
        } else {
            sccache::build_runtime::wire::MAX_BLOB_SOURCES
        };
        let sources = candidates
            .into_iter()
            .take(limit)
            .map(|(&server, details, _, _)| {
                Ok(dist::NativeBlobSource {
                    server,
                    token: details
                        .job_authorizer
                        .generate_blob_token(blob, recipient)?,
                })
            })
            .collect();
        drop(servers);
        sources
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
        #[cfg(feature = "scheduler-dashboard")]
        let _dashboard_change = DashboardChange(self);
        validate_heartbeat(server_id, cpu_capacity, &capabilities)?;
        // LOCKS
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| anyhow::anyhow!("jobs mutex poisoned"))?;
        let mut servers = self
            .servers
            .lock()
            .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;

        Self::prune_servers(&mut servers, &mut jobs);

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

                reconcile_stale_assignments(details, &mut jobs, server_id, active_job_ids, now);
                let mut assigned_job_ids: Vec<_> = details.jobs_assigned.keys().copied().collect();
                assigned_job_ids.sort_unstable();
                self.queue_changed.notify_waiters();
                return Ok(HeartbeatServerResult {
                    is_new: false,
                    assigned_job_ids,
                });
            }
            Some(ref mut details) if details.server_nonce != server_nonce => {
                for job_id in details.jobs_assigned.keys() {
                    log_lost_job(*job_id, server_id, "worker_restarted", jobs.get(job_id));
                    if jobs.remove(job_id).is_none() {
                        warn!("Unknown job found when replacing server {server_id}: {job_id}");
                    }
                }
            }
            _ => (),
        }
        info!("Registered new server {server_id:?}");
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
        drop(servers);
        drop(jobs);
        self.queue_changed.notify_waiters();
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
        #[cfg(feature = "scheduler-dashboard")]
        let _dashboard_change = DashboardChange(self);
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
        Self::prune_servers(&mut servers, &mut jobs);
        drop(jobs);
        let details = servers
            .get(&server_id)
            .ok_or_else(|| anyhow::anyhow!("worker name update from unknown server {server_id}"))?;
        if details.server_nonce != server_nonce {
            bail!("worker name update from stale server epoch {server_id}")
        }
        if let Some(existing) = details.worker_name.as_ref() {
            if existing == &worker_name {
                return Ok(());
            }
            bail!(
                "distributed worker {server_id} changed name from {existing:?} to {worker_name:?} without restarting"
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
        drop(servers);
        info!("Server {server_id:?} registered worker name {worker_name:?}");
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
        #[cfg(feature = "scheduler-dashboard")]
        let _dashboard_change = DashboardChange(self);
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
                bail!("Job id {job_id} is not registered on server {server_id:?}")
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
                (from, to) => bail!("Invalid job state transition from {from} to {to}"),
            }
            info!("Job {job_id} updated state to {job_state:?}");
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
        drop(servers);
        drop(jobs);
        self.queue_changed.notify_waiters();
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_is_draining(&self) -> bool {
        self.is_draining()
    }

    #[cfg(feature = "scheduler-dashboard")]
    fn install_dashboard_waker(&self, sender: std::sync::mpsc::SyncSender<()>) -> Result<()> {
        self.dashboard_waker
            .set(sender)
            .map_err(|_| anyhow::anyhow!("dashboard waker already installed"))
    }

    #[cfg(feature = "scheduler-dashboard")]
    fn handle_dashboard_snapshot(&self) -> Result<sccache_dashboard::Snapshot> {
        dashboard::snapshot(self)
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "Status reports whole CPU slots, rounded upward from validated capacity"
    )]
    #[expect(
        clippy::cast_sign_loss,
        reason = "Heartbeat admission rejects negative CPU capacity"
    )]
    fn handle_status(&self) -> Result<SchedulerStatusResult> {
        #[cfg(feature = "scheduler-dashboard")]
        let _dashboard_change = DashboardChange(self);
        // LOCKS
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| anyhow::anyhow!("jobs mutex poisoned"))?;
        let mut servers = self
            .servers
            .lock()
            .map_err(|_| anyhow::anyhow!("servers mutex poisoned"))?;

        Self::prune_servers(&mut servers, &mut jobs);

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
                .map(|v| v.max_jobs(self.job_slack))
                .fold(0, usize::saturating_add),
            available_jobs: if self.is_draining() {
                0
            } else {
                servers
                    .values()
                    .map(|v| v.available_jobs(self.job_slack))
                    .fold(0, usize::saturating_add)
            },
        })
    }
}

pub struct Server {
    execution_queue: std::sync::Arc<dist::execution_queue::ExecutionQueue>,
    #[cfg(target_os = "linux")]
    native_worker: Option<NativeDispatcher>,
}

impl Server {
    fn new() -> Self {
        Self {
            execution_queue: std::sync::Arc::new(dist::execution_queue::ExecutionQueue::new(
                std::num::NonZeroUsize::new(sccache::util::num_cpus())
                    .unwrap_or(std::num::NonZeroUsize::MIN),
            )),
            #[cfg(target_os = "linux")]
            native_worker: None,
        }
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
        #[cfg(target_os = "linux")]
        let removed = self.native_worker.as_ref().map_or(0, |dispatcher| {
            dispatcher.reconcile(&known, heartbeat_started_at)
        });
        #[cfg(not(target_os = "linux"))]
        let removed = {
            let _ = (known, heartbeat_started_at);
            0
        };
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
}

#[cfg(test)]
mod scheduler_tests {
    use super::*;

    fn test_platform() -> sccache::build_runtime::ContentId {
        sccache::build_runtime::ContentId::of(b"scheduler-lifecycle-test")
    }

    fn test_capabilities() -> dist::WorkerCapabilities {
        dist::WorkerCapabilities {
            native_platform: Some(test_platform()),
            native_placement: Some(dist::NativePlacement::default()),
        }
    }

    async fn test_allocate(
        scheduler: Arc<Scheduler>,
        requester: &dyn SchedulerOutgoing,
        _marker: char,
    ) -> Result<AllocJobResult> {
        scheduler
            .handle_alloc_native_job(
                requester,
                native_test_assignment(test_platform(), BTreeMap::new())?,
                &NetworkSnapshot::default(),
                Default::default(),
            )
            .await
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
    }

    pub(super) struct TestJobAuthorizer;

    impl JobAuthorizer for TestJobAuthorizer {
        fn generate_token(&self, _job_id: JobId) -> Result<String> {
            Ok(String::new())
        }

        fn verify_token(&self, _job_id: JobId, _token: &str) -> Result<()> {
            Ok(())
        }

        fn generate_blob_token(
            &self,
            _blob: sccache::build_runtime::BlobRef,
            _recipient: sccache::build_runtime::wire::BlobRecipient,
        ) -> Result<String> {
            Ok(String::new())
        }

        fn verify_blob_token(
            &self,
            _blob: sccache::build_runtime::BlobRef,
            _recipient: sccache::build_runtime::wire::BlobRecipient,
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
                test_capabilities(),
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

    #[async_trait::async_trait]
    impl SchedulerOutgoing for AcceptAssign {
        async fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _assignment: NativeAssignment,
            _auth: String,
        ) -> Result<AssignJobResult> {
            Ok(AssignJobResult {
                state: JobState::Pending,
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
        let plan = NativeTransferPlan::new(&network, &HashMap::new(), None, None, None);
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
                    #[cfg(feature = "scheduler-dashboard")]
                    dashboard: None,
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
                    #[cfg(feature = "scheduler-dashboard")]
                    dashboard: None,
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
                    native_platform: Some(ContentId::of(server.to_string().as_bytes())),
                    native_placement: Some(placement),
                },
            )?;
        }
        let sources = scheduler.native_blob_sources(
            blob,
            Some(requester),
            sccache::build_runtime::wire::BlobRecipient::Scheduler,
            None,
            None,
        )?;
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].server, peer);
        let recovery = scheduler.native_blob_sources(
            blob,
            None,
            sccache::build_runtime::wire::BlobRecipient::Scheduler,
            None,
            None,
        )?;
        assert_eq!(recovery.len(), 3);
        assert_eq!(recovery[2].server, empty);
        let mut network = NetworkSnapshot::default();
        for (id, rate, remaining) in [(requester, 100 << 20, 100 << 20), (peer, 10 << 20, 0)] {
            network.receive.peers.insert(
                Peer::Worker(id),
                sccache::build_runtime::PeerCapacity {
                    observed_bytes_per_second: rate,
                    isolated_bytes_per_second: rate,
                    wire_per_mille: 1000,
                    active_remaining_bytes: remaining,
                    body_bytes: 0,
                },
            );
        }
        let ranked = scheduler.native_blob_sources(
            blob,
            None,
            sccache::build_runtime::wire::BlobRecipient::Scheduler,
            None,
            Some(&network),
        )?;
        assert_eq!(ranked[0].server, peer);
        assert_eq!(ranked[2].server, empty);
        let direct = scheduler.native_blob_sources(
            blob,
            None,
            sccache::build_runtime::wire::BlobRecipient::Client(ServerId::from_digest([4; 32])),
            Some(empty),
            None,
        )?;
        assert_eq!(direct[0].server, empty);
        assert_eq!(direct.len(), 3);
        let direct = scheduler.native_blob_sources(
            blob,
            None,
            sccache::build_runtime::wire::BlobRecipient::Client(ServerId::from_digest([4; 32])),
            None,
            None,
        )?;
        assert_eq!(direct.len(), 2);
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
            trace: None,
            ticket: Ticket([42; 32]),
            input_blobs,
            estimated_result_bytes: None,
            receiver: None,
            delivery_profile: None,
            spec: ExecutionSpec {
                compiler_result: None,
                working_inputs: Default::default(),
                scratch: Default::default(),
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

    #[tokio::test]
    async fn native_staged_closure_survives_stale_heartbeat_and_failed_compilation() -> Result<()> {
        use sccache::build_runtime::{BlobRef, ContentId, wire::NativeJobPhase};
        let scheduler = Arc::new(Scheduler::new());
        let worker: ServerId = ServerId::from_digest([1; 32]);
        let peer: ServerId = ServerId::from_digest([2; 32]);
        let platform = ContentId::of(b"native-staging-test");
        let nonce = ServerNonce::new();
        let capabilities = dist::WorkerCapabilities {
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
        let AllocJobResult::Success { job_alloc, .. } = Arc::clone(&scheduler)
            .handle_alloc_native_job(
                &AcceptAssign,
                native_test_assignment(platform, BTreeMap::from([(blob.id, blob.size)]))?,
                &NetworkSnapshot::default(),
                Default::default(),
            )
            .await?
        else {
            bail!("worker unavailable");
        };
        let id = job_alloc.job_id;
        assert!(
            scheduler
                .native_blob_sources(
                    blob,
                    Some(peer),
                    sccache::build_runtime::wire::BlobRecipient::Scheduler,
                    None,
                    None
                )?
                .is_empty()
        );
        scheduler.observe_native_lifecycle(peer, id, dist::NativeLifecycleEvent::InputsStaged);
        assert!(
            scheduler
                .native_blob_sources(
                    blob,
                    Some(peer),
                    sccache::build_runtime::wire::BlobRecipient::Scheduler,
                    None,
                    None
                )?
                .is_empty()
        );
        scheduler.observe_native_lifecycle(worker, id, dist::NativeLifecycleEvent::InputsStaged);
        heartbeat(&[id])?;
        assert_eq!(
            scheduler
                .native_blob_sources(
                    blob,
                    Some(peer),
                    sccache::build_runtime::wire::BlobRecipient::Scheduler,
                    None,
                    None
                )?
                .len(),
            1
        );
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
        assert_eq!(
            scheduler
                .native_blob_sources(
                    blob,
                    Some(peer),
                    sccache::build_runtime::wire::BlobRecipient::Scheduler,
                    None,
                    None
                )?
                .len(),
            1
        );
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

    #[tokio::test]
    async fn native_completed_timing_supersedes_heartbeat_until_worker_restart() -> Result<()> {
        use sccache::build_runtime::{
            ContentId, ResultManifest,
            wire::{ActionObservation, WorkerTiming},
        };
        let scheduler = Arc::new(Scheduler::new());
        let worker: ServerId = ServerId::from_digest([1; 32]);
        let platform = ContentId::of(b"timing-platform");
        let nonce = ServerNonce::new();
        let capabilities = dist::WorkerCapabilities {
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
        let AllocJobResult::Success { job_alloc, .. } = Arc::clone(&scheduler)
            .handle_alloc_native_job(
                &AcceptAssign,
                native_test_assignment(platform, BTreeMap::new())?,
                &NetworkSnapshot::default(),
                Default::default(),
            )
            .await?
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

    #[tokio::test]
    async fn native_producer_receipt_places_consumer_before_next_heartbeat() -> Result<()> {
        use sccache::build_runtime::{Artifact, BlobRef, ContentId, ResultManifest};
        let scheduler = Arc::new(Scheduler::new());
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
        let AllocJobResult::Success { job_alloc, .. } = Arc::clone(&scheduler)
            .handle_alloc_native_job(
                &AcceptAssign,
                native_test_assignment(platform, BTreeMap::new())?,
                &network,
                Default::default(),
            )
            .await?
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
        assert!(
            scheduler
                .native_blob_sources(
                    blob,
                    Some(other),
                    sccache::build_runtime::wire::BlobRecipient::Scheduler,
                    None,
                    None
                )?
                .is_empty()
        );
        scheduler.observe_native_lifecycle(producer, job, dist::NativeLifecycleEvent::Negotiated);
        scheduler.observe_native_lifecycle(other, job, committed());
        assert!(
            scheduler
                .native_blob_sources(
                    blob,
                    Some(other),
                    sccache::build_runtime::wire::BlobRecipient::Scheduler,
                    None,
                    None
                )?
                .is_empty()
        );
        scheduler.observe_native_lifecycle(producer, job, committed());
        let sources = scheduler.native_blob_sources(
            blob,
            Some(other),
            sccache::build_runtime::wire::BlobRecipient::Scheduler,
            None,
            None,
        )?;
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].server, producer);
        scheduler.handle_update_job_state(job, producer, JobState::Complete)?;
        let AllocJobResult::Success { job_alloc, .. } = Arc::clone(&scheduler)
            .handle_alloc_native_job(
                &AcceptAssign,
                native_test_assignment(platform, BTreeMap::from([(blob.id, blob.size)]))?,
                &network,
                Default::default(),
            )
            .await?
        else {
            bail!("consumer not allocated")
        };
        // Producer is slower but avoids fetching a 512 MiB dependency.
        assert_eq!(job_alloc.server_id, producer);
        // Worker incarnation changes invalidate the hints and prior job IDs.
        register(producer, 2_000_000_000)?;
        scheduler.observe_native_lifecycle(producer, job, dist::NativeLifecycleEvent::Negotiated);
        scheduler.observe_native_lifecycle(producer, job, committed());
        assert!(
            scheduler
                .native_blob_sources(
                    blob,
                    Some(other),
                    sccache::build_runtime::wire::BlobRecipient::Scheduler,
                    None,
                    None
                )?
                .is_empty()
        );
        let AllocJobResult::Success { job_alloc, .. } = Arc::clone(&scheduler)
            .handle_alloc_native_job(
                &AcceptAssign,
                native_test_assignment(platform, BTreeMap::from([(blob.id, blob.size)]))?,
                &network,
                Default::default(),
            )
            .await?
        else {
            bail!("consumer not allocated after restart")
        };
        assert_eq!(job_alloc.server_id, other);
        Ok(())
    }

    #[tokio::test]
    async fn native_jobs_queue_at_zero_cpu_and_wait_for_real_reservation_capacity() -> Result<()> {
        use sccache::build_runtime::ContentId;
        let scheduler = Arc::new(Scheduler::new_with_job_slack(JobSlackConfig {
            static_jobs: 0,
            percent: 0.0,
        }));
        let a: ServerId = ServerId::from_digest([1; 32]);
        let b: ServerId = ServerId::from_digest([2; 32]);
        let nonce_a = ServerNonce::new();
        let nonce_b = ServerNonce::new();
        let platform = ContentId::of(b"native-test");
        scheduler.handle_heartbeat_server(
            a,
            nonce_a.clone(),
            0.0,
            &[],
            Box::new(TestJobAuthorizer),
            dist::WorkerCapabilities {
                native_platform: Some(platform),
                native_placement: Some(dist::NativePlacement {
                    queue: dist::NativeQueueSnapshot {
                        capacity: 2,
                        compiler_slots: 1,
                        staging_slots: 2,
                        publication_slots: 2,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            },
        )?;
        scheduler.handle_heartbeat_server(
            b,
            nonce_b,
            1.0,
            &[],
            Box::new(TestJobAuthorizer),
            dist::WorkerCapabilities {
                native_platform: Some(ContentId::of(b"other")),
                native_placement: Some(dist::NativePlacement::default()),
            },
        )?;
        let mut assignment =
            native_test_assignment(platform, BTreeMap::from([(ContentId([1; 32]), 10)]))?;
        assignment.spec.command.arguments = vec![
            b"--crate-name".to_vec(),
            b"example_crate".to_vec(),
            b"--target=x86_64-unknown-linux-gnu".to_vec(),
        ];
        let AllocJobResult::Success { job_alloc, .. } = Arc::clone(&scheduler)
            .handle_alloc_native_job(
                &AcceptAssign,
                assignment.clone(),
                &NetworkSnapshot::default(),
                Default::default(),
            )
            .await?
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
        #[cfg(feature = "scheduler-dashboard")]
        {
            let snapshot = scheduler.handle_dashboard_snapshot()?;
            let job = &snapshot.jobs[0];
            let description = job
                .description
                .as_ref()
                .context("missing job description")?;
            assert_eq!(description.executable, "tool");
            assert_eq!(description.subject.as_deref(), Some("example_crate"));
            assert_eq!(
                description.target.as_deref(),
                Some("x86_64-unknown-linux-gnu")
            );
            assert_eq!(description.input_bytes, 10);
            assert_eq!(description.input_blobs, 1);
        }
        let AllocJobResult::Success {
            job_alloc: second, ..
        } = Arc::clone(&scheduler)
            .handle_alloc_native_job(
                &AcceptAssign,
                assignment.clone(),
                &NetworkSnapshot::default(),
                Default::default(),
            )
            .await?
        else {
            bail!("second reservation unavailable at zero CPU")
        };
        assert_eq!(second.server_id, a);
        {
            let servers = scheduler.servers.lock().unwrap();
            let worker = &servers[&a];
            assert_eq!(worker.max_jobs(scheduler.job_slack), 2);
            assert_eq!(worker.available_jobs(scheduler.job_slack), 0);
        }
        let network = NetworkSnapshot::default();
        let waiting = Arc::clone(&scheduler).handle_alloc_native_job(
            &AcceptAssign,
            assignment.clone(),
            &network,
            Default::default(),
        );
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), waiting.as_mut())
                .await
                .is_err()
        );
        // Incompatible platforms are not temporary queue pressure.
        let missing =
            native_test_assignment(ContentId::of(b"no compatible platform"), BTreeMap::new())?;
        assert!(matches!(
            Arc::clone(&scheduler)
                .handle_alloc_native_job(
                    &AcceptAssign,
                    missing,
                    &NetworkSnapshot::default(),
                    Default::default()
                )
                .await?,
            AllocJobResult::Fail { .. }
        ));
        scheduler.handle_update_job_state(job_alloc.job_id, a, JobState::Complete)?;
        // The terminal result occupies a reservation until the worker acknowledges it.
        scheduler.handle_heartbeat_server(
            a,
            nonce_a,
            0.0,
            &[second.job_id],
            Box::new(TestJobAuthorizer),
            dist::WorkerCapabilities {
                native_platform: Some(platform),
                native_placement: Some(dist::NativePlacement {
                    queue: dist::NativeQueueSnapshot {
                        capacity: 2,
                        compiler_slots: 1,
                        staging_slots: 2,
                        publication_slots: 2,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            },
        )?;
        let AllocJobResult::Success { job_alloc, .. } =
            tokio::time::timeout(Duration::from_secs(5), waiting).await??
        else {
            bail!("queued work did not become available after completion");
        };
        assert_eq!(job_alloc.server_id, a);
        Ok(())
    }

    #[cfg(feature = "scheduler-dashboard")]
    #[test]
    fn scheduler_status_does_not_wait_for_busy_scheduling_locks() {
        let scheduler = Scheduler::new_with_job_slack(JobSlackConfig {
            static_jobs: 0,
            percent: 200.0,
        });
        {
            let _servers = scheduler.servers.lock().unwrap();
            assert!(scheduler.handle_dashboard_snapshot().is_err());
            assert!(scheduler.jobs.try_lock().is_ok());
        }
        {
            let _jobs = scheduler.jobs.lock().unwrap();
            assert!(scheduler.handle_dashboard_snapshot().is_err());
        }
        assert!(scheduler.handle_dashboard_snapshot().is_ok());
    }

    #[tokio::test]
    async fn scheduler_status_tracks_per_worker_admission_and_capacity_changes() -> Result<()> {
        let scheduler = Arc::new(Scheduler::new());
        let ids = [
            ServerId::from_digest([1; 32]),
            ServerId::from_digest([2; 32]),
        ];
        let nonce = ServerNonce::new();
        let capabilities = |capacity| dist::WorkerCapabilities {
            native_platform: Some(test_platform()),
            native_placement: Some(dist::NativePlacement {
                queue: dist::NativeQueueSnapshot {
                    capacity,
                    compiler_slots: 1,
                    staging_slots: 1,
                    publication_slots: 1,
                    ..Default::default()
                },
                ..Default::default()
            }),
        };
        for (id, capacity) in ids.into_iter().zip([2, 3]) {
            scheduler.handle_heartbeat_server(
                id,
                nonce.clone(),
                0.0,
                &[],
                Box::new(TestJobAuthorizer),
                capabilities(capacity),
            )?;
        }
        let status = scheduler.handle_status()?;
        assert_eq!(
            (status.num_cpus, status.max_jobs, status.available_jobs),
            (0, 5, 5)
        );
        for _ in 0..5 {
            assert!(matches!(
                test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'c').await?,
                AllocJobResult::Success { .. }
            ));
        }
        let status = scheduler.handle_status()?;
        assert_eq!(
            (status.in_progress, status.max_jobs, status.available_jobs),
            (5, 5, 0)
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'c')
            )
            .await
            .is_err()
        );
        let assigned = {
            let servers = scheduler.servers.lock().unwrap();
            servers[&ids[1]]
                .jobs_assigned
                .keys()
                .copied()
                .collect::<Vec<_>>()
        };
        scheduler.handle_heartbeat_server(
            ids[1],
            nonce,
            0.0,
            &assigned,
            Box::new(TestJobAuthorizer),
            capabilities(4),
        )?;
        let status = scheduler.handle_status()?;
        assert_eq!(
            (status.in_progress, status.max_jobs, status.available_jobs),
            (5, 6, 1)
        );
        #[cfg(feature = "scheduler-dashboard")]
        {
            let snapshot = scheduler.handle_dashboard_snapshot()?;
            assert_eq!(snapshot.totals.available, status.available_jobs);
            assert_eq!(snapshot.totals.max_jobs, status.max_jobs);
        }
        Ok(())
    }

    struct StatusDuringAssign<'a>(&'a Scheduler);

    #[async_trait::async_trait]
    impl SchedulerOutgoing for StatusDuringAssign<'_> {
        async fn do_assign_job(
            &self,
            _server_id: ServerId,
            job_id: JobId,
            _assignment: NativeAssignment,
            _auth: String,
        ) -> Result<AssignJobResult> {
            let _ = job_id;
            // Status must include reservations even before a JobDetail exists.
            let status = self.0.handle_status()?;
            assert_eq!(status.in_progress, 1);
            assert_eq!(status.available_jobs, status.max_jobs - 1);
            #[cfg(feature = "scheduler-dashboard")]
            {
                let snapshot = self.0.handle_dashboard_snapshot()?;
                assert_eq!(snapshot.totals.assigned, 1);
                assert_eq!(snapshot.totals.assigning, 1);
                assert_eq!(snapshot.jobs.len(), 1);
                assert_eq!(snapshot.jobs[0].id, job_id.to_string());
                assert_eq!(snapshot.jobs[0].state, "Assigning");
            }
            Ok(AssignJobResult {
                state: JobState::Pending,
            })
        }
    }

    struct SnapshotDuringAssign<'a> {
        scheduler: &'a Scheduler,
        nonce: ServerNonce,
    }

    #[async_trait::async_trait]
    impl SchedulerOutgoing for SnapshotDuringAssign<'_> {
        async fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            _assignment: NativeAssignment,
            _auth: String,
        ) -> Result<AssignJobResult> {
            let snapshot = self.scheduler.handle_heartbeat_server(
                server_id,
                self.nonce.clone(),
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
                test_capabilities(),
            )?;
            assert_eq!(snapshot.assigned_job_ids, vec![job_id]);
            Ok(AssignJobResult {
                state: JobState::Pending,
            })
        }
    }

    #[tokio::test]
    async fn heartbeat_reports_inflight_and_accepted_assignments() -> Result<()> {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } = test_allocate(
            Arc::clone(&scheduler),
            &SnapshotDuringAssign {
                scheduler: &scheduler,
                nonce: nonce.clone(),
            },
            'c',
        )
        .await?
        else {
            panic!("expected job allocation");
        };
        let snapshot = scheduler.handle_heartbeat_server(
            server_id,
            nonce.clone(),
            1.0,
            &[],
            Box::new(TestJobAuthorizer),
            test_capabilities(),
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
            test_capabilities(),
        )?;
        assert!(snapshot.assigned_job_ids.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn status_counts_assignment_rpc_reservations() {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        register_test_server(&scheduler, server_id, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } =
            test_allocate(Arc::clone(&scheduler), &StatusDuringAssign(&scheduler), 'c')
                .await
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

    struct StalledAssign(tokio::sync::Notify);

    #[async_trait::async_trait]
    impl SchedulerOutgoing for StalledAssign {
        async fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _assignment: NativeAssignment,
            _auth: String,
        ) -> Result<AssignJobResult> {
            self.0.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancelled_assignment_releases_reserved_capacity() -> Result<()> {
        let scheduler = Arc::new(Scheduler::new());
        let worker = ServerId::from_digest([1; 32]);
        register_test_server(&scheduler, worker, ServerNonce::new());
        let requester = Arc::new(StalledAssign(tokio::sync::Notify::new()));
        let task = tokio::spawn({
            let scheduler = Arc::clone(&scheduler);
            let requester = Arc::clone(&requester);
            async move { test_allocate(scheduler, requester.as_ref(), 'c').await }
        });
        tokio::time::timeout(Duration::from_secs(5), requester.0.notified()).await?;
        assert_eq!(scheduler.handle_status()?.in_progress, 1);
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        assert_no_assigned_jobs(&scheduler, &worker);
        assert_eq!(scheduler.handle_status()?.in_progress, 0);
        Ok(())
    }

    #[tokio::test]
    async fn maintenance_drain_refuses_new_allocations_without_creating_job_state() {
        let dir = tempfile::tempdir().unwrap();
        let drain = dir.path().join("scheduler-drain");
        let scheduler = Arc::new(Scheduler::new_with_job_slack_and_drain(
            JobSlackConfig::default(),
            Some(drain.clone()),
        ));
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        register_test_server(&scheduler, server_id, ServerNonce::new());

        std::fs::write(&drain, b"drain").unwrap();
        assert!(scheduler.handle_is_draining());
        assert_eq!(scheduler.handle_status().unwrap().available_jobs, 0);
        let allocation = test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'c')
            .await
            .unwrap();
        assert!(matches!(allocation, AllocJobResult::Fail { .. }));
        assert_no_assigned_jobs(&scheduler, &server_id);

        std::fs::remove_file(&drain).unwrap();
        assert!(!scheduler.handle_is_draining());
        let allocation = test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'c')
            .await
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

    #[async_trait::async_trait]
    impl SchedulerOutgoing for ReapDuringAssign<'_> {
        async fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            _assignment: NativeAssignment,
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
                test_capabilities(),
            )?;
            assert!(!heartbeat.is_new);

            Ok(AssignJobResult {
                state: JobState::Pending,
            })
        }
    }

    #[tokio::test]
    async fn ready_transition_starts_its_own_unclaimed_timeout() {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());

        let AllocJobResult::Success { job_alloc, .. } =
            test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'c')
                .await
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
                test_capabilities(),
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
                test_capabilities(),
            )
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[tokio::test]
    async fn progressing_pending_upload_renews_lease_but_inactive_upload_expires() -> Result<()> {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } =
            test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'c').await?
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
            test_capabilities(),
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
            test_capabilities(),
        )?;
        assert_no_assigned_jobs(&scheduler, &server_id);
        Ok(())
    }

    #[tokio::test]
    async fn pending_jobs_expire_but_started_jobs_remain_owned_by_execution() {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());

        let AllocJobResult::Success { job_alloc, .. } =
            test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'c')
                .await
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
                test_capabilities(),
            )
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);

        let AllocJobResult::Success { job_alloc, .. } =
            test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'c')
                .await
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
                test_capabilities(),
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

        fn generate_blob_token(
            &self,
            _blob: sccache::build_runtime::BlobRef,
            _recipient: sccache::build_runtime::wire::BlobRecipient,
        ) -> Result<String> {
            bail!("synthetic authorization failure")
        }

        fn verify_blob_token(
            &self,
            _blob: sccache::build_runtime::BlobRef,
            _recipient: sccache::build_runtime::wire::BlobRecipient,
            _token: &str,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn failed_token_generation_never_reserves_capacity() {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        scheduler
            .handle_heartbeat_server(
                server_id,
                ServerNonce::new(),
                1.0,
                &[],
                Box::new(RejectToken),
                test_capabilities(),
            )
            .unwrap();
        assert!(
            test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'c')
                .await
                .is_err()
        );
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[tokio::test]
    async fn completion_without_assignment_does_not_discard_job() {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        register_test_server(&scheduler, server_id, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } =
            test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'c')
                .await
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

    #[tokio::test]
    async fn started_jobs_reconcile_against_worker_running_inventory() {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } =
            test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'd')
                .await
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
                test_capabilities(),
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
                test_capabilities(),
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
                test_capabilities(),
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

    #[tokio::test]
    async fn only_the_completing_worker_can_retry_a_known_completion() -> Result<()> {
        let scheduler = Arc::new(Scheduler::new());
        let owner: ServerId = ServerId::from_digest([1; 32]);
        let other: ServerId = ServerId::from_digest([2; 32]);
        register_test_server(&scheduler, owner, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } =
            test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'f').await?
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

    #[tokio::test]
    async fn returned_running_job_resets_missing_heartbeat_grace() {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } =
            test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'd')
                .await
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
                test_capabilities(),
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
                test_capabilities(),
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
                test_capabilities(),
            )
            .unwrap();
        assert!(scheduler.jobs.lock().unwrap().contains_key(&job_id));
        scheduler
            .handle_update_job_state(job_id, server_id, JobState::Complete)
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[tokio::test]
    async fn state_acknowledgments_are_idempotent() {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        register_test_server(&scheduler, server_id, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } =
            test_allocate(Arc::clone(&scheduler), &AcceptAssign, 'd')
                .await
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
                test_capabilities(),
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
                test_capabilities(),
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
                    test_capabilities(),
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
                test_capabilities(),
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

    #[tokio::test]
    async fn allocation_fails_if_assignment_is_cleaned_up() {
        let scheduler = Arc::new(Scheduler::new());
        let server_id: ServerId = ServerId::from_digest([1; 32]);
        let server_nonce = ServerNonce::new();

        register_test_server(&scheduler, server_id, server_nonce.clone());

        let requester = ReapDuringAssign {
            scheduler: &scheduler,
            server_id,
            server_nonce,
        };
        let allocation = test_allocate(Arc::clone(&scheduler), &requester, 'c')
            .await
            .unwrap();

        assert!(matches!(allocation, AllocJobResult::Fail { .. }));
        assert_no_assigned_jobs(&scheduler, &server_id);
    }
}
