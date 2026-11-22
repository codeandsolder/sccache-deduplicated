//! Connect ordinary compiler discovery to the native execution contract.
//! The scheduler owns results; the client neither initializes nor writes an
//! archive cache. The existing compiler frontends still determine whether
//! a compilation is cacheable and supply its input closure.

use std::{
    collections::BTreeMap,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use crate::{
    build_runtime::{
        BuildPath, CommandSpec, ContentId, ExecutionRoot, ExecutionSpec, OutputSpec, PreparedTree,
        SourceDigestCache, TreeRecipe,
    },
    cache::FileObjectSource,
    client::{SharedConnection, connection_task},
    config::{DistAuth, DistToolchainConfig, HTTPUrl, NativeClientConfig},
    dist::{
        self,
        native::{NativeBuildResult, NativeBuildSource, NativeCacheClient, broker},
        pkg,
    },
    mock_command::CommandCreatorSync,
    protocol::{NativeNamespacePolicy, Request, Response},
    server::{DistClientContainer, DistInfo, SccacheService},
};

use super::{
    CacheControl, Cacheable, Compilation, CompileResult, CompileTransport, DistPackagers, DistType,
};

struct DirectEndpoint {
    config: NativeClientConfig,
    scheduler: Option<HTTPUrl>,
    auth: DistAuth,
}

enum Endpoint {
    Direct(Box<DirectEndpoint>),
    Namespace {
        connection: SharedConnection,
        chunk_bytes: usize,
    },
}

pub struct NativeCompilerClient {
    endpoint: Endpoint,
    policy: NativeNamespacePolicy,
    toolchains: Vec<DistToolchainConfig>,
    toolchain_digests: Arc<SourceDigestCache>,
}

fn installed_digest_cache(catalogs: &[PathBuf]) -> Arc<SourceDigestCache> {
    let mut cache = SourceDigestCache::default();
    for path in catalogs {
        if let Err(error) = cache.load_catalog(path) {
            warn!(
                "Native installation catalog {} unavailable: {error:#}",
                path.display()
            );
        }
    }
    Arc::new(cache)
}

impl NativeCompilerClient {
    pub fn new(
        config: NativeClientConfig,
        scheduler: Option<HTTPUrl>,
        auth: DistAuth,
        toolchains: Vec<DistToolchainConfig>,
        catalogs: &[PathBuf],
    ) -> Self {
        let policy = NativeNamespacePolicy {
            platform: ContentId::of(config.platform_contract.as_bytes()),
            build_timeout_secs: config.build_timeout_secs,
            renewal_interval_secs: config.renewal_interval_secs,
            max_metadata_bytes: config.max_metadata_bytes,
            max_result_bytes: config.max_result_bytes,
        };
        Self {
            endpoint: Endpoint::Direct(Box::new(DirectEndpoint {
                config,
                scheduler,
                auth,
            })),
            policy,
            toolchains,
            toolchain_digests: installed_digest_cache(catalogs),
        }
    }

    pub fn from_namespace(
        connection: SharedConnection,
        chunk_bytes: usize,
        policy: NativeNamespacePolicy,
        toolchains: Vec<DistToolchainConfig>,
        catalogs: &[PathBuf],
    ) -> Self {
        Self {
            endpoint: Endpoint::Namespace {
                connection,
                chunk_bytes,
            },
            policy,
            toolchains,
            toolchain_digests: installed_digest_cache(catalogs),
        }
    }

    pub fn toolchain_digests(&self) -> Arc<SourceDigestCache> {
        Arc::clone(&self.toolchain_digests)
    }

    pub const fn namespace_policy(&self) -> &NativeNamespacePolicy {
        &self.policy
    }

    pub fn serve_namespace(&self, stream: broker::DaemonStream) -> Result<()> {
        let client = self.connect_http()?;
        broker::serve_action(&client, &self.policy, stream)
    }

    pub async fn status(&self) -> DistInfo {
        match &self.endpoint {
            Endpoint::Namespace { connection, .. } => {
                let result = connection_task(Arc::clone(connection), |conn| {
                    let Response::DistStatus(status) = conn.request(Request::DistStatus)? else {
                        anyhow::bail!("unexpected native namespace distribution status");
                    };
                    Ok(status)
                })
                .await;
                result.unwrap_or_else(|error| {
                    DistInfo::NotConnected(None, format!("native daemon unavailable: {error:#}"))
                })
            }
            Endpoint::Direct(endpoint) => {
                let DirectEndpoint {
                    config, scheduler, ..
                } = endpoint.as_ref();
                let result = async {
                    let scheduler = scheduler.as_ref().context("scheduler URL unavailable")?;
                    let url = dist::http::urls::scheduler_status(&scheduler.to_url())?;
                    let client = crate::util::new_reqwest_client_builder()?
                        .timeout(Duration::from_secs(config.request_timeout_secs))
                        .build()?;
                    dist::http::common::bincode_req_fut(client.get(url)).await
                }
                .await;
                match result {
                    Ok(status) => DistInfo::SchedulerStatus(scheduler.clone(), status),
                    Err(error) => DistInfo::NotConnected(
                        scheduler.clone(),
                        format!("native scheduler unavailable: {error:#}"),
                    ),
                }
            }
        }
    }

    fn allows_automatic_toolchain(&self, executable: &Path) -> bool {
        !self.toolchains.iter().any(|configured| match configured {
            DistToolchainConfig::NoDist {
                compiler_executable,
            }
            | DistToolchainConfig::PathOverride {
                compiler_executable,
                ..
            } => compiler_executable == executable,
        })
    }

    fn connect_http(&self) -> Result<NativeCacheClient> {
        let Endpoint::Direct(endpoint) = &self.endpoint else {
            anyhow::bail!("namespace client cannot authenticate directly with scheduler");
        };
        let DirectEndpoint { config, auth, .. } = endpoint.as_ref();
        let token = match auth {
            DistAuth::Token { token } => token.clone(),
            DistAuth::Oauth2CodeGrantPKCE { auth_url, .. }
            | DistAuth::Oauth2Implicit { auth_url, .. } => {
                DistClientContainer::get_cached_config_auth_token(auth_url)?
            }
        };
        NativeCacheClient::new(
            config.endpoint.to_url(),
            token,
            Duration::from_secs(config.request_timeout_secs),
            config.max_metadata_bytes,
        )
    }

    fn execute(&self, plan: &CompilerPlan) -> Result<NativeBuildResult> {
        match &self.endpoint {
            Endpoint::Direct(_) => self.connect_http()?.run_action(
                &plan.spec,
                &plan.inputs,
                &plan.destinations,
                &self.policy.build_policy(),
            ),
            Endpoint::Namespace {
                connection,
                chunk_bytes,
            } => broker::run_action(
                connection,
                *chunk_bytes,
                &self.policy,
                &plan.spec,
                &plan.inputs,
                &plan.destinations,
            ),
        }
    }
}

struct CompilerPlan {
    spec: ExecutionSpec,
    inputs: Vec<PreparedTree>,
    destinations: BTreeMap<String, PathBuf>,
}

impl CompilerPlan {
    fn prepare(
        command: dist::CompileCommand,
        cwd: &Path,
        outputs: Vec<FileObjectSource>,
        transformer: dist::PathTransformer,
        packagers: DistPackagers,
        platform: ContentId,
        toolchain_digests: &SourceDigestCache,
    ) -> Result<Self> {
        let mut layout = pkg::CompilerInputs::new(transformer);
        layout.directory(cwd)?;
        let mut paths = BTreeMap::new();
        let mut destinations = BTreeMap::new();
        for output in outputs {
            let local = cwd.join(output.path);
            ensure!(
                local != Path::new("/dev/null"),
                "native outputs must be regular files"
            );
            match std::fs::symlink_metadata(&local) {
                Ok(metadata) => ensure!(
                    metadata.is_file(),
                    "native output would replace a nonregular file"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect native output destination"),
            }
            let parent = local.parent().context("native output parent missing")?;
            let name = local.file_name().context("native output name missing")?;
            // The input layout preserves symlink and parent traversal. The
            // output descriptor addresses the actual resolved backing entry.
            let remote_parent = layout.directory(parent)?;
            let remote = Path::new(&remote_parent).join(name);
            let path = BuildPath::new(remote.as_os_str().as_bytes().to_vec())?;
            ensure!(
                paths
                    .insert(
                        output.key.clone(),
                        OutputSpec {
                            path,
                            required: !output.optional
                        }
                    )
                    .is_none(),
                "duplicate native output key"
            );
            destinations.insert(output.key, local);
        }
        let (inputs, toolchain) = packagers;
        let before = toolchain_digests.catalog_hits();
        let start = Instant::now();
        let toolchain = toolchain
            .native_mapping()?
            .prepare_with_cache(toolchain_digests)?;
        let after = toolchain_digests.catalog_hits();
        debug!(
            "native toolchain preparation took {:.3}s; verified installation memo: {} files, {} bytes (process totals: {} files, {} bytes)",
            start.elapsed().as_secs_f64(),
            after.0.saturating_sub(before.0),
            after.1.saturating_sub(before.1),
            after.0,
            after.1
        );
        let inputs = inputs.native_mapping()?.prepare()?;
        let layout = layout.into_native_mapping()?.prepare()?;
        let directories = pkg::native_directory_metadata()?;
        let inputs = vec![toolchain, inputs, layout];
        let recipe = TreeRecipe::union(directories, inputs.iter().map(PreparedTree::id));
        let root = ExecutionRoot::resolve(
            recipe,
            &inputs
                .iter()
                .map(|tree| (tree.id(), tree.manifest()))
                .collect(),
        )?;
        let spec = ExecutionSpec {
            platform,
            root,
            mounts: BTreeMap::new(),
            command: CommandSpec {
                executable: BuildPath::new(command.executable.into_bytes())?,
                arguments: command
                    .arguments
                    .into_iter()
                    .map(String::into_bytes)
                    .collect(),
                cwd: BuildPath::new(command.cwd.into_bytes())?,
                environment: command
                    .env_vars
                    .into_iter()
                    .map(|(name, value)| (name.into_bytes(), value.into_bytes()))
                    .collect(),
            },
            outputs: paths,
        };
        spec.validate()?;
        Ok(Self {
            spec,
            inputs,
            destinations,
        })
    }
}

pub(super) async fn compile<T: CommandCreatorSync>(
    client: Arc<NativeCompilerClient>,
    service: &SccacheService<T>,
    creator: T,
    cwd: PathBuf,
    compilation: Box<dyn Compilation<T>>,
    control: CacheControl,
    pool: &tokio::runtime::Handle,
) -> Result<(CompileResult, process::Output)> {
    let start = Instant::now();
    let mut transformer = dist::PathTransformer::new();
    let (local, remote, cacheable) =
        compilation.generate_compile_commands(&mut transformer, CompileTransport::Native)?;
    let eligible = control == CacheControl::Default
        && cacheable == Cacheable::Yes
        && compilation.is_locally_preprocessed()
        && compilation.automatic_dist_toolchain_is_ready()
        && client.allows_automatic_toolchain(&local.get_executable());
    let mut fallback = DistType::NoDist;
    if let Some(remote) = remote.filter(|_| eligible) {
        let result = (|| {
            super::core::validate_dist_environment_dependencies(
                &remote,
                &compilation.dist_environment_dependencies(),
            )?;
            let outputs = compilation
                .outputs()
                .filter(|output| output.key != "d")
                .collect();
            // Preserve root mappings, but do not carry the large reverse
            // path table into the independent directory-only plan.
            let mut layout = dist::PathTransformer::new();
            for (local, remote) in transformer.path_mappings() {
                layout.add_root_mapping(local, &remote);
            }
            let packagers = compilation.into_dist_packagers(transformer)?;
            Ok::<_, anyhow::Error>(pool.spawn_blocking(move || {
                let plan = CompilerPlan::prepare(
                    remote,
                    &cwd,
                    outputs,
                    layout,
                    packagers,
                    client.policy.platform,
                    &client.toolchain_digests,
                )?;
                client.execute(&plan)
            }))
        })();
        let result = match result {
            Ok(task) => task.await?,
            Err(error) => Err(error),
        };
        match result {
            Ok(result) if result.output.status.success() => {
                let elapsed = start.elapsed();
                let classification = match result.source {
                    NativeBuildSource::Hit => CompileResult::CacheHit(elapsed),
                    NativeBuildSource::Worker(addr) => {
                        CompileResult::NativeMiss(DistType::Ok(addr.to_string()), elapsed)
                    }
                };
                return Ok((classification, result.output));
            }
            Ok(result) => {
                // Incomplete compiler environment discovery can also produce
                // an ordinary nonzero exit. Preserve caller semantics by
                // rerunning locally without writing an archive cache.
                warn!(
                    "native compilation failed on {:?}; retrying locally",
                    result.source
                );
                fallback = DistType::Error;
            }
            Err(error) => {
                warn!("native compilation unavailable; compiling locally: {error:#}");
                fallback = DistType::Error;
            }
        }
    }
    let output = local.execute(service, &creator).await?;
    let result = if output.status.success() {
        CompileResult::NotCached(fallback, start.elapsed())
    } else {
        CompileResult::CompileFailed(fallback, start.elapsed())
    };
    Ok((result, output))
}

#[cfg(all(test, feature = "native-store"))]
mod tests {
    use super::*;
    use crate::{
        build_runtime::{ExecutionPolicy, NativeStore, execute},
        cache::storage_from_config,
        compiler::{CompilerArguments, GenerateHashKeyContext, get_compiler_info},
        config::Config,
        jobserver::Client,
        mock_command::ProcessCommandCreator,
    };
    use std::{ffi::OsString, io::Read};

    fn config() -> Result<Config> {
        let endpoint = HTTPUrl::from_url(reqwest::Url::parse("http://127.0.0.1:1/")?);
        let mut config = Config::default();
        config.dist.scheduler_url = Some(endpoint.clone());
        config.dist.native = Some(NativeClientConfig {
            endpoint,
            platform_contract: "test".into(),
            request_timeout_secs: 1,
            build_timeout_secs: 60,
            renewal_interval_secs: 1,
            max_metadata_bytes: 64 * 1024 * 1024,
            max_result_bytes: 64 * 1024 * 1024,
        });
        Ok(config)
    }

    fn verify_compilation(
        executable: &Path,
        args: &[&str],
        name: &str,
        source: &str,
    ) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let cwd = temp.path().canonicalize()?;
        std::fs::write(cwd.join(name), source)?;
        std::fs::create_dir(cwd.join("build"))?;
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let environment = vec![("PATH".into(), "/usr/bin:/bin".into())];
        let rt = tokio::runtime::Runtime::new()?;
        let pool = rt.handle();
        let mut config = config()?;
        config.fallback_cache.dir = cwd.join("unexpected-archive-cache");
        config.dist.cache_dir = cwd.join("unexpected-toolchain-cache");
        let storage = storage_from_config(&config, pool)?;
        assert_eq!(storage.cache_type_name(), "native");
        let creator = ProcessCommandCreator::new(&Client::new_num(1));
        let (compiler, _) = rt.block_on(get_compiler_info(
            creator.clone(),
            executable,
            &cwd,
            &args,
            &environment,
            pool,
            crate::compiler::CompilerDiscovery::default(),
        ))?;
        let CompilerArguments::Ok(mut hasher) = compiler.parse_arguments(&args, &cwd, &environment)
        else {
            anyhow::bail!("real compiler arguments are not cacheable");
        };
        let hashed = rt.block_on(hasher.generate_hash_key(GenerateHashKeyContext {
            creator: &creator,
            cwd: cwd.clone(),
            env_vars: environment.clone(),
            may_dist: true,
            pool,
            rewrite_includes_only: false,
            storage,
            cache_control: CacheControl::Default,
        }))?;
        assert_eq!(hashed.cache_control, CacheControl::Default);
        let compilation = hashed.compilation;
        let mut transformer = dist::PathTransformer::new();
        let (_, remote, cacheable) =
            compilation.generate_compile_commands(&mut transformer, CompileTransport::Native)?;
        assert_eq!(cacheable, Cacheable::Yes);
        let remote = remote.context("no distributed command for real compiler")?;
        super::super::core::validate_dist_environment_dependencies(
            &remote,
            &compilation.dist_environment_dependencies(),
        )?;
        let outputs = compilation
            .outputs()
            .filter(|output| output.key != "d")
            .collect();
        let mut layout = dist::PathTransformer::new();
        for (local, remote) in transformer.path_mappings() {
            layout.add_root_mapping(local, &remote);
        }
        let platform = ContentId::of(b"test");
        let plan = CompilerPlan::prepare(
            remote,
            &cwd,
            outputs,
            layout,
            compilation.into_dist_packagers(transformer)?,
            platform,
            &SourceDigestCache::default(),
        )?;
        let store = NativeStore::open(&cwd.join("native-store"))?;
        let _leases = plan
            .inputs
            .iter()
            .map(|tree| tree.import(&store))
            .collect::<Result<Vec<_>>>()?;
        let result = execute(
            &plan.spec,
            &store,
            &ExecutionPolicy {
                platform,
                bubblewrap: "/usr/bin/bwrap".into(),
                scratch: cwd.clone(),
                timeout: Duration::from_secs(60),
                max_result_bytes: 64 * 1024 * 1024,
            },
            || Ok(()),
        )?;
        if !result.status().success() {
            let mut stderr = Vec::new();
            if let Some(blob) = result.diagnostics().1 {
                result.open_blob(blob.id)?.read_to_end(&mut stderr)?;
            }
            anyhow::bail!(
                "isolated compiler failed: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        let manifest = result
            .successful_result()
            .context("compiler produced no result")?;
        plan.spec.action_request()?.validate_result(manifest)?;
        let reference = process::Command::new(executable)
            .args(&args)
            .current_dir(&cwd)
            .env_clear()
            .envs(environment)
            .output()?;
        ensure!(
            reference.status.success(),
            "local compiler failed: {}",
            String::from_utf8_lossy(&reference.stderr)
        );
        for (name, output) in &manifest.outputs {
            let mut bytes = Vec::new();
            result.open_blob(output.blob.id)?.read_to_end(&mut bytes)?;
            assert_eq!(
                ContentId::of(&bytes),
                ContentId::of(&std::fs::read(&plan.destinations[name])?),
                "output {name} differs from local compile"
            );
        }
        assert!(!config.fallback_cache.dir.exists());
        assert!(!config.dist.cache_dir.exists());
        Ok(())
    }

    #[test]
    #[ignore = "requires GCC, ldd and Linux Bubblewrap"]
    fn native_gcc_compiler_plan() -> Result<()> {
        verify_compilation(
            Path::new("/usr/bin/gcc"),
            &[
                "-c",
                "input.c",
                "-o",
                "build/input.o",
                "-MMD",
                "-MF",
                "build/input.d",
            ],
            "input.c",
            "int square(int x) { return x*x; }\n",
        )
    }

    #[test]
    #[ignore = "requires a Rust toolchain, ldd and Linux Bubblewrap"]
    fn native_rust_compiler_plan() -> Result<()> {
        let sysroot = process::Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()?;
        ensure!(sysroot.status.success(), "rustc sysroot lookup failed");
        let sysroot = PathBuf::from(String::from_utf8(sysroot.stdout)?.trim());
        verify_compilation(
            &sysroot.join("bin/rustc"),
            &[
                "--crate-name",
                "input",
                "--crate-type",
                "rlib",
                "--emit=link,dep-info",
                "--out-dir",
                "build",
                "input.rs",
            ],
            "input.rs",
            "pub fn square(x: i32) -> i32 { x*x }\n",
        )
    }
}
