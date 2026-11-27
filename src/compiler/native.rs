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
        ActionKey, ActionMode, BuildPath, CommandSpec, CompilerResultIdentity, ContentId,
        DescriptorDigestProvider, ExecutionRoot, ExecutionSpec, OutputKind, OutputSpec,
        PreparedTree, SourceDigestCache, TreeEntry, TreeId, TreeManifest, TreeRecipe,
        TreeTimestamp,
    },
    cache::FileObjectSource,
    client::{SharedConnection, connection_task},
    config::{DistAuth, DistToolchainConfig, HTTPUrl, NativeClientConfig},
    dist::{
        self,
        native::{LocalExecutor, NativeBuildResult, NativeCacheClient, broker},
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
    cluster: Option<sccache_peer_identity::PeerConfig>,
    client: std::sync::Mutex<Option<NativeCacheClient>>,
    auth: DistAuth,
    local: Option<LocalExecutor>,
    intermediates: crate::dist::native::result_session::Registry,
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

fn installed_digest_cache(
    catalogs: &[PathBuf],
    provider: Option<DescriptorDigestProvider>,
) -> Arc<SourceDigestCache> {
    let mut cache = SourceDigestCache::default().with_descriptor_provider(provider);
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
        cluster: Option<sccache_peer_identity::PeerConfig>,
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
        let local = config
            .local_execution
            .clone()
            .map(|config| LocalExecutor::new(config, policy.platform));
        Self {
            endpoint: Endpoint::Direct(Box::new(DirectEndpoint {
                config,
                scheduler,
                cluster,
                client: std::sync::Mutex::new(None),
                auth,
                local,
                intermediates: crate::dist::native::result_session::Registry::default(),
            })),
            policy,
            toolchains,
            toolchain_digests: installed_digest_cache(catalogs, None),
        }
    }

    pub fn from_namespace(
        connection: SharedConnection,
        chunk_bytes: usize,
        policy: NativeNamespacePolicy,
        toolchains: Vec<DistToolchainConfig>,
        catalogs: &[PathBuf],
        provider: Option<DescriptorDigestProvider>,
    ) -> Self {
        Self {
            endpoint: Endpoint::Namespace {
                connection,
                chunk_bytes,
            },
            policy,
            toolchains,
            toolchain_digests: installed_digest_cache(catalogs, provider),
        }
    }

    pub(crate) fn reference(
        &self,
        file: &std::fs::File,
    ) -> Result<
        Option<(
            crate::build_runtime::BlobRef,
            crate::build_runtime::ReferenceBlobProvider,
        )>,
    > {
        use crate::{
            build_runtime::intermediate_fs::intermediate_reference,
            protocol::{TransferReply, TransferRequest},
        };
        let Some(reference) = intermediate_reference(file)? else {
            return Ok(None);
        };
        let provider = match &self.endpoint {
            Endpoint::Direct(endpoint) => {
                // SAFETY: geteuid only queries process credentials.
                let group = endpoint
                    .intermediates
                    .get(unsafe { libc::geteuid() }, reference.session)?;
                group.authorize(reference.blob)?;
                crate::build_runtime::ReferenceBlobProvider::new(move |blob| {
                    Ok(Box::new(group.read(blob)?))
                })
            }
            Endpoint::Namespace { connection, .. } => {
                ensure!(
                    matches!(
                        connection.blocking_lock().transfer(
                            TransferRequest::IntermediateAuthorize {
                                session: reference.session,
                                blob: reference.blob
                            }
                        )?,
                        TransferReply::Ack
                    ),
                    "unexpected intermediate authorization response"
                );
                crate::dist::native::intermediate::source(reference)
            }
        };
        log::debug!("using retained CAS input {:?}", reference.blob.id);
        Ok(Some((reference.blob, provider)))
    }

    pub(crate) async fn hash_files(
        self: &Arc<Self>,
        files: &[PathBuf],
        pool: &tokio::runtime::Handle,
    ) -> Result<Vec<String>> {
        let jobs = files.iter().map(|path| {
            let client = Arc::clone(self);
            let path = path.clone();
            pool.spawn_blocking(move || {
                let file = std::fs::File::open(path)?;
                if let Some((blob, _)) = client.reference(&file)? {
                    Ok(crate::util::hex(&blob.id.0))
                } else {
                    crate::util::Digest::reader_sync(file)
                }
            })
        });
        futures::future::try_join_all(jobs)
            .await?
            .into_iter()
            .collect()
    }

    pub fn toolchain_digests(&self) -> Arc<SourceDigestCache> {
        Arc::clone(&self.toolchain_digests)
    }

    pub const fn namespace_policy(&self) -> &NativeNamespacePolicy {
        &self.policy
    }

    pub fn serve_namespace(&self, stream: broker::DaemonStream, uid: u32) -> Result<()> {
        let client = self.connect_http()?;
        let Endpoint::Direct(endpoint) = &self.endpoint else {
            anyhow::bail!("native namespace endpoint cannot serve");
        };
        broker::serve_action(
            &client,
            &self.policy,
            stream,
            endpoint.local.as_ref(),
            &endpoint.intermediates,
            uid,
        )
    }

    pub(crate) fn open_intermediate(
        &self,
        uid: u32,
    ) -> Result<(
        crate::build_runtime::wire::Ticket,
        Arc<crate::dist::native::result_session::NativeResultSession>,
    )> {
        let Endpoint::Direct(endpoint) = &self.endpoint else {
            anyhow::bail!("intermediate registry is daemon-owned");
        };
        let session = Arc::new(
            crate::dist::native::result_session::NativeResultSession::open(
                self.connect_http()?,
                Duration::from_secs(self.policy.renewal_interval_secs),
            )?,
        );
        let token = endpoint.intermediates.insert(uid, &session)?;
        Ok((token, session))
    }

    pub(crate) fn intermediate(
        &self,
        uid: u32,
        token: crate::build_runtime::wire::Ticket,
    ) -> Result<Arc<crate::dist::native::result_session::NativeResultSession>> {
        let Endpoint::Direct(endpoint) = &self.endpoint else {
            anyhow::bail!("intermediate registry is daemon-owned");
        };
        endpoint.intermediates.get(uid, token)
    }

    pub async fn status(self: &Arc<Self>) -> DistInfo {
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
                let scheduler = &endpoint.scheduler;
                let client = Arc::clone(self);
                let result = async {
                    // Enrollment and credential refresh use the synchronous
                    // cluster runtime bridge; do not block the async IPC task.
                    let transport =
                        tokio::task::spawn_blocking(move || client.connect_http()).await??;
                    transport.scheduler_status().await
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
        let mut saved = endpoint
            .client
            .lock()
            .map_err(|_| anyhow::anyhow!("native client credentials poisoned"))?;
        if let Some(client) = saved.as_ref().cloned() {
            drop(saved);
            client.refresh_credentials();
            return Ok(client);
        }
        let cluster = endpoint
            .cluster
            .clone()
            .context("native client cluster trust required")?;
        let scheduler = endpoint
            .scheduler
            .as_ref()
            .context("native client scheduler endpoint required")?;
        let auth = auth.clone();
        let peer = crate::dist::cluster::open_peer(
            cluster,
            &scheduler.to_url(),
            sccache_cluster_identity::Role::Client,
            move || DistClientContainer::enrollment_token(&auth),
        )?;
        let client = NativeCacheClient::new(
            &config.endpoint.to_url(),
            peer,
            Duration::from_secs(config.request_timeout_secs),
            config.max_metadata_bytes,
        )?;
        *saved = Some(client.clone());
        drop(saved);
        Ok(client)
    }

    async fn execute(
        self: Arc<Self>,
        plan: CompilerPlan,
        mode: ActionMode,
        pool: &tokio::runtime::Handle,
    ) -> Result<(NativeBuildResult, crate::build_runtime::ActionKey)> {
        let fingerprint = plan.spec.action_request()?.action_fingerprint()?;
        let key = fingerprint.key()?;
        debug!(
            "native action {key:?}: components={:?}; input trees={:?}",
            fingerprint.components,
            plan.inputs.iter().map(PreparedTree::id).collect::<Vec<_>>()
        );
        let result = match &self.endpoint {
            Endpoint::Direct(_) => {
                pool.spawn_blocking(crate::server::activity::inherit_blocking(move || {
                    let Endpoint::Direct(endpoint) = &self.endpoint else {
                        unreachable!()
                    };
                    self.connect_http()?.run_action_retained(
                        &plan.spec,
                        &plan.inputs,
                        &plan.destinations,
                        &self.policy.build_policy(mode),
                        endpoint.local.as_ref(),
                        (
                            &endpoint.intermediates,
                            // SAFETY: geteuid only queries process credentials.
                            unsafe { libc::geteuid() },
                        ),
                    )
                }))
                .await?
            }
            Endpoint::Namespace {
                connection,
                chunk_bytes,
            } => {
                broker::run_action(
                    Arc::clone(connection),
                    *chunk_bytes,
                    self.policy.clone(),
                    plan.spec,
                    mode,
                    plan.inputs,
                    plan.destinations,
                )
                .await
            }
        }?;
        Ok((result, key))
    }
}

struct NativeOutput {
    name: String,
    source: PathBuf,
    destination: PathBuf,
    required: bool,
    kind: OutputKind,
}

impl NativeOutput {
    fn file(cwd: &Path, output: FileObjectSource) -> Self {
        let path = cwd.join(output.path);
        Self {
            name: output.key,
            source: path.clone(),
            destination: path,
            required: !output.optional,
            kind: OutputKind::File,
        }
    }
    const fn generated(name: String, source: PathBuf, destination: PathBuf) -> Self {
        Self {
            name,
            source,
            destination,
            required: true,
            kind: OutputKind::GeneratedTree,
        }
    }

    fn remote_path(&self, layout: &mut pkg::CompilerInputs) -> Result<BuildPath> {
        let path = if self.kind.is_tree() {
            PathBuf::from(layout.directory(&self.source)?)
        } else {
            ensure!(
                self.source != Path::new("/dev/null"),
                "native outputs must be regular files"
            );
            match std::fs::symlink_metadata(&self.source) {
                Ok(metadata) => ensure!(
                    metadata.is_file(),
                    "native output would replace a nonregular file"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect native output destination"),
            }
            let parent = self
                .source
                .parent()
                .context("native output parent missing")?;
            let name = self
                .source
                .file_name()
                .context("native output name missing")?;
            Path::new(&layout.directory(parent)?).join(name)
        };
        BuildPath::new(path.as_os_str().as_bytes().to_vec())
    }
}

/// The compiler frontend declares which semantic identity it can establish.
///
/// Opaque extensions keep exact execution identity: their code can observe
/// arbitrary environment values and input metadata outside compiler dep-info.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ResultIdentityPolicy {
    Exact,
    PreprocessedC,
    Rust,
}

impl ResultIdentityPolicy {
    fn identity(
        self,
        key: &str,
        command: &CommandSpec,
        toolchain: TreeId,
        inputs: &TreeManifest,
    ) -> Result<Option<CompilerResultIdentity>> {
        if self == Self::Exact || opaque_compiler_extension(command, inputs) {
            return Ok(None);
        }
        let environment = compiler_environment(command, self);
        let input_closure = if self == Self::Rust {
            // Rust's dep-info includes sources and direct externs, but the
            // packaged search closure also includes transitive dependencies.
            // Rustc reads these by content; do not make delivery mtimes inputs.
            let mut manifest = inputs.clone();
            let stamp = TreeTimestamp {
                seconds: 0,
                nanoseconds: 0,
            };
            manifest.root.modified = stamp;
            for entry in manifest.entries.values_mut() {
                match entry {
                    TreeEntry::Directory(metadata) | TreeEntry::File { metadata, .. } => {
                        metadata.modified = stamp;
                    }
                    TreeEntry::Symlink { modified, .. } => *modified = stamp,
                    TreeEntry::Hardlink(_) => {}
                }
            }
            Some(manifest.id()?)
        } else {
            None
        };
        Ok(Some(CompilerResultIdentity {
            semantic: ContentId::of(key.as_bytes()),
            toolchain,
            input_closure,
            environment,
        }))
    }
}

/// Retain exact identity for extensions executing arbitrary native code.
///
/// Their dependencies lie outside ordinary compiler frontend discovery.
fn opaque_compiler_extension(command: &CommandSpec, inputs: &TreeManifest) -> bool {
    command.arguments.iter().any(|arg| {
        [
            b"-fplugin".as_slice(),
            b"-fpass-plugin",
            b"-load",
            b"-add-plugin",
            b"-plugin",
            b"-wrapper",
            b"-specs",
            b"--specs",
            b"-Zcodegen-backend",
            b"codegen-backend=",
        ]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
    }) || inputs
        .entries
        .keys()
        .any(|path| path.as_bytes().ends_with(b".so"))
}

/// Hash compiler driver/runtime environment dependencies.
///
/// Rust source-observed values and Cargo semantic environment are already
/// included in the frontend digest. Omit job, shell and scheduler bookkeeping.
fn compiler_environment(command: &CommandSpec, policy: ResultIdentityPolicy) -> ContentId {
    let mut digest = blake3::Hasher::new();
    digest.update(b"sccache-native-compiler-environment-v1\0");
    for (name, value) in &command.environment {
        let name = name.as_slice();
        let relevant = [
            b"LANG".as_slice(),
            b"LANGUAGE",
            b"TZ",
            b"TERM",
            b"SOURCE_DATE_EPOCH",
            b"PATH",
        ]
        .contains(&name)
            || [b"LC_".as_slice(), b"LD_"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
            || match policy {
                ResultIdentityPolicy::PreprocessedC => {
                    [b"GCC_".as_slice(), b"CLANG_", b"CCC_"]
                        .iter()
                        .any(|prefix| name.starts_with(prefix))
                        || [
                            b"COMPILER_PATH".as_slice(),
                            b"LIBRARY_PATH",
                            b"CPATH",
                            b"C_INCLUDE_PATH",
                            b"CPLUS_INCLUDE_PATH",
                            b"OBJC_INCLUDE_PATH",
                            b"DEPENDENCIES_OUTPUT",
                            b"SUNPRO_DEPENDENCIES",
                        ]
                        .contains(&name)
                }
                ResultIdentityPolicy::Rust => {
                    name.starts_with(b"RUSTC_")
                        || [
                            b"RUST_MIN_STACK".as_slice(),
                            b"RUST_BACKTRACE",
                            b"RUST_LIB_BACKTRACE",
                            b"RUSTFLAGS",
                        ]
                        .contains(&name)
                }
                ResultIdentityPolicy::Exact => false,
            };
        if relevant {
            for field in [name, value.as_slice()] {
                digest.update(&(field.len() as u128).to_le_bytes());
                digest.update(field);
            }
        }
    }
    ContentId(*digest.finalize().as_bytes())
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
        outputs: Vec<NativeOutput>,
        transformer: dist::PathTransformer,
        packagers: DistPackagers,
        identity: (ContentId, ResultIdentityPolicy, &str),
        preparation: (&SourceDigestCache, Option<&NativeCompilerClient>),
    ) -> Result<Self> {
        let (toolchain_digests, native) = preparation;
        let (platform, result_policy, key) = identity;
        let mut layout = pkg::CompilerInputs::new(transformer);
        layout.directory(cwd)?;
        let mut paths = BTreeMap::new();
        let mut destinations = BTreeMap::new();
        for output in outputs {
            let path = output.remote_path(&mut layout)?;
            ensure!(
                paths
                    .insert(
                        output.name.clone(),
                        OutputSpec {
                            path,
                            required: output.required,
                            kind: output.kind,
                        }
                    )
                    .is_none(),
                "duplicate native output key"
            );
            destinations.insert(output.name, output.destination);
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
        let mapped = inputs.native_mapping()?;
        let inputs = if let Some(native) = native {
            mapped.prepare_with_references(&|file, _| native.reference(file))?
        } else {
            mapped.prepare()?
        };
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
        let command = CommandSpec {
            umask: command
                .umask
                .context("native execution requires a known process umask")?,
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
        };
        let compiler_result =
            result_policy.identity(key, &command, inputs[0].id(), inputs[1].manifest())?;
        let spec = ExecutionSpec {
            compiler_result,
            platform,
            root,
            mounts: BTreeMap::new(),
            command,
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

/// Split a Rust action without changing its logical cwd, argument ordering,
/// target, or environment. The private delivery directories are independent
/// of all of those key fields.
struct NativeLink {
    workspace: super::rust_link::NativeLinkWorkspace,
    layout: super::rust_link::NativeLinkLayout,
    executable: PathBuf,
    logical_cwd: PathBuf,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    expected: Vec<FileObjectSource>,
    physical_cwd: PathBuf,
}

impl NativeLink {
    fn prepare(
        layout: super::rust_link::NativeLinkLayout,
        remote: &mut dist::CompileCommand,
        transformer: &dist::PathTransformer,
        scratch: &Path,
        local_environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
        expected: Vec<FileObjectSource>,
        physical_cwd: PathBuf,
    ) -> Result<Self> {
        use super::rust_link::{NativeLinkWorkspace, RustLinkStages};

        let args = remote
            .arguments
            .iter()
            .map(std::ffi::OsString::from)
            .collect();
        let logical_cwd = PathBuf::from(&remote.cwd);
        let stages = RustLinkStages::from_expanded(args, &logical_cwd, |cwd, path| {
            let logical = cwd.join(path);
            let physical = transformer
                .to_local(logical.to_str().context("non-UTF8 logical output root")?)?
                .canonicalize()?;
            let mut mapping = dist::PathTransformer::new();
            for (local, remote) in transformer.path_mappings() {
                mapping.add_root_mapping(local, &remote);
            }
            Ok(PathBuf::from(
                mapping
                    .as_dist_abs(&physical)
                    .context("output path has no native mapping")?,
            ))
        })?;
        let workspace = NativeLinkWorkspace::new(stages, scratch, |root| {
            transformer.to_local(root.to_str().context("non-UTF8 output root")?)
        })?;
        remote.arguments = workspace
            .codegen_arguments()
            .into_iter()
            .map(|arg| {
                arg.into_string()
                    .map_err(|_| anyhow::anyhow!("non-UTF8 native argument"))
            })
            .collect::<Result<_>>()?;
        // Literal leading @ arguments have already been expanded by the
        // frontend. The worker command cannot regenerate response files.
        ensure!(
            !remote.arguments.iter().any(|arg| arg.starts_with('@')),
            "native worker would expand a literal response-file operand"
        );
        Ok(Self {
            workspace,
            layout,
            executable: PathBuf::from(&remote.executable),
            logical_cwd,
            environment: local_environment,
            expected,
            physical_cwd,
        })
    }

    fn outputs(&self) -> Vec<NativeOutput> {
        self.workspace
            .outputs()
            .enumerate()
            .map(|(index, (_, physical, destination))| {
                NativeOutput::generated(
                    format!("codegen-{index}"),
                    physical.to_owned(),
                    destination.to_owned(),
                )
            })
            .collect()
    }

    async fn finish<T: CommandCreatorSync>(
        &self,
        creator: &T,
        mut generated: process::Output,
    ) -> Result<process::Output> {
        use crate::errors::ProcessError;
        use crate::mock_command::RunCommand;
        let mut args = self.layout.mounts.clone();
        args.extend(self.workspace.overlay_arguments()?);
        args.extend([
            "--chdir".into(),
            self.logical_cwd.clone().into_os_string(),
            "--".into(),
            self.executable.clone().into_os_string(),
        ]);
        args.extend(self.workspace.link_arguments()?);

        let mut command = creator.clone().new_command_sync("/usr/bin/bwrap");
        command
            .args(&args)
            .env_clear()
            .envs(self.environment.clone())
            .current_dir("/");
        command.share_jobserver();
        let linked = match crate::util::run_input_output(command, None).await {
            Ok(output) => output,
            Err(error) => match error.downcast::<ProcessError>() {
                Ok(ProcessError(output)) => output,
                Err(error) => return Err(error),
            },
        };
        if linked.status.success() {
            self.workspace.publish(
                &self.expected,
                &self.physical_cwd,
                self.layout.dep_info.as_deref(),
            )?;
        }
        if !linked.status.success() {
            debug!(
                "native local link failed with {}: {}",
                linked.status,
                String::from_utf8_lossy(&linked.stderr)
            );
        }
        generated.status = linked.status;
        generated.stdout.extend(linked.stdout);
        generated.stderr.extend(linked.stderr);
        Ok(generated)
    }
}

fn prepare_dispatch(
    compilation: Box<dyn Compilation<impl CommandCreatorSync>>,
    remote: &mut dist::CompileCommand,
    transformer: dist::PathTransformer,
    cwd: &Path,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    scratch: &mut Option<tempfile::TempDir>,
    split: &mut Option<NativeLink>,
) -> Result<(Vec<NativeOutput>, dist::PathTransformer, DistPackagers)> {
    super::core::validate_dist_environment_dependencies(
        remote,
        &compilation.dist_environment_dependencies(),
    )?;
    let expected = compilation
        .outputs()
        .filter(|output| output.key != "d")
        .collect::<Vec<_>>();
    let outputs = if let Some(layout) = compilation.native_link_layout() {
        let directory = tempfile::Builder::new()
            .prefix("sccache-native-link-")
            .tempdir()?;
        let link = NativeLink::prepare(
            layout.clone(),
            remote,
            &transformer,
            directory.path(),
            environment,
            expected,
            cwd.to_owned(),
        )?;
        let outputs = link.outputs();
        *scratch = Some(directory);
        *split = Some(link);
        outputs
    } else {
        expected
            .into_iter()
            .map(|output| NativeOutput::file(cwd, output))
            .collect()
    };
    let mut layout = dist::PathTransformer::new();
    for (local, remote) in transformer.path_mappings() {
        layout.add_root_mapping(local, &remote);
    }
    let packagers = compilation.into_dist_packagers(transformer)?;
    Ok((outputs, layout, packagers))
}

async fn finish_link<T: CommandCreatorSync>(
    result: Result<(NativeBuildResult, ActionKey)>,
    split: Option<&NativeLink>,
    creator: &T,
) -> Result<(NativeBuildResult, ActionKey)> {
    match (result, split) {
        (Ok((mut result, key)), Some(link)) if result.output.status.success() => {
            crate::server::activity::phase(crate::server::activity::Phase::LocalCompile);
            result.output = link.finish(creator, result.output).await?;
            Ok((result, key))
        }
        (result, _) => result,
    }
}

pub(super) async fn compile<T: CommandCreatorSync>(
    client: Arc<NativeCompilerClient>,
    service: &SccacheService<T>,
    creator: T,
    cwd: PathBuf,
    compilation: Box<dyn Compilation<T>>,
    identity: (CacheControl, &str),
    pool: &tokio::runtime::Handle,
) -> Result<(CompileResult, process::Output)> {
    let start = Instant::now();
    let result_policy = compilation.native_result_policy();
    let (control, key) = identity;
    let key = key.to_owned();
    crate::server::activity::phase(crate::server::activity::Phase::PlanCompile);
    let mut transformer = dist::PathTransformer::new();
    let (local, remote, cacheable) =
        compilation.generate_compile_commands(&mut transformer, CompileTransport::Native)?;
    let eligible = control != CacheControl::ForceNoCache
        && cacheable == Cacheable::Yes
        && compilation.is_locally_preprocessed()
        && compilation.automatic_dist_toolchain_is_ready()
        && client.allows_automatic_toolchain(&local.get_executable());
    let mode = if control == CacheControl::ForceRecache {
        ActionMode::Refresh
    } else {
        ActionMode::Reuse
    };
    let mut fallback = DistType::NoDist;
    if let Some(mut remote) = remote.filter(|_| eligible) {
        // Hold the temporary parent until link completion and artifact
        // publication. It is private scratch, not a cache tier.
        let mut scratch = None;
        let mut split = None;
        let result = (|| {
            let (outputs, layout, packagers) = prepare_dispatch(
                compilation,
                &mut remote,
                transformer,
                &cwd,
                local.get_env_vars(),
                &mut scratch,
                &mut split,
            )?;
            let preparation_client = Arc::clone(&client);
            Ok::<_, anyhow::Error>(pool.spawn_blocking(move || {
                CompilerPlan::prepare(
                    remote,
                    &cwd,
                    outputs,
                    layout,
                    packagers,
                    (preparation_client.policy.platform, result_policy, &key),
                    (
                        &preparation_client.toolchain_digests,
                        Some(&preparation_client),
                    ),
                )
            }))
        })();
        let result = match result {
            Ok(task) => match task.await? {
                Ok(plan) => {
                    crate::server::activity::phase(crate::server::activity::Phase::RunDistributed);
                    client.execute(plan, mode, pool).await
                }
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        let result = finish_link(result, split.as_ref(), &creator).await;
        // Explicit drop order: the workspace's TempDirs reference scratch.
        drop(split);
        drop(scratch);
        match result {
            Ok((result, key)) if result.output.status.success() => {
                let report = crate::protocol::NativeCompileReport {
                    key,
                    mode,
                    source: result.source,
                };
                return Ok((
                    CompileResult::Native(report, start.elapsed()),
                    result.output,
                ));
            }
            Ok((result, _)) => {
                // Incomplete compiler environment discovery can also produce
                // an ordinary nonzero exit. Preserve caller semantics by
                // rerunning locally without writing an archive cache.
                warn!(
                    "native compilation failed on {:?} with {}; retrying locally: {}",
                    result.source,
                    result.output.status,
                    String::from_utf8_lossy(&result.output.stderr)
                );
                fallback = DistType::Error;
            }
            Err(error) if error.is::<crate::client::IpcTransportFailure>() => return Err(error),
            Err(error) => {
                warn!("native compilation unavailable; compiling locally: {error:#}");
                fallback = DistType::Error;
            }
        }
    }
    crate::server::activity::phase(crate::server::activity::Phase::LocalCompile);
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
        let endpoint = HTTPUrl::from_url(url::Url::parse("http://127.0.0.1:1/")?);
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
            local_execution: None,
        });
        Ok(config)
    }

    fn verify_compilation(
        executable: &Path,
        args: &[&str],
        name: &str,
        source: &str,
        split_link: bool,
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
        let CompilerArguments::Ok(mut hasher) = compiler.parse_arguments(
            &args,
            &cwd,
            &environment,
            super::super::CompilerCachePolicy::Native,
        ) else {
            anyhow::bail!("real compiler arguments are not cacheable");
        };
        let hashed = rt.block_on(hasher.generate_hash_key(GenerateHashKeyContext {
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            native: None,
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
        let result_policy = compilation.native_result_policy();
        let mut transformer = dist::PathTransformer::new();
        let (_, remote, cacheable) =
            compilation.generate_compile_commands(&mut transformer, CompileTransport::Native)?;
        assert_eq!(cacheable, Cacheable::Yes);
        let mut remote = remote.context("no distributed command for real compiler")?;
        super::super::core::validate_dist_environment_dependencies(
            &remote,
            &compilation.dist_environment_dependencies(),
        )?;
        let expected = compilation
            .outputs()
            .filter(|output| output.key != "d")
            .collect::<Vec<_>>();
        let mut replay = None;
        let outputs = if split_link {
            let layout = compilation
                .native_link_layout()
                .context("linked Rust invocation did not select split linking")?
                .clone();
            let link = NativeLink::prepare(
                layout,
                &mut remote,
                &transformer,
                &cwd,
                environment.clone(),
                expected.clone(),
                cwd.clone(),
            )?;
            let outputs = link.outputs();
            replay = Some(link);
            outputs
        } else {
            assert!(compilation.native_link_layout().is_none());
            expected
                .into_iter()
                .map(|output| NativeOutput::file(&cwd, output))
                .collect()
        };
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
            (platform, result_policy, &hashed.key),
            (&SourceDigestCache::default(), None),
        )?;
        let store = NativeStore::open(&cwd.join("native-store"))?;
        let leases = plan
            .inputs
            .iter()
            .map(|tree| tree.import(&store).map(std::sync::Arc::new))
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
            &leases,
            None,
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
        let mut replayed = BTreeMap::new();
        if let Some(link) = &replay {
            use crate::build_runtime::{Artifact, materialize_tree};
            for (index, (_, _, destination)) in link.workspace.outputs().enumerate() {
                let Artifact::GeneratedTree(manifest) =
                    &manifest.outputs[&format!("codegen-{index}")]
                else {
                    anyhow::bail!("expected generated codegen tree");
                };
                let staged = materialize_tree(
                    manifest,
                    destination.parent().context("stage parent")?,
                    |blob, path| {
                        std::io::copy(
                            &mut result.open_blob(blob.id)?,
                            &mut std::fs::File::create(path)?,
                        )?;
                        Ok(())
                    },
                )?;
                staged.publish(destination)?;
            }
            let output = rt.block_on(link.finish(
                &creator,
                process::Output {
                    status: result.status(),
                    stdout: vec![],
                    stderr: vec![],
                },
            ))?;
            ensure!(
                output.status.success(),
                "native link failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            for output in &link.expected {
                let physical = cwd.join(&output.path);
                if output.optional && !physical.exists() {
                    continue;
                }
                replayed.insert(physical.clone(), std::fs::read(physical)?);
            }
            ensure!(
                !replayed.is_empty(),
                "local link did not produce an artifact"
            );
            assert!(!cwd.join("build/input-stage.rlink").exists());
        }
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
        if split_link {
            for (path, bytes) in replayed {
                assert_eq!(ContentId::of(&bytes), ContentId::of(&std::fs::read(path)?));
            }
        } else {
            for (name, output) in &manifest.outputs {
                let mut bytes = Vec::new();
                let crate::build_runtime::Artifact::File { blob, .. } = output else {
                    anyhow::bail!("expected file output");
                };
                result.open_blob(blob.id)?.read_to_end(&mut bytes)?;
                assert_eq!(
                    ContentId::of(&bytes),
                    ContentId::of(&std::fs::read(&plan.destinations[name])?),
                    "output {name} differs from local compile"
                );
            }
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
            false,
        )
    }

    #[test_case::test_case(false; "completed_rlib")]
    #[test_case::test_case(true; "split_link_bin")]
    #[ignore = "requires a nightly Rust toolchain, ldd and Linux Bubblewrap"]
    fn native_rust_compiler_plan(split_link: bool) -> Result<()> {
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
                if split_link { "bin" } else { "rlib" },
                "--emit=link,dep-info",
                "--out-dir",
                "build",
                "-Cextra-filename=-stage",
                "input.rs",
            ],
            "input.rs",
            if split_link {
                "fn main() { println!(\"{}\", 7 * 7); }\n"
            } else {
                "pub fn square(x: i32) -> i32 { x*x }\n"
            },
            split_link,
        )
    }
}
