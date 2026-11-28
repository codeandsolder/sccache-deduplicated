//! Connect ordinary compiler discovery to the native execution contract.
//! The scheduler owns results; the client neither initializes nor writes an
//! archive cache. The existing compiler frontends still determine whether
//! a compilation is cacheable and supply its input closure.

use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use crate::{
    build_runtime::{
        ActionMode, Artifact, BuildPath, CommandSpec, CompilerResultIdentity, ContentId,
        DescriptorDigestProvider, ExecutionRoot, ExecutionSpec, OutputKind, OutputSpec,
        PreparedTree, ReferenceBlobProvider, ResultManifest, SourceDigestCache, TreeEntry, TreeId,
        TreeLayer, TreeManifest, TreePath, TreeRecipe, TreeTimestamp,
    },
    cache::FileObjectSource,
    client::{SharedConnection, connection_task},
    config::{DistAuth, HTTPUrl, NativeClientConfig},
    dist::{
        self,
        native::{NativeBuildResult, NativeCacheClient, broker},
        pkg,
    },
    mock_command::CommandCreatorSync,
    protocol::{NativeNamespacePolicy, Request, Response},
    server::{DistClientContainer, DistInfo},
};

use super::{CacheControl, Cacheable, Compilation, CompileResult, CompileTransport, DistPackagers};

struct DirectEndpoint {
    config: NativeClientConfig,
    scheduler: Option<HTTPUrl>,
    cluster: Option<sccache_peer_identity::PeerConfig>,
    client: std::sync::Mutex<Option<NativeCacheClient>>,
    auth: DistAuth,
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
                cluster,
                client: std::sync::Mutex::new(None),
                auth,
                intermediates: crate::dist::native::result_session::Registry::default(),
            })),
            policy,
            toolchain_digests: installed_digest_cache(catalogs, None),
        }
    }

    pub fn from_namespace(
        connection: SharedConnection,
        chunk_bytes: usize,
        policy: NativeNamespacePolicy,
        catalogs: &[PathBuf],
        provider: Option<DescriptorDigestProvider>,
    ) -> Self {
        Self {
            endpoint: Endpoint::Namespace {
                connection,
                chunk_bytes,
            },
            policy,
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
        let client = Arc::clone(self);
        crate::util::hash_input_batch(files, pool, move |path| {
            if path.is_dir() {
                return crate::util::Digest::path_sync(path);
            }
            let file = std::fs::File::open(path)?;
            if let Some((blob, _)) = client.reference(&file)? {
                Ok(crate::util::hex(&blob.id.0))
            } else {
                // Check the opened descriptor for mutation while hashing;
                // do not memoize mutable build inputs by timestamps.
                let blob = crate::build_runtime::hash_descriptor(&file)?;
                Ok(crate::util::hex(&blob.id.0))
            }
        })
        .await
    }

    /// Reuse installed toolchain content digests for files selected by
    /// compiler dependency discovery. Mutable project inputs still use
    /// descriptor content hashes or retained CAS references.
    pub(crate) async fn hash_compiler_inputs(
        self: &Arc<Self>,
        files: &[PathBuf],
        sysroot: &Path,
        pool: &tokio::runtime::Handle,
    ) -> Result<Vec<String>> {
        let client = Arc::clone(self);
        let sysroot = sysroot.canonicalize()?;
        crate::util::hash_input_batch(files, pool, move |path| {
            if path.is_dir() {
                return crate::util::Digest::path_sync(path);
            }
            if path.starts_with(&sysroot) {
                return Ok(crate::util::hex(
                    &client.toolchain_digests.file_digest(path)?.id.0,
                ));
            }
            let file = std::fs::File::open(path)?;
            let blob = match client.reference(&file)? {
                Some((blob, _)) => blob,
                None => crate::build_runtime::hash_descriptor(&file)?,
            };
            Ok(crate::util::hex(&blob.id.0))
        })
        .await
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
        broker::serve_action(&client, &self.policy, stream, &endpoint.intermediates, uid)
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

    pub(crate) async fn report_live_traces(
        self: &Arc<Self>,
        report: &crate::build_runtime::wire::LiveTraceBatch,
    ) -> Result<()> {
        let client = Arc::clone(self);
        let transport = tokio::task::spawn_blocking(move || client.connect_http()).await??;
        transport.report_live_traces(report).await
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

    async fn stage_lease(self: &Arc<Self>, pool: &tokio::runtime::Handle) -> Result<StageLease> {
        use crate::build_runtime::ReferenceBlobProvider;
        let client = Arc::clone(self);
        pool.spawn_blocking(move || {
            match &client.endpoint {
                Endpoint::Direct(_) => {
                    // SAFETY: geteuid only queries process credentials.
                    let (token, group) = client.open_intermediate(unsafe { libc::geteuid() })?;
                    let provider =
                        ReferenceBlobProvider::new(move |blob| Ok(Box::new(group.read(blob)?)));
                    Ok(StageLease { token, provider })
                }
                Endpoint::Namespace { .. } => {
                    use crate::build_runtime::intermediate_fs::IntermediateReference;
                    use crate::dist::native::intermediate;
                    let (token, connection) = intermediate::open()?;
                    // Keep the daemon-owned retention group alive for every
                    // reference handed to a dependent action.
                    let lease = std::sync::Mutex::new(connection);
                    let provider = ReferenceBlobProvider::new(move |blob| {
                        let _lease = lease
                            .lock()
                            .map_err(|_| anyhow::anyhow!("stage lease poisoned"))?;
                        intermediate::source(IntermediateReference {
                            session: token,
                            blob,
                        })
                        .open(blob)
                    });
                    Ok(StageLease { token, provider })
                }
            }
        })
        .await?
    }

    async fn execute(
        self: Arc<Self>,
        plan: CompilerPlan,
        mode: ActionMode,
        retained: BTreeSet<crate::build_runtime::wire::Ticket>,
        pool: &tokio::runtime::Handle,
    ) -> Result<(NativeBuildResult, crate::build_runtime::ActionKey)> {
        let fingerprint = plan.spec.action_request()?.action_fingerprint()?;
        let key = fingerprint.key()?;
        crate::server::activity::key_evidence(
            &fingerprint.schema,
            blake3::Hash::from_bytes(key.0).to_hex().as_ref(),
            fingerprint
                .components
                .iter()
                .map(|(name, digest)| {
                    (
                        name.as_str(),
                        blake3::Hash::from_bytes(digest.0).to_hex().to_string(),
                    )
                })
                .collect(),
        );
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
                        (
                            &endpoint.intermediates,
                            // SAFETY: geteuid only queries process credentials.
                            unsafe { libc::geteuid() },
                        ),
                        retained,
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
                    retained,
                )
                .await
            }
        }?;
        Ok((result, key))
    }
}

struct StageLease {
    token: crate::build_runtime::wire::Ticket,
    provider: crate::build_runtime::ReferenceBlobProvider,
}

struct NativeOutput {
    name: String,
    source: PathBuf,
    destination: PathBuf,
    remote: Option<BuildPath>,
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
            remote: None,
            required: !output.optional,
            kind: OutputKind::File,
        }
    }
    const fn generated(name: String, source: PathBuf, destination: PathBuf) -> Self {
        Self {
            name,
            source,
            destination,
            remote: None,
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
            if let Some(remote) = &self.remote {
                return Ok(remote.clone());
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

/// Compiler-specific package construction policy. It never selects a
/// different cache-key algorithm.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CompilerPackagingPolicy {
    Default,
    PreprocessedC,
    Rust,
}

/// Select packaging requirements for extensions executing native code.
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

fn prepare_toolchain(
    packager: Box<dyn pkg::ToolchainPackager>,
    digests: &SourceDigestCache,
    policy: CompilerPackagingPolicy,
    command: &mut CommandSpec,
    inputs: &TreeManifest,
) -> Result<PreparedTree> {
    let scope = match (policy, opaque_compiler_extension(command, inputs)) {
        (CompilerPackagingPolicy::Rust, false) => pkg::ToolchainScope::RustCompiler,
        (CompilerPackagingPolicy::Rust, true) => pkg::ToolchainScope::RustOpaque,
        (CompilerPackagingPolicy::PreprocessedC, false) => pkg::ToolchainScope::PreprocessedC,
        _ => pkg::ToolchainScope::Default,
    };
    let before = digests.catalog_hits();
    let start = Instant::now();
    let package = packager.native_mapping(scope)?;
    ensure!(
        scope != pkg::ToolchainScope::PreprocessedC || package.search.is_some(),
        "C toolchain did not establish its execution environment"
    );
    if let Some(search) = package.search {
        if let Some(path) = search.path {
            command.environment.insert(b"PATH".to_vec(), path);
        }
        command.environment.remove(b"LD_LIBRARY_PATH".as_slice());
        if let Some(libraries) = search.libraries {
            command
                .environment
                .insert(b"LD_LIBRARY_PATH".to_vec(), libraries);
        }
    }
    if policy != CompilerPackagingPolicy::Rust {
        // The preprocessor already consumed source-level environment.
        // Construct the remaining driver environment explicitly. Search
        // paths are established by the actual toolchain package above.
        command.environment.retain(|name, _| {
            let name = name.as_slice();
            [
                b"PATH".as_slice(),
                b"LD_LIBRARY_PATH",
                b"CCC_OVERRIDE_OPTIONS",
            ]
            .contains(&name)
                || super::c_driver_environment::darwin_variable(std::ffi::OsStr::from_bytes(name))
                || (scope != pkg::ToolchainScope::PreprocessedC
                    && [
                        b"SOURCE_DATE_EPOCH".as_slice(),
                        b"GCC_EXEC_PREFIX",
                        b"COMPILER_PATH",
                        b"LIBRARY_PATH",
                        b"CUDA_PATH",
                        b"CUDA_HOME",
                        b"NVCC_PREPEND_FLAGS",
                        b"NVCC_APPEND_FLAGS",
                    ]
                    .contains(&name))
        });
        for (name, value) in [
            (b"LANG".as_slice(), b"C".as_slice()),
            (b"LC_ALL", b"C"),
            (b"TZ", b"UTC"),
        ] {
            command.environment.insert(name.to_vec(), value.to_vec());
        }
    }
    let prepared = package.mapping.prepare_with_cache(digests)?;
    let after = digests.catalog_hits();
    debug!(
        "native toolchain preparation took {:.3}s; verified installation memo: {} files, {} bytes (process totals: {} files, {} bytes)",
        start.elapsed().as_secs_f64(),
        after.0.saturating_sub(before.0),
        after.1.saturating_sub(before.1),
        after.0,
        after.1
    );
    Ok(prepared)
}

#[derive(Clone)]
struct CompilerPlan {
    spec: ExecutionSpec,
    inputs: Vec<PreparedTree>,
    destinations: BTreeMap<String, PathBuf>,
    codegen_only: BTreeSet<TreePath>,
}

impl CompilerPlan {
    /// Classify only files actually observed in private writable locations
    /// that are absent from the immutable snapshot. The final compiler
    /// recreates these files; they are not dependencies on the origin.
    fn generated_paths(
        &self,
        invocation: &link_capture::CapturedInvocation,
    ) -> Result<BTreeSet<PathBuf>> {
        let mut recipe = self.spec.root.recipe.clone();
        recipe.layers.retain(|layer| {
            !layer
                .destination
                .as_ref()
                .is_some_and(|path| self.spec.working_inputs.contains(path))
        });
        let immutable = recipe.compose(
            &self
                .inputs
                .iter()
                .map(|tree| (tree.id(), tree.manifest()))
                .collect(),
        )?;
        let roots = self
            .spec
            .outputs
            .values()
            .map(|output| {
                let path = Path::new(std::ffi::OsStr::from_bytes(output.path.as_bytes()));
                if output.kind.is_tree() {
                    Ok(path)
                } else {
                    path.parent().context("output has no parent")
                }
            })
            .chain(
                self.spec
                    .scratch
                    .iter()
                    .map(|path| Ok(Path::new(std::ffi::OsStr::from_bytes(path.as_bytes())))),
            )
            .chain(std::iter::once(Ok(Path::new("/tmp"))))
            .collect::<Result<Vec<_>>>()?;
        Ok(invocation
            .existing_paths
            .iter()
            .filter(|path| {
                roots.iter().any(|root| path.starts_with(root))
                    && path.strip_prefix("/").is_ok_and(|relative| {
                        !immutable
                            .entries
                            .contains_key(relative.as_os_str().as_bytes())
                    })
            })
            .cloned()
            .collect())
    }

    fn complete_link_inputs(
        &mut self,
        inputs: &link_inputs::LinkInputs,
        captures: Vec<link_capture::CapturedInvocation>,
        cache: &SourceDigestCache,
        client: Option<&NativeCompilerClient>,
    ) -> Result<()> {
        let mut required = BTreeSet::new();
        for invocation in captures {
            let generated = self.generated_paths(&invocation)?;
            let additional = inputs.prepare_captured(&invocation, &generated, cache, client)?;
            for tree in &additional {
                required.extend(tree.manifest().entries.keys().cloned());
            }
            self.extend_inputs(additional)?;
        }
        if !self.spec.command.arguments.iter().any(|arg| {
            arg.windows(b"codegen-backend".len())
                .any(|part| part == b"codegen-backend")
        }) {
            self.project_link_sources(&required)?;
        }
        Ok(())
    }

    /// Preserve the actual linker dependency selection and all independently
    /// declared non-source inputs. Drop codegen-only file entries from the
    /// original compiler input layer without reopening or transferring them.
    fn project_link_sources(&mut self, required: &BTreeSet<TreePath>) -> Result<()> {
        if self.codegen_only.is_empty() {
            return Ok(());
        }
        let source = &self.inputs[1];
        let previous = source.id();
        let paths = source
            .manifest()
            .entries
            .keys()
            .filter(|path| !self.codegen_only.contains(*path) || required.contains(*path))
            .cloned()
            .collect::<Vec<_>>();
        let projected = source.select_paths(paths)?;
        if previous == projected.id() {
            return Ok(());
        }
        let mut recipe = self.spec.root.recipe.clone();
        let layer = recipe
            .layers
            .get_mut(1)
            .context("missing compiler input layer")?;
        ensure!(
            layer.tree == previous && layer.source.is_none() && layer.destination.is_none(),
            "unexpected compiler input layer"
        );
        layer.tree = projected.id();
        self.inputs[1] = projected;
        self.spec.root = ExecutionRoot::resolve(
            recipe,
            &self
                .inputs
                .iter()
                .map(|tree| (tree.id(), tree.manifest()))
                .collect(),
        )?;
        self.spec.compiler_result = None;
        self.spec.validate()
    }

    /// Extend a completed root using its existing snapshot as the authority.
    /// Different package builders may normalize timestamps differently.
    /// Keep the already-declared inode for an identical file (content and
    /// permissions) or symlink; never silently replace different content.
    fn extend_inputs(&mut self, additional: Vec<PreparedTree>) -> Result<()> {
        let mut recipe = self.spec.root.recipe.clone();
        let mut root = recipe.compose(
            &self
                .inputs
                .iter()
                .map(|tree| (tree.id(), tree.manifest()))
                .collect(),
        )?;
        for prepared in additional {
            let mut selected = Vec::new();
            for (path, entry) in &prepared.manifest().entries {
                let Some(existing) = root.entries.get(path) else {
                    selected.push(path.clone());
                    continue;
                };
                let equal = match (existing, entry) {
                    (TreeEntry::Directory(_), TreeEntry::Directory(_)) => true,
                    (
                        TreeEntry::File {
                            blob: a,
                            metadata: am,
                        },
                        TreeEntry::File {
                            blob: b,
                            metadata: bm,
                        },
                    ) => a == b && am.mode == bm.mode,
                    (
                        TreeEntry::Symlink { target: a, .. },
                        TreeEntry::Symlink { target: b, .. },
                    ) => a == b,
                    _ => existing == entry,
                };
                ensure!(
                    equal,
                    "additional native input conflicts with existing snapshot: {path:?}"
                );
            }
            if selected.is_empty() {
                continue;
            }
            let prepared = prepared.select_paths(selected)?;
            recipe.layers.push(TreeLayer {
                tree: prepared.id(),
                source: None,
                destination: None,
            });
            self.inputs.push(prepared);
            root = recipe.compose(
                &self
                    .inputs
                    .iter()
                    .map(|tree| (tree.id(), tree.manifest()))
                    .collect(),
            )?;
        }
        self.spec.root = ExecutionRoot {
            id: root.id()?,
            recipe,
        };
        self.spec.compiler_result = None;
        self.spec.validate()
    }

    fn prepare(
        command: dist::CompileCommand,
        cwd: &Path,
        outputs: Vec<NativeOutput>,
        transformer: dist::PathTransformer,
        packagers: DistPackagers,
        identity: (ContentId, CompilerPackagingPolicy, &str),
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
        let mut command = CommandSpec {
            umask: 0o022,
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
        let pkg::NativeInputPlan {
            mapping: mapped,
            codegen_only,
        } = inputs.native_mapping()?;
        let inputs = if let Some(native) = native {
            mapped.prepare_with_references(&|file, _| native.reference(file))?
        } else {
            mapped.prepare()?
        };
        let toolchain = prepare_toolchain(
            toolchain,
            toolchain_digests,
            result_policy,
            &mut command,
            inputs.manifest(),
        )?;
        let layout = layout.into_native_mapping(|_| false)?.prepare()?;
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
        let compiler_result = Some(CompilerResultIdentity {
            semantic: ContentId::of(key.as_bytes()),
        });
        let spec = ExecutionSpec {
            compiler_result,
            working_inputs: Default::default(),
            scratch: Default::default(),
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
            codegen_only,
        })
    }
}

/// Split a Rust action without changing its logical cwd, argument ordering,
/// target, or environment. The private delivery directories are independent
/// of all of those key fields.
mod link_capture;
mod link_inputs;

struct NativeLink {
    inputs: Arc<link_inputs::LinkInputs>,
    workspace: super::rust_link::NativeLinkWorkspace,
    layout: super::rust_link::NativeLinkLayout,
    expected: Vec<FileObjectSource>,
    physical_cwd: PathBuf,
}

impl NativeLink {
    fn prepare(
        layout: super::rust_link::NativeLinkLayout,
        remote: &mut dist::CompileCommand,
        transformer: &dist::PathTransformer,
        scratch: &Path,
        expected: Vec<FileObjectSource>,
        physical_cwd: PathBuf,
    ) -> Result<Self> {
        use super::rust_link::{NativeLinkWorkspace, RustLinkStages};

        let args: Vec<std::ffi::OsString> = remote
            .arguments
            .iter()
            .map(std::ffi::OsString::from)
            .collect();
        let logical_cwd = PathBuf::from(&remote.cwd);
        let inputs = Arc::new(link_inputs::LinkInputs::new(
            transformer.to_local(&remote.executable)?,
            physical_cwd.clone(),
            layout.environment.clone(),
            transformer,
            args.clone(),
        ));
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
            inputs,
            workspace,
            layout,
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

    /// Reuse codegen's immutable inputs and add leased generated files at
    /// their exact logical locations. No codegen bytes travel via the caller.
    fn plan(
        &self,
        base: &CompilerPlan,
        generated: &ResultManifest,
        provider: &ReferenceBlobProvider,
    ) -> Result<(CompilerPlan, PathBuf)> {
        base.spec.action_request()?.validate_result(generated)?;
        let mut plan = base.clone();
        let mut recipe = plan.spec.root.recipe.clone();
        let mut artifact = None;
        for (index, (logical, _, _)) in self.workspace.outputs().enumerate() {
            let name = format!("codegen-{index}");
            let Artifact::GeneratedTree(tree) = generated
                .outputs
                .get(&name)
                .context("missing codegen tree")?
            else {
                anyhow::bail!("unexpected codegen result kind");
            };
            for (relative, entry) in &tree.entries {
                let path = logical.join(std::ffi::OsStr::from_bytes(relative.as_bytes()));
                if path.starts_with(self.workspace.codegen_directory())
                    && path.extension().is_some_and(|ext| ext == "rlink")
                {
                    ensure!(
                        matches!(entry, TreeEntry::File { .. }),
                        "invalid .rlink artifact type"
                    );
                    ensure!(
                        artifact.replace(path).is_none(),
                        "multiple .rlink artifacts"
                    );
                }
            }
            let prepared = PreparedTree::from_references(tree.clone(), provider)?;
            let destination =
                TreePath::new(logical.strip_prefix("/")?.as_os_str().as_bytes().to_vec())?;
            recipe.layers.push(TreeLayer {
                tree: prepared.id(),
                source: None,
                destination: Some(destination.clone()),
            });
            plan.spec.working_inputs.insert(destination);
            plan.inputs.push(prepared);
        }
        let artifact = artifact.context("missing .rlink artifact")?;
        plan.spec.root = ExecutionRoot::resolve(
            recipe,
            &plan
                .inputs
                .iter()
                .map(|tree| (tree.id(), tree.manifest()))
                .collect(),
        )?;
        // Linking uses the exact action contract, including all link arguments,
        // external dependencies, and generated codegen content.
        plan.spec.compiler_result = None;
        plan.spec.command.arguments = self
            .workspace
            .link_arguments(&artifact)
            .into_iter()
            .map(|arg| arg.as_os_str().as_bytes().to_vec())
            .collect();
        plan.spec.validate()?;
        Ok((plan, artifact))
    }

    fn publish(&self, artifact: &Path) -> Result<()> {
        self.workspace.publish(
            artifact,
            &self.expected,
            &self.physical_cwd,
            self.layout.dep_info.as_deref(),
        )
    }
}

fn prepare_dispatch(
    compilation: Box<dyn Compilation<impl CommandCreatorSync>>,
    remote: &mut dist::CompileCommand,
    transformer: dist::PathTransformer,
    cwd: &Path,
    scratch: &mut Option<tempfile::TempDir>,
    split: &mut Option<NativeLink>,
) -> Result<(Vec<NativeOutput>, dist::PathTransformer, DistPackagers)> {
    super::core::validate_dist_environment_dependencies(
        remote,
        &compilation.dist_environment_dependencies(CompileTransport::Native),
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
            expected,
            cwd.to_owned(),
        )?;
        let outputs = link.outputs();
        *scratch = Some(directory);
        *split = Some(link);
        outputs
    } else if compilation.native_relocatable_output() {
        let [output] = <[_; 1]>::try_from(expected)
            .map_err(|_| anyhow::anyhow!("relocatable object requires exactly one output"))?;
        ensure!(
            output.key == "obj" && !output.optional,
            "invalid relocatable object"
        );
        let mut output = NativeOutput::file(cwd, output);
        let mut positions = remote
            .arguments
            .iter()
            .enumerate()
            .filter(|(_, argument)| *argument == "-o");
        let (position, _) = positions
            .next()
            .context("missing native object destination")?;
        ensure!(
            positions.next().is_none(),
            "multiple native object destinations"
        );
        let destination = remote
            .arguments
            .get_mut(position + 1)
            .context("missing -o operand")?;
        // The toolchain already declares /out. The actual command and
        // output contract share this path, independent of delivery.
        *destination = "/out/object.o".into();
        output.remote = Some(BuildPath::new(b"/out/object.o".to_vec())?);
        vec![output]
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

/// Obtain the actual linker command in a scheduler-owned, cacheable
/// planning task. No generated compiler artifacts are published by this
/// task. A failing discovery is explicit; there is no broad inventory or
/// caller-side linking fallback.
async fn prepare_link_action(
    client: &Arc<NativeCompilerClient>,
    plan: &mut CompilerPlan,
    inputs: Arc<link_inputs::LinkInputs>,
    mode: ActionMode,
    pool: &tokio::runtime::Handle,
    reports: &mut Vec<crate::protocol::NativeCompileReport>,
) -> Result<Option<NativeBuildResult>> {
    use crate::protocol::{NativeCompileReport, NativeStage};
    let start = Instant::now();
    let scratch = tempfile::Builder::new()
        .prefix("sccache-link-capture-")
        .tempdir()?;
    let directory = scratch.path().to_owned();
    let preparation_client = Arc::clone(client);
    let discovery = Arc::clone(&inputs);
    let mut base = plan.clone();
    let prepared = pool
        .spawn_blocking(move || {
            let capture = discovery
                .relay()?
                .map(|(basename, expected)| {
                    link_capture::LinkCapture::configure(
                        base.clone(),
                        &basename,
                        expected,
                        &directory,
                        &preparation_client.toolchain_digests,
                    )
                })
                .transpose()?;
            if capture.is_none() {
                base.complete_link_inputs(
                    &discovery,
                    Vec::new(),
                    &preparation_client.toolchain_digests,
                    Some(&preparation_client),
                )?;
            }
            Ok::<_, anyhow::Error>((base, capture))
        })
        .await??;
    let (base, capture) = prepared;
    *plan = base;
    let Some((capture, capture_plan)) = capture else {
        return Ok(None);
    };
    let (result, key) = Arc::clone(client)
        .execute(capture_plan, mode, BTreeSet::new(), pool)
        .await?;
    reports.push(NativeCompileReport {
        key,
        mode,
        source: result.source,
        stage: NativeStage::LinkPlan,
        successful: result.output.status.success(),
        duration: start.elapsed(),
    });
    if !result.output.status.success() {
        return Ok(Some(result));
    }
    let preparation_client = Arc::clone(client);
    let mut completed = plan.clone();
    *plan = pool
        .spawn_blocking(move || {
            completed.complete_link_inputs(
                &inputs,
                capture.read()?,
                &preparation_client.toolchain_digests,
                Some(&preparation_client),
            )?;
            Ok::<_, anyhow::Error>(completed)
        })
        .await??;
    Ok(None)
}

fn deliver_compiler_messages(
    mut output: process::Output,
    (mut discovery, success): (Vec<u8>, Vec<u8>),
) -> process::Output {
    if !discovery.is_empty() {
        discovery.append(&mut output.stderr);
        output.stderr = discovery;
    }
    if output.status.success() {
        output.stderr.extend(success);
    }
    output
}

pub(super) async fn compile<T: CommandCreatorSync>(
    client: Arc<NativeCompilerClient>,
    _creator: T,
    cwd: PathBuf,
    compilation: Box<dyn Compilation<T>>,
    identity: (CacheControl, &str),
    pool: &tokio::runtime::Handle,
) -> Result<(CompileResult, process::Output)> {
    let start = Instant::now();
    let result_policy = compilation.native_packaging_policy();
    let delivery = compilation.native_delivery_messages();
    let (control, key) = identity;
    let key = key.to_owned();
    crate::server::activity::phase(crate::server::activity::Phase::PlanCompile);
    let mut transformer = dist::PathTransformer::new();
    let (_, remote, cacheable) =
        compilation.generate_compile_commands(&mut transformer, CompileTransport::Native)?;
    ensure!(
        control != CacheControl::ForceNoCache,
        "native compile requires a cacheable identity; uncached execution is prohibited"
    );
    ensure!(
        cacheable == Cacheable::Yes,
        "compiler invocation is not cacheable"
    );
    ensure!(
        compilation.automatic_dist_toolchain_is_ready(),
        "automatic distributed compiler toolchain is incomplete"
    );
    let mut remote = remote.context("compiler invocation has no native distributed command")?;
    let mode = if control == CacheControl::ForceRecache {
        ActionMode::Refresh
    } else {
        ActionMode::Reuse
    };
    // Hold the private delivery directories until split-link completion.
    let mut scratch = None;
    let mut split = None;
    let (outputs, layout, packagers) = prepare_dispatch(
        compilation,
        &mut remote,
        transformer,
        &cwd,
        &mut scratch,
        &mut split,
    )?;
    let preparation_client = Arc::clone(&client);
    let plan = pool
        .spawn_blocking(move || {
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
        })
        .await??;
    crate::server::activity::phase(crate::server::activity::Phase::RunDistributed);
    use crate::protocol::{NativeCompileReport, NativeStage};
    let mut reports = Vec::new();
    let result = if let Some(link) = split {
        let stage_start = Instant::now();
        let lease = client.stage_lease(pool).await?;
        let mut codegen = plan.clone();
        codegen.destinations.clear();
        let (mut generated, generated_key) = Arc::clone(&client)
            .execute(codegen, mode, BTreeSet::from([lease.token]), pool)
            .await?;
        reports.push(NativeCompileReport {
            key: generated_key,
            mode,
            source: generated.source,
            stage: NativeStage::Codegen,
            successful: generated.output.status.success(),
            duration: stage_start.elapsed(),
        });
        if generated.output.status.success() {
            let manifest = generated
                .manifest
                .take()
                .context("missing successful codegen manifest")?;
            let (link, mut link_plan, artifact) = pool
                .spawn_blocking(move || {
                    let (link_plan, artifact) = link.plan(&plan, &manifest, &lease.provider)?;
                    Ok::<_, anyhow::Error>((link, link_plan, artifact))
                })
                .await??;
            let failure = prepare_link_action(
                &client,
                &mut link_plan,
                Arc::clone(&link.inputs),
                mode,
                pool,
                &mut reports,
            )
            .await?;
            let stage_start = Instant::now();
            let (mut linked, key) = if let Some(mut failure) = failure {
                generated.output.stdout.append(&mut failure.output.stdout);
                generated.output.stderr.append(&mut failure.output.stderr);
                failure.output.stdout = generated.output.stdout;
                failure.output.stderr = generated.output.stderr;
                return Ok((
                    CompileResult::Native(reports, start.elapsed()),
                    deliver_compiler_messages(failure.output, delivery),
                ));
            } else {
                client
                    .execute(link_plan, mode, BTreeSet::new(), pool)
                    .await?
            };
            if linked.output.status.success() {
                pool.spawn_blocking(move || link.publish(&artifact))
                    .await??;
            }
            generated.output.stdout.append(&mut linked.output.stdout);
            generated.output.stderr.append(&mut linked.output.stderr);
            linked.output.stdout = generated.output.stdout;
            linked.output.stderr = generated.output.stderr;
            reports.push(NativeCompileReport {
                key,
                mode,
                source: linked.source,
                stage: NativeStage::Link,
                successful: linked.output.status.success(),
                duration: stage_start.elapsed(),
            });
            linked
        } else {
            generated
        }
    } else {
        let stage_start = Instant::now();
        let (result, key) = client.execute(plan, mode, BTreeSet::new(), pool).await?;
        reports.push(NativeCompileReport {
            key,
            mode,
            source: result.source,
            stage: NativeStage::Compile,
            successful: result.output.status.success(),
            duration: stage_start.elapsed(),
        });
        result
    };
    drop(scratch);
    Ok((
        CompileResult::Native(reports, start.elapsed()),
        deliver_compiler_messages(result.output, delivery),
    ))
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
        });
        Ok(config)
    }

    fn hash_test_invocation(
        rt: &tokio::runtime::Runtime,
        creator: &ProcessCommandCreator,
        executable: &Path,
        cwd: &Path,
        args: &[OsString],
        environment: &[(OsString, OsString)],
        config: &Config,
        native_identity: bool,
    ) -> Result<super::super::HashResult<ProcessCommandCreator>> {
        let pool = rt.handle();
        let storage = storage_from_config(config, pool)?;
        assert_eq!(storage.cache_type_name(), "native");
        let (compiler, _) = rt.block_on(get_compiler_info(
            creator.clone(),
            executable,
            cwd,
            args,
            environment,
            pool,
            crate::compiler::CompilerDiscovery::default(),
        ))?;
        let CompilerArguments::Ok(mut hasher) = compiler.parse_arguments(
            args,
            cwd,
            environment,
            super::super::CompilerCachePolicy::Native,
        ) else {
            anyhow::bail!("real compiler arguments are not cacheable");
        };
        let hashed = rt.block_on(hasher.generate_hash_key(GenerateHashKeyContext {
            native: native_identity.then(|| {
                Arc::new(NativeCompilerClient::new(
                    config.dist.native.clone().unwrap(),
                    config.dist.scheduler_url.clone(),
                    None,
                    config.dist.auth.clone(),
                    &[],
                ))
            }),
            creator,
            cwd: cwd.to_owned(),
            env_vars: environment.to_vec(),
            may_dist: true,
            pool,
            rewrite_includes_only: false,
            storage,
            cache_control: CacheControl::Default,
        }))?;
        assert_eq!(hashed.cache_control, CacheControl::Default);
        Ok(hashed)
    }

    fn execute_fixture_plan(
        plan: &CompilerPlan,
        store: &NativeStore,
        scratch: &Path,
    ) -> Result<crate::build_runtime::CapturedExecution> {
        let leases = plan
            .inputs
            .iter()
            .map(|tree| tree.import(store).map(Arc::new))
            .collect::<Result<Vec<_>>>()?;
        let result = execute(
            &plan.spec,
            store,
            &ExecutionPolicy {
                platform: plan.spec.platform,
                bubblewrap: "/usr/bin/bwrap".into(),
                scratch: scratch.to_owned(),
                timeout: Duration::from_secs(60),
                max_result_bytes: 64 * 1024 * 1024,
            },
            &leases,
            None,
            || Ok(()),
            |_| {},
        )?;
        if !result.status().success() {
            let mut stderr = Vec::new();
            if let Some(blob) = result.diagnostics().1 {
                result.open_blob(blob.id)?.read_to_end(&mut stderr)?;
            }
            anyhow::bail!(
                "isolated compiler stage failed: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        let manifest = result
            .successful_result()
            .context("missing successful fixture result")?;
        plan.spec.action_request()?.validate_result(manifest)?;
        Ok(result)
    }

    fn publish_fixture_trees(
        plan: &CompilerPlan,
        result: &crate::build_runtime::CapturedExecution,
    ) -> Result<()> {
        let manifest = result
            .successful_result()
            .context("missing fixture result")?;
        for (name, destination) in &plan.destinations {
            let Artifact::GeneratedTree(tree) = &manifest.outputs[name] else {
                anyhow::bail!("expected generated fixture tree");
            };
            let staged = crate::build_runtime::materialize_tree(
                tree,
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
        Ok(())
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
        if args.contains(&"static=fixture") {
            for directory in ["first", "second"] {
                std::fs::create_dir(cwd.join(directory))?;
                std::fs::write(
                    cwd.join(directory).join("fixture.c"),
                    "int fixture(void) { return 49; }\n",
                )?;
                ensure!(
                    process::Command::new("cc")
                        .current_dir(cwd.join(directory))
                        .args(["-c", "fixture.c", "-o", "fixture.o"])
                        .status()?
                        .success(),
                    "fixture C compile failed"
                );
                ensure!(
                    process::Command::new("ar")
                        .current_dir(cwd.join(directory))
                        .args(["crs", "libfixture.a", "fixture.o"])
                        .status()?
                        .success(),
                    "fixture archive creation failed"
                );
            }
        }
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let environment = vec![("PATH".into(), "/usr/bin:/bin".into())];
        let rt = tokio::runtime::Runtime::new()?;
        let config = config()?;
        let creator = ProcessCommandCreator::new(&Client::new_num(1));
        let hashed = hash_test_invocation(
            &rt,
            &creator,
            executable,
            &cwd,
            &args,
            &environment,
            &config,
            true,
        )?;
        let compilation = hashed.compilation;
        let result_policy = compilation.native_packaging_policy();
        let mut transformer = dist::PathTransformer::new();
        let (_, remote, cacheable) =
            compilation.generate_compile_commands(&mut transformer, CompileTransport::Native)?;
        assert_eq!(cacheable, Cacheable::Yes);
        let mut remote = remote.context("no distributed command for real compiler")?;
        super::super::core::validate_dist_environment_dependencies(
            &remote,
            &compilation.dist_environment_dependencies(CompileTransport::Native),
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
        let result = execute_fixture_plan(&plan, &store, &cwd)?;
        let manifest = result
            .successful_result()
            .context("missing compiler fixture result")?;
        let mut replayed = BTreeMap::new();
        if let Some(link) = &replay {
            let readers = manifest
                .blobs()?
                .into_iter()
                .map(|(id, _)| Ok((id, result.open_file(id)?)))
                .collect::<Result<BTreeMap<_, _>>>()?;
            let encoding = result.physical_encoding();
            let provider = ReferenceBlobProvider::new(move |blob| {
                use std::os::fd::AsRawFd;
                let pinned = readers.get(&blob.id).context("missing captured blob")?;
                let file = std::fs::File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
                Ok(Box::new(crate::build_runtime::BlobReader::open(
                    file, encoding,
                )?))
            });
            let cache = SourceDigestCache::default();
            let (mut link_plan, artifact) = link.plan(&plan, manifest, &provider)?;
            if args.iter().any(|arg| arg == "static=fixture") {
                let root = link_plan.spec.root.recipe.compose(
                    &link_plan
                        .inputs
                        .iter()
                        .map(|tree| (tree.id(), tree.manifest()))
                        .collect(),
                )?;
                for (directory, selected) in [("first", true), ("second", false)] {
                    let path = TreePath::new(
                        cwd.join(directory)
                            .join("libfixture.a")
                            .strip_prefix("/")?
                            .as_os_str()
                            .as_bytes()
                            .to_vec(),
                    )?;
                    assert_eq!(root.entries.contains_key(&path), selected);
                }
            }

            // Exercise the capture action without the external linker closure.
            // No host linker is available to this execution.
            if let Some((basename, expected)) = link.inputs.relay()? {
                let (capture, capture_plan) = link_capture::LinkCapture::configure(
                    link_plan.clone(),
                    &basename,
                    expected,
                    &cwd,
                    &cache,
                )?;
                let captured = execute_fixture_plan(&capture_plan, &store, &cwd)?;
                publish_fixture_trees(&capture_plan, &captured)?;
                link_plan.complete_link_inputs(&link.inputs, capture.read()?, &cache, None)?;
            } else {
                link_plan.complete_link_inputs(&link.inputs, Vec::new(), &cache, None)?;
            }
            {
                let source_path = TreePath::new(
                    cwd.join(name)
                        .strip_prefix("/")?
                        .as_os_str()
                        .as_bytes()
                        .to_vec(),
                )?;
                assert!(plan.codegen_only.contains(&source_path));
                assert!(
                    !link_plan.inputs[1]
                        .manifest()
                        .entries
                        .contains_key(&source_path)
                );
            }
            let linked = execute_fixture_plan(&link_plan, &store, &cwd)?;
            publish_fixture_trees(&link_plan, &linked)?;
            link.publish(&artifact)?;
            for output in &link.expected {
                let physical = cwd.join(&output.path);
                if output.optional && !physical.exists() {
                    continue;
                }
                replayed.insert(physical.clone(), std::fs::read(physical)?);
            }
            ensure!(
                !replayed.is_empty(),
                "remote link task did not produce an artifact"
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
        assert!(!cwd.join("unexpected-archive-cache").exists());
        Ok(())
    }

    fn cxx_cargo_plan(
        rt: &tokio::runtime::Runtime,
        root: &Path,
        compiler_path: &Path,
        digests: &SourceDigestCache,
        alternate: bool,
    ) -> Result<CompilerPlan> {
        let target = root.join("target");
        let profile = target.join("debug");
        let out = profile.join("build/boringssl-0123456789abcdef/out");
        let cwd = out.join("native-cxx/build");
        for directory in [&cwd, &profile.join("deps"), &profile.join("bin")] {
            std::fs::create_dir_all(directory)?;
        }
        let source = out.join("input.cc");
        std::fs::write(
            &source,
            "#include <vector>\nextern \"C\" int size() { std::vector<int> a{1,2,3}; return a.size(); }\nextern \"C\" const char* file() { return __FILE__; }\n",
        )?;
        let environment = vec![
            (
                "PATH".into(),
                format!(
                    "{}:/usr/bin:/bin:{}",
                    if alternate { "/bin" } else { "/usr/bin" },
                    profile.join("bin").display()
                )
                .into(),
            ),
            (
                "LD_LIBRARY_PATH".into(),
                format!(
                    "{}:{}:{}",
                    profile.join("deps").display(),
                    profile.display(),
                    root.join("missing").display()
                )
                .into(),
            ),
            ("OUT_DIR".into(), out.as_os_str().into()),
            (
                "SCCACHE_CANONICAL_TARGET_ROOT".into(),
                target.as_os_str().into(),
            ),
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            ("LANG".into(), "C".into()),
        ];
        let args = vec![
            "-g".into(),
            "-O2".into(),
            "-MMD".into(),
            "-MF".into(),
            cwd.join("input.d").into_os_string(),
            "-c".into(),
            source.into_os_string(),
            "-o".into(),
            cwd.join(if alternate { "renamed.o" } else { "input.o" })
                .into_os_string(),
        ];
        let config = config()?;

        let creator = ProcessCommandCreator::new(&Client::new_num(1));
        let hash = hash_test_invocation(
            rt,
            &creator,
            compiler_path,
            &cwd,
            &args,
            &environment,
            &config,
            true,
        )?;
        let compilation = hash.compilation;
        let policy = compilation.native_packaging_policy();
        let mut transformer = dist::PathTransformer::new();
        let (_, remote, cacheable) =
            compilation.generate_compile_commands(&mut transformer, CompileTransport::Native)?;
        assert_eq!(cacheable, Cacheable::Yes);
        let mut remote = remote.context("missing real C++ native command")?;
        let (outputs, layout, packagers) = prepare_dispatch(
            compilation,
            &mut remote,
            transformer,
            &cwd,
            &mut None,
            &mut None,
        )?;
        assert!(
            remote
                .arguments
                .windows(2)
                .any(|args| args == ["-o", "/out/object.o"])
        );
        assert_eq!(
            outputs[0].destination,
            cwd.join(if alternate { "renamed.o" } else { "input.o" })
        );
        CompilerPlan::prepare(
            remote,
            &cwd,
            outputs,
            layout,
            packagers,
            (ContentId::of(b"test"), policy, &hash.key),
            (digests, None),
        )
    }

    fn execute_cxx_cargo_plan(
        plan: &CompilerPlan,
        store: &NativeStore,
        scratch: &Path,
    ) -> Result<crate::build_runtime::ResultManifest> {
        let result = execute_fixture_plan(plan, store, scratch)?;
        let manifest = result
            .successful_result()
            .context("missing C++ result")?
            .clone();
        let staged = manifest
            .blobs()?
            .into_iter()
            .map(|(id, size)| {
                store.stage_expected(
                    crate::build_runtime::BlobRef { id, size },
                    result.open_blob(id)?,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        store.publish(
            &plan.spec.action_request()?.action_fingerprint()?,
            &manifest,
            staged,
            ActionMode::Reuse,
        )?;
        Ok(manifest)
    }

    #[test]
    #[ignore = "requires real g++ and Linux Bubblewrap"]
    fn native_cxx_cargo_search_environment_is_independent_of_build_root() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let rt = tokio::runtime::Runtime::new()?;
        let compiler = which::which("g++")?;
        let digests = SourceDigestCache::default();
        let first = cxx_cargo_plan(&rt, &temp.path().join("first"), &compiler, &digests, false)?;
        let second = cxx_cargo_plan(&rt, &temp.path().join("second"), &compiler, &digests, true)?;
        assert_eq!(
            first.spec.command.environment[b"PATH".as_slice()],
            b"/__sccache/toolchain/bin"
        );
        assert!(
            !first
                .spec
                .command
                .environment
                .contains_key(b"LD_LIBRARY_PATH".as_slice())
        );
        assert!(
            !second
                .spec
                .command
                .environment
                .contains_key(b"LD_LIBRARY_PATH".as_slice())
        );
        let fingerprint = first.spec.action_request()?.action_fingerprint()?;
        let other = second.spec.action_request()?.action_fingerprint()?;
        assert_eq!(
            fingerprint,
            other,
            "different components: {:?}",
            fingerprint.differing_components(&other)
        );
        let store = NativeStore::open(&temp.path().join("cas"))?;
        let first_result = execute_cxx_cargo_plan(&first, &store, temp.path())?;
        let hit = store
            .lookup(other.key()?)?
            .context("second root missed the first result")?;
        assert_eq!(hit.manifest(), &first_result);
        drop(hit);
        let second_result = execute_cxx_cargo_plan(&second, &store, temp.path())?;
        assert_eq!(
            first_result, second_result,
            "independent sandbox executions differed"
        );
        assert_eq!(store.duplicate_misses()?.identical_outputs, 0);
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

    #[test]
    #[ignore = "requires nightly Rust, native archive tools and Bubblewrap"]
    fn native_rust_compiler_plan_static_archive() -> Result<()> {
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
                "staticlib",
                "--emit=link,dep-info",
                "--out-dir",
                "build",
                "-Cextra-filename=-stage",
                "-Lnative=first",
                "-Lnative=second",
                "-l",
                "static=fixture",
                "input.rs",
            ],
            "input.rs",
            "extern \"C\" { fn fixture() -> i32; } pub fn value() -> i32 { unsafe { fixture() } }\n",
            true,
        )
    }
}
