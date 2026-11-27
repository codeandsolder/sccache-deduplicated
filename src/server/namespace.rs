//! Connection-owned blob transport. Paths returned by a daemon are never
//! meaningful in a caller's potentially different filesystem namespace.
use crate::cache::Storage;
use crate::compiler::PreprocessorCacheEntry;
use crate::errors::{Context, Result, anyhow, bail};
use crate::protocol::{StorageBlob, TransferReply, TransferRequest};
use anyhow::ensure;
use bytes::Bytes;
use std::io::Read;
#[cfg(feature = "dist-client")]
use std::io::{Seek, SeekFrom};
#[cfg(feature = "dist-client")]
use tokio::io::AsyncWriteExt;

fn validate_storage_key(key: &str) -> Result<()> {
    ensure!(
        key.len() == 64
            && key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid storage key"
    );
    Ok(())
}

enum UploadKind {
    Storage {
        kind: StorageBlob,
        key: String,
    },
    #[cfg(feature = "dist-client")]
    Toolchain {
        compiler: std::path::PathBuf,
        key: String,
    },
    #[cfg(feature = "dist-client")]
    Run {
        job: crate::dist::JobId,
    },
}

enum UploadData {
    Memory(Vec<u8>),
    #[cfg(feature = "dist-client")]
    File(tokio::fs::File),
}

enum Transfer {
    Idle,
    Download(Bytes),
    Upload {
        kind: UploadKind,
        remaining: u64,
        data: UploadData,
    },
}

#[cfg(feature = "dist-client")]
#[derive(Default)]
pub(super) struct ToolchainReservations {
    keys: tokio::sync::Mutex<
        std::collections::HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>,
    >,
}

#[cfg(feature = "dist-client")]
impl ToolchainReservations {
    async fn reserve(&self, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut keys = self.keys.lock().await;
            keys.retain(|_, lock| lock.strong_count() != 0);
            keys.get(key)
                .and_then(std::sync::Weak::upgrade)
                .unwrap_or_else(|| {
                    let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
                    keys.insert(key.to_owned(), std::sync::Arc::downgrade(&lock));
                    lock
                })
        };
        lock.lock_owned().await
    }
}

#[cfg(feature = "dist-client")]
struct Reservation {
    compiler: std::path::PathBuf,
    key: String,
    max_size: u64,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

#[cfg(feature = "dist-client")]
struct Allocation {
    job: crate::dist::JobAlloc,
    toolchain: crate::dist::Toolchain,
    ready: bool,
}

#[cfg(all(feature = "dist-client", target_os = "linux"))]
struct ImpactUpload {
    group: std::sync::Arc<crate::dist::native::result_session::NativeResultSession>,
    scope: crate::build_runtime::ContentId,
    expected: Option<crate::build_runtime::TreeId>,
    blob: crate::build_runtime::BlobRef,
    remaining: u64,
    hash: blake3::Hasher,
    file: tokio::fs::File,
}

pub(super) struct TransferSession {
    state: Transfer,
    chunk_bytes: usize,
    #[cfg(feature = "dist-client")]
    dist: Option<std::sync::Arc<dyn crate::dist::Client>>,
    #[cfg(feature = "dist-client")]
    toolchain: Option<crate::dist::Toolchain>,
    #[cfg(feature = "dist-client")]
    allocation: Option<Allocation>,
    #[cfg(feature = "dist-client")]
    reservations: std::sync::Arc<ToolchainReservations>,
    #[cfg(feature = "dist-client")]
    reservation: Option<Reservation>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    native: Option<std::sync::Arc<crate::compiler::NativeCompilerClient>>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    native_exchange: Option<crate::dist::native::broker::NativeExchange>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    intermediate: Option<std::sync::Arc<crate::dist::native::result_session::NativeResultSession>>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    intermediate_read: Option<(tokio::fs::File, u64)>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    impact_upload: Option<ImpactUpload>,
    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    uid: u32,
}

impl TransferSession {
    pub(super) fn new(
        chunk_bytes: usize,
        #[cfg(feature = "dist-client")] reservations: std::sync::Arc<ToolchainReservations>,
    ) -> Self {
        Self {
            state: Transfer::Idle,
            chunk_bytes,
            #[cfg(feature = "dist-client")]
            dist: None,
            #[cfg(feature = "dist-client")]
            toolchain: None,
            #[cfg(feature = "dist-client")]
            allocation: None,
            #[cfg(feature = "dist-client")]
            reservations,
            #[cfg(feature = "dist-client")]
            reservation: None,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            native: None,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            native_exchange: None,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            intermediate: None,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            intermediate_read: None,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            impact_upload: None,
            #[cfg(all(feature = "dist-client", target_os = "linux"))]
            uid: 0,
        }
    }

    pub(super) const fn request_budget(
        &self,
        request: &super::SccacheRequest,
        limits: super::activity::CompileLimits,
    ) -> std::time::Duration {
        #[cfg(feature = "dist-client")]
        if matches!(
            (&self.state, request),
            (
                Transfer::Upload {
                    kind: UploadKind::Run { .. },
                    ..
                },
                super::Message::WithoutBody(crate::protocol::Request::Transfer(
                    TransferRequest::FinishWrite
                ))
            )
        ) {
            return limits.budget(super::activity::Phase::RunDistributed);
        }
        let _ = request;
        limits.budget(super::activity::Phase::IdentifyToolchain)
    }

    pub(super) const fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    pub(super) async fn initialize_distribution(
        &mut self,
        client: &super::DistClientContainer,
    ) -> Option<bool> {
        #[cfg(feature = "dist-client")]
        {
            // Only the daemon initializes scheduler credentials and connections.
            #[cfg(target_os = "linux")]
            {
                self.native.clone_from(&client.native);
                if self.native.is_some() {
                    self.dist = None;
                    return None;
                }
            }
            self.dist = match client.get_client().await {
                Ok(client) => client,
                Err(error) => {
                    warn!("Namespace distribution unavailable: {error:#}");
                    None
                }
            };
            self.dist
                .as_ref()
                .map(|client| client.rewrite_includes_only())
        }
        #[cfg(not(feature = "dist-client"))]
        {
            let _ = client;
            None
        }
    }

    pub(super) fn native_policy(&self) -> Option<crate::protocol::NativeNamespacePolicy> {
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        {
            self.native
                .as_ref()
                .map(|client| client.namespace_policy().clone())
        }
        #[cfg(not(all(feature = "dist-client", target_os = "linux")))]
        {
            None
        }
    }

    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    pub(super) const fn set_uid(&mut self, uid: u32) {
        self.uid = uid;
    }

    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    pub(super) async fn handle_intermediate(
        &mut self,
        request: TransferRequest,
        client: Option<std::sync::Arc<crate::compiler::NativeCompilerClient>>,
    ) -> Result<TransferReply> {
        use tokio::io::AsyncReadExt;
        let client = client.context("native distribution unavailable")?;
        let uid = self.uid;
        match request {
            TransferRequest::IntermediateOpen => {
                ensure!(
                    self.intermediate.is_none(),
                    "intermediate session already open"
                );
                let (token, session) =
                    tokio::task::spawn_blocking(move || client.open_intermediate(uid)).await??;
                self.intermediate = Some(session);
                Ok(TransferReply::IntermediateOpened(token))
            }
            TransferRequest::IntermediateAuthorize { session, blob } => {
                client.intermediate(uid, session)?.authorize(blob)?;
                Ok(TransferReply::Ack)
            }
            TransferRequest::IntermediateRead { session, blob } => {
                ensure!(
                    self.intermediate_read.is_none(),
                    "intermediate read already active"
                );
                let group = client.intermediate(uid, session)?;
                let file = tokio::task::spawn_blocking(move || group.read(blob)).await??;
                if blob.size != 0 {
                    self.intermediate_read = Some((tokio::fs::File::from_std(file), blob.size));
                }
                Ok(TransferReply::ReadStarted(Some(blob.size)))
            }
            TransferRequest::IntermediatePackage {
                session,
                identity,
                upstream,
                path,
                offline,
            } => {
                ensure!(
                    self.intermediate_read.is_none(),
                    "intermediate read already active"
                );
                let group = client.intermediate(uid, session)?;
                let file = tokio::task::spawn_blocking(move || {
                    let Some(package) = group.retain_package(identity, upstream, path, offline)?
                    else {
                        return Ok::<_, anyhow::Error>(None);
                    };
                    let mut file = tempfile::tempfile()?;
                    bincode::serialize_into(&mut file, &package)?;
                    file.rewind()?;
                    Ok(Some(file))
                })
                .await??;
                let Some(file) = file else {
                    return Ok(TransferReply::ReadStarted(None));
                };
                let size = file.metadata()?.len();
                if size != 0 {
                    self.intermediate_read = Some((tokio::fs::File::from_std(file), size));
                }
                Ok(TransferReply::ReadStarted(Some(size)))
            }
            TransferRequest::IntermediateImpactLookup { session, scope } => {
                let group = client.intermediate(uid, session)?;
                let head =
                    tokio::task::spawn_blocking(move || group.retain_impact_head(scope)).await??;
                Ok(TransferReply::ImpactHead(head))
            }
            TransferRequest::IntermediateImpactBegin {
                session,
                scope,
                expected,
                blob,
            } => {
                ensure!(self.impact_upload.is_none(), "impact upload already active");
                ensure!(
                    blob.size > 0 && blob.size <= client.namespace_policy().max_result_bytes,
                    "invalid impact record size"
                );
                let group = client.intermediate(uid, session)?;
                let file = tokio::fs::File::from_std(tempfile::tempfile()?);
                self.impact_upload = Some(ImpactUpload {
                    group,
                    scope,
                    expected,
                    blob,
                    remaining: blob.size,
                    hash: blake3::Hasher::new(),
                    file,
                });
                Ok(TransferReply::ImpactUploadStarted(self.chunk_bytes))
            }
            TransferRequest::IntermediateImpactWrite(bytes) => {
                let mut upload = self
                    .impact_upload
                    .take()
                    .context("no impact upload active")?;
                let count = u64::try_from(bytes.len())?;
                ensure!(
                    count > 0 && bytes.len() <= self.chunk_bytes && count <= upload.remaining,
                    "invalid impact upload chunk"
                );
                upload.file.write_all(&bytes).await?;
                upload.hash.update(&bytes);
                upload.remaining -= count;
                self.impact_upload = Some(upload);
                Ok(TransferReply::Ack)
            }
            TransferRequest::IntermediateImpactCommit => {
                let upload = self
                    .impact_upload
                    .take()
                    .context("no impact upload active")?;
                ensure!(
                    upload.remaining == 0 && upload.hash.finalize().as_bytes() == &upload.blob.id.0,
                    "incomplete or corrupt impact record"
                );
                let file = rewind_file(upload.file).await?;
                let updated = tokio::task::spawn_blocking(move || {
                    upload.group.publish_impact_head(
                        upload.scope,
                        upload.expected,
                        upload.blob,
                        file,
                    )
                })
                .await??;
                Ok(TransferReply::ImpactUpdated(updated))
            }
            TransferRequest::IntermediateChunk => {
                let (file, remaining) = self
                    .intermediate_read
                    .as_mut()
                    .context("no intermediate read active")?;
                let size = usize::try_from((*remaining).min(self.chunk_bytes as u64))?;
                ensure!(size != 0, "invalid intermediate chunk limit");
                let mut bytes = vec![0; size];
                file.read_exact(&mut bytes).await?;
                *remaining -= size as u64;
                if *remaining == 0 {
                    self.intermediate_read = None;
                }
                Ok(TransferReply::Chunk(bytes))
            }
            _ => bail!("invalid intermediate request"),
        }
    }

    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    async fn handle_native(&mut self, request: TransferRequest) -> Result<TransferReply> {
        use crate::dist::native::broker::NativeExchange;
        use std::time::Duration;

        match request {
            TransferRequest::NativeStart => {
                ensure!(
                    matches!(self.state, Transfer::Idle) && self.native_exchange.is_none(),
                    "native action already active"
                );
                let client = self
                    .native
                    .clone()
                    .context("native namespace handshake required")?;
                let timeout = Duration::from_secs(client.namespace_policy().build_timeout_secs);
                let uid = self.uid;
                self.native_exchange = Some(NativeExchange::start(
                    self.chunk_bytes,
                    timeout,
                    move |stream| client.serve_namespace(stream, uid),
                )?);
                Ok(TransferReply::Ack)
            }
            TransferRequest::NativeWrite(bytes) => {
                self.native_exchange
                    .as_mut()
                    .context("no native action active")?
                    .write(bytes)
                    .await?;
                Ok(TransferReply::Ack)
            }
            TransferRequest::NativeRead => Ok(TransferReply::Chunk(
                self.native_exchange
                    .as_mut()
                    .context("no native action active")?
                    .read()
                    .await?,
            )),
            TransferRequest::NativeEnd => {
                self.native_exchange
                    .take()
                    .context("no native action active")?
                    .finish()
                    .await?;
                Ok(TransferReply::Ack)
            }
            TransferRequest::Abort => {
                self.abort();
                Ok(TransferReply::Ack)
            }
            _ => bail!("legacy transfers unavailable in native namespace mode"),
        }
    }

    pub(super) async fn handle(
        &mut self,
        request: TransferRequest,
        storage: &dyn Storage,
    ) -> Result<TransferReply> {
        let reply = self.handle_request(request, storage).await;
        if reply.is_err() {
            self.abort();
        }
        reply
    }

    fn abort(&mut self) {
        self.state = Transfer::Idle;
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        {
            self.native_exchange = None;
            self.intermediate_read = None;
            self.impact_upload = None;
        }
        #[cfg(feature = "dist-client")]
        {
            self.reservation = None;
            self.allocation = None;
        }
    }

    fn begin_download(&mut self, data: Option<Bytes>) -> TransferReply {
        let len = data.as_ref().map(|data| data.len() as u64);
        self.state = data
            .filter(|data| !data.is_empty())
            .map_or(Transfer::Idle, Transfer::Download);
        TransferReply::ReadStarted(len)
    }

    async fn begin_upload(&mut self, kind: UploadKind, len: u64) -> Result<TransferReply> {
        ensure!(
            matches!(self.state, Transfer::Idle),
            "another transfer is active"
        );
        let data = match &kind {
            UploadKind::Storage { .. } => UploadData::Memory(Vec::new()),
            #[cfg(feature = "dist-client")]
            _ => UploadData::File(tokio::fs::File::from_std(
                tokio::task::spawn_blocking(tempfile::tempfile).await??,
            )),
        };
        self.state = Transfer::Upload {
            kind,
            remaining: len,
            data,
        };
        Ok(TransferReply::WriteStarted)
    }

    fn read_chunk(&mut self) -> Result<TransferReply> {
        let Transfer::Download(data) = &mut self.state else {
            bail!("no download is active");
        };
        let chunk = data.split_to(data.len().min(self.chunk_bytes)).to_vec();
        if data.is_empty() {
            self.state = Transfer::Idle;
        }
        Ok(TransferReply::Chunk(chunk))
    }

    async fn write_chunk(&mut self, chunk: Vec<u8>) -> Result<TransferReply> {
        let Transfer::Upload {
            remaining, data, ..
        } = &mut self.state
        else {
            bail!("no upload is active");
        };
        ensure!(
            !chunk.is_empty() && chunk.len() <= self.chunk_bytes,
            "invalid upload chunk size"
        );
        let len = chunk.len() as u64;
        ensure!(len <= *remaining, "upload exceeds declared size");
        match data {
            UploadData::Memory(bytes) => {
                bytes
                    .try_reserve(chunk.len())
                    .context("upload does not fit in memory")?;
                bytes.extend_from_slice(&chunk);
            }
            #[cfg(feature = "dist-client")]
            UploadData::File(file) => file.write_all(&chunk).await?,
        }
        *remaining -= len;
        Ok(TransferReply::Ack)
    }

    async fn finish_upload(&mut self, storage: &dyn Storage) -> Result<TransferReply> {
        let Transfer::Upload {
            kind,
            remaining,
            data,
        } = std::mem::replace(&mut self.state, Transfer::Idle)
        else {
            bail!("no upload is active");
        };
        ensure!(remaining == 0, "incomplete upload");
        match (kind, data) {
            (UploadKind::Storage { kind, key }, UploadData::Memory(bytes)) => {
                store_blob(storage, kind, &key, bytes).await
            }
            #[cfg(feature = "dist-client")]
            (UploadKind::Toolchain { compiler, key }, UploadData::File(file)) => {
                let reservation = self
                    .reservation
                    .take()
                    .context("no toolchain reservation is active")?;
                ensure!(
                    reservation.key == key && reservation.compiler == compiler,
                    "toolchain reservation mismatch"
                );
                let tc = self
                    .dist_client()?
                    .import_namespace_toolchain(compiler, key, rewind_file(file).await?)
                    .await?;
                drop(reservation);
                self.toolchain = Some(tc.clone());
                Ok(TransferReply::Toolchain(Some(tc)))
            }
            #[cfg(feature = "dist-client")]
            (UploadKind::Run { job }, UploadData::File(file)) => {
                self.finish_run(job, rewind_file(file).await?).await
            }
            #[cfg(feature = "dist-client")]
            _ => bail!("upload kind does not match its buffer"),
        }
    }

    async fn handle_request(
        &mut self,
        request: TransferRequest,
        storage: &dyn Storage,
    ) -> Result<TransferReply> {
        ensure!(
            self.chunk_bytes > 0,
            "IPC frame limit is too small for namespace transfers"
        );
        #[cfg(all(feature = "dist-client", target_os = "linux"))]
        if self.native.is_some() {
            return self.handle_native(request).await;
        }
        match request {
            TransferRequest::Read { kind, key } => {
                validate_storage_key(&key)?;
                ensure!(
                    matches!(self.state, Transfer::Idle),
                    "another transfer is active"
                );
                let data = read_blob(storage, kind, &key)
                    .await
                    .with_context(|| format!("namespace storage lookup for key {key}"))
                    .inspect_err(|error| warn!("{error:#}"))?;
                Ok(self.begin_download(data))
            }
            TransferRequest::BeginWrite { kind, key, len } => {
                validate_storage_key(&key)?;
                if let Some(capacity) = storage.max_size().await? {
                    ensure!(len <= capacity, "upload exceeds cache capacity");
                }
                self.begin_upload(UploadKind::Storage { kind, key }, len)
                    .await
            }
            TransferRequest::ReadChunk => self.read_chunk(),
            TransferRequest::WriteChunk(chunk) => self.write_chunk(chunk).await,
            TransferRequest::FinishWrite => self.finish_upload(storage).await,
            TransferRequest::Abort => {
                self.abort();
                Ok(TransferReply::Ack)
            }
            request => {
                #[cfg(feature = "dist-client")]
                {
                    self.handle_dist(request).await
                }
                #[cfg(not(feature = "dist-client"))]
                {
                    let _ = request;
                    bail!("distributed compilation is not enabled");
                }
            }
        }
    }

    #[cfg(feature = "dist-client")]
    fn dist_client(&self) -> Result<std::sync::Arc<dyn crate::dist::Client>> {
        self.dist
            .clone()
            .context("namespace distribution is not available")
    }

    #[cfg(feature = "dist-client")]
    async fn handle_dist(&mut self, request: TransferRequest) -> Result<TransferReply> {
        use crate::dist::{AllocJobResult, SubmitToolchainResult};
        ensure!(
            matches!(self.state, Transfer::Idle),
            "another transfer is active"
        );
        let client = self.dist_client()?;
        match request {
            TransferRequest::LookupToolchain { compiler, key } => {
                self.lookup_toolchain(compiler, key).await
            }
            TransferRequest::BeginToolchain { compiler, key, len } => {
                validate_storage_key(&key)?;
                ensure!(self.allocation.is_none(), "a job is already allocated");
                self.validate_reservation(&compiler, &key, len)?;
                self.begin_upload(UploadKind::Toolchain { compiler, key }, len)
                    .await
            }
            TransferRequest::Allocate { toolchain } => {
                ensure!(self.allocation.is_none(), "a job is already allocated");
                ensure!(
                    self.toolchain.as_ref() == Some(&toolchain),
                    "toolchain not prepared by this session"
                );
                match client.do_alloc_job(toolchain.clone()).await? {
                    AllocJobResult::Success {
                        job_alloc,
                        need_toolchain,
                    } => {
                        let reply = TransferReply::Allocation {
                            server: job_alloc.server_id,
                            job: job_alloc.job_id,
                            need_toolchain,
                        };
                        self.allocation = Some(Allocation {
                            job: job_alloc,
                            toolchain,
                            ready: !need_toolchain,
                        });
                        Ok(reply)
                    }
                    AllocJobResult::Fail { msg } => Ok(TransferReply::AllocationFailed(msg)),
                }
            }
            TransferRequest::SubmitToolchain { job } => {
                let allocation = self
                    .allocation
                    .as_mut()
                    .context("no allocation is active")?;
                ensure!(
                    allocation.job.job_id == job && !allocation.ready,
                    "unexpected toolchain submission"
                );
                let result = client
                    .do_submit_toolchain(allocation.job.clone(), allocation.toolchain.clone())
                    .await?;
                allocation.ready = matches!(result, SubmitToolchainResult::Success);
                Ok(TransferReply::Submitted(result))
            }
            TransferRequest::BeginRun { job, len } => {
                let allocation = self
                    .allocation
                    .as_ref()
                    .context("no allocation is active")?;
                ensure!(
                    allocation.job.job_id == job && allocation.ready,
                    "job not ready"
                );
                self.begin_upload(UploadKind::Run { job }, len).await
            }
            TransferRequest::Status => Ok(TransferReply::Status(client.do_get_status().await?)),
            TransferRequest::WorkerLabel { server } => Ok(TransferReply::WorkerLabel(
                client.worker_label(server).await,
            )),
            _ => bail!("invalid distributed transfer operation"),
        }
    }

    #[cfg(feature = "dist-client")]
    fn validate_reservation(&self, compiler: &std::path::Path, key: &str, len: u64) -> Result<()> {
        let Reservation {
            compiler: reserved_compiler,
            key: reserved_key,
            max_size,
            ..
        } = self
            .reservation
            .as_ref()
            .context("toolchain upload was not reserved")?;
        ensure!(
            reserved_key == key && reserved_compiler == compiler,
            "toolchain reservation mismatch"
        );
        ensure!(
            len <= *max_size,
            "toolchain exceeds daemon archive capacity"
        );
        Ok(())
    }

    #[cfg(feature = "dist-client")]
    async fn lookup_toolchain(
        &mut self,
        compiler: std::path::PathBuf,
        key: String,
    ) -> Result<TransferReply> {
        let client = self.dist_client()?;
        validate_storage_key(&key)?;
        ensure!(self.allocation.is_none(), "a job is already allocated");
        ensure!(
            self.reservation.is_none(),
            "a toolchain is already reserved"
        );
        let (mut tc, max_size) = client
            .lookup_namespace_toolchain(compiler.clone(), key.clone())
            .await?;
        if tc.is_none() {
            let guard = self.reservations.reserve(&key).await;
            (tc, _) = client
                .lookup_namespace_toolchain(compiler.clone(), key.clone())
                .await?;
            if tc.is_none() {
                self.reservation = Some(Reservation {
                    compiler,
                    key,
                    max_size,
                    _guard: guard,
                });
            }
        }
        self.toolchain.clone_from(&tc);
        Ok(TransferReply::Toolchain(tc))
    }

    #[cfg(feature = "dist-client")]
    async fn finish_run(
        &mut self,
        job: crate::dist::JobId,
        mut file: std::fs::File,
    ) -> Result<TransferReply> {
        let allocation = self.allocation.take().context("no allocation is active")?;
        ensure!(
            allocation.job.job_id == job && allocation.ready,
            "job not ready"
        );
        let (spec, file) = tokio::task::spawn_blocking(move || -> Result<_> {
            let spec: crate::protocol::NamespaceRunSpec = bincode::deserialize_from(&mut file)?;
            Ok((spec, file))
        })
        .await??;
        let result = self
            .dist_client()?
            .do_run_job(
                allocation.job,
                spec.command,
                spec.outputs,
                Box::new(FileInputs(file)),
            )
            .await?;
        let bytes = tokio::task::spawn_blocking(move || bincode::serialize(&result)).await??;
        Ok(self.begin_download(Some(bytes.into())))
    }
}

#[cfg(feature = "dist-client")]
struct FileInputs(std::fs::File);

#[cfg(feature = "dist-client")]
impl crate::dist::pkg::InputsPackager for FileInputs {
    #[cfg(target_os = "linux")]
    fn native_mapping(self: Box<Self>) -> Result<crate::build_runtime::MappedTree> {
        bail!("namespace archive transport cannot supply a native input mapping")
    }

    fn write_inputs(mut self: Box<Self>, output: &mut dyn std::io::Write) -> Result<()> {
        std::io::copy(&mut self.0, output)?;
        Ok(())
    }
}

async fn read_blob(storage: &dyn Storage, kind: StorageBlob, key: &str) -> Result<Option<Bytes>> {
    match kind {
        StorageBlob::Cache => storage.get_raw(key).await,
        StorageBlob::Preprocessor => match storage.get_preprocessor_cache_entry(key).await? {
            Some(mut entry) => Ok(Some(
                tokio::task::spawn_blocking(move || -> Result<Bytes> {
                    let mut bytes = Vec::new();
                    entry.read_to_end(&mut bytes)?;
                    Ok(bytes.into())
                })
                .await??,
            )),
            None => Ok(None),
        },
    }
}

#[cfg(feature = "dist-client")]
async fn rewind_file(mut file: tokio::fs::File) -> Result<std::fs::File> {
    file.flush().await?;
    let mut file = file.into_std().await;
    tokio::task::spawn_blocking(move || -> Result<_> {
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    })
    .await?
}

async fn store_blob(
    storage: &dyn Storage,
    kind: StorageBlob,
    key: &str,
    bytes: Vec<u8>,
) -> Result<TransferReply> {
    match kind {
        StorageBlob::Cache => {
            storage.put_raw(key, bytes.into()).await?;
        }
        StorageBlob::Preprocessor => {
            let entry = PreprocessorCacheEntry::read(&bytes).map_err(|e| anyhow!("{e}"))?;
            storage.put_preprocessor_cache_entry(key, entry).await?;
        }
    }
    Ok(TransferReply::Ack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{Cache, CacheMode, CacheRead, CacheWrite, IpcStorage};
    use crate::client::ServerConnection;
    use crate::mock_command::ProcessCommandCreator;
    use crate::server::SccacheService;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct MemoryStorage {
        entries: Mutex<HashMap<String, Bytes>>,
    }

    #[async_trait]
    impl Storage for MemoryStorage {
        async fn get(&self, key: &str) -> Result<Cache> {
            self.get_raw(key).await?.map_or(Ok(Cache::Miss), |data| {
                CacheRead::from(Cursor::new(data)).map(Cache::Hit)
            })
        }

        async fn put(&self, key: &str, entry: CacheWrite) -> Result<Duration> {
            self.put_raw(key, entry.finish()?.into()).await
        }

        async fn get_raw(&self, key: &str) -> Result<Option<Bytes>> {
            Ok(self.entries.lock().await.get(key).cloned())
        }

        async fn put_raw(&self, key: &str, data: Bytes) -> Result<Duration> {
            self.entries.lock().await.insert(key.to_owned(), data);
            Ok(Duration::ZERO)
        }

        async fn check(&self) -> Result<CacheMode> {
            Ok(CacheMode::ReadWrite)
        }

        fn location(&self) -> String {
            "test-memory".into()
        }

        async fn current_size(&self) -> Result<Option<u64>> {
            Ok(None)
        }

        async fn max_size(&self) -> Result<Option<u64>> {
            Ok(Some(64 * 1024 * 1024))
        }
    }

    #[cfg(all(feature = "dist-client", target_os = "linux"))]
    #[tokio::test]
    async fn abort_releases_intermediate_read_descriptor() -> Result<()> {
        let mut session = TransferSession::new(4096, Arc::new(ToolchainReservations::default()));
        session.intermediate_read = Some((tokio::fs::File::from_std(tempfile::tempfile()?), 8));
        assert!(matches!(
            session
                .handle(TransferRequest::Abort, &MemoryStorage::default())
                .await?,
            TransferReply::Ack
        ));
        assert!(session.intermediate_read.is_none());
        Ok(())
    }

    #[test]
    fn namespace_blob_transport_round_trips_large_cache_entries() -> Result<()> {
        let runtime = crate::util::new_client_runtime()?;
        runtime.block_on(async {
            let storage = Arc::new(MemoryStorage::default());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let service = SccacheService::<ProcessCommandCreator>::mock_with_storage(
                storage.clone(),
                tokio::runtime::Handle::current(),
            );
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await?;
                service.bind(socket).await
            });
            let key = "a".repeat(64);
            let other = "b".repeat(64);
            let data = vec![0x5a; 9 * 1024 * 1024 + 123];
            let expected = data.clone();
            let key_copy = key.clone();
            let other_copy = other.clone();
            let socket = std::net::TcpStream::connect(addr)?;
            let client = IpcStorage::connect(ServerConnection::new(Box::new(socket))?).await?;
            assert!(client.get_raw(&key).await?.is_none());
            client.put_raw(&key, data.into()).await?;
            assert_eq!(
                client.get_raw(&key).await?.as_deref(),
                Some(expected.as_slice())
            );
            assert_eq!(
                storage.get_raw(&key).await?.as_deref(),
                Some(expected.as_slice())
            );

            // The transfer can return bytes successfully while the artifact
            // itself is corrupt. That is a read error, not an absent key.
            let error = client.get(&key).await.unwrap_err();
            assert!(format!("{error:#}").contains(&key));
            assert!(matches!(client.get(&other).await?, Cache::Miss));

            let conn = client.conn();
            crate::client::connection_task(conn, move |conn| {
                assert!(matches!(
                    conn.transfer(TransferRequest::BeginWrite {
                        kind: StorageBlob::Cache,
                        key: other_copy,
                        len: 10,
                    })?,
                    TransferReply::WriteStarted
                ));
                conn.transfer(TransferRequest::WriteChunk(vec![1; 3]))?;
                assert!(conn.transfer(TransferRequest::FinishWrite).is_err());
                // The same connection remains usable after a failed transaction.
                assert!(matches!(
                    conn.transfer(TransferRequest::Read {
                        kind: StorageBlob::Cache,
                        key: key_copy,
                    })?,
                    TransferReply::ReadStarted(Some(_))
                ));
                conn.transfer(TransferRequest::Abort)?;
                Ok(())
            })
            .await?;
            assert!(storage.get_raw(&other).await?.is_none());
            drop(client);
            server.await??;
            Ok(())
        })
    }
}
