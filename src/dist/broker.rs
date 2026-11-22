//! Client-side distributed compilation through the existing daemon connection.
//! Neither scheduler credentials nor daemon-local filesystem paths cross this
//! boundary; compiler discovery and package construction remain in the caller.
use super::pkg::{InputsPackager, ToolchainPackager};
use super::{
    AllocJobResult, Client, CompileCommand, CustomToolchainOverride, JobAlloc, RunJobResult,
    SchedulerStatusResult, ServerId, SubmitToolchainResult, Toolchain,
};
use crate::client::{SharedConnection, connection_task};
use crate::config::DistToolchainConfig;
use crate::errors::{Context, Result, bail};
use crate::protocol::{NamespaceRunSpec, TransferReply, TransferRequest};
use crate::util::Digest;
use anyhow::ensure;
use async_trait::async_trait;
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) struct NamespaceClient {
    conn: SharedConnection,
    chunk_bytes: usize,
    rewrite_includes_only: bool,
    toolchains: Vec<DistToolchainConfig>,
}

impl NamespaceClient {
    pub(crate) const fn new(
        conn: SharedConnection,
        chunk_bytes: usize,
        rewrite_includes_only: bool,
        toolchains: Vec<DistToolchainConfig>,
    ) -> Self {
        Self {
            conn,
            chunk_bytes,
            rewrite_includes_only,
            toolchains,
        }
    }

    async fn request(&self, request: TransferRequest) -> Result<TransferReply> {
        connection_task(Arc::clone(&self.conn), move |conn| conn.transfer(request)).await
    }

    fn custom_toolchain(&self, compiler: &Path) -> Option<CustomToolchainOverride> {
        self.toolchains.iter().find_map(|config| match config {
            DistToolchainConfig::PathOverride {
                compiler_executable,
                archive,
                archive_compiler_executable,
                archive_cargo_executable,
            } if compiler_executable == compiler => Some(CustomToolchainOverride {
                compiler_executable: archive_compiler_executable.clone(),
                archive: archive.clone(),
                cargo_executable: archive_cargo_executable.clone(),
            }),
            _ => None,
        })
    }
}

/// Isolate weak toolchain identities across independent filesystem namespaces.
/// The packager still supplies its normal compiler/helper dependency identity.
/// If namespace identity is unavailable, use the actual package digest instead
/// of assuming that an identically named compiler belongs to this namespace.
#[cfg(target_os = "linux")]
fn namespace_fingerprint() -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let namespace = std::fs::metadata("/proc/self/ns/mnt").ok()?;
    let root = std::fs::metadata("/").ok()?;
    let mountinfo = std::fs::read("/proc/self/mountinfo").ok()?;
    let boot = std::fs::read("/proc/sys/kernel/random/boot_id").ok()?;
    let mut digest = Digest::new();
    digest.delimiter(b"mount-namespace-v1");
    for value in [namespace.dev(), namespace.ino(), root.dev(), root.ino()] {
        digest.update(&value.to_le_bytes());
    }
    digest.delimiter(&boot);
    digest.delimiter(&mountinfo);
    Some(digest.finish())
}

#[cfg(not(target_os = "linux"))]
const fn namespace_fingerprint() -> Option<String> {
    None
}

enum PackageSource {
    File(std::fs::File),
    Packager(Box<dyn ToolchainPackager>),
}

fn construct_package(packager: Box<dyn ToolchainPackager>) -> Result<std::fs::File> {
    // Temporary transport staging only. The daemon owns the persistent package
    // cache. The packager needs a regular seekable file for its archive output.
    let temp = tempfile::NamedTempFile::new()?;
    packager.write_pkg(fs_err::File::from_parts(temp.reopen()?, temp.path()))?;
    let mut file = temp.reopen()?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[async_trait]
impl Client for NamespaceClient {
    async fn do_alloc_job(&self, toolchain: Toolchain) -> Result<AllocJobResult> {
        match self
            .request(TransferRequest::Allocate { toolchain })
            .await?
        {
            TransferReply::Allocation {
                server,
                job,
                need_toolchain,
            } => Ok(AllocJobResult::Success {
                // The genuine signed allocation stays in the daemon's per-
                // connection session. Only the opaque job identifier is returned.
                job_alloc: JobAlloc {
                    auth: String::new(),
                    job_id: job,
                    server_id: server,
                },
                need_toolchain,
            }),
            TransferReply::AllocationFailed(msg) => Ok(AllocJobResult::Fail { msg }),
            _ => bail!("unexpected broker allocation response"),
        }
    }

    async fn do_get_status(&self) -> Result<SchedulerStatusResult> {
        let TransferReply::Status(status) = self.request(TransferRequest::Status).await? else {
            bail!("unexpected broker status response");
        };
        Ok(status)
    }

    async fn do_submit_toolchain(
        &self,
        allocation: JobAlloc,
        _: Toolchain,
    ) -> Result<SubmitToolchainResult> {
        let TransferReply::Submitted(result) = self
            .request(TransferRequest::SubmitToolchain {
                job: allocation.job_id,
            })
            .await?
        else {
            bail!("unexpected broker submit response");
        };
        Ok(result)
    }

    async fn do_run_job(
        &self,
        allocation: JobAlloc,
        command: CompileCommand,
        outputs: Vec<String>,
        inputs_packager: Box<dyn InputsPackager>,
    ) -> Result<RunJobResult> {
        let chunk_bytes = self.chunk_bytes;
        connection_task(Arc::clone(&self.conn), move |conn| {
            let mut inputs = tempfile::tempfile()?;
            bincode::serialize_into(&mut inputs, &NamespaceRunSpec { command, outputs })?;
            inputs_packager.write_inputs(&mut inputs)?;
            let len = inputs.metadata()?.len();
            inputs.seek(SeekFrom::Start(0))?;
            ensure!(
                matches!(
                    conn.transfer(TransferRequest::BeginRun {
                        job: allocation.job_id,
                        len
                    })?,
                    TransferReply::WriteStarted
                ),
                "expected run upload start"
            );
            conn.upload(len, chunk_bytes, inputs)?;
            let TransferReply::ReadStarted(Some(result_len)) =
                conn.transfer(TransferRequest::FinishWrite)?
            else {
                bail!("expected distributed job result");
            };
            let mut result = tempfile::tempfile()?;
            conn.download(result_len, chunk_bytes, &mut result)?;
            result.seek(SeekFrom::Start(0))?;
            Ok(bincode::deserialize_from(result)?)
        })
        .await
    }

    async fn worker_label(&self, server: ServerId) -> String {
        match self.request(TransferRequest::WorkerLabel { server }).await {
            Ok(TransferReply::WorkerLabel(label)) => label,
            _ => server.addr().to_string(),
        }
    }

    async fn put_toolchain(
        &self,
        compiler: PathBuf,
        weak_key: String,
        packager: Box<dyn ToolchainPackager>,
    ) -> Result<(Toolchain, Option<CustomToolchainOverride>)> {
        ensure!(!self.toolchains.iter().any(|config| matches!(config, DistToolchainConfig::NoDist { compiler_executable } if *compiler_executable == compiler)), "compiler distribution is disabled in this namespace");
        let custom = self.custom_toolchain(&compiler);
        let chunk_bytes = self.chunk_bytes;
        connection_task(Arc::clone(&self.conn), move |conn| {
            let (key, source) = if let Some(custom) = custom.as_ref() {
                let mut file = std::fs::File::open(&custom.archive)
                    .context("could not open namespace toolchain override")?;
                let key = Digest::reader_sync(&mut file)?;
                file.seek(SeekFrom::Start(0))?;
                (key, PackageSource::File(file))
            } else if let Some(namespace) = namespace_fingerprint() {
                let mut digest = Digest::new();
                digest.delimiter(namespace.as_bytes());
                digest.delimiter(weak_key.as_bytes());
                if let Some(extra) = packager.cache_key_extension()? {
                    digest.delimiter(extra.as_bytes());
                }
                (digest.finish(), PackageSource::Packager(packager))
            } else {
                let mut file = construct_package(packager)?;
                let key = Digest::reader_sync(&mut file)?;
                file.seek(SeekFrom::Start(0))?;
                (key, PackageSource::File(file))
            };
            let TransferReply::Toolchain(found) =
                conn.transfer(TransferRequest::LookupToolchain {
                    compiler: compiler.clone(),
                    key: key.clone(),
                })?
            else {
                bail!("unexpected broker toolchain lookup response");
            };
            let result = (|| {
                let tc = match found {
                    Some(tc) => tc,
                    None => {
                        let file = match source {
                            PackageSource::File(file) => file,
                            PackageSource::Packager(packager) => construct_package(packager)?,
                        };
                        upload_toolchain(conn, compiler, key, file, chunk_bytes)?
                    }
                };
                Ok((tc, custom))
            })();
            if result.is_err() {
                let _ = conn.transfer(TransferRequest::Abort);
            }
            result
        })
        .await
    }

    fn rewrite_includes_only(&self) -> bool {
        self.rewrite_includes_only
    }

    fn get_custom_toolchain(&self, executable: &Path) -> Option<PathBuf> {
        self.custom_toolchain(executable)
            .map(|toolchain| toolchain.archive)
    }
}

fn upload_toolchain(
    conn: &mut crate::client::ServerConnection,
    compiler: PathBuf,
    key: String,
    package: std::fs::File,
    chunk_bytes: usize,
) -> Result<Toolchain> {
    let len = package.metadata()?.len();
    ensure!(
        matches!(
            conn.transfer(TransferRequest::BeginToolchain { compiler, key, len })?,
            TransferReply::WriteStarted
        ),
        "expected toolchain upload start"
    );
    conn.upload(len, chunk_bytes, package)?;
    let TransferReply::Toolchain(Some(toolchain)) = conn.transfer(TransferRequest::FinishWrite)?
    else {
        bail!("expected imported toolchain identity");
    };
    Ok(toolchain)
}
