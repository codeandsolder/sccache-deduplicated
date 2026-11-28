use crate::compiler::ColorMode;
use crate::server::{DistInfo, ServerInfo, ServerStats};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;

/// A client request.
#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    /// Zero the server's statistics.
    ZeroStats,
    /// Get server statistics.
    GetStats,
    /// Get dist status.
    DistStatus,
    /// Shut the server down gracefully.
    Shutdown,
    /// Execute a compile or fetch a cached compilation result.
    Compile(Compile),

    // --- Storage RPCs (client-side mode) ---
    /// One-shot handshake: client requests cache metadata from the daemon.
    StorageHandshake,
    /// Transfer an opaque blob without sharing filesystem paths.
    Transfer(TransferRequest),
    /// Merge per-invocation stats into the daemon's running totals.
    RecordStats(Box<ServerStats>),
    /// List active daemon-owned compile requests without accessing cache storage.
    ActiveCompiles,
    /// Request cancellation of one active daemon-owned compile.
    CancelCompile(String),
    /// Open a dedicated observation connection for a caller-owned compile.
    ObserveCompile(CompileIdentity),
    /// Report caller-monotonic phase ages on that connection.
    ObservePhase(Box<crate::server::activity::CompileActivity>),
}

/// A server response.
#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    /// Response for `Request::Compile`.
    Compile(CompileResponse),
    /// Response for `Request::ZeroStats`.
    ZeroStats,
    /// Response for `Request::GetStats`, containing server statistics.
    Stats(Box<ServerInfo>),
    /// Response for `Request::DistStatus`, containing client info.
    DistStatus(DistInfo),
    /// Response for `Request::Shutdown`, containing server statistics.
    ShuttingDown(Box<ServerInfo>),
    /// Second response for `Request::Compile`, containing the results of the compilation.
    CompileFinished(CompileFinished),

    // --- Storage RPC responses (client-side mode) ---
    /// Response for `Request::StorageHandshake`.
    StorageHandshake(StorageHandshakeInfo),
    /// Response for a namespace-safe transfer request.
    Transfer(Result<TransferReply, String>),
    /// Response for `Request::RecordStats`.
    RecordStats,
    /// Liveness notification, carrying the actual phase and age.
    CompileProgress(crate::server::activity::CompileActivity),
    /// Terminal failure; no automatic duplicate compilation is permitted.
    CompileAborted(String),
    /// Active daemon-owned compiler requests.
    ActiveCompiles(Vec<crate::server::activity::CompileActivity>),
    CompileCancellationRequested(bool),
    /// Liveness for a pending non-compile RPC.
    Heartbeat,
    /// The connection-owned operation was abandoned; the session is invalid.
    RequestAborted(String),
    /// The daemon registered a caller-owned compile with this ID.
    CompileObserved(String),
    ObservationAccepted,
}

/// Maximum application payload in a transfer frame. The framing envelope
/// stays well below the default 8 MiB IPC frame limit.
pub const TRANSFER_CHUNK_BYTES: usize = 1024 * 1024;
pub const NAMESPACE_PROTOCOL_VERSION: u32 = 9;

#[derive(Serialize, Deserialize)]
pub enum TransferRequest {
    // Native action stream: only a connection that completed the native
    // handshake can start one. No scheduler tickets or credentials cross IPC.
    NativeStart,
    NativeRead,
    NativeWrite(#[serde(with = "serde_bytes")] Vec<u8>),
    NativeEnd,
    IntermediateOpen,
    IntermediateAuthorize {
        session: crate::build_runtime::wire::Ticket,
        blob: crate::build_runtime::BlobRef,
    },
    IntermediateRead {
        session: crate::build_runtime::wire::Ticket,
        blob: crate::build_runtime::BlobRef,
    },
    IntermediateChunk,
    Abort,
}

#[derive(Serialize, Deserialize)]
pub enum TransferReply {
    ReadStarted(Option<u64>),
    Chunk(#[serde(with = "serde_bytes")] Vec<u8>),
    Ack,
    IntermediateOpened(crate::build_runtime::wire::Ticket),
}

impl TransferRequest {
    pub(crate) const fn is_intermediate(&self) -> bool {
        matches!(
            self,
            Self::IntermediateOpen
                | Self::IntermediateAuthorize { .. }
                | Self::IntermediateRead { .. }
                | Self::IntermediateChunk
        )
    }
}

// Transfer frames can carry complete object data; don't dump payload bytes
// or metadata such as filenames into diagnostics.
impl std::fmt::Debug for TransferRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::NativeStart => "NativeStart",
            Self::NativeRead => "NativeRead",
            Self::NativeWrite(_) => "NativeWrite",
            Self::NativeEnd => "NativeEnd",
            Self::IntermediateOpen => "IntermediateOpen",
            Self::IntermediateAuthorize { .. } => "IntermediateAuthorize",
            Self::IntermediateRead { .. } => "IntermediateRead",
            Self::IntermediateChunk => "IntermediateChunk",
            Self::Abort => "Abort",
        };
        f.write_str(name)
    }
}

impl std::fmt::Debug for TransferReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadStarted(len) => f.debug_tuple("ReadStarted").field(len).finish(),
            Self::Chunk(bytes) => f.debug_tuple("Chunk").field(&bytes.len()).finish(),
            Self::Ack => f.write_str("Ack"),
            Self::IntermediateOpened(_) => f.write_str("IntermediateOpened"),
        }
    }
}

/// Possible responses from the server for a `Compile` request.
#[derive(Serialize, Deserialize, Debug)]
pub enum CompileResponse {
    /// The compilation was started.
    CompileStarted,
    /// A verified non-compilation compiler query.
    CompilerQuery,
    /// A compilation cannot be executed under the remote action contract.
    RejectedCompilation(String),
    /// The compiler was not supported.
    UnsupportedCompiler(OsString),
}

/// A successful native action, reported only after verified output delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCompileReport {
    pub key: crate::build_runtime::ActionKey,
    pub mode: crate::build_runtime::ActionMode,
    pub source: NativeBuildSource,
    pub stage: NativeStage,
    pub successful: bool,
    pub duration: std::time::Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeStage {
    Compile,
    Codegen,
    LinkPlan,
    Link,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeBuildSource {
    Hit,
    Worker(crate::build_runtime::PeerId),
}

/// Information about a finished scheduler-owned compiler request.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CompileFinished {
    /// The return code of the compile process, if available.
    pub retcode: Option<i32>,
    /// The signal that terminated the compile process, if available.
    pub signal: Option<i32>,
    /// The compiler's stdout.
    pub stdout: Vec<u8>,
    /// The compiler's stderr.
    pub stderr: Vec<u8>,
    /// The state of any compiler options passed to control color output.
    pub color_mode: ColorMode,
    /// Native actions and outcomes, in dependency order.
    pub native: Vec<NativeCompileReport>,
}

/// The contents of a compile request from a client.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Compile {
    /// Caller PID for correlating a request with local build processes.
    pub client_pid: u32,
    /// The full path to the compiler executable.
    pub exe: OsString,
    /// The current working directory in which to execute the compile.
    pub cwd: OsString,
    /// The commandline arguments passed to the compiler.
    pub args: Vec<OsString>,
    /// The environment variables present when the compiler was executed, as (var, val).
    pub env_vars: Vec<(OsString, OsString)>,
}

/// Compiler identity for observation only. Arguments and environment are
/// never sent to the daemon merely to observe a caller-owned compile.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompileIdentity {
    pub client_pid: u32,
    pub exe: OsString,
    pub cwd: OsString,
}

impl From<&Compile> for CompileIdentity {
    fn from(value: &Compile) -> Self {
        Self {
            client_pid: value.client_pid,
            exe: value.exe.clone(),
            cwd: value.cwd.clone(),
        }
    }
}

/// Cache metadata returned by the daemon on `StorageHandshake`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageHandshakeInfo {
    pub location: String,
    pub cache_type_name: String,
    pub basedirs: Vec<Vec<u8>>,
    pub max_size: Option<u64>,
    pub namespace_protocol: u32,
    pub transfer_chunk_bytes: usize,
    pub native: Option<NativeNamespacePolicy>,
}

/// Public execution limits and platform identity for a namespace caller.
/// Endpoints, authentication and worker allocation capabilities are private
/// to the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeNamespacePolicy {
    pub platform: crate::build_runtime::ContentId,
    pub build_timeout_secs: u64,
    pub renewal_interval_secs: u64,
    pub max_metadata_bytes: u64,
    pub max_result_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_transfer_frames_roundtrip_full_chunk() -> anyhow::Result<()> {
        let payload = (0..TRANSFER_CHUNK_BYTES)
            .map(|index| index.to_le_bytes()[0])
            .collect::<Vec<_>>();
        {
            let request = TransferRequest::NativeWrite(payload.clone());
            let bytes = bincode::serialize(&Request::Transfer(request))?;
            assert!(bytes.len() <= payload.len() + 32);
            match bincode::deserialize(&bytes)? {
                Request::Transfer(TransferRequest::NativeWrite(decoded)) => {
                    assert_eq!(decoded, payload)
                }
                _ => anyhow::bail!("unexpected decoded transfer request"),
            }
        }
        let bytes = bincode::serialize(&Response::Transfer(Ok(TransferReply::Chunk(
            payload.clone(),
        ))))?;
        assert!(bytes.len() <= payload.len() + 32);
        let Response::Transfer(Ok(TransferReply::Chunk(decoded))) = bincode::deserialize(&bytes)?
        else {
            anyhow::bail!("unexpected decoded transfer response");
        };
        assert_eq!(decoded, payload);
        Ok(())
    }
}
