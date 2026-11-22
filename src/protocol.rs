use crate::cache::CacheMode;
use crate::compiler::ColorMode;
use crate::config::PreprocessorCacheModeConfig;
use crate::dist::{
    CompileCommand, JobId, SchedulerStatusResult, ServerId, SubmitToolchainResult, Toolchain,
};
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
}

/// Maximum application payload in a transfer frame. The framing envelope
/// stays well below the default 8 MiB IPC frame limit.
pub const TRANSFER_CHUNK_BYTES: usize = 1024 * 1024;
pub const NAMESPACE_PROTOCOL_VERSION: u32 = 3;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum StorageBlob {
    Cache,
    Preprocessor,
}

#[derive(Serialize, Deserialize)]
pub enum TransferRequest {
    Read {
        kind: StorageBlob,
        key: String,
    },
    BeginWrite {
        kind: StorageBlob,
        key: String,
        len: u64,
    },
    LookupToolchain {
        compiler: std::path::PathBuf,
        key: String,
    },
    BeginToolchain {
        compiler: std::path::PathBuf,
        key: String,
        len: u64,
    },
    Allocate {
        toolchain: Toolchain,
    },
    SubmitToolchain {
        job: JobId,
    },
    BeginRun {
        job: JobId,
        len: u64,
    },
    Status,
    WorkerLabel {
        server: ServerId,
    },
    WriteChunk(Vec<u8>),
    FinishWrite,
    ReadChunk,
    Abort,
}

#[derive(Serialize, Deserialize)]
pub enum TransferReply {
    ReadStarted(Option<u64>),
    WriteStarted,
    Chunk(Vec<u8>),
    Toolchain(Option<Toolchain>),
    Allocation {
        server: ServerId,
        job: JobId,
        need_toolchain: bool,
    },
    AllocationFailed(String),
    Submitted(SubmitToolchainResult),
    Status(SchedulerStatusResult),
    WorkerLabel(String),
    Ack,
}

// Transfer frames can carry complete object data; don't dump payload bytes
// or metadata such as filenames into diagnostics.
impl std::fmt::Debug for TransferRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Read { .. } => "Read",
            Self::BeginWrite { .. } => "BeginWrite",
            Self::LookupToolchain { .. } => "LookupToolchain",
            Self::BeginToolchain { .. } => "BeginToolchain",
            Self::Allocate { .. } => "Allocate",
            Self::SubmitToolchain { .. } => "SubmitToolchain",
            Self::BeginRun { .. } => "BeginRun",
            Self::Status => "Status",
            Self::WorkerLabel { .. } => "WorkerLabel",
            Self::WriteChunk(_) => "WriteChunk",
            Self::FinishWrite => "FinishWrite",
            Self::ReadChunk => "ReadChunk",
            Self::Abort => "Abort",
        };
        f.write_str(name)
    }
}

impl std::fmt::Debug for TransferReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadStarted(len) => f.debug_tuple("ReadStarted").field(len).finish(),
            Self::WriteStarted => f.write_str("WriteStarted"),
            Self::Chunk(bytes) => f.debug_tuple("Chunk").field(&bytes.len()).finish(),
            Self::Toolchain(_) => f.write_str("Toolchain"),
            Self::Allocation { .. } => f.write_str("Allocation"),
            Self::AllocationFailed(_) => f.write_str("AllocationFailed"),
            Self::Submitted(_) => f.write_str("Submitted"),
            Self::Status(_) => f.write_str("Status"),
            Self::WorkerLabel(_) => f.write_str("WorkerLabel"),
            Self::Ack => f.write_str("Ack"),
        }
    }
}

/// Serialized at the start of the input stream, followed by the raw input
/// archive. All of it is chunked, including unusually large argument vectors.
#[derive(Serialize, Deserialize)]
pub struct NamespaceRunSpec {
    pub command: CompileCommand,
    pub outputs: Vec<String>,
}

/// Possible responses from the server for a `Compile` request.
#[derive(Serialize, Deserialize, Debug)]
pub enum CompileResponse {
    /// The compilation was started.
    CompileStarted,
    /// The server could not handle this compilation request.
    UnhandledCompile,
    /// The compiler was not supported.
    UnsupportedCompiler(OsString),
}

/// Information about a finished compile, either from cache or executed locally.
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
}

/// The contents of a compile request from a client.
#[derive(Serialize, Deserialize, Debug)]
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

/// Cache metadata returned by the daemon on `StorageHandshake`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StorageHandshakeInfo {
    pub location: String,
    pub cache_type_name: String,
    pub basedirs: Vec<Vec<u8>>,
    pub preprocessor_cache_mode_config: PreprocessorCacheModeConfig,
    pub cache_mode: CacheMode,
    pub max_size: Option<u64>,
    pub namespace_protocol: u32,
    pub transfer_chunk_bytes: usize,
    pub dist_rewrite_includes_only: Option<bool>,
}
