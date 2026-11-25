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

#[cfg(feature = "dist-client")]
pub use self::client::Client;
#[cfg(feature = "dist-server")]
pub use self::server::Server;
#[cfg(feature = "dist-server")]
pub use self::server::{
    ClientAuthCheck, ClientVisibleMsg, HEARTBEAT_TIMEOUT, Scheduler, ServerAuthCheck,
};

pub(crate) mod transport;
#[cfg(feature = "dist-client")]
mod worker_routes;

mod common {
    use reqwest::header;
    use serde::{Deserialize, Serialize};
    #[cfg(all(test, feature = "dist-server"))]
    use {crate::util::BASE64_URL_SAFE_ENGINE, base64::Engine};

    use crate::dist;
    use crate::errors::{Context, Result};

    // Note that content-length is necessary due to https://github.com/tiny-http/tiny-http/issues/147
    pub trait ReqwestRequestBuilderExt: Sized {
        fn bincode<T: serde::Serialize + ?Sized>(self, bincode: &T) -> Result<Self>;
        fn bytes(self, bytes: Vec<u8>) -> Self;
    }
    impl ReqwestRequestBuilderExt for reqwest::blocking::RequestBuilder {
        fn bincode<T: serde::Serialize + ?Sized>(self, bincode: &T) -> Result<Self> {
            let bytes =
                bincode::serialize(bincode).context("Failed to serialize body to bincode")?;
            Ok(self.bytes(bytes))
        }
        fn bytes(self, bytes: Vec<u8>) -> Self {
            self.header(
                header::CONTENT_TYPE,
                mime::APPLICATION_OCTET_STREAM.to_string(),
            )
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(bytes)
        }
    }
    impl ReqwestRequestBuilderExt for reqwest::RequestBuilder {
        fn bincode<T: serde::Serialize + ?Sized>(self, bincode: &T) -> Result<Self> {
            let bytes =
                bincode::serialize(bincode).context("Failed to serialize body to bincode")?;
            Ok(self.bytes(bytes))
        }
        fn bytes(self, bytes: Vec<u8>) -> Self {
            self.header(
                header::CONTENT_TYPE,
                mime::APPLICATION_OCTET_STREAM.to_string(),
            )
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(bytes)
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub enum AllocJobHttpResponse {
        Success {
            job_alloc: dist::JobAlloc,
            need_toolchain: bool,
            routes: sccache_peer_identity::RouteSet,
        },
        Fail {
            msg: String,
        },
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct WorkerRouteHttpResponse {
        pub routes: sccache_peer_identity::RouteSet,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct WorkerNameHttpResponse {
        pub worker_name: Option<String>,
    }

    #[cfg(feature = "dist-server")]
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HeartbeatServerHttpRequest {
        pub jwt_key: Vec<u8>,
        pub cpu_capacity: f64,
        // Executing jobs and pending jobs receiving bytes from a client.
        pub active_job_ids: Vec<dist::JobId>,
        pub native_placement: Option<dist::NativePlacement>,
        pub server_nonce: dist::ServerNonce,
        pub routes: sccache_peer_identity::RouteSet,
    }

    #[cfg(feature = "dist-server")]
    #[derive(Serialize, Deserialize)]
    pub struct HeartbeatReply {
        pub result: dist::HeartbeatServerResult,
        pub revoked: Vec<sccache_peer_identity::PeerId>,
    }

    #[cfg(feature = "dist-server")]
    impl std::fmt::Debug for HeartbeatServerHttpRequest {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HeartbeatServerHttpRequest")
                .field("cpu_capacity", &self.cpu_capacity)
                .field("active_job_ids", &self.active_job_ids)
                .field("native_placement_present", &self.native_placement.is_some())
                .field("server_nonce", &self.server_nonce)
                .field("routes", &self.routes)
                // JWT signing key is deliberately not logged.
                .finish_non_exhaustive()
        }
    }
    #[cfg(all(test, feature = "dist-server"))]
    mod tests {
        use super::*;

        #[test]
        fn heartbeat_debug_redacts_jwt_signing_key() {
            let jwt_key = b"jwt-signing-secret".to_vec();
            let encoded_secret = BASE64_URL_SAFE_ENGINE.encode(&jwt_key);
            let heartbeat = HeartbeatServerHttpRequest {
                jwt_key,
                cpu_capacity: 4.0,
                active_job_ids: Vec::new(),
                native_placement: None,
                server_nonce: dist::ServerNonce::new(),
                routes: sccache_peer_identity::RouteSet::new(
                    "127.0.0.1:10501".parse().unwrap(),
                    [],
                ),
            };
            let debug = format!("{heartbeat:?}");
            assert!(!debug.contains(&encoded_secret));
            assert!(!debug.contains("jwt-signing-secret"));
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RunJobHttpRequest {
        pub command: dist::CompileCommand,
        pub outputs: dist::OutputRequest,
    }
}

pub mod urls {
    use crate::dist::{JobId, ServerId};
    use crate::errors::Result;

    /// Build the scheduler allocation endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if `scheduler_url` cannot be used as a base URL.
    pub fn scheduler_alloc_job(scheduler_url: &reqwest::Url) -> Result<reqwest::Url> {
        Ok(scheduler_url.join("/api/v1/scheduler/alloc_job")?)
    }

    /// Build the scheduler certificate endpoint for `server_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if `scheduler_url` cannot be used as a base URL.
    pub fn scheduler_worker_route(
        scheduler_url: &reqwest::Url,
        server_id: ServerId,
    ) -> Result<reqwest::Url> {
        Ok(scheduler_url.join(&format!("/api/v1/scheduler/worker_route/{server_id}"))?)
    }

    /// Build the scheduler worker-name lookup endpoint for `server_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if `scheduler_url` cannot be used as a base URL.
    pub fn scheduler_worker_name(
        scheduler_url: &reqwest::Url,
        server_id: ServerId,
    ) -> Result<reqwest::Url> {
        Ok(scheduler_url.join(&format!("/api/v1/scheduler/worker_name/{server_id}"))?)
    }

    /// Build the scheduler heartbeat endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if `scheduler_url` cannot be used as a base URL.
    pub fn scheduler_heartbeat_server(scheduler_url: &reqwest::Url) -> Result<reqwest::Url> {
        Ok(scheduler_url.join("/api/v4/scheduler/heartbeat_server")?)
    }

    /// Build the scheduler job-state endpoint for `job_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if `scheduler_url` cannot be used as a base URL.
    pub fn scheduler_job_state(
        scheduler_url: &reqwest::Url,
        job_id: JobId,
    ) -> Result<reqwest::Url> {
        Ok(scheduler_url.join(&format!("/api/v1/scheduler/job_state/{job_id}"))?)
    }

    /// Build the scheduler status endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if `scheduler_url` cannot be used as a base URL.
    pub fn scheduler_status(scheduler_url: &reqwest::Url) -> Result<reqwest::Url> {
        Ok(scheduler_url.join("/api/v1/scheduler/status")?)
    }

    /// Build the worker assignment endpoint.
    ///
    /// # Errors
    /// Returns an error if the worker origin is not a valid base URL.
    pub fn server_assign_job(base: &reqwest::Url, job_id: JobId) -> Result<reqwest::Url> {
        Ok(base.join(&format!("/api/v1/distserver/assign_job/{job_id}"))?)
    }
    /// Build the worker native assignment endpoint.
    ///
    /// # Errors
    /// Returns an error if the worker origin is not a valid base URL.
    pub fn server_assign_native_job(base: &reqwest::Url, job_id: JobId) -> Result<reqwest::Url> {
        Ok(base.join(&format!("/api/v5/distserver/assign_native_job/{job_id}"))?)
    }
    /// Build the worker peer blob endpoint.
    ///
    /// # Errors
    /// Returns an error if the worker origin is not a valid base URL.
    pub fn server_native_blob(base: &reqwest::Url) -> Result<reqwest::Url> {
        Ok(base.join("/api/v3/distserver/native_blob")?)
    }
    /// Build the worker native execution endpoint.
    ///
    /// # Errors
    /// Returns an error if the worker origin is not a valid base URL.
    pub fn server_run_native_job(base: &reqwest::Url, job_id: JobId) -> Result<reqwest::Url> {
        Ok(base.join(&format!("/api/v5/distserver/run_native_job/{job_id}"))?)
    }
    /// Build the worker toolchain submission endpoint.
    ///
    /// # Errors
    /// Returns an error if the worker origin is not a valid base URL.
    pub fn server_submit_toolchain(base: &reqwest::Url, job_id: JobId) -> Result<reqwest::Url> {
        Ok(base.join(&format!("/api/v1/distserver/submit_toolchain/{job_id}"))?)
    }
    /// Build the worker archive execution endpoint.
    ///
    /// # Errors
    /// Returns an error if the worker origin is not a valid base URL.
    pub fn server_run_job(base: &reqwest::Url, job_id: JobId) -> Result<reqwest::Url> {
        Ok(base.join(&format!("/api/v2/distserver/run_job/{job_id}"))?)
    }
}

#[cfg(feature = "dist-server")]
mod server {
    use self::cluster_http::{Listener, ListenerRole, Request};
    use crate::dist::cluster::{BlockingRoutes, refresh_blocking};
    use crate::util::num_cpus;
    use byteorder::{BigEndian, ReadBytesExt};
    use rouille::accept;
    use sccache_cluster_identity::{
        ClusterCa, ClusterListener, EnrollmentAuthority, Identity, PeerCredentials, Registry, Role,
        SchedulerEnrollment, TlsCredentials,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, HashSet};
    use std::convert::Infallible;
    use std::io::Read;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::result::Result as StdResult;
    use std::sync::atomic;
    use std::sync::{Arc, LazyLock, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::common::{
        AllocJobHttpResponse, HeartbeatReply, HeartbeatServerHttpRequest, ReqwestRequestBuilderExt,
        RunJobHttpRequest, WorkerNameHttpResponse, WorkerRouteHttpResponse,
    };
    use super::transport::{self, send_blocking};
    use super::urls;
    use crate::build_runtime::{
        BlobRef, ContentId,
        wire::{ScheduleReply, WorkerAllocation},
    };
    use crate::dist::{
        self, AllocJobResult, AssignJobResult, HeartbeatServerResult, InputsReader, JobAssignment,
        JobAuthorizer, JobId, JobState, NativeAssignment, RunJobResult, SchedulerStatusResult,
        ServerId, ServerNonce, SubmitToolchainResult, ToolchainReader, UpdateJobStateResult,
    };
    use crate::errors::{Context, Result, anyhow};
    use crate::util::BASE64_URL_SAFE_ENGINE;
    use base64::Engine;
    use bincode::Options;

    mod cluster_http;
    mod native;

    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
    const HEARTBEAT_ERROR_INTERVAL: Duration = Duration::from_secs(10);
    pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);
    // Allocating a job is a control-plane operation, not a toolchain upload.
    // A hung worker must never permanently occupy a scheduler HTTP thread.
    const ASSIGN_JOB_TIMEOUT: Duration = Duration::from_secs(20);

    struct LoadAwareCapacity {
        previous_cpu_times: Option<(u64, u64)>,
        idle_fraction: f64,
    }

    impl LoadAwareCapacity {
        fn new() -> Self {
            Self {
                previous_cpu_times: read_cpu_times(),
                idle_fraction: 1.0,
            }
        }

        fn advertised_cpus(&mut self, running_jobs: usize) -> f64 {
            if let Some(current) = read_cpu_times()
                && let Some(previous) = self.previous_cpu_times.replace(current)
                && let Some(idle_fraction) = idle_fraction(previous, current)
            {
                self.idle_fraction = idle_fraction;
            }
            effective_cpu_capacity(num_cpus(), self.idle_fraction, running_jobs)
        }
    }

    fn idle_fraction(previous: (u64, u64), current: (u64, u64)) -> Option<f64> {
        let total = current.0.checked_sub(previous.0)?;
        let idle = current.1.checked_sub(previous.1)?;
        (total != 0 && idle <= total).then_some(idle as f64 / total as f64)
    }

    fn effective_cpu_capacity(cpus: usize, idle_fraction: f64, running_jobs: usize) -> f64 {
        // The measured idle CPUs exclude our own executing jobs. Restore those
        // before the scheduler subtracts all of its outstanding reservations.
        (cpus as f64 * idle_fraction + running_jobs as f64).min(cpus as f64)
    }

    #[cfg(target_os = "linux")]
    fn read_cpu_times() -> Option<(u64, u64)> {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let mut fields = stat.lines().next()?.split_whitespace();
        (fields.next()? == "cpu").then_some(())?;
        let values = fields
            .take(8)
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .ok()?;
        (values.len() == 8).then_some(())?;
        Some((values.iter().sum(), values[3].saturating_add(values[4])))
    }

    #[cfg(target_os = "freebsd")]
    fn read_cpu_times() -> Option<(u64, u64)> {
        let output = std::process::Command::new("/sbin/sysctl")
            .args(["-n", "kern.cp_time"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let values = std::str::from_utf8(&output.stdout)
            .ok()?
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .ok()?;
        (values.len() == 5).then_some(())?;
        Some((values.iter().sum(), values[4]))
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    fn read_cpu_times() -> Option<(u64, u64)> {
        None
    }

    #[cfg(test)]
    mod capacity_tests {
        use super::*;

        #[test]
        fn capacity_tracks_idle_and_running_jobs() {
            assert_eq!(idle_fraction((100, 20), (200, 45)), Some(0.25));
            assert_eq!(idle_fraction((100, 20), (100, 20)), None);
            assert_eq!(idle_fraction((100, 20), (90, 21)), None);
            assert_eq!(effective_cpu_capacity(8, 0.25, 0), 2.0);
            assert_eq!(effective_cpu_capacity(8, 0.25, 3), 5.0);
            assert_eq!(effective_cpu_capacity(8, 0.0, 0), 0.0);
            assert_eq!(effective_cpu_capacity(8, 0.0, 20), 8.0);
            assert_eq!(effective_cpu_capacity(8, 0.0625, 0), 0.5);
        }
    }

    // The running set has one owner for both load-advertisement and scheduler
    // reconciliation. A guard clears its ID even if a build request unwinds.
    struct RunningJobGuard {
        jobs: Arc<Mutex<HashSet<JobId>>>,
        job_id: JobId,
    }
    impl RunningJobGuard {
        fn new(jobs: &Arc<Mutex<HashSet<JobId>>>, job_id: JobId) -> Result<Self> {
            let mut active = jobs
                .lock()
                .map_err(|_| anyhow!("running jobs mutex poisoned"))?;
            if !active.insert(job_id) {
                return Err(anyhow!("job {job_id} is already running"));
            }
            drop(active);
            Ok(Self {
                jobs: Arc::clone(jobs),
                job_id,
            })
        }
    }
    impl Drop for RunningJobGuard {
        fn drop(&mut self) {
            // Never leak a running entry if a different thread poisoned the lock.
            let mut jobs = self.jobs.lock().unwrap_or_else(|error| error.into_inner());
            jobs.remove(&self.job_id);
        }
    }

    #[cfg(test)]
    #[test]
    fn running_job_guard_tracks_exact_ownership_and_rejects_duplicates() -> Result<()> {
        let active = Arc::new(Mutex::new(HashSet::<JobId>::new()));
        let first = RunningJobGuard::new(&active, JobId(5))?;
        let second = RunningJobGuard::new(&active, JobId(6))?;
        assert!(RunningJobGuard::new(&active, JobId(5)).is_err());
        assert_eq!(active.lock().unwrap().len(), 2);
        drop(first);
        assert_eq!(
            active.lock().unwrap().iter().copied().collect::<Vec<_>>(),
            vec![JobId(6)]
        );
        drop(second);
        assert!(active.lock().unwrap().is_empty());
        Ok(())
    }

    // A pending assignment must survive a genuinely progressing archive upload,
    // but a connected client that stops sending bytes must not hold a slot.
    type UploadActivity = Arc<Mutex<HashMap<JobId, Instant>>>;

    struct ProgressReader<R> {
        inner: R,
        activity: UploadActivity,
        job_id: JobId,
    }

    impl<R: Read> ProgressReader<R> {
        fn new(inner: R, activity: &UploadActivity, job_id: JobId) -> Result<Self> {
            let mut uploads = activity
                .lock()
                .map_err(|_| anyhow!("upload activity mutex poisoned"))?;
            match uploads.entry(job_id) {
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err(anyhow!("job {job_id} already has an active upload"));
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(Instant::now());
                }
            }
            drop(uploads);
            Ok(Self {
                inner,
                activity: Arc::clone(activity),
                job_id,
            })
        }
    }

    impl<R: Read> Read for ProgressReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let bytes = self.inner.read(buffer)?;
            if bytes != 0 {
                let mut uploads = self
                    .activity
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if let Some(last_progress) = uploads.get_mut(&self.job_id) {
                    *last_progress = Instant::now();
                }
            }
            Ok(bytes)
        }
    }

    impl<R> Drop for ProgressReader<R> {
        fn drop(&mut self) {
            self.activity
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&self.job_id);
        }
    }

    fn recently_progressing_uploads(activity: &UploadActivity, now: Instant) -> Vec<JobId> {
        let uploads = activity.lock().unwrap_or_else(|error| error.into_inner());
        uploads
            .iter()
            .filter_map(|(&job, &progress)| {
                (now.saturating_duration_since(progress) < HEARTBEAT_TIMEOUT).then_some(job)
            })
            .collect()
    }

    #[cfg(test)]
    #[test]
    fn upload_activity_requires_recent_byte_progress() -> Result<()> {
        let activity = UploadActivity::default();
        let job = JobId(42);
        let mut reader = ProgressReader::new(std::io::Cursor::new(b"archive"), &activity, job)?;
        assert!(ProgressReader::new(std::io::empty(), &activity, job).is_err());
        let now = Instant::now();
        activity
            .lock()
            .unwrap()
            .insert(job, now.checked_sub(HEARTBEAT_TIMEOUT).unwrap());
        assert!(recently_progressing_uploads(&activity, now).is_empty());
        let mut bytes = [0; 3];
        reader.read_exact(&mut bytes)?;
        assert_eq!(&bytes, b"arc");
        assert_eq!(
            recently_progressing_uploads(&activity, Instant::now()),
            vec![job]
        );
        drop(reader);
        assert!(activity.lock().unwrap().is_empty());
        Ok(())
    }

    struct SafeRequest<'a>(&'a Request);

    impl std::fmt::Debug for SafeRequest<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Request")
                .field("method", &self.0.method())
                .field("url", &self.0.url())
                .field("remote_addr", &self.0.remote_addr())
                .finish()
        }
    }

    // Messages that are non-sensitive and can be sent to the client
    #[derive(Debug)]
    pub struct ClientVisibleMsg(String);
    impl ClientVisibleMsg {
        pub fn from_nonsensitive(s: String) -> Self {
            ClientVisibleMsg(s)
        }
    }

    pub trait ClientAuthCheck: Send + Sync {
        fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg>;
    }
    type ServerAuthenticator = dyn Fn(&str) -> Option<ServerId> + Send + Sync;
    pub type ServerAuthCheck = Box<ServerAuthenticator>;

    const JWT_KEY_LENGTH: usize = 256 / 8;
    static JWT_HEADER: LazyLock<jwt::Header> =
        LazyLock::new(|| jwt::Header::new(jwt::Algorithm::HS256));
    static JWT_VALIDATION: LazyLock<jwt::Validation> = LazyLock::new(|| {
        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
        validation.leeway = 0;
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation
    });

    // Based on rouille::input::json::json_input
    #[derive(Debug)]
    pub enum RouilleBincodeError {
        BodyAlreadyExtracted,
        WrongContentType,
        BodyTooLarge,
        BodyReadError(std::io::Error),
        ParseError(bincode::Error),
    }
    impl From<bincode::Error> for RouilleBincodeError {
        fn from(err: bincode::Error) -> RouilleBincodeError {
            RouilleBincodeError::ParseError(err)
        }
    }
    impl std::error::Error for RouilleBincodeError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match *self {
                RouilleBincodeError::ParseError(ref e) => Some(e),
                RouilleBincodeError::BodyReadError(ref e) => Some(e),
                _ => None,
            }
        }
    }
    impl std::fmt::Display for RouilleBincodeError {
        fn fmt(
            &self,
            fmt: &mut std::fmt::Formatter<'_>,
        ) -> std::result::Result<(), std::fmt::Error> {
            write!(
                fmt,
                "{}",
                match *self {
                    RouilleBincodeError::BodyAlreadyExtracted => {
                        "the body of the request was already extracted"
                    }
                    RouilleBincodeError::WrongContentType => {
                        "the request didn't have a binary content type"
                    }
                    RouilleBincodeError::BodyTooLarge => "control-plane request body exceeds limit",
                    RouilleBincodeError::BodyReadError(_) =>
                        "error reading control-plane request body",
                    RouilleBincodeError::ParseError(_) => "error while parsing the bincode body",
                }
            )
        }
    }
    fn bincode_input<O>(request: &Request) -> std::result::Result<O, RouilleBincodeError>
    where
        O: serde::de::DeserializeOwned,
    {
        if let Some(header) = request.header("Content-Type") {
            if !header.starts_with("application/octet-stream") {
                return Err(RouilleBincodeError::WrongContentType);
            }
        } else {
            return Err(RouilleBincodeError::WrongContentType);
        }

        let mut body = request
            .data()
            .ok_or(RouilleBincodeError::BodyAlreadyExtracted)?;
        let bytes = transport::read_bounded(&mut body, transport::CONTROL_REQUEST_LIMIT).map_err(
            |error| match error {
                transport::BoundedReadError::TooLarge => RouilleBincodeError::BodyTooLarge,
                transport::BoundedReadError::Io(error) => RouilleBincodeError::BodyReadError(error),
            },
        )?;
        transport::decode_bincode(&bytes).map_err(From::from)
    }

    // Based on try_or_400 in rouille, but with logging
    #[derive(Serialize)]
    pub struct ErrJson {
        description: String,
        cause: Option<Box<ErrJson>>,
    }

    impl ErrJson {
        fn from_err<E: ?Sized + std::error::Error>(err: &E) -> ErrJson {
            let cause = err.source().map(ErrJson::from_err).map(Box::new);
            ErrJson {
                description: err.to_string(),
                cause,
            }
        }

        fn into_data(self) -> String {
            match serde_json::to_string(&self) {
                Ok(data) => data,
                Err(error) => format!("failed to serialize authentication error: {error}"),
            }
        }
    }
    macro_rules! try_or_err_and_log {
        ($reqid:expr, $code:expr, $result:expr) => {
            match $result {
                Ok(r) => r,
                Err(err) => {
                    // TODO: would ideally just use error_chain
                    let err: Box<dyn std::error::Error + 'static> = err.into();
                    let mut err_msg = err.to_string();
                    let mut maybe_cause = std::error::Error::source(&*err);
                    while let Some(cause) = maybe_cause {
                        err_msg.push_str(", caused by: ");
                        err_msg.push_str(&cause.to_string());
                        maybe_cause = std::error::Error::source(cause);
                    }

                    warn!("Res {} error: {}", $reqid, err_msg);
                    let json = ErrJson::from_err(&*err);
                    return rouille::Response::json(&json).with_status_code($code);
                }
            }
        };
    }
    macro_rules! try_or_400_log {
        ($reqid:expr, $result:expr) => {
            try_or_err_and_log!($reqid, 400, $result)
        };
    }
    macro_rules! try_bincode_input {
        ($reqid:expr, $request:expr) => {{
            match bincode_input($request) {
                Ok(value) => value,
                Err(error) => {
                    let status = if matches!(error, RouilleBincodeError::BodyTooLarge) {
                        413
                    } else {
                        400
                    };
                    warn!("Res {} error: {}", $reqid, error);
                    return rouille::Response::json(&ErrJson::from_err(&error))
                        .with_status_code(status);
                }
            }
        }};
    }

    macro_rules! try_or_500_log {
        ($reqid:expr, $result:expr) => {
            try_or_err_and_log!($reqid, 500, $result)
        };
    }
    fn make_401_with_body(short_err: &str, body: ClientVisibleMsg) -> rouille::Response {
        rouille::Response {
            status_code: 401,
            headers: vec![(
                "WWW-Authenticate".into(),
                format!("Bearer error=\"{}\"", short_err).into(),
            )],
            data: rouille::ResponseBody::from_data(body.0),
            upgrade: None,
        }
    }
    fn make_401(short_err: &str) -> rouille::Response {
        make_401_with_body(short_err, ClientVisibleMsg(String::new()))
    }
    fn bearer_http_auth(request: &Request) -> Option<&str> {
        let header = request.header("Authorization")?;

        let mut split = header.splitn(2, ' ');

        let authtype = split.next()?;
        if authtype != "Bearer" {
            return None;
        }

        split.next()
    }

    fn authenticate_client(request: &Request) -> StdResult<(), rouille::Response> {
        if request.role() != Role::Client {
            return Err(make_401("client_role_required"));
        }
        Ok(())
    }

    fn authenticate_server(request: &Request) -> StdResult<ServerId, rouille::Response> {
        if request.role() != Role::Worker {
            return Err(make_401("worker_role_required"));
        }
        Ok(request.id())
    }

    /// Return `content` as a bincode-encoded `Response`.
    pub fn bincode_response<T>(content: &T) -> rouille::Response
    where
        T: serde::Serialize,
    {
        let data = bincode::serialize(content).context("Failed to serialize response body");
        let data = try_or_500_log!("bincode body serialization", data);

        rouille::Response {
            status_code: 200,
            headers: vec![
                ("Content-Type".into(), "application/octet-stream".into()),
                ("Content-Length".into(), data.len().to_string().into()),
            ],
            data: rouille::ResponseBody::from_data(data),
            upgrade: None,
        }
    }

    /// Return `content` as either a bincode or json encoded `Response`
    /// depending on the Accept header in `request`.
    fn prepare_response<T>(request: &Request, content: &T) -> rouille::Response
    where
        T: serde::Serialize,
    {
        accept!(request,
        "application/octet-stream" => bincode_response(content),
        "application/json" => rouille::Response::json(content),
        )
    }

    // Verification of job auth in a request
    macro_rules! job_auth_or_401 {
        ($request:ident, $job_authorizer:expr, $job_id:expr) => {{
            let verify_result = match bearer_http_auth($request) {
                Some(token) => $job_authorizer.verify_token($job_id, token),
                None => Err(anyhow!("no Authorization header")),
            };
            match verify_result {
                Ok(()) => (),
                Err(err) => {
                    let err: Box<dyn std::error::Error> = err.into();
                    let json = ErrJson::from_err(&*err);
                    return make_401_with_body("invalid_jwt", ClientVisibleMsg(json.into_data()));
                }
            }
        }};
    }

    #[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct JobJwt {
        pub exp: u64,
        pub job_id: dist::JobId,
    }

    // Separate claim schema: a job token cannot authorize a peer blob
    // lookup, and a blob token authorizes only the exact digest and length.
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BlobJwt {
        exp: u64,
        blob: BlobRef,
    }

    static BLOB_JWT_VALIDATION: LazyLock<jwt::Validation> = LazyLock::new(|| {
        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
        validation.leeway = 0;
        validation
    });

    // Generation and verification of worker capabilities
    struct JWTJobAuthorizer {
        encoding_key: jwt::EncodingKey,
        decoding_key: jwt::DecodingKey,
    }
    impl JWTJobAuthorizer {
        fn boxed(server_key: &[u8]) -> Result<Box<Self>> {
            anyhow::ensure!(
                server_key.len() == JWT_KEY_LENGTH,
                "Invalid job JWT key length"
            );
            Ok(Box::new(Self {
                encoding_key: jwt::EncodingKey::from_secret(server_key)
                    .context("Invalid job JWT signing key")?,
                decoding_key: jwt::DecodingKey::from_secret(server_key)
                    .context("Invalid job JWT verification key")?,
            }))
        }
    }
    impl dist::JobAuthorizer for JWTJobAuthorizer {
        fn generate_token(&self, job_id: JobId) -> Result<String> {
            let claims = JobJwt { exp: 0, job_id };
            jwt::encode(&JWT_HEADER, &claims, &self.encoding_key)
                .map_err(|e| anyhow!("Failed to create JWT for job: {}", e))
        }
        fn verify_token(&self, job_id: JobId, token: &str) -> Result<()> {
            let valid_claims = JobJwt { exp: 0, job_id };
            jwt::decode(token, &self.decoding_key, &JWT_VALIDATION)
                .map_err(|e| anyhow!("JWT decode failed: {}", e))
                .and_then(|res| {
                    fn identical_t<T>(_: &T, _: &T) {}
                    identical_t(&res.claims, &valid_claims);
                    if res.claims == valid_claims {
                        Ok(())
                    } else {
                        Err(anyhow!("mismatched claims"))
                    }
                })
        }

        fn generate_blob_token(&self, blob: BlobRef) -> Result<String> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let exp = now
                .checked_add(60)
                .context("peer capability deadline overflow")?;
            Ok(jwt::encode(
                &JWT_HEADER,
                &BlobJwt { exp, blob },
                &self.encoding_key,
            )?)
        }

        fn verify_blob_token(&self, blob: BlobRef, token: &str) -> Result<()> {
            let claims =
                jwt::decode::<BlobJwt>(token, &self.decoding_key, &BLOB_JWT_VALIDATION)?.claims;
            anyhow::ensure!(claims.blob == blob, "mismatched peer blob capability");
            Ok(())
        }
    }

    #[test]
    fn peer_blob_token_is_exact_and_distinct_from_job_token() -> Result<()> {
        let authorizer = JWTJobAuthorizer::boxed(&[3; JWT_KEY_LENGTH])?;
        let blob = BlobRef {
            id: ContentId::of(b"data"),
            size: 4,
        };
        let token = authorizer.generate_blob_token(blob)?;
        authorizer.verify_blob_token(blob, &token)?;
        assert!(
            authorizer
                .verify_blob_token(BlobRef { size: 5, ..blob }, &token)
                .is_err()
        );
        assert!(
            authorizer
                .verify_blob_token(
                    BlobRef {
                        id: ContentId::of(b"else"),
                        ..blob
                    },
                    &token
                )
                .is_err()
        );
        let job = JobId(17);
        assert!(authorizer.verify_token(job, &token).is_err());
        assert!(
            authorizer
                .verify_blob_token(blob, &authorizer.generate_token(job)?)
                .is_err()
        );
        let expired = jwt::encode(
            &JWT_HEADER,
            &BlobJwt { exp: 1, blob },
            &authorizer.encoding_key,
        )?;
        assert!(authorizer.verify_blob_token(blob, &expired).is_err());
        Ok(())
    }

    #[test]
    fn test_job_token_verification() -> Result<()> {
        let ja = JWTJobAuthorizer::boxed(&[2; JWT_KEY_LENGTH])?;

        let job_id = JobId(55);
        let token = ja.generate_token(job_id)?;

        let job_id2 = JobId(56);
        let token2 = ja.generate_token(job_id2)?;

        let ja2 = JWTJobAuthorizer::boxed(&[3; JWT_KEY_LENGTH])?;

        assert!(JWTJobAuthorizer::boxed(&[]).is_err());
        assert!(JWTJobAuthorizer::boxed(&[1; JWT_KEY_LENGTH - 1]).is_err());
        // Check tokens are deterministic
        assert_eq!(token, ja.generate_token(job_id)?);
        // Check token verification works
        assert!(ja.verify_token(job_id, &token).is_ok());
        assert!(ja.verify_token(job_id, &token2).is_err());
        assert!(ja.verify_token(job_id2, &token).is_err());
        assert!(ja.verify_token(job_id2, &token2).is_ok());
        // Check token verification with a different key fails
        assert!(ja2.verify_token(job_id, &token).is_err());
        assert!(ja2.verify_token(job_id2, &token2).is_err());
        Ok(())
    }

    pub struct Scheduler<S> {
        cluster_directory: PathBuf,
        public_addr: SocketAddr,
        handler: S,
        // Is this client permitted to use the scheduler?
        check_client_auth: Box<dyn ClientAuthCheck>,
        // Do we believe the server is who they appear to be?
        check_server_auth: ServerAuthCheck,
        native_cache: Option<crate::config::scheduler::NativeCacheConfig>,
    }

    impl<S: dist::SchedulerIncoming + 'static> Scheduler<S> {
        pub fn new(
            cluster_directory: PathBuf,
            public_addr: SocketAddr,
            handler: S,
            check_client_auth: Box<dyn ClientAuthCheck>,
            check_server_auth: ServerAuthCheck,
            native_cache: Option<crate::config::scheduler::NativeCacheConfig>,
        ) -> Self {
            Self {
                cluster_directory,
                public_addr,
                handler,
                check_client_auth,
                check_server_auth,
                native_cache,
            }
        }

        pub fn start(self) -> Result<Infallible> {
            let Self {
                cluster_directory,
                public_addr,
                handler,
                check_client_auth,
                check_server_auth,
                native_cache,
            } = self;
            anyhow::ensure!(
                cluster_directory.is_absolute(),
                "scheduler cluster directory must be absolute"
            );
            std::fs::create_dir_all(&cluster_directory)?;
            let authority = EnrollmentAuthority::new(
                ClusterCa::open(&cluster_directory.join("ca-key.pem"))?,
                Registry::open(&cluster_directory.join("registry.bin"))?,
                7,
            )?;
            let scheduler_key = cluster_directory.join("key.pem");
            let identity = Identity::open(&scheduler_key)?;
            let scheduler_id = identity.id()?;
            let leaf = authority.scheduler_certificate(&identity)?;
            sccache_cluster_identity::publish_trust_anchor(
                authority.certificate(),
                &cluster_directory.join("ca.pem"),
            )?;
            info!(
                "Cluster scheduler identity {scheduler_id}, trust anchor {}",
                cluster_directory.join("ca.pem").display()
            );
            let credential = Arc::new(TlsCredentials::new(
                identity,
                leaf,
                authority.certificate().clone(),
                Role::Scheduler,
            )?);
            let tls = Arc::new(ClusterListener::new(&credential)?);
            let native_tls = native_cache
                .as_ref()
                .map(|_| ClusterListener::new_data(&credential).map(Arc::new))
                .transpose()?;
            let current = Arc::new(Mutex::new(credential));
            let outbound = Arc::clone(&current);
            let requester = Arc::new(SchedulerRequester {
                routes: Arc::new(BlockingRoutes::new(move || {
                    outbound
                        .lock()
                        .map(|leaf| Arc::clone(&leaf))
                        .map_err(|_| anyhow!("scheduler credentials poisoned"))
                })),
                addresses: Mutex::default(),
            });
            let handler = Arc::new(handler);
            let enrollment = Arc::new(SchedulerEnrollment::new(
                authority,
                move |role, id, _, token| match role {
                    Role::Client => check_client_auth.check(token).is_ok(),
                    Role::Worker => check_server_auth(token) == Some(id),
                    Role::Scheduler => false,
                },
            ));
            let renewal_enrollment = Arc::clone(&enrollment);
            let renewal_tls = Arc::clone(&tls);
            let renewal_native_tls = native_tls.clone();
            thread::Builder::new()
                .name("scheduler-certificate-renewal".into())
                .spawn(move || {
                    loop {
                        thread::sleep(Duration::from_hours(1));
                        let renew = || -> Result<()> {
                            let mut active = current
                                .lock()
                                .map_err(|_| anyhow!("scheduler credentials poisoned"))?;
                            if active.renewal_due(Duration::from_hours(24))? {
                                let identity = Identity::open(&scheduler_key)?;
                                let authority = renewal_enrollment.authority();
                                let leaf = authority.scheduler_certificate(&identity)?;
                                let next = Arc::new(TlsCredentials::new(
                                    identity,
                                    leaf,
                                    authority.certificate().clone(),
                                    Role::Scheduler,
                                )?);
                                renewal_tls.reload(&next)?;
                                if let Some(tls) = &renewal_native_tls {
                                    tls.reload(&next)?;
                                }
                                *active = next;
                            }
                            Ok(())
                        };
                        if let Err(error) = renew() {
                            warn!("Scheduler certificate renewal failed: {error:#}");
                        }
                    }
                })?;
            let native_endpoint = if let Some(config) = native_cache {
                let handler = Arc::clone(&handler);
                let requester = Arc::clone(&requester);
                let allocation_routes = Arc::clone(&requester);
                let peer_handler = Arc::clone(&handler);
                let result_handler = Arc::clone(&handler);
                let peer_routes = Arc::clone(&requester);
                let network = Arc::new(crate::build_runtime::NetworkMeter::default());
                let peer_network = Arc::clone(&network);
                let bound = native::spawn(
                    &config,
                    move |assignment, snapshot, packages| match handler.handle_alloc_native_job(
                        &*requester,
                        assignment,
                        snapshot,
                        packages,
                    )? {
                        AllocJobResult::Success {
                            job_alloc,
                            need_toolchain,
                        } => {
                            anyhow::ensure!(!need_toolchain, "native allocation requested archive");
                            Ok(ScheduleReply::Assigned(WorkerAllocation {
                                peer: job_alloc.server_id,
                                routes: allocation_routes.addresses(job_alloc.server_id)?,
                                job: job_alloc.job_id.0,
                                auth: job_alloc.auth,
                            }))
                        }
                        AllocJobResult::Fail { msg } => {
                            Ok(ScheduleReply::Unavailable { message: msg })
                        }
                    },
                    move |blob, requester, store, deadline| {
                        for source in peer_handler.native_blob_sources(blob, requester)? {
                            if std::time::Instant::now() >= deadline {
                                break;
                            }
                            match native::fetch_peer(
                                &peer_routes,
                                source,
                                blob,
                                &peer_network,
                                deadline,
                            ) {
                                Ok(Some((reader, encoding))) => match store
                                    .stage_expected_physical(blob, encoding, reader)
                                {
                                    Ok(staged) => return Ok(Some(staged)),
                                    Err(error) => debug!("native peer content rejected: {error:#}"),
                                },
                                Ok(None) => {}
                                Err(error) => debug!("native peer lookup failed: {error:#}"),
                            }
                        }
                        Ok(None)
                    },
                    move |server, job, event| {
                        result_handler.observe_native_lifecycle(server, job, event)
                    },
                    native_tls.context("missing native data TLS listener")?,
                    Arc::clone(&enrollment),
                    network,
                )?;
                Some((config.public_addr, bound))
            } else {
                None
            };

            macro_rules! check_server_auth_or_err {
                ($request:ident) => {{
                    match authenticate_server($request) {
                        Ok(server_id) => server_id,
                        Err(response) => return response,
                    }
                }};
            }

            info!("Scheduler listening for clients on {}", public_addr);
            let request_count = atomic::AtomicUsize::new(0);

            let registry = Arc::clone(&enrollment);
            let server = Listener::bind(
                public_addr,
                tls,
                ListenerRole::Scheduler(enrollment),
                num_cpus() * 8,
                move |request| {
                    let req_id = request_count.fetch_add(1, atomic::Ordering::Relaxed);
                    trace!(target: "sccache_http", "Req {}: {:?}", req_id, SafeRequest(request));
                    let response = (|| {
                        router!(request,
                            (POST) (/api/v1/scheduler/alloc_job) => {
                                if let Err(response) = authenticate_client(request) {
                                    return response;
                                }
                                let toolchain = try_bincode_input!(req_id, request);
                                trace!("Req {}: alloc_job: {:?}", req_id, toolchain);

                                let alloc_job_res: AllocJobResult = try_or_500_log!(req_id, handler.handle_alloc_job(&*requester, toolchain));
                                let res = match alloc_job_res {
                                    AllocJobResult::Success { job_alloc, need_toolchain } => {
                                        let routes = try_or_500_log!(req_id, requester.addresses(job_alloc.server_id));
                                        AllocJobHttpResponse::Success { job_alloc, need_toolchain, routes }
                                    }
                                    AllocJobResult::Fail { msg } => AllocJobHttpResponse::Fail { msg }
                                };
                                prepare_response(request, &res)
                            },
                            (GET) (/api/v1/scheduler/native_routes) => {
                                if let Some((primary, bind)) = native_endpoint {
                                    let routes = crate::dist::cluster_routes::discover(primary, bind);
                                    prepare_response(request, &WorkerRouteHttpResponse { routes })
                                } else {
                                    rouille::Response::empty_404()
                                }
                            },
                            (GET) (/api/v1/scheduler/worker_route/{server_id: ServerId}) => {
                                if let Err(response) = authenticate_client(request) { return response; }
                                let routes = try_or_500_log!(req_id, requester.addresses(server_id));
                                prepare_response(request, &WorkerRouteHttpResponse { routes })
                            },
                            (GET) (/api/v1/scheduler/worker_name/{server_id: ServerId}) => {
                                if let Err(response) = authenticate_client(request) {
                                    return response;
                                }
                                let worker_name = try_or_500_log!(
                                    req_id,
                                    handler.handle_get_worker_name(server_id)
                                );
                                prepare_response(request, &WorkerNameHttpResponse { worker_name })
                            },
                            (POST) (/api/v4/scheduler/heartbeat_server) => {
                                let server_id = check_server_auth_or_err!(request);
                                let worker_name = request
                                    .header("X-Sccache-Worker-Name")
                                    .map(ToOwned::to_owned);
                                let native_platform = try_or_400_log!(req_id, request.header("X-Sccache-Native-Platform").map(|value| -> Result<ContentId> {
                                    let bytes = BASE64_URL_SAFE_ENGINE.decode(value)?;
                                    Ok(ContentId(bytes.try_into().map_err(|_| anyhow!("invalid native platform digest"))?))
                                }).transpose());
                                let archive = match request.header("X-Sccache-Archive-Worker") {
                                    None | Some("true") => true,
                                    Some("false") => false,
                                    _ => return rouille::Response::empty_400(),
                                };
                                let heartbeat_server = try_bincode_input!(req_id, request);

                                trace!(target: "sccache_heartbeat", "Req {}: heartbeat_server: {:?}", req_id, heartbeat_server);

                                let HeartbeatServerHttpRequest {
                                    cpu_capacity, active_job_ids, native_placement, jwt_key,
                                    server_nonce, routes,
                                } = heartbeat_server;
                                let job_authorizer = try_or_400_log!(req_id, JWTJobAuthorizer::boxed(&jwt_key));
                                try_or_400_log!(req_id, requester.register(server_id, routes));
                                let worker_name_nonce = server_nonce.clone();
                                let res: HeartbeatServerResult = try_or_500_log!(req_id, handler.handle_heartbeat_server(
                                    server_id, server_nonce,
                                    cpu_capacity, &active_job_ids,
                                    job_authorizer, dist::WorkerCapabilities {
                                        archive, native_platform, native_placement,
                                    }
                                ));
                                if let Some(worker_name) = worker_name
                                    && let Err(error) = handler.handle_update_worker_name(
                                        server_id,
                                        worker_name_nonce,
                                        worker_name,
                                    )
                                {
                                    // Display metadata must never take a healthy worker offline.
                                    warn!("Could not register display name for {server_id:?}: {error:#}");
                                }
                                let revoked = try_or_500_log!(req_id, registry.authority().registry().revoked());
                                prepare_response(request, &HeartbeatReply { result: res, revoked })
                            },
                            (POST) (/api/v1/scheduler/job_state/{job_id: JobId}) => {
                                let server_id = check_server_auth_or_err!(request);
                                let job_state = try_bincode_input!(req_id, request);
                                trace!("Req {}: job state: {:?}", req_id, job_state);

                                let res: UpdateJobStateResult = try_or_500_log!(req_id, handler.handle_update_job_state(
                                    job_id, server_id, job_state
                                ));
                                prepare_response(request, &res)
                            },
                            (GET) (/api/v1/scheduler/status) => {
                                let res: SchedulerStatusResult = try_or_500_log!(req_id, handler.handle_status());
                                prepare_response(request, &res)
                            },
                            (GET) (/api/v1/scheduler/drain_status) => {
                                let draining = u8::from(handler.handle_is_draining());
                                rouille::Response::text(format!("{draining}\n"))
                            },
                            _ => {
                                warn!("Unknown request {:?}", SafeRequest(request));
                                rouille::Response::empty_404()
                            },
                        )
                    })();
                    trace!(target: "sccache_http", "Res {}: {:?}", req_id, response);
                    response
                },
            )?;
            server.run()?;
            Err(anyhow!("scheduler HTTPS listener terminated"))
        }
    }

    pub(super) struct SchedulerRequester {
        routes: Arc<BlockingRoutes>,
        addresses: Mutex<HashMap<ServerId, (sccache_peer_identity::RouteSet, Instant)>>,
    }

    impl SchedulerRequester {
        fn register(&self, id: ServerId, routes: sccache_peer_identity::RouteSet) -> Result<()> {
            anyhow::ensure!(routes.valid(), "invalid worker endpoints");
            let mut addresses = self
                .addresses
                .lock()
                .map_err(|_| anyhow!("worker routes poisoned"))?;
            addresses.retain(|_, (_, updated)| updated.elapsed() < HEARTBEAT_TIMEOUT);
            addresses.insert(id, (routes.clone(), Instant::now()));
            drop(addresses);
            self.routes.prime(id, Role::Worker, &routes);
            Ok(())
        }

        fn addresses(&self, id: ServerId) -> Result<sccache_peer_identity::RouteSet> {
            self.addresses
                .lock()
                .map_err(|_| anyhow!("worker routes poisoned"))?
                .get(&id)
                .filter(|(_, updated)| updated.elapsed() < HEARTBEAT_TIMEOUT)
                .map(|(routes, _)| routes.clone())
                .context("worker route unavailable")
        }

        fn endpoints(&self, id: ServerId) -> Result<Vec<SocketAddr>> {
            Ok(self.routes.ordered(id, Role::Worker, &self.addresses(id)?))
        }

        fn download_endpoints(&self, id: ServerId, size: u64) -> Result<Vec<SocketAddr>> {
            Ok(self.routes.ordered_transfer(
                id,
                Role::Worker,
                &self.addresses(id)?,
                crate::dist::cluster_routes::Transfer::Download(size),
            ))
        }

        fn endpoint(
            &self,
            id: ServerId,
            address: SocketAddr,
        ) -> Result<(reqwest::blocking::Client, reqwest::Url)> {
            self.routes.endpoint(id, Role::Worker, address)
        }

        fn failed(&self, id: ServerId, address: SocketAddr) {
            self.routes.failed(id, Role::Worker, address);
        }
    }

    impl dist::SchedulerOutgoing for SchedulerRequester {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            assignment: JobAssignment,
            auth: String,
        ) -> Result<AssignJobResult> {
            let mut last_error = None;
            for address in self.endpoints(server_id)? {
                let (client, base) = self.endpoint(server_id, address)?;
                let url = match &assignment {
                    JobAssignment::Archive(_) => urls::server_assign_job(&base, job_id)?,
                    JobAssignment::Native(_) => urls::server_assign_native_job(&base, job_id)?,
                };
                let req = client
                    .post(url)
                    .bearer_auth(&auth)
                    .timeout(ASSIGN_JOB_TIMEOUT);
                let req = match &assignment {
                    JobAssignment::Archive(tc) => req.bincode(tc)?,
                    JobAssignment::Native(assignment) => req
                        .header("Content-Type", "application/octet-stream")
                        .body(crate::dist::native::codec().serialize(&**assignment)?),
                };
                match send_blocking(req) {
                    Err(error)
                        if error
                            .downcast_ref::<reqwest::Error>()
                            .is_some_and(reqwest::Error::is_connect) =>
                    {
                        self.failed(server_id, address);
                        last_error = Some(error);
                    }
                    result => return result.context("POST to worker assignment failed"),
                }
            }
            Err(last_error.unwrap_or_else(|| anyhow!("worker has no route")))
        }
    }

    pub struct Server<S> {
        public_addr: SocketAddr,
        bind_address: Option<SocketAddr>,
        peer: Arc<PeerCredentials>,
        jwt_key: Vec<u8>,
        server_nonce: ServerNonce,
        worker_name: Option<String>,
        handler: S,
    }

    impl<S: dist::ServerIncoming + 'static> Server<S> {
        pub fn new(
            public_addr: SocketAddr,
            bind_address: Option<SocketAddr>,
            peer: Arc<PeerCredentials>,
            worker_name: Option<String>,
            handler: S,
        ) -> Result<Self> {
            if let Some(name) = &worker_name {
                reqwest::header::HeaderValue::from_str(name).context("invalid worker name")?;
            }
            let mut jwt_key = vec![0; JWT_KEY_LENGTH];
            rand::fill(&mut jwt_key);
            let server_nonce = ServerNonce::new();

            Ok(Self {
                public_addr,
                bind_address,
                peer,
                jwt_key,
                server_nonce,
                worker_name,
                handler,
            })
        }

        pub fn start(self) -> Result<Infallible> {
            let Self {
                public_addr,
                bind_address,
                peer,
                jwt_key,
                server_nonce,
                worker_name,
                handler,
            } = self;
            let socket = cluster_http::bind_data_socket(public_addr, bind_address)?;
            let bind_address = socket.local_addr()?;
            let mut load_aware_capacity = LoadAwareCapacity::new();
            let handler = Arc::new(handler);
            let heartbeat_handler = Arc::clone(&handler);
            let running_jobs = Arc::new(Mutex::new(HashSet::<JobId>::new()));
            let heartbeat_running_jobs = Arc::clone(&running_jobs);
            let upload_activity = UploadActivity::default();
            let heartbeat_upload_activity = Arc::clone(&upload_activity);
            let heartbeat_jwt_key = jwt_key.clone();
            let job_authorizer = JWTJobAuthorizer::boxed(&jwt_key)?;
            let credentials = peer.current()?;
            let tls = Arc::new(ClusterListener::new(&credentials)?);
            let scheduler_id = peer.scheduler_id();
            let requester = Arc::new(ServerRequester {
                routes: BlockingRoutes::for_peer(Arc::clone(&peer)),
                peer: Arc::clone(&peer),
            });
            let heartbeat_requester = Arc::clone(&requester);
            let heartbeat_tls = Arc::clone(&tls);
            let revocations = Arc::new(cluster_http::Revocations::default());
            let heartbeat_revocations = Arc::clone(&revocations);
            thread::spawn(move || {
                let mut last_renewal = Instant::now();
                let mut active = credentials;
                thread::sleep(Duration::from_millis(250));
                loop {
                    // A new assignment can arrive after this request starts but
                    // before its response. Never prune that assignment.
                    let heartbeat_started_at = Instant::now();
                    trace!(target: "sccache_heartbeat", "Performing heartbeat");
                    let running_job_ids: Vec<_> = heartbeat_running_jobs
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .iter()
                        .copied()
                        .collect();
                    let advertised_cpus =
                        load_aware_capacity.advertised_cpus(heartbeat_handler.executing_jobs());
                    let capabilities = heartbeat_handler.capabilities();
                    // Transfers keep their assignment alive, but do not count as
                    // executing compiler processes for CPU-capacity restoration.
                    let active_job_ids =
                        running_job_ids
                            .into_iter()
                            .chain(capabilities.native_placement.iter().flat_map(|placement| {
                                placement.queue.jobs.iter().filter_map(|(&id, progress)| {
                                    progress.phase.active().then_some(id)
                                })
                            }))
                            .chain(recently_progressing_uploads(
                                &heartbeat_upload_activity,
                                Instant::now(),
                            ))
                            .collect::<HashSet<_>>()
                            .into_iter()
                            .collect();
                    let heartbeat_req = HeartbeatServerHttpRequest {
                        cpu_capacity: advertised_cpus,
                        active_job_ids,
                        native_placement: capabilities.native_placement,
                        jwt_key: heartbeat_jwt_key.clone(),
                        server_nonce: server_nonce.clone(),
                        routes: crate::dist::cluster_routes::discover(public_addr, bind_address),
                    };
                    if last_renewal.elapsed() >= Duration::from_hours(1) {
                        last_renewal = Instant::now();
                        match refresh_blocking(&peer) {
                            Ok(next) if !Arc::ptr_eq(&active, &next) => {
                                if let Err(error) = heartbeat_tls.reload(&next) {
                                    warn!("Worker TLS reload failed: {error:#}");
                                } else {
                                    active = next;
                                }
                            }
                            Ok(_) => {}
                            Err(error) => warn!("Worker certificate renewal failed: {error:#}"),
                        }
                    }
                    let heartbeat_result = (|| -> Result<HeartbeatReply> {
                        let (client, base) = heartbeat_requester.endpoint()?;
                        let mut heartbeat_request = client
                            .post(urls::scheduler_heartbeat_server(&base)?)
                            // A stalled scheduler must not permanently stop heartbeats.
                            .timeout(HEARTBEAT_INTERVAL);
                        if let Some(worker_name) = worker_name.as_ref() {
                            heartbeat_request =
                                heartbeat_request.header("X-Sccache-Worker-Name", worker_name);
                        }
                        heartbeat_request = heartbeat_request.header(
                            "X-Sccache-Archive-Worker",
                            if capabilities.archive {
                                "true"
                            } else {
                                "false"
                            },
                        );
                        if let Some(platform) = capabilities.native_platform {
                            heartbeat_request = heartbeat_request.header(
                                "X-Sccache-Native-Platform",
                                BASE64_URL_SAFE_ENGINE.encode(platform.0),
                            );
                        }
                        heartbeat_request
                            .bincode(&heartbeat_req)
                            .and_then(send_blocking)
                    })();
                    match heartbeat_result {
                        Ok(HeartbeatReply {
                            result:
                                HeartbeatServerResult {
                                    is_new,
                                    assigned_job_ids,
                                },
                            revoked,
                        }) => {
                            heartbeat_revocations.update(revoked);
                            trace!(target: "sccache_heartbeat", "Heartbeat success is_new={}", is_new);
                            match heartbeat_handler.handle_reconcile_assignments(
                                &assigned_job_ids,
                                heartbeat_started_at,
                            ) {
                                Ok(removed) if removed > 0 => {
                                    info!("Reconciled {removed} stale worker assignments");
                                }
                                Err(error) => {
                                    warn!("Unable to reconcile worker assignments: {error:#}");
                                }
                                _ => {}
                            }
                            // TODO: if is_new, terminate all running jobs
                            if is_new {
                                info!("Server connected to scheduler");
                            }
                            thread::sleep(HEARTBEAT_INTERVAL);
                        }
                        Err(e) => {
                            error!(target: "sccache_heartbeat", "Failed to send heartbeat to server: {}", e);
                            thread::sleep(HEARTBEAT_ERROR_INTERVAL);
                        }
                    }
                }
            });

            info!("Server listening for clients on {}", bind_address);
            let request_count = atomic::AtomicUsize::new(0);

            let server = Listener::from_socket(
                socket,
                tls,
                ListenerRole::Worker {
                    scheduler: scheduler_id,
                    revocations,
                },
                num_cpus() * 8,
                move |request| {
                    let req_id = request_count.fetch_add(1, atomic::Ordering::Relaxed);
                    trace!("Req {}: {:?}", req_id, SafeRequest(request));
                    let response = (|| {
                        router!(request,
                            (POST) (/api/v1/distserver/assign_job/{job_id: JobId}) => {
                                if request.role() != Role::Scheduler { return make_401("scheduler_role_required"); }
                                job_auth_or_401!(request, &job_authorizer, job_id);
                                let toolchain = try_bincode_input!(req_id, request);
                                trace!("Req {}: assign_job({}): {:?}", req_id, job_id, toolchain);

                                let res: AssignJobResult = try_or_500_log!(req_id, handler.handle_assign_job(job_id, toolchain));
                                prepare_response(request, &res)
                            },
                            (POST) (/api/v5/distserver/assign_native_job/{job_id: JobId}) => {
                                if request.role() != Role::Scheduler { return make_401("scheduler_role_required"); }
                                job_auth_or_401!(request, &job_authorizer, job_id);
                                let limit = try_or_400_log!(req_id, handler.native_metadata_limit().context("native worker disabled"));
                                let assignment: NativeAssignment = try_or_400_log!(req_id, native::metadata(request, limit));
                                let res = try_or_500_log!(req_id, handler.handle_assign_native_job(requester.clone(), job_id, assignment));
                                prepare_response(request, &res)
                            },
                            (POST) (/api/v3/distserver/native_blob) => {
                                if request.role() == Role::Client { return make_401("peer_role_required"); }
                                let blob: BlobRef = try_or_400_log!(req_id, native::metadata(request, 40));
                                let Some(token) = bearer_http_auth(request) else {
                                    return rouille::Response::text("invalid peer capability").with_status_code(401);
                                };
                                if job_authorizer.verify_blob_token(blob, token).is_err() {
                                    return rouille::Response::text("invalid peer capability").with_status_code(401);
                                }
                                let file = try_or_500_log!(req_id, handler.handle_native_blob(blob));
                                match file {
                                    Some((file, encoding)) => try_or_500_log!(req_id, native::physical_blob_response(file, encoding)),
                                    None => rouille::Response::empty_404(),
                                }
                            },
                            (POST) (/api/v5/distserver/run_native_job/{job_id: JobId}) => {
                                if request.role() != Role::Client { return make_401("client_role_required"); }
                                job_auth_or_401!(request, &job_authorizer, job_id);
                                let operation: crate::build_runtime::wire::NativeRunRequest = try_or_400_log!(req_id, native::metadata(request, 16));
                                let res = try_or_500_log!(req_id, handler.handle_run_native_job(job_id, operation));
                                let data = try_or_500_log!(req_id, crate::dist::native::codec().serialize(&res));
                                rouille::Response::from_data("application/octet-stream", data)
                            },
                            (POST) (/api/v1/distserver/submit_toolchain/{job_id: JobId}) => {
                                if request.role() != Role::Client { return make_401("client_role_required"); }
                                job_auth_or_401!(request, &job_authorizer, job_id);
                                trace!("Req {}: submit_toolchain({})", req_id, job_id);

                                let body = try_or_400_log!(
                                    req_id,
                                    request
                                        .data()
                                        .context("missing submit_toolchain request body")
                                );
                                let progress = try_or_500_log!(req_id, ProgressReader::new(body, &upload_activity, job_id));
                                let toolchain_rdr = ToolchainReader(Box::new(progress));
                                let res: SubmitToolchainResult = try_or_500_log!(req_id, handler.handle_submit_toolchain(requester.as_ref(), job_id, toolchain_rdr));
                                prepare_response(request, &res)
                            },
                            (POST) (/api/v2/distserver/run_job/{job_id: JobId}) => {
                                if request.role() != Role::Client { return make_401("client_role_required"); }
                                job_auth_or_401!(request, &job_authorizer, job_id);

                                let mut body = try_or_400_log!(
                                    req_id,
                                    request.data().context("missing run_job request body")
                                );
                                let bincode_length = try_or_500_log!(req_id, body.read_u32::<BigEndian>()
                                    .context("failed to read run job input length")) as u64;

                                let mut bincode_reader = body.take(bincode_length);
                                let runjob = try_or_500_log!(req_id, bincode::deserialize_from(&mut bincode_reader)
                                    .context("failed to deserialize run job request"));
                                trace!("Req {}: run_job({}): {:?}", req_id, job_id, runjob);
                                let RunJobHttpRequest { command, outputs } = runjob;
                                let body = bincode_reader.into_inner();
                                let inputs_rdr = InputsReader::new(Box::new(body));

                                let _running_job = try_or_500_log!(req_id, RunningJobGuard::new(&running_jobs, job_id));
                                let res: RunJobResult = try_or_500_log!(req_id, handler.handle_run_job(requester.as_ref(), job_id, command, outputs, inputs_rdr));
                                prepare_response(request, &res)
                            },
                            _ => {
                                warn!("Unknown request {:?}", SafeRequest(request));
                                rouille::Response::empty_404()
                            },
                        )
                    })();
                    trace!("Res {}: {:?}", req_id, response);
                    response
                },
            )?;
            server.run()?;
            Err(anyhow!("worker HTTPS listener terminated"))
        }
    }

    struct ServerRequester {
        routes: BlockingRoutes,
        peer: Arc<PeerCredentials>,
    }

    impl ServerRequester {
        fn endpoint(&self) -> Result<(reqwest::blocking::Client, reqwest::Url)> {
            self.routes.endpoint(
                self.peer.scheduler_id(),
                Role::Scheduler,
                self.peer.scheduler_address(),
            )
        }
    }

    impl dist::ServerOutgoing for ServerRequester {
        fn do_update_job_state(
            &self,
            job_id: JobId,
            state: JobState,
        ) -> Result<UpdateJobStateResult> {
            let publish = || {
                let (client, base) = self.endpoint()?;
                let url = urls::scheduler_job_state(&base, job_id)?;
                send_blocking(
                    client
                        .post(url)
                        // Never retain an execution slot forever on a stalled ACK.
                        .timeout(HEARTBEAT_TIMEOUT)
                        .bincode(&state)?,
                )
            };
            // A lost response may follow a successful scheduler transition.
            // The scheduler accepts repeated state updates and terminal acks.
            publish().or_else(|first_error| {
                warn!(
                    "Retrying job {job_id} state {state} after scheduler response failure: {first_error:#}"
                );
                publish().with_context(|| {
                    format!("POST to scheduler job_state failed; first attempt: {first_error:#}")
                })
            })
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::{Ipv4Addr, SocketAddrV4};

        fn request_from(ip: Ipv4Addr, headers: Vec<(String, String)>) -> Request {
            Request::fake_http_from(
                SocketAddr::V4(SocketAddrV4::new(ip, 12345)),
                "POST",
                "/api/test?access_token=query-secret",
                headers,
                Vec::new(),
            )
        }

        #[test]
        fn inbound_control_bincode_is_bounded() {
            let headers = vec![(
                "Content-Type".to_owned(),
                "application/octet-stream".to_owned(),
            )];
            let good = Request::fake_http_from(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
                "POST",
                "/api/test",
                headers.clone(),
                bincode::serialize(&123_u64).expect("serialize control value"),
            );
            assert_eq!(bincode_input::<u64>(&good).expect("decode valid body"), 123);

            let oversized = Request::fake_http_from(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
                "POST",
                "/api/test",
                headers,
                vec![0; transport::CONTROL_REQUEST_LIMIT + 1],
            );
            assert!(matches!(
                bincode_input::<u64>(&oversized),
                Err(RouilleBincodeError::BodyTooLarge)
            ));
        }

        #[test]
        fn safe_request_debug_excludes_headers_and_query() {
            let request = request_from(
                Ipv4Addr::LOCALHOST,
                vec![(
                    "Authorization".to_owned(),
                    "Bearer header-secret".to_owned(),
                )],
            );
            let debug = format!("{:?}", SafeRequest(&request));
            assert!(debug.contains("/api/test"));
            assert!(!debug.contains("header-secret"));
            assert!(!debug.contains("query-secret"));
        }
    }
}

#[cfg(feature = "dist-client")]
mod client {
    use super::super::cache;
    use crate::config;
    use crate::dist::pkg::{InputsPackager, ToolchainPackager};
    use crate::dist::{
        self, AllocJobResult, CompileCommand, JobAlloc, RunJobResult, SchedulerStatusResult,
        ServerId, SubmitToolchainResult, Toolchain,
    };

    use crate::compression::deflate::ZlibWriter;
    use async_trait::async_trait;
    use byteorder::{BigEndian, WriteBytesExt};
    use reqwest::Body;
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::common::{
        AllocJobHttpResponse, ReqwestRequestBuilderExt, RunJobHttpRequest, WorkerNameHttpResponse,
    };
    use super::transport::{RequestClass, send_async};
    use super::urls;
    use super::worker_routes::WorkerRoutes;
    use crate::errors::{Context, Result};
    use sccache_cluster_identity::PeerCredentials;

    const WORKER_NAME_CACHE_TTL: Duration = Duration::from_secs(300);
    const WORKER_NAME_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

    type WorkerNameCache = HashMap<ServerId, (Option<String>, Instant)>;

    pub struct Client {
        worker_routes: WorkerRoutes,
        // server_id -> (optional display name, lookup time). Successful names are
        // stable for a server identity; negative/legacy results are retried later.
        server_names: Arc<Mutex<WorkerNameCache>>,
        pool: tokio::runtime::Handle,
        tc_cache: Arc<cache::ClientToolchains>,
        rewrite_includes_only: bool,
    }

    impl Client {
        /// Create a distributed-compilation HTTP client.
        ///
        /// # Errors
        ///
        /// Returns an error if the HTTP client or local toolchain cache cannot be initialized.
        pub fn new(
            pool: &tokio::runtime::Handle,
            peer: Arc<PeerCredentials>,
            cache_dir: &Path,
            cache_size: u64,
            toolchain_configs: &[config::DistToolchainConfig],
            rewrite_includes_only: bool,
        ) -> Result<Self> {
            let worker_routes = WorkerRoutes::new(peer);
            let client_toolchains =
                cache::ClientToolchains::new(cache_dir, cache_size, toolchain_configs)
                    .context("failed to initialise client toolchains")?;
            Ok(Self {
                worker_routes,
                server_names: Arc::default(),
                pool: pool.clone(),
                tc_cache: Arc::new(client_toolchains),
                rewrite_includes_only,
            })
        }
    }

    #[async_trait]
    impl dist::Client for Client {
        async fn do_alloc_job(&self, tc: Toolchain) -> Result<AllocJobResult> {
            let scheduler = self.worker_routes.control().await?;
            let url = urls::scheduler_alloc_job(scheduler.base())?;
            let req = scheduler.client().post(url).bincode(&tc)?;

            match send_async(req, RequestClass::Control).await? {
                AllocJobHttpResponse::Success {
                    job_alloc,
                    need_toolchain,
                    routes,
                } => {
                    self.worker_routes.allocation(job_alloc.server_id, routes)?;
                    Ok(AllocJobResult::Success {
                        job_alloc,
                        need_toolchain,
                    })
                }
                AllocJobHttpResponse::Fail { msg } => Ok(AllocJobResult::Fail { msg }),
            }
        }

        async fn worker_label(&self, server_id: ServerId) -> String {
            let fallback = server_id.to_string();
            {
                let Ok(names) = self.server_names.lock() else {
                    debug!("worker-name cache mutex poisoned; using {fallback}");
                    return fallback;
                };
                if let Some((worker_name, checked_at)) = names.get(&server_id) {
                    let ttl = if worker_name.is_some() {
                        WORKER_NAME_CACHE_TTL
                    } else {
                        WORKER_NAME_NEGATIVE_CACHE_TTL
                    };
                    if checked_at.elapsed() < ttl {
                        return worker_name.clone().unwrap_or(fallback);
                    }
                }
            }

            let scheduler = match self.worker_routes.control().await {
                Ok(scheduler) => scheduler,
                Err(error) => {
                    debug!("worker name control route unavailable: {error:#}");
                    return fallback;
                }
            };
            let url = match urls::scheduler_worker_name(scheduler.base(), server_id) {
                Ok(url) => url,
                Err(error) => {
                    debug!("could not build worker-name lookup URL: {error}");
                    return fallback;
                }
            };
            let req = scheduler.client().get(url);

            let checked_at = Instant::now();
            match send_async::<WorkerNameHttpResponse>(req, RequestClass::WorkerName).await {
                Ok(response) => {
                    let worker_name = response.worker_name;
                    if let Ok(mut names) = self.server_names.lock() {
                        names.insert(server_id, (worker_name.clone(), checked_at));
                    }
                    worker_name.unwrap_or(fallback)
                }
                Err(error) => {
                    // This is intentionally non-fatal: old schedulers do not expose
                    // the metadata endpoint. Cache the fallback briefly, then retry
                    // so a rolling scheduler upgrade converges without daemon restart.
                    trace!("worker-name lookup unavailable for {server_id:?}: {error}");
                    if let Ok(mut names) = self.server_names.lock() {
                        names.insert(server_id, (None, checked_at));
                    }
                    fallback
                }
            }
        }

        async fn do_get_status(&self) -> Result<SchedulerStatusResult> {
            let scheduler = self.worker_routes.control().await?;
            let url = urls::scheduler_status(scheduler.base())?;
            let req = scheduler.client().get(url);
            send_async(req, RequestClass::Control).await
        }

        async fn do_submit_toolchain(
            &self,
            job_alloc: JobAlloc,
            tc: Toolchain,
        ) -> Result<SubmitToolchainResult> {
            self.worker_routes
                .send(
                    job_alloc.server_id,
                    RequestClass::ToolchainUpload,
                    |client, base| {
                        let url = urls::server_submit_toolchain(base, job_alloc.job_id)?;
                        let toolchain_file = self
                            .tc_cache
                            .get_toolchain(&tc)?
                            .context("couldn't find toolchain locally")?;
                        let stream = tokio_util::io::ReaderStream::new(tokio::fs::File::from_std(
                            toolchain_file.into(),
                        ));
                        Ok(client
                            .post(url)
                            .bearer_auth(&job_alloc.auth)
                            .body(Body::wrap_stream(stream)))
                    },
                )
                .await
        }

        async fn do_run_job(
            &self,
            job_alloc: JobAlloc,
            command: CompileCommand,
            outputs: Vec<String>,
            inputs_packager: Box<dyn InputsPackager>,
        ) -> Result<RunJobResult> {
            crate::server::activity::phase(crate::server::activity::Phase::StageInputs);
            let body = self
                .pool
                .spawn_blocking(move || -> Result<_> {
                    let outputs = dist::OutputRequest {
                        paths: outputs,
                        compression_level: crate::compression::cache_level(),
                    };
                    let bincode = bincode::serialize(&RunJobHttpRequest { command, outputs })
                        .context("failed to serialize run job request")?;
                    let bincode_length = u32::try_from(bincode.len())
                        .context("run job request metadata exceeds the u32 wire-format limit")?;

                    let mut body = vec![];
                    body.write_u32::<BigEndian>(bincode_length)
                        .context("failed to encode run job request length")?;
                    body.write_all(&bincode)
                        .context("failed to encode run job request metadata")?;
                    {
                        let header_size = body.len();
                        let mut compressor = ZlibWriter::new(&mut body)?;
                        inputs_packager
                            .write_inputs(&mut compressor)
                            .context("Could not write inputs for compilation")?;
                        let input_size = compressor.total_in();
                        let body = compressor.finish().context("failed to finish compressor")?;
                        let compressed_size = body.len() - header_size;
                        trace!("Compressed inputs from {input_size} -> {compressed_size}");
                    }

                    Ok(body)
                })
                .await??;
            crate::server::activity::phase(crate::server::activity::Phase::RunDistributed);
            let body = bytes::Bytes::from(body);
            self.worker_routes
                .send(
                    job_alloc.server_id,
                    RequestClass::BuildResult,
                    |client, base| {
                        let url = urls::server_run_job(base, job_alloc.job_id)?;
                        Ok(client
                            .post(url)
                            .bearer_auth(&job_alloc.auth)
                            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                            .header(reqwest::header::CONTENT_LENGTH, body.len())
                            .body(body.clone()))
                    },
                )
                .await
        }

        async fn put_toolchain(
            &self,
            compiler_path: PathBuf,
            weak_key: String,
            toolchain_packager: Box<dyn ToolchainPackager>,
        ) -> Result<(Toolchain, Option<crate::dist::CustomToolchainOverride>)> {
            let compiler_path = compiler_path.clone();
            let weak_key = weak_key.clone();
            let tc_cache = self.tc_cache.clone();

            self.pool
                .spawn_blocking(move || {
                    tc_cache.put_toolchain(&compiler_path, &weak_key, toolchain_packager)
                })
                .await?
        }

        async fn lookup_namespace_toolchain(
            &self,
            compiler: PathBuf,
            key: String,
        ) -> Result<(Option<Toolchain>, u64)> {
            let cache = self.tc_cache.clone();
            self.pool
                .spawn_blocking(move || cache.lookup_namespace_toolchain(&compiler, &key))
                .await?
        }

        async fn import_namespace_toolchain(
            &self,
            compiler: PathBuf,
            key: String,
            package: std::fs::File,
        ) -> Result<Toolchain> {
            let cache = self.tc_cache.clone();
            self.pool
                .spawn_blocking(move || cache.import_namespace_toolchain(&compiler, &key, package))
                .await?
        }

        fn rewrite_includes_only(&self) -> bool {
            self.rewrite_includes_only
        }
        fn get_custom_toolchain(&self, exe: &Path) -> Option<PathBuf> {
            match self.tc_cache.get_custom_toolchain(exe) {
                Ok(Some((_, toolchain_override))) => Some(toolchain_override.archive),
                _ => None,
            }
        }
    }
}
