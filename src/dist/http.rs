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

pub(crate) mod common {
    use reqwest::header;
    use serde::{Deserialize, Serialize};
    #[cfg(feature = "dist-server")]
    use {crate::util::BASE64_URL_SAFE_ENGINE, base64::Engine, std::collections::HashMap};

    use crate::dist;
    #[cfg(feature = "dist-client")]
    use crate::errors::HttpClientError;
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

    #[cfg(feature = "dist-client")]
    pub async fn bincode_req_fut<T: serde::de::DeserializeOwned + 'static>(
        req: reqwest::RequestBuilder,
    ) -> Result<T> {
        // Work around tiny_http issue #151 by disabling HTTP pipeline with
        // `Connection: close`.
        let res = req.header(header::CONNECTION, "close").send().await?;

        let status = res.status();
        let bytes = res.bytes().await?;
        if !status.is_success() {
            let errmsg = format!(
                "Error {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&bytes)
            );
            if status.is_client_error() {
                anyhow::bail!(HttpClientError(errmsg));
            }
            anyhow::bail!(errmsg);
        }
        Ok(bincode::deserialize(&bytes)?)
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub enum AllocJobHttpResponse {
        Success {
            job_alloc: dist::JobAlloc,
            need_toolchain: bool,
            cert_digest: Vec<u8>,
        },
        Fail {
            msg: String,
        },
    }
    impl AllocJobHttpResponse {
        #[cfg(feature = "dist-server")]
        pub fn from_alloc_job_result(
            res: dist::AllocJobResult,
            certs: &HashMap<dist::ServerId, (Vec<u8>, Vec<u8>)>,
        ) -> Self {
            match res {
                dist::AllocJobResult::Success {
                    job_alloc,
                    need_toolchain,
                } => {
                    if let Some((digest, _)) = certs.get(&job_alloc.server_id) {
                        AllocJobHttpResponse::Success {
                            job_alloc,
                            need_toolchain,
                            cert_digest: digest.to_owned(),
                        }
                    } else {
                        AllocJobHttpResponse::Fail {
                            msg: format!(
                                "missing certificates for server {}",
                                job_alloc.server_id.addr()
                            ),
                        }
                    }
                }
                dist::AllocJobResult::Fail { msg } => AllocJobHttpResponse::Fail { msg },
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ServerCertificateHttpResponse {
        pub cert_digest: Vec<u8>,
        pub cert_pem: Vec<u8>,
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
        pub server_nonce: dist::ServerNonce,
        pub cert_digest: Vec<u8>,
        pub cert_pem: Vec<u8>,
    }

    #[cfg(feature = "dist-server")]
    impl std::fmt::Debug for HeartbeatServerHttpRequest {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HeartbeatServerHttpRequest")
                .field("cpu_capacity", &self.cpu_capacity)
                .field("active_job_ids", &self.active_job_ids)
                .field("server_nonce", &self.server_nonce)
                .field(
                    "cert_digest",
                    &BASE64_URL_SAFE_ENGINE.encode(&self.cert_digest),
                )
                .finish()
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
                server_nonce: dist::ServerNonce::new(),
                cert_digest: vec![1, 2, 3],
                cert_pem: b"certificate".to_vec(),
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
    pub fn scheduler_server_certificate(
        scheduler_url: &reqwest::Url,
        server_id: ServerId,
    ) -> Result<reqwest::Url> {
        Ok(scheduler_url.join(&format!(
            "/api/v1/scheduler/server_certificate/{}",
            server_id.addr()
        ))?)
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
        Ok(scheduler_url.join(&format!(
            "/api/v1/scheduler/worker_name/{}",
            server_id.addr()
        ))?)
    }

    /// Build the scheduler heartbeat endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if `scheduler_url` cannot be used as a base URL.
    pub fn scheduler_heartbeat_server(scheduler_url: &reqwest::Url) -> Result<reqwest::Url> {
        Ok(scheduler_url.join("/api/v1/scheduler/heartbeat_server")?)
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

    /// Build the native server assignment endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the generated server URL is invalid.
    pub fn server_assign_native_job(server_id: ServerId, job_id: JobId) -> Result<reqwest::Url> {
        Ok(reqwest::Url::parse(&format!(
            "https://{}/api/v3/distserver/assign_native_job/{job_id}",
            server_id.addr()
        ))?)
    }

    /// Build the native job execution endpoint.
    ///
    /// # Errors
    /// Returns an error if the generated server URL is invalid.
    pub fn server_run_native_job(server_id: ServerId, job_id: JobId) -> Result<reqwest::Url> {
        Ok(reqwest::Url::parse(&format!(
            "https://{}/api/v3/distserver/run_native_job/{job_id}",
            server_id.addr()
        ))?)
    }

    /// Build the server archive assignment endpoint.
    ///
    /// # Errors
    /// Returns an error if the generated server URL is invalid.
    pub fn server_assign_job(server_id: ServerId, job_id: JobId) -> Result<reqwest::Url> {
        let url = format!(
            "https://{}/api/v1/distserver/assign_job/{job_id}",
            server_id.addr()
        );
        Ok(reqwest::Url::parse(&url)?)
    }

    /// Build the server toolchain-submission endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the generated server URL is invalid.
    pub fn server_submit_toolchain(server_id: ServerId, job_id: JobId) -> Result<reqwest::Url> {
        let url = format!(
            "https://{}/api/v1/distserver/submit_toolchain/{job_id}",
            server_id.addr()
        );
        Ok(reqwest::Url::parse(&url)?)
    }

    /// Build the server run-job endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the generated server URL is invalid.
    pub fn server_run_job(server_id: ServerId, job_id: JobId) -> Result<reqwest::Url> {
        let url = format!(
            "https://{}/api/v2/distserver/run_job/{job_id}",
            server_id.addr()
        );
        Ok(reqwest::Url::parse(&url)?)
    }
}

#[cfg(feature = "dist-server")]
mod server {
    use crate::util::{new_reqwest_blocking_client, num_cpus};
    use byteorder::{BigEndian, ReadBytesExt};
    use rouille::accept;
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, HashSet};
    use std::convert::Infallible;
    use std::io::Read;
    use std::net::{IpAddr, SocketAddr};
    use std::result::Result as StdResult;
    use std::sync::atomic;
    use std::sync::{Arc, LazyLock, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::common::{
        AllocJobHttpResponse, HeartbeatServerHttpRequest, ReqwestRequestBuilderExt,
        RunJobHttpRequest, ServerCertificateHttpResponse, WorkerNameHttpResponse,
    };
    use super::urls;
    use crate::build_runtime::{
        ContentId,
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

    mod native;

    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
    const HEARTBEAT_ERROR_INTERVAL: Duration = Duration::from_secs(10);
    pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

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

    struct SafeRequest<'a>(&'a rouille::Request);

    impl std::fmt::Debug for SafeRequest<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Request")
                .field("method", &self.0.method())
                .field("url", &self.0.url())
                .field("remote_addr", &self.0.remote_addr())
                .finish()
        }
    }

    fn request_origin_ip(request: &rouille::Request) -> Result<IpAddr> {
        let peer_ip = request.remote_addr().ip();
        if !peer_ip.is_loopback() {
            return Ok(peer_ip);
        }
        match request.header("X-Real-IP") {
            Some(value) => value
                .parse()
                .context("invalid X-Real-IP value from loopback proxy"),
            None => Ok(peer_ip),
        }
    }

    pub fn bincode_req<T: serde::de::DeserializeOwned + 'static>(
        req: reqwest::blocking::RequestBuilder,
    ) -> Result<T> {
        // Work around tiny_http issue #151 by disabling HTTP pipeline with
        // `Connection: close`.
        let mut res = req.header(reqwest::header::CONNECTION, "close").send()?;
        let status = res.status();
        let mut body = vec![];
        res.copy_to(&mut body)
            .context("error reading response body")?;
        if !status.is_success() {
            Err(anyhow!(
                "Error {} (Headers={:?}): {}",
                status.as_u16(),
                res.headers(),
                String::from_utf8_lossy(&body)
            ))
        } else {
            bincode::deserialize(&body).map_err(Into::into)
        }
    }

    fn create_https_cert_and_privkey(addr: SocketAddr) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let rsa_key = openssl::rsa::Rsa::<openssl::pkey::Private>::generate(2048)
            .context("failed to generate rsa privkey")?;
        let privkey_pem = rsa_key
            .private_key_to_pem()
            .context("failed to create pem from rsa privkey")?;
        let privkey: openssl::pkey::PKey<openssl::pkey::Private> =
            openssl::pkey::PKey::from_rsa(rsa_key)
                .context("failed to create openssl pkey from rsa privkey")?;
        let mut builder =
            openssl::x509::X509::builder().context("failed to create x509 builder")?;

        // Populate the certificate with the necessary parts, mostly from mkcert in openssl
        builder
            .set_version(2)
            .context("failed to set x509 version")?;
        let serial_number = openssl::bn::BigNum::from_u32(0)
            .and_then(|bn| bn.to_asn1_integer())
            .context("failed to create openssl asn1 0")?;
        builder
            .set_serial_number(serial_number.as_ref())
            .context("failed to set x509 serial number")?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)
            .context("failed to create openssl not before asn1")?;
        builder
            .set_not_before(not_before.as_ref())
            .context("failed to set not before on x509")?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(365)
            .context("failed to create openssl not after asn1")?;
        builder
            .set_not_after(not_after.as_ref())
            .context("failed to set not after on x509")?;
        builder
            .set_pubkey(privkey.as_ref())
            .context("failed to set pubkey for x509")?;

        let mut name = openssl::x509::X509Name::builder()?;
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, &addr.to_string())?;
        let name = name.build();

        builder
            .set_subject_name(&name)
            .context("failed to set subject name")?;
        builder
            .set_issuer_name(&name)
            .context("failed to set issuer name")?;

        // Add the SubjectAlternativeName
        let extension = openssl::x509::extension::SubjectAlternativeName::new()
            .ip(&addr.ip().to_string())
            .build(&builder.x509v3_context(None, None))
            .context("failed to build SAN extension for x509")?;
        builder
            .append_extension(extension)
            .context("failed to append SAN extension for x509")?;

        // Add ExtendedKeyUsage
        let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
            .server_auth()
            .build()
            .context("failed to build EKU extension for x509")?;
        builder
            .append_extension(ext_key_usage)
            .context("fails to append EKU extension for x509")?;

        // Finish the certificate
        builder
            .sign(&privkey, openssl::hash::MessageDigest::sha256())
            .context("failed to sign x509 with sha256")?;
        let cert: openssl::x509::X509 = builder.build();
        let cert_pem = cert.to_pem().context("failed to create pem from x509")?;
        let cert_digest = cert
            .digest(openssl::hash::MessageDigest::sha256())
            .context("failed to create digest of x509 certificate")?
            .as_ref()
            .to_owned();

        Ok((cert_digest, cert_pem, privkey_pem))
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
                    RouilleBincodeError::ParseError(_) => "error while parsing the bincode body",
                }
            )
        }
    }
    fn bincode_input<O>(request: &rouille::Request) -> std::result::Result<O, RouilleBincodeError>
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

        if let Some(mut b) = request.data() {
            bincode::deserialize_from::<_, O>(&mut b).map_err(From::from)
        } else {
            Err(RouilleBincodeError::BodyAlreadyExtracted)
        }
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
    fn bearer_http_auth(request: &rouille::Request) -> Option<&str> {
        let header = request.header("Authorization")?;

        let mut split = header.splitn(2, ' ');

        let authtype = split.next()?;
        if authtype != "Bearer" {
            return None;
        }

        split.next()
    }

    fn authenticate_client(
        request: &rouille::Request,
        check: &dyn ClientAuthCheck,
    ) -> StdResult<(), rouille::Response> {
        let token = bearer_http_auth(request).ok_or_else(|| make_401("no_bearer_auth"))?;
        check.check(token).map_err(|message| {
            warn!("Bearer auth failed: {message:?}");
            make_401_with_body("bearer_auth_failed", message)
        })
    }

    fn authenticate_server(
        request: &rouille::Request,
        check: &dyn Fn(&str) -> Option<ServerId>,
    ) -> StdResult<ServerId, rouille::Response> {
        let server_id = bearer_http_auth(request)
            .and_then(check)
            .ok_or_else(|| make_401("invalid_bearer_token"))?;
        let origin = request_origin_ip(request).map_err(|error| {
            warn!("Could not determine server origin IP: {error}");
            rouille::Response::empty_400()
        })?;
        if server_id.addr().ip() != origin {
            return Err(make_401("invalid_bearer_token_mismatched_address"));
        }
        Ok(server_id)
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
    pub fn prepare_response<T>(request: &rouille::Request, content: &T) -> rouille::Response
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

    // Generation and verification of job auth
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
            public_addr: SocketAddr,
            handler: S,
            check_client_auth: Box<dyn ClientAuthCheck>,
            check_server_auth: ServerAuthCheck,
            native_cache: Option<crate::config::scheduler::NativeCacheConfig>,
        ) -> Self {
            Self {
                public_addr,
                handler,
                check_client_auth,
                check_server_auth,
                native_cache,
            }
        }

        pub fn start(self) -> Result<Infallible> {
            let Self {
                public_addr,
                handler,
                check_client_auth,
                check_server_auth,
                native_cache,
            } = self;
            let requester = Arc::new(SchedulerRequester {
                client: Mutex::new(new_reqwest_blocking_client()?),
            });
            let server_certificates =
                Arc::new(Mutex::new(HashMap::<ServerId, (Vec<u8>, Vec<u8>)>::new()));

            let handler = Arc::new(handler);
            let check_client_auth: Arc<dyn ClientAuthCheck> = Arc::from(check_client_auth);
            let check_server_auth: Arc<ServerAuthenticator> = Arc::from(check_server_auth);
            if let Some(config) = native_cache {
                let handler = Arc::clone(&handler);
                let requester = Arc::clone(&requester);
                let certs = Arc::clone(&server_certificates);
                native::spawn(
                    &config,
                    move |assignment| match handler
                        .handle_alloc_native_job(&*requester, assignment)?
                    {
                        AllocJobResult::Success {
                            job_alloc,
                            need_toolchain,
                        } => {
                            anyhow::ensure!(!need_toolchain, "native allocation requested archive");
                            let certificate = certs
                                .lock()
                                .map_err(|_| anyhow!("server certificate mutex poisoned"))?
                                .get(&job_alloc.server_id)
                                .context("native worker certificate unavailable")?
                                .1
                                .clone();
                            Ok(ScheduleReply::Assigned(WorkerAllocation {
                                address: job_alloc.server_id.addr(),
                                job: job_alloc.job_id.0,
                                auth: job_alloc.auth,
                                certificate,
                            }))
                        }
                        AllocJobResult::Fail { msg } => {
                            Ok(ScheduleReply::Unavailable { message: msg })
                        }
                    },
                    Arc::clone(&check_client_auth),
                    Arc::clone(&check_server_auth),
                )?;
            }

            macro_rules! check_server_auth_or_err {
                ($request:ident) => {{
                    match authenticate_server($request, &*check_server_auth) {
                        Ok(server_id) => server_id,
                        Err(response) => return response,
                    }
                }};
            }

            fn maybe_update_certs(
                client: &mut reqwest::blocking::Client,
                certs: &mut HashMap<ServerId, (Vec<u8>, Vec<u8>)>,
                server_id: ServerId,
                cert_digest: Vec<u8>,
                cert_pem: Vec<u8>,
            ) -> Result<()> {
                if let Some((saved_cert_digest, _)) = certs.get(&server_id)
                    && saved_cert_digest == &cert_digest
                {
                    return Ok(());
                }
                info!(
                    "Adding new certificate for {} to scheduler",
                    server_id.addr()
                );
                let mut client_builder = reqwest::blocking::ClientBuilder::new();
                // Add all the certificates we know about
                client_builder = client_builder.add_root_certificate(
                    reqwest::Certificate::from_pem(&cert_pem)
                        .context("failed to interpret pem as certificate")?,
                );
                for (_, cert_pem) in certs.values() {
                    client_builder = client_builder.add_root_certificate(
                        reqwest::Certificate::from_pem(cert_pem)
                            .context("stored server certificate is no longer valid")?,
                    );
                }
                // Finish the client
                let new_client = client_builder
                    // Disable connection pool to avoid broken connection
                    // between runtime
                    .pool_max_idle_per_host(0)
                    .build()
                    .context("failed to create a HTTP client")?;
                // Use the updated certificates
                *client = new_client;
                certs.insert(server_id, (cert_digest, cert_pem));
                Ok(())
            }

            info!("Scheduler listening for clients on {}", public_addr);
            let request_count = atomic::AtomicUsize::new(0);
            // From server_id -> cert_digest, cert_pem

            let server = rouille::Server::new(public_addr, move |request| {
                let req_id = request_count.fetch_add(1, atomic::Ordering::Relaxed);
                trace!(target: "sccache_http", "Req {}: {:?}", req_id, SafeRequest(request));
                let response = (|| router!(request,
                    (POST) (/api/v1/scheduler/alloc_job) => {
                        if let Err(response) = authenticate_client(request, &*check_client_auth) {
                            return response;
                        }
                        let toolchain = try_or_400_log!(req_id, bincode_input(request));
                        trace!("Req {}: alloc_job: {:?}", req_id, toolchain);

                        let alloc_job_res: AllocJobResult = try_or_500_log!(req_id, handler.handle_alloc_job(&*requester, toolchain));
                        let certs = try_or_500_log!(
                            req_id,
                            server_certificates
                                .lock()
                                .map_err(|_| anyhow!("server certificate mutex poisoned"))
                        );
                        let res = AllocJobHttpResponse::from_alloc_job_result(alloc_job_res, &certs);
                        prepare_response(request, &res)
                    },
                    (GET) (/api/v1/scheduler/server_certificate/{server_id: ServerId}) => {
                        let certs = {
                            let guard = try_or_500_log!(
                                req_id,
                                server_certificates
                                    .lock()
                                    .map_err(|_| anyhow!("server certificate mutex poisoned"))
                            );
                            guard.get(&server_id).map(ToOwned::to_owned)
                        };

                        let (cert_digest, cert_pem) = try_or_500_log!(req_id, certs
                            .context("server cert not available"));
                        let res = ServerCertificateHttpResponse {
                            cert_digest,
                            cert_pem,
                        };
                        prepare_response(request, &res)
                    },
                    (GET) (/api/v1/scheduler/worker_name/{server_id: ServerId}) => {
                        if let Err(response) = authenticate_client(request, &*check_client_auth) {
                            return response;
                        }
                        let worker_name = try_or_500_log!(
                            req_id,
                            handler.handle_get_worker_name(server_id)
                        );
                        prepare_response(request, &WorkerNameHttpResponse { worker_name })
                    },
                    (POST) (/api/v1/scheduler/heartbeat_server) => {
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
                        let heartbeat_server = try_or_400_log!(req_id, bincode_input(request));
                        trace!(target: "sccache_heartbeat", "Req {}: heartbeat_server: {:?}", req_id, heartbeat_server);

                        let HeartbeatServerHttpRequest { cpu_capacity, active_job_ids, jwt_key, server_nonce, cert_digest, cert_pem } = heartbeat_server;
                        let job_authorizer = try_or_400_log!(req_id, JWTJobAuthorizer::boxed(&jwt_key));
                        let mut requester_client = try_or_500_log!(
                            req_id,
                            requester
                                .client
                                .lock()
                                .map_err(|_| anyhow!("scheduler HTTP client mutex poisoned"))
                        );
                        let mut certs = try_or_500_log!(
                            req_id,
                            server_certificates
                                .lock()
                                .map_err(|_| anyhow!("server certificate mutex poisoned"))
                        );
                        try_or_500_log!(req_id, maybe_update_certs(
                            &mut requester_client,
                            &mut certs,
                            server_id, cert_digest, cert_pem
                        ));
                        let worker_name_nonce = server_nonce.clone();
                        let res: HeartbeatServerResult = try_or_500_log!(req_id, handler.handle_heartbeat_server(
                            server_id, server_nonce,
                            cpu_capacity, &active_job_ids,
                            job_authorizer, dist::WorkerCapabilities { archive, native_platform }
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
                        prepare_response(request, &res)
                    },
                    (POST) (/api/v1/scheduler/job_state/{job_id: JobId}) => {
                        let server_id = check_server_auth_or_err!(request);
                        let job_state = try_or_400_log!(req_id, bincode_input(request));
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
                ))();
                 trace!(target: "sccache_http", "Res {}: {:?}", req_id, response);
                response
            }).map_err(|e| anyhow!("Failed to start http server for sccache scheduler: {e}"))?;

            // This limit is rouille's default for `start_server_with_pool`, which
            // we would use, except that interface doesn't permit any sort of
            // error handling to be done.
            let server = server.pool_size(num_cpus() * 8);
            server.run();

            Err(anyhow!("Rouille scheduler server terminated"))
        }
    }

    struct SchedulerRequester {
        client: Mutex<reqwest::blocking::Client>,
    }

    impl dist::SchedulerOutgoing for SchedulerRequester {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            assignment: JobAssignment,
            auth: String,
        ) -> Result<AssignJobResult> {
            let url = match &assignment {
                JobAssignment::Archive(_) => urls::server_assign_job(server_id, job_id)?,
                JobAssignment::Native(_) => urls::server_assign_native_job(server_id, job_id)?,
            };
            let req = {
                let client = self
                    .client
                    .lock()
                    .map_err(|_| anyhow!("scheduler HTTP client mutex poisoned"))?;
                client.post(url)
            };
            let req = req.bearer_auth(auth).timeout(HEARTBEAT_TIMEOUT);
            let req = match assignment {
                JobAssignment::Archive(tc) => req.bincode(&tc)?,
                JobAssignment::Native(assignment) => req
                    .header("Content-Type", "application/octet-stream")
                    .body(crate::dist::native::codec().serialize(&*assignment)?),
            };
            bincode_req(req).context("POST to worker assignment failed")
        }
    }

    pub struct Server<S> {
        bind_address: SocketAddr,
        scheduler_url: reqwest::Url,
        scheduler_auth: String,
        // HTTPS pieces all the builders will use for connection encryption
        cert_digest: Vec<u8>,
        cert_pem: Vec<u8>,
        privkey_pem: Vec<u8>,
        // Key used to sign any requests relating to jobs
        jwt_key: Vec<u8>,
        // Randomly generated nonce to allow the scheduler to detect server restarts
        server_nonce: ServerNonce,
        worker_name: Option<String>,
        handler: S,
    }

    impl<S: dist::ServerIncoming + 'static> Server<S> {
        pub fn new(
            public_addr: SocketAddr,
            bind_address: Option<SocketAddr>,
            scheduler_url: reqwest::Url,
            scheduler_auth: String,
            handler: S,
        ) -> Result<Self> {
            Self::new_inner(
                public_addr,
                bind_address,
                scheduler_url,
                scheduler_auth,
                None,
                handler,
            )
        }

        /// Create a distributed worker that advertises a stable display name.
        pub fn new_with_worker_name(
            public_addr: SocketAddr,
            bind_address: Option<SocketAddr>,
            scheduler_url: reqwest::Url,
            scheduler_auth: String,
            worker_name: String,
            handler: S,
        ) -> Result<Self> {
            reqwest::header::HeaderValue::from_str(&worker_name)
                .context("distributed worker name is not a valid HTTP header value")?;
            Self::new_inner(
                public_addr,
                bind_address,
                scheduler_url,
                scheduler_auth,
                Some(worker_name),
                handler,
            )
        }

        fn new_inner(
            public_addr: SocketAddr,
            bind_address: Option<SocketAddr>,
            scheduler_url: reqwest::Url,
            scheduler_auth: String,
            worker_name: Option<String>,
            handler: S,
        ) -> Result<Self> {
            let (cert_digest, cert_pem, privkey_pem) =
                create_https_cert_and_privkey(public_addr)
                    .context("failed to create HTTPS certificate for server")?;
            let mut jwt_key = vec![0; JWT_KEY_LENGTH];
            rand::fill(&mut jwt_key);
            let server_nonce = ServerNonce::new();

            Ok(Self {
                bind_address: bind_address.unwrap_or(public_addr),
                scheduler_url,
                scheduler_auth,
                cert_digest,
                cert_pem,
                privkey_pem,
                jwt_key,
                server_nonce,
                worker_name,
                handler,
            })
        }

        pub fn start(self) -> Result<Infallible> {
            let Self {
                bind_address,
                scheduler_url,
                scheduler_auth,
                cert_digest,
                cert_pem,
                privkey_pem,
                jwt_key,
                server_nonce,
                worker_name,
                handler,
            } = self;
            let mut load_aware_capacity = LoadAwareCapacity::new();
            let handler = Arc::new(handler);
            let heartbeat_handler = Arc::clone(&handler);
            let capabilities = handler.capabilities();
            let running_jobs = Arc::new(Mutex::new(HashSet::<JobId>::new()));
            let heartbeat_running_jobs = Arc::clone(&running_jobs);
            let upload_activity = UploadActivity::default();
            let heartbeat_upload_activity = Arc::clone(&upload_activity);
            let heartbeat_jwt_key = jwt_key.clone();
            let heartbeat_cert_pem = cert_pem.clone();
            let job_authorizer = JWTJobAuthorizer::boxed(&jwt_key)?;
            let heartbeat_url = urls::scheduler_heartbeat_server(&scheduler_url)?;
            let requester = ServerRequester {
                client: new_reqwest_blocking_client()?,
                scheduler_url,
                scheduler_auth: scheduler_auth.clone(),
            };

            let heartbeat_client = new_reqwest_blocking_client()?;
            // TODO: detect if this panics
            thread::spawn(move || {
                let client = heartbeat_client;
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
                        load_aware_capacity.advertised_cpus(running_job_ids.len());
                    // Transfers keep their assignment alive, but do not count as
                    // executing compiler processes for CPU-capacity restoration.
                    let active_job_ids = running_job_ids
                        .into_iter()
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
                        jwt_key: heartbeat_jwt_key.clone(),
                        server_nonce: server_nonce.clone(),
                        cert_digest: cert_digest.clone(),
                        cert_pem: heartbeat_cert_pem.clone(),
                    };
                    let mut heartbeat_request = client
                        .post(heartbeat_url.clone())
                        // A stalled scheduler must not permanently stop heartbeats.
                        .timeout(HEARTBEAT_INTERVAL)
                        .bearer_auth(scheduler_auth.clone());
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
                    let heartbeat_result = heartbeat_request
                        .bincode(&heartbeat_req)
                        .and_then(bincode_req);
                    match heartbeat_result {
                        Ok(HeartbeatServerResult {
                            is_new,
                            assigned_job_ids,
                        }) => {
                            trace!(target: "sccache_heartbeat", "Heartbeat success is_new={}", is_new);
                            match heartbeat_handler.handle_reconcile_assignments(
                                &assigned_job_ids,
                                heartbeat_started_at,
                            ) {
                                Ok(removed) if removed > 0 => {
                                    info!("Discarded {removed} stale unclaimed worker assignments");
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

            let server = rouille::Server::new_ssl(bind_address, move |request| {
                let req_id = request_count.fetch_add(1, atomic::Ordering::Relaxed);
                trace!("Req {}: {:?}", req_id, SafeRequest(request));
                let response = (|| router!(request,
                    (POST) (/api/v1/distserver/assign_job/{job_id: JobId}) => {
                        job_auth_or_401!(request, &job_authorizer, job_id);
                        let toolchain = try_or_400_log!(req_id, bincode_input(request));
                        trace!("Req {}: assign_job({}): {:?}", req_id, job_id, toolchain);

                        let res: AssignJobResult = try_or_500_log!(req_id, handler.handle_assign_job(job_id, toolchain));
                        prepare_response(request, &res)
                    },
                    (POST) (/api/v3/distserver/assign_native_job/{job_id: JobId}) => {
                        job_auth_or_401!(request, &job_authorizer, job_id);
                        let limit = try_or_400_log!(req_id, handler.native_metadata_limit().context("native worker disabled"));
                        let assignment: NativeAssignment = try_or_400_log!(req_id, native::metadata(request, limit));
                        let res = try_or_500_log!(req_id, handler.handle_assign_native_job(job_id, assignment));
                        prepare_response(request, &res)
                    },
                    (POST) (/api/v3/distserver/run_native_job/{job_id: JobId}) => {
                        job_auth_or_401!(request, &job_authorizer, job_id);
                        let _running_job = try_or_500_log!(req_id, RunningJobGuard::new(&running_jobs, job_id));
                        let res = try_or_500_log!(req_id, handler.handle_run_native_job(&requester, job_id));
                        let data = try_or_500_log!(req_id, crate::dist::native::codec().serialize(&res));
                        rouille::Response::from_data("application/octet-stream", data)
                    },
                    (POST) (/api/v1/distserver/submit_toolchain/{job_id: JobId}) => {
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
                        let res: SubmitToolchainResult = try_or_500_log!(req_id, handler.handle_submit_toolchain(&requester, job_id, toolchain_rdr));
                        prepare_response(request, &res)
                    },
                    (POST) (/api/v2/distserver/run_job/{job_id: JobId}) => {
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
                        let res: RunJobResult = try_or_500_log!(req_id, handler.handle_run_job(&requester, job_id, command, outputs, inputs_rdr));
                        prepare_response(request, &res)
                    },
                    _ => {
                        warn!("Unknown request {:?}", SafeRequest(request));
                        rouille::Response::empty_404()
                    },
                ))();
                trace!("Res {}: {:?}", req_id, response);
                response
            }, cert_pem, privkey_pem).map_err(|e| anyhow!("Failed to start http server for sccache server: {e}"))?;

            // This limit is rouille's default for `start_server_with_pool`, which
            // we would use, except that interface doesn't permit any sort of
            // error handling to be done.
            let server = server.pool_size(num_cpus() * 8);
            server.run();

            Err(anyhow!("Rouille HTTPS server terminated"))
        }
    }

    struct ServerRequester {
        client: reqwest::blocking::Client,
        scheduler_url: reqwest::Url,
        scheduler_auth: String,
    }

    impl dist::ServerOutgoing for ServerRequester {
        fn do_update_job_state(
            &self,
            job_id: JobId,
            state: JobState,
        ) -> Result<UpdateJobStateResult> {
            let url = urls::scheduler_job_state(&self.scheduler_url, job_id)?;
            let publish = || {
                bincode_req(
                    self.client
                        .post(url.clone())
                        // Never retain an execution slot forever on a stalled ACK.
                        .timeout(HEARTBEAT_TIMEOUT)
                        .bearer_auth(self.scheduler_auth.clone())
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

        fn request_from(ip: Ipv4Addr, headers: Vec<(String, String)>) -> rouille::Request {
            rouille::Request::fake_http_from(
                SocketAddr::V4(SocketAddrV4::new(ip, 12345)),
                "POST",
                "/api/test?access_token=query-secret",
                headers,
                Vec::new(),
            )
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

        #[test]
        fn direct_request_cannot_spoof_x_real_ip() -> Result<()> {
            let remote_ip = Ipv4Addr::new(198, 51, 100, 7);
            let request = request_from(
                remote_ip,
                vec![("X-Real-IP".to_owned(), "203.0.113.9".to_owned())],
            );
            assert_eq!(request_origin_ip(&request)?, IpAddr::V4(remote_ip));
            Ok(())
        }

        #[test]
        fn loopback_proxy_can_supply_x_real_ip() -> Result<()> {
            let request = request_from(
                Ipv4Addr::LOCALHOST,
                vec![("X-Real-IP".to_owned(), "203.0.113.9".to_owned())],
            );
            assert_eq!(
                request_origin_ip(&request)?,
                "203.0.113.9".parse::<IpAddr>()?
            );
            Ok(())
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
        AllocJobHttpResponse, ReqwestRequestBuilderExt, RunJobHttpRequest,
        ServerCertificateHttpResponse, WorkerNameHttpResponse, bincode_req_fut,
    };
    use super::urls;
    use crate::errors::{Context, Result, anyhow};

    const REQUEST_TIMEOUT_SECS: u64 = 1200;
    const CONNECT_TIMEOUT_SECS: u64 = 20;
    const WORKER_NAME_LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);
    const WORKER_NAME_CACHE_TTL: Duration = Duration::from_secs(300);
    const WORKER_NAME_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

    type WorkerNameCache = HashMap<ServerId, (Option<String>, Instant)>;

    pub struct Client {
        auth_token: String,
        scheduler_url: reqwest::Url,
        // cert_digest -> cert_pem
        server_certs: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
        // server_id -> (optional display name, lookup time). Successful names are
        // stable for a server identity; negative/legacy results are retried later.
        server_names: Arc<Mutex<WorkerNameCache>>,
        http: Arc<Mutex<reqwest::Client>>,
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
            scheduler_url: reqwest::Url,
            cache_dir: &Path,
            cache_size: u64,
            toolchain_configs: &[config::DistToolchainConfig],
            auth_token: String,
            rewrite_includes_only: bool,
        ) -> Result<Self> {
            let timeout = Duration::new(REQUEST_TIMEOUT_SECS, 0);
            let connect_timeout = Duration::new(CONNECT_TIMEOUT_SECS, 0);
            let client = reqwest::ClientBuilder::new()
                .timeout(timeout)
                .connect_timeout(connect_timeout)
                // Disable connection pool to avoid broken connection
                // between runtime
                .pool_max_idle_per_host(0)
                .build()
                .context("failed to create an async HTTP client")?;
            let client_toolchains =
                cache::ClientToolchains::new(cache_dir, cache_size, toolchain_configs)
                    .context("failed to initialise client toolchains")?;
            Ok(Self {
                auth_token,
                scheduler_url,
                server_certs: Arc::default(),
                server_names: Arc::default(),
                http: Arc::new(Mutex::new(client)),
                pool: pool.clone(),
                tc_cache: Arc::new(client_toolchains),
                rewrite_includes_only,
            })
        }

        fn update_certs(
            client: &mut reqwest::Client,
            certs: &mut HashMap<Vec<u8>, Vec<u8>>,
            cert_digest: Vec<u8>,
            cert_pem: Vec<u8>,
        ) -> Result<()> {
            let mut client_async_builder = reqwest::ClientBuilder::new();
            // Add all the certificates we know about
            client_async_builder = client_async_builder.add_root_certificate(
                reqwest::Certificate::from_pem(&cert_pem)
                    .context("failed to interpret pem as certificate")?,
            );
            for cert_pem in certs.values() {
                client_async_builder = client_async_builder.add_root_certificate(
                    reqwest::Certificate::from_pem(cert_pem)
                        .context("stored server certificate is no longer valid")?,
                );
            }
            // Finish the client
            let timeout = Duration::new(REQUEST_TIMEOUT_SECS, 0);
            let new_client_async = client_async_builder
                .timeout(timeout)
                .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
                // Disable keep-alive
                .pool_max_idle_per_host(0)
                .build()
                .context("failed to create an async HTTP client")?;
            // Use the updated certificates
            *client = new_client_async;
            certs.insert(cert_digest, cert_pem);
            Ok(())
        }
    }

    #[async_trait]
    impl dist::Client for Client {
        async fn do_alloc_job(&self, tc: Toolchain) -> Result<AllocJobResult> {
            let scheduler_url = self.scheduler_url.clone();
            let url = urls::scheduler_alloc_job(&scheduler_url)?;
            let mut req = {
                let client = self
                    .http
                    .lock()
                    .map_err(|_| anyhow!("HTTP client mutex poisoned"))?;
                client.post(url)
            };
            req = req.bearer_auth(self.auth_token.clone()).bincode(&tc)?;

            let http_client = self.http.clone();
            let server_certs = self.server_certs.clone();

            match bincode_req_fut(req).await? {
                AllocJobHttpResponse::Success {
                    job_alloc,
                    need_toolchain,
                    cert_digest,
                } => {
                    let server_id = job_alloc.server_id;
                    let alloc_job_res = Ok(AllocJobResult::Success {
                        job_alloc,
                        need_toolchain,
                    });
                    let has_certificate = server_certs
                        .lock()
                        .map_err(|_| anyhow!("server certificate mutex poisoned"))?
                        .contains_key(&cert_digest);
                    if has_certificate {
                        return alloc_job_res;
                    }
                    info!(
                        "Need to request new certificate for server {}",
                        server_id.addr()
                    );
                    let url = urls::scheduler_server_certificate(&scheduler_url, server_id)?;
                    let req = {
                        let client = http_client
                            .lock()
                            .map_err(|_| anyhow!("HTTP client mutex poisoned"))?;
                        client.get(url)
                    };
                    let res: ServerCertificateHttpResponse = bincode_req_fut(req)
                        .await
                        .context("GET to scheduler server_certificate failed")?;

                    // TODO: Move to asynchronous reqwest client only.
                    // This function internally builds a blocking reqwest client;
                    // However, it does so by utilizing a runtime which it drops,
                    // triggering (rightfully) a sanity check that prevents from
                    // dropping a runtime in asynchronous context.
                    // For the time being, we work around this by off-loading it
                    // to a dedicated blocking-friendly thread pool.
                    self.pool
                        .spawn_blocking(move || -> Result<()> {
                            let mut client = http_client
                                .lock()
                                .map_err(|_| anyhow!("HTTP client mutex poisoned"))?;
                            let mut certs = server_certs
                                .lock()
                                .map_err(|_| anyhow!("server certificate mutex poisoned"))?;
                            Self::update_certs(
                                &mut client,
                                &mut certs,
                                res.cert_digest,
                                res.cert_pem,
                            )
                            .context("failed to update server certificates")
                        })
                        .await
                        .context("certificate update task failed")??;

                    alloc_job_res
                }
                AllocJobHttpResponse::Fail { msg } => Ok(AllocJobResult::Fail { msg }),
            }
        }

        async fn worker_label(&self, server_id: ServerId) -> String {
            let fallback = server_id.addr().to_string();
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

            let url = match urls::scheduler_worker_name(&self.scheduler_url, server_id) {
                Ok(url) => url,
                Err(error) => {
                    debug!("could not build worker-name lookup URL: {error}");
                    return fallback;
                }
            };
            let req = {
                let Ok(client) = self.http.lock() else {
                    debug!("HTTP client mutex poisoned during worker-name lookup");
                    return fallback;
                };
                client
                    .get(url)
                    .bearer_auth(self.auth_token.clone())
                    .timeout(WORKER_NAME_LOOKUP_TIMEOUT)
            };

            let checked_at = Instant::now();
            match bincode_req_fut::<WorkerNameHttpResponse>(req).await {
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
            let scheduler_url = self.scheduler_url.clone();
            let url = urls::scheduler_status(&scheduler_url)?;
            let req = {
                let client = self
                    .http
                    .lock()
                    .map_err(|_| anyhow!("HTTP client mutex poisoned"))?;
                client.get(url)
            };
            bincode_req_fut(req).await
        }

        async fn do_submit_toolchain(
            &self,
            job_alloc: JobAlloc,
            tc: Toolchain,
        ) -> Result<SubmitToolchainResult> {
            match self.tc_cache.get_toolchain(&tc) {
                Ok(Some(toolchain_file)) => {
                    let url = urls::server_submit_toolchain(job_alloc.server_id, job_alloc.job_id)?;
                    let req = {
                        let client = self
                            .http
                            .lock()
                            .map_err(|_| anyhow!("HTTP client mutex poisoned"))?;
                        client.post(url)
                    };
                    let toolchain_file = tokio::fs::File::from_std(toolchain_file.into());
                    let toolchain_file_stream = tokio_util::io::ReaderStream::new(toolchain_file);
                    let body = Body::wrap_stream(toolchain_file_stream);
                    let req = req.bearer_auth(job_alloc.auth).body(body);
                    bincode_req_fut(req).await
                }
                Ok(None) => Err(anyhow!("couldn't find toolchain locally")),
                Err(e) => Err(e),
            }
        }

        async fn do_run_job(
            &self,
            job_alloc: JobAlloc,
            command: CompileCommand,
            outputs: Vec<String>,
            inputs_packager: Box<dyn InputsPackager>,
        ) -> Result<RunJobResult> {
            let url = urls::server_run_job(job_alloc.server_id, job_alloc.job_id)?;

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
            let mut req = {
                let client = self
                    .http
                    .lock()
                    .map_err(|_| anyhow!("HTTP client mutex poisoned"))?;
                client.post(url)
            };
            req = req.bearer_auth(job_alloc.auth.clone()).bytes(body);
            bincode_req_fut(req).await
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
