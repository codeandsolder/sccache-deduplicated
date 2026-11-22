#[macro_use]
extern crate log;

use anyhow::{Context, Result, bail};
use base64::Engine;
use sccache::config::{
    INSECURE_DIST_CLIENT_TOKEN,
    scheduler::{self as scheduler_config, JobSlackConfig},
    server as server_config,
};
use sccache::dist::{
    self, AllocJobResult, AssignJobResult, BuilderIncoming, CompileCommand, HeartbeatServerResult,
    InputsReader, JobAlloc, JobAuthorizer, JobComplete, JobId, JobState, OutputRequest,
    RunJobResult, SchedulerIncoming, SchedulerOutgoing, SchedulerStatusResult, ServerId,
    ServerIncoming, ServerNonce, ServerOutgoing, StagedToolchainArchive, SubmitToolchainResult,
    TcCache, Toolchain, ToolchainReader, UpdateJobStateResult,
};
use sccache::util::BASE64_URL_SAFE_ENGINE;
use sccache::util::daemonize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque, btree_map};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg_attr(target_os = "freebsd", path = "build_freebsd.rs")]
mod build;

mod cmdline;
mod command_helpers;
mod token_check;

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
    incr_env_strs
        .iter()
        .for_each(|incr_str| match env::var(incr_str) {
            Ok(incr_val) if incr_val == "1" => {
                println!(
                    "sccache: incremental compilation is prohibited: Unset {} to continue.",
                    incr_str
                );
                std::process::exit(1);
            }
            _ => (),
        });

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
            eprintln!("sccache-dist: error: {}", e);

            for e in e.chain().skip(1) {
                eprintln!("sccache-dist: caused by: {}", e);
            }
            2
        }
    });
}

fn create_server_token(server_id: ServerId, auth_token: &str) -> String {
    format!("{} {}", server_id.addr(), auth_token)
}
fn check_server_token(server_token: &str, auth_token: &str) -> Option<ServerId> {
    let mut split = server_token.splitn(2, ' ');
    let server_addr = split.next().and_then(|addr| addr.parse().ok())?;
    match split.next() {
        Some(t) if t == auth_token => Some(ServerId::new(server_addr)),
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
    jwt::decode::<ServerJwt>(server_token, key, validation)
        .map(|res| res.claims.server_id)
        .ok()
}

fn run(command: Command) -> Result<i32> {
    match command {
        Command::Auth(AuthSubcommand::Base64 { num_bytes }) => {
            let mut bytes = vec![0; num_bytes];
            rand::fill(&mut bytes);
            // As long as it can be copied, it doesn't matter if this is base64 or hex etc
            println!("{}", BASE64_URL_SAFE_ENGINE.encode(bytes));
            Ok(0)
        }
        Command::Auth(AuthSubcommand::JwtHS256ServerToken {
            secret_key,
            server_id,
        }) => {
            let header = jwt::Header::new(jwt::Algorithm::HS256);
            let secret_key = BASE64_URL_SAFE_ENGINE.decode(secret_key)?;
            let token = create_jwt_server_token(server_id, &header, &secret_key)
                .context("Failed to create server token")?;
            println!("{}", token);
            Ok(0)
        }

        Command::Scheduler(scheduler_config::Config {
            public_addr,
            client_auth,
            server_auth,
            maintenance_drain_file,
            job_slack,
        }) => {
            let check_client_auth: Box<dyn dist::http::ClientAuthCheck> = match client_auth {
                scheduler_config::ClientAuth::Insecure => Box::new(token_check::EqCheck::new(
                    INSECURE_DIST_CLIENT_TOKEN.to_owned(),
                )),
                scheduler_config::ClientAuth::Token { token } => {
                    Box::new(token_check::EqCheck::new(token))
                }
                scheduler_config::ClientAuth::JwtValidate {
                    audience,
                    issuer,
                    jwks_url,
                } => Box::new(
                    token_check::ValidJWTCheck::new(audience, issuer, &jwks_url)
                        .context("Failed to create a checker for valid JWTs")?,
                ),
                scheduler_config::ClientAuth::ProxyToken { url, cache_secs } => {
                    Box::new(token_check::ProxyTokenCheck::new(url, cache_secs)?)
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
                    Box::new(move |server_token| {
                        check_jwt_server_token(server_token, &key, &validation)
                    })
                }
            };

            if maintenance_drain_file
                .as_deref()
                .is_some_and(|path| !path.is_absolute())
            {
                bail!("scheduler maintenance_drain_file must be absolute")
            }
            daemonize(&[])?;
            info!(
                "Distributed scheduler job slack: static={} percent={}%",
                job_slack.static_jobs, job_slack.percent
            );
            let scheduler =
                Scheduler::new_with_job_slack_and_drain(job_slack, maintenance_drain_file);
            let http_scheduler = dist::http::Scheduler::new(
                public_addr,
                scheduler,
                check_client_auth,
                check_server_auth,
            );
            // A running server never exits successfully (Result<Infallible>).
            match http_scheduler.start()? {}
        }

        Command::Server(server_config::Config {
            builder,
            cache_dir,
            public_addr,
            bind_address,
            scheduler_url,
            scheduler_auth,
            toolchain_cache_size,
            toolchain_archive_sources,
        }) => {
            let builder: Box<dyn dist::BuilderIncoming> = match builder {
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Docker => {
                    Box::new(build::DockerBuilder::new().context("Docker builder failed to start")?)
                }
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Overlay {
                    bwrap_path,
                    build_dir,
                } => Box::new(
                    build::OverlayBuilder::new(bwrap_path, build_dir)
                        .context("Overlay builder failed to start")?,
                ),
                #[cfg(target_os = "freebsd")]
                server_config::BuilderType::Pot {
                    pot_fs_root,
                    clone_from,
                    pot_cmd,
                    pot_clone_args,
                } => Box::new(
                    build::PotBuilder::new(pot_fs_root, clone_from, pot_cmd, pot_clone_args)
                        .context("Pot builder failed to start")?,
                ),
                _ => bail!(
                    "Builder type `{}` not supported on this platform",
                    format!("{:?}", builder)
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                ),
            };

            let server_id = ServerId::new(public_addr);
            let scheduler_auth = match scheduler_auth {
                server_config::SchedulerAuth::Insecure => {
                    warn!("Server starting with DANGEROUSLY_INSECURE scheduler authentication");
                    create_server_token(server_id, INSECURE_DIST_SERVER_TOKEN)
                }
                server_config::SchedulerAuth::Token { token } => {
                    create_server_token(server_id, &token)
                }
                server_config::SchedulerAuth::JwtToken { token } => {
                    let token_server_id: ServerId =
                        dangerous_insecure_extract_jwt_server_token(&token)
                            .context("Could not decode scheduler auth jwt")?;
                    if token_server_id != server_id {
                        bail!(
                            "JWT server id ({:?}) did not match configured server id ({:?})",
                            token_server_id,
                            server_id
                        )
                    }
                    token
                }
            };

            let server = Server::new(
                builder,
                &cache_dir,
                toolchain_cache_size,
                toolchain_archive_sources,
            )
            .context("Failed to create sccache server instance")?;
            let worker_name = dist_worker_name()?;
            let http_server = dist::http::Server::new_with_worker_name(
                public_addr,
                bind_address,
                scheduler_url.to_url(),
                scheduler_auth,
                worker_name,
                server,
            )
            .context("Failed to create sccache HTTP server instance")?;
            // A running server never exits successfully (Result<Infallible>).
            match http_server.start()? {}
        }
    }
}

fn init_logging() {
    if env::var(sccache::LOGGING_ENV).is_ok() {
        let mut builder = env_logger::Builder::from_env(sccache::LOGGING_ENV);

        // Enable millisecond precision timestamps if SCCACHE_LOG_MILLIS is set
        if env::var("SCCACHE_LOG_MILLIS").is_ok() {
            builder.format_timestamp_millis();
        }

        match builder.try_init() {
            Ok(_) => (),
            Err(e) => panic!("Failed to initialize logging: {:?}", e),
        }
    }
}

const SERVER_REMEMBER_ERROR_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_PENDING_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_READY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Copy, Clone)]
struct JobDetail {
    server_id: ServerId,
    state: JobState,
    // Time spent in the current phase, not the total time since allocation.
    state_since: Instant,
    // First heartbeat that did not report this Started job as executing.
    missing_since: Option<Instant>,
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

    fn transition_to(&mut self, state: JobState, now: Instant) {
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
    job_slack: JobSlackConfig,
    maintenance_drain_file: Option<PathBuf>,

    // Currently running jobs, can never be Complete
    jobs: Mutex<BTreeMap<JobId, JobDetail>>,
    servers: Mutex<HashMap<ServerId, ServerDetails>>,
    completed_acks: Mutex<CompletedJobAcks>,
}

struct ServerDetails {
    jobs_assigned: HashSet<JobId>,
    // Reservations for assignment RPCs still in flight. Once assigned,
    // the state and unclaimed timeout are owned exclusively by JobDetail.
    jobs_assigning: HashMap<JobId, Instant>,
    last_seen: Instant,
    last_error: Option<Instant>,
    cpu_capacity: f64,
    server_nonce: ServerNonce,
    worker_name: Option<String>,
    job_authorizer: Box<dyn JobAuthorizer>,
}

impl Scheduler {
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

    fn with_job_id_base(job_id_base: u64) -> Self {
        Self::with_job_id_base_and_slack(job_id_base, JobSlackConfig::default())
    }

    fn with_job_id_base_and_slack(job_id_base: u64, job_slack: JobSlackConfig) -> Self {
        Self::with_job_id_base_and_slack_and_drain(job_id_base, job_slack, None)
    }

    fn with_job_id_base_and_slack_and_drain(
        job_id_base: u64,
        job_slack: JobSlackConfig,
        maintenance_drain_file: Option<PathBuf>,
    ) -> Self {
        Scheduler {
            job_id_base,
            job_count: AtomicUsize::new(0),
            job_slack,
            maintenance_drain_file,
            jobs: Mutex::new(BTreeMap::new()),
            servers: Mutex::new(HashMap::new()),
            completed_acks: Mutex::new(CompletedJobAcks::default()),
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
        &self,
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
            warn!(
                "Server {} appears to be dead, pruning it in the scheduler",
                server_id.addr()
            );
            let Some(server_details) = servers.remove(&server_id) else {
                error!("server {server_id:?} disappeared while pruning");
                continue;
            };
            for job_id in server_details.jobs_assigned {
                warn!(
                    "Non-terminated job {} was cleaned up in server pruning",
                    job_id
                );
                // A job may be missing here if it failed to allocate
                // initially, so just warn if it's not present.
                if jobs.remove(&job_id).is_none() {
                    warn!(
                        "Non-terminated job {} assignment originally failed.",
                        job_id
                    );
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

fn admission_weight(job_count: usize, cpu_capacity: f64, job_slack: JobSlackConfig) -> Option<f64> {
    (job_count < job_slack.max_jobs(cpu_capacity))
        .then_some((cpu_capacity - job_count as f64).max(0.0) + 0.5)
}

fn weighted_server(candidates: &[(ServerId, f64)], draw: f64) -> Option<ServerId> {
    let total: f64 = candidates.iter().map(|(_, weight)| weight).sum();
    let mut ticket = draw * total;
    for &(server_id, weight) in candidates {
        if weight > 0.0 {
            if ticket < weight {
                return Some(server_id);
            }
            ticket -= weight;
        }
    }
    candidates
        .iter()
        .rev()
        .find(|(_, weight)| *weight > 0.0)
        .map(|(id, _)| *id)
}

impl SchedulerIncoming for Scheduler {
    fn handle_alloc_job(
        &self,
        requester: &dyn SchedulerOutgoing,
        tc: Toolchain,
    ) -> Result<AllocJobResult> {
        if self.is_draining() {
            return Ok(AllocJobResult::Fail {
                msg: "scheduler is draining for maintenance".to_owned(),
            });
        }
        let (job_id, server_id, auth) = {
            // LOCKS
            let mut servers = self.servers.lock().unwrap();

            let res = {
                let mut healthy = Vec::new();
                let mut retry = Vec::new();
                let now = Instant::now();
                for (&server_id, details) in servers.iter_mut() {
                    let Some(weight) = admission_weight(
                        details.jobs_assigned.len(),
                        details.cpu_capacity,
                        self.job_slack,
                    ) else {
                        continue;
                    };
                    if details.last_error.is_some_and(|when| {
                        now.duration_since(when) > SERVER_REMEMBER_ERROR_TIMEOUT
                    }) {
                        details.last_error = None;
                    }
                    if details.last_error.is_some() {
                        retry.push((server_id, weight));
                    } else {
                        healthy.push((server_id, weight));
                    }
                }
                let selected = [&healthy, &retry]
                    .into_iter()
                    .find_map(|candidates| weighted_server(candidates, rand::random::<f64>()));
                if let Some(server_id) = selected {
                    let server_details = servers
                        .get_mut(&server_id)
                        .expect("selected worker remains registered");
                    let job_id = self.next_job_id();
                    // Unique while holding the servers lock: every allocation
                    // advances job_count, including assignments that later fail.
                    // Token generation may fail. Never reserve worker capacity
                    // until an auth token is ready to send.
                    let auth = server_details
                        .job_authorizer
                        .generate_token(job_id)
                        .context("Could not create an auth token for this job")?;
                    assert!(server_details.jobs_assigned.insert(job_id));
                    assert!(
                        server_details
                            .jobs_assigning
                            .insert(job_id, Instant::now())
                            .is_none()
                    );

                    info!(
                        "Job {} created and will be assigned to server {:?}",
                        job_id, server_id
                    );
                    Some((job_id, server_id, auth))
                } else {
                    None
                }
            };

            if let Some(res) = res {
                res
            } else {
                let msg = format!(
                    "Insufficient capacity across {} available servers",
                    servers.len()
                );
                return Ok(AllocJobResult::Fail { msg });
            }
        };
        let AssignJobResult {
            state,
            need_toolchain,
        } = requester
            .do_assign_job(server_id, job_id, tc, auth.clone())
            .with_context(|| {
                // LOCKS
                let mut servers = self.servers.lock().unwrap();
                if let Some(entry) = servers.get_mut(&server_id) {
                    entry.last_error = Some(Instant::now());
                    entry.jobs_assigning.remove(&job_id);
                    if !entry.jobs_assigned.remove(&job_id) {
                        "assign job failed and job not known to the server"
                    } else {
                        "assign job failed, job un-assigned from the server"
                    }
                } else {
                    "assign job failed and server not known"
                }
            })?;
        {
            // LOCKS
            let mut jobs = self.jobs.lock().unwrap();
            let mut servers = self.servers.lock().unwrap();

            let Some(details) = servers.get_mut(&server_id) else {
                let msg = format!("Job {job_id} assignment completed after server disappeared");
                warn!("{msg}");
                return Ok(AllocJobResult::Fail { msg });
            };
            if !details.jobs_assigned.contains(&job_id)
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
                        server_id,
                        state,
                        state_since: Instant::now(),
                        missing_since: None,
                    }
                )
                .is_none()
            );
            details.jobs_assigning.remove(&job_id);
            info!(
                "Job {} successfully assigned and saved with state {:?}",
                job_id, state
            );
        }
        let job_alloc = JobAlloc {
            auth,
            job_id,
            server_id,
        };
        Ok(AllocJobResult::Success {
            job_alloc,
            need_toolchain,
        })
    }

    fn handle_heartbeat_server(
        &self,
        server_id: ServerId,
        server_nonce: ServerNonce,
        cpu_capacity: f64,
        running_job_ids: &[JobId],
        job_authorizer: Box<dyn JobAuthorizer>,
    ) -> Result<HeartbeatServerResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        self.prune_servers(&mut servers, &mut jobs);

        if !cpu_capacity.is_finite() || cpu_capacity < 0.0 {
            bail!("invalid worker CPU capacity {cpu_capacity}");
        }
        match servers.get_mut(&server_id) {
            Some(ref mut details) if details.server_nonce == server_nonce => {
                let now = Instant::now();
                details.last_seen = now;
                details.cpu_capacity = cpu_capacity;

                // The worker heartbeat is authoritative for *executing* jobs.
                // A Started job missing from one heartbeat can be an in-flight
                // snapshot, so require a full heartbeat timeout of absence.
                let running: HashSet<JobId> = running_job_ids.iter().copied().collect();
                let stale_jobs: Vec<_> = details
                    .jobs_assigned
                    .iter()
                    .copied()
                    .filter(|job_id| match jobs.get_mut(job_id) {
                        Some(detail) if detail.server_id == server_id => {
                            if detail.state == JobState::Started {
                                if running.contains(job_id) {
                                    detail.missing_since = None;
                                    false
                                } else {
                                    let since = detail.missing_since.get_or_insert(now);
                                    now.duration_since(*since) >= dist::http::HEARTBEAT_TIMEOUT
                                }
                            } else {
                                detail.is_stale_unclaimed(now)
                            }
                        }
                        Some(_) => false,
                        None => details.jobs_assigning.get(job_id).is_some_and(|&since| {
                            now.duration_since(since) > UNCLAIMED_PENDING_TIMEOUT
                        }),
                    })
                    .collect();

                if !stale_jobs.is_empty() {
                    warn!(
                        "The following stale jobs will be de-allocated: {:?}",
                        stale_jobs
                    );
                    for job_id in stale_jobs {
                        if !details.jobs_assigned.remove(&job_id) {
                            warn!(
                                "Stale job for server {} not assigned: {}",
                                server_id.addr(),
                                job_id
                            );
                        }
                        details.jobs_assigning.remove(&job_id);
                        jobs.remove(&job_id);
                    }
                }

                let mut assigned_job_ids: Vec<_> = details.jobs_assigned.iter().copied().collect();
                assigned_job_ids.sort_unstable();
                return Ok(HeartbeatServerResult {
                    is_new: false,
                    assigned_job_ids,
                });
            }
            Some(ref mut details) if details.server_nonce != server_nonce => {
                for job_id in details.jobs_assigned.iter() {
                    if jobs.remove(job_id).is_none() {
                        warn!(
                            "Unknown job found when replacing server {}: {}",
                            server_id.addr(),
                            job_id
                        );
                    }
                }
            }
            _ => (),
        }
        info!("Registered new server {:?}", server_id);
        servers.insert(
            server_id,
            ServerDetails {
                last_seen: Instant::now(),
                last_error: None,
                jobs_assigned: HashSet::new(),
                jobs_assigning: HashMap::new(),
                cpu_capacity,
                server_nonce,
                worker_name: None,
                job_authorizer,
            },
        );
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
        let worker_name = validate_worker_name(worker_name)?;
        // Match heartbeat lock ordering so a stale named worker cannot reserve
        // a display name after it has stopped heartbeating.
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();
        self.prune_servers(&mut servers, &mut jobs);
        drop(jobs);
        let details = servers.get(&server_id).ok_or_else(|| {
            anyhow::anyhow!(
                "worker name update from unknown server {}",
                server_id.addr()
            )
        })?;
        if details.server_nonce != server_nonce {
            bail!(
                "worker name update from stale server epoch {}",
                server_id.addr()
            )
        }
        if let Some(existing) = details.worker_name.as_ref() {
            if existing == &worker_name {
                return Ok(());
            }
            bail!(
                "distributed worker {} changed name from {:?} to {:?} without restarting",
                server_id.addr(),
                existing,
                worker_name
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
            .expect("server disappeared while scheduler lock was held")
            .worker_name = Some(worker_name.clone());
        info!(
            "Server {:?} registered worker name {:?}",
            server_id, worker_name
        );
        Ok(())
    }

    fn handle_get_worker_name(&self, server_id: ServerId) -> Result<Option<String>> {
        Ok(self
            .servers
            .lock()
            .unwrap()
            .get(&server_id)
            .and_then(|details| details.worker_name.clone()))
    }

    fn handle_update_job_state(
        &self,
        job_id: JobId,
        server_id: ServerId,
        job_state: JobState,
    ) -> Result<UpdateJobStateResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        if let btree_map::Entry::Occupied(mut entry) = jobs.entry(job_id) {
            let job_detail = entry.get();
            if job_detail.server_id != server_id {
                bail!(
                    "Job id {} is not registered on server {:?}",
                    job_id,
                    server_id
                )
            }

            let details = servers.get_mut(&server_id).ok_or_else(|| {
                anyhow::anyhow!("Job state updated, but server is not known to scheduler")
            })?;
            if !details.jobs_assigned.contains(&job_id) {
                bail!("job {job_id} was not assigned to server {server_id:?}");
            }

            let now = Instant::now();
            details.last_seen = now;

            match (job_detail.state, job_state) {
                (current, requested) if current == requested => {}
                (JobState::Pending, JobState::Ready) | (JobState::Ready, JobState::Started) => {
                    entry.get_mut().transition_to(job_state, now);
                }
                (JobState::Started, JobState::Complete) => {
                    let mut acks = self.completed_acks.lock().unwrap();
                    details.jobs_assigned.remove(&job_id);
                    entry.remove_entry();
                    acks.record(job_id, server_id, now);
                }
                (from, to) => bail!("Invalid job state transition from {} to {}", from, to),
            }
            info!("Job {} updated state to {:?}", job_id, job_state);
        } else if job_state == JobState::Complete
            && self
                .completed_acks
                .lock()
                .unwrap()
                .contains(job_id, server_id, Instant::now())
        {
            // The scheduler applied a prior completion, but its reply was lost.
            info!("Job {job_id} completion acknowledged again");
        } else {
            bail!("Unknown job {job_id} for server {server_id:?}")
        }
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_is_draining(&self) -> bool {
        self.is_draining()
    }

    fn handle_status(&self) -> Result<SchedulerStatusResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        self.prune_servers(&mut servers, &mut jobs);

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
                .map(|v| self.job_slack.max_jobs(v.cpu_capacity))
                .fold(0, usize::saturating_add),
            available_jobs: if self.is_draining() {
                0
            } else {
                servers
                    .values()
                    .map(|v| {
                        self.job_slack
                            .max_jobs(v.cpu_capacity)
                            .saturating_sub(v.jobs_assigned.len())
                    })
                    .fold(0, usize::saturating_add)
            },
        })
    }
}

struct LocalAssignment {
    toolchain: Toolchain,
    // Local time of receipt, not the scheduler's assignment timestamp.
    accepted_at: Instant,
}

pub struct Server {
    builder: Box<dyn BuilderIncoming>,
    cache: Mutex<TcCache>,
    staging_dir: PathBuf,
    toolchain_cache_size: u64,
    #[cfg(target_os = "linux")]
    toolchain_archive_sources: Vec<PathBuf>,
    job_toolchains: Mutex<HashMap<JobId, LocalAssignment>>,
}

impl Server {
    pub fn new(
        builder: Box<dyn BuilderIncoming>,
        cache_dir: &Path,
        toolchain_cache_size: u64,
        toolchain_archive_sources: Vec<PathBuf>,
    ) -> Result<Server> {
        if toolchain_archive_sources
            .iter()
            .any(|path| !path.is_absolute())
        {
            bail!("toolchain archive sources must be absolute paths");
        }
        #[cfg(not(target_os = "linux"))]
        if !toolchain_archive_sources.is_empty() {
            bail!("local toolchain archive reflinks require Linux");
        }
        let cache = TcCache::new(&cache_dir.join("tc"), toolchain_cache_size)
            .context("Failed to create toolchain cache")?;
        Ok(Server {
            builder,
            cache: Mutex::new(cache),
            staging_dir: cache_dir.join("tc"),
            toolchain_cache_size,
            #[cfg(target_os = "linux")]
            toolchain_archive_sources,
            job_toolchains: Mutex::new(HashMap::new()),
        })
    }

    /// Try local archive sources before asking the client to upload. The
    /// cache mutex is not held while cloning or verifying archive contents.
    fn has_or_reuse_toolchain(&self, tc: &Toolchain) -> bool {
        if self.cache.lock().unwrap().contains_toolchain(tc) {
            return true;
        }
        #[cfg(target_os = "linux")]
        for source in &self.toolchain_archive_sources {
            match StagedToolchainArchive::clone_verified(
                &self.staging_dir,
                source,
                tc.clone(),
                self.toolchain_cache_size,
            ) {
                Ok(staged) => {
                    let mut cache = self.cache.lock().unwrap();
                    match cache.insert_staged(staged) {
                        Ok(()) => {
                            debug!("Reused local toolchain archive {}", tc.archive_id);
                            return true;
                        }
                        Err(error) => debug!("Could not install cloned archive: {error:#}"),
                    }
                }
                Err(error) => trace!(
                    "Local archive source {} unavailable: {error:#}",
                    source.display()
                ),
            }
        }
        self.cache.lock().unwrap().contains_toolchain(tc)
    }
}

impl ServerIncoming for Server {
    fn handle_reconcile_assignments(
        &self,
        assigned_job_ids: &[JobId],
        heartbeat_started_at: Instant,
    ) -> Result<usize> {
        let known: HashSet<_> = assigned_job_ids.iter().copied().collect();
        let mut local = self.job_toolchains.lock().unwrap();
        let before = local.len();
        local.retain(|id, assignment| {
            // A scheduler reservation precedes receipt by the worker. Do not
            // prune assignments received after the heartbeat request began.
            assignment.accepted_at >= heartbeat_started_at || known.contains(id)
        });
        let removed = before - local.len();
        drop(local);
        Ok(removed)
    }

    fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = !self.has_or_reuse_toolchain(&tc);
        assert!(
            self.job_toolchains
                .lock()
                .unwrap()
                .insert(
                    job_id,
                    LocalAssignment {
                        toolchain: tc,
                        accepted_at: Instant::now(),
                    }
                )
                .is_none()
        );
        let state = if need_toolchain {
            JobState::Pending
        } else {
            // TODO: can start prepping the build environment now
            JobState::Ready
        };
        Ok(AssignJobResult {
            state,
            need_toolchain,
        })
    }
    fn handle_submit_toolchain(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        tc_rdr: ToolchainReader,
    ) -> Result<SubmitToolchainResult> {
        let tc = match self.job_toolchains.lock().unwrap().get(&job_id) {
            Some(assigned) => assigned.toolchain.clone(),
            None => return Ok(SubmitToolchainResult::JobNotFound),
        };
        // Streaming and hashing large archives must not hold the cache mutex:
        // other toolchains still need to be assigned while uploads are slow.
        let staged = match StagedToolchainArchive::receive(
            &self.staging_dir,
            tc,
            tc_rdr,
            self.toolchain_cache_size,
        ) {
            Ok(staged) => staged,
            Err(error) => {
                warn!("Could not receive or verify toolchain archive: {error:#}");
                return Ok(SubmitToolchainResult::CannotCache);
            }
        };
        let inserted = self.cache.lock().unwrap().insert_staged(staged);
        if let Err(error) = inserted {
            warn!("Could not install verified toolchain archive: {error:#}");
            return Ok(SubmitToolchainResult::CannotCache);
        }
        // Uploads can outlive a scheduler-side timeout. Never publish Ready
        // for a job that has since been removed by heartbeat reconciliation.
        if !self.job_toolchains.lock().unwrap().contains_key(&job_id) {
            return Ok(SubmitToolchainResult::JobNotFound);
        }
        requester
            .do_update_job_state(job_id, JobState::Ready)
            .context("Updating job state failed")?;
        Ok(SubmitToolchainResult::Success)
    }
    fn handle_run_job(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        command: CompileCommand,
        outputs: OutputRequest,
        inputs_rdr: InputsReader,
    ) -> Result<RunJobResult> {
        // Claim the local job before sending any scheduler transition. A
        // duplicate/unknown run must never mark someone else's job Started.
        let assigned = self.job_toolchains.lock().unwrap().remove(&job_id);
        let Some(assigned) = assigned else {
            return Ok(RunJobResult::JobNotFound);
        };
        if let Err(error) = requester.do_update_job_state(job_id, JobState::Started) {
            let mut jobs = self.job_toolchains.lock().unwrap();
            if jobs.insert(job_id, assigned).is_some() {
                bail!("job {job_id} reappeared while restoring failed start transition");
            }
            return Err(error).context("Updating job state failed");
        }

        let res = self
            .builder
            .run_build(
                assigned.toolchain,
                command,
                outputs,
                inputs_rdr,
                &self.cache,
            )
            .map(|res| {
                RunJobResult::Complete(JobComplete {
                    output: res.output,
                    outputs: res.outputs,
                })
            })
            .map_err(|e| e.context("run build failed"));
        requester
            .do_update_job_state(job_id, JobState::Complete)
            .context("Updating job state failed")?;
        res
    }
}

#[cfg(test)]
mod scheduler_tests {
    use super::*;

    fn test_toolchain(marker: char) -> Toolchain {
        Toolchain {
            archive_id: sccache::dist::ArchiveId::try_from(marker.to_string().repeat(64)).unwrap(),
        }
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
        let a: ServerId = "127.0.0.1:10501".parse().unwrap();
        let b: ServerId = "127.0.0.2:10501".parse().unwrap();
        let c: ServerId = "127.0.0.3:10501".parse().unwrap();
        let choices = [(a, 1.5), (b, 3.5), (c, 0.5)];
        assert_eq!(weighted_server(&choices, 0.0), Some(a));
        assert_eq!(weighted_server(&choices, 0.27), Some(a));
        assert_eq!(weighted_server(&choices, 0.28), Some(b));
        assert_eq!(weighted_server(&choices, 0.999), Some(c));
        assert_eq!(weighted_server(&[(c, 0.0)], 0.0), None);
    }

    struct TestJobAuthorizer;

    impl JobAuthorizer for TestJobAuthorizer {
        fn generate_token(&self, _job_id: JobId) -> Result<String> {
            Ok(String::new())
        }

        fn verify_token(&self, _job_id: JobId, _token: &str) -> Result<()> {
            Ok(())
        }
    }

    fn register_test_server(scheduler: &Scheduler, server_id: ServerId, nonce: ServerNonce) {
        scheduler
            .handle_heartbeat_server(server_id, nonce, 1.0, &[], Box::new(TestJobAuthorizer))
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

    impl SchedulerOutgoing for AcceptAssign {
        fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _tc: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    #[test]
    fn scheduler_status_tracks_per_worker_admission_and_capacity_changes() {
        let scheduler = Scheduler::new_with_job_slack(JobSlackConfig {
            static_jobs: 0,
            percent: 200.0,
        });
        let ids: [ServerId; 3] = [
            "127.0.0.1:10501".parse().unwrap(),
            "127.0.0.1:10502".parse().unwrap(),
            "127.0.0.1:10503".parse().unwrap(),
        ];
        let nonce = ServerNonce::new();
        for (id, cpus) in ids.into_iter().zip([1.0, 3.0, 0.0]) {
            scheduler
                .handle_heartbeat_server(id, nonce.clone(), cpus, &[], Box::new(TestJobAuthorizer))
                .unwrap();
        }
        let status = scheduler.handle_status().unwrap();
        assert_eq!(
            (status.num_cpus, status.max_jobs, status.available_jobs),
            (4, 13, 13)
        );
        for _ in 0..13 {
            assert!(matches!(
                scheduler
                    .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
                    .unwrap(),
                AllocJobResult::Success { .. }
            ));
        }
        assert!(matches!(
            scheduler
                .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
                .unwrap(),
            AllocJobResult::Fail { .. }
        ));
        let status = scheduler.handle_status().unwrap();
        assert_eq!(
            (status.in_progress, status.max_jobs, status.available_jobs),
            (13, 13, 0)
        );
        scheduler
            .handle_heartbeat_server(ids[0], nonce.clone(), 0.0, &[], Box::new(TestJobAuthorizer))
            .unwrap();
        scheduler
            .handle_heartbeat_server(ids[1], nonce, 4.0, &[], Box::new(TestJobAuthorizer))
            .unwrap();
        let status = scheduler.handle_status().unwrap();
        // Three jobs remain assigned to the now-busy worker; the other worker
        // can admit three more despite the fleet's nominal capacity being full.
        assert_eq!(
            (status.in_progress, status.max_jobs, status.available_jobs),
            (13, 14, 3)
        );
    }

    struct StatusDuringAssign<'a>(&'a Scheduler);

    impl SchedulerOutgoing for StatusDuringAssign<'_> {
        fn do_assign_job(
            &self,
            _server_id: ServerId,
            _job_id: JobId,
            _tc: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            // Status must include reservations even before a JobDetail exists.
            let status = self.0.handle_status()?;
            assert_eq!(status.in_progress, 1);
            assert_eq!(status.available_jobs, status.max_jobs - 1);
            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    struct SnapshotDuringAssign<'a> {
        scheduler: &'a Scheduler,
        nonce: ServerNonce,
    }

    impl SchedulerOutgoing for SnapshotDuringAssign<'_> {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            _tc: Toolchain,
            _auth: String,
        ) -> Result<AssignJobResult> {
            let snapshot = self.scheduler.handle_heartbeat_server(
                server_id,
                self.nonce.clone(),
                1.0,
                &[],
                Box::new(TestJobAuthorizer),
            )?;
            assert_eq!(snapshot.assigned_job_ids, vec![job_id]);
            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    #[test]
    fn heartbeat_reports_inflight_and_accepted_assignments() -> Result<()> {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse()?;
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } = scheduler.handle_alloc_job(
            &SnapshotDuringAssign {
                scheduler: &scheduler,
                nonce: nonce.clone(),
            },
            test_toolchain('c'),
        )?
        else {
            panic!("expected job allocation");
        };
        let snapshot = scheduler.handle_heartbeat_server(
            server_id,
            nonce.clone(),
            1.0,
            &[],
            Box::new(TestJobAuthorizer),
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
        )?;
        assert!(snapshot.assigned_job_ids.is_empty());
        Ok(())
    }

    #[test]
    fn status_counts_assignment_rpc_reservations() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        register_test_server(&scheduler, server_id, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&StatusDuringAssign(&scheduler), test_toolchain('c'))
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

    #[test]
    fn idle_workers_receive_jobs_proportional_to_cpu_capacity() {
        let scheduler = Scheduler::new();
        let ids: Vec<ServerId> = ["127.0.0.1:10501", "127.0.0.2:10501", "127.0.0.3:10501"]
            .into_iter()
            .map(|s| s.parse().unwrap())
            .collect();

        for (&id, capacity) in ids.iter().zip([1.0, 3.0, 0.0]) {
            scheduler
                .handle_heartbeat_server(
                    id,
                    ServerNonce::new(),
                    capacity,
                    &[],
                    Box::new(TestJobAuthorizer),
                )
                .unwrap();
        }

        let mut observed = Vec::new();
        for _ in 0..1024 {
            let result = scheduler
                .handle_alloc_job(&AcceptAssign, test_toolchain('b'))
                .unwrap();
            let AllocJobResult::Success { job_alloc, .. } = result else {
                panic!("eligible idle workers must accept a job");
            };
            observed.push(job_alloc.server_id);
            for state in [JobState::Ready, JobState::Started, JobState::Complete] {
                scheduler
                    .handle_update_job_state(job_alloc.job_id, job_alloc.server_id, state)
                    .unwrap();
            }
        }

        let first = observed
            .iter()
            .filter(|&&selected| selected == ids[0])
            .count();
        assert!(
            (210..=350).contains(&first),
            "first worker received {first} jobs"
        );
        let busy = observed
            .iter()
            .filter(|&&selected| selected == ids[2])
            .count();
        assert!(
            (40..=150).contains(&busy),
            "busy worker received {busy} jobs"
        );
    }

    #[test]
    fn maintenance_drain_refuses_new_allocations_without_creating_job_state() {
        let dir = tempfile::tempdir().unwrap();
        let drain = dir.path().join("scheduler-drain");
        let scheduler =
            Scheduler::new_with_job_slack_and_drain(JobSlackConfig::default(), Some(drain.clone()));
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        register_test_server(&scheduler, server_id, ServerNonce::new());

        std::fs::write(&drain, b"drain").unwrap();
        assert!(scheduler.handle_is_draining());
        assert_eq!(scheduler.handle_status().unwrap().available_jobs, 0);
        let allocation = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
            .unwrap();
        assert!(matches!(allocation, AllocJobResult::Fail { .. }));
        assert_no_assigned_jobs(&scheduler, &server_id);

        std::fs::remove_file(&drain).unwrap();
        assert!(!scheduler.handle_is_draining());
        let allocation = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
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

    impl SchedulerOutgoing for ReapDuringAssign<'_> {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            _tc: Toolchain,
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
            )?;
            assert!(!heartbeat.is_new);

            Ok(AssignJobResult {
                state: JobState::Pending,
                need_toolchain: false,
            })
        }
    }

    #[test]
    fn ready_transition_starts_its_own_unclaimed_timeout() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());

        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
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
            .handle_heartbeat_server(server_id, nonce, 1.0, &[], Box::new(TestJobAuthorizer))
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[test]
    fn pending_jobs_expire_but_started_jobs_remain_owned_by_execution() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());

        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
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
            )
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);

        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
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
            .handle_heartbeat_server(server_id, nonce, 1.0, &[], Box::new(TestJobAuthorizer))
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
    }

    #[test]
    fn failed_token_generation_never_reserves_capacity() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        scheduler
            .handle_heartbeat_server(
                server_id,
                ServerNonce::new(),
                1.0,
                &[],
                Box::new(RejectToken),
            )
            .unwrap();
        assert!(
            scheduler
                .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
                .is_err()
        );
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[test]
    fn completion_without_assignment_does_not_discard_job() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        register_test_server(&scheduler, server_id, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('c'))
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
                .insert(job_alloc.job_id);
        }
        scheduler
            .handle_update_job_state(job_alloc.job_id, server_id, JobState::Complete)
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[test]
    fn started_jobs_reconcile_against_worker_running_inventory() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('d'))
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
            .handle_heartbeat_server(server_id, nonce, 1.0, &[], Box::new(TestJobAuthorizer))
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

    #[test]
    fn only_the_completing_worker_can_retry_a_known_completion() -> Result<()> {
        let scheduler = Scheduler::new();
        let owner: ServerId = "127.0.0.1:10501".parse()?;
        let other: ServerId = "127.0.0.1:10502".parse()?;
        register_test_server(&scheduler, owner, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } =
            scheduler.handle_alloc_job(&AcceptAssign, test_toolchain('f'))?
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
        let owner: ServerId = "127.0.0.1:10501".parse()?;
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

    #[test]
    fn returned_running_job_resets_missing_heartbeat_grace() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let nonce = ServerNonce::new();
        register_test_server(&scheduler, server_id, nonce.clone());
        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('d'))
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
            .handle_heartbeat_server(server_id, nonce, 1.0, &[], Box::new(TestJobAuthorizer))
            .unwrap();
        assert!(scheduler.jobs.lock().unwrap().contains_key(&job_id));
        scheduler
            .handle_update_job_state(job_id, server_id, JobState::Complete)
            .unwrap();
        assert_no_assigned_jobs(&scheduler, &server_id);
    }

    #[test]
    fn state_acknowledgments_are_idempotent() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        register_test_server(&scheduler, server_id, ServerNonce::new());
        let AllocJobResult::Success { job_alloc, .. } = scheduler
            .handle_alloc_job(&AcceptAssign, test_toolchain('d'))
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
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let nonce = ServerNonce::new();
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                8.0,
                &[],
                Box::new(TestJobAuthorizer),
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
            )
            .unwrap();
        assert!(heartbeat.is_new);
        assert_eq!(scheduler.handle_get_worker_name(server_id).unwrap(), None);
    }

    #[test]
    fn duplicate_active_worker_names_are_rejected() {
        let scheduler = Scheduler::new();
        let first: ServerId = "127.0.0.1:10501".parse().unwrap();
        let second: ServerId = "127.0.0.2:10501".parse().unwrap();
        let first_nonce = ServerNonce::new();
        let second_nonce = ServerNonce::new();
        for (server_id, nonce) in [(first, first_nonce.clone()), (second, second_nonce.clone())] {
            scheduler
                .handle_heartbeat_server(server_id, nonce, 8.0, &[], Box::new(TestJobAuthorizer))
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
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let nonce = ServerNonce::new();
        scheduler
            .handle_heartbeat_server(
                server_id,
                nonce.clone(),
                8.0,
                &[],
                Box::new(TestJobAuthorizer),
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

    #[test]
    fn allocation_fails_if_assignment_is_cleaned_up() {
        let scheduler = Scheduler::new();
        let server_id: ServerId = "127.0.0.1:10501".parse().unwrap();
        let server_nonce = ServerNonce::new();

        register_test_server(&scheduler, server_id, server_nonce.clone());

        let requester = ReapDuringAssign {
            scheduler: &scheduler,
            server_id,
            server_nonce,
        };
        let allocation = scheduler
            .handle_alloc_job(&requester, test_toolchain('c'))
            .unwrap();

        assert!(matches!(allocation, AllocJobResult::Fail { .. }));
        assert_no_assigned_jobs(&scheduler, &server_id);
    }
}

#[cfg(test)]
mod server_upload_tests {
    use super::*;
    use sccache::util::Digest;
    use std::io::{self, Cursor, Read};
    use std::sync::{Arc, mpsc};
    use std::thread;

    struct NoopBuilder;

    impl BuilderIncoming for NoopBuilder {
        fn run_build(
            &self,
            _toolchain: Toolchain,
            _command: CompileCommand,
            _outputs: OutputRequest,
            _inputs_rdr: InputsReader<'_>,
            _cache: &Mutex<TcCache>,
        ) -> Result<sccache::dist::BuildResult> {
            unreachable!("upload tests must never execute a compile");
        }
    }

    struct RecordingRequester(Mutex<Vec<JobState>>);

    impl ServerOutgoing for RecordingRequester {
        fn do_update_job_state(
            &self,
            _job_id: JobId,
            state: JobState,
        ) -> Result<UpdateJobStateResult> {
            self.0.lock().unwrap().push(state);
            Ok(UpdateJobStateResult::Success)
        }
    }

    fn test_server() -> Result<(tempfile::TempDir, Arc<Server>)> {
        let dir = tempfile::tempdir()?;
        let server = Server::new(Box::new(NoopBuilder), dir.path(), 1024 * 1024, vec![])?;
        Ok((dir, Arc::new(server)))
    }

    fn tc(contents: &[u8]) -> Result<Toolchain> {
        Ok(Toolchain {
            archive_id: sccache::dist::ArchiveId::try_from(Digest::reader_sync(contents)?)?,
        })
    }

    struct PausingReader {
        sent: bool,
        started: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
        inner: Cursor<Vec<u8>>,
    }

    impl Read for PausingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.sent {
                self.sent = true;
                self.started.send(()).unwrap();
                self.resume.recv().unwrap();
            }
            self.inner.read(buf)
        }
    }

    #[test]
    fn reconcile_removes_only_stale_unclaimed_assignments() -> Result<()> {
        let (_dir, server) = test_server()?;
        for id in [JobId(41), JobId(42)] {
            server.handle_assign_job(id, tc(b"older toolchain")?)?;
        }
        let heartbeat_started_at = Instant::now();
        // This assignment arrived after the heartbeat began and may be
        // legitimately absent from the scheduler's earlier snapshot.
        server.handle_assign_job(JobId(43), tc(b"new toolchain")?)?;

        assert_eq!(
            server.handle_reconcile_assignments(&[JobId(42)], heartbeat_started_at)?,
            1
        );
        {
            let jobs = server.job_toolchains.lock().unwrap();
            assert!(!jobs.contains_key(&JobId(41)));
            assert!(jobs.contains_key(&JobId(42)));
            assert!(jobs.contains_key(&JobId(43)));
        }
        let next_heartbeat = Instant::now();
        assert_eq!(
            server.handle_reconcile_assignments(&[JobId(43)], next_heartbeat)?,
            1
        );
        let jobs = server.job_toolchains.lock().unwrap();
        assert!(!jobs.contains_key(&JobId(42)));
        assert!(jobs.contains_key(&JobId(43)));
        Ok(())
    }

    #[test]
    fn removed_job_does_not_publish_ready_after_upload_finishes() -> Result<()> {
        let (_dir, server) = test_server()?;
        let job_id = JobId(71);
        let bytes = b"toolchain still uploading";
        server.handle_assign_job(job_id, tc(bytes)?)?;

        let (started_tx, started_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let uploader = Arc::clone(&server);
        let upload = thread::spawn(move || {
            let requester = RecordingRequester(Mutex::new(Vec::new()));
            let reader = PausingReader {
                sent: false,
                started: started_tx,
                resume: resume_rx,
                inner: Cursor::new(bytes.to_vec()),
            };
            let outcome = uploader.handle_submit_toolchain(
                &requester,
                job_id,
                ToolchainReader::new(Box::new(reader)),
            );
            (outcome, requester.0.lock().unwrap().clone())
        });
        started_rx.recv_timeout(Duration::from_secs(5))?;

        let removed = server.handle_reconcile_assignments(&[], Instant::now())?;
        // Always release the upload, even if the expected cleanup failed.
        resume_tx.send(())?;
        let (outcome, published) = upload.join().unwrap();
        assert_eq!(removed, 1);
        assert!(matches!(outcome?, SubmitToolchainResult::JobNotFound));
        assert!(published.is_empty());
        Ok(())
    }

    #[test]
    fn unknown_run_does_not_publish_any_job_state() -> Result<()> {
        let (_dir, server) = test_server()?;
        let requester = RecordingRequester(Mutex::new(Vec::new()));
        let result = server.handle_run_job(
            &requester,
            JobId(999),
            CompileCommand {
                executable: "cc".to_owned(),
                arguments: Vec::new(),
                env_vars: Vec::new(),
                cwd: "/tmp".to_owned(),
            },
            OutputRequest {
                paths: Vec::new(),
                compression_level: 3,
            },
            InputsReader::new(Box::new(Cursor::new(Vec::new()))),
        )?;
        assert!(matches!(result, RunJobResult::JobNotFound));
        assert!(requester.0.lock().unwrap().is_empty());
        Ok(())
    }

    struct RejectStartRequester;
    impl ServerOutgoing for RejectStartRequester {
        fn do_update_job_state(
            &self,
            _job_id: JobId,
            _state: JobState,
        ) -> Result<UpdateJobStateResult> {
            bail!("synthetic failure to acknowledge Started")
        }
    }

    #[test]
    fn failed_started_ack_restores_unclaimed_local_job() -> Result<()> {
        let (_dir, server) = test_server()?;
        let job_id = JobId(42);
        let toolchain = tc(b"custom toolchain")?;
        server.handle_assign_job(job_id, toolchain.clone())?;
        let failed = server.handle_run_job(
            &RejectStartRequester,
            job_id,
            CompileCommand {
                executable: "cc".to_owned(),
                arguments: Vec::new(),
                env_vars: Vec::new(),
                cwd: "/tmp".to_owned(),
            },
            OutputRequest {
                paths: Vec::new(),
                compression_level: 3,
            },
            InputsReader::new(Box::new(Cursor::new(Vec::new()))),
        );
        assert!(failed.is_err());
        assert_eq!(
            server
                .job_toolchains
                .lock()
                .unwrap()
                .get(&job_id)
                .map(|assigned| &assigned.toolchain),
            Some(&toolchain)
        );
        Ok(())
    }

    #[test]
    fn assignments_are_not_blocked_by_in_progress_toolchain_uploads() -> Result<()> {
        let (_dir, server) = test_server()?;
        let first = b"first valid toolchain archive";
        server.handle_assign_job(JobId(41), tc(first)?)?;
        let (started_tx, started_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let uploader = Arc::clone(&server);
        let upload = thread::spawn(move || {
            let requester = RecordingRequester(Mutex::new(Vec::new()));
            let reader = PausingReader {
                sent: false,
                started: started_tx,
                resume: resume_rx,
                inner: Cursor::new(first.to_vec()),
            };
            let outcome = uploader.handle_submit_toolchain(
                &requester,
                JobId(41),
                ToolchainReader::new(Box::new(reader)),
            );
            (outcome, requester.0.lock().unwrap().clone())
        });
        started_rx.recv_timeout(Duration::from_secs(5))?;

        let second_server = Arc::clone(&server);
        let (assignment_tx, assignment_rx) = mpsc::channel();
        let assignment = thread::spawn(move || {
            let result =
                second_server.handle_assign_job(JobId(42), tc(b"second toolchain").unwrap());
            assignment_tx.send(result).unwrap();
        });
        // Release the upload after checking the other assignment, even when
        // the assertion fails, so the test never leaves a blocked thread.
        let not_blocked = assignment_rx.recv_timeout(Duration::from_secs(2));
        resume_tx.send(())?;
        assignment.join().unwrap();
        let (upload_result, states) = upload.join().unwrap();
        assert!(
            not_blocked.is_ok(),
            "assignment was blocked by another toolchain's upload"
        );
        assert!(matches!(upload_result?, SubmitToolchainResult::Success));
        assert_eq!(states, vec![JobState::Ready]);
        Ok(())
    }

    #[test]
    fn corrupt_toolchain_is_not_published_as_ready_or_cached() -> Result<()> {
        let (_dir, server) = test_server()?;
        let expected = tc(b"expected")?;
        server.handle_assign_job(JobId(43), expected.clone())?;
        let requester = RecordingRequester(Mutex::new(Vec::new()));
        let result = server.handle_submit_toolchain(
            &requester,
            JobId(43),
            ToolchainReader::new(Box::new(Cursor::new(b"wrong".to_vec()))),
        )?;
        assert!(matches!(result, SubmitToolchainResult::CannotCache));
        assert!(requester.0.lock().unwrap().is_empty());
        assert!(!server.cache.lock().unwrap().contains_toolchain(&expected));
        Ok(())
    }

    #[test]
    fn oversized_archive_is_rejected_without_publishing_ready() -> Result<()> {
        let (_dir, server) = test_server()?;
        let bytes = vec![7; 1024 * 1024 + 1];
        let expected = tc(&bytes)?;
        server.handle_assign_job(JobId(44), expected.clone())?;
        let requester = RecordingRequester(Mutex::new(Vec::new()));
        let result = server.handle_submit_toolchain(
            &requester,
            JobId(44),
            ToolchainReader::new(Box::new(Cursor::new(bytes))),
        )?;
        assert!(matches!(result, SubmitToolchainResult::CannotCache));
        assert!(requester.0.lock().unwrap().is_empty());
        assert!(!server.cache.lock().unwrap().contains_toolchain(&expected));
        Ok(())
    }
}
