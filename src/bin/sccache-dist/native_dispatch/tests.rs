use super::*;
use sccache::{
    build_runtime::{
        BuildPath, CommandSpec, ContentId, ExecutionRoot, ExecutionSpec, SpacePolicy, TreeId,
        TreeMetadata, TreeRecipe, TreeTimestamp, wire::Ticket,
    },
    config::{HTTPUrl, server::NativeWorkerConfig},
};
use std::{collections::BTreeMap, num::NonZeroUsize};

fn worker(
    root: &std::path::Path,
    url: reqwest::Url,
    peer: Arc<sccache_cluster_identity::PeerCredentials>,
) -> Result<NativeWorker> {
    NativeWorker::new(
        NativeWorkerConfig {
            cache_url: HTTPUrl::from_url(url),
            directory: root.join("store"),
            space: SpacePolicy {
                min_available_bytes: 1 << 20,
                target_available_bytes: 2 << 20,
                max_resident_bytes: 1 << 30,
                target_resident_bytes: 1 << 29,
                max_evictions_per_pass: 8,
                gc_batch: 16,
            },
            scratch: root.join("scratch"),
            bubblewrap: "/usr/bin/bwrap".into(),
            platform_contract: "dispatch-test".into(),
            renewal_interval_secs: 1,
            request_timeout_secs: 5,
            execution_timeout_secs: 5,
            max_result_bytes: 1024,
            max_metadata_bytes: 1 << 20,
            artifact_grace_secs: 300,
            artifact_grace_bytes: None,
            max_inflight_jobs: NonZeroUsize::new(2),
            package_import: None,
            package_transfer: Default::default(),
        },
        peer,
    )
}

fn assignment(marker: u8) -> Result<NativeAssignment> {
    Ok(NativeAssignment {
        estimated_result_bytes: None,
        ticket: Ticket([marker; 32]),
        input_blobs: BTreeMap::new(),
        spec: ExecutionSpec {
            platform: ContentId::of(b"dispatch-test"),
            root: ExecutionRoot {
                id: TreeId([0; 32]),
                recipe: TreeRecipe::union(
                    TreeMetadata {
                        mode: 0o755,
                        modified: TreeTimestamp {
                            seconds: 1,
                            nanoseconds: 0,
                        },
                    },
                    [TreeId([0; 32])],
                ),
            },
            mounts: BTreeMap::new(),
            command: CommandSpec {
                umask: 0o022,
                executable: BuildPath::new(b"/bin/tool".to_vec())?,
                arguments: Vec::new(),
                cwd: BuildPath::new(b"/".to_vec())?,
                environment: BTreeMap::new(),
            },
            outputs: BTreeMap::new(),
        },
    })
}

struct RecordingRequester {
    states: mpsc::Sender<(JobId, JobState)>,
}

impl ServerOutgoing for RecordingRequester {
    fn do_update_job_state(&self, id: JobId, state: JobState) -> Result<UpdateJobStateResult> {
        self.states.send((id, state))?;
        Ok(UpdateJobStateResult::Success)
    }
}

fn active_jobs(dispatcher: &NativeDispatcher) -> Vec<JobId> {
    dispatcher
        .snapshot()
        .jobs
        .into_iter()
        .filter_map(|(id, job)| job.phase.active().then_some(id))
        .collect()
}

fn terminal(dispatcher: &NativeDispatcher, id: JobId) -> Result<NativeRunResult> {
    let started = Instant::now();
    loop {
        let result = dispatcher.poll(id, NativeRunRequest::Poll)?;
        if !matches!(result, NativeRunResult::Pending(_)) {
            return Ok(result);
        }
        ensure!(
            started.elapsed() < Duration::from_secs(5),
            "dispatcher did not finish"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn native_dispatcher_assignment_starts_before_poll_but_after_delegation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (verification_tx, verification_rx) = mpsc::channel();
    let (delegation_tx, delegation_rx) = mpsc::channel::<u16>();
    let delegation_rx = Mutex::new(delegation_rx);
    // Model a scheduler which holds its admission lock until the worker
    // returns the assignment response. Verification is deliberately blocked.
    use http_body_util::{BodyExt, Full};
    use sccache_cluster_identity::{
        ClusterCa, ClusterListener, EnrollmentAuthority, Identity, PeerConfig, Registry, Role,
        SchedulerEnrollment, TlsCredentials,
    };
    let cluster = directory.path().join("cluster");
    std::fs::create_dir_all(&cluster)?;
    let authority = EnrollmentAuthority::new(
        ClusterCa::open(&cluster.join("ca-key.pem"))?,
        Registry::open(&cluster.join("registry.bin"))?,
        7,
    )?;
    let identity = Identity::open(&cluster.join("key.pem"))?;
    let scheduler_id = identity.id()?;
    let leaf = authority.scheduler_certificate(&identity)?;
    let ca_certificate = cluster.join("ca.pem");
    sccache_cluster_identity::publish_trust_anchor(authority.certificate(), &ca_certificate)?;
    let credentials = TlsCredentials::new(
        identity,
        leaf,
        authority.certificate().clone(),
        Role::Scheduler,
    )?;
    let tls = Arc::new(ClusterListener::new(&credentials)?);
    let enrollment = Arc::new(SchedulerEnrollment::new(authority, |role, _, _, token| {
        role == Role::Worker && token == "test"
    }));
    let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
    socket.set_nonblocking(true)?;
    let url = reqwest::Url::parse(&format!("https://{}/", socket.local_addr()?))?;
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let delegation_rx = Arc::new(delegation_rx);
    let handle = thread::spawn(move || -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        rt.block_on(async move {
            let socket = tokio::net::TcpListener::from_std(socket)?;
            loop {
                let (connection, _) = tokio::select! {
                    result = socket.accept() => result?,
                    _ = &mut stopped => return Ok(()),
                };
                let tls = Arc::clone(&tls);
                let enrollment = Arc::clone(&enrollment);
                let verification_tx = verification_tx.clone();
                let delegation_rx = Arc::clone(&delegation_rx);
                tokio::spawn(async move {
                    let _ = tls
                        .serve_scheduler(connection, enrollment, move |peer, request| {
                            let verification_tx = verification_tx.clone();
                            let delegation_rx = Arc::clone(&delegation_rx);
                            async move {
                                let status = if peer.role() != Role::Worker {
                                    401
                                } else {
                                    match request.uri().path() {
                                        "/api/v5/native/worker/verify" => {
                                            let id = request
                                                .headers()
                                                .get("X-Sccache-Native-Job")
                                                .and_then(|value| value.to_str().ok())
                                                .and_then(|job| job.parse::<u64>().ok());
                                            match id {
                                                Some(id)
                                                    if verification_tx.send(JobId(id)).is_ok() =>
                                                {
                                                    tokio::task::spawn_blocking(move || {
                                                        delegation_rx
                                                            .lock()
                                                            .unwrap()
                                                            .recv_timeout(Duration::from_secs(5))
                                                            .unwrap_or(503)
                                                    })
                                                    .await
                                                    .unwrap_or(503)
                                                }
                                                _ => 400,
                                            }
                                        }
                                        "/api/v5/native/worker/renew"
                                        | "/api/v5/native/worker/fail" => 200,
                                        _ => 409,
                                    }
                                };
                                let mut response = hyper::Response::new(
                                    Full::new(bytes::Bytes::new())
                                        .map_err(|never| match never {})
                                        .boxed_unsync(),
                                );
                                *response.status_mut() =
                                    hyper::StatusCode::from_u16(status).unwrap();
                                response
                            }
                        })
                        .await;
                });
            }
        })
    });
    let peer = sccache::dist::cluster::open_peer(
        PeerConfig {
            directory: cluster.join("worker"),
            ca_certificate,
            scheduler_id,
        },
        &url,
        Role::Worker,
        "test",
    )?;
    let result = (|| -> Result<()> {
        let queue = Arc::new(ExecutionQueue::new(NonZeroUsize::MIN));
        let dispatcher =
            NativeDispatcher::new(worker(directory.path(), url, peer)?, Arc::clone(&queue))?;
        let (state_tx, states) = mpsc::channel();
        let requester: Arc<dyn ServerOutgoing> = Arc::new(RecordingRequester { states: state_tx });
        let first = JobId(1);
        let second = JobId(2);
        let third = JobId(3);
        dispatcher.assign(first, assignment(1)?, Arc::clone(&requester))?;
        // No client status request has been issued.
        assert_eq!(verification_rx.recv_timeout(Duration::from_secs(5))?, first);
        assert!(states.try_recv().is_err());
        assert_eq!(queue.active(), 0);
        dispatcher.assign(second, assignment(2)?, Arc::clone(&requester))?;
        assert!(
            dispatcher
                .assign(third, assignment(3)?, Arc::clone(&requester))
                .is_err()
        );
        for id in [first, second] {
            assert_eq!(
                dispatcher.poll(id, NativeRunRequest::Poll)?,
                NativeRunResult::Pending(NativeJobPhase::Queued)
            );
            assert_eq!(
                dispatcher.poll(id, NativeRunRequest::Poll)?,
                NativeRunResult::Pending(NativeJobPhase::Queued)
            );
        }
        assert_eq!(
            active_jobs(&dispatcher).into_iter().collect::<HashSet<_>>(),
            HashSet::from([first, second])
        );
        assert!(
            dispatcher
                .poll(first, NativeRunRequest::Acknowledge)
                .is_err()
        );
        assert!(verification_rx.try_recv().is_err());
        assert!(states.try_recv().is_err());

        // A cancellation of a queued job holds its reservation until its
        // stage drains, and never performs verification or starts a compiler.
        assert_eq!(
            dispatcher.reconcile(&HashSet::from([first]), Instant::now()),
            1
        );
        assert_eq!(
            dispatcher.reconcile(&HashSet::from([first]), Instant::now()),
            0
        );
        assert!(
            dispatcher
                .assign(third, assignment(3)?, Arc::clone(&requester))
                .is_err()
        );
        delegation_tx.send(200)?;
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (first, JobState::Started)
        );
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (first, JobState::Complete)
        );
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (second, JobState::Complete)
        );
        assert!(verification_rx.try_recv().is_err());

        for id in [first, second] {
            assert_eq!(terminal(&dispatcher, id)?, NativeRunResult::Unavailable);
            assert_eq!(
                dispatcher.poll(id, NativeRunRequest::Poll)?,
                NativeRunResult::Unavailable
            );
        }
        assert!(active_jobs(&dispatcher).is_empty());
        assert!(
            dispatcher
                .assign(third, assignment(3)?, Arc::clone(&requester))
                .is_err()
        );
        for _ in 0..2 {
            assert_eq!(
                dispatcher.poll(first, NativeRunRequest::Acknowledge)?,
                NativeRunResult::Acknowledged
            );
        }
        assert_eq!(
            dispatcher.poll(first, NativeRunRequest::Poll)?,
            NativeRunResult::JobNotFound
        );

        // An older heartbeat cannot cancel a new assignment. A scheduler
        // that declines delegation must never observe Started.
        let cutoff = Instant::now();
        dispatcher.assign(third, assignment(3)?, Arc::clone(&requester))?;
        assert_eq!(verification_rx.recv_timeout(Duration::from_secs(5))?, third);
        assert_eq!(dispatcher.reconcile(&HashSet::new(), cutoff), 0);
        assert!(states.try_recv().is_err());
        delegation_tx.send(409)?;
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (third, JobState::Complete)
        );
        assert_eq!(terminal(&dispatcher, third)?, NativeRunResult::Unavailable);
        assert!(states.try_recv().is_err());
        assert_eq!(queue.active(), 0);
        assert_eq!(
            dispatcher.poll(second, NativeRunRequest::Poll)?,
            NativeRunResult::Unavailable
        );
        dispatcher.poll(second, NativeRunRequest::Acknowledge)?;
        dispatcher.poll(third, NativeRunRequest::Acknowledge)?;
        Ok(())
    })();
    let _ = stop.send(());
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("test cache server panicked"))??;
    result
}

#[test]
fn native_dispatcher_reaps_only_expired_terminal_reservations() {
    let now = Instant::now();
    let mut entries = HashMap::new();
    for (id, state) in [
        (
            JobId(1),
            State::Terminal {
                result: Arc::new(Terminal::Stored),
                completed_at: now.checked_sub(RESULT_RETENTION).unwrap(),
            },
        ),
        (
            JobId(2),
            State::Terminal {
                result: Arc::new(Terminal::Unavailable),
                completed_at: now,
            },
        ),
        (JobId(3), State::Active(NativeJobPhase::Ready)),
    ] {
        entries.insert(
            id,
            Reservation {
                accepted_at: now,
                phase_since: now,
                remaining: RemainingInputs::default(),
                cancelled: Arc::new(AtomicBool::new(false)),
                state,
            },
        );
    }
    Shared::reap(&mut entries);
    assert!(!entries.contains_key(&JobId(1)));
    assert!(entries.contains_key(&JobId(2)));
    assert!(entries.contains_key(&JobId(3)));
}
