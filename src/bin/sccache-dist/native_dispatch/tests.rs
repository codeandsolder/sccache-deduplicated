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
    url: url::Url,
    peer: Arc<sccache_cluster_identity::PeerCredentials>,
) -> Result<NativeWorker> {
    NativeWorker::new(
        NativeWorkerConfig {
            cache_url: HTTPUrl::from_url(url),
            directory: Some(root.join("store")),
            space: Some(SpacePolicy {
                min_available_bytes: 1 << 20,
                target_available_bytes: 2 << 20,
                max_resident_bytes: 1 << 30,
                target_resident_bytes: 1 << 29,
                max_evictions_per_pass: 8,
                gc_batch: 16,
            }),
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
        None,
    )
}

fn assignment(marker: u8) -> Result<NativeAssignment> {
    Ok(NativeAssignment {
        trace: None,
        estimated_result_bytes: None,
        receiver: None,
        delivery_profile: None,
        ticket: Ticket([marker; 32]),
        input_blobs: BTreeMap::new(),
        spec: ExecutionSpec {
            compiler_result: None,
            working_inputs: Default::default(),
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

#[async_trait::async_trait]
impl ServerOutgoing for RecordingRequester {
    async fn do_update_job_state(
        &self,
        id: JobId,
        state: JobState,
    ) -> Result<UpdateJobStateResult> {
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
fn asynchronous_stage_pool_bounds_active_tasks_and_drains_on_close() -> Result<()> {
    use std::sync::atomic::AtomicUsize;
    let runtime = sccache::http_client::io_runtime()?;
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    let (started, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let pool = spawn_async_pool(runtime, 3, receiver, {
        let gate = Arc::clone(&gate);
        let active = Arc::clone(&active);
        let completed = Arc::clone(&completed);
        move |id| {
            let gate = Arc::clone(&gate);
            let active = Arc::clone(&active);
            let completed = Arc::clone(&completed);
            let started = started.clone();
            async move {
                active.fetch_add(1, Ordering::AcqRel);
                if started.send(id).is_ok()
                    && let Ok(permit) = gate.acquire().await
                {
                    permit.forget();
                    completed.fetch_add(1, Ordering::AcqRel);
                }
                active.fetch_sub(1, Ordering::AcqRel);
            }
        }
    });
    runtime.block_on(async {
        for id in 0..8 {
            sender.send(id).await?;
        }
        drop(sender);
        for _ in 0..3 {
            tokio::time::timeout(Duration::from_secs(5), observed.recv())
                .await?
                .context("stage task did not start")?;
        }
        assert_eq!(active.load(Ordering::Acquire), 3);
        assert!(observed.try_recv().is_err());
        gate.add_permits(8);
        tokio::time::timeout(Duration::from_secs(5), pool).await??;
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert_eq!(completed.load(Ordering::Acquire), 8);
        Ok::<_, anyhow::Error>(())
    })
}

#[test]
fn native_dispatcher_assignment_starts_before_poll_but_after_delegation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (verification_tx, verification_rx) = mpsc::channel();
    let mut delegation_tx = HashMap::new();
    let mut delegation_rx = HashMap::new();
    for id in [JobId(1), JobId(2), JobId(3)] {
        let (send, receive) = tokio::sync::oneshot::channel::<u16>();
        delegation_tx.insert(id, send);
        delegation_rx.insert(id, receive);
    }
    let delegation_rx = Mutex::new(delegation_rx);
    // Model a scheduler which holds its admission lock until the worker
    // returns the assignment response. Verification is deliberately blocked.
    use axum::{
        Router,
        extract::Extension,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use sccache_cluster_identity::{
        AuthenticatedPeer, ClusterCa, ClusterListener, EnrollmentAuthority, Identity, PeerConfig,
        Registry, Role, SchedulerEnrollment, TlsCredentials,
    };
    let cluster = directory.path().join("cluster");
    std::fs::create_dir_all(&cluster)?;
    let authority = EnrollmentAuthority::new(
        ClusterCa::open(&cluster.join("ca-key.pem"))?,
        Registry::initialize(&cluster.join("registry.bin"))?,
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
    let url = url::Url::parse(&format!("https://{}/", socket.local_addr()?))?;
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let delegation_rx = Arc::new(delegation_rx);
    let worker_status = |Extension(peer): Extension<AuthenticatedPeer>| async move {
        if peer.role() == Role::Worker {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        }
    };
    let router = Router::new()
        .route(
            "/api/v5/native/worker/verify",
            post(
                move |Extension(peer): Extension<AuthenticatedPeer>, headers: HeaderMap| {
                    let verification_tx = verification_tx.clone();
                    let delegation_rx = Arc::clone(&delegation_rx);
                    async move {
                        if peer.role() != Role::Worker {
                            return StatusCode::UNAUTHORIZED;
                        }
                        let Some(id) = headers
                            .get("x-sccache-native-job")
                            .and_then(|value| value.to_str().ok())
                            .and_then(|job| job.parse::<u64>().ok())
                        else {
                            return StatusCode::BAD_REQUEST;
                        };
                        if verification_tx.send(JobId(id)).is_err() {
                            return StatusCode::BAD_REQUEST;
                        }
                        let receive = delegation_rx.lock().unwrap().remove(&JobId(id));
                        let Some(receive) = receive else {
                            return StatusCode::CONFLICT;
                        };
                        let status = tokio::time::timeout(Duration::from_secs(5), receive)
                            .await
                            .ok()
                            .and_then(|result| result.ok())
                            .unwrap_or(503);
                        StatusCode::from_u16(status).unwrap()
                    }
                },
            ),
        )
        .route("/api/v5/native/worker/renew", post(worker_status))
        .route("/api/v5/native/worker/fail", post(worker_status))
        .fallback(|| async { StatusCode::CONFLICT });
    let router = tls.scheduler_router(enrollment, router)?;
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
                let router = router.clone();
                tokio::spawn(async move {
                    let _ = tls.serve(connection, router).await;
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
        || Ok("test".into()),
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
        // Despite one compiler and a blocked first authorization, the
        // second admitted job must be able to begin staging.
        assert_eq!(
            verification_rx.recv_timeout(Duration::from_secs(5))?,
            second
        );
        assert_eq!(dispatcher.snapshot().staging_slots, 2);
        assert_eq!(dispatcher.snapshot().publication_slots, 2);
        assert!(dispatcher.snapshot().valid());
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

        // A cancelled staging job keeps its reservation until the
        // outstanding authorization drains, and never starts a compiler.
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
        delegation_tx
            .remove(&second)
            .context("second authorization")?
            .send(409)
            .map_err(|_| anyhow::anyhow!("second authorization lost"))?;
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (second, JobState::Complete)
        );
        delegation_tx
            .remove(&first)
            .context("first authorization")?
            .send(200)
            .map_err(|_| anyhow::anyhow!("first authorization lost"))?;
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (first, JobState::Started)
        );
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (first, JobState::Complete)
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
        delegation_tx
            .remove(&third)
            .context("third authorization")?
            .send(409)
            .map_err(|_| anyhow::anyhow!("third authorization lost"))?;
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
                trace: None,
            },
        );
    }
    Shared::reap(&mut entries);
    assert!(!entries.contains_key(&JobId(1)));
    assert!(entries.contains_key(&JobId(2)));
    assert!(entries.contains_key(&JobId(3)));
}
