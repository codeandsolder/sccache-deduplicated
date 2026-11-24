use super::*;
use sccache::{
    build_runtime::{
        BuildPath, CommandSpec, ContentId, ExecutionRoot, ExecutionSpec, SpacePolicy, TreeId,
        TreeMetadata, TreeRecipe, TreeTimestamp, wire::Ticket,
    },
    config::{HTTPUrl, server::NativeWorkerConfig},
};
use std::{collections::BTreeMap, num::NonZeroUsize};

fn worker(root: &std::path::Path, url: reqwest::Url) -> Result<NativeWorker> {
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
            request_timeout_secs: 1,
            execution_timeout_secs: 5,
            max_result_bytes: 1024,
            max_metadata_bytes: 1 << 20,
            artifact_grace_secs: 300,
            artifact_grace_bytes: None,
            max_inflight_jobs: NonZeroUsize::new(2),
            package_import: None,
            package_transfer: Default::default(),
        },
        "test".into(),
    )
}

fn assignment(marker: u8) -> Result<NativeAssignment> {
    Ok(NativeAssignment {
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
                executable: BuildPath::new(b"/bin/tool".to_vec())?,
                arguments: Vec::new(),
                cwd: BuildPath::new(b"/".to_vec())?,
                environment: BTreeMap::new(),
            },
            outputs: BTreeMap::new(),
        },
    })
}

struct PausingRequester {
    states: mpsc::Sender<(JobId, JobState)>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ServerOutgoing for PausingRequester {
    fn do_update_job_state(&self, id: JobId, state: JobState) -> Result<UpdateJobStateResult> {
        self.states.send((id, state))?;
        if state == JobState::Started {
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))?;
        }
        Ok(UpdateJobStateResult::Success)
    }
}

fn terminal(
    dispatcher: &NativeDispatcher,
    requester: &Arc<dyn ServerOutgoing>,
    id: JobId,
) -> Result<NativeRunResult> {
    let started = Instant::now();
    loop {
        let result = dispatcher.poll(id, Arc::clone(requester), NativeRunRequest::Poll)?;
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
fn native_dispatcher_claim_is_nonblocking_and_replayable_with_bounded_reservations() -> Result<()> {
    let directory = tempfile::tempdir()?;
    // No successful transfer: exercise actual dispatcher failure/cleanup
    // without needing a compiler or a complete native scheduler.
    let server = rouille::Server::new("127.0.0.1:0", |_| {
        rouille::Response::text("test lease unavailable").with_status_code(409)
    })
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let url = reqwest::Url::parse(&format!("http://{}/", server.server_addr()))?;
    let (handle, stop) = server.stoppable();
    let result = (|| -> Result<()> {
        let queue = Arc::new(ExecutionQueue::new(NonZeroUsize::MIN));
        let dispatcher = NativeDispatcher::new(worker(directory.path(), url)?, Arc::clone(&queue))?;
        let (state_tx, states) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let requester: Arc<dyn ServerOutgoing> = Arc::new(PausingRequester {
            states: state_tx,
            release: Mutex::new(release_rx),
        });
        let first = JobId(1);
        let second = JobId(2);
        let third = JobId(3);
        dispatcher.assign(first, assignment(1)?)?;
        dispatcher.assign(second, assignment(2)?)?;
        assert!(dispatcher.assign(third, assignment(3)?).is_err());
        assert!(dispatcher.active_jobs().is_empty());

        assert_eq!(
            dispatcher.poll(first, Arc::clone(&requester), NativeRunRequest::Poll)?,
            NativeRunResult::Pending(NativeJobPhase::Queued)
        );
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (first, JobState::Started)
        );
        assert_eq!(
            dispatcher.poll(first, Arc::clone(&requester), NativeRunRequest::Poll)?,
            NativeRunResult::Pending(NativeJobPhase::Staging)
        );
        assert_eq!(
            dispatcher.poll(second, Arc::clone(&requester), NativeRunRequest::Poll)?,
            NativeRunResult::Pending(NativeJobPhase::Queued)
        );
        assert_eq!(
            dispatcher.poll(second, Arc::clone(&requester), NativeRunRequest::Poll)?,
            NativeRunResult::Pending(NativeJobPhase::Queued)
        );
        assert_eq!(
            dispatcher.active_jobs().into_iter().collect::<HashSet<_>>(),
            HashSet::from([first, second])
        );
        assert_eq!(queue.active(), 0);
        assert!(
            dispatcher
                .poll(first, Arc::clone(&requester), NativeRunRequest::Acknowledge)
                .is_err()
        );
        assert!(states.try_recv().is_err());

        // Queued cancellation cannot lose ownership of its reservation or
        // permit another job to exceed the bound before cleanup.
        assert_eq!(
            dispatcher.reconcile(&HashSet::from([first]), Instant::now()),
            0
        );
        assert!(dispatcher.assign(third, assignment(3)?).is_err());
        release.send(())?;
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (first, JobState::Complete)
        );
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (second, JobState::Started)
        );
        release.send(())?;
        assert_eq!(
            states.recv_timeout(Duration::from_secs(5))?,
            (second, JobState::Complete)
        );

        for id in [first, second] {
            assert_eq!(
                terminal(&dispatcher, &requester, id)?,
                NativeRunResult::Unavailable
            );
            assert_eq!(
                dispatcher.poll(id, Arc::clone(&requester), NativeRunRequest::Poll)?,
                NativeRunResult::Unavailable
            );
        }
        assert!(dispatcher.active_jobs().is_empty());
        assert!(dispatcher.assign(third, assignment(3)?).is_err());
        assert_eq!(
            dispatcher.poll(first, Arc::clone(&requester), NativeRunRequest::Acknowledge)?,
            NativeRunResult::Acknowledged
        );
        assert_eq!(
            dispatcher.poll(first, Arc::clone(&requester), NativeRunRequest::Acknowledge)?,
            NativeRunResult::Acknowledged
        );
        assert_eq!(
            dispatcher.poll(first, Arc::clone(&requester), NativeRunRequest::Poll)?,
            NativeRunResult::JobNotFound
        );
        let cutoff = Instant::now();
        dispatcher.assign(third, assignment(3)?)?;
        assert_eq!(dispatcher.reconcile(&HashSet::new(), cutoff), 0);
        assert_eq!(dispatcher.reconcile(&HashSet::new(), Instant::now()), 1);
        assert_eq!(
            dispatcher.poll(third, Arc::clone(&requester), NativeRunRequest::Poll)?,
            NativeRunResult::JobNotFound
        );
        assert_eq!(
            dispatcher.poll(second, Arc::clone(&requester), NativeRunRequest::Poll)?,
            NativeRunResult::Unavailable
        );
        dispatcher.poll(second, requester, NativeRunRequest::Acknowledge)?;
        Ok(())
    })();
    stop.send(()).map_err(|error| anyhow::anyhow!("{error}"))?;
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("test cache server panicked"))?;
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
