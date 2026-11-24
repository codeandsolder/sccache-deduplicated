use super::*;

fn worker(port: u16) -> Peer {
    Peer::Worker(SocketAddr::from(([127, 0, 0, 1], port)))
}

#[test]
fn planner_prefers_missing_individual_rates_then_group_and_respects_cooldown() {
    let now = Instant::now();
    let a = worker(1);
    let b = worker(2);
    let mut planner = Planner::new(now, PROBE_MIN_BYTES);
    planner.workers = BTreeMap::from([(a, now), (b, now)]);
    let empty = NetworkSnapshot::default();
    assert_eq!(
        planner.select(&empty, now, 2),
        Some((Direction::Send, BTreeSet::from([a])))
    );
    let calibrated = NetworkMeter::default();
    for peer in [a, b] {
        calibrated.observe_calibration_rate(Direction::Send, peer, 100_000_000);
        calibrated.observe_calibration_rate(Direction::Receive, peer, 10_000_000);
    }
    let network = empty.with_calibration(&calibrated.snapshot());
    let members = BTreeSet::from([a, b]);
    assert_eq!(
        planner.select(&network, now, 2),
        Some((Direction::Send, members.clone()))
    );
    planner
        .history
        .insert((Direction::Send, members.clone()), now + REFRESH_DELAY);
    assert_eq!(
        planner.select(&network, now, 2),
        Some((Direction::Receive, members.clone()))
    );
    planner
        .history
        .insert((Direction::Receive, members), now + REFRESH_DELAY);
    assert!(planner.select(&network, now, 2).is_none());
    assert!(
        planner
            .select(&network, now + POLL_FRESHNESS + Duration::from_secs(1), 2)
            .is_none()
    );
}

fn coordinator_with_round(direction: Direction) -> (ProbeCoordinator, Peer, Arc<Round>) {
    let now = Instant::now();
    let passive = Arc::new(NetworkMeter::default());
    let peer = worker(10501);
    let round = Arc::new(Round {
        id: 42,
        key: (direction, BTreeSet::from([peer])),
        permit: passive.idle_gate().permit(Duration::ZERO).unwrap(),
        starts: now,
        expires: now + PROBE_HTTP_TIMEOUT,
        meter: NetworkMeter::default(),
        budgets: BTreeMap::from([(peer, PROBE_MIN_BYTES)]),
        progress: Mutex::new(Progress {
            issued: BTreeSet::from([peer]),
            ..Progress::default()
        }),
    });
    let mut planner = Planner::new(now, PROBE_MIN_BYTES);
    planner.round = Some(Arc::clone(&round));
    let coordinator = ProbeCoordinator {
        passive,
        calibrated: Arc::new(NetworkMeter::default()),
        planner: Mutex::new(planner),
        max_bytes: PROBE_MIN_BYTES,
        parallelism: 2,
        active: Arc::new(AtomicUsize::new(0)),
    };
    (coordinator, peer, round)
}

#[test]
fn grant_is_bound_to_worker_direction_and_single_claim() -> Result<()> {
    let (coordinator, peer, round) = coordinator_with_round(Direction::Send);
    assert!(
        coordinator
            .stream(worker(2), 42, Direction::Send, io::repeat(0))
            .is_err()
    );
    assert!(
        coordinator
            .stream(peer, 41, Direction::Send, io::repeat(0))
            .is_err()
    );
    assert!(
        coordinator
            .stream(peer, 42, Direction::Receive, io::repeat(0))
            .is_err()
    );
    let mut stream = coordinator.stream(peer, 42, Direction::Send, ProbePayload::new(b"test"))?;
    assert!(
        coordinator
            .stream(peer, 42, Direction::Send, io::repeat(0))
            .is_err()
    );
    assert_eq!(io::copy(&mut stream, &mut io::sink())?, PROBE_MIN_BYTES);
    assert!(!round.complete());
    assert!(
        round
            .receipt(
                peer,
                ProbeReceipt {
                    round: 42,
                    bytes: 1,
                    elapsed_nanos: 1_000_000_000
                }
            )
            .is_err()
    );
    round.receipt(
        peer,
        ProbeReceipt {
            round: 42,
            bytes: PROBE_MIN_BYTES,
            elapsed_nanos: 1_000_000_000,
        },
    )?;
    assert!(round.complete());
    coordinator.tick();
    assert_eq!(
        coordinator.calibrated.snapshot().send.peers[&peer].observed_bytes_per_second,
        PROBE_MIN_BYTES
    );
    assert_eq!(coordinator.passive.snapshot().send.peers.len(), 0);
    assert_eq!(
        round.meter.snapshot().send.peers[&peer].body_bytes,
        PROBE_MIN_BYTES
    );
    Ok(())
}

#[test]
fn real_work_preempts_round_and_discards_partial_calibration() -> Result<()> {
    let (coordinator, peer, round) = coordinator_with_round(Direction::Send);
    let mut stream = coordinator.stream(peer, 42, Direction::Send, ProbePayload::new(b"test"))?;
    let mut buffer = [0; 32];
    stream.read_exact(&mut buffer)?;
    let _work = coordinator.passive.idle_gate().begin();
    assert_eq!(
        stream.read(&mut buffer).unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(!round.complete());
    coordinator.tick();
    assert!(coordinator.planner.lock().unwrap().round.is_none());
    assert!(coordinator.calibrated.snapshot().send.peers.is_empty());
    Ok(())
}

#[test]
fn network_only_rates_do_not_replace_passive_compression_or_processing() {
    let peer = worker(1);
    let calibrated = NetworkMeter::default();
    calibrated.observe_calibration_rate(Direction::Send, peer, 5_000_000);
    let snapshot = NetworkSnapshot::default().with_calibration(&calibrated.snapshot());
    assert_eq!(snapshot.send.rate(peer, 100_000_000), 5_000_000);
    assert_eq!(snapshot.send.logical_rate(peer, 100_000_000), 100_000_000);
    assert_eq!(snapshot.send.wire_bytes(peer, 1024), 1024);
    assert_eq!(snapshot.send.peers[&peer].active_remaining_bytes, 0);
    assert!(snapshot.receive.peers.is_empty());
}

#[test]
fn pairwise_refinement_requires_evidence_of_contention() {
    use crate::build_runtime::SharedCapacity;

    let now = Instant::now();
    let members = BTreeSet::from([worker(1), worker(2), worker(3)]);
    let mut planner = Planner::new(now, PROBE_MIN_BYTES);
    planner.workers = members.iter().map(|&peer| (peer, now)).collect();
    let calibration = NetworkMeter::default();
    for &peer in &members {
        calibration.observe_calibration_rate(Direction::Send, peer, 100_000_000);
        calibration.observe_calibration_rate(Direction::Receive, peer, 100_000_000);
    }
    let mut snapshot = NetworkSnapshot::default().with_calibration(&calibration.snapshot());
    for direction in [Direction::Send, Direction::Receive] {
        planner
            .history
            .insert((direction, members.clone()), now + REFRESH_DELAY);
    }
    assert!(planner.select(&snapshot, now, 3).is_none());
    snapshot.send.shared.push(SharedCapacity {
        members,
        bytes_per_second: 100_000_000,
    });
    assert_eq!(
        planner.select(&snapshot, now, 3),
        Some((Direction::Send, BTreeSet::from([worker(1), worker(2)])))
    );
}

#[test]
fn upload_dispatch_measures_actual_bytes_without_cas_insertion() -> Result<()> {
    let (coordinator, peer, round) = coordinator_with_round(Direction::Receive);
    let Peer::Worker(address) = peer else {
        anyhow::bail!("not a worker");
    };
    let mut body = codec().serialize(&42_u64)?;
    let mut payload = ProbePayload::new(b"upload").take(PROBE_MIN_BYTES);
    payload.read_to_end(&mut body)?;
    let request = Request::fake_http(
        "POST",
        "/api/v2/native/worker/probe_upload",
        Vec::new(),
        body,
    );
    let response = coordinator.dispatch(&request, address, "probe_upload", 1024)?;
    assert_eq!(response.status_code, 200);
    assert!(round.complete());
    assert_eq!(
        round.meter.snapshot().receive.peers[&peer].body_bytes,
        PROBE_MIN_BYTES
    );
    assert!(coordinator.passive.snapshot().receive.peers.is_empty());
    Ok(())
}

#[test]
fn native_calibration_http_route_authenticates_streams_and_never_populates_cas() -> Result<()> {
    use super::super::tests::with_native_service;
    use std::io::Cursor;

    for direction in [Direction::Send, Direction::Receive] {
        let (coordinator, peer, round) = coordinator_with_round(direction);
        let coordinator = Arc::new(coordinator);
        with_native_service(
            Arc::clone(&coordinator.passive),
            Some(Arc::clone(&coordinator)),
            |url, sessions, _network| {
                let http = reqwest::blocking::Client::builder()
                    .timeout(PROBE_HTTP_TIMEOUT)
                    .build()?;
                let request = |operation: &str, token: &str| -> Result<_> {
                    Ok(http
                        .post(url.join(&format!("/api/v2/native/worker/{operation}"))?)
                        .bearer_auth(token)
                        .header("Content-Type", "application/octet-stream"))
                };
                let header = codec().serialize(&42_u64)?;
                let operation = match direction {
                    Direction::Send => "probe_download",
                    Direction::Receive => "probe_upload",
                };
                let denied = request(operation, "client-token")?
                    .body(header.clone())
                    .send()?;
                assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);
                match direction {
                    Direction::Send => {
                        let response = request(operation, "worker-token")?
                            .body(header)
                            .send()?
                            .error_for_status()?;
                        let bytes =
                            io::copy(&mut response.take(PROBE_MIN_BYTES + 1), &mut io::sink())?;
                        assert_eq!(bytes, PROBE_MIN_BYTES);
                        let receipt = ProbeReceipt {
                            round: 42,
                            bytes,
                            elapsed_nanos: 1_000_000_000,
                        };
                        request("probe_receipt", "worker-token")?
                            .body(codec().serialize(&receipt)?)
                            .send()?
                            .error_for_status()?;
                    }
                    Direction::Receive => {
                        // Unknown-length body exercises the chunked upload path.
                        let body = reqwest::blocking::Body::new(
                            Cursor::new(header)
                                .chain(ProbePayload::new(b"upload").take(PROBE_MIN_BYTES)),
                        );
                        request(operation, "worker-token")?
                            .body(body)
                            .send()?
                            .error_for_status()?;
                    }
                }
                assert!(round.complete());
                let snapshot = round.meter.snapshot();
                let observed = match direction {
                    Direction::Send => &snapshot.send,
                    Direction::Receive => &snapshot.receive,
                };
                assert_eq!(observed.peers[&peer].body_bytes, PROBE_MIN_BYTES);
                assert_eq!(sessions.store().stats()?.blobs, 0);
                Ok(())
            },
        )?;
    }
    Ok(())
}

#[test]
fn stale_blocked_streams_cannot_exceed_global_probe_concurrency() -> Result<()> {
    let (coordinator, peer, _) = coordinator_with_round(Direction::Receive);
    let stream = coordinator.stream(peer, 42, Direction::Receive, io::repeat(0))?;
    let second = coordinator.acquire_slot()?;
    assert!(coordinator.acquire_slot().is_err());
    let work = coordinator.passive.idle_gate().begin();
    coordinator.tick();
    // Reaping a cancelled round does not free slots owned by open readers.
    assert!(coordinator.acquire_slot().is_err());
    drop(stream);
    let replacement = coordinator.acquire_slot()?;
    drop((second, replacement, work));
    assert_eq!(coordinator.active.load(Ordering::Acquire), 0);
    Ok(())
}
