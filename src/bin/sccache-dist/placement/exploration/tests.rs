use super::*;
use crate::{Scheduler, scheduler_tests::TestJobAuthorizer};
use sccache::{
    build_runtime::{
        BlobResidency, ConcurrentCapacity, ContentId, NetworkSnapshot, PeerCapacity, SharedCapacity,
    },
    dist::{self, SchedulerIncoming, ServerNonce},
};

fn id(port: u16) -> ServerId {
    ServerId::from_digest(std::array::from_fn(|index| port.to_le_bytes()[index % 2]))
}

fn peer(port: u16) -> Peer {
    Peer::Worker(id(port))
}

fn capacity(remaining: u64) -> PeerCapacity {
    PeerCapacity {
        observed_bytes_per_second: 100_000_000,
        isolated_bytes_per_second: 100_000_000,
        wire_per_mille: 1000,
        active_remaining_bytes: remaining,
        body_bytes: 0,
    }
}

fn register(
    scheduler: &Scheduler,
    server: ServerId,
    placement: dist::NativePlacement,
) -> anyhow::Result<()> {
    scheduler.handle_heartbeat_server(
        server,
        ServerNonce::new(),
        4.0,
        &[],
        Box::new(TestJobAuthorizer),
        dist::WorkerCapabilities {
            archive: false,
            native_platform: Some(ContentId::of(b"test")),
            native_placement: Some(placement),
        },
    )?;
    Ok(())
}

fn demand() -> NativeInputBlobs {
    BTreeMap::from([(ContentId::of(b"already demanded"), 200_000_000)])
}

fn network() -> NetworkSnapshot {
    NetworkSnapshot {
        send: DirectionSnapshot {
            peers: BTreeMap::from([(peer(1), capacity(400_000_000)), (peer(2), capacity(0))]),
            ..DirectionSnapshot::default()
        },
        receive: DirectionSnapshot::default(),
    }
}

#[test]
fn native_exploration_prefers_a_real_near_equivalent_unanswered_overlap_once() -> anyhow::Result<()>
{
    let scheduler = Scheduler::new();
    for server in [id(1), id(2)] {
        register(&scheduler, server, dist::NativePlacement::default())?;
    }
    let servers = scheduler.servers.lock().unwrap();
    let network = network();
    let plan = NativeTransferPlan::new(&network, &servers, None, None);
    let mut history = Exploration::default();
    let now = Instant::now();
    let options = [(id(1), 3.0), (id(2), 3.01)];
    assert_eq!(
        choose_worker(
            &options,
            &servers,
            &demand(),
            &BTreeMap::new(),
            &plan,
            &mut history,
            now
        ),
        Some(id(2))
    );
    assert_eq!(history.attempts.len(), 1);
    assert_eq!(
        choose_worker(
            &options,
            &servers,
            &demand(),
            &BTreeMap::new(),
            &plan,
            &mut history,
            now
        ),
        Some(id(1))
    );
    assert_eq!(
        choose_worker(
            &options,
            &servers,
            &demand(),
            &BTreeMap::new(),
            &plan,
            &mut history,
            now + COOLDOWN
        ),
        Some(id(2))
    );
    Ok(())
}

#[test]
fn native_exploration_never_increases_required_payload_or_exceeds_eta_budget() -> anyhow::Result<()>
{
    let scheduler = Scheduler::new();
    let requested = demand();
    let mut warm = dist::NativePlacement::default();
    let mut filter = BlobResidency::for_count(1).unwrap();
    for &blob in requested.keys() {
        filter.insert(blob);
    }
    warm.residency = Some(filter);
    register(&scheduler, id(1), warm)?;
    register(&scheduler, id(2), dist::NativePlacement::default())?;
    let network = network();
    let mut history = Exploration::default();
    let now = Instant::now();
    let options = [(id(1), 3.0), (id(2), 3.01)];
    {
        let servers = scheduler.servers.lock().unwrap();
        let plan = NativeTransferPlan::new(&network, &servers, None, None);
        assert_eq!(
            choose_worker(
                &options,
                &servers,
                &requested,
                &BTreeMap::new(),
                &plan,
                &mut history,
                now
            ),
            Some(id(1))
        );
    }
    register(&scheduler, id(1), dist::NativePlacement::default())?;
    let servers = scheduler.servers.lock().unwrap();
    let plan = NativeTransferPlan::new(&network, &servers, None, None);
    assert_eq!(
        choose_worker(
            &[(id(1), 3.0), (id(2), 3.03)],
            &servers,
            &requested,
            &BTreeMap::new(),
            &plan,
            &mut history,
            now
        ),
        Some(id(1))
    );
    assert!(history.attempts.is_empty());
    Ok(())
}

#[test]
fn native_exploration_skips_answered_or_unmeasurable_overlap() -> anyhow::Result<()> {
    let scheduler = Scheduler::new();
    for server in [id(1), id(2)] {
        register(&scheduler, server, dist::NativePlacement::default())?;
    }
    let servers = scheduler.servers.lock().unwrap();
    let mut network = network();
    let mut history = Exploration::default();
    let now = Instant::now();
    let options = [(id(1), 3.0), (id(2), 3.01)];
    network.send.independent.push(ConcurrentCapacity {
        rates: BTreeMap::from([(peer(1), 100_000_000), (peer(2), 100_000_000)]),
    });
    {
        let plan = NativeTransferPlan::new(&network, &servers, None, None);
        assert_eq!(
            choose_worker(
                &options,
                &servers,
                &demand(),
                &BTreeMap::new(),
                &plan,
                &mut history,
                now
            ),
            Some(id(1))
        );
    }
    network.send.independent.clear();
    network.send.shared.push(SharedCapacity {
        members: BTreeSet::from([peer(1), peer(2)]),
        bytes_per_second: 100_000_000,
    });
    {
        let plan = NativeTransferPlan::new(&network, &servers, None, None);
        assert_eq!(
            choose_worker(
                &options,
                &servers,
                &demand(),
                &BTreeMap::new(),
                &plan,
                &mut history,
                now
            ),
            Some(id(1))
        );
    }
    network.send.shared.clear();
    network
        .send
        .peers
        .get_mut(&peer(1))
        .unwrap()
        .active_remaining_bytes = 0;
    let plan = NativeTransferPlan::new(&network, &servers, None, None);
    assert_eq!(
        choose_worker(
            &options,
            &servers,
            &demand(),
            &BTreeMap::new(),
            &plan,
            &mut history,
            now
        ),
        Some(id(1))
    );
    assert!(history.attempts.is_empty());
    Ok(())
}

#[test]
fn native_exploration_accounts_for_future_upload_arrival_and_direction() {
    let mut snapshot = network().send;
    assert_eq!(
        question(&snapshot, Direction::Receive, peer(2), 200_000_000, 1.0),
        Some((Direction::Receive, BTreeSet::from([peer(1), peer(2)])))
    );
    assert!(question(&snapshot, Direction::Receive, peer(2), 200_000_000, 3.5).is_none());
    assert!(question(&snapshot, Direction::Send, peer(2), 1, 0.0).is_none());
    snapshot
        .peers
        .get_mut(&peer(2))
        .unwrap()
        .isolated_bytes_per_second = 0;
    assert!(question(&snapshot, Direction::Send, peer(2), 200_000_000, 0.0).is_none());
}

#[test]
fn native_exploration_checks_content_identity_not_only_equal_byte_counts() {
    let baseline = demand();
    let other = BTreeMap::from([(ContentId::of(b"unneeded on baseline worker"), 200_000_000)]);
    assert!(!no_extra_inputs(&other, &baseline));
    assert!(no_extra_inputs(&baseline, &baseline));
    assert!(no_extra_inputs(&BTreeMap::new(), &baseline));
}
