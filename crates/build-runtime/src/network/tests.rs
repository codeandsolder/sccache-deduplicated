use super::*;

fn worker(port: u16) -> Peer {
    Peer::Worker(SocketAddr::from(([127, 0, 0, 1], port)))
}

fn feed(meter: &mut DirectionMeter, now: Instant, rates: &[(Peer, u64)]) {
    for (&peer, record) in &meter.peers {
        let mut activity = record.counters.activity.lock().unwrap();
        let rate = rates
            .iter()
            .find(|(id, _)| *id == peer)
            .map_or(0, |(_, rate)| *rate);
        if rate != 0 {
            activity.active = 1;
            record.counters.bytes.fetch_add(rate, Ordering::Relaxed);
        } else if activity.active != 0 {
            activity.active = 0;
            activity.idle_epoch += 1;
        }
    }
    meter.sample(now, Duration::from_secs(1));
}

#[test]
fn concurrent_windows_learn_directional_shared_capacity_and_reject_contradictions() {
    let a = worker(1);
    let b = worker(2);
    let start = Instant::now();
    let mut send = DirectionMeter::default();
    send.record(a, start);
    send.record(b, start);
    for second in 1..=3 {
        feed(
            &mut send,
            start + Duration::from_secs(second),
            &[(a, 100_000_000)],
        );
    }
    for second in 4..=6 {
        feed(
            &mut send,
            start + Duration::from_secs(second),
            &[(b, 100_000_000)],
        );
    }
    assert!(send.snapshot().shared.is_empty());
    for second in 7..=9 {
        feed(
            &mut send,
            start + Duration::from_secs(second),
            &[(a, 50_000_000), (b, 50_000_000)],
        );
    }
    // Initial transition is not a full concurrent observation.
    assert!(send.snapshot().shared.is_empty());
    feed(
        &mut send,
        start + Duration::from_secs(10),
        &[(a, 50_000_000), (b, 50_000_000)],
    );
    let learned = send.snapshot();
    assert_eq!(learned.shared.len(), 1);
    assert_eq!(learned.shared[0].bytes_per_second, 100_000_000);
    assert_eq!(learned.peers[&a].observed_bytes_per_second, 100_000_000);
    assert!(DirectionMeter::default().snapshot().shared.is_empty());
    feed(
        &mut send,
        start + Duration::from_secs(11),
        &[(a, 100_000_000), (b, 100_000_000)],
    );
    assert!(send.snapshot().shared.is_empty());
}

#[test]
fn low_demand_or_short_nonoverlapping_transfers_do_not_infer_a_ceiling() {
    let a = worker(1);
    let b = worker(2);
    let start = Instant::now();
    let mut meter = DirectionMeter::default();
    meter.record(a, start);
    meter.record(b, start);
    for second in 1..=12 {
        let active = if second % 2 == 0 { a } else { b };
        feed(
            &mut meter,
            start + Duration::from_secs(second),
            &[(active, 10_000_000)],
        );
    }
    for second in 13..=18 {
        feed(
            &mut meter,
            start + Duration::from_secs(second),
            &[(a, 5_000_000), (b, 5_000_000)],
        );
    }
    assert!(meter.snapshot().shared.is_empty());
}

#[test]
fn fair_sharing_reallocates_capacity_when_a_transfer_finishes() {
    let a = worker(1);
    let b = worker(2);
    let c = worker(3);
    let demand = |bytes| TransferDemand {
        bytes,
        bytes_per_second: 100_000_000,
    };
    let independent = DirectionSnapshot::default();
    let demands = BTreeMap::from([
        (a, demand(20_000_000)),
        (b, demand(200_000_000)),
        (c, demand(100_000_000)),
    ]);
    assert_eq!(independent.finish_times(&demands)[&b], 2.0);
    let shared = DirectionSnapshot {
        peers: BTreeMap::new(),
        independent: Vec::new(),
        shared: vec![SharedCapacity {
            members: BTreeSet::from([a, b]),
            bytes_per_second: 100_000_000,
        }],
    };
    let times = shared.finish_times(&demands);
    assert!((times[&a] - 0.4).abs() < 1e-9);
    assert!((times[&b] - 2.2).abs() < 1e-9);
    assert!((times[&c] - 1.0).abs() < 1e-9);
}

#[test]
fn overlapping_constraints_do_not_serialise_independent_paths() {
    let a = worker(1);
    let b = worker(2);
    let c = worker(3);
    let demands = [a, b, c]
        .into_iter()
        .map(|peer| {
            (
                peer,
                TransferDemand {
                    bytes: 100_000_000,
                    bytes_per_second: 100_000_000,
                },
            )
        })
        .collect();
    let network = DirectionSnapshot {
        peers: BTreeMap::new(),
        independent: Vec::new(),
        shared: vec![
            SharedCapacity {
                members: BTreeSet::from([a, b]),
                bytes_per_second: 60_000_000,
            },
            SharedCapacity {
                members: BTreeSet::from([b, c]),
                bytes_per_second: 100_000_000,
            },
        ],
    };
    let times = network.finish_times(&demands);
    assert!((times[&a] - 100.0 / 30.0).abs() < 1e-9);
    assert!((times[&b] - times[&a]).abs() < 1e-9);
    assert!((times[&c] - 100.0 / 70.0).abs() < 1e-9);
}

#[test]
fn metering_counts_encoded_bytes_and_clears_aborted_remaining() -> io::Result<()> {
    let peer = worker(1);
    let meter = NetworkMeter::default();
    let mut stream = meter.meter(Direction::Send, peer, &b"abc"[..], 10, None);
    let mut buffer = [0; 2];
    stream.read_exact(&mut buffer)?;
    assert_eq!(meter.snapshot().send.peers[&peer].active_remaining_bytes, 8);
    drop(stream);
    assert_eq!(meter.snapshot().send.peers[&peer].active_remaining_bytes, 0);
    let mut stream = meter.meter(Direction::Receive, peer, &b"abc"[..], 3, Some(3));
    stream.read_to_end(&mut Vec::new())?;
    let state = meter.state.lock().unwrap();
    let send = state.send.peers[&peer].counters.sample();
    let receive = state.receive.peers[&peer].counters.sample();
    assert_eq!(send.bytes, 2);
    assert_eq!(send.completed_logical, 0);
    assert_eq!(receive.completed_wire, 3);
    assert_eq!(receive.completed_logical, 3);
    Ok(())
}
#[test]
fn output_estimates_learn_real_missing_bytes_including_zero() {
    let mut result = ResultTransferEstimate::default();
    result.observe(8 << 20, 2, Duration::from_secs(2));
    assert_eq!(result.expected_bytes, 8 << 20);
    assert_eq!(result.expected_requests, 2);
    assert!(result.bytes_per_second < ResultTransferEstimate::default().bytes_per_second);
    result.observe(0, 0, Duration::ZERO);
    assert_eq!(result.expected_bytes, 6 << 20);
    assert!(result.valid());
}

#[test]
fn future_arrivals_only_compete_with_remaining_bytes() {
    let a = worker(1);
    let b = worker(2);
    let demand = |bytes| TransferDemand {
        bytes,
        bytes_per_second: 100_000_000,
    };
    let demands = BTreeMap::from([(a, demand(20_000_000)), (b, demand(200_000_000))]);
    let shared = DirectionSnapshot {
        peers: BTreeMap::new(),
        independent: Vec::new(),
        shared: vec![SharedCapacity {
            members: BTreeSet::from([a, b]),
            bytes_per_second: 100_000_000,
        }],
    };
    let remaining = shared.remaining_after(&demands, 0.4);
    assert!(!remaining.contains_key(&a));
    assert_eq!(remaining[&b].bytes, 180_000_000);
    assert!(shared.remaining_after(&demands, 3.0).is_empty());
}

#[test]
fn concurrent_capacity_requires_independent_baselines_and_covers_subsets() {
    let a = worker(1);
    let b = worker(2);
    let c = worker(3);
    let members = BTreeSet::from([a, b, c]);
    let start = Instant::now();
    let mut meter = DirectionMeter::default();
    for peer in [a, b, c] {
        meter.record(peer, start);
    }
    let full = [(a, 100_000_000), (b, 100_000_000), (c, 100_000_000)];
    // The first concurrent run alone cannot tell us whether it is saturated.
    for second in 1..=5 {
        feed(&mut meter, start + Duration::from_secs(second), &full);
    }
    assert!(!meter.snapshot().overlap_known(&members));
    for (index, peer) in [a, b, c].into_iter().enumerate() {
        for second in 0..3 {
            feed(
                &mut meter,
                start + Duration::from_secs(6 + 3 * index as u64 + second),
                &[(peer, 100_000_000)],
            );
        }
    }
    for second in 15..=18 {
        feed(&mut meter, start + Duration::from_secs(second), &full);
    }
    let measured = meter.snapshot();
    assert!(measured.shared.is_empty());
    assert!(measured.overlap_known(&members));
    assert!(measured.overlap_known(&BTreeSet::from([a, b])));
    assert!(!measured.overlap_known(&BTreeSet::from([a, worker(4)])));
    // Faster isolated rates can make the old experiment uninformative.
    for second in 19..=22 {
        feed(
            &mut meter,
            start + Duration::from_secs(second),
            &[(a, 200_000_000)],
        );
    }
    assert!(!meter.snapshot().overlap_known(&members));
}
