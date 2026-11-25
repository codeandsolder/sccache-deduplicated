use super::*;
use sccache::dist::NativeQueueSnapshot;

fn progress(phase: NativeJobPhase, elapsed: Duration, remaining: u64) -> NativeJobProgress {
    NativeJobProgress {
        phase,
        phase_nanoseconds: u64::try_from(elapsed.as_nanos()).unwrap(),
        remaining_input_bytes: remaining,
        remaining_input_blobs: u64::from(remaining != 0),
    }
}

fn publication_start(
    forecast: super::super::WorkerForecast<'_>,
    inputs: &NativeInputBlobs,
    raw: u64,
    contention: f64,
) -> f64 {
    publication_forecast(
        forecast,
        inputs,
        None,
        DeliveryRates {
            raw,
            archive: forecast
                .placement
                .timing
                .transfer
                .archive_download_bytes_per_second,
            wire_per_mille: 1000,
            contention,
        },
        None,
    )
    .ready_at
}

fn placement() -> NativePlacement {
    let mut placement = NativePlacement {
        queue: NativeQueueSnapshot {
            capacity: 16,
            compiler_slots: 4,
            compiler_active: 0,
            staging_slots: 2,
            publication_slots: 2,
            jobs: Default::default(),
        },
        timing: sccache::build_runtime::wire::WorkerTiming {
            execution_nanoseconds: 1_000_000_000,
            ..Default::default()
        },
        ..Default::default()
    };
    placement.timing.transfer.raw_request_nanoseconds = 0;
    placement.timing.result.expected_bytes = 100;
    placement.timing.result.bytes_per_second = 100;
    placement.timing.result.expected_requests = 0;
    placement
}

fn start(
    placement: &NativePlacement,
    assigned: &Assignments,
    requested: &NativeInputBlobs,
    cpus: f64,
) -> f64 {
    publication_start(
        super::super::WorkerForecast {
            capacity: cpus,
            assigned,
            placement,
            recent: &RecentResidency::default(),
            cost: ActionCost::baseline(placement),
        },
        requested,
        100,
        1.0,
    )
}

fn phase_assignments(
    placement: &mut NativePlacement,
    inputs: &NativeInputBlobs,
    phases: impl IntoIterator<Item = (JobId, NativeJobPhase)>,
) -> Assignments {
    phases
        .into_iter()
        .map(|(id, phase)| {
            placement
                .queue
                .jobs
                .insert(id, progress(phase, Duration::ZERO, 0));
            (
                id,
                Some(AssignedNative {
                    packages: Default::default(),
                    inputs: inputs.clone(),
                    class: None,
                    cost: None,
                    milestone: None,
                }),
            )
        })
        .collect()
}

#[test]
fn native_pipeline_does_not_charge_publication_or_terminal_as_cpu_work() {
    let mut placement = placement();
    let inputs = NativeInputBlobs::new();
    let assigned = phase_assignments(
        &mut placement,
        &inputs,
        [
            (JobId(1), NativeJobPhase::Publishing),
            (JobId(2), NativeJobPhase::Terminal),
        ],
    );
    assert_eq!(start(&placement, &assigned, &inputs, 1.0), 1.0);
    placement.queue.jobs.insert(
        JobId(1),
        progress(NativeJobPhase::Executing, Duration::from_millis(750), 0),
    );
    placement.queue.compiler_active = 1;
    assert_eq!(start(&placement, &assigned, &inputs, 1.0), 1.25);
    placement
        .queue
        .jobs
        .insert(JobId(1), progress(NativeJobPhase::Ready, Duration::ZERO, 0));
    placement.queue.compiler_active = 0;
    assert_eq!(start(&placement, &assigned, &inputs, 1.0), 2.0);
}

#[test]
fn native_pipeline_waits_for_staging_slots_and_reuses_future_content() {
    let mut placement = placement();
    let shared = ContentId::of(b"shared");
    let independent = ContentId::of(b"independent");
    let inputs = NativeInputBlobs::from([(shared, 1_000)]);
    let assigned = Assignments::from([(
        JobId(1),
        Some(AssignedNative {
            packages: Default::default(),
            inputs: inputs.clone(),
            class: None,
            cost: None,
            milestone: None,
        }),
    )]);
    placement.queue.jobs.insert(
        JobId(1),
        progress(NativeJobPhase::Staging, Duration::ZERO, 200),
    );
    // Two staging slots allow a warm new job to pass a slow download.
    assert_eq!(
        start(&placement, &assigned, &NativeInputBlobs::new(), 2.0),
        1.0
    );
    // A consumer of the same immutable blob waits for the existing transfer,
    // not another 1000-byte transfer. Only 200 bytes remain.
    assert_eq!(start(&placement, &assigned, &inputs, 2.0), 3.0);
    let new = NativeInputBlobs::from([(shared, 1_000), (independent, 100)]);
    assert_eq!(start(&placement, &assigned, &new, 2.0), 4.0);
    placement.queue.staging_slots = 1;
    assert_eq!(
        start(&placement, &assigned, &NativeInputBlobs::new(), 2.0),
        3.0
    );
    // Verified closure overrides a stale or absent Bloom snapshot.
    placement
        .queue
        .jobs
        .insert(JobId(1), progress(NativeJobPhase::Ready, Duration::ZERO, 0));
    assert_eq!(start(&placement, &assigned, &inputs, 2.0), 1.0);
    assert!(confirmed_inputs(&assigned, &placement).contains(&shared));
}

#[test]
fn native_pipeline_predicts_publication_backpressure_separately() {
    let mut placement = placement();
    placement.queue.publication_slots = 1;
    let inputs = NativeInputBlobs::new();
    let assigned = phase_assignments(
        &mut placement,
        &inputs,
        [
            (JobId(1), NativeJobPhase::Publishing),
            (JobId(2), NativeJobPhase::AwaitingPublication),
        ],
    );
    assert_eq!(start(&placement, &assigned, &inputs, 4.0), 2.0);
    placement.queue.publication_slots = 2;
    assert_eq!(start(&placement, &assigned, &inputs, 4.0), 1.0);
}

#[test]
fn native_pipeline_capacity_counts_local_and_unobserved_reservations_once() {
    let mut placement = placement();
    placement.queue.capacity = 3;
    placement
        .queue
        .jobs
        .insert(JobId(1), progress(NativeJobPhase::Ready, Duration::ZERO, 0));
    placement.queue.jobs.insert(
        JobId(2),
        progress(NativeJobPhase::Terminal, Duration::ZERO, 0),
    );
    assert!(placement.queue.valid());
    assert!(placement.queue.has_capacity([JobId(1)].into_iter()));
    assert!(
        !placement
            .queue
            .has_capacity([JobId(1), JobId(3)].into_iter())
    );
    placement
        .queue
        .jobs
        .get_mut(&JobId(1))
        .unwrap()
        .remaining_input_blobs = 1;
    assert!(!placement.queue.valid());
}

#[test]
fn native_pipeline_legacy_execution_shares_compiler_not_publication_slots() {
    let mut placement = placement();
    placement.queue.publication_slots = 1;
    let assigned = Assignments::from([(JobId(1), None), (JobId(2), None)]);
    let inputs = NativeInputBlobs::new();
    assert_eq!(start(&placement, &assigned, &inputs, 1.0), 3.0);
    assert_eq!(start(&placement, &assigned, &inputs, 3.0), 1.0);
    placement.queue.compiler_active = 2;
    assert_eq!(start(&placement, &assigned, &inputs, 2.0), 2.0);
}

#[test]
fn native_pipeline_uses_each_reservations_learned_service_time() {
    let mut placement = placement();
    let inputs = NativeInputBlobs::new();
    let large = ActionCost {
        phase: Default::default(),
        execution_nanoseconds: 8_000_000_000,
        output_bytes: 400,
        output_requests: 0,
    };
    let small = ActionCost {
        phase: Default::default(),
        execution_nanoseconds: 200_000_000,
        output_bytes: 0,
        output_requests: 0,
    };
    let assigned = Assignments::from([(
        JobId(1),
        Some(AssignedNative {
            packages: Default::default(),
            inputs: inputs.clone(),
            class: None,
            cost: Some(large),
            milestone: None,
        }),
    )]);
    placement.queue.jobs.insert(
        JobId(1),
        progress(NativeJobPhase::Executing, Duration::from_secs(3), 0),
    );
    placement.queue.compiler_active = 1;
    let recent = RecentResidency::default();
    let forecast = super::super::WorkerForecast {
        capacity: 1.0,
        assigned: &assigned,
        placement: &placement,
        recent: &recent,
        cost: small,
    };
    assert_eq!(publication_start(forecast, &inputs, 100, 1.0), 5.2);
    placement.queue.jobs.insert(
        JobId(1),
        progress(NativeJobPhase::Publishing, Duration::from_secs(1), 0),
    );
    placement.queue.compiler_active = 0;
    placement.queue.publication_slots = 1;
    let forecast = super::super::WorkerForecast {
        placement: &placement,
        capacity: 4.0,
        assigned: &assigned,
        recent: &recent,
        cost: small,
    };
    assert_eq!(publication_start(forecast, &inputs, 100, 1.0), 3.0);
}

#[test]
fn native_pipeline_charges_warm_preparation_and_publication_without_uploads() {
    let mut placement = placement();
    placement.queue.staging_slots = 1;
    placement.queue.publication_slots = 1;
    let inputs = NativeInputBlobs::new();
    let action = ActionCost {
        phase: super::super::cost::PhaseCost {
            staging_nanoseconds: 10_000_000,
            publication_nanoseconds: 20_000_000,
        },
        execution_nanoseconds: 30_000_000,
        output_bytes: 0,
        output_requests: 0,
    };
    let assigned = Assignments::from([(
        JobId(1),
        Some(AssignedNative {
            packages: Default::default(),
            inputs: inputs.clone(),
            class: None,
            cost: Some(action),
            milestone: None,
        }),
    )]);
    let recent = RecentResidency::default();
    let forecast = super::super::WorkerForecast {
        capacity: 1.0,
        assigned: &assigned,
        placement: &placement,
        recent: &recent,
        cost: action,
    };
    let pipeline = publication_forecast(
        forecast,
        &inputs,
        None,
        DeliveryRates {
            raw: 100,
            archive: 100,
            wire_per_mille: 1000,
            contention: 1.0,
        },
        None,
    );
    // One staging slot: 10ms per job. One compiler: first runs
    // from 10–40ms, second 40–70ms; first publication 40–60ms.
    assert_eq!(pipeline.inputs_ready_at, 0.020);
    assert_eq!(pipeline.ready_at, 0.070);
    assert_eq!(pipeline.traffic.wire_bytes, 0);
}

#[test]
fn direct_input_is_not_charged_to_scheduler_shared_link() {
    let mut placement = placement();
    placement.timing.transfer.raw_request_nanoseconds = 0;
    let assigned = Assignments::default();
    let recent = RecentResidency::default();
    let direct_id = ContentId::of(b"resident on peer");
    let cold_id = ContentId::of(b"only scheduler");
    let requested = NativeInputBlobs::from([(direct_id, 1000), (cold_id, 1000)]);
    let forecast = super::super::WorkerForecast {
        capacity: 4.0,
        assigned: &assigned,
        placement: &placement,
        recent: &recent,
        cost: ActionCost::baseline(&placement),
    };
    let rates = DeliveryRates {
        raw: 1000,
        archive: 1000,
        wire_per_mille: 1000,
        contention: 2.0,
    };
    let direct = DirectInputs::from([(direct_id, 10_000)]);
    let result = publication_forecast(forecast, &requested, None, rates, Some(&direct));
    assert_eq!(result.traffic.wire_bytes, 1000);
    assert_eq!(result.traffic.direct_bytes, 1000);
    assert_eq!(result.traffic.wire_time, Duration::from_secs(1));
    assert_eq!(result.traffic.direct_time, Duration::from_millis(100));
    let baseline = publication_forecast(forecast, &requested, None, rates, None);
    assert_eq!(baseline.traffic.wire_bytes, 2000);
    assert!(result.inputs_ready_at < baseline.inputs_ready_at);
}
