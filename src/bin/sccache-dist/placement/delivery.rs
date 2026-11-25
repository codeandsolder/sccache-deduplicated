//! Distinguish logical input identities, actual wire traffic and decoder
//! service. This is a forecast; the worker negotiates and verifies delivery.

use sccache::build_runtime::{
    ContentId, DirectionSnapshot, PackageCatalog, PackageDeliveryLimits, PackageTransferCost, Peer,
    transfer_seconds,
};
use sccache::dist::NativeInputBlobs;
use std::{collections::BTreeMap, time::Duration};

pub(super) type DirectInputs = BTreeMap<ContentId, u64>;

#[derive(Clone, Copy)]
pub(super) struct DeliveryRates {
    pub raw: u64,
    pub archive: u64,
    pub wire_per_mille: u64,
    pub contention: f64,
}

impl DeliveryRates {
    pub(super) fn new(
        network: &DirectionSnapshot,
        peer: Peer,
        cost: PackageTransferCost,
        current_wire_rate: Option<u64>,
    ) -> Self {
        let wire_per_mille = u64::try_from(network.wire_bytes(peer, 1000))
            .unwrap_or(1000)
            .max(1);
        Self {
            raw: current_wire_rate.map_or_else(
                || network.logical_rate(peer, cost.download_bytes_per_second),
                |rate| {
                    u64::try_from(u128::from(rate) * 1000 / u128::from(wire_per_mille))
                        .unwrap_or(u64::MAX)
                        .clamp(1, 1_000_000_000_000)
                },
            ),
            archive: current_wire_rate
                .unwrap_or_else(|| network.rate(peer, cost.archive_download_bytes_per_second)),
            wire_per_mille,
            contention: 1.0,
        }
    }
}

fn duration(seconds: f64) -> Duration {
    Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX)
}

fn nanoseconds(value: u128) -> Duration {
    Duration::new(
        u64::try_from(value / 1_000_000_000).unwrap_or(u64::MAX),
        u32::try_from(value % 1_000_000_000).unwrap_or_default(),
    )
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct InputTraffic {
    pub wire_bytes: u128,
    pub archive_bytes: u128,
    pub wire_time: Duration,
    pub direct_bytes: u128,
    pub direct_time: Duration,
}

impl InputTraffic {
    pub(super) fn extend(&mut self, other: Self) {
        self.wire_bytes = self.wire_bytes.saturating_add(other.wire_bytes);
        self.archive_bytes = self.archive_bytes.saturating_add(other.archive_bytes);
        self.wire_time = self.wire_time.saturating_add(other.wire_time);
        self.direct_bytes = self.direct_bytes.saturating_add(other.direct_bytes);
        self.direct_time = self.direct_time.saturating_add(other.direct_time);
    }

    pub(super) fn effective_rate(self) -> u64 {
        u64::try_from(
            self.wire_bytes.saturating_mul(1_000_000_000) / self.wire_time.as_nanos().max(1),
        )
        .unwrap_or(u64::MAX)
        .clamp(1, 1_000_000_000_000)
    }
}

pub(super) struct Delivery {
    pub traffic: InputTraffic,
    pub processing: Duration,
}

impl Delivery {
    pub(super) fn raw(
        bytes: u128,
        requests: u64,
        cost: PackageTransferCost,
        rates: DeliveryRates,
    ) -> Self {
        Self {
            traffic: InputTraffic {
                wire_bytes: bytes
                    .saturating_mul(u128::from(rates.wire_per_mille))
                    .div_ceil(1000),
                archive_bytes: 0,
                wire_time: duration(transfer_seconds(bytes, rates.raw)),
                ..InputTraffic::default()
            },
            processing: Duration::from_nanos(
                requests
                    .div_ceil(u64::from(cost.raw_parallelism))
                    .saturating_mul(cost.raw_request_nanoseconds),
            ),
        }
    }

    pub(super) fn plan(
        mut missing: NativeInputBlobs,
        catalog: Option<&PackageCatalog>,
        limits: Option<PackageDeliveryLimits>,
        cost: PackageTransferCost,
        rates: DeliveryRates,
        direct: Option<&DirectInputs>,
    ) -> Self {
        let archives = catalog
            .zip(limits)
            .map_or_else(Vec::new, |(catalog, limits)| {
                catalog.select(&mut missing, limits, cost)
            });
        // Package reconstruction precedes raw delivery on the actual worker.
        // Only the remaining exact identities can use the direct raw path.
        let mut direct_traffic = InputTraffic::default();
        let mut direct_requests = 0_u64;
        if let Some(direct) = direct {
            missing.retain(|id, size| {
                let Some(&rate) = direct.get(id).filter(|&&rate| rate > rates.raw) else {
                    return true;
                };
                let bytes = u128::from(*size);
                direct_traffic.direct_bytes += bytes;
                direct_traffic.direct_time = direct_traffic
                    .direct_time
                    .saturating_add(duration(transfer_seconds(bytes, rate)));
                direct_requests = direct_requests.saturating_add(1);
                false
            });
        }
        let mut delivery = Self::raw(
            missing.values().map(|&size| u128::from(size)).sum(),
            u64::try_from(missing.len())
                .unwrap_or(u64::MAX)
                .saturating_add(direct_requests),
            cost,
            rates,
        );
        delivery.traffic.extend(direct_traffic);
        let mut processing = Duration::ZERO;
        let mut longest = Duration::ZERO;
        for archive in archives {
            let wire = u128::from(archive.blob.size);
            delivery.traffic.extend(InputTraffic {
                wire_bytes: wire,
                archive_bytes: wire,
                wire_time: duration(transfer_seconds(wire, rates.archive)),
                ..InputTraffic::default()
            });
            let service = nanoseconds(cost.archive_processing_nanoseconds(archive));
            processing = processing.saturating_add(service);
            longest = longest.max(service);
        }
        // Original archive downloads share the link; expansion can run on
        // the worker's bounded decoder pool. The critical path is at least
        // the longest expansion and at least total work / parallelism.
        let parallelism = limits.map_or(1, |limits| limits.parallelism.max(1));
        delivery.processing = delivery
            .processing
            .saturating_add(longest.max(processing / parallelism));
        delivery
    }
}
