//! Distinguish logical input identities, actual wire traffic and decoder
//! service. This is a forecast; the worker negotiates and verifies delivery.

use sccache::build_runtime::{
    DirectionSnapshot, PackageCatalog, PackageDeliveryLimits, PackageTransferCost, Peer,
    transfer_seconds,
};
use sccache::dist::NativeInputBlobs;
use std::time::Duration;

#[derive(Clone, Copy)]
pub(super) struct DeliveryRates {
    pub raw: u64,
    pub archive: u64,
    pub wire_per_mille: u64,
    pub contention: f64,
}

impl DeliveryRates {
    pub(super) fn new(network: &DirectionSnapshot, peer: Peer, cost: PackageTransferCost) -> Self {
        Self {
            raw: network.logical_rate(peer, cost.download_bytes_per_second),
            archive: network.rate(peer, cost.archive_download_bytes_per_second),
            wire_per_mille: u64::try_from(network.wire_bytes(peer, 1000))
                .unwrap_or(1000)
                .max(1),
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
}

impl InputTraffic {
    pub(super) fn extend(&mut self, other: Self) {
        self.wire_bytes = self.wire_bytes.saturating_add(other.wire_bytes);
        self.archive_bytes = self.archive_bytes.saturating_add(other.archive_bytes);
        self.wire_time = self.wire_time.saturating_add(other.wire_time);
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
    ) -> Self {
        let archives = catalog
            .zip(limits)
            .map_or_else(Vec::new, |(catalog, limits)| {
                catalog.select(&mut missing, limits, cost)
            });
        let mut delivery = Self::raw(
            missing.values().map(|&size| u128::from(size)).sum(),
            u64::try_from(missing.len()).unwrap_or(u64::MAX),
            cost,
            rates,
        );
        let mut processing = Duration::ZERO;
        let mut longest = Duration::ZERO;
        for archive in archives {
            let wire = u128::from(archive.blob.size);
            delivery.traffic.extend(InputTraffic {
                wire_bytes: wire,
                archive_bytes: wire,
                wire_time: duration(transfer_seconds(wire, rates.archive)),
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
