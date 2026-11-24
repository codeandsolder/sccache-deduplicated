//! Worker-side bounded memory-only calibration on the native cache route.

use std::{
    io::{self, Cursor, Read},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize};

use super::{NativeCacheClient, Role, codec, decode_response};
use crate::build_runtime::{Direction, IdleGate, ProbePayload, ProbeStream};

pub(crate) const PROBE_DURATION: Duration = Duration::from_secs(2);
pub(crate) const PROBE_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const PROBE_IDLE: Duration = Duration::from_secs(10);
pub(crate) const PROBE_MIN_BYTES: u64 = 1 << 20;
pub(crate) const PROBE_MAX_BYTES: u64 = 256 << 20;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct ProbeGrant {
    pub round: u64,
    pub direction: Direction,
    pub bytes: u64,
    pub delay_millis: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct ProbeReceipt {
    pub round: u64,
    pub bytes: u64,
    pub elapsed_nanos: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum ProbeOffer {
    Disabled,
    Wait,
    Granted(ProbeGrant),
}

impl NativeCacheClient {
    fn probe_once(&self, gate: &Arc<IdleGate>) -> Result<Duration> {
        let Some(permit) = gate.permit(PROBE_IDLE) else {
            return Ok(Duration::from_secs(2));
        };
        let response = self
            .request("probe_offer")?
            .timeout(PROBE_HTTP_TIMEOUT)
            .body(Vec::new())
            .send()?
            .error_for_status()?;
        let grant = match decode_response::<ProbeOffer>(response, self.metadata_limit)? {
            ProbeOffer::Disabled => return Ok(Duration::from_secs(30)),
            ProbeOffer::Wait => return Ok(Duration::from_secs(2)),
            ProbeOffer::Granted(grant) => grant,
        };
        ensure!(
            (PROBE_MIN_BYTES..=PROBE_MAX_BYTES).contains(&grant.bytes)
                && grant.delay_millis <= 5000,
            "invalid network calibration grant"
        );
        if !permit.wait(Duration::from_millis(grant.delay_millis)) {
            return Ok(Duration::from_secs(2));
        }
        let header = codec().with_limit(8).serialize(&grant.round)?;
        match grant.direction {
            Direction::Send => {
                let response = self
                    .request("probe_download")?
                    .timeout(PROBE_HTTP_TIMEOUT)
                    .body(header)
                    .send()?
                    .error_for_status()?;
                let started = Instant::now();
                // Read the terminating chunk as well as the granted bytes.
                // A receipt confirms that data actually reached the worker.
                let mut stream = ProbeStream::new(
                    response,
                    permit.clone(),
                    grant.bytes + 1,
                    PROBE_HTTP_TIMEOUT,
                );
                let bytes = io::copy(&mut stream, &mut io::sink())?;
                ensure!(
                    permit.valid() && bytes <= grant.bytes,
                    "invalid or preempted calibration download"
                );
                let receipt = ProbeReceipt {
                    round: grant.round,
                    bytes,
                    elapsed_nanos: u64::try_from(started.elapsed().as_nanos())?,
                };
                self.request("probe_receipt")?
                    .timeout(PROBE_HTTP_TIMEOUT)
                    .body(codec().with_limit(24).serialize(&receipt)?)
                    .send()?
                    .error_for_status()?;
            }
            Direction::Receive => {
                let stream = ProbeStream::new(
                    ProbePayload::new(&header),
                    permit,
                    grant.bytes,
                    PROBE_DURATION,
                );
                let body = reqwest::blocking::Body::new(Cursor::new(header).chain(stream));
                self.request("probe_upload")?
                    .timeout(PROBE_HTTP_TIMEOUT)
                    .body(body)
                    .send()?
                    .error_for_status()?;
            }
        }
        Ok(Duration::from_secs(2))
    }

    /// Poll the scheduler for low-priority probe grants. The local assignment
    /// gate cancels calibration before compilation/staging begins.
    /// # Errors
    /// Returns an error if the probe worker cannot be started.
    pub fn start_calibration(&self, gate: &Arc<IdleGate>) -> Result<()> {
        let mut client = self.clone();
        client.role = Role::Calibration;
        let gate = Arc::downgrade(gate);
        std::thread::Builder::new()
            .name("native-network-calibration".into())
            .spawn(move || {
                loop {
                    let Some(active) = gate.upgrade() else {
                        break;
                    };
                    let delay = client.probe_once(&active).unwrap_or_else(|error| {
                        trace!("Native network calibration deferred: {error:#}");
                        Duration::from_secs(5)
                    });
                    drop(active);
                    std::thread::sleep(delay);
                }
            })?;
        Ok(())
    }
}
