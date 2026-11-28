//! Live input observation transport. The assigned worker asks logical
//! questions; only the original submitting client can answer them. Bulk
//! bytes use the existing verified CAS upload/download paths.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use bincode::Options;

use super::{NativeCacheClient, retryable_transport_error};
use crate::build_runtime::{
    BlobRef, NativeStore, StagedBlob,
    discovery::{DiscoveryQuery, DiscoveryReply, DiscoveryTranscript, DiscoveryTransport},
    wire::{DiscoveryAnswer, DiscoveryOperation, DiscoveryRequest, Ticket},
};

pub(super) struct RemoteDiscovery {
    client: NativeCacheClient,
    ticket: Ticket,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    sequence: u64,
}

impl RemoteDiscovery {
    pub(super) fn new(
        client: NativeCacheClient,
        ticket: Ticket,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            client,
            ticket,
            deadline,
            cancelled,
            sequence: 0,
        }
    }

    fn remaining(&self) -> Result<Duration> {
        ensure!(
            !self.cancelled.load(Ordering::Acquire),
            "discovery action cancelled"
        );
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "discovery action deadline exceeded");
        Ok(remaining)
    }

    fn request(&mut self, operation: DiscoveryOperation) -> Result<DiscoveryAnswer> {
        let request = DiscoveryRequest {
            sequence: self.sequence,
            operation,
        };
        let mut delay = Duration::from_millis(5);
        loop {
            let remaining = self.remaining()?;
            match self
                .client
                .control_with_timeout::<_, Option<DiscoveryAnswer>>(
                    "discovery_request",
                    &(self.ticket, &request),
                    remaining.min(self.client.timeout),
                ) {
                Ok(Some(answer)) => {
                    self.sequence = self
                        .sequence
                        .checked_add(1)
                        .context("discovery sequence overflow")?;
                    if let DiscoveryAnswer::Rejected(message) = answer {
                        bail!("discovery origin rejected operation: {message}");
                    }
                    return Ok(answer);
                }
                Ok(None) => {}
                Err(error) if retryable_transport_error(&error) => {
                    debug!("retrying discovery request: {error:#}");
                }
                Err(error) => return Err(error),
            }
            thread::sleep(delay.min(remaining));
            delay = (delay * 2).min(Duration::from_millis(50));
        }
    }
}

impl DiscoveryTransport for RemoteDiscovery {
    fn query(&mut self, query: &DiscoveryQuery) -> Result<DiscoveryReply> {
        let DiscoveryAnswer::Observed(reply) =
            self.request(DiscoveryOperation::Observe(query.clone()))?
        else {
            bail!("scheduler returned wrong discovery observation");
        };
        Ok(reply)
    }

    fn seal(&mut self, transcript: &DiscoveryTranscript) -> Result<()> {
        ensure!(
            self.request(DiscoveryOperation::Seal(transcript.fingerprint()?))?
                == DiscoveryAnswer::Sealed,
            "scheduler did not seal discovery"
        );
        Ok(())
    }

    fn stage_blob(&mut self, store: &NativeStore, blob: BlobRef) -> Result<StagedBlob> {
        ensure!(
            self.request(DiscoveryOperation::Fetch(blob))? == DiscoveryAnswer::Available,
            "scheduler did not supply discovery blob"
        );
        let request = super::codec().serialize(&(self.ticket, blob))?;
        let (reader, encoding) = self
            .client
            .receive_blob(
                "discovery_download",
                request,
                blob,
                self.remaining()?.min(self.client.timeout),
            )?
            .context("discovery blob unavailable after verification")?;
        store.stage_expected_physical(blob, encoding, reader)
    }
}

/// Origin operations are performed by the calling process, not by the
/// scheduler or the compiler. A blob upload is pinned until the scheduler
/// accepts the corresponding answer.
#[cfg(feature = "dist-client")]
pub(in crate::dist) fn serve_origin(
    origin: &mut crate::build_runtime::discovery::DiscoveryOrigin,
    client: &NativeCacheClient,
    ticket: Ticket,
    demand: DiscoveryRequest,
    deadline: Instant,
    renewal: Duration,
) -> Result<()> {
    let mut upload = None;
    let mut origin_failure = None;
    let answer = match (|| -> Result<DiscoveryAnswer> {
        match demand.operation {
            DiscoveryOperation::Observe(query) => {
                Ok(DiscoveryAnswer::Observed(origin.query(query)?))
            }
            DiscoveryOperation::Fetch(blob) => {
                let manifest = NativeStore::blob_retention_manifest(blob)?;
                upload = Some(client.push_tree(
                    &manifest,
                    |id| {
                        ensure!(id == blob.id, "unexpected discovery upload content");
                        origin.open_blob(blob)
                    },
                    renewal,
                )?);
                Ok(DiscoveryAnswer::Available)
            }
            DiscoveryOperation::Seal(expected) => {
                ensure!(
                    origin.seal()?.fingerprint()? == expected,
                    "origin discovery transcript changed before sealing"
                );
                Ok(DiscoveryAnswer::Sealed)
            }
        }
    })() {
        Ok(answer) => answer,
        Err(error) => {
            // Path-specific details stay at the origin. The worker receives
            // a bounded explicit failure, never a fabricated missing file.
            warn!("Live origin discovery failed: {error:#}");
            origin_failure = Some(error);
            DiscoveryAnswer::Rejected("origin could not verify the requested observation".into())
        }
    };
    let result = loop {
        if Instant::now() >= deadline {
            break Err(anyhow::anyhow!("discovery response deadline exceeded"));
        }
        match client.discovery_answer(ticket, demand.sequence, &answer) {
            Ok(()) => break Ok(()),
            Err(error) if retryable_transport_error(&error) => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(error) => break Err(error),
        }
    };
    if let Some(upload) = upload {
        if let Err(error) = client.close(upload) {
            debug!("Discovery upload pin release failed: {error:#}");
        }
    }
    result?;
    if let Some(error) = origin_failure {
        return Err(error);
    }
    Ok(())
}
