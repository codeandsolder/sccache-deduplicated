//! One scoped native action over the caller's existing daemon connection.
//! The daemon owns the scheduler transaction. The caller owns input discovery
//! and all filesystem output installation. The stream carries no credentials,
//! scheduler tickets, worker capabilities, or daemon filesystem paths.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufWriter, Read, Write},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use bincode::Options;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    build_runtime::{
        ActionMode, BlobRef, ContentId, ExecutionSpec, PreparedTree, ResultManifest, TreeId,
        TreeManifest, wire::NativeRunResult,
    },
    client::{SharedConnection, connection_task},
    protocol::{NativeNamespacePolicy, TransferReply, TransferRequest},
};

use super::{
    NativeBuildPolicy, NativeBuildResult, NativeBuildSource, NativeCacheClient,
    client::{
        BlobSink, InputBlob, InputProvider, LocalInputs, NativeProgress, Outcome, failed_output,
        fetch_result, validate_manifest, verify_destinations,
    },
    codec, copy_verified,
};

mod pipe;
pub use pipe::{DaemonStream, NativeExchange};

#[derive(Serialize, Deserialize)]
enum Event {
    Progress(NativeProgress),
    NeedTree(TreeId),
    NeedBlob {
        tree: TreeId,
        blob: BlobRef,
    },
    Ready {
        source: NativeBuildSource,
        manifest: ResultManifest,
    },
    Failed {
        source: NativeBuildSource,
        failure: NativeRunResult,
    },
    Done,
}

#[derive(Serialize, Deserialize)]
enum ResultRequest {
    Blob(BlobRef),
    Finish,
}

fn send<T: Serialize>(stream: &mut impl Write, value: &T, limit: u64) -> Result<()> {
    let mut bytes = vec![0; 8];
    codec()
        .with_limit(limit)
        .serialize_into(&mut bytes, value)?;
    let length = u64::try_from(bytes.len() - 8)?;
    bytes[..8].copy_from_slice(&length.to_le_bytes());
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn receive<T: DeserializeOwned>(stream: &mut impl Read, limit: u64) -> Result<T> {
    let mut length = [0; 8];
    stream.read_exact(&mut length)?;
    let length = u64::from_le_bytes(length);
    ensure!(
        length <= limit,
        "native namespace message exceeds configured limit"
    );
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(length)?)?;
    stream.take(length).read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? == length,
        "truncated native namespace message"
    );
    Ok(codec().with_limit(limit).deserialize(&bytes)?)
}

impl NativeNamespacePolicy {
    pub const fn build_policy(&self, mode: ActionMode) -> NativeBuildPolicy {
        NativeBuildPolicy {
            mode,
            timeout: Duration::from_secs(self.build_timeout_secs),
            renewal_interval: Duration::from_secs(self.renewal_interval_secs),
            max_result_bytes: self.max_result_bytes,
        }
    }

    fn event_limit(&self) -> Result<u64> {
        self.max_metadata_bytes
            .checked_add(self.max_result_bytes)
            .context("native namespace event limit overflow")
    }
}

struct RemoteInputs<'a> {
    stream: &'a mut DaemonStream,
    limit: u64,
    trace: Option<crate::latency_trace::TraceContext>,
}

impl InputProvider for RemoteInputs<'_> {
    fn trace_context(&self) -> Option<crate::latency_trace::TraceContext> {
        self.trace
    }

    fn progress(&mut self, progress: NativeProgress) -> Result<()> {
        send(self.stream, &Event::Progress(progress), self.limit)
    }

    fn manifest(&mut self, tree: TreeId) -> Result<TreeManifest> {
        send(self.stream, &Event::NeedTree(tree), self.limit)?;
        receive(self.stream, self.limit)
    }

    fn open_blob(&mut self, tree: TreeId, blob: BlobRef) -> Result<Option<InputBlob>> {
        send(self.stream, &Event::NeedBlob { tree, blob }, self.limit)?;
        let available: bool = receive(self.stream, self.limit)?;
        Ok(available.then(|| {
            InputBlob::new(
                Box::new(self.stream.blob_reader(blob.size)),
                blob.size,
                true,
            )
        }))
    }
}

/// Complete one action in the daemon. Only declared input trees/blobs are
/// requested. The caller reads verified outputs through the active result pin.
pub fn serve_action(
    client: &NativeCacheClient,
    policy: &NativeNamespacePolicy,
    mut stream: DaemonStream,
    registry: &super::result_session::Registry,
    uid: u32,
) -> Result<()> {
    serve_inner(client, policy, &mut stream, registry, uid)
}

fn serve_inner(
    client: &NativeCacheClient,
    policy: &NativeNamespacePolicy,
    stream: &mut DaemonStream,
    registry: &super::result_session::Registry,
    uid: u32,
) -> Result<()> {
    let (trace, spec, mode, selected, retained): (
        Option<crate::latency_trace::TraceContext>,
        ExecutionSpec,
        ActionMode,
        BTreeSet<String>,
        BTreeSet<crate::build_runtime::wire::Ticket>,
    ) = receive(stream, policy.max_metadata_bytes)?;
    ensure!(
        trace.is_none_or(crate::latency_trace::TraceContext::valid),
        "invalid namespace trace context"
    );
    ensure!(
        selected.iter().all(|name| spec.outputs.contains_key(name)),
        "undeclared selected result output"
    );
    ensure!(
        spec.platform == policy.platform,
        "native namespace platform mismatch"
    );
    let retained = retained
        .into_iter()
        .map(|token| registry.get(uid, token))
        .collect::<Result<Vec<_>>>()?;
    let build_policy = policy.build_policy(mode);
    let mut inputs = RemoteInputs {
        stream,
        limit: policy.max_metadata_bytes,
        trace,
    };
    match client.acquire_action(&spec, &mut inputs, &build_policy, &selected)? {
        Outcome::Failed { source, failure } => {
            send(
                stream,
                &Event::Failed { source, failure },
                policy.event_limit()?,
            )?;
        }
        Outcome::Ready {
            source,
            mut delivery,
            manifest,
        } => {
            validate_manifest(&spec, &manifest, policy.max_result_bytes)?;
            let blobs = manifest.selected_blobs(&selected)?;
            delivery.with_download(build_policy.renewal_interval, &blobs, |download| {
                send(
                    stream,
                    &Event::Ready {
                        source,
                        manifest: manifest.clone(),
                    },
                    policy.max_metadata_bytes,
                )?;
                loop {
                    match receive(stream, policy.max_metadata_bytes)? {
                        ResultRequest::Finish => break,
                        ResultRequest::Blob(blob) => {
                            ensure!(
                                blobs.get(&blob.id) == Some(&blob.size),
                                "undeclared native result blob"
                            );
                            let mut writer =
                                BufWriter::with_capacity(stream.chunk_bytes(), &mut *stream);
                            download(blob, &mut BlobSink::Stream(&mut writer))?;
                            writer.flush()?;
                        }
                    }
                }
                Ok(())
            })?;
            // Closing a connection-owned result lease is independent of local
            // file installation. Send completion only after all transfers and
            // their validation have finished.
            for group in retained {
                delivery.retain(&group, &manifest, build_policy.renewal_interval)?;
            }
            drop(delivery);
            send(stream, &Event::Done, policy.max_metadata_bytes)?;
        }
    }
    Ok(())
}

pub async fn run_action(
    connection: SharedConnection,
    chunk_bytes: usize,
    policy: NativeNamespacePolicy,
    spec: ExecutionSpec,
    mode: ActionMode,
    inputs: Vec<PreparedTree>,
    destinations: BTreeMap<String, PathBuf>,
    retained: BTreeSet<crate::build_runtime::wire::Ticket>,
) -> Result<NativeBuildResult> {
    ensure!(
        spec.platform == policy.platform,
        "native namespace platform mismatch"
    );
    let activity = crate::server::activity::current();
    connection_task(connection, move |connection| {
        crate::server::activity::sync_scope(activity, || {
            let inputs = LocalInputs::new(&spec, &inputs)?;
            let destinations = verify_destinations(&spec, &destinations)?;
            ensure!(
                matches!(
                    connection.transfer(TransferRequest::NativeStart)?,
                    TransferReply::Ack
                ),
                "unexpected native stream start response"
            );
            let result = run_inner(
                &mut pipe::CallerStream::new(connection, chunk_bytes),
                &policy,
                &spec,
                mode,
                &inputs,
                &destinations,
                retained,
            );
            let request = if result.is_ok() {
                TransferRequest::NativeEnd
            } else {
                TransferRequest::Abort
            };
            let close = connection.transfer(request);
            match result {
                Ok(result) => {
                    ensure!(
                        matches!(close?, TransferReply::Ack),
                        "unexpected native stream end response"
                    );
                    Ok(result)
                }
                Err(error) => Err(error),
            }
        })
    })
    .await
}

fn run_inner(
    stream: &mut pipe::CallerStream<'_>,
    policy: &NativeNamespacePolicy,
    spec: &ExecutionSpec,
    mode: ActionMode,
    inputs: &LocalInputs<'_>,
    destinations: &BTreeMap<String, PathBuf>,
    mut retained: BTreeSet<crate::build_runtime::wire::Ticket>,
) -> Result<NativeBuildResult> {
    let limit = policy.max_metadata_bytes;
    let destinations = super::intermediate::Destinations::new(destinations.clone())?;
    let selected = destinations.eager.keys().cloned().collect::<BTreeSet<_>>();
    retained.extend(destinations.sessions());
    send(
        stream,
        &(
            crate::server::activity::trace_context(),
            spec,
            mode,
            selected,
            retained,
        ),
        limit,
    )?;
    let mut advertised = BTreeMap::<TreeId, BTreeMap<ContentId, u64>>::new();
    let mut buffer = vec![0; stream.chunk_bytes()];
    loop {
        match receive(stream, policy.event_limit()?)? {
            Event::Progress(progress) => progress.apply(),
            Event::NeedTree(id) => {
                let manifest = inputs.tree(id)?.manifest();
                advertised.insert(id, manifest.blobs()?);
                send(stream, manifest, limit)?;
            }
            Event::NeedBlob { tree, blob } => {
                // A manifest may already be known by the scheduler. The
                // caller must authorize against its prepared input even if
                // this connection never received NeedTree for that tree.
                let blobs = match advertised.entry(tree) {
                    std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(inputs.tree(tree)?.manifest().blobs()?)
                    }
                };
                ensure!(
                    blobs.get(&blob.id) == Some(&blob.size),
                    "undeclared native input blob"
                );
                let Some(mut reader) = inputs.open_source(tree, blob)? else {
                    send(stream, &false, limit)?;
                    continue;
                };
                send(stream, &true, limit)?;
                let mut remaining = blob.size;
                while remaining > 0 {
                    let count = usize::try_from(remaining.min(u64::try_from(buffer.len())?))?;
                    reader.read_exact(&mut buffer[..count])?;
                    stream.write_all(&buffer[..count])?;
                    remaining -= u64::try_from(count)?;
                }
            }
            Event::Ready { source, manifest } => {
                crate::server::activity::phase(crate::server::activity::Phase::RestoreOutputs);
                let staged = fetch_result(
                    spec,
                    &manifest,
                    &destinations.eager,
                    inputs,
                    policy.max_result_bytes,
                    |blob, destination| {
                        send(stream, &ResultRequest::Blob(blob), limit)?;
                        // Bound this read to the current blob, rather than consuming
                        // the following framed message. Verify again at the caller.
                        copy_verified(stream.take(blob.size), blob, destination)
                    },
                )?;
                send(stream, &ResultRequest::Finish, limit)?;
                match receive(stream, limit)? {
                    Event::Done => {
                        let references = destinations.stage(&manifest)?;
                        let output = staged.install()?;
                        references.install()?;
                        return Ok(NativeBuildResult {
                            source,
                            output,
                            manifest: Some(manifest),
                        });
                    }
                    _ => bail!("unexpected native result completion"),
                }
            }
            Event::Failed { source, failure } => {
                return Ok(NativeBuildResult {
                    source,
                    output: failed_output(failure)?,
                    manifest: None,
                });
            }
            Event::Done => bail!("unexpected native action completion"),
        }
    }
}
