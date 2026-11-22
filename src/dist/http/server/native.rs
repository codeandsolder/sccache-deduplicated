//! Dedicated native cache listener. Reuse scheduler authentication and job
//! ownership without running filesystem I/O on the scheduling request pool.

use std::{io::Read, sync::Arc, thread, time::Duration};

use anyhow::{Context, Result, anyhow, ensure};
use bincode::Options;
use rouille::{Request, Response};
use serde::{Serialize, de::DeserializeOwned};

use super::{ClientAuthCheck, ServerAuthenticator, authenticate_client, authenticate_server};
use crate::{
    build_runtime::{
        ExecutionSpec, NativeSessions, NativeStore,
        wire::{Publisher, ScheduleReply, UploadHeader},
    },
    config::scheduler::NativeCacheConfig,
    dist::native::{DownloadRequest, ExecutionRequest, ManifestRequest, OpenTreeRequest, codec},
};

pub(super) type Allocator =
    dyn Fn(crate::dist::NativeAssignment) -> Result<ScheduleReply> + Send + Sync;

pub(super) fn spawn(
    config: &NativeCacheConfig,
    allocate: impl Fn(crate::dist::NativeAssignment) -> Result<ScheduleReply> + Send + Sync + 'static,
    client_auth: Arc<dyn ClientAuthCheck>,
    server_auth: Arc<ServerAuthenticator>,
) -> Result<()> {
    let limits = config.session_limits()?;
    let sessions = Arc::new(NativeSessions::new(
        NativeStore::open_managed(&config.directory, config.space)?,
        limits,
    )?);
    let maintenance = Arc::downgrade(&sessions);
    let metadata_limit = config.max_metadata_bytes;
    let server = rouille::Server::new(config.public_addr, move |request| {
        respond(
            request,
            &sessions,
            &allocate,
            &*client_auth,
            &*server_auth,
            metadata_limit,
        )
    })
    .map_err(|error| anyhow!("could not bind native cache listener: {error}"))?
    .pool_size(config.http_threads);
    info!("Native cache listening on {}", config.public_addr);
    thread::Builder::new()
        .name("native-cache-maintenance".into())
        .spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(1));
                let Some(maintenance) = maintenance.upgrade() else {
                    break;
                };
                if let Err(error) = maintenance.reap() {
                    error!("native cache session reap failed: {error:#}");
                }
                match maintenance.store().maintain_space() {
                    Ok(Some(report)) if !report.minimum_satisfied => {
                        warn!("native cache space pressure: {report:?}");
                    }
                    Ok(_) => {}
                    Err(error) => error!("native cache space maintenance failed: {error:#}"),
                }
            }
        })?;
    thread::Builder::new()
        .name("native-cache-http".into())
        .spawn(move || {
            server.run();
            error!("native cache HTTP listener terminated");
        })?;
    Ok(())
}

const PREFIX: &str = "/api/v2/native/";

fn respond(
    request: &Request,
    sessions: &NativeSessions,
    allocate: &Allocator,
    client_auth: &dyn ClientAuthCheck,
    server_auth: &ServerAuthenticator,
    limit: usize,
) -> Response {
    if request.method() != "POST" {
        return Response::empty_404();
    }
    let url = request.url();
    let Some(path) = url.strip_prefix(PREFIX) else {
        return Response::empty_404();
    };
    let Some((role, operation)) = path.split_once('/') else {
        return Response::empty_404();
    };
    let publisher = match role {
        "client" => {
            if let Err(response) = authenticate_client(request, client_auth) {
                return response;
            }
            Publisher::Client
        }
        "worker" => {
            let server = match authenticate_server(request, server_auth) {
                Ok(server) => server,
                Err(response) => return response,
            };
            let Some(job) = request
                .header("X-Sccache-Native-Job")
                .and_then(|job| job.parse::<u64>().ok())
            else {
                return Response::empty_400();
            };
            Publisher::Worker {
                address: server.addr(),
                job,
            }
        }
        _ => return Response::empty_404(),
    };
    if request.header("Content-Type") != Some("application/octet-stream") {
        return Response::empty_400();
    }
    match dispatch(request, sessions, allocate, publisher, operation, limit) {
        Ok(response) => response,
        Err(error) => {
            // Do not return host paths, auth tokens or raw internal metadata
            // to callers. The service log carries diagnostic context.
            warn!("Native cache {operation} rejected: {error:#}");
            Response::text("native cache operation rejected").with_status_code(409)
        }
    }
}

fn dispatch(
    request: &Request,
    sessions: &NativeSessions,
    allocate: &Allocator,
    publisher: Publisher,
    operation: &str,
    limit: usize,
) -> Result<Response> {
    match operation {
        "admit" if publisher == Publisher::Client => {
            let input: ExecutionSpec = metadata(request, limit)?;
            encode(&sessions.admit(input.action_request()?, publisher)?, limit)
        }
        "schedule" if publisher == Publisher::Client => {
            let ExecutionRequest { ticket, spec } = metadata(request, limit)?;
            let request = spec.action_request()?;
            encode(
                &sessions.schedule(ticket, &request, || {
                    allocate(crate::dist::NativeAssignment { ticket, spec })
                })?,
                limit,
            )
        }
        "status" if publisher == Publisher::Client => {
            encode(&sessions.status(metadata(request, limit)?)?, limit)
        }
        "close" => {
            sessions.close(metadata(request, limit)?, publisher)?;
            encode(&(), limit)
        }
        "download" => {
            let DownloadRequest { ticket, id } = metadata(request, limit)?;
            let file = sessions.download(ticket, publisher, id)?;
            Ok(Response::from_file("application/octet-stream", file))
        }
        "tree_offer" if publisher == Publisher::Client => {
            encode(&sessions.offer_tree(metadata(request, limit)?)?, limit)
        }
        "tree_commit" if publisher == Publisher::Client => {
            encode(&sessions.commit_tree(metadata(request, limit)?)?, limit)
        }
        "tree_open" => {
            let OpenTreeRequest { action, tree } = metadata(request, limit)?;
            encode(&sessions.open_tree(tree, publisher, Some(action))?, limit)
        }
        "verify" => {
            let ExecutionRequest { ticket, spec } = metadata(request, limit)?;
            sessions.verify_execution(ticket, publisher, &spec.action_request()?)?;
            encode(&(), limit)
        }
        "begin" => {
            let ManifestRequest { ticket, manifest } = metadata(request, limit)?;
            encode(&sessions.begin(ticket, publisher, manifest)?, limit)
        }
        "upload" => {
            let mut body = request.data().context("missing native upload body")?;
            // Fixed-width header, never deserialize or buffer the actual blob.
            let header: UploadHeader = codec().with_limit(72).deserialize_from(&mut body)?;
            sessions.upload(header.ticket, publisher, header.blob, body)?;
            encode(&(), limit)
        }
        "commit" => encode(
            &sessions.commit(metadata(request, limit)?, publisher)?,
            limit,
        ),
        "renew" => {
            sessions.renew(metadata(request, limit)?, publisher)?;
            encode(&(), limit)
        }
        "fail" => {
            sessions.fail(metadata(request, limit)?, publisher)?;
            encode(&(), limit)
        }
        _ => Ok(Response::empty_404()),
    }
}

pub(super) fn metadata<T: DeserializeOwned>(request: &Request, limit: usize) -> Result<T> {
    let limit = u64::try_from(limit)?;
    let max_read = limit
        .checked_add(1)
        .context("native metadata limit overflow")?;
    let mut data = Vec::new();
    request
        .data()
        .context("missing native metadata body")?
        .take(max_read)
        .read_to_end(&mut data)?;
    ensure!(
        u64::try_from(data.len())? <= limit,
        "native metadata exceeds configured limit"
    );
    Ok(codec().with_limit(limit).deserialize(&data)?)
}

fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Response> {
    let data = codec().with_limit(u64::try_from(limit)?).serialize(value)?;
    Ok(Response::from_data("application/octet-stream", data))
}

#[cfg(test)]
mod tests;
