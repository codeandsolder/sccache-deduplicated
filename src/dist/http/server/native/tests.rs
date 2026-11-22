use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
};

use super::*;
use crate::{
    build_runtime::{
        ActionFingerprint, Artifact, BlobRef, ContentId, ResultManifest, SessionLimits,
        wire::{NativeAdmission, NativeStatus},
    },
    dist::{JobId, ServerId, native::NativeCacheClient},
};

struct ClientCheck;

impl ClientAuthCheck for ClientCheck {
    fn check(&self, token: &str) -> std::result::Result<(), super::super::ClientVisibleMsg> {
        if token == "client-token" {
            Ok(())
        } else {
            Err(super::super::ClientVisibleMsg::from_nonsensitive(
                "invalid client".into(),
            ))
        }
    }
}

fn action() -> ActionRequest {
    ActionRequest {
        fingerprint: ActionFingerprint {
            schema: "native-test-v1".into(),
            components: BTreeMap::from([("input".into(), ContentId::of(b"source"))]),
        },
        input_trees: BTreeSet::new(),
        required_outputs: BTreeSet::from(["obj".into()]),
        optional_outputs: BTreeSet::new(),
    }
}

fn limits() -> SessionLimits {
    SessionLimits {
        idle_timeout: Duration::from_secs(30),
        max_sessions: 16,
        max_result_bytes: 32 * 1024 * 1024,
        max_result_blobs: 8,
        max_tree_bytes: 64 * 1024 * 1024,
        max_tree_blobs: 100,
        max_concurrent_uploads: 2,
        max_total_uploads: 4,
    }
}

fn make_client(url: &reqwest::Url, token: &str) -> Result<NativeCacheClient> {
    NativeCacheClient::new(
        url.clone(),
        token.into(),
        Duration::from_secs(10),
        1024 * 1024,
    )
}

#[test]
fn direct_worker_upload_and_verified_client_hit_over_http() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let sessions = Arc::new(NativeSessions::new(
        NativeStore::open(directory.path())?,
        limits(),
    )?);
    let worker: ServerId = "127.0.0.1:10501".parse()?;
    let server = rouille::Server::new("127.0.0.1:0", {
        let sessions = Arc::clone(&sessions);
        move |request| {
            respond(
                request,
                &sessions,
                &|job| {
                    ensure!(
                        job.job_id == JobId(42)
                            && job.server_id == worker
                            && job.auth == "allocation-proof",
                        "invalid job capability"
                    );
                    Ok(())
                },
                &ClientCheck,
                &move |token| (token == "worker-token").then_some(worker),
                1024 * 1024,
            )
        }
    })
    .map_err(|error| anyhow!("{error}"))?
    .pool_size(4);
    let url = reqwest::Url::parse(&format!("http://{}/", server.server_addr()))?;
    let (handle, stop) = server.stoppable();
    let outcome = (|| -> Result<()> {
        let client = make_client(&url, "client-token")?;
        let worker_client = make_client(&url, "worker-token")?.for_worker(JobId(42));
        let wrong_job = worker_client.clone().for_worker(JobId(43));
        let unauthorized = make_client(&url, "bad-token")?;
        assert!(unauthorized.admit(&action()).is_err());

        let NativeAdmission::Compile { ticket } = client.admit(&action())? else {
            anyhow::bail!("expected compilation");
        };
        assert_eq!(client.admit(&action())?, NativeAdmission::InFlight);
        let mut allocation = JobAlloc {
            server_id: worker,
            job_id: JobId(42),
            auth: "bad-proof".into(),
        };
        assert!(client.delegate(ticket, allocation.clone()).is_err());
        allocation.auth = "allocation-proof".into();
        client.delegate(ticket, allocation)?;
        worker_client.renew(ticket)?;
        assert!(client.renew(ticket).is_err());
        assert!(wrong_job.renew(ticket).is_err());

        let bytes = vec![0x5a; 2 * 1024 * 1024];
        let blob = BlobRef {
            id: ContentId::of(&bytes),
            size: u64::try_from(bytes.len())?,
        };
        let output = ResultManifest {
            outputs: BTreeMap::from([(
                "obj".into(),
                Artifact {
                    blob,
                    mode: Some(0o644),
                },
            )]),
            stdout: None,
            stderr: None,
        };
        assert_eq!(
            worker_client.begin(ticket, output.clone())?.missing,
            vec![blob]
        );
        assert!(worker_client.commit(ticket).is_err());
        assert!(
            wrong_job
                .upload(ticket, blob, Cursor::new(bytes.clone()))
                .is_err()
        );
        assert!(
            worker_client
                .upload(ticket, blob, Cursor::new(vec![0; bytes.len()]))
                .is_err()
        );
        worker_client.upload(ticket, blob, Cursor::new(bytes.clone()))?;
        assert_eq!(worker_client.commit(ticket)?, output);
        assert_eq!(client.status(ticket)?, NativeStatus::Ready(output.clone()));
        let mut downloaded = Vec::new();
        client.download(ticket, blob, &mut downloaded)?;
        assert_eq!(downloaded, bytes);
        assert!(
            client
                .download(
                    ticket,
                    BlobRef {
                        id: ContentId::of(b"other"),
                        size: 5
                    },
                    Vec::new()
                )
                .is_err()
        );
        assert!(worker_client.status(ticket).is_err());
        let NativeAdmission::Hit {
            ticket: hit,
            manifest,
        } = client.admit(&action())?
        else {
            anyhow::bail!("expected stored hit");
        };
        assert_eq!(manifest, output);
        client.close(ticket)?;
        client.close(hit)?;
        assert_eq!(sessions.store().stats()?.blobs, 1);
        Ok(())
    })();
    stop.send(()).map_err(|error| anyhow!("{error}"))?;
    handle
        .join()
        .map_err(|_| anyhow!("native HTTP test server panicked"))?;
    outcome
}

#[test]
fn metadata_is_bounded_and_rejects_trailing_bytes() -> Result<()> {
    let request = Request::fake_http(
        "POST",
        "/api/v2/native/client/status",
        Vec::new(),
        vec![0; 33],
    );
    assert!(metadata::<crate::build_runtime::wire::Ticket>(&request, 32).is_err());
    let request = Request::fake_http(
        "POST",
        "/api/v2/native/client/status",
        Vec::new(),
        vec![0; 33],
    );
    assert!(metadata::<crate::build_runtime::wire::Ticket>(&request, 64).is_err());
    let header = UploadHeader {
        ticket: crate::build_runtime::wire::Ticket([7; 32]),
        blob: BlobRef {
            id: ContentId::of(b"abc"),
            size: 3,
        },
    };
    let encoded = codec().serialize(&header)?;
    assert_eq!(encoded.len(), 72);
    Ok(())
}
