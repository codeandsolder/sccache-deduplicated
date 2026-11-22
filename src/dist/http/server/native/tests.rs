use std::{collections::BTreeMap, io::Cursor};

use super::*;
use crate::{
    build_runtime::{
        Artifact, BlobRef, BuildPath, CommandSpec, ContentId, ExecutionRoot, ExecutionSpec,
        OutputSpec, ResultManifest, SessionLimits, TreeManifest, TreeMetadata, TreeRecipe,
        TreeTimestamp,
        wire::{NativeAdmission, NativeStatus, ScheduleReply, WorkerAllocation},
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

fn action(root: &TreeManifest) -> Result<ExecutionSpec> {
    let id = root.id()?;
    Ok(ExecutionSpec {
        platform: ContentId::of(b"test-platform"),
        root: ExecutionRoot::resolve(
            TreeRecipe::union(
                TreeMetadata {
                    mode: 0o755,
                    modified: TreeTimestamp {
                        seconds: 1,
                        nanoseconds: 0,
                    },
                },
                [id],
            ),
            &BTreeMap::from([(id, root)]),
        )?,
        mounts: BTreeMap::new(),
        command: CommandSpec {
            executable: BuildPath::new(b"/bin/tool".to_vec())?,
            arguments: Vec::new(),
            cwd: BuildPath::new(b"/".to_vec())?,
            environment: BTreeMap::new(),
        },
        outputs: BTreeMap::from([(
            "obj".into(),
            OutputSpec {
                path: BuildPath::new(b"/out/obj".to_vec())?,
                required: true,
            },
        )]),
    })
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

fn with_native_service(
    operation: impl FnOnce(&reqwest::Url, &NativeSessions) -> Result<()>,
) -> Result<()> {
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
                &move |_| {
                    Ok(ScheduleReply::Assigned(WorkerAllocation {
                        address: worker.addr(),
                        job: 42,
                        auth: "allocation-proof".into(),
                        certificate: vec![1],
                    }))
                },
                &ClientCheck,
                &move |token| (token == "worker-token").then_some(worker),
                1024 * 1024,
                None,
            )
        }
    })
    .map_err(|error| anyhow!("{error}"))?
    .pool_size(4);
    let url = reqwest::Url::parse(&format!("http://{}/", server.server_addr()))?;
    let (handle, stop) = server.stoppable();
    let outcome = operation(&url, &sessions);
    stop.send(()).map_err(|error| anyhow!("{error}"))?;
    handle
        .join()
        .map_err(|_| anyhow!("native HTTP test server panicked"))?;
    outcome
}

#[test]
fn direct_worker_upload_and_verified_client_hit_over_http() -> Result<()> {
    with_native_service(|url, sessions| {
        let client = make_client(url, "client-token")?;
        let worker_client = make_client(url, "worker-token")?.for_worker(JobId(42));
        let wrong_job = worker_client.clone().for_worker(JobId(43));
        let unauthorized = make_client(url, "bad-token")?;
        let root = TreeManifest {
            root: TreeMetadata {
                mode: 0o755,
                modified: TreeTimestamp {
                    seconds: 1,
                    nanoseconds: 0,
                },
            },
            entries: BTreeMap::new(),
        };
        let offer = client.offer_tree(&root)?;
        assert!(offer.missing.is_empty());
        assert_eq!(client.commit_tree(offer.ticket)?, root.id()?);
        let spec = action(&root)?;

        assert!(unauthorized.admit(&spec).is_err());

        let NativeAdmission::Compile { ticket } = client.admit(&spec)? else {
            anyhow::bail!("expected compilation");
        };
        assert_eq!(client.admit(&spec)?, NativeAdmission::InFlight);
        let mut wrong_spec = spec.clone();
        wrong_spec.command.arguments.push(b"changed".to_vec());
        assert!(client.schedule(ticket, wrong_spec).is_err());
        let allocation = client.schedule(ticket, spec.clone())?;
        assert!(matches!(allocation, ScheduleReply::Assigned(_)));
        assert_eq!(client.schedule(ticket, spec.clone())?, allocation);
        worker_client.renew(ticket)?;
        worker_client.verify_execution(ticket, spec.clone())?;
        let mut wrong = spec.clone();
        wrong.command.arguments.push(b"changed".to_vec());
        assert!(worker_client.verify_execution(ticket, wrong).is_err());
        assert!(wrong_job.verify_execution(ticket, spec.clone()).is_err());
        client.close(offer.ticket)?;
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
        } = client.admit(&spec)?
        else {
            anyhow::bail!("expected stored hit");
        };
        assert_eq!(manifest, output);
        client.close(ticket)?;
        client.close(hit)?;
        assert_eq!(sessions.store().stats()?.blobs, 1);
        Ok(())
    })
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

#[test]
#[cfg(target_os = "linux")]
#[ignore = "requires Linux Bubblewrap and ldd"]
fn native_action_transfers_inputs_executes_and_publishes_without_worker_result_store() -> Result<()>
{
    use crate::build_runtime::ExecutionPolicy;
    use std::{fs, process::Command};
    with_native_service(|url, sessions| {
        let directory = tempfile::tempdir()?;
        let sender = NativeStore::open(&directory.path().join("sender"))?;
        let worker_store = NativeStore::open(&directory.path().join("worker"))?;
        let root = directory.path().join("root");
        for name in ["bin", "out", "tmp", "proc", "dev", "src"] {
            fs::create_dir_all(root.join(name))?;
        }
        fs::copy("/bin/sh", root.join("bin/tool"))?;
        let dependencies = Command::new("ldd").arg("/bin/sh").output()?;
        ensure!(
            dependencies.status.success(),
            "cannot determine shell dependencies"
        );
        for line in std::str::from_utf8(&dependencies.stdout)?.lines() {
            if let Some(path) = line.split_whitespace().find(|part| part.starts_with('/')) {
                let destination = root.join(path.strip_prefix('/').context("library path")?);
                fs::create_dir_all(destination.parent().context("library parent")?)?;
                fs::copy(path, destination)?;
            }
        }
        let root = sender.capture_tree(&root)?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("input"), b"hello native\n")?;
        let source = sender.capture_tree(&source)?;
        let client = make_client(url, "client-token")?;
        let worker = make_client(url, "worker-token")?.for_worker(JobId(42));
        let root_pin = client.push_tree(
            root.manifest(),
            |id| root.open_file(id),
            Duration::from_secs(1),
        )?;
        let source_pin = client.push_tree(
            source.manifest(),
            |id| source.open_file(id),
            Duration::from_secs(1),
        )?;
        let mut spec = action(root.manifest())?;
        spec.mounts
            .insert(BuildPath::new(b"/src".to_vec())?, source.id());
        spec.command.arguments = vec![b"-c".to_vec(), b"IFS= read -r data < /src/input; printf '%s' \"$data\" > /out/obj; printf diagnostic >&2".to_vec()];
        let NativeAdmission::Compile { ticket } = client.admit(&spec)? else {
            anyhow::bail!("expected native compilation");
        };
        assert!(matches!(
            client.schedule(ticket, spec.clone())?,
            ScheduleReply::Assigned(_)
        ));
        client.close(root_pin)?;
        client.close(source_pin)?;
        let policy = ExecutionPolicy {
            platform: spec.platform,
            bubblewrap: "/usr/bin/bwrap".into(),
            scratch: directory.path().into(),
            timeout: Duration::from_secs(10),
            max_result_bytes: 1024,
        };
        let result = worker.execute_on_worker(
            ticket,
            &spec,
            &worker_store,
            &policy,
            Duration::from_secs(1),
            None,
        )?;
        let manifest = result
            .successful_result()
            .context("native execution failed")?;
        assert_eq!(
            client.status(ticket)?,
            NativeStatus::Ready(manifest.clone())
        );
        let mut bytes = Vec::new();
        client.download(ticket, manifest.outputs["obj"].blob, &mut bytes)?;
        assert_eq!(bytes, b"hello native");
        bytes.clear();
        client.download(
            ticket,
            manifest.stderr.context("missing diagnostics")?,
            &mut bytes,
        )?;
        assert_eq!(bytes, b"diagnostic");
        assert_eq!(worker_store.stats()?.actions, 0);
        assert_eq!(sessions.store().stats()?.actions, 1);
        let NativeAdmission::Hit {
            ticket: hit,
            manifest: cached,
        } = client.admit(&spec)?
        else {
            anyhow::bail!("expected cache hit");
        };
        assert_eq!(&cached, manifest);
        client.close(ticket)?;
        client.close(hit)?;
        Ok(())
    })
}
