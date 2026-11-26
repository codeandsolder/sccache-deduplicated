//! Regression for idle uploads retaining the worker's HTTP and execution slots.
use std::{io, net::SocketAddr, path::Path, sync::Arc, time::Duration};

use bytes::Bytes;
use futures::{StreamExt as _, stream};
use sccache::{
    compression::deflate::ZlibWriter,
    dist::{
        AllocJobResult, ArchiveId, Client as _, CompileCommand, JobAlloc, OutputRequest,
        RunJobResult, SubmitToolchainResult, Toolchain,
        http::{Client, urls},
        pkg::ToolchainPackageBuilder,
    },
    errors::{Context as _, Result, anyhow, bail},
    util::Digest,
};
use sccache_cluster_identity::{ClusterHttpClient, PeerCredentials, Role};
use tokio::{io::AsyncReadExt as _, sync::oneshot, task::JoinSet};

use crate::harness;

const SOURCE: &[u8] = b".text\n.globl entry\nentry:\n.byte 1, 2, 3, 4\n";
const REQUEST_LIMIT: Duration = Duration::from_secs(130);
const HEALTHY_LIMIT: Duration = Duration::from_secs(30);

struct Archive {
    content: Bytes,
    toolchain: Toolchain,
}

impl Archive {
    fn new(package: &ToolchainPackageBuilder, path: &Path) -> Result<Self> {
        package.write_compressed_tar(std::fs::File::create(path)?)?;
        let content = Bytes::from(std::fs::read(path)?);
        let toolchain = Toolchain {
            archive_id: ArchiveId::try_from(Digest::reader_sync(content.as_ref())?)?,
        };
        Ok(Self { content, toolchain })
    }
}

struct ArchiveClient {
    client: Client,
    peer: Arc<PeerCredentials>,
    worker: SocketAddr,
    archives: [Archive; 3],
    run: Bytes,
    run_prefix: Bytes,
    reference: Vec<u8>,
}

impl ArchiveClient {
    fn new(root: &Path, system: &harness::DistSystem, worker: SocketAddr) -> Result<Self> {
        let assembler = which::which("as")?;
        let mut package = ToolchainPackageBuilder::new();
        package.add_common()?;
        package.add_executable_and_deps(assembler.clone())?;
        let archive_path = root.join("toolchain.tar.gz");
        let healthy_archive = Archive::new(&package, &archive_path)?;
        let first_marker = root.join("first-marker");
        std::fs::write(&first_marker, b"first")?;
        package.add_file(first_marker)?;
        let first_archive = Archive::new(&package, &archive_path)?;
        let second_marker = root.join("second-marker");
        std::fs::write(&second_marker, b"second")?;
        package.add_file(second_marker)?;
        let second_archive = Archive::new(&package, &archive_path)?;

        std::fs::write(root.join("input.s"), SOURCE)?;
        let local = std::process::Command::new(&assembler)
            .current_dir(root)
            .args(["-o", "reference.o", "input.s"])
            .output()?;
        anyhow::ensure!(
            local.status.success(),
            "reference assembler failed: {:?}",
            local.stderr
        );
        let reference = std::fs::read(root.join("reference.o"))?;
        let command = CompileCommand {
            umask: Some(0o022),
            executable: assembler
                .to_str()
                .context("non-UTF-8 assembler path")?
                .to_owned(),
            arguments: ["-o", "/out.o", "/input.s"].map(str::to_owned).to_vec(),
            env_vars: Vec::new(),
            cwd: "/".into(),
        };
        let outputs = OutputRequest {
            paths: vec!["/out.o".into()],
            compression_level: 1,
        };
        // The wire request is a length-prefixed bincode struct (command,
        // outputs), followed by a zlib-compressed tar of the compiler inputs.
        let metadata = bincode::serialize(&(command, outputs))?;
        let mut run = u32::try_from(metadata.len())?.to_be_bytes().to_vec();
        run.extend_from_slice(&metadata);
        let header_len = run.len();
        let mut inputs = tar::Builder::new(ZlibWriter::new(&mut run)?);
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(SOURCE.len())?);
        header.set_cksum();
        inputs.append_data(&mut header, "input.s", SOURCE)?;
        inputs.into_inner()?.finish()?;
        let run = Bytes::from(run);
        let run_prefix = run.slice(..header_len + 2);
        let peer = sccache::dist::cluster::open_peer(
            system.cluster_config(),
            &system.scheduler_url().to_url(),
            Role::Client,
            || Ok(sccache::config::INSECURE_DIST_CLIENT_TOKEN.to_owned()),
        )?;
        let client = Client::new(
            sccache::http_client::io_runtime()?.handle(),
            Arc::clone(&peer),
            &root.join("raw-client-toolchains"),
            64 * 1024 * 1024,
            &[],
            false,
        )?;
        Ok(Self {
            client,
            peer,
            worker,
            archives: [first_archive, second_archive, healthy_archive],
            run,
            run_prefix,
            reference,
        })
    }

    async fn allocate(&self, archive: &Archive, need_toolchain: bool) -> Result<JobAlloc> {
        let AllocJobResult::Success {
            job_alloc,
            need_toolchain: requested,
        } = self.client.do_alloc_job(archive.toolchain.clone()).await?
        else {
            bail!("scheduler refused archive allocation");
        };
        assert_eq!(requested, need_toolchain);
        Ok(job_alloc)
    }

    fn request(&self, job: &JobAlloc, upload: bool, stalled: bool) -> Result<wreq::RequestBuilder> {
        let credential = self.peer.current()?;
        let path = if stalled {
            ClusterHttpClient::new_bound(
                &credential,
                job.server_id,
                Role::Worker,
                self.worker,
                ("127.0.0.2".parse()?, Some("lo")),
            )?
        } else {
            ClusterHttpClient::new(&credential, job.server_id, Role::Worker, self.worker)?
        };
        let url = if upload {
            urls::server_submit_toolchain(path.base(), job.job_id)?
        } else {
            urls::server_run_job(path.base(), job.job_id)?
        };
        Ok(path
            .client()
            .post(url.as_str())
            .bearer_auth(&job.auth)
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            // Give the server's idle deadline time to fire before the client.
            .read_timeout(REQUEST_LIMIT)
            .timeout(REQUEST_LIMIT))
    }

    async fn upload(&self, job: &JobAlloc, archive: &Archive) -> Result<()> {
        let response = self
            .request(job, true, false)?
            .body(archive.content.clone())
            .send()
            .await?
            .error_for_status()?;
        assert!(matches!(
            bincode::deserialize::<SubmitToolchainResult>(&response.bytes().await?)?,
            SubmitToolchainResult::Success
        ));
        Ok(())
    }

    async fn compile(&self, job: &JobAlloc) -> Result<()> {
        let response = self
            .request(job, false, false)?
            .body(self.run.clone())
            .send()
            .await?
            .error_for_status()?;
        let RunJobResult::Complete(result) = bincode::deserialize(&response.bytes().await?)? else {
            bail!("worker lost a valid assignment");
        };
        assert_eq!(result.output.code, 0, "{:?}", result.output.stderr);
        let [(path, frame)] = result
            .outputs
            .try_into()
            .map_err(|_: Vec<_>| anyhow!("expected one output"))?;
        assert_eq!(path, "/out.o");
        let mut object = Vec::new();
        let _verified = frame.materialize(&mut object)?;
        assert_eq!(object, self.reference);
        Ok(())
    }

    async fn stall(
        &self,
        jobs: &mut JoinSet<Result<Stalled>>,
        job: &JobAlloc,
        archive: Option<&Archive>,
    ) -> Result<()> {
        let upload = archive.is_some();
        let request = self.request(job, upload, true)?;
        let prefix = archive.map_or_else(
            || self.run_prefix.clone(),
            |archive| archive.content.slice(..1024),
        );
        let (waiting, started) = oneshot::channel();
        let body = stream::iter([Ok::<_, io::Error>(prefix)]).chain(stream::once(async move {
            let _ = waiting.send(());
            std::future::pending::<io::Result<Bytes>>().await
        }));
        jobs.spawn(async move {
            let response = request.body(wreq::Body::wrap_stream(body)).send().await?;
            let status = response.status();
            let body = response.bytes().await?;
            if upload {
                assert!(status.is_success(), "toolchain failure response: {status}");
                assert!(matches!(
                    bincode::deserialize::<SubmitToolchainResult>(&body)?,
                    SubmitToolchainResult::CannotCache
                ));
                Ok(Stalled::Toolchain)
            } else {
                assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR);
                assert!(
                    String::from_utf8_lossy(&body).contains("distributed request body idle"),
                    "run failure must come from the server's body idle timeout: {body:?}"
                );
                Ok(Stalled::Run)
            }
        });
        tokio::time::timeout(HEALTHY_LIMIT, started).await??;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Stalled {
    Toolchain,
    Run,
}

async fn stalled_handshakes(worker: SocketAddr) -> Result<JoinSet<Result<()>>> {
    let mut sockets = JoinSet::new();
    for _ in 0..3 {
        let mut socket = tokio::net::TcpStream::connect(worker).await?;
        sockets.spawn(async move {
            let mut bytes = [0; 64];
            tokio::time::timeout(HEALTHY_LIMIT, async {
                loop {
                    match socket.read(&mut bytes).await {
                        Ok(0) => return Ok(()),
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    }
                }
            })
            .await??;
            Ok(())
        });
    }
    Ok(sockets)
}

#[test]
#[cfg_attr(
    not(feature = "dist-tests"),
    ignore = "requires isolated Docker distribution harness"
)]
fn test_dist_transport_stalled_peers_do_not_starve_worker() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let mut system = harness::DistSystem::new(&harness::sccache_dist_path(), root);
    system.add_scheduler();
    let worker = system.add_server(&[]);
    let url = match &worker {
        harness::ServerHandle::Container { url, .. }
        | harness::ServerHandle::Process { url, .. } => url,
    };
    let worker = sccache_cluster_identity::endpoint(&url.to_url())?;
    let client = ArchiveClient::new(root, &system, worker)?;
    let [first_archive, second_archive, healthy_archive] = &client.archives;
    assert!(
        client
            .archives
            .iter()
            .all(|archive| archive.content.len() > 1024)
    );

    sccache::http_client::io_runtime()?.block_on(async {
        let mut handshakes = stalled_handshakes(worker).await?;
        let mut stalls = JoinSet::new();
        // Two unrelated archives stall while a third remains available.
        let first = client.allocate(first_archive, true).await?;
        let second = client.allocate(second_archive, true).await?;
        client
            .stall(&mut stalls, &first, Some(first_archive))
            .await?;
        client
            .stall(&mut stalls, &second, Some(second_archive))
            .await?;
        let run = client.allocate(healthy_archive, true).await?;
        client.upload(&run, healthy_archive).await?;
        client.stall(&mut stalls, &run, None).await?;

        // Healthy traffic on the local path must not wait for the stalled
        // remote-path bodies to expire. A real assembler result is checked.
        tokio::time::timeout(HEALTHY_LIMIT, async {
            assert_eq!(client.client.do_get_status().await?.num_servers, 1);
            let healthy = client.allocate(healthy_archive, false).await?;
            client.compile(&healthy).await?;
            assert_eq!(client.client.do_get_status().await?.in_progress, 3);
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        assert!(
            stalls.try_join_next().is_none(),
            "healthy build finished only after a stall ended"
        );
        while let Some(result) = handshakes.join_next().await {
            result??;
        }

        let mut uploads = 0;
        let mut runs = 0;
        while let Some(result) = stalls.join_next().await {
            match result?? {
                Stalled::Toolchain => uploads += 1,
                Stalled::Run => runs += 1,
            }
        }
        assert_eq!((uploads, runs), (2, 1));
        // The aborted run releases its scheduler reservation. Pending upload
        // reservations intentionally remain retryable until their lease expires.
        assert_eq!(client.client.do_get_status().await?.in_progress, 2);
        for (job, archive) in [(&first, first_archive), (&second, second_archive)] {
            client.upload(job, archive).await?;
            client.compile(job).await?;
        }
        let healthy = client.allocate(healthy_archive, false).await?;
        client.compile(&healthy).await?;
        assert_eq!(client.client.do_get_status().await?.in_progress, 0);
        Ok(())
    })
}
