//! The control plane and each worker have independent TLS trust contexts.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow, ensure};
use tokio::sync::Mutex as AsyncMutex;

use super::{
    common::ServerCertificateHttpResponse,
    transport::{self, RequestClass, send_async},
    urls,
};
use crate::dist::ServerId;

#[derive(Clone)]
struct WorkerTrust {
    digest: Vec<u8>,
    client: reqwest::Client,
}

type Slot = Arc<AsyncMutex<Option<WorkerTrust>>>;

#[derive(Clone, Copy)]
enum Lookup<'a> {
    Current,
    Allocation(&'a [u8]),
    AfterFailure(&'a [u8]),
}

impl Lookup<'_> {
    fn accepts(self, digest: &[u8]) -> bool {
        match self {
            Self::Current => true,
            Self::Allocation(expected) => digest == expected,
            Self::AfterFailure(previous) => digest != previous,
        }
    }
}

pub(super) struct WorkerTrustCache {
    control: reqwest::Client,
    scheduler: reqwest::Url,
    auth: String,
    workers: Mutex<HashMap<ServerId, Slot>>,
}

impl WorkerTrustCache {
    pub(super) fn new(control: reqwest::Client, scheduler: reqwest::Url, auth: String) -> Self {
        Self {
            control,
            scheduler,
            auth,
            workers: Mutex::default(),
        }
    }

    fn slot(&self, server: ServerId) -> Result<Slot> {
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| anyhow!("worker trust cache poisoned"))?;
        if let Some(slot) = workers.get(&server) {
            return Ok(Arc::clone(slot));
        }
        // The cache only retains reusable clients, not per-job credentials.
        // An in-flight refresh owns its slot independently of this map.
        if workers.len() >= 256 {
            workers.retain(|_, slot| Arc::strong_count(slot) > 1);
        }
        let slot = Arc::new(AsyncMutex::new(None));
        if workers.len() < 256 {
            workers.insert(server, Arc::clone(&slot));
        }
        drop(workers);
        Ok(slot)
    }

    async fn resolve(&self, server: ServerId, lookup: Lookup<'_>) -> Result<WorkerTrust> {
        let slot = self.slot(server)?;
        let mut cached = slot.lock().await;
        if let Some(trust) = cached
            .as_ref()
            .filter(|trust| lookup.accepts(&trust.digest))
        {
            return Ok(trust.clone());
        }
        let url = urls::scheduler_server_certificate(&self.scheduler, server)?;
        let response: ServerCertificateHttpResponse = send_async(
            self.control.get(url).bearer_auth(&self.auth),
            RequestClass::Control,
        )
        .await
        .context("retrieve current worker certificate from scheduler")?;
        let certificate =
            transport::verified_worker_certificate(&response.cert_digest, &response.cert_pem)?;
        if let Lookup::Allocation(expected) = lookup {
            ensure!(
                response.cert_digest == expected,
                "worker {server:?} certificate changed during allocation"
            );
        }
        // A refresh that confirms the existing pin must not rebuild or retry.
        if let Some(trust) = cached
            .as_ref()
            .filter(|trust| trust.digest == response.cert_digest)
        {
            return Ok(trust.clone());
        }
        let trust = WorkerTrust {
            digest: response.cert_digest,
            client: transport::pinned_async_client(certificate)?,
        };
        debug!(
            "Installed verified TLS pin for {server:?}: {:02x?}",
            trust.digest
        );
        *cached = Some(trust.clone());
        drop(cached);
        Ok(trust)
    }

    pub(super) async fn allocation(&self, server: ServerId, digest: &[u8]) -> Result<()> {
        self.resolve(server, Lookup::Allocation(digest)).await?;
        Ok(())
    }

    pub(super) async fn send<T: serde::de::DeserializeOwned>(
        &self,
        server: ServerId,
        class: RequestClass,
        request: impl Fn(&reqwest::Client) -> Result<reqwest::RequestBuilder>,
    ) -> Result<T> {
        let trust = self.resolve(server, Lookup::Current).await?;
        match send_async(request(&trust.client)?, class).await {
            Err(error)
                if error
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(reqwest::Error::is_connect) =>
            {
                let fresh = self
                    .resolve(server, Lookup::AfterFailure(&trust.digest))
                    .await?;
                if fresh.digest == trust.digest {
                    return Err(error);
                }
                info!(
                    "Worker {server:?} TLS pin rotated: {:02x?} -> {:02x?}",
                    trust.digest, fresh.digest
                );
                // A connect failure precedes sending the request body. Do not
                // replay a request after an ambiguous HTTP/body failure.
                send_async(request(&fresh.client)?, class).await
            }
            outcome => outcome,
        }
    }
}

#[cfg(all(test, feature = "dist-server"))]
mod tests {
    use super::*;
    use std::{net::SocketAddr, sync::mpsc, thread};

    struct RunningServer {
        thread: Option<thread::JoinHandle<()>>,
        stop: mpsc::Sender<()>,
    }

    impl Drop for RunningServer {
        fn drop(&mut self) {
            let _ = self.stop.send(());
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn stop_handle<F>(server: rouille::Server<F>) -> RunningServer
    where
        F: Fn(&rouille::Request) -> rouille::Response + Send + Sync + 'static,
    {
        let (thread, stop) = server.stoppable();
        RunningServer {
            thread: Some(thread),
            stop,
        }
    }

    fn worker(
        address: SocketAddr,
        response: u32,
    ) -> Result<(RunningServer, ServerId, ServerCertificateHttpResponse)> {
        let (cert_digest, cert_pem, key) =
            super::super::server::create_https_cert_and_privkey(address)?;
        let bytes = bincode::serialize(&response)?;
        let server = rouille::Server::new_ssl(
            address,
            move |_| rouille::Response::from_data("application/octet-stream", bytes.clone()),
            cert_pem.clone(),
            key,
        )
        .map_err(|error| anyhow!("{error}"))?
        .pool_size(2);
        let address = server.server_addr();
        Ok((
            stop_handle(server),
            ServerId::new(address),
            ServerCertificateHttpResponse {
                cert_digest,
                cert_pem,
            },
        ))
    }

    async fn query(cache: &WorkerTrustCache, server: ServerId) -> Result<u32> {
        let url = reqwest::Url::parse(&format!("https://{}/test", server.addr()))?;
        cache
            .send(server, RequestClass::Control, |client| {
                Ok(client.post(url.clone()))
            })
            .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn long_lived_client_rotates_only_the_affected_worker_pin() -> Result<()> {
        let (old, first, certificate) = worker("127.0.0.1:0".parse()?, 1)?;
        let (_other, second, other_certificate) = worker("127.0.0.1:0".parse()?, 2)?;
        let certificates = Arc::new(Mutex::new(HashMap::from([
            (first, certificate.clone()),
            (second, other_certificate.clone()),
        ])));
        let advertised = Arc::clone(&certificates);
        let scheduler = rouille::Server::new("127.0.0.1:0", move |request| {
            if request.header("Authorization") != Some("Bearer test-client") {
                return rouille::Response::text("unauthorized").with_status_code(401);
            }
            let Some(id) = request
                .url()
                .rsplit('/')
                .next()
                .and_then(|part| part.parse::<ServerId>().ok())
            else {
                return rouille::Response::empty_404();
            };
            let guard = advertised.lock().unwrap();
            guard
                .get(&id)
                .map_or_else(rouille::Response::empty_404, |cert| {
                    rouille::Response::from_data(
                        "application/octet-stream",
                        bincode::serialize(cert).unwrap(),
                    )
                })
        })
        .map_err(|error| anyhow!("{error}"))?
        .pool_size(4);
        let endpoint = reqwest::Url::parse(&format!("http://{}/", scheduler.server_addr()))?;
        let _scheduler = stop_handle(scheduler);
        let cache =
            WorkerTrustCache::new(transport::async_client()?, endpoint, "test-client".into());

        assert!(cache.allocation(first, &[0; 32]).await.is_err());
        cache.allocation(first, &certificate.cert_digest).await?;
        cache
            .allocation(second, &other_certificate.cert_digest)
            .await?;
        assert_eq!(query(&cache, first).await?, 1);
        assert_eq!(query(&cache, second).await?, 2);
        drop(old);
        let (_rotated, same, new_certificate) = worker(first.addr(), 3)?;
        assert_eq!(same, first);
        // An unverified change must not authorize a retry or poison the pin.
        certificates.lock().unwrap().insert(
            first,
            ServerCertificateHttpResponse {
                cert_digest: certificate.cert_digest.clone(),
                cert_pem: new_certificate.cert_pem.clone(),
            },
        );
        assert!(query(&cache, first).await.is_err());
        certificates
            .lock()
            .unwrap()
            .insert(first, new_certificate.clone());
        let (a, b, c) = tokio::join!(
            query(&cache, first),
            query(&cache, first),
            query(&cache, second)
        );
        assert_eq!((a?, b?, c?), (3, 3, 2));
        cache
            .allocation(first, &new_certificate.cert_digest)
            .await?;
        assert!(
            cache
                .allocation(first, &certificate.cert_digest)
                .await
                .is_err()
        );
        assert_eq!(query(&cache, first).await?, 3);
        Ok(())
    }
}
