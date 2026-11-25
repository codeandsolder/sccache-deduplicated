//! Enrollment client that authenticates the scheduler before sending a token.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{Result, ensure};
use bincode::Options;
use openssl::x509::X509;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

use super::{CONTROL_LIMIT, CONTROL_TIMEOUT, ENROLL_CLIENT, ENROLL_WORKER, RENEW, codec};
use crate::{EnrollmentRequest, EnrollmentResponse, Identity, PeerId, Role, TlsCredentials};

fn client_config(ca: &X509, credentials: Option<&TlsCredentials>) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.to_der()?))?;
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots);
    let config = match credentials {
        Some(credentials) => {
            ensure!(
                credentials.ca.to_der()? == ca.to_der()?,
                "credential belongs to another cluster"
            );
            config.with_client_auth_cert(
                vec![CertificateDer::from(credentials.certificate.to_der()?)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    credentials.identity.private_key().private_key_to_pkcs8()?,
                )),
            )?
        }
        None => config.with_no_client_auth(),
    };
    Ok(config)
}

/// A pooled HTTPS connection path to one specific cluster service.
pub struct ClusterHttpClient {
    client: reqwest::Client,
    base: reqwest::Url,
}

impl ClusterHttpClient {
    /// Build a mutually authenticated client for one candidate endpoint.
    ///
    /// # Errors
    /// Returns an error for invalid credentials, role or transport configuration.
    pub fn new(
        credentials: &TlsCredentials,
        expected: PeerId,
        role: Role,
        address: SocketAddr,
    ) -> Result<Self> {
        Self::with_trust(
            &credentials.ca,
            expected,
            role,
            address,
            Some(credentials),
            None,
        )
    }

    /// Pin a pooled transport to a local source and, on Linux, its device.
    ///
    /// # Errors
    /// Returns an error for invalid trust or transport configuration.
    pub fn new_bound(
        credentials: &TlsCredentials,
        expected: PeerId,
        role: Role,
        address: SocketAddr,
        source: (IpAddr, Option<&str>),
    ) -> Result<Self> {
        Self::with_trust(
            &credentials.ca,
            expected,
            role,
            address,
            Some(credentials),
            Some(source),
        )
    }

    fn with_trust(
        ca: &X509,
        expected: PeerId,
        role: Role,
        address: SocketAddr,
        credentials: Option<&TlsCredentials>,
        source: Option<(IpAddr, Option<&str>)>,
    ) -> Result<Self> {
        let config = client_config(ca, credentials)?;
        ensure!(
            role != Role::Client,
            "client-only identity has no TLS service"
        );
        let name = role.tls_name(expected);
        let base = reqwest::Url::parse(&format!("https://{name}:{}/", address.port()))?;
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(config)
            .resolve(&name, address)
            .no_proxy()
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(std::time::Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONTROL_TIMEOUT)
            .read_timeout(std::time::Duration::from_secs(90));
        if let Some((ip, device)) = source {
            builder = builder.local_address(ip);
            #[cfg(target_os = "linux")]
            if let Some(device) = device {
                builder = builder.interface(device);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = device;
        }
        let client = builder.build()?;
        Ok(Self { client, base })
    }

    /// The pinned service origin, independent of its candidate socket address.
    #[must_use = "requests must target the logical TLS authority"]
    pub const fn base(&self) -> &reqwest::Url {
        &self.base
    }

    /// Clone the pooled HTTP client for integration with existing RPC builders.
    #[must_use = "use the client only for its pinned logical service origin"]
    pub fn client(&self) -> reqwest::Client {
        self.client.clone()
    }

    /// Build a request to this authenticated service, rejecting foreign URLs.
    ///
    /// # Errors
    /// Returns an error if the path escapes the configured service origin.
    pub fn request(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder> {
        let url = self.base.join(path)?;
        ensure!(
            url.origin() == self.base.origin()
                && url.username().is_empty()
                && url.password().is_none(),
            "request leaves cluster service origin"
        );
        Ok(self.client.request(method, url))
    }
}

/// Blocking HTTP client bound to the expected principal and candidate endpoint.
///
/// # Errors
/// Returns an error if trust, identity or HTTP configuration is invalid.
pub fn blocking_client(
    credentials: &TlsCredentials,
    expected: PeerId,
    role: Role,
    address: SocketAddr,
    timeout: std::time::Duration,
) -> Result<(reqwest::blocking::Client, reqwest::Url)> {
    blocking_client_bound(credentials, expected, role, address, timeout, None)
}

/// Blocking transport with an optional explicit local address/device.
///
/// # Errors
/// Returns an error for invalid trust or transport configuration.
pub fn blocking_client_bound(
    credentials: &TlsCredentials,
    expected: PeerId,
    role: Role,
    address: SocketAddr,
    timeout: std::time::Duration,
    source: Option<(IpAddr, Option<&str>)>,
) -> Result<(reqwest::blocking::Client, reqwest::Url)> {
    ensure!(
        role != Role::Client,
        "client-only identity has no TLS service"
    );
    let name = role.tls_name(expected);
    let base = reqwest::Url::parse(&format!("https://{name}:{}/", address.port()))?;
    let mut builder = reqwest::blocking::Client::builder()
        .tls_backend_preconfigured(client_config(&credentials.ca, Some(credentials))?)
        .resolve(&name, address)
        .no_proxy()
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONTROL_TIMEOUT)
        .timeout(timeout);
    if let Some((ip, device)) = source {
        builder = builder.local_address(ip);
        #[cfg(target_os = "linux")]
        if let Some(device) = device {
            builder = builder.interface(device);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = device;
    }
    let client = builder.build()?;
    Ok((client, base))
}

/// A client pinned to the cluster CA and expected scheduler public key.
/// The route may change without changing TLS authority.
pub struct EnrollmentClient {
    transport: ClusterHttpClient,
    ca: X509,
}

impl EnrollmentClient {
    /// Connect using a provisioned CA, logical scheduler identity and candidate address.
    ///
    /// # Errors
    /// Returns an error if trust or client configuration is invalid.
    pub fn new(
        ca: &X509,
        scheduler: PeerId,
        address: SocketAddr,
        credentials: Option<&TlsCredentials>,
    ) -> Result<Self> {
        let transport = ClusterHttpClient::with_trust(
            ca,
            scheduler,
            Role::Scheduler,
            address,
            credentials,
            None,
        )?;
        Ok(Self {
            transport,
            ca: ca.clone(),
        })
    }

    /// First enrollment with an authorized worker or client token.
    ///
    /// # Errors
    /// Returns an error for transport, authorization or certificate validation failure.
    pub async fn enroll(
        &self,
        identity: Identity,
        role: Role,
        token: &str,
    ) -> Result<TlsCredentials> {
        let path = match role {
            Role::Worker => ENROLL_WORKER,
            Role::Client => ENROLL_CLIENT,
            Role::Scheduler => anyhow::bail!("scheduler identity cannot be remotely enrolled"),
        };
        let request = self
            .transport
            .request(reqwest::Method::POST, path)?
            .bearer_auth(token);
        self.issue(request, identity, role).await
    }

    /// Renew on a connection configured with the currently enrolled credential.
    ///
    /// # Errors
    /// Returns an error if the issuer refuses renewal or the new leaf is invalid.
    pub async fn renew(&self, identity: Identity, role: Role) -> Result<TlsCredentials> {
        self.issue(
            self.transport.request(reqwest::Method::POST, RENEW)?,
            identity,
            role,
        )
        .await
    }

    async fn issue(
        &self,
        request: reqwest::RequestBuilder,
        identity: Identity,
        role: Role,
    ) -> Result<TlsCredentials> {
        let mut reply = request
            .timeout(CONTROL_TIMEOUT)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(codec().serialize(&EnrollmentRequest::new(&identity)?)?)
            .send()
            .await?
            .error_for_status()?;
        let mut bytes = Vec::new();
        while let Some(chunk) = reply.chunk().await? {
            ensure!(
                chunk.len() <= CONTROL_LIMIT.saturating_sub(bytes.len()),
                "certificate response exceeds limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let issued: EnrollmentResponse = codec().deserialize(&bytes)?;
        let (leaf, assigned_role) = issued.into_certificate()?;
        ensure!(assigned_role == role, "unexpected issued role");
        TlsCredentials::new(identity, leaf, self.ca.clone(), role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClusterCa, ClusterListener, EnrollmentAuthority, Registry, SchedulerEnrollment};
    use hyper::StatusCode;
    use tokio::{net::TcpListener, task::JoinHandle};

    struct Server {
        address: SocketAddr,
        id: PeerId,
        ca: X509,
        enrollment: Arc<SchedulerEnrollment>,
        task: JoinHandle<Result<()>>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn server(directory: &std::path::Path, data_only: bool) -> Result<Server> {
        let authority = EnrollmentAuthority::new(
            ClusterCa::open(&directory.join("ca.pem"))?,
            Registry::initialize(&directory.join("registry.bin"))?,
            7,
        )?;
        let scheduler = Identity::open(&directory.join("scheduler.pem"))?;
        let id = scheduler.id()?;
        let ca = authority.certificate().clone();
        let leaf = authority.scheduler_certificate(&scheduler)?;
        let credentials = TlsCredentials::new(scheduler, leaf, ca.clone(), Role::Scheduler)?;
        let tls = Arc::new(if data_only {
            ClusterListener::new_data(&credentials)?
        } else {
            ClusterListener::new(&credentials)?
        });
        let enrollment = Arc::new(SchedulerEnrollment::new(authority, |role, _, _, token| {
            matches!(
                (role, token),
                (Role::Worker, "worker-token") | (Role::Client, "client-token")
            )
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let router = tls.scheduler_router(
            Arc::clone(&enrollment),
            axum::Router::new().fallback(
                |axum::extract::Extension(peer): axum::extract::Extension<
                    super::super::AuthenticatedPeer,
                >| {
                    std::future::ready(format!("{}:{:?}", peer.id(), peer.role()))
                },
            ),
        )?;
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted?;
                        let tls = Arc::clone(&tls);
                        let router = router.clone();
                        connections.spawn(async move { tls.serve(socket, router).await });
                    },
                    Some(_) = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        });
        Ok(Server {
            address,
            id,
            ca,
            enrollment,
            task,
        })
    }

    fn expired_leaf(ca: &ClusterCa, identity: Identity) -> Result<TlsCredentials> {
        use openssl::{asn1::Asn1Time, hash::MessageDigest};
        let mut builder = ca.leaf_builder(&identity.request()?, Role::Worker, 7)?;
        builder.set_not_before(Asn1Time::from_unix(1)?.as_ref())?;
        builder.set_not_after(Asn1Time::from_unix(2)?.as_ref())?;
        builder.sign(&ca.key, MessageDigest::sha256())?;
        Ok(TlsCredentials {
            identity,
            certificate: builder.build(),
            ca: ca.certificate().clone(),
            role: Role::Worker,
        })
    }

    #[tokio::test]
    async fn expired_running_peer_reenrolls_once_and_revocation_still_wins() -> Result<()> {
        use crate::{PeerConfig, PeerCredentials, open_identity, publish_trust_anchor};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let directory = tempfile::tempdir()?;
        let server = server(directory.path(), false).await?;
        let anchor = directory.path().join("anchor.pem");
        publish_trust_anchor(&server.ca, &anchor)?;
        let config = PeerConfig {
            directory: directory.path().join("member"),
            ca_certificate: anchor,
            scheduler_id: server.id,
        };
        let ca = ClusterCa::open(&directory.path().join("ca.pem"))?;
        let calls = Arc::new(AtomicUsize::new(0));
        let token_calls = Arc::clone(&calls);
        let peer = PeerCredentials::open(config.clone(), server.address, Role::Worker, move || {
            token_calls.fetch_add(1, Ordering::Relaxed);
            Ok("worker-token".into())
        })
        .await?;
        let member_id = peer.current()?.id()?;
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        peer.install_test_credential(expired_leaf(&ca, open_identity(&config)?)?)?;
        let (first, second) = tokio::join!(peer.refresh(), peer.refresh());
        let (first, second) = (first?, second?);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.id()?, member_id);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        let reloaded = TlsCredentials::load(
            open_identity(&config)?,
            &config.directory.join("leaf.der"),
            server.ca.clone(),
            Role::Worker,
        )?;
        assert_eq!(first.certificate.to_der()?, reloaded.certificate.to_der()?);
        peer.install_test_credential(expired_leaf(&ca, open_identity(&config)?)?)?;
        server.enrollment.authority().registry().revoke(member_id)?;
        assert!(peer.refresh().await.is_err());
        assert!(peer.refresh().await.is_err()); // retry delay, not another enrollment
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert!(peer.current()?.renewal_due(std::time::Duration::ZERO)?);
        Ok(())
    }

    #[tokio::test]
    async fn data_listener_requires_mutual_tls() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let server = server(directory.path(), true).await?;
        let key_path = directory.path().join("worker.pem");
        let identity = Identity::open(&key_path)?;
        let request = EnrollmentRequest::new(&identity)?;
        let (leaf, role) = server
            .enrollment
            .authority()
            .enroll(&request, |_| Some(Role::Worker))?
            .into_certificate()?;
        let credentials = TlsCredentials::new(identity, leaf, server.ca.clone(), role)?;
        let data =
            ClusterHttpClient::new(&credentials, server.id, Role::Scheduler, server.address)?;
        let probe = data
            .request(reqwest::Method::GET, "/api/v1/cluster/probe")?
            .send()
            .await?;
        assert_eq!(probe.status(), StatusCode::NO_CONTENT);
        let ip = server.address.ip();
        assert_eq!(
            probe
                .headers()
                .get(crate::PATH_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(crate::NetworkPath::new(ip, ip).to_string().as_str())
        );
        let enrolled =
            EnrollmentClient::new(&server.ca, server.id, server.address, Some(&credentials))?;
        assert!(
            enrolled
                .renew(Identity::open(&key_path)?, Role::Worker)
                .await
                .is_err()
        );
        let without_certificate =
            EnrollmentClient::new(&server.ca, server.id, server.address, None)?;
        let probe = without_certificate
            .transport
            .request(reqwest::Method::GET, "/api/v1/cluster/probe")?
            .send()
            .await;
        assert!(probe.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_renewal_and_revocation_on_real_https() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let server = server(directory.path(), false).await?;
        let key_path = directory.path().join("worker.pem");
        let leaf_path = directory.path().join("worker.der");
        let bootstrap = EnrollmentClient::new(&server.ca, server.id, server.address, None)?;
        let worker = Identity::open(&key_path)?;
        let worker_id = worker.id()?;
        // Supplying an identity in HTTP headers cannot authenticate an application request.
        let denied = bootstrap
            .transport
            .client
            .get(bootstrap.transport.base.join("probe")?)
            .header("X-Sccache-Peer", worker_id.to_string())
            .bearer_auth("worker-token")
            .send()
            .await?;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert!(
            bootstrap
                .enroll(Identity::open(&key_path)?, Role::Worker, "client-token")
                .await
                .is_err()
        );
        let wrong_scheduler = EnrollmentClient::new(&server.ca, worker_id, server.address, None)?;
        assert!(
            wrong_scheduler
                .enroll(Identity::open(&key_path)?, Role::Worker, "worker-token")
                .await
                .is_err()
        );
        let credential = bootstrap
            .enroll(worker, Role::Worker, "worker-token")
            .await?;
        assert_eq!(credential.id()?, worker_id);
        credential.persist(&leaf_path)?;
        let credential = TlsCredentials::load(
            Identity::open(&key_path)?,
            &leaf_path,
            server.ca.clone(),
            Role::Worker,
        )?;
        assert!(!credential.renewal_due(std::time::Duration::from_secs(3600))?);
        let enrolled =
            EnrollmentClient::new(&server.ca, server.id, server.address, Some(&credential))?;
        let probe = enrolled
            .transport
            .client
            .get(enrolled.transport.base.join("probe")?)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        assert_eq!(probe, format!("{worker_id}:Worker"));
        let renewed = enrolled
            .renew(Identity::open(&key_path)?, Role::Worker)
            .await?;
        assert_eq!(renewed.id()?, worker_id);
        assert_ne!(
            credential.certificate.to_der()?,
            renewed.certificate.to_der()?
        );
        renewed.persist(&leaf_path)?;
        assert!(
            enrolled
                .renew(
                    Identity::open(&directory.path().join("other.pem"))?,
                    Role::Worker
                )
                .await
                .is_err()
        );
        assert!(
            bootstrap
                .enroll(Identity::open(&key_path)?, Role::Client, "client-token")
                .await
                .is_err()
        );
        server.enrollment.authority().registry().revoke(worker_id)?;
        // This request uses the already established authenticated connection.
        let revoked = enrolled
            .transport
            .client
            .get(enrolled.transport.base.join("probe")?)
            .send()
            .await?;
        assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
        assert!(
            enrolled
                .renew(Identity::open(&key_path)?, Role::Worker)
                .await
                .is_err()
        );
        assert!(
            bootstrap
                .enroll(Identity::open(&key_path)?, Role::Worker, "worker-token")
                .await
                .is_err()
        );
        Ok(())
    }
}

#[cfg(test)]
mod worker_tests {
    use super::*;
    use crate::{ClusterCa, ClusterListener, EnrollmentAuthority, Registry};
    use hyper::StatusCode;
    use tokio::{net::TcpListener, task::JoinHandle};

    fn listen(
        listener: TcpListener,
        tls: Arc<ClusterListener>,
        authorized: PeerId,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let router = tls.worker_router(
                move |peer| peer.id() == authorized && peer.role() == Role::Scheduler,
                axum::Router::new().fallback(
                    |axum::extract::Extension(peer): axum::extract::Extension<
                        super::super::AuthenticatedPeer,
                    >| { std::future::ready(peer.id().to_string()) },
                ),
            )?;
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted?;
                        let tls = Arc::clone(&tls);
                        let router = router.clone();
                        connections.spawn(async move { tls.serve(socket, router).await });
                    },
                    Some(_) = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        })
    }

    #[tokio::test]
    async fn one_worker_identity_authenticates_on_two_routes_and_across_renewal() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let authority = EnrollmentAuthority::new(
            ClusterCa::open(&directory.path().join("ca.pem"))?,
            Registry::initialize(&directory.path().join("registry.bin"))?,
            7,
        )?;
        let ca = authority.certificate().clone();
        let worker_path = directory.path().join("worker.pem");
        let worker = Identity::open(&worker_path)?;
        let worker_id = worker.id()?;
        let worker_request = EnrollmentRequest::new(&worker)?;
        let (leaf, role) = authority
            .enroll(&worker_request, |_| Some(Role::Worker))?
            .into_certificate()?;
        let worker = TlsCredentials::new(worker, leaf, ca.clone(), role)?;
        let scheduler = Identity::open(&directory.path().join("scheduler.pem"))?;
        let scheduler_id = scheduler.id()?;
        let scheduler_leaf = authority.scheduler_certificate(&scheduler)?;
        let scheduler =
            TlsCredentials::new(scheduler, scheduler_leaf, ca.clone(), Role::Scheduler)?;
        let tls = Arc::new(ClusterListener::new(&worker)?);
        let first = TcpListener::bind("127.0.0.1:0").await?;
        let second = TcpListener::bind("127.0.0.1:0").await?;
        let first_addr = first.local_addr()?;
        let second_addr = second.local_addr()?;
        let first_task = listen(first, Arc::clone(&tls), scheduler_id);
        let second_task = listen(second, Arc::clone(&tls), scheduler_id);
        let first_path = ClusterHttpClient::new(&scheduler, worker_id, Role::Worker, first_addr)?;
        assert_eq!(
            first_path
                .request(reqwest::Method::GET, "/probe")?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?,
            scheduler_id.to_string()
        );
        #[cfg(target_os = "linux")]
        {
            // A second source address to the very same remote service is a
            // separate pooled path, without changing TLS principal identity.
            let source = "127.0.0.2".parse()?;
            let bound = ClusterHttpClient::new_bound(
                &scheduler,
                worker_id,
                Role::Worker,
                first_addr,
                (source, Some("lo")),
            )?;
            let response = bound
                .request(reqwest::Method::GET, "/probe")?
                .send()
                .await?
                .error_for_status()?;
            let path: crate::NetworkPath = response
                .headers()
                .get(super::super::PATH_HEADER)
                .ok_or_else(|| anyhow::anyhow!("missing authenticated path"))?
                .to_str()?
                .parse()?;
            assert_eq!(path.remote, source);
            assert_eq!(path.local, first_addr.ip());
            assert_eq!(response.text().await?, scheduler_id.to_string());
        }
        let (renewed, role) = authority
            .renew(&worker_request, worker_id, Role::Worker)?
            .into_certificate()?;
        let renewed =
            TlsCredentials::new(Identity::open(&worker_path)?, renewed, ca.clone(), role)?;
        tls.reload(&renewed)?;
        assert!(tls.reload(&scheduler).is_err());
        let second_path = ClusterHttpClient::new(&scheduler, worker_id, Role::Worker, second_addr)?;
        assert_eq!(
            second_path
                .request(reqwest::Method::GET, "/probe")?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?,
            scheduler_id.to_string()
        );
        assert!(
            second_path
                .request(reqwest::Method::GET, "//foreign.invalid/")
                .is_err()
        );
        let wrong_peer =
            ClusterHttpClient::new(&scheduler, scheduler_id, Role::Worker, second_addr)?;
        assert!(
            wrong_peer
                .request(reqwest::Method::GET, "/probe")?
                .send()
                .await
                .is_err()
        );
        let anonymous =
            ClusterHttpClient::with_trust(&ca, worker_id, Role::Worker, first_addr, None, None)?;
        assert!(
            anonymous
                .request(reqwest::Method::GET, "/probe")?
                .send()
                .await
                .is_err()
        );
        let wrong_role = ClusterHttpClient::new(&renewed, worker_id, Role::Worker, first_addr)?;
        assert_eq!(
            wrong_role
                .request(reqwest::Method::GET, "/probe")?
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        first_task.abort();
        second_task.abort();
        Ok(())
    }
}
