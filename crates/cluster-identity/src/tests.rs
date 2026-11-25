use super::*;
use openssl::{
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{
        X509Ref,
        store::{X509Store, X509StoreBuilder},
    },
};
use std::net::{SocketAddr, TcpStream};

fn trust_store(ca: &X509Ref) -> Result<X509Store> {
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(ca.to_owned())?;
    Ok(store.build())
}

impl TlsCredentials {
    /// Configure a client with only the cluster CA, not system public roots.
    ///
    /// # Errors
    /// Returns an error if TLS context setup fails.
    fn connector(&self) -> Result<SslConnector> {
        let mut connector = SslConnector::builder(SslMethod::tls_client())?;
        connector.set_cert_store(trust_store(&self.ca)?);
        connector.set_certificate(&self.certificate)?;
        connector.set_private_key(self.identity.private_key())?;
        connector.check_private_key()?;
        connector.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        Ok(connector.build())
    }

    /// Build a server accepting only valid cluster certificates in allowed roles.
    ///
    /// # Errors
    /// Returns an error for invalid role configuration or TLS setup failure.
    fn acceptor(&self, allowed_roles: &[Role]) -> Result<SslAcceptor> {
        ensure!(
            self.role != Role::Client,
            "client-only credential cannot serve TLS"
        );
        ensure!(!allowed_roles.is_empty(), "server must allow a peer role");
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        acceptor.set_cert_store(trust_store(&self.ca)?);
        acceptor.set_certificate(&self.certificate)?;
        acceptor.set_private_key(self.identity.private_key())?;
        acceptor.check_private_key()?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        let allowed_roles = allowed_roles.to_vec();
        acceptor.set_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            move |verified, context| {
                verified
                    && (context.error_depth() != 0
                        || context.current_cert().is_some_and(|leaf| {
                            allowed_roles
                                .iter()
                                .any(|role| authenticated_peer(leaf, *role).is_ok())
                        }))
            },
        );
        Ok(acceptor.build())
    }

    /// Connect to a candidate address while authenticating the expected peer.
    ///
    /// # Errors
    /// Returns an error for connection, TLS handshake or identity failure.
    fn connect(
        &self,
        address: SocketAddr,
        expected: PeerId,
        role: Role,
        timeout: Duration,
    ) -> Result<openssl::ssl::SslStream<TcpStream>> {
        let stream = TcpStream::connect_timeout(&address, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let stream = self
            .connector()?
            .connect(&role.tls_name(expected), stream)?;
        let certificate = stream
            .ssl()
            .peer_certificate()
            .context("missing peer certificate")?;
        ensure!(
            authenticated_peer(&certificate, role)? == expected,
            "wrong peer identity"
        );
        Ok(stream)
    }
}

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

fn identity(directory: &tempfile::TempDir, label: &str) -> Result<Identity> {
    Identity::open(&directory.path().join(label))
}

#[test]
fn persistent_ca_and_key_survive_restart_and_renewal() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("ca.pem");
    let ca = ClusterCa::open(&path)?;
    let worker = identity(&directory, "worker")?;
    let first = ca.issue(&worker.request()?, Role::Worker, 7)?;
    let reopened = ClusterCa::open(&path)?;
    let restarted = identity(&directory, "worker")?;
    let second = reopened.issue(&restarted.request()?, Role::Worker, 7)?;
    assert_eq!(ca.certificate().to_der()?, reopened.certificate().to_der()?);
    assert_eq!(authenticated_peer(&first, Role::Worker)?, restarted.id()?);
    assert_eq!(authenticated_peer(&second, Role::Worker)?, restarted.id()?);
    assert_ne!(first.to_der()?, second.to_der()?);
    assert!(authenticated_peer(&second, Role::Client).is_err());
    assert!(ca.issue(&worker.request()?, Role::Worker, 0).is_err());
    Ok(())
}

#[test]
fn corrupt_ca_is_not_replaced() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("ca.pem");
    fs::write(&path, b"corrupt")?;
    assert!(ClusterCa::open(&path).is_err());
    assert_eq!(fs::read(path)?, b"corrupt");
    Ok(())
}

fn credentials(ca: &ClusterCa, identity: Identity, role: Role) -> Result<TlsCredentials> {
    let certificate = ca.issue(&identity.request()?, role, 7)?;
    TlsCredentials::new(identity, certificate, ca.certificate().clone(), role)
}

#[test]
fn genuine_mutual_tls_without_ip_san() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let ca = ClusterCa::open(&directory.path().join("ca.pem"))?;
    let scheduler = identity(&directory, "scheduler")?;
    let worker = identity(&directory, "worker")?;
    let expected_worker = worker.id()?;
    let expected_scheduler = scheduler.id()?;
    let acceptor = credentials(&ca, scheduler, Role::Scheduler)?.acceptor(&[Role::Worker])?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = thread::spawn(move || -> Result<()> {
        let mut stream = acceptor.accept(listener.accept()?.0)?;
        let peer = stream
            .ssl()
            .peer_certificate()
            .context("missing client certificate")?;
        assert_eq!(authenticated_peer(&peer, Role::Worker)?, expected_worker);
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes)?;
        assert_eq!(&bytes, b"ping");
        stream.write_all(b"pong")?;
        Ok(())
    });
    let worker = credentials(&ca, worker, Role::Worker)?;
    let mut stream = worker.connect(
        address,
        expected_scheduler,
        Role::Scheduler,
        Duration::from_secs(3),
    )?;
    stream.write_all(b"ping")?;
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes)?;
    assert_eq!(&bytes, b"pong");
    server
        .join()
        .map_err(|_| anyhow::anyhow!("server thread panicked"))??;
    Ok(())
}

#[test]
fn rejects_unexpected_server_identity_and_client_role() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let ca = ClusterCa::open(&directory.path().join("ca.pem"))?;
    let scheduler = identity(&directory, "scheduler")?;
    let expected_scheduler = scheduler.id()?;
    let worker = identity(&directory, "worker")?;
    let wrong_peer = worker.id()?;
    let worker = credentials(&ca, worker, Role::Worker)?;
    let client = credentials(&ca, identity(&directory, "client")?, Role::Client)?;
    assert!(client.acceptor(&[Role::Scheduler]).is_err());
    let acceptor = credentials(&ca, scheduler, Role::Scheduler)?.acceptor(&[Role::Worker])?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = thread::spawn(move || -> Result<()> {
        for _ in 0..2 {
            let (socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.set_write_timeout(Some(Duration::from_secs(3)))?;
            assert!(acceptor.accept(socket).is_err());
        }
        Ok(())
    });
    let timeout = Duration::from_secs(3);
    assert!(
        worker
            .connect(address, wrong_peer, Role::Scheduler, timeout)
            .is_err()
    );
    // TLS 1.3 may report the server's client-auth rejection on the first read.
    if let Ok(mut stream) = client.connect(address, expected_scheduler, Role::Scheduler, timeout) {
        assert!(
            stream
                .write_all(b"ping")
                .and_then(|()| stream.read_exact(&mut [0; 4]))
                .is_err()
        );
    }
    server
        .join()
        .map_err(|_| anyhow::anyhow!("server thread panicked"))??;
    Ok(())
}

#[test]
fn refuses_wrong_key_and_wrong_issuer() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let ca = ClusterCa::open(&directory.path().join("ca.pem"))?;
    let alien_ca = ClusterCa::open(&directory.path().join("alien.pem"))?;
    let worker = identity(&directory, "worker")?;
    let certificate = ca.issue(&worker.request()?, Role::Worker, 7)?;
    assert!(
        TlsCredentials::new(
            identity(&directory, "other")?,
            certificate.clone(),
            ca.certificate().clone(),
            Role::Worker
        )
        .is_err()
    );
    assert!(
        TlsCredentials::new(
            worker,
            certificate,
            alien_ca.certificate().clone(),
            Role::Worker
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn first_enrollment_and_renewal_bind_roles_and_keys() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let authority = EnrollmentAuthority::new(
        ClusterCa::open(&directory.path().join("ca.pem"))?,
        Registry::open(&directory.path().join("registry.bin"))?,
        7,
    )?;
    let worker = identity(&directory, "worker")?;
    let request = EnrollmentRequest::new(&worker)?;
    assert!(authority.enroll(&request, || None).is_err());
    assert!(
        authority
            .enroll(&request, || Some(Role::Scheduler))
            .is_err()
    );
    let (certificate, role) = authority
        .enroll(&request, || Some(Role::Worker))?
        .into_certificate()?;
    assert_eq!(role, Role::Worker);
    assert_eq!(authenticated_peer(&certificate, role)?, worker.id()?);
    let other = identity(&directory, "other")?;
    assert!(
        authority
            .renew(&EnrollmentRequest::new(&other)?, worker.id()?, role)
            .is_err()
    );
    let (renewed, renewed_role) = authority
        .renew(&request, worker.id()?, role)?
        .into_certificate()?;
    assert_eq!(renewed_role, role);
    assert_eq!(authenticated_peer(&renewed, role)?, worker.id()?);
    assert_ne!(certificate.to_der()?, renewed.to_der()?);
    TlsCredentials::new(worker, renewed, authority.certificate().clone(), role)?;
    Ok(())
}

#[test]
fn registry_persists_role_and_revocation_and_excludes_other_writers() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("registry.bin");
    let peer = identity(&directory, "worker")?.id()?;
    let registry = Registry::open(&path)?;
    assert!(Registry::open(&path).is_err());
    registry.register(peer, Role::Worker)?;
    registry.register(peer, Role::Worker)?;
    assert!(registry.register(peer, Role::Client).is_err());
    assert!(registry.is_active(peer, Role::Worker)?);
    drop(registry);
    let registry = Registry::open(&path)?;
    assert!(registry.is_active(peer, Role::Worker)?);
    registry.revoke(peer)?;
    drop(registry);
    let registry = Registry::open(&path)?;
    assert!(!registry.is_active(peer, Role::Worker)?);
    assert!(registry.register(peer, Role::Worker).is_err());
    drop(registry);
    fs::write(&path, b"corrupt")?;
    assert!(Registry::open(&path).is_err());
    assert_eq!(fs::read(path)?, b"corrupt");
    Ok(())
}

#[test]
fn peer_identity_has_a_canonical_config_representation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let peer = identity(&directory, "peer")?.id()?;
    let encoded = peer.to_string();
    assert_eq!(encoded.len(), 64);
    assert_eq!(encoded.parse::<PeerId>()?, peer);
    assert!("127.0.0.1:10501".parse::<PeerId>().is_err());
    assert!("x".repeat(64).parse::<PeerId>().is_err());
    Ok(())
}
