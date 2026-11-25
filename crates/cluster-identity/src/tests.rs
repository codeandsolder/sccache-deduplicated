use super::*;
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
    let authority =
        EnrollmentAuthority::new(ClusterCa::open(&directory.path().join("ca.pem"))?, 7)?;
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
