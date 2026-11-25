//! TLS contexts with an exclusive cluster trust store and role-bound peer names.

use super::{Identity, PeerId, Role, authenticated_peer};
use anyhow::{Context, Result, ensure};
use openssl::{
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode, SslVersion},
    stack::Stack,
    x509::{
        X509, X509PurposeId, X509Ref, X509StoreContext,
        store::{X509Store, X509StoreBuilder},
    },
};
use std::{
    net::{SocketAddr, TcpStream},
    time::Duration,
};

fn trust_store(ca: &X509Ref) -> Result<X509Store> {
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(ca.to_owned())?;
    Ok(store.build())
}

fn validate_purpose(ca: &X509Ref, leaf: &X509Ref, purpose: X509PurposeId) -> Result<()> {
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(ca.to_owned())?;
    store.set_purpose(purpose)?;
    let store = store.build();
    let chain = Stack::new()?;
    let mut context = X509StoreContext::new()?;
    let (valid, error) = context.init(&store, leaf, &chain, |context| {
        Ok((context.verify_cert()?, context.error()))
    })?;
    ensure!(valid, "invalid cluster leaf: {error}");
    Ok(())
}

/// A local TLS leaf and key, restricted to its enrolled role and cluster.
pub struct TlsCredentials {
    identity: Identity,
    certificate: X509,
    ca: X509,
    role: Role,
}

impl TlsCredentials {
    /// Assemble local credentials returned by an authenticated issuer.
    ///
    /// # Errors
    /// Rejects a leaf with an unexpected key, identity, role or issuer signature.
    pub fn new(identity: Identity, certificate: X509, ca: X509, role: Role) -> Result<Self> {
        ensure!(
            authenticated_peer(&certificate, role)? == identity.id()?,
            "issued certificate does not match local key"
        );
        let issuer_key = ca.public_key()?;
        ensure!(
            certificate.verify(&issuer_key)?,
            "invalid cluster leaf signature"
        );
        ensure!(
            certificate
                .issuer_name()
                .try_cmp(ca.subject_name())?
                .is_eq(),
            "unexpected certificate issuer"
        );
        validate_purpose(&ca, &certificate, X509PurposeId::SSL_CLIENT)?;
        if role != Role::Client {
            validate_purpose(&ca, &certificate, X509PurposeId::SSL_SERVER)?;
        }
        Ok(Self {
            identity,
            certificate,
            ca,
            role,
        })
    }

    /// Configure a client with only the cluster CA, not system public roots.
    ///
    /// # Errors
    /// Returns an error if TLS context setup fails.
    pub fn connector(&self) -> Result<SslConnector> {
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
    pub fn acceptor(&self, allowed_roles: &[Role]) -> Result<SslAcceptor> {
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
    pub fn connect(
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
