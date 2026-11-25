//! TLS contexts with an exclusive cluster trust store and role-bound peer names.

use super::{Identity, PeerId, Role, authenticated_peer};
use anyhow::{Context, Result, ensure};
use btls::{
    stack::Stack,
    x509::{X509, X509Ref, X509StoreContext, store::X509StoreBuilder, verify::X509Purpose},
};
use std::time::Duration;

fn validate_purpose(ca: &X509Ref, leaf: &X509Ref, purpose: X509Purpose) -> Result<()> {
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(ca.to_owned())?;
    store.verify_param_mut().set_purpose(purpose)?;
    let store = store.build();
    let chain = Stack::new()?;
    let mut context = X509StoreContext::new()?;
    let (valid, error) = context.init(&store, leaf, &chain, |context| {
        Ok((context.verify_cert()?, context.verify_result()))
    })?;
    ensure!(valid, "invalid cluster leaf: {error:?}");
    Ok(())
}

/// Verify the persisted identity and issuer independently of certificate
/// lifetime. Only renewal recovery uses this without the full TLS checks.
pub fn verify_leaf_identity(
    identity: &Identity,
    certificate: &X509Ref,
    ca: &X509Ref,
    role: Role,
) -> Result<()> {
    ensure!(
        authenticated_peer(certificate, role)? == identity.id()?,
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
            .context("missing certificate issuer")?
            .try_cmp(ca.subject_name().context("missing CA subject")?)?
            .is_eq(),
        "unexpected certificate issuer"
    );
    Ok(())
}

/// A local TLS leaf and key, restricted to its enrolled role and cluster.
pub struct TlsCredentials {
    pub(crate) identity: Identity,
    pub(crate) certificate: X509,
    pub(crate) ca: X509,
    pub(crate) role: Role,
}

impl TlsCredentials {
    /// Assemble local credentials returned by an authenticated issuer.
    ///
    /// # Errors
    /// Rejects a leaf with an unexpected key, identity, role or issuer signature.
    pub fn new(identity: Identity, certificate: X509, ca: X509, role: Role) -> Result<Self> {
        verify_leaf_identity(&identity, &certificate, &ca, role)?;
        validate_purpose(&ca, &certificate, X509Purpose::TlsClient)?;
        if role != Role::Client {
            validate_purpose(&ca, &certificate, X509Purpose::TlsServer)?;
        }
        Ok(Self {
            identity,
            certificate,
            ca,
            role,
        })
    }

    /// Load the persisted leaf for an existing identity and provisioned trust.
    ///
    /// # Errors
    /// Returns an error for invalid or expired credentials or storage failure.
    pub fn load(
        identity: Identity,
        certificate_path: &std::path::Path,
        ca: X509,
        role: Role,
    ) -> Result<Self> {
        let bytes = std::fs::read(certificate_path)?;
        Self::new(identity, X509::from_der(&bytes)?, ca, role)
    }

    /// Atomically persist the verified leaf without replacing the private key.
    ///
    /// # Errors
    /// Returns an error if certificate encoding or durable publication fails.
    pub fn persist(&self, path: &std::path::Path) -> Result<()> {
        use std::io::Write;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&self.certificate.to_der()?)?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|error| error.error)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    /// Return the stable enrolled identity.
    ///
    /// # Errors
    /// Returns an error if the local public key cannot be encoded.
    pub fn id(&self) -> Result<PeerId> {
        self.identity.id()
    }

    /// Whether renewal is due before the supplied horizon.
    ///
    /// # Errors
    /// Returns an error if the time cannot be compared to the certificate.
    pub fn renewal_due(&self, within: Duration) -> Result<bool> {
        let remaining =
            btls::asn1::Asn1Time::days_from_now(0)?.diff(self.certificate.not_after())?;
        let seconds = i64::from(remaining.days) * 86400 + i64::from(remaining.secs);
        Ok(u64::try_from(seconds).map_or(true, |seconds| seconds <= within.as_secs()))
    }
}
