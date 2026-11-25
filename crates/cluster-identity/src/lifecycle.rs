//! Persistent peer credential lifecycle, shared by the worker and build client.

use std::{
    fs,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use openssl::{asn1::Asn1Time, x509::X509};

use super::{EnrollmentClient, Identity, PeerId, Role, TlsCredentials};
use sccache_peer_identity::PeerConfig;

const RENEWAL_WINDOW: Duration = Duration::from_hours(24);

/// Persistent member identity and current certificate. The scheduler is
/// authenticated before any enrollment credential is transmitted.
pub struct PeerCredentials {
    config: PeerConfig,
    ca: X509,
    scheduler: SocketAddr,
    role: Role,
    current: Mutex<Arc<TlsCredentials>>,
}

/// Open the member key before requesting a key-bound enrollment token.
///
/// # Errors
/// Returns an error for invalid paths or identity storage failure.
pub fn open_identity(config: &PeerConfig) -> Result<Identity> {
    ensure!(
        config.directory.is_absolute() && config.ca_certificate.is_absolute(),
        "cluster credential paths must be absolute"
    );
    fs::create_dir_all(&config.directory)?;
    Identity::open(&config.directory.join("key.pem"))
}

fn load_ca(config: &PeerConfig) -> Result<X509> {
    Ok(X509::from_pem(&fs::read(&config.ca_certificate)?)?)
}

impl PeerCredentials {
    /// Load an existing credential, or enroll the persistent key on first use.
    /// The bootstrap token is requested only for first enrollment or expired leaves.
    /// Expired members re-enroll the same key under the current bootstrap policy.
    /// Renewal failure leaves a still-valid existing leaf usable.
    ///
    /// # Errors
    /// Returns an error for invalid local state, rejected enrollment or unusable credentials.
    pub async fn open(
        config: PeerConfig,
        scheduler: SocketAddr,
        role: Role,
        enrollment_token: impl FnOnce() -> Result<String>,
    ) -> Result<Self> {
        ensure!(
            role != Role::Scheduler,
            "scheduler must use the local issuer"
        );
        let identity = open_identity(&config)?;
        let ca = load_ca(&config)?;
        let path = config.directory.join("leaf.der");
        let persisted = match fs::read(&path) {
            Ok(bytes) => Some(X509::from_der(&bytes).context("invalid persisted certificate DER")?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let credential = if let Some(certificate) = &persisted
            && !certificate
                .not_after()
                .compare(&Asn1Time::days_from_now(0)?)?
                .is_lt()
        {
            TlsCredentials::new(identity, certificate.clone(), ca.clone(), role).context(
                "persisted peer certificate is invalid; explicitly re-enroll if required",
            )?
        } else {
            // Expired leaves cannot authenticate renewal. Re-enroll the
            // same private key using bootstrap policy; an invalid or foreign
            // persisted certificate is never silently treated as absent.
            if let Some(certificate) = &persisted {
                super::tls::verify_leaf_identity(&identity, certificate, &ca, role)?;
            }
            let token = enrollment_token()?;
            let client = EnrollmentClient::new(&ca, config.scheduler_id, scheduler, None)?;
            let credential = client.enroll(identity, role, &token).await?;
            credential.persist(&path)?;
            credential
        };
        Ok(Self {
            config,
            ca,
            scheduler,
            role,
            current: Mutex::new(Arc::new(credential)),
        })
    }

    /// Return the current leaf without holding a lock across network I/O.
    ///
    /// # Errors
    /// Returns an error if credential storage is poisoned.
    pub fn current(&self) -> Result<Arc<TlsCredentials>> {
        self.current
            .lock()
            .map(|credential| Arc::clone(&credential))
            .map_err(|_| anyhow::anyhow!("cluster credentials poisoned"))
    }

    /// Renew a near-expiry leaf, preserving the local identity and role.
    ///
    /// # Errors
    /// Returns an error if renewal or durable publication fails.
    pub async fn refresh(&self) -> Result<Arc<TlsCredentials>> {
        let current = self.current()?;
        if !current.renewal_due(RENEWAL_WINDOW)? {
            return Ok(current);
        }
        let client = EnrollmentClient::new(
            &self.ca,
            self.config.scheduler_id,
            self.scheduler,
            Some(&current),
        )?;
        let renewed = Arc::new(
            client
                .renew(open_identity(&self.config)?, self.role)
                .await?,
        );
        let mut active = self
            .current
            .lock()
            .map_err(|_| anyhow::anyhow!("cluster credentials poisoned"))?;
        if Arc::ptr_eq(&current, &active) {
            renewed.persist(&self.config.directory.join("leaf.der"))?;
            *active = renewed;
        }
        let credential = Arc::clone(&active);
        drop(active);
        Ok(credential)
    }

    /// Scheduler identity as provisioned out of band.
    #[must_use = "the scheduler principal is used to authenticate all routes"]
    pub const fn scheduler_id(&self) -> PeerId {
        self.config.scheduler_id
    }

    /// The configured reliable scheduler control endpoint.
    #[must_use = "the endpoint is required to contact the scheduler"]
    pub const fn scheduler_address(&self) -> SocketAddr {
        self.scheduler
    }
}

/// Resolve a configured HTTPS address without using its hostname as identity.
///
/// # Errors
/// Returns an error for insecure URLs, embedded credentials or no endpoint.
pub fn endpoint(url: &reqwest::Url) -> Result<SocketAddr> {
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "cluster endpoint must be an HTTPS origin"
    );
    url.socket_addrs(|| None)?
        .into_iter()
        .next()
        .context("cluster endpoint resolved to no address")
}

/// Publish a scheduler's public trust anchor independently of its private CA.
///
/// # Errors
/// Returns an error if the file cannot be written durably or an existing
/// trust anchor identifies a different CA.
pub fn publish_trust_anchor(ca: &X509, path: &Path) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let matches = |bytes: &[u8]| -> Result<()> {
        ensure!(
            X509::from_pem(bytes)?.to_der()? == ca.to_der()?,
            "existing trust anchor identifies a different CA"
        );
        Ok(())
    };
    match fs::read(path) {
        Ok(bytes) => return matches(&bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&ca.to_pem()?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
    }
    file.as_file().sync_all()?;
    match file.persist_noclobber(path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            return matches(&fs::read(path)?);
        }
        Err(error) => return Err(error.error.into()),
    }
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
