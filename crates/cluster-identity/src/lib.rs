//! Cluster-local credentials. Enrollment authorization belongs to the scheduler;
//! this crate never derives a role from an untrusted CSR.

use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result, ensure};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, PKeyRef, Private, Public},
    sha::sha256,
    x509::{
        X509, X509Builder, X509Name, X509NameBuilder, X509Req,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};

pub use sccache_peer_identity::{PeerConfig, PeerId, Role};

fn key_id<T: openssl::pkey::HasPublic>(key: &PKeyRef<T>) -> Result<PeerId> {
    Ok(PeerId::from_digest(sha256(&key.public_key_to_der()?)))
}

fn generate_key() -> Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

fn validate_request_key(key: &PKeyRef<Public>) -> Result<()> {
    ensure!(key.id() == Id::EC, "enrollment requires an EC key");
    let ec = key.ec_key()?;
    ensure!(
        ec.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
        "enrollment requires P-256"
    );
    ec.check_key()?;
    Ok(())
}

fn name(common_name: &str) -> Result<X509Name> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
    Ok(name.build())
}

fn serial() -> Result<Asn1Integer> {
    let mut number = BigNum::new()?;
    number.rand(159, MsbOption::ONE, false)?;
    Ok(number.to_asn1_integer()?)
}

fn certificate_builder(
    subject: &X509Name,
    issuer: &openssl::x509::X509NameRef,
    key: &PKeyRef<impl openssl::pkey::HasPublic>,
    days: u32,
) -> Result<X509Builder> {
    ensure!(days > 0, "certificate validity must be positive");
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(serial()?.as_ref())?;
    builder.set_subject_name(subject)?;
    builder.set_issuer_name(issuer)?;
    builder.set_pubkey(key)?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(days)?.as_ref())?;
    Ok(builder)
}

// Publish a complete private file without ever replacing an existing identity.
// Concurrent first startups read the winning identity rather than minting two.
fn load_or_create(path: &Path, create: impl FnOnce() -> Result<Vec<u8>>) -> Result<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => return Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&create()?)?;
    file.as_file().sync_all()?;
    match file.persist_noclobber(path) {
        Ok(_) => {
            #[cfg(unix)]
            fs::File::open(parent)?.sync_all()?;
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    Ok(fs::read(path)?)
}

/// A peer's persistent private key, owned by the peer, never the issuer.
pub struct Identity(PKey<Private>);

impl Identity {
    /// Load or atomically generate a P-256 private key.
    ///
    /// # Errors
    /// Returns an error on storage or cryptographic failure.
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = load_or_create(path, || Ok(generate_key()?.private_key_to_pem_pkcs8()?))?;
        let key = PKey::private_key_from_pem(&bytes)?;
        validate_request_key(PKey::public_key_from_der(&key.public_key_to_der()?)?.as_ref())?;
        Ok(Self(key))
    }

    /// # Errors
    /// Returns an error if public key encoding fails.
    pub fn id(&self) -> Result<PeerId> {
        key_id(&self.0)
    }

    /// Generate a proof-of-possession CSR; role assignment is external.
    ///
    /// # Errors
    /// Returns an error if the CSR cannot be generated.
    pub fn request(&self) -> Result<X509Req> {
        let mut request = X509Req::builder()?;
        request.set_version(0)?;
        request.set_pubkey(&self.0)?;
        request.set_subject_name(name("sccache enrollment")?.as_ref())?;
        request.sign(&self.0, MessageDigest::sha256())?;
        Ok(request.build())
    }

    /// Private key for the local TLS implementation.
    #[must_use = "the returned value is required for TLS identity verification"]
    pub fn private_key(&self) -> &PKeyRef<Private> {
        &self.0
    }
}

/// Scheduler-owned issuer. The CA key and certificate are persisted together.
pub struct ClusterCa {
    key: PKey<Private>,
    certificate: X509,
}

impl ClusterCa {
    /// Load or create a cluster CA. Never regenerate an unreadable existing CA.
    ///
    /// # Errors
    /// Returns an error on storage, parsing or cryptographic failure.
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = load_or_create(path, || {
            let key = generate_key()?;
            let name = name("sccache cluster CA")?;
            let mut builder = certificate_builder(&name, &name, &key, 3650)?;
            builder
                .append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
            builder.append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()?,
            )?;
            builder.sign(&key, MessageDigest::sha256())?;
            let mut bytes = key.private_key_to_pem_pkcs8()?;
            bytes.extend(builder.build().to_pem()?);
            Ok(bytes)
        })?;
        let key = PKey::private_key_from_pem(&bytes)?;
        let certificate = X509::from_pem(&bytes)?;
        ensure!(certificate.public_key()?.public_eq(&key), "CA key mismatch");
        ensure!(certificate.verify(&key)?, "invalid CA signature");
        Ok(Self { key, certificate })
    }

    /// Cluster trust anchor; does not expose the CA signing key.
    #[must_use = "the returned value is required for TLS identity verification"]
    pub const fn certificate(&self) -> &X509 {
        &self.certificate
    }

    /// Issue a leaf for an already-authorized role. Ignore all CSR extensions.
    ///
    /// # Errors
    /// Rejects invalid proof of possession, unsupported keys or certificate failures.
    pub fn issue(&self, request: &X509Req, role: Role, days: u32) -> Result<X509> {
        let key = request.public_key()?;
        validate_request_key(&key)?;
        ensure!(request.verify(&key)?, "invalid CSR signature");
        let identity = key_id(&key)?;
        let tls_name = role.tls_name(identity);
        let subject = name(role.label())?;
        let mut builder =
            certificate_builder(&subject, self.certificate.subject_name(), &key, days)?;
        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
        let mut usage = ExtendedKeyUsage::new();
        usage.client_auth();
        if role != Role::Client {
            usage.server_auth();
        }
        builder.append_extension(usage.critical().build()?)?;
        let san = SubjectAlternativeName::new()
            .dns(&tls_name)
            .build(&builder.x509v3_context(Some(&self.certificate), None))?;
        builder.append_extension(san)?;
        builder.sign(&self.key, MessageDigest::sha256())?;
        let certificate = builder.build();
        ensure!(
            certificate.not_after() <= self.certificate.not_after(),
            "leaf outlives cluster CA"
        );
        Ok(certificate)
    }
}

/// Extract and verify the role-bound identity from a TLS-verified leaf.
///
/// The caller MUST have already verified the chain, validity and proof of
/// possession using the configured cluster CA and appropriate TLS purpose.
///
/// # Errors
/// Returns an error for unexpected or missing SANs or mismatched identity.
pub fn authenticated_peer(certificate: &openssl::x509::X509Ref, role: Role) -> Result<PeerId> {
    let key = certificate.public_key()?;
    validate_request_key(&key)?;
    let identity = key_id(&key)?;
    let expected = role.tls_name(identity);
    let names = certificate
        .subject_alt_names()
        .context("missing peer SAN")?;
    ensure!(
        names.len() == 1
            && names
                .get(0)
                .and_then(openssl::x509::GeneralNameRef::dnsname)
                == Some(expected.as_str()),
        "unexpected peer role or identity"
    );
    Ok(identity)
}

#[cfg(test)]
mod tests;

mod tls;
pub use tls::TlsCredentials;

mod enrollment;
pub use enrollment::{EnrollmentAuthority, EnrollmentRequest, EnrollmentResponse};

mod registry;
pub use registry::Registry;

mod http;
pub use http::{
    AuthenticatedPeer, ClusterBody, ClusterHttpClient, ClusterListener, EnrollmentClient,
    SchedulerEnrollment, blocking_client,
};

mod lifecycle;
pub use lifecycle::{PeerCredentials, endpoint, open_identity, publish_trust_anchor};
