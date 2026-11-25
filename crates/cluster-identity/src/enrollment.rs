//! Bounded enrollment and renewal messages, independent of the HTTP transport.

use super::{ClusterCa, Identity, PeerId, Role, key_id, validate_request_key};
use anyhow::{Context, Result, ensure};
use openssl::{
    sha::sha256,
    x509::{X509, X509Req},
};
use serde::{Deserialize, Serialize};

const MAX_CSR_BYTES: usize = 16 * 1024;

/// A signed CSR without a caller-selected authorization role.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    csr_der: Vec<u8>,
}

impl EnrollmentRequest {
    /// Build a request for the local persistent key.
    ///
    /// # Errors
    /// Returns an error if the CSR cannot be signed or encoded.
    pub fn new(identity: &Identity) -> Result<Self> {
        Ok(Self {
            csr_der: identity.request()?.to_der()?,
        })
    }

    fn parse(&self) -> Result<X509Req> {
        ensure!(
            !self.csr_der.is_empty() && self.csr_der.len() <= MAX_CSR_BYTES,
            "invalid CSR size"
        );
        let request = X509Req::from_der(&self.csr_der)?;
        ensure!(
            request.to_der()? == self.csr_der,
            "noncanonical CSR encoding"
        );
        Ok(request)
    }
}

/// The issuer-signed certificate and its assigned role. Trust is provisioned
/// separately; the response cannot introduce a new trust anchor.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentResponse {
    certificate_der: Vec<u8>,
    role: Role,
}

impl EnrollmentResponse {
    /// Decode the issued certificate; verify it against the local key and
    /// independently configured CA before installing it.
    ///
    /// # Errors
    /// Returns an error if the certificate is invalid DER.
    pub fn into_certificate(self) -> Result<(X509, Role)> {
        Ok((X509::from_der(&self.certificate_der)?, self.role))
    }
}

/// Scheduler-local machine certificate authority. Initial authorization is
/// supplied by the scheduler's existing worker/client authentication policy.
pub struct EnrollmentAuthority {
    ca: ClusterCa,
    validity_days: u32,
}

impl EnrollmentAuthority {
    /// Set a positive, bounded validity period for remote credentials.
    ///
    /// # Errors
    /// Returns an error for an unsupported certificate lifetime.
    pub fn new(ca: ClusterCa, validity_days: u32) -> Result<Self> {
        ensure!(
            (1..=30).contains(&validity_days),
            "remote certificate lifetime must be 1–30 days"
        );
        Ok(Self { ca, validity_days })
    }

    /// The CA certificate to provision in peer trust configuration.
    #[must_use = "peers must authenticate the cluster CA before enrollment"]
    pub const fn certificate(&self) -> &X509 {
        self.ca.certificate()
    }

    /// Return the fingerprint of the cluster CA certificate.
    ///
    /// # Errors
    /// Returns an error if the CA certificate cannot be encoded.
    pub fn fingerprint(&self) -> Result<[u8; 32]> {
        Ok(sha256(&self.certificate().to_der()?))
    }

    /// Authorize initial enrollment using the existing role-aware policy.
    ///
    /// The scheduler role is never issued via remote enrollment.
    ///
    /// # Errors
    /// Rejects invalid credentials, unauthorized roles or malformed CSRs.
    pub fn enroll(
        &self,
        request: &EnrollmentRequest,
        authorize: impl FnOnce() -> Option<Role>,
    ) -> Result<EnrollmentResponse> {
        let role = authorize().context("enrollment authorization denied")?;
        ensure!(
            role != Role::Scheduler,
            "scheduler identity cannot be remotely enrolled"
        );
        self.issue(&request.parse()?, role)
    }

    /// Renew an authenticated principal without allowing key or role changes.
    ///
    /// Only call after mutual TLS and current enrollment authorization have
    /// been checked. An expired or revoked principal must not reach this API.
    ///
    /// # Errors
    /// Rejects a CSR for another key or an unauthorized role.
    pub fn renew(
        &self,
        request: &EnrollmentRequest,
        authenticated_id: PeerId,
        authenticated_role: Role,
    ) -> Result<EnrollmentResponse> {
        ensure!(
            authenticated_role != Role::Scheduler,
            "scheduler identity cannot be remotely renewed"
        );
        let request = request.parse()?;
        let key = request.public_key()?;
        validate_request_key(&key)?;
        ensure!(
            key_id(&key)? == authenticated_id,
            "renewal cannot change peer identity"
        );
        self.issue(&request, authenticated_role)
    }

    fn issue(&self, request: &X509Req, role: Role) -> Result<EnrollmentResponse> {
        let certificate = self.ca.issue(request, role, self.validity_days)?;
        Ok(EnrollmentResponse {
            certificate_der: certificate.to_der()?,
            role,
        })
    }
}
