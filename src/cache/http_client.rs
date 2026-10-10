use opendal::{HttpTransporter, OperationContext};
use opendal_http_transport_reqwest::ReqwestTransport;
use reqwest::ClientBuilder;

use crate::errors::*;

/// Build the OpenDAL context shared by HTTP-backed cache services.
///
/// # Errors
///
/// Returns an error if reqwest cannot construct the cache HTTP client.
pub(super) fn build_http_context() -> Result<OperationContext> {
    let user_agent = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
    let client = ClientBuilder::new()
        .user_agent(user_agent)
        .build()
        .context("failed to build cache HTTP client")?;
    let transport = HttpTransporter::new(ReqwestTransport::new(client));
    Ok(OperationContext::new().with_http_transport(transport))
}
