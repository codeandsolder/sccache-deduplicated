//! Native Wreq transport for OpenDAL services.
use crate::errors::Result;
use futures::{StreamExt as _, TryStreamExt as _};
use http::{Request, Response, header};
use http_body_util::BodyExt as _;
use opendal::raw::{parse_content_encoding, parse_content_length};
use opendal::{Buffer, Error, ErrorKind, HttpBody, HttpRedirect, HttpTransport, HttpTransporter};
use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Clone)]
struct WreqTransport {
    client: wreq::Client,
}

fn transport_error(message: &'static str, error: wreq::Error) -> Error {
    let temporary = error.is_connect()
        || error.is_timeout()
        || error.is_request()
        || error.is_body()
        || error.is_decode();
    Error::new(ErrorKind::Unexpected, message)
        .with_operation("wreq::fetch")
        .with_temporary(temporary)
        .set_source(error.without_uri())
}

struct BufferBody(Buffer);

impl http_body::Body for BufferBody {
    type Data = bytes::Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.0.next().map(|chunk| Ok(http_body::Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.0.len() as u64)
    }
}

impl HttpTransport for WreqTransport {
    async fn fetch(&self, request: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        let (mut parts, body) = request.into_parts();
        let original = parts.uri.clone();
        let original_url = url::Url::parse(&original.to_string()).map_err(|error| {
            Error::new(ErrorKind::Unexpected, "invalid storage request URL").set_source(error)
        })?;
        let target = match parts.extensions.get::<HttpRedirect>() {
            Some(redirect) => url::Url::parse(redirect.uri().original_uri()).map_err(|error| {
                Error::new(ErrorKind::Unexpected, "invalid storage redirect URL").set_source(error)
            })?,
            None => original_url.clone(),
        };
        if original_url.origin() != target.origin() {
            // Reusing a redirect must not leak credentials across origins.
            for name in [
                header::AUTHORIZATION,
                header::PROXY_AUTHORIZATION,
                header::COOKIE,
                header::HeaderName::from_static("cookie2"),
                header::WWW_AUTHENTICATE,
            ] {
                parts.headers.remove(name);
            }
        }
        let is_head = parts.method == http::Method::HEAD;
        let mut request = self
            .client
            .request(parts.method, target.as_str())
            .headers(parts.headers)
            .version(parts.version);
        if !body.is_empty() {
            request = request.body(wreq::Body::wrap(BufferBody(body)));
        }
        let response = request
            .send()
            .await
            .map_err(|error| transport_error("send storage request", error))?;
        let length = if is_head || parse_content_encoding(response.headers())?.is_some() {
            None
        } else {
            parse_content_length(response.headers())?
        };
        let final_uri = response.uri().clone();
        let redirect = if final_uri == original {
            None
        } else {
            Some(
                parts
                    .extensions
                    .get::<HttpRedirect>()
                    .filter(|saved| saved.uri().original_uri() == final_uri.to_string())
                    .cloned()
                    .unwrap_or_else(|| HttpRedirect::new(final_uri)),
            )
        };
        let response: Response<wreq::Body> = response.into();
        let (mut parts, body) = response.into_parts();
        parts.extensions.insert(original);
        if let Some(redirect) = redirect {
            parts.extensions.insert(redirect);
        }
        let stream = body
            .into_data_stream()
            .filter_map(|result| {
                std::future::ready(match result {
                    Ok(bytes) if bytes.is_empty() => None,
                    result => Some(result),
                })
            })
            .map_ok(Buffer::from)
            .map_err(|error| {
                Error::new(ErrorKind::Unexpected, "read storage response")
                    .with_operation("wreq::fetch")
                    .with_temporary(true)
                    .set_source(error)
            });
        Ok(Response::from_parts(parts, HttpBody::new(stream, length)))
    }
}

/// Build a pooled HTTP transport with a custom monitoring user agent.
/// # Errors
/// Returns an error if the HTTP client cannot be configured.
pub fn set_user_agent() -> Result<HttpTransporter> {
    let user_agent = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let client = wreq::Client::builder()
        .user_agent(user_agent)
        .redirect(wreq::redirect::Policy::limited(10))
        .build()?;
    Ok(HttpTransporter::new(WreqTransport { client }))
}
