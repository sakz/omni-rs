pub mod h2;
pub mod session;
pub mod split;

use crate::h2 as h2core;
use omni_domain::stream::BoxProxyStream;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Clone, Default)]
pub struct XhttpOutboundSpec {
    pub path: Option<String>,
    pub host: Option<String>,
    pub mode: Option<String>,
}

/// Basic (packet-less) mode: one H2 POST stream per connection.
pub async fn connect_outbound<S>(
    underlay: S,
    spec: &XhttpOutboundSpec,
    target: &omni_domain::stream::ProxyTarget,
) -> io::Result<BoxProxyStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = h2core::client_handshake(underlay).await?;
    let host = match (&spec.host, target) {
        (Some(h), _) => h.clone(),
        (None, omni_domain::stream::ProxyTarget::Domain(h, _)) => h.clone(),
        (None, omni_domain::stream::ProxyTarget::Tcp(a)) => a.ip().to_string(),
    };
    let path = spec.path.clone().unwrap_or_else(|| "/".to_string());
    let stream = conn.open_proxy_stream("POST", &path, &host, "").await?;
    Ok(omni_domain::stream::boxed(stream))
}

pub async fn serve_inbound<S>(
    io: S,
    expect_path: Option<String>,
    handler: crate::h2::StreamHandler,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    h2core::serve_requests(io, expect_path, handler).await
}
