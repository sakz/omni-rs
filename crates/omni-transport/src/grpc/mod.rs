use crate::h2 as h2core;
use omni_domain::stream::BoxProxyStream;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

pub const GRPC_METHOD: &str = "POST";
pub const GRPC_CONTENT_TYPE: &str = "application/grpc";

#[derive(Debug, Clone)]
pub struct GrpcOutboundSpec {
    pub service_name: String,
    pub host_header: Option<String>,
}

pub async fn connect_outbound<T>(
    underlay: T,
    spec: &GrpcOutboundSpec,
    target: &omni_domain::stream::ProxyTarget,
) -> io::Result<BoxProxyStream>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = h2core::client_handshake(underlay).await?;
    let host = match (&spec.host_header, target) {
        (Some(h), _) => h.clone(),
        (None, omni_domain::stream::ProxyTarget::Domain(h, _)) => h.clone(),
        (None, omni_domain::stream::ProxyTarget::Tcp(a)) => a.ip().to_string(),
    };
    let path = h2core::grpc_path_for(&spec.service_name);
    let stream = conn
        .open_proxy_stream(GRPC_METHOD, &path, &host, GRPC_CONTENT_TYPE)
        .await?;
    Ok(omni_domain::stream::boxed(stream))
}

pub async fn serve<S>(
    io: S,
    service_name: &str,
    on_stream: crate::h2::StreamHandler,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let prefix = h2core::grpc_path_for(service_name);
    let handler: h2core::StreamHandler = Arc::new(move |s: BoxProxyStream| on_stream(s));
    h2core::serve_requests(io, Some(prefix), handler).await
}
