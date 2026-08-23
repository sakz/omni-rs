use crate::common::TargetedOutboundConfig;
use omni_domain::stream::{BoxProxyStream, ProxyStream};
use std::io;

#[derive(Debug, Clone)]
pub struct NaiveOutboundConfig {
    pub base: TargetedOutboundConfig,
}

pub async fn connect_tcp<S>(
    underlay: S,
    _cfg: &NaiveOutboundConfig,
    target: &omni_domain::stream::ProxyTarget,
) -> io::Result<BoxProxyStream>
where
    S: ProxyStream + 'static,
{
    let mut conn = omni_transport::h2::client_handshake(underlay).await?;
    let authority = match target {
        omni_domain::stream::ProxyTarget::Domain(h, p) => format!("{}:{}", h, p),
        omni_domain::stream::ProxyTarget::Tcp(a) => a.to_string(),
    };
    let stream = conn
        .open_proxy_stream("CONNECT", "/", &authority, "")
        .await?;
    Ok(omni_domain::stream::boxed(stream))
}
