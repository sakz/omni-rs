
use crate::common::{unsupported, TargetedOutboundConfig};
use omni_domain::stream::ProxyStream;

#[derive(Debug, Clone)]
pub struct AnyTlsOutboundConfig {
    pub base: TargetedOutboundConfig,
    pub password: String,
}

pub async fn connect_tcp<S>(
    _underlay: S,
    _cfg: &AnyTlsOutboundConfig,
    _target: &omni_domain::stream::ProxyTarget,
) -> std::io::Result<S>
where
    S: ProxyStream,
{
    Err(unsupported("anytls"))
}
