pub mod codec;

use omni_domain::stream::ProxyTarget;

pub fn unsupported(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("outbound protocol '{}' not yet implemented", what),
    )
}

pub fn unsupported_transport(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("transport '{}' not yet implemented", what),
    )
}

#[derive(Debug, Clone)]
pub struct TargetedOutboundConfig {
    pub server: String,
    pub server_port: u16,
}

impl TargetedOutboundConfig {
    pub fn target(&self) -> ProxyTarget {
        ProxyTarget::Domain(self.server.clone(), self.server_port)
    }
}
