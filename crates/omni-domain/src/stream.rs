use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyTarget {
    Tcp(std::net::SocketAddr),
    Domain(String, u16),
}

impl ProxyTarget {
    pub fn host(&self) -> String {
        match self {
            ProxyTarget::Tcp(a) => a.ip().to_string(),
            ProxyTarget::Domain(h, _) => h.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            ProxyTarget::Tcp(a) => a.port(),
            ProxyTarget::Domain(_, p) => *p,
        }
    }

    pub fn with_port(self, port: u16) -> ProxyTarget {
        match self {
            ProxyTarget::Tcp(mut a) => {
                a.set_port(port);
                ProxyTarget::Tcp(a)
            }
            ProxyTarget::Domain(h, _) => ProxyTarget::Domain(h, port),
        }
    }
}

impl std::fmt::Display for ProxyTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyTarget::Tcp(a) => write!(f, "{}", a),
            ProxyTarget::Domain(h, p) => write!(f, "{}:{}", h, p),
        }
    }
}

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

pub type BoxProxyStream = Box<dyn ProxyStream>;

pub fn boxed<S>(s: S) -> BoxProxyStream
where
    S: ProxyStream + 'static,
{
    Box::new(s)
}

#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub source: Option<std::net::SocketAddr>,
    pub target: ProxyTarget,
    pub data: bytes::Bytes,
}

pub type PacketTx = tokio::sync::mpsc::Sender<UdpPacket>;
pub type PacketRx = tokio::sync::mpsc::Receiver<UdpPacket>;

pub struct UdpHandle {
    pub to_remote: PacketTx,
    pub from_remote: tokio::sync::Mutex<PacketRx>,
}

impl UdpHandle {
    pub fn new(to_remote: PacketTx, from_remote: PacketRx) -> Self {
        Self {
            to_remote,
            from_remote: tokio::sync::Mutex::new(from_remote),
        }
    }
}

pub trait OutboundUdp: Send + Sync {
    fn connect_udp(
        &self,
        target: &ProxyTarget,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<UdpHandle>> + Send + '_>>;

    fn supports_udp(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NetCaps {
    pub tcp: bool,
    pub udp: bool,
}
