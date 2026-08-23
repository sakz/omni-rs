pub use std::io;

use omni_domain::ports::resolver::Resolver;
use omni_domain::stream::ProxyTarget;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

pub struct Dialer {
    pub resolver: Arc<dyn Resolver>,
    pub connect_timeout: Duration,
    pub tcp_nodelay: bool,
}

impl Dialer {
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Dialer {
            resolver,
            connect_timeout: Duration::from_secs(10),
            tcp_nodelay: true,
        }
    }

    pub async fn dial_tcp(&self, target: &ProxyTarget) -> io::Result<TcpStream> {
        let addr = self.resolve(target).await?;
        let fut = TcpStream::connect(addr);
        match tokio::time::timeout(self.connect_timeout, fut).await {
            Ok(Ok(s)) => {
                if self.tcp_nodelay {
                    let _ = s.set_nodelay(true);
                }
                Ok(s)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "dial: timeout")),
        }
    }

    pub async fn bind_udp_for(&self, target: &ProxyTarget) -> io::Result<UdpSocket> {
        let addr = self.resolve(target).await?;
        let local = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        UdpSocket::bind(local).await
    }

    pub async fn resolve(
        &self,
        target: &ProxyTarget,
    ) -> io::Result<std::net::SocketAddr> {
        match target {
            ProxyTarget::Tcp(a) => Ok(*a),
            ProxyTarget::Domain(h, p) => {
                let res = self.resolver.resolve(h, *p).await?;
                match res.addrs.first() {
                    Some(a) => Ok(*a),
                    None => Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "dns: no address records found",
                    )),
                }
            }
        }
    }
}
