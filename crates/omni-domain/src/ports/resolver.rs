#[derive(Debug, Clone)]
pub struct ResolvedAddrs {
    pub addrs: Vec<std::net::SocketAddr>,
}

pub type ResolveFut<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<ResolvedAddrs>> + Send + 'a>>;

pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> ResolveFut<'_>;
}
