use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver:: Resolver as HickoryResolver;
use omni_domain::ports::resolver::{ResolveFut, ResolvedAddrs};
use std::net::SocketAddr;
use std::sync::Arc;

pub struct HickoryDns {
    inner: HickoryResolver<TokioConnectionProvider>,
}

impl HickoryDns {
    pub fn new(servers: &[String]) -> Result<Self, String> {
        let mut cfg = ResolverConfig::new();
        if servers.is_empty() {
            return Err("dns: no servers".to_string());
        }
        for s in servers {
            let addr = normalize_dns_addr(s)?;
            cfg.add_name_server(NameServerConfig::new(addr, hickory_resolver::proto::xfer::Protocol::Udp));
        }
        Ok(HickoryDns {
            inner: HickoryResolver::builder_with_config(cfg, TokioConnectionProvider::default())
                .build(),
        })
    }
}

fn normalize_dns_addr(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim_start_matches("udp://").trim_start_matches("tcp://");
    if let Some(rest) = s.strip_prefix("https://") {
        let host = rest.split('/').next().unwrap_or(rest);
        return Ok(format!("{}:443", host).parse().map_err(|e| format!("{}", e))?);
    }
    if let Some(rest) = s.strip_prefix("tls://") {
        return Ok(format!("{}:853", rest).parse().map_err(|e| format!("{}", e))?);
    }
    if !s.contains(':') {
        return format!("{}:53", s).parse().map_err(|e| format!("{}", e));
    }
    if s.starts_with('[') {
        return s.parse().map_err(|e| format!("{}", e));
    }
    let parts: Vec<&str> = s.rsplitn(2, ':').collect();
    if parts.len() == 2 && parts[1].parse::<std::net::IpAddr>().is_ok() {
        return s.parse().map_err(|e| format!("{}", e));
    }
    format!("[{}]:{}", parts[1].trim_matches('['), parts[0])
        .parse()
        .map_err(|e| format!("{}", e))
}

#[derive(Clone)]
struct Inner(HickoryResolver<TokioConnectionProvider>);

impl omni_domain::ports::resolver::Resolver for HickoryDns {
    fn resolve(&self, host: &str, port: u16) -> ResolveFut<'_> {
        let inner = Inner(self.inner.clone());
        let host = host.to_string();
        let fut = async move {
            let resp = inner
                .0
                .lookup_ip(host)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("dns: {}", e)))?;
            let addrs: Vec<SocketAddr> = resp
                .iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect();
            Ok(ResolvedAddrs { addrs })
        };
        Box::pin(fut)
    }
}

pub struct SystemResolver;

impl omni_domain::ports::resolver::Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> ResolveFut<'_> {
        let host = host.to_string();
        Box::pin(async move {
            let mut iter = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("dns: {}", e)))?;
            let addrs: Vec<SocketAddr> = iter.by_ref().collect();
            Ok(ResolvedAddrs { addrs })
        })
    }
}

pub type SharedResolver = Arc<dyn omni_domain::ports::resolver::Resolver>;
