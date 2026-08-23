use crate::wire::RuntimeConfigWire;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum Backend {
    Iouring,
    Epoll,
    Tokio,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Iouring => "iouring",
            Backend::Epoll => "epoll",
            Backend::Tokio => "tokio",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub backend: Backend,
    pub metrics_port: Option<u16>,
    pub user_persist_path: String,
    pub nodes: Vec<ResolvedNode>,
    pub outbounds: Vec<ResolvedOutbound>,
}

#[derive(Debug, Clone)]
pub struct ResolvedNode {
    pub tag: String,
    pub protocol: String,
    pub listen: std::net::SocketAddr,
    pub network_caps: NetworkCaps,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkCaps {
    pub tcp: bool,
    pub udp: bool,
}

impl NetworkCaps {
    pub fn caps(&self) -> &'static str {
        match (self.tcp, self.udp) {
            (true, true) => "tcp+udp",
            (true, false) => "tcp",
            (false, true) => "udp",
            (false, false) => "none",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedOutbound {
    pub tag: String,
    pub outbound_type: String,
}

pub fn default_user_persist_path() -> String {
    "users.json".to_string()
}

pub fn resolve(wire: &RuntimeConfigWire, backend: Backend) -> RuntimeConfig {
    RuntimeConfig {
        backend,
        metrics_port: wire.metrics_port,
        user_persist_path: wire
            .user_persist_path
            .clone()
            .unwrap_or_else(default_user_persist_path),
        nodes: Vec::new(),
        outbounds: wire
            .outbounds
            .iter()
            .map(|o| ResolvedOutbound {
                tag: o.tag.clone(),
                outbound_type: o.outbound_type.clone(),
            })
            .collect(),
    }
}

pub type ExtraMap = BTreeMap<String, serde_json::Value>;
