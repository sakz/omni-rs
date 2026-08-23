use omni_config::wire::{NodeConfigWire, RuntimeConfigWire};
use std::collections::BTreeMap;
use std::net::SocketAddr;

#[derive(Clone)]
pub enum InboundProto {
    Socks(omni_proto::proto::socks::SocksInboundConfig),
    Trojan(String),
    Shadowsocks(omni_proto::proto::shadowsocks::inbound::SsInboundConfig),
    Vless(Vec<[u8; 16]>),
    Vmess(Vec<[u8; 16]>),
    Hysteria2 {
        password: String,
        tls: Option<TlsServerSetup>,
    },
    Anytls {
        password: String,
    },
    Naive,
    Mieru {
        username: String,
        password: String,
    },
}

#[derive(Clone, Default)]
pub struct TlsServerSetup {
    pub material_cert: Vec<u8>,
    pub material_key: Vec<u8>,
    pub alpn: Vec<String>,
}

#[derive(Clone, Default)]
pub enum WrapTransport {
    #[default]
    None,
    Ws(omni_transport::ws::WsInboundSpec),
    HttpUp(omni_transport::httpup::HttpUpSpec),
    Grpc(String),
    H2 {
        path: Option<String>,
        host: Option<String>,
    },
}

pub struct NodePlan {
    pub tag: String,
    pub proto: InboundProto,
    pub listen_addrs: Vec<SocketAddr>,
    pub tls: Option<TlsServerSetup>,
    pub wrap: WrapTransport,
    pub accept_proxy_protocol: bool,
    pub accept_udp_proxy_protocol: bool,
    pub udp_enabled: bool,
    pub inbound_mux: Option<omni_mux::MuxKind>,
}

pub struct AssemblyError(pub String);

impl std::fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn spec_view(
    t: &Option<omni_config::wire::TlsInboundSpecWire>,
) -> omni_transport::tls::TlsSpecView<'_> {
    match t {
        Some(s) => omni_transport::tls::TlsSpecView {
            cert_mode: s.cert_mode.as_deref(),
            cert_domain: s.cert_domain.as_deref(),
            cert_file: s.cert_file.as_deref(),
            key_file: s.key_file.as_deref(),
            cert_content: s.cert_content.as_deref(),
            key_content: s.key_content.as_deref(),
        },
        None => omni_transport::tls::TlsSpecView {
            cert_mode: None,
            cert_domain: None,
            cert_file: None,
            key_file: None,
            cert_content: None,
            key_content: None,
        },
    }
}

pub fn expand_listen_addrs(node: &NodeConfigWire) -> Result<Vec<SocketAddr>, String> {
    let listen_ip: std::net::IpAddr = node
        .listen
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.trim_start_matches('[')
                .trim_end_matches(']')
                .parse()
                .map_err(|e| format!("invalid listen address '{}': {}", s, e))
        })
        .unwrap_or_else(|| Ok(std::net::Ipv4Addr::UNSPECIFIED.into()))?;

    let mut ports: Vec<u16> = Vec::new();
    if let Some(p) = node.port {
        ports.push(p);
    }
    if let Some(ps) = &node.ports {
        ports.extend_from_slice(ps);
    }
    if let Some(ranges) = &node.port_ranges {
        for r in ranges {
            if r.to < r.from {
                return Err(format!("invalid port range {}-{}", r.from, r.to));
            }
            ports.extend(r.from..=r.to);
        }
    }
    if ports.is_empty() {
        return Err("missing listen_port".to_string());
    }
    Ok(ports
        .iter()
        .map(|p| SocketAddr::new(listen_ip, *p))
        .collect())
}

pub fn build_node_plans(wire: &RuntimeConfigWire) -> Result<Vec<NodePlan>, String> {
    let mut plans = Vec::new();
    for (i, node) in wire.nodes.iter().enumerate() {
        let tag = if node.tag.is_empty() {
            format!("in-{}", i)
        } else {
            node.tag.clone()
        };
        let addrs = expand_listen_addrs(node)?;

        let mut hy2_password: Option<String> = None;
        let mut hy2_tls: Option<TlsServerSetup> = None;
        let proto = match node.r#type.as_str() {
            "socks" | "socks5" => InboundProto::Socks(Default::default()),
            "trojan" => {
                let pass = str_field(&node.protocol.fields, "password")
                    .ok_or_else(|| "trojan inbound requires a non-empty 'password'".to_string())?;
                InboundProto::Trojan(omni_proto::proto::trojan::password_hash(&pass))
            }
            "shadowsocks" | "ss" => {
                let method = str_field(&node.protocol.fields, "method").ok_or_else(|| {
                    "shadowsocks inbound requires a non-empty 'method'".to_string()
                })?;
                let password = str_field(&node.protocol.fields, "password").ok_or_else(|| {
                    "shadowsocks inbound requires a non-empty 'password'".to_string()
                })?;
                InboundProto::Shadowsocks(
                    omni_proto::proto::shadowsocks::inbound::SsInboundConfig { method, password },
                )
            }
            "vmess" => {
                let mut parsed = Vec::new();
                if let Some(serde_json::Value::Array(arr)) = node.protocol.fields.get("users") {
                    for u in arr.iter().filter_map(|x| x.as_str()) {
                        let b = crate::crypto_shim::parse_uuid(u)
                            .ok_or_else(|| format!("vmess: invalid UUID '{}'", u))?;
                        parsed.push(b);
                    }
                }
                if let Some(single) = str_field(&node.protocol.fields, "uuid") {
                    let b = crate::crypto_shim::parse_uuid(&single)
                        .ok_or_else(|| format!("vmess: invalid UUID '{}'", single))?;
                    parsed.push(b);
                }
                if parsed.is_empty() {
                    return Err("vmess inbound requires at least one user uuid".to_string());
                }
                InboundProto::Vmess(parsed)
            }
            "hysteria2" | "hy2" => {
                let password = str_field(&node.protocol.fields, "password").ok_or_else(|| {
                    "hysteria2 inbound requires a non-empty 'password'".to_string()
                })?;
                hy2_password = Some(password);
                hy2_tls = if let Some(ts) = &node.tls {
                    if ts.enabled || ts.cert_mode.is_some() {
                        let view = spec_view(&node.tls);
                        let material = omni_transport::tls::resolve_tls_pems(&view, false)?;
                        Some(TlsServerSetup {
                            material_cert: material.cert_pem,
                            material_key: material.key_pem,
                            alpn: vec!["h3".to_string()],
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };
                InboundProto::Socks(Default::default())
            }
            "naive" => InboundProto::Naive,
            "mieru" => InboundProto::Mieru {
                username: str_field(&node.protocol.fields, "username")
                    .ok_or_else(|| "mieru inbound requires a non-empty 'username'".to_string())?,
                password: str_field(&node.protocol.fields, "password")
                    .ok_or_else(|| "mieru inbound requires a non-empty 'password'".to_string())?,
            },
            "anytls" => InboundProto::Anytls {
                password: str_field(&node.protocol.fields, "password")
                    .ok_or_else(|| "anytls inbound requires a non-empty 'password'".to_string())?,
            },
            "vless" => {
                let mut uuids_raw = match node.protocol.fields.get("users") {
                    Some(serde_json::Value::Array(arr)) => arr
                        .iter()
                        .filter_map(|u| u.as_str().map(String::from))
                        .collect::<Vec<_>>(),
                    _ => Vec::new(),
                };
                let mut uuids = vec![str_field(&node.protocol.fields, "uuid")];
                for u in uuids_raw.drain(..) {
                    uuids.push(Some(u));
                }
                let mut parsed = Vec::new();
                for u in uuids.into_iter().flatten() {
                    let b = crate::crypto_shim::parse_uuid(&u).ok_or_else(|| {
                        format!("vmess: invalid UUID in extra[\"users\"] array: {}", u)
                    })?;
                    parsed.push(b);
                }
                if parsed.is_empty() {
                    return Err("vless inbound requires at least one user uuid".to_string());
                }
                InboundProto::Vless(parsed)
            }
            other => {
                return Err(format!("inbound protocol '{}' not yet implemented", other));
            }
        };

        let tls = if let Some(ts) = &node.tls {
            if ts.enabled || ts.cert_mode.is_some() {
                let view = spec_view(&node.tls);
                let email_present = false;
                let material = omni_transport::tls::resolve_tls_pems(&view, email_present)?;
                Some(TlsServerSetup {
                    material_cert: material.cert_pem,
                    material_key: material.key_pem,
                    alpn: ts.alpn.clone().unwrap_or_default(),
                })
            } else {
                None
            }
        } else {
            None
        };

        let wrap = if let Some(ws) = &node.ws {
            WrapTransport::Ws(omni_transport::ws::WsInboundSpec {
                path: ws.path.clone(),
                host: ws.host.clone(),
                max_concurrent_streams: ws.max_concurrent_streams,
            })
        } else if let Some(h) = &node.httpup {
            WrapTransport::HttpUp(omni_transport::httpup::HttpUpSpec {
                path: h.path.clone(),
                host: h.host.clone(),
            })
        } else if let Some(g) = &node.grpc {
            WrapTransport::Grpc(
                g.service_name
                    .clone()
                    .unwrap_or_else(|| "GunService".to_string()),
            )
        } else if let Some(h2spec) = &node.h2 {
            WrapTransport::H2 {
                path: h2spec.path.clone(),
                host: h2spec.host.clone(),
            }
        } else {
            WrapTransport::None
        };

        if let crate::runtime::assembly::node_builder::WrapTransport::Ws(_) = wrap {
            if tls.is_none() {
                tracing::debug!(target: "internal.transport", "ws without tls on inbound {}", tag);
            }
        }

        let proto = if let Some(pw) = hy2_password {
            InboundProto::Hysteria2 {
                password: pw,
                tls: hy2_tls.take(),
            }
        } else {
            proto
        };

        let inbound_mux = if node.mux_enabled {
            let kind = node
                .mux
                .as_ref()
                .and_then(|m| m.kind.as_deref())
                .unwrap_or("smux");
            match omni_mux::MuxKind::parse(kind) {
                Some(k) => Some(k),
                None => {
                    return Err(format!("mux kind '{}' not yet supported", kind));
                }
            }
        } else {
            None
        };

        plans.push(NodePlan {
            tag,
            proto,
            listen_addrs: addrs,
            tls,
            wrap,
            accept_proxy_protocol: node.accept_proxy_protocol || node.enable_proxy_protocol,
            accept_udp_proxy_protocol: node.accept_udp_proxy_protocol
                || node.enable_udp_proxy_protocol,
            udp_enabled: true,
            inbound_mux,
        });
    }
    Ok(plans)
}

fn str_field(m: &BTreeMap<String, serde_json::Value>, k: &str) -> Option<String> {
    m.get(k).and_then(|v| v.as_str()).map(String::from)
}

pub struct CryptoShim;

impl Default for CryptoShim {
    fn default() -> Self {
        Self
    }
}

pub fn io_err_pub(msg: &str) -> std::io::Error {
    std::io::Error::other(msg.to_string())
}
