use crate::matching::geo::GeoRegistry;
use crate::observability::online_tracker::OnlineTracker;
use crate::observability::Counters;
use crate::resolver::hickory::{HickoryDns, SystemResolver};
use crate::runtime::assembly::listener_executor;
use crate::runtime::assembly::node_builder::{build_node_plans, NodePlan};
use crate::runtime::assembly::outbound_artifacts::{
    DirectOutbound, HttpConnectConnector, RejectOutbound, RouterBuilder, Socks5Connector,
    SsConnector, TlsClientSpec, TrojanConnector, VlessConnector,
};
use omni_config::wire::{OutboundSpecWire, RuntimeConfigWire};
use std::collections::BTreeMap;
use std::sync::Arc;

pub struct CoreRuntime {
    pub plans: Vec<Arc<NodePlan>>,
    pub router: Arc<crate::runtime::assembly::outbound_artifacts::Router>,
    pub dialer: Arc<omni_transport::dial::Dialer>,
    pub counters: Arc<Counters>,
    pub online: Arc<OnlineTracker>,
    pub metrics_port: Option<u16>,
}

#[derive(Debug)]
pub enum CoreError {
    Config(String),
    Assembly(String),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Config(e) => write!(f, "{}", e),
            CoreError::Assembly(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for CoreError {}

fn tls_obj_of(ob: &OutboundSpecWire) -> Option<&serde_json::Map<String, serde_json::Value>> {
    ob.rest.get("tls").and_then(|v| v.as_object())
}

fn tls_obj_and_insecure(ob: &OutboundSpecWire) -> bool {
    tls_obj_of(ob)
        .and_then(|m| m.get("insecure"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false)
}

fn tls_obj_sni(ob: &OutboundSpecWire) -> Option<String> {
    tls_obj_of(ob).and_then(|m| {
        m.get("server_name")
            .or_else(|| m.get("sni"))
            .and_then(|s| s.as_str())
            .map(String::from)
    })
}

fn json_str_arr(v: Option<&serde_json::Value>) -> Vec<String> {
    match v {
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn json_u16_arr(v: Option<&serde_json::Value>) -> Vec<u16> {
    match v {
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_u64())
            .map(|x| x as u16)
            .collect(),
        Some(serde_json::Value::Number(n)) => {
            n.as_u64().map(|x| vec![x as u16]).unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

fn parse_tls_client_spec(
    v: Option<&serde_json::Value>,
    fallback_sni: &str,
) -> Option<TlsClientSpec> {
    let obj = match v {
        Some(serde_json::Value::Object(m)) => m,
        _ => return None,
    };
    let enabled = obj.get("enabled").and_then(|b| b.as_bool()).unwrap_or(true);
    if !enabled && obj.len() <= 1 {
        return None;
    }
    let skip_verify = obj
        .get("insecure")
        .or_else(|| obj.get("skip_verify"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    let sni_override = obj
        .get("server_name")
        .or_else(|| obj.get("sni"))
        .and_then(|s| s.as_str())
        .map(String::from);
    let alpn = json_str_arr(obj.get("alpn"));
    let _ = fallback_sni;
    Some(TlsClientSpec {
        skip_verify,
        alpn,
        sni_override,
    })
}

fn build_connector(
    ob: &OutboundSpecWire,
) -> Result<Option<Arc<dyn super::assembly::outbound_artifacts::OutboundConnector>>, String> {
    let target = ob.target.clone().unwrap_or_default();
    let server = target.server.clone().unwrap_or_default();
    let port = target.server_port.unwrap_or_default();
    let get = |k: &str| ob.rest.get(k).and_then(|v| v.as_str()).map(String::from);
    let tls = parse_tls_client_spec(ob.rest.get("tls"), &server);
    let transport = crate::runtime::assembly::outbound_artifacts::TransportSpec::parse(
        ob.rest.get("transport"),
    );
    let mux_pool: Option<Arc<omni_mux::pool::MuxPool>> = ob
        .rest
        .get("mux")
        .and_then(|m| m.as_object())
        .and_then(|m| {
            let enabled = m.get("enabled").and_then(|b| b.as_bool()).unwrap_or(true);
            if !enabled {
                return None;
            }
            let kind = m.get("kind").and_then(|k| k.as_str()).unwrap_or("smux");
            let parsed = omni_mux::MuxKind::parse(kind)?;
            Some(Arc::new(omni_mux::pool::MuxPool::new(parsed)))
        });

    match ob.outbound_type.as_str() {
        "direct" => Ok(Some(Arc::new(DirectOutbound))),
        "reject" | "block" => Ok(Some(Arc::new(RejectOutbound))),
        "trojan" => Ok(Some(Arc::new(TrojanConnector {
            tag_name: ob.tag.clone(),
            server,
            port,
            password: get("password").unwrap_or_default(),
            tls,
            transport: transport.clone(),
            mux_pool: mux_pool.clone(),
        }))),
        "shadowsocks" | "ss" => Ok(Some(Arc::new(SsConnector {
            tag_name: ob.tag.clone(),
            config: omni_proto::proto::shadowsocks::outbound::SsOutboundConfig {
                server,
                server_port: port,
                method: get("method").unwrap_or_default(),
                password: get("password").unwrap_or_default(),
            },
        }))),
        "vless" => Ok(Some(Arc::new(VlessConnector {
            tag_name: ob.tag.clone(),
            config: omni_proto::proto::vless::outbound::VlessOutboundConfig {
                server,
                server_port: port,
                uuid: get("uuid").unwrap_or_default(),
            },
            tls,
            transport: transport.clone(),
            mux_pool: mux_pool.clone(),
        }))),
        "vmess" => Ok(Some(Arc::new(
            crate::runtime::assembly::outbound_artifacts::VmessConnector {
                mux_pool: mux_pool.clone(),
                tag_name: ob.tag.clone(),
                config: omni_proto::proto::vmess::outbound::VmessOutboundConfig {
                    base: crate::common_alias::TargetedOutboundConfig {
                        server,
                        server_port: port,
                    },
                    uuid: get("uuid").unwrap_or_default(),
                    security: ob
                        .rest
                        .get("security")
                        .and_then(|v| v.as_str())
                        .unwrap_or("auto")
                        .to_string(),
                },
                tls,
            },
        ))),
        "hysteria2" | "hy2" => Ok(Some(Arc::new(
            crate::runtime::assembly::outbound_artifacts::Hysteria2Connector {
                conn_pool: Arc::new(tokio::sync::Mutex::new(None)),
                tag_name: ob.tag.clone(),
                insecure: tls_obj_and_insecure(ob),
                sni: tls_obj_sni(ob),
                server,
                port,
                password: get("password").unwrap_or_default(),
            },
        ))),
        "naive" => Ok(Some(Arc::new(
            crate::runtime::assembly::outbound_artifacts::NaiveConnector {
                tag_name: ob.tag.clone(),
                server,
                port,
                insecure: tls_obj_and_insecure(ob),
                sni: tls_obj_sni(ob),
            },
        ))),
        "anytls" => Ok(Some(Arc::new(
            crate::runtime::assembly::outbound_artifacts::AnytlsConnector {
                tag_name: ob.tag.clone(),
                tls: parse_tls_client_spec(ob.rest.get("tls"), &server),
                session_pool: Arc::new(tokio::sync::Mutex::new(None)),
                insecure: tls_obj_and_insecure(ob),
                sni: tls_obj_sni(ob),
                server,
                port,
                password: get("password").unwrap_or_default(),
            },
        ))),
        "mieru" => Ok(Some(Arc::new(
            crate::runtime::assembly::outbound_artifacts::MieruConnector {
                tag_name: ob.tag.clone(),
                config: omni_proto::proto::mieru::outbound::MieruOutboundConfig {
                    server,
                    port,
                    username: get("username").unwrap_or_default(),
                    password: get("password").unwrap_or_default(),
                },
            },
        ))),
        "socks" | "socks5" => Ok(Some(Arc::new(Socks5Connector {
            tag_name: ob.tag.clone(),
            config: omni_proto::proto::socks::client::SocksOutboundConfig {
                server,
                server_port: port,
                username: get("username"),
                password: get("password"),
            },
        }))),
        "http" | "httpconnect" | "httpproxy" => Ok(Some(Arc::new(HttpConnectConnector {
            tag_name: ob.tag.clone(),
            server,
            port,
            username: get("username"),
            password: get("password"),
        }))),
        other => Err(format!(
            "config validation failed for outbound {}: protocol '{}' not yet implemented",
            ob.tag, other
        )),
    }
}

fn rule_from_entry(ob: &OutboundSpecWire) -> omni_domain::matching::ast::RouteRuleAst {
    omni_domain::matching::ast::RouteRuleAst {
        domain_suffix: json_str_arr(ob.rest.get("domain_suffix")),
        domain_keyword: json_str_arr(ob.rest.get("domain_keyword")),
        domain_regex: json_str_arr(ob.rest.get("domain_regex")),
        ip_cidr: json_str_arr(ob.rest.get("ip_cidr")),
        geoip: json_str_arr(ob.rest.get("geoip")),
        geosite: json_str_arr(ob.rest.get("geosite")),
        ports: json_u16_arr(ob.rest.get("ports")),
        port_ranges: ob
            .rest
            .get("port_ranges")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|r| {
                        let from = r.get("from")?.as_u64()? as u16;
                        let to = r.get("to")?.as_u64()? as u16;
                        Some((from, to))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        inbound_tags: json_str_arr(ob.rest.get("inbound_tags")),
    }
}

impl CoreRuntime {
    pub async fn initialize(wire: &RuntimeConfigWire) -> Result<Self, CoreError> {
        crate::runtime::assembly::validation::validate(wire).map_err(CoreError::Config)?;

        let resolver_arc: Arc<dyn omni_domain::ports::resolver::Resolver> =
            match wire.dns.as_ref().and_then(|d| d.default_dns.clone()) {
                Some(servers) if !servers.is_empty() => {
                    Arc::new(HickoryDns::new(&servers).map_err(CoreError::Assembly)?)
                }
                _ => Arc::new(SystemResolver),
            };
        let dialer = Arc::new(omni_transport::dial::Dialer::new(resolver_arc));

        let geo = Arc::new(GeoRegistry::new());
        load_geo_files(&geo, wire);

        let mut builder = RouterBuilder::new();
        for ob in &wire.outbounds {
            let connector = build_connector(ob).map_err(CoreError::Config)?;
            if let Some(c) = connector {
                builder.add_connector(c);
            }
            let ast = rule_from_entry(ob);
            let hijack = ob
                .rest
                .get("hijack")
                .and_then(|h| h.as_object())
                .and_then(|m| {
                    m.get("response_b64")
                        .or_else(|| m.get("response_base64"))
                        .and_then(|s| s.as_str())
                        .map(String::from)
                });
            builder
                .add_rule_entry(ast, ob.tag.clone(), hijack)
                .map_err(CoreError::Config)?;
        }

        if !builder.has_connector("direct") {
            builder.add_connector(Arc::new(DirectOutbound));
        }
        if !builder.has_connector("reject") {
            builder.add_connector(Arc::new(RejectOutbound));
        }

        let router: Arc<crate::runtime::assembly::outbound_artifacts::Router> =
            Arc::new(builder.build(geo));
        let plans = build_node_plans(wire)
            .map_err(CoreError::Config)?
            .into_iter()
            .map(Arc::new)
            .collect();

        Ok(Self {
            plans,
            router: router.clone(),
            dialer,
            counters: Arc::new(Counters::default()),
            online: OnlineTracker::new(),
            metrics_port: wire.metrics_port,
        })
    }

    fn shared_for(&self, tag: &str) -> crate::pipeline::PipelineShared {
        crate::pipeline::PipelineShared {
            inbound_tag: tag.to_string(),
            counters: self.counters.clone(),
            online: self.online.clone(),
            router: self.router.clone(),
            dialer: self.dialer.clone(),
        }
    }

    pub async fn serve(self) -> Result<(), CoreError> {
        let mut tasks = Vec::new();

        if !self.plans.is_empty() {
            let by_tag: BTreeMap<String, Arc<NodePlan>> = self
                .plans
                .iter()
                .map(|p| (p.tag.clone(), p.clone()))
                .collect();
            let tags: Vec<String> = by_tag.keys().cloned().collect();
            let mut set = listener_executor::ListenerSet { tasks: Vec::new() };
            for tag in tags {
                let plans_for_tag: Vec<Arc<NodePlan>> = self
                    .plans
                    .iter()
                    .filter(|p| p.tag == tag && !matches!(p.proto, crate::runtime::assembly::node_builder::InboundProto::Hysteria2 { .. }))
                    .cloned()
                    .collect();
                if plans_for_tag.is_empty() {
                    continue;
                }
                let shared = self.shared_for(&tag);
                let ls = listener_executor::spawn_listeners(plans_for_tag, |_| shared.clone())
                    .await
                    .map_err(|e| CoreError::Assembly(e.to_string()))?;
                set.tasks.extend(ls.tasks);
            }
            tasks.extend(set.tasks);

            for plan in &self.plans {
                if let crate::runtime::assembly::node_builder::InboundProto::Hysteria2 {
                    password,
                    tls,
                } = &plan.proto
                {
                    for addr in &plan.listen_addrs {
                        let shared = self.shared_for(&plan.tag);
                        let tls_material = match tls {
                            Some(t) => omni_transport::tls::ServerCertMaterial {
                                cert_pem: t.material_cert.clone(),
                                key_pem: t.material_key.clone(),
                            },
                            None => {
                                let m = omni_transport::tls::generate_self_signed("hysteria.local")
                                    .map_err(CoreError::Assembly)?;
                                omni_transport::tls::ServerCertMaterial {
                                    cert_pem: m.cert_pem,
                                    key_pem: m.key_pem,
                                }
                            }
                        };
                        let cfg = omni_proto::proto::hysteria2::inbound::Hysteria2ServerConfig {
                            listen: *addr,
                            password: password.clone(),
                            tls_material,
                        };
                        let listener =
                            omni_proto::proto::hysteria2::inbound::Hysteria2Listener::bind(&cfg)
                                .map_err(|e| CoreError::Assembly(e.to_string()))?;
                        tracing::info!(
                            target: "internal.listener",
                            "listening inbound={} proto=hysteria2 addr={}",
                            plan.tag, addr
                        );
                        let shared2 = shared.clone();
                        tasks.push(tokio::spawn(async move {
                            listener
                                .run(move |stream, addr| {
                                    let shared = shared2.clone();
                                    async move {
                                        let target = parse_hy_addr(&addr).unwrap_or_else(|| {
                                            omni_domain::stream::ProxyTarget::Domain(
                                                String::new(),
                                                0,
                                            )
                                        });
                                        crate::runtime::assembly::listener_executor::run_tcp_route(
                                            shared,
                                            stream,
                                            target,
                                            Vec::new(),
                                            None,
                                        )
                                        .await
                                    }
                                })
                                .await
                        }));
                    }
                }
            }
        }

        if let Some(port) = self.metrics_port {
            let c = self.counters.clone();
            let o = self.online.clone();
            tasks.push(tokio::spawn(async move {
                crate::observability::metrics::serve_metrics(port, c, o).await
            }));
        }

        tracing::info!(
            target: "internal.relay",
            "supervisor running listeners={} metrics={}",
            self.plans.len(),
            self.metrics_port.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
        );

        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!(target: "internal.relay", "shutdown signal received");
                for t in tasks {
                    t.abort();
                }
                Ok(())
            }
            Err(e) => Err(CoreError::Assembly(format!("signal handler: {}", e))),
        }
    }

    pub fn backend_name(&self) -> &'static str {
        "tokio"
    }
}

fn load_geo_files(geo: &GeoRegistry, wire: &RuntimeConfigWire) {
    let mut loaded_any = false;
    if let Some(extra) = wire.extra.get("geosite_path").and_then(|v| v.as_str()) {
        match geo.load_dat(extra) {
            Ok(_) => loaded_any = true,
            Err(e) => {
                tracing::warn!(target: "internal.geo", "geosite load failed path={} error={}", extra, e)
            }
        }
    }
    if let Some(extra) = wire.extra.get("geoip_path").and_then(|v| v.as_str()) {
        match geo.load_dat(extra) {
            Ok(_) => loaded_any = true,
            Err(e) => {
                tracing::warn!(target: "internal.geo", "geoip load failed path={} error={}", extra, e)
            }
        }
    }
    let _ = loaded_any;
}

fn parse_hy_addr(addr: &str) -> Option<omni_domain::stream::ProxyTarget> {
    let addr = addr.trim_start_matches('[');
    if let Some(rest) = addr.strip_prefix(']') {
        let rest = rest.trim_start_matches(':');
        let port: u16 = rest.parse().ok()?;
        let host = &addr[..addr.len() - rest.len() - 1];
        return Some(omni_domain::stream::ProxyTarget::Tcp(
            format!("[{}]:{}", host, port).parse().ok()?,
        ));
    }
    let (h, p) = addr.rsplit_once(':')?;
    let port: u16 = p.parse().ok()?;
    if let Ok(ip) = h.parse() {
        Some(omni_domain::stream::ProxyTarget::Tcp(
            std::net::SocketAddr::new(ip, port),
        ))
    } else {
        Some(omni_domain::stream::ProxyTarget::Domain(
            h.to_string(),
            port,
        ))
    }
}

pub(crate) fn parse_naive_authority(authority: &str) -> omni_domain::stream::ProxyTarget {
    let a = authority.trim_start_matches('[');
    if let Some(idx) = a.find(']') {
        let host = &a[..idx];
        let rest = &a[idx + 1..];
        let port = rest.trim_start_matches(':').parse().unwrap_or(443);
        if let Ok(ip) = host.parse() {
            return omni_domain::stream::ProxyTarget::Tcp(std::net::SocketAddr::new(ip, port));
        }
        return omni_domain::stream::ProxyTarget::Domain(host.to_string(), port);
    }
    match a.rsplit_once(':') {
        Some((h, p)) => {
            if let Ok(ip) = h.parse() {
                omni_domain::stream::ProxyTarget::Tcp(std::net::SocketAddr::new(
                    ip,
                    p.parse().unwrap_or(443),
                ))
            } else {
                omni_domain::stream::ProxyTarget::Domain(h.to_string(), p.parse().unwrap_or(443))
            }
        }
        None => omni_domain::stream::ProxyTarget::Domain(a.to_string(), 443),
    }
}
