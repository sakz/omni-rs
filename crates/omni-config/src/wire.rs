use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct PolicySpecWire {
    #[serde(default)]
    pub default_throttle_ms: Option<u64>,
    #[serde(default)]
    pub default_reject_reason: Option<String>,
    #[serde(default)]
    pub rate_limit: Option<BTreeMap<String, RateLimitSpecWire>>,
    #[serde(default)]
    pub user_binding: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub rules: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct RateLimitSpecWire {
    #[serde(default)]
    pub upload: Option<u64>,
    #[serde(default)]
    pub download: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct RuntimeConfigWire {
    #[serde(default, alias = "ConfigPath")]
    pub config_path: Option<String>,
    #[serde(default, alias = "config_url", alias = "ConfigUrl")]
    pub config_url: Option<String>,
    #[serde(default)]
    pub outbounds: Vec<OutboundSpecWire>,
    #[serde(default)]
    pub policy: Option<PolicySpecWire>,
    #[serde(default, alias = "backend")]
    pub backend: Option<String>,
    #[serde(default)]
    pub ntp: Option<NtpSyncConfigWire>,
    #[serde(default)]
    pub panel: Option<PanelConfigWire>,
    #[serde(default, alias = "Nodes")]
    pub nodes: Vec<NodeConfigWire>,
    #[serde(default, alias = "Extra")]
    pub extra: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub dns: Option<DnsWire>,
    #[serde(default)]
    pub metrics_port: Option<u16>,
    #[serde(default)]
    pub geo: Option<GeoUpdateConfigWire>,
    #[serde(default)]
    pub user_persist_path: Option<String>,
    #[serde(default, alias = "dns_config")]
    pub dns_config: Option<serde_json::Value>,
    #[serde(default, alias = "rule_list")]
    pub rule_list: Option<RuleListConfigWire>,
    #[serde(default, alias = "access_log")]
    pub access_log: Option<AccessLogConfigWire>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct NodeConfigWire {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default, alias = "ipAddress", alias = "listen")]
    pub listen: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default, alias = "ports")]
    pub ports: Option<Vec<u16>>,
    #[serde(default, alias = "port_ranges")]
    pub port_ranges: Option<Vec<PortRangeWire>>,
    #[serde(default)]
    pub outbound_type: String,
    #[serde(default, alias = "acceptProxyProtocol")]
    pub accept_proxy_protocol: bool,
    #[serde(default, alias = "enable_proxy_protocol")]
    pub enable_proxy_protocol: bool,
    #[serde(default, alias = "acceptUdpProxyProtocol")]
    pub accept_udp_proxy_protocol: bool,
    #[serde(default, alias = "enable_udp_proxy_protocol")]
    pub enable_udp_proxy_protocol: bool,
    #[serde(default, alias = "mux_enabled")]
    pub mux_enabled: bool,
    #[serde(default)]
    pub mux: Option<MuxSpecWire>,
    #[serde(default)]
    pub quic_congestion_control: Option<String>,
    #[serde(default)]
    pub tls: Option<TlsInboundSpecWire>,
    #[serde(default)]
    pub ws: Option<WsSpecWire>,
    #[serde(default)]
    pub h2: Option<H2SpecWire>,
    #[serde(default)]
    pub grpc: Option<GrpcSpecWire>,
    #[serde(default)]
    pub httpup: Option<HttpupSpecWire>,
    #[serde(default)]
    pub xhttp: Option<XhttpSpecWire>,
    #[serde(default)]
    pub quic: Option<QuicSpecWire>,
    #[serde(default, alias = "shadowsocks_invalid_access")]
    pub ss_invalid_access: Option<ShadowsocksInvalidAccessConfigWire>,
    #[serde(default, alias = "ss_ip_user_cache")]
    pub ss_ip_user_cache: Option<SsIpUserCacheConfigWire>,
    #[serde(default, flatten)]
    pub protocol: ProtocolPayloadWire,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProtocolPayloadWire {
    #[serde(flatten)]
    pub fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortRangeWire {
    pub from: u16,
    pub to: u16,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct TlsInboundSpecWire {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_mode: Option<String>,
    #[serde(default)]
    pub cert_domain: Option<String>,
    #[serde(default)]
    pub cert_file: Option<String>,
    #[serde(default)]
    pub key_pem: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
    #[serde(default)]
    pub cert_content: Option<String>,
    #[serde(default)]
    pub key_content: Option<String>,
    #[serde(default)]
    pub skip_verify: bool,
    #[serde(default)]
    pub reject_unknown_sni: bool,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub reality: Option<InboundRealitySpecWire>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct InboundRealitySpecWire {
    #[serde(default)]
    pub handshake_addr: Option<String>,
    #[serde(default)]
    pub handshake_port: Option<u16>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub short_ids: Vec<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub server_names: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct WsSpecWire {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub max_concurrent_streams: Option<u32>,
    #[serde(default)]
    pub early_data: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct H2SpecWire {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct GrpcSpecWire {
    #[serde(default)]
    pub service_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct HttpupSpecWire {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct XhttpSpecWire {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct QuicSpecWire {
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub congestion_control: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct MuxSpecWire {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub concurrency: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct ShadowsocksInvalidAccessConfigWire {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub forbidden_time: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct SsIpUserCacheConfigWire {
    #[serde(default)]
    pub persist_enabled: bool,
    #[serde(default)]
    pub persist_path: Option<String>,
    #[serde(default)]
    pub persist_interval_secs: Option<u64>,
    #[serde(default)]
    pub sync_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct OutboundSpecWire {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub outbound_type: String,
    #[serde(default)]
    pub target: Option<TargetSpecWire>,
    #[serde(flatten)]
    pub rest: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct TargetSpecWire {
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub server_port: Option<u16>,
    #[serde(default)]
    pub ip_hint: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct PanelConfigWire {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub node_id: Option<u64>,
    #[serde(default)]
    pub push_interval_secs: Option<u64>,
    #[serde(default)]
    pub pull_interval_secs: Option<u64>,
    #[serde(default)]
    pub report_interval_secs: Option<u64>,
    #[serde(default)]
    pub ws_enabled: bool,
    #[serde(default)]
    pub codec: Option<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct NtpSyncConfigWire {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub sync_interval_secs: Option<u64>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct GeoUpdateConfigWire {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub interval_secs: Option<u64>,
    #[serde(default)]
    pub geoip_url: Option<String>,
    #[serde(default)]
    pub geosite_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct RuleListConfigWire {
    #[serde(default)]
    pub spans: Option<Vec<String>>,
    #[serde(default)]
    pub regex_patterns: Option<Vec<String>>,
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct AccessLogConfigWire {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub sample_rate: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct DnsWire {
    #[serde(default)]
    pub default_dns: Option<Vec<String>>,
    #[serde(default)]
    pub dns_env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub dns_map: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub trust_negative_responses: bool,
}
