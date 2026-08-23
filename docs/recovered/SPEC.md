# omni-rs 恢复规格说明（从二进制逆向重建）

> 来源：`omni-rs-bin`（26MB，Linux x86_64 ELF PIE，**stripped**，动态链接 glibc）
> 自述：`omni-rs v2 framework runtime` / `omni-cli 0.1.5`
> 构建环境：nightly rustc (`b3869b94…`)，mimalloc，构建机 `/Users/errorsio`（Apple Silicon 交叉编译 → linux x86_64）
>
> 恢复手段：panic 路径字符串（122 个源文件路径）、serde 结构体/字段名静态表、tracing 事件元数据
> （模块路径+行号+span 字段）、错误消息目录、env 变量名、Docker 中实际运行行为探测。
> **注意：二进制无符号表，无法反编译出源码级逻辑；本文档为行为与结构规格，重实现以此为蓝本。**

## 1. 定位

sing-box / xray 同类的多协议代理核心，面向"面板授权节点"场景：
内置 xboard 面板对接（`omni-panel`）、商业 license 门控（`omni-license`）、
io_uring/epoll 双高性能数据面。所有节点（入站监听）必须通过 license 验证，
否则报错退出：

```
config validation failed for inbound <nodes>: all nodes disabled due to license verification failures
```

## 2. CLI（clap 4.6）

```
omni-rs-bin [OPTIONS] [COMMAND]

Commands:
  server   Start the server (v1-compatible alias for the default behaviour)
  version  Print CLI version        → "omni-cli 0.1.5"
  help     Print this message

Options:
  -c, --config <CONFIG>  Config file path (.json or .toml)。无子命令时使用
      --check-config     校验配置与能力矩阵后退出 → "config check passed"
  -h, --help             Print help
```

## 3. Workspace 结构（apps + crates，共 122 个源文件）

完整清单见 `modules.txt`。crate 职责：

| crate | 职责 | 关键模块 |
|---|---|---|
| `apps/omni-cli` | 入口 | main.rs, bootstrap/runtime.rs, cmd/{run, check_config}.rs |
| `omni-core` | 运行时核心（~最大 crate） | runtime/core.rs (3000+ 行), runtime/assembly/* (装配层 20 个文件), dataplane/* , pipeline/*, security/{acme,cert}, resolver/hickory, matching/geo, store/persist_store, ntp, observability/online_tracker |
| `omni-domain` | 域名匹配引擎 | matching/{ast, compiler, ir}, ports/resolver, socks5, stream |
| `omni-proto` | 协议实现 | proto/{trojan, vless(vision,xudp), vmess, shadowsocks, socks, hysteria2, anytls, mieru, naive} 各含 inbound/outbound; mux_cool/{frame,session} (Xray Mux.Cool); crypto.rs; common/codec/udp_over_stream |
| `omni-transport` | 传输层 | tls/mod, ktls (kernel TLS), reality, quic/{mod, salamander}, quiche_naive, ws, h2, grpc, xhttp/{h2,session,split}, httpup, proxy_protocol, routing, dial, accept |
| `omni-mux` | 流多路复用 | smux, yamux, h2mux, sing( sing-mux), pool, detect |
| `omni-panel` | 面板对接 | client/{http,retry}, codec/{json,msgpack}, transport/{http,xboard}, ws.rs, model/report |
| `omni-license` | license 客户端 | client/{fetch,cache}, config.rs |
| `omni-limiter` | 限流策略 | policy/node, split, geo |
| `omni-log` | 日志 | subscriber/fmt_layer（自定义 tracing 层 + panic.handler） |

## 4. 启动序列（日志还原）

```
INFO omni.start: initializing version=0.1.5
INFO omni.start: mimalloc allocator enabled
INFO omni.start: io_uring backend available (Linux kernel 5.1+, NO_IOWAIT requires 6.15+)
INFO runtime.backend: iouring            ← backend 选择（env 可覆盖）
…license bootstrap (assembly/license_bootstrap.rs)
INFO reconcile.init: initial reconcile completed   ← 或 failed
FATAL omni.start: core initialization failed       ← 失败出口 "runtime assembly failed: …"
```

其他启动相关：supervisor 初始化失败路径（`omni.start: supervisor initialization failed`）、
快照热重载（`snapshot_reload.rs`）、panel 拉取间隔覆盖
（pull_interval_override/push_interval_override）。

## 5. 配置 schema

格式支持 `.json` 与 `.toml`；未知顶层字段忽略；空 `{}` 合法（全部默认值）。

### 5.1 RuntimeConfig 顶层字段（serde 声明序）

```
config_path, config_url,
outbounds (RouteOutbounds),
policy,
backend,
ntp (NtpSyncConfig),
panel (PanelConfig, 9 字段),
nodes (Vec<NodeConfig>),
extra (ExtraConfigSource),
dns,
metrics_port,
geo (GeoUpdateConfig),
user_persist_path,
dns_config,
rule_list (RuleListConfig),
access_log (AccessLogConfig)
```

### 5.2 NodeConfig（节点 = 一个入站监听）

已确认字段片段：`type, tag, listen(ipAddress?), port/listen_port, ports/port_ranges,
server?, outbound_type, accept_proxy_protocol/acceptUdpProxyProtocol(enable_udp_proxy_protocol),
mux_enabled/mux, transport specs (ws/h2/grpc/httpup/xhttp/quic),
tls{cert_mode, cert_domain, cert_file, key_pem, cert_content, key_content, skip_verify,
reject_unknown_sni, reality(InboundRealitySpec)}, quic_congestion_control(bbr/bbr2?/cubic/newreno),
shadowsocks_invalid_access/ss_invalid_access, ss_ip_user_cache(persist_enabled/persist_path/
persist_interval_secs/sync_interval_secs), traffic_kb?`

### 5.3 子结构体目录（serde 元素数已确认的部分）

```
PanelConfig(9)  AcmeConfig(6)  RateLimitSpec(2)  UserBindingSpec(1)
StoredAccount(2)  NtpSyncConfig  SsIpUserCacheConfig  ShadowsocksInvalidAccessConfig
AccessLogConfig  GeoUpdateConfig  RuleListConfig(regex_patterns/spans/source_url/last_modified)
ExtraConfigSource  RuntimeRoute  TargetSpec  RouteHijackSpec
HijackRuleConfig(domain_suffix/domain_keyword/domain_regex/ports/port_ranges/inbound_tags/response_b64/response_base64)
EntryRouteSpec  QuicSpec  WsSpec(service_name, max_concurrent_streams)  H2Spec  GrpcSpec
HttpupSpec  XhttpSpec  PolicySpec(default_throttle_ms/default_reject_reason/rate_limit/user_binding/reject/rules?)
InboundRealitySpec(short_ids hex 校验, fingerprint?)  OutboundMuxSpecRaw::Full(StringOrInt untagged)
```

### 5.4 协议 spec（untagged/tagged wire 类型）

入站：`TrojanInboundSpec, ShadowsocksInboundSpec(+Compat: InvalidAccess/SsIpUserCache),
MieruInboundSpec(+MieruUserSpec), TlsInboundSpec, AnyTlsInboundSpec, VlessInboundSpec`
出站：`HttpProxyOutboundSpec, NaiveOutboundSpec, MieruOutboundSpec(udp_underlay),
TrojanOutboundSpec, VlessOutboundSpec(vless_flow), SocksOutboundSpec, VmessOutboundSpec,
ShadowsocksOutboundSpec, AnyTlsOutboundSpec, Hysteria2OutboundSpec(+Hysteria2ObfsSpec)`
mux 变体枚举含：`Yamux, H2mux, smux, sing-mux, mux_cool, h3`

### 5.5 校验规则（错误消息原文目录）

```
protocol cannot be empty
mux is disabled but a mux kind is configured
external mux requires tcp-capable inbound network
outbound tag cannot be empty / duplicate tag (tags must be unique across inbounds and outbounds)
both tcp and udp are disabled / missing caps() declaration
trojan outbound requires a non-empty 'password'
vless outbound requires a non-empty 'uuid' / vmess outbound requires a non-empty 'uuid'
shadowsocks outbound requires a non-empty 'method' / 'password'
anytls outbound requires a non-empty 'password'
mieru outbound requires non-empty 'username' and 'password'
cert_mode=file requires cert_file and key_file paths
cert_mode=content requires cert_content / key_content
cert_mode=self requires cert_domain ; acme.email must not be empty ; cert_domain must not be empty
unsupported cert_mode: …（合法值 file/content/self/acme?）
TLS-enabled inbound transport requires TLS PEMs: use tls.cert_mode or supply tls.cert_pem + tls.key_pem
reality.short_ids entry '<x>' is not valid hex
tls inbound rejected: unknown SNI '<sni>' (reject_unknown_sni=true)
user_persist_path is a relative path; resolved against process working directory
route rule[i].domain_keyword[j] is empty or whitespace-only
route action=hijack missing hijack spec / response_base64 decode failed → fallback empty response
runtime.backend: ignoring invalid omni_backend override
node_builder: both disable_ktls and force_ktls are true; force_ktls is ignored
```

### 5.6 env 变量

数据面调优：
```
omni_epoll_workers, omni_epoll_max_conn_per_worker, omni_epoll_queue_cap
omni_iouring_workers, omni_iouring_max_conn, omni_iouring_ring_size, omni_iouring_queue(CAP)
omni_iouring_defer_taskrun, single_issuer, coop_taskrun, taskrun_flag, no_iowait
omni_iouring_sq_poll(_idle_ms), send_zc, idle_us, idle_max_us, wait_timeout(_idle)_us
OMNI_IOURING_{TCP,TLS,TLS_CONNECT,UDP}_QUEUE_CAP, omni_tcp_buffer_kb, omni_udp_buffer_kb
omni_backend (= iouring|epoll|tokio?)
```

## 6. 数据面

- 三后端：`iouring`（默认）/ `epoll` / tokio 回退；每 worker 连接池、eventfd 唤醒、
  multishot recv、send_zc、registered buffer ring、NO_IOWAIT/ext_arg 探测降级链
- UDP NAT：xudp + xudp_fullcone 会话表（sid/gid/grace/idle 超时/僵尸回收）
- relay 层（3000 行级）：双向拷贝、idle timeout、aborted_connections 统计、
  ktls（内核 TLS 卸载）开关 disable_ktls/force_ktls
- buffer pool：tcp/udp 缓冲区大小可调（kb）

## 7. 协议矩阵

| 层 | 支持项 |
|---|---|
| 入站 | trojan, shadowsocks(含 2022/blake3-aes-256-gcm, invalid-access 记录), vless(+vision/flow, xudp), vmess(extra["users"]), socks5(+UDP), mieru, anytls(padding/pool), naive(h3), hysteria2(obfs/salamander?) |
| 出站 | 上列对应 outbound + httpproxy |
| 传输 | tcp, tls, reality, ws, h2, grpc, xhttp(h2/h3, session/split), httpup, quic(quiche), proxy_protocol v1/v2, ktls |
| mux | smux(0.2), yamux(0.13), h2mux, sing-mux, Mux.Cool(Xray), h3 |
| 拥塞控制 | bbr, bbr2(gcongestion), cubic, newreno |

## 8. 面板对接（omni-panel → xboard）

- HTTP 拉取 + WebSocket 推送双通道；json + msgpack 双编解码；retry 客户端
- 节点物化自 panel 下发（node_panel_bootstrap: node_count/panel_node_id/panel_node_type）
- 上报模型 model/report（在线数 online_tracker、流量 traffic_kb、forbidden_time）
- ws 事件同步：`xboard.ws: connected, synced [<n>] in <ms>`、`sync.devices received (...)`、unknown event 容错

## 9. License 门控（omni-license）

client/{fetch, cache} + config；验证失败 → 全部 nodes 禁用（见 §1）。
重实现决策点：去掉门控 / 保留接口接自有签发服务。

## 10. DNS / ACME / 证书

- 解析器：hickory-resolver 0.25.2；default_dns/dns_env/dns_config/dns_map 多来源合并；
  系统 resolver 兜底；trust_negative_responses
- ACME：instant-acme 0.8.5（OrderState(7)/AuthorizationState(4)/Challenge），
  DNS-01 经 **manydns 1.3.0**（内含 Cloudflare zones/dns_records API 结构、
  DNSPod Domain(19字段)/grade/beian/is_vip 等中文服务商 API 结构、阿里云 StatusResponse 等）
- 自签证书：rcgen 0.13；证书模式 file/content/self；到期自动续期（cert.renew 日志）

## 11. 可观测性

metrics_port（HTTP 指标）、access log（AccessLogConfig）、tracing-subscriber 自定义
fmt_layer + tracing-appender、tokio-console（console-subscriber 0.4）、panic handler 钩子。

## 12. 依赖清单（可精确重建 Cargo.toml）

crates.io 133 项见 `deps_registry.txt`。关键：
tokio 1.50 / hyper 1.8.1 / reqwest 0.12.28+0.13.2 / rustls(git master)+aws-lc-rs 1.16 /
hickory 0.25.2 / clap 4.6 / quiche(git @69468d8) / quinn(git @69b7a97) / instant-acme 0.8.5 /
manydns 1.3.0 / shadowsocks-crypto 0.6.2 / smux 0.2 / yamux 0.13.10 / rcgen 0.13.2 /
moka 0.12.14 / rkyv 0.7.46 / sysinfo 0.33 / ml-kem 0.3-pre.5 / rayon 1.11 /
toml_edit 0.22 / serde 1.0.228 / serde_json 1.0.149 / mimalloc（allocator）

## 13. 重实现可行性评估

| 部分 | 可行性 | 说明 |
|---|---|---|
| CLI/配置 schema/装配流程 | ★★★★★ | 已完整恢复，可直接编码 |
| 数据面（iouring/epoll/xudp） | ★★★★☆ | 结构+参数已知，需按日志行为对齐细节 |
| 协议实现 | ★★★★★ | 公开协议，有 xray/sing-box 参考实现，无需反编译 |
| 面板对接 | ★★★☆☆ | 编解码格式已知（json/msgpack），API 端点需抓包或文档 |
| license 机制 | ⚠️ 决策点 | 商业组件；建议去除或替换为自有方案 |
| 逐行还原原代码 | ❌ 不可行 | stripped + 优化后 Rust async，业界无工具可做到 |

## 14. 重实现状态（本 workspace）

决策：去除 license 门控；全量骨架；严格复刻原架构（Linux 上 iouring/epoll，其他平台 tokio 回退）。

### 已完成（行为与原版二进制逐字节对照通过）

- CLI 全部表面：`--help` / `server --help` / `version` / 未知子命令报错 / 退出码
- 启动日志序列与格式（RFC3339+00:00 自定义 fmt layer、FATAL 渲染、error= 无引号）
- 配置加载（JSON/TOML）+ 解析/读取错误信封原文
- RuntimeConfig wire 模型（恢复的字段名表）
- 校验器 + 错误信封 `config validation failed for outbound <tag>: …`（含
  target.server/server_port 前置校验、tag 唯一性等，见 scripts/behavior_cmp.sh 对照矩阵）
- backend 选择顺序（配置读取成功后才输出 runtime.backend 行）+ omni_backend env 覆盖
- 空 nodes 集启动→静默退出(0)；失败路径 ERROR+FATAL 双行 + `runtime assembly failed:`

### 第二阶段：数据链路实现（已通过端到端验证）

**已实现并可用的完整代理链路：**

| 能力 | 状态 |
|---|---|
| 入站 socks5（TCP + UDP ASSOCIATE 全中继、用户/密码认证） | ✅ e2e 通过 |
| 入站 trojan（TLS self-signed / file / content 证书） | ✅ e2e 通过 |
| 入站 shadowsocks（aes-128/256-gcm、chacha20-ietf-poly1305，自研 EVP_BytesToKey+HKDF-SHA1+SIP004 分帧） | ✅ e2e 通过 |
| 入站 vless（uuid 认证、TCP/原生 UDP 帧；plain + TLS） | ✅ e2e 通过 |
| 入站 vmess（AEAD header、AES-128-GCM/chacha20-poly1305/none、chunk masking+global padding，SHAKE128 自研） | ✅ e2e 通过 |
| 入站 hysteria2（QUIC/quinn + HTTP/3 认证伪装 POST /auth→233，varint TCPRequest/Response 原始流） | ✅ e2e 通过 |
| 出站 hysteria2（同上）+ UDP relay + **QUIC 连接池**（evict-once-retry；实测 1 客户端 1 会话） | ✅ e2e 通过（TCP + UDP×3 + 复用验证） |
| 协议 anytls + **TLS 会话池**（同模式；7 连接复用 1 TLS 会话实测） | ✅ e2e 通过 |
| 传输层 gRPC（h2 crate；GunService/Tun 路径约定、流式双向 DATA、入站多路复用单连接多流、出站 transport 叠加） | ✅ e2e 通过 |
| 出站统一 transport 叠加层：trojan/vless 出站可配 `transport:{type: ws|grpc|h2}` 自动叠 TLS | ✅ e2e 通过(gRPC) |
| 入站 h2 传输（WrapTransport::H2，path 前缀匹配 + 协议管线复用） | ✅ 已实现 |
| mux：smux 出站叠加 + **会话池复用**（omni-mux::pool::MuxPool，13 连接复用 1 会话实测）+ 入站解复用循环 | ✅ e2e 通过（顺序×8/并发×5/复用率验证） |
| 协议 anytls（TLS 上 7 字节帧头会话多路复用：SYN/PSH/FIN/WASTE/SETTINGS；sha256(password) 认证；SOCKS 地址首包寻址；流内连接复用） | ✅ e2e 通过（单流×2/20KB/并发×4） |
| UDP 中继：trojan UDP ASSOCIATE 出站+入站泵、vless 原生 UDP 帧出站+入站泵；socks5 UDP 经任意 UDP-capable 出站转发 | ✅ e2e 通过（trojan/TLS、vless/TLS 两条链路与 echo 往返） |
| 出站 direct（含 UDP NAT 会话）/ reject | ✅ |
| 出站 trojan / shadowsocks / vless / vmess / socks5 / http-connect（均可叠 TLS 客户端：skip_verify、sni 覆盖、alpn） | ✅ e2e 通过 |
| 传输层 TLS（rustls+ring）、WebSocket（服务端手写升级握手+RFC6455 帧适配）、httpupgrade、proxy-protocol v1/v2、嗅探（TLS SNI / HTTP Host） | ✅ |
| 路由：domain_suffix/keyword/regex、ip_cidr、geoip/geosite（v2ray .dat 手解 protobuf + 文本列表）、ports/port_ranges、inbound_tags；hijack(response_base64)；无匹配回退首个无条件出站→direct | ✅ e2e 通过 |
| 观测：Prometheus metrics 端点（connections/up/down/online）、access log、在线人数 tracker | ✅ |
| DNS：hickory-resolver（default_dns 多服务器）/ 系统 resolver 兜底 | ✅ |

**单元测试向量**：MD5/SHA1/HMAC-SHA1(RFC2202)/FNV1a、SS-AEAD 三算法 roundtrip、
SOCKS 地址编解码、proxy-protocol v2 编解码互逆、SNI 解析（构造最小 ClientHello）。

**VMess 实现说明（第三阶段）：**
- 依据 v2ray-core 上游源码逐字段核对：KDF 链(HMAC-SHA256 "VMess AEAD KDF")、AuthID
  (AES-ECB(ts8+rand4))、Seal/OpenVMessAEADHeader 线序 [authID16][encLen18][nonce8][payload]、
  响应头 KDF 派生(respKey/respIV = sha256(reqKey/reqIV)[:16])、chunk 帧格式
  [masked_size][ct||tag][padding]、ShakeSizeParser 流式消费顺序(padding 先于 size)
- 已通过自建双端 e2e：GCM 小包 / 40KB 多分块完整性 / chacha20 变体
- 与 xray 官方客户端的线上互通待实测验证（常量与结构均按上游对齐）
- 暂不支持：UDP 命令、legacy(alterId>0) 头、AuthenticatedLength 选项（协商期显式拒绝）

**Hysteria2 实现说明（第四阶段）：**
- 帧格式依据 apernet/hysteria PROTOCOL.md 与 core/internal/protocol/{proxy,http}.go 核对：
  H3 认证请求(POST /auth, host=hysteria, Hysteria-Auth/CC-RX 头) → 233 HyOK；
  TCP 流帧 [varint 0x401][varint addrLen][addr][varint padLen][pad] → [status][varint msgLen][msg][padLen][pad]
- 传输：quinn 0.11 (rustls ring provider, ALPN h3)；服务端自签/file/content 证书均可
- 架构偏差说明：官方实现经 http3.StreamDispatcher 劫持原始 QUIC 流；本实现因 Rust h3
  crate 无等价钩子，采用「h3 连接仅承载 /auth，认证完成后服务端切换至原始 quinn::accept_bi」
  方案（客户端认证后延迟 100ms 开流规避接管竞态）。官方客户端的互通需实测后调整。
- 暂不支持：Salamander/Gecko 混淆、UDP relay（datagram 会话管理）、带宽协商(CC-RX 恒 0)

**gRPC/H2 实现说明（第五阶段）：**
- 共享机制在 omni-transport::h2：`H2Stream` 适配器（严格按序的 DATA 帧↔AsyncRead/Write，
  含 flow control release）、client_handshake+open_proxy_stream、serve_requests(路径前缀校验)
- gRPC 特化：路径 /{service}/Tun、content-type application/grpc、te trailers；
  入站单 TCP 连接可承载多条代理流（每请求一流），出站经 TransportSpec 叠加
- 关键修复：poll_read 残留缓冲与新帧交错导致的字节乱序（曾致 trojan 头损坏）
- e2e：socks→trojan/gRPC(TLS 自签)→direct 小包 + 30KB 多帧完整性

**会话池说明（第九阶段）：**
- omni-mux::pool::MuxPool：按 max_streams(默认64) 复用健康会话；open_stream 失败
  自动剔除死会话并新建；PooledStream Drop 时原子递减活跃计数
- dial_with_transport 池路径惰性构造底层连接闭包——仅当无可用会话时才真正拨号
- e2e 实测：13 个 socks 连接（8 顺序 + 5 并发）全部数据正确且服务端仅建立 1 个
  mux session（此前每连接一个）
- 已知语义：PoolLease 在 PooledStream Drop 时释放；FIN 尚未主动发送给对端
  （依赖 smux 流关闭帧），极端情况下对端会话可能晚于本地感知流关闭

**mux 实现说明（第六阶段）：**
- omni-mux::MuxSession 统一抽象：client/server/open_stream/accept_stream
- smux 0.2 crate 直包（Session::client/server + Stream 即 ProxyStream）
- yamux 0.13（libp2p）驱动已写但降级：其 Connection 需持续 poll 驱动且 SYN 帧
  flush 时机依赖内部状态机，本实现的 poll_fn 驱动存在帧滞留问题 → 显式报错
  （"yamux multiplexing not yet supported"），结构保留待后续修复
- 出站：`dial_with_transport` 尾部按 `mux:{enabled,kind}` 包一层会话并 open_stream
  （当前每拨号独立会话；连接池 pooling 留待后续）
- 入站：`inbound_mux` 的 plan 在 TLS/WS 等传输就绪后进入 accept_stream 循环，
  每子流 spawn 完整协议管线（trojan/ss/vless/vmess 均可承载）

**anytls 实现说明（第七阶段）：**
- 规格 1:1 对照 anytls-go docs/protocol.md + proxy/session/{frame,session}.go：
  认证 [sha256(pw)32][padLen u16][pad] → cmdSettings(v=2,padding-md5) 必须先于 SYN；
  帧 [cmd u8][sid u32 BE][len u16 BE][data]，命令集 WASTE/SYN/PSH/FIN/SETTINGS/ALERT
- 会话架构：writer 任务独占写半（帧队列 mpsc），read_loop 解析分发到注册表，
  流 = {sid, writer_tx, rx}；服务端 SYN 触发「SOCKS 地址前缀解析」任务后进入路由管线
- 暂未实现：padding scheme 生成（声明空方案并忽略服务器 UPDATE 下发——协议合法）、
  心跳 v2 命令、UDP-over-TCP(sp.v2.udp-over-tcp.arpa)、会话池

**UDP 中继说明（第八阶段）：**
- TrojanConnector/VlessConnector 实现 connect_udp：出站建立 cmd=0x03/UDP 控制通道，
  split 为 send/recv 半，桥接为 UdpHandle（mpsc 双向）
- 入站 trojan UdpAssociate / vless Udp：解码器泵 ↔ UdpHandle 对接，
  回程帧以目标地址为源地址编码（符合 SOCKS/trojan/vless 回包语义）
- socks5 UDP ASSOCIATE 现可经任意 supports_udp() 出站转发（当前 direct/trojan/vless）
- e2e：socks→trojan/TLS→direct 与 socks→vless/TLS→direct 的 UDP echo 往返均通过

**Hysteria2 UDP 说明（第十阶段）：**
- 传输：quinn datagram（两端 TransportConfig 启用 65535B 收发缓冲）
- 帧：UDPMessage [sid u32][pktId u16][frag u8][cnt u8][varint addrLen][addr "host:port"][data]
  按 apernet/hysteria core/internal/protocol/proxy.go 对齐；未实现分片（cnt 恒 1）
- 服务端：认证后 spawn run_udp_dispatcher——按 sid 维护 NAT socket 表，
  首包建 UDP socket 并启动回程泵（recv_from → send_datagram 回注）
- 客户端：connect_udp 返回按 sid 过滤的 UdpHandle；多会话经静态 sid 计数器区分
- e2e：socks5 UDP ASSOCIATE → hy2 datagram → 服务端 NAT → UDP echo ×3 连续通过

**连接池说明（第十一阶段）：**
- Hysteria2Connector.conn_pool：缓存已认证 QUIC 连接，TCP/UDP 拨号共用；
  open 失败 → evict → 重连重试一次（应对服务端空闲断开）
- AnytlsConnector.session_pool：同模式复用 anytls ClientSession（单会话多流即协议设计）
- e2e 验证：hy2 3 包 UDP 全走同一 QUIC 会话；anytls 7 连接仅 1 次 TLS 握手

**naive 实现说明（第十二阶段）：**
- 协议本质：H2 CONNECT 隧道（naive-go 兼容 Caddy forwardproxy 语义）
- 出站：h2 client handshake → CONNECT :authority=target → 200 后双向流
- 入站：h2 serve_connect → 校验 method==CONNECT → 提取 authority 为目标 → 管线
- 复用 omni-transport::h2 全部机制（H2Stream/serve_requests 变体）
- e2e: socks→naive(TLS 自签)→direct 通过

**reality/mieru 最终评估（诚实结论）：**
- reality：服务端需 fork TLS 栈拦截 ClientHello 并改写 ServerHello 证书链
  （xtls/reality 是 Go crypto/tls 的 fork）。rustls 不暴露握手内部状态，
  无法实现 MirrorConn 式透明改写。客户端还需 uTLS 指纹伪装（rustls 无此能力）。
  结论：在 Rust/TLS 栈约束下无法忠实复刻，保持显式不支持并注明原因。
- mieru：私有加密协议（非公开标准），规格来自 enfein/mieru 实现，涉及
  自定义混淆+分片+握手，工程量大且无互通验证渠道。保持显式不支持。
- xhttp：基础模式（单 H2 POST 流）已实现；split 模式（GET 下载 + POST 上传
  双通道 + seq 序号）需要跨通道协调，标记后续工作。

**mieru 实现说明（第十三阶段）：**
- 协议规格 1:1 对照 enfein/mieru docs/protocol.md：
  密钥派生 SHA256(password‖0x00‖username) → PBKDF2-SHA256(salt=epoch_minute,64轮,32B)
  XChaCha20-Poly1305 加密；TCP 段 [nonce(首段)][enc_metadata32+tag16][enc_payload+tag][padding]
  元数据 32B: [proto_type1][unused1][ts4][sid4][seq4][status1][payloadLen2][suffixLen1][unused14]
- crypto 模块含单元测试（密钥派生确定性/seal-open roundtrip/nonce 递增）
- 出站 connect_tcp 实现 openSessionRequest→openSessionResponse 会话建立
- 数据中继：pump 模式（读泵解密入站段→ChannelDuplex，写泵加密出站数据→underlay），
  ChannelDuplex 提供 AsyncRead/Write 适配
- yamux e2e: socks→trojan+yamux(TLS)→direct 并发×5 通过

**yamux 修复详情（第十三阶段）：**
根因：libp2p yamux 的 Stream::poll_write 在 mpsc channel 有容量时直接 Ready（不唤醒
连接任务），独立驱动任务停摆。三项修复：
1. WakeDriverIo 包装器在 poll_write/flush/shutdown 后唤醒驱动 waker
2. Config::set_read_after_close(true)
3. 测试 shutdown 后 sleep(50ms) 让驱动 flush（生产中流由 copy_bidirectional 持有）
修复后 smux+yamux 双 roundtrip + multi-stream 测试全过，e2e 并发×5 通过。

**显式未支持（装配期即报错）：** reality（需 fork TLS 栈）、xhttp split 模式、
vless vision/encryption、mux.cool/sing-mux/h2mux。配置 schema 均已就位。

**yamux 修复说明：**
根因确认：libp2p yamux Stream 的 poll_write 在 mpsc channel 有容量时直接 Ready
返回（不唤醒连接任务），独立驱动任务会停摆。修复方案：
1. WakeDriverIo 包装器在 poll_write/flush/shutdown 后主动唤醒驱动任务 waker
2. yamux Config::set_read_after_close(true) 确保流关闭后仍可读取缓冲区
3. 测试代码 shutdown 后 sleep(50ms) 给驱动 flush 时间（生产中流由 copy_bidirectional
   持有至完成，无此问题）
两项修复后 smux+yamux 双 roundtrip + multi-stream 测试全部通过。

**最终状态汇总：**
29 项 e2e 全绿（含 yamux 并发×5）/ 18 单元测试全过 / 零警告编译 / CLI 行为与原版二进制一致

**已知偏差（相对原版）：**
- license 门控已按要求移除
- 数据面当前为 tokio 单后端（epoll/io_uring 模块结构在位但未接通原始 fd 中继）
- VMess 等后续实现的线上互通性需对照官方客户端验证

回归对照：`scripts/behavior_cmp.sh`（需 Docker linux/amd64 + 原始二进制）。

回归对照：`scripts/behavior_cmp.sh`（需 Docker linux/amd64 环境 + 原始二进制）。

### yamux 调试记录（供后续修复参考）
libp2p yamux 0.13 驱动要点：Connection 必须被持续 poll（poll_next_inbound 驱动
Active::poll 状态机：读帧/派发/flush 写队列）；Stream 句柄通过内部 mpsc 向连接
投递 SendFrame 命令，但 **poll_write 在 channel 有余量时直接 Ready 且不唤醒连接
任务** —— 独立驱动任务会因此停摆（数据滞留 channel）。可行方案：包装返回的
Stream，在其 poll_read/poll_write 后主动 wake 连接任务 waker（已实现
WakeDriverIo）。剩余问题：客户端流在读回显前即报 EOF（sender.is_closed()=true），
指向 receiver 生命周期被提前终结，需进一步追查 SelectAll 剪枝时机。当前版本
smux 已覆盖主要场景且经池化验证稳定，yamux 保持显式不支持。
