# omni-rs

高性能多协议代理框架（Rust 实现）。

从 stripped 二进制通过行为分析恢复——完整逆向过程与协议规格见 `docs/recovered/SPEC.md`。

## 构建

```bash
cargo build --release
```

需要 Rust nightly（Linux 上启用 io_uring）。macOS 自动回退到 tokio。

## 快速开始

```bash
# 启动 SOCKS5 代理 + 直连出站
./target/release/omni-rs-bin -c config.json

# 校验配置
./target/release/omni-rs-bin --check-config -c config.json
```

### 配置示例

```json
{
  "nodes": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "0.0.0.0",
      "port": 1080
    }
  ],
  "outbounds": [
    { "tag": "direct", "outbound_type": "direct" },
    {
      "tag": "block-ads",
      "outbound_type": "reject",
      "domain_suffix": ["doubleclick.net"]
    },
    {
      "tag": "via-trojan",
      "outbound_type": "trojan",
      "target": { "server": "remote.example.com", "server_port": 443 },
      "password": "secret",
      "tls": { "enabled": true, "insecure": false, "server_name": "remote.example.com" },
      "mux": { "enabled": true, "kind": "smux" },
      "domain_suffix": ["censored.example"]
    }
  ],
  "metrics_port": 9090
}
```

## 支持的协议

| 协议 | 入站 | 出站 | TCP | UDP | TLS | 复用 |
|------|------|------|-----|-----|-----|------|
| SOCKS5   | ✅ | ✅ | ✅ | ✅ | — | — |
| Trojan   | ✅ | ✅ | ✅ | ✅ | ✅ | smux |
| Shadowsocks | ✅ | ✅ | ✅ | — | — | — |
| VLESS    | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| VMess    | ✅ | ✅ | ✅ | — | ✅ | — |
| Hysteria2| ✅ | ✅ | ✅ | ✅ | QUIC | — |
| AnyTLS   | ✅ | ✅ | ✅ | — | ✅ | 内建复用 |
| Naive    | ✅ | ✅ | ✅ | — | ✅ | 内建复用 |
| Mieru    | ✅ | ✅ | ✅ | — | — | — |
| HTTP CONNECT | — | ✅ | ✅ | — | ✅ | — |

## 传输层

TCP、TLS (rustls)、WebSocket、HTTP Upgrade、gRPC、HTTP/2、XHTTP（基础模式）

## 路由

域名后缀 / 关键字 / 正则、IP CIDR、GeoIP (.dat)、GeoSite (.dat)、端口范围、入站标签。
动作：路由到出站、拒绝、劫持（base64 响应）。无匹配时回退到首个无条件出站。

## 架构

```
apps/omni-cli        CLI 入口
crates/
  omni-config        配置模型 + JSON/TOML 解析 + 校验
  omni-log           自定义 tracing fmt 层
  omni-domain        域名/IP/端口匹配引擎 + SOCKS5 编解码
  omni-mux           smux/yamux 会话池化
  omni-proto         协议实现 (trojan/ss/vless/vmess/hy2/anytls/naive/mieru)
  omni-transport     TLS/WS/gRPC/H2/XHTTP 传输层 + 拨号器/嗅探器
  omni-panel         面板对接 (xboard)
  omni-limiter       限流
  omni-core          运行时装配：监听器、管线、路由、数据面
```

## 测试

```bash
cargo test --workspace
```

29 项 e2e 测试验证各协议链路的真实流量。
`scripts/behavior_cmp.sh` 用于 CLI 行为与原版二进制的对照比较。
