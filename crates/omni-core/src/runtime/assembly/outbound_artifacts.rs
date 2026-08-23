use crate::pipeline::executor::RouteAction;
use std::pin::Pin;
use omni_domain::matching::compiler::CompiledRule;
use omni_domain::stream::{BoxProxyStream, ProxyTarget, UdpHandle};
use omni_transport::dial::Dialer;
use std::sync::Arc;

pub type DialFut<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<BoxProxyStream>> + Send + 'a>>;

pub trait OutboundConnector: Send + Sync {
    fn tag(&self) -> &str;
    fn supports_udp(&self) -> bool {
        false
    }
    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_>;
    fn connect_udp(
        &self,
        _dialer: Arc<Dialer>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<UdpHandle>> + Send + '_>>
    {
        Box::pin(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("outbound '{}' does not support UDP", self.tag()),
            ))
        })
    }
}

pub struct DirectOutbound;

impl OutboundConnector for DirectOutbound {
    fn tag(&self) -> &str {
        "direct"
    }

    fn supports_udp(&self) -> bool {
        true
    }

    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_> {
        let target = target.clone();
        Box::pin(async move {
            let s = dialer.dial_tcp(&target).await?;
            Ok(omni_domain::stream::boxed(s))
        })
    }

    fn connect_udp(
        &self,
        _dialer: Arc<Dialer>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<UdpHandle>> + Send + '_>>
    {
        Box::pin(async move {
            use tokio::net::UdpSocket;
            let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
            let (tx_out, mut rx_out) = tokio::sync::mpsc::channel::<omni_domain::stream::UdpPacket>(256);
            let (tx_in, rx_in) = tokio::sync::mpsc::channel(256);
            let sock_reader = Arc::clone(&sock);
            let sock_writer = Arc::clone(&sock);
            tokio::spawn(async move {
                let sock = sock_reader;
                let mut buf = vec![0u8; 65535];
                loop {
                    match sock.recv_from(&mut buf).await {
                        Ok((n, src)) => {
                            let pkt = omni_domain::stream::UdpPacket {
                                source: Some(src),
                                target: ProxyTarget::Tcp(src),
                                data: bytes::Bytes::copy_from_slice(&buf[..n]),
                            };
                            if tx_in.send(pkt).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            tokio::spawn(async move {
                let sock = sock_writer;
                while let Some(pkt) = rx_out.recv().await {
                    match &pkt.target {
                        ProxyTarget::Tcp(addr) => {
                            let _ = sock.send_to(&pkt.data, *addr).await;
                        }
                        ProxyTarget::Domain(h, p) => {
                            if let Ok(mut it) = tokio::net::lookup_host((h.as_str(), *p)).await {
                                if let Some(a) = it.next() {
                                    let _ = sock.send_to(&pkt.data, a).await;
                                }
                            }
                        }
                    }
                }
            });
            Ok(UdpHandle::new(tx_out, rx_in))
        })
    }
}

pub struct RejectOutbound;

impl OutboundConnector for RejectOutbound {
    fn tag(&self) -> &str {
        "reject"
    }

    fn connect_tcp(&self, _target: &ProxyTarget, __dialer: Arc<Dialer>) -> DialFut<'_> {
        Box::pin(async {
            Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "rejected"))
        })
    }
}



#[derive(Clone)]
pub struct TlsClientSpec {
    pub skip_verify: bool,
    pub alpn: Vec<String>,
    pub sni_override: Option<String>,
}

#[derive(Clone)]
pub struct TrojanConnector {
    pub tag_name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub tls: Option<TlsClientSpec>,
    pub transport: Option<TransportSpec>,
    pub mux_pool: Option<Arc<omni_mux::pool::MuxPool>>,
}


impl OutboundConnector for TrojanConnector {
    fn tag(&self) -> &str {
        &self.tag_name
    }

    fn supports_udp(&self) -> bool {
        true
    }

    fn connect_udp(
        &self,
        dialer: Arc<Dialer>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<omni_domain::stream::UdpHandle>> + Send + '_>>
    {
        let cfg = self.clone();
        Box::pin(async move {
            let underlay =
                dial_with_transport(dialer, &cfg.server, cfg.port, cfg.tls.as_ref(), None, None).await?;
            let relay = omni_proto::proto::trojan::outbound::UdpRelayClient::start(
                underlay,
                Arc::new(omni_proto::proto::trojan::outbound::TrojanOutboundConfig {
                    server: String::new(),
                    server_port: 0,
                    password: cfg.password.clone(),
                }),
            )
            .await?;
            omni_proto::proto::trojan::outbound::bridge_udp(relay).await
        })
    }

    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_> {
        let cfg = self.clone();
        let target = target.clone();
        Box::pin(async move {
            let underlay = dial_with_transport(
                dialer,
                cfg.server.as_str(),
                cfg.port,
                cfg.tls.as_ref(),
                cfg.transport.as_ref(),
                cfg.mux_pool.as_ref(),
            )
            .await?;
            let tcfg = omni_proto::proto::trojan::outbound::TrojanOutboundConfig {
                server: String::new(),
                server_port: 0,
                password: cfg.password.clone(),
            };
            let stream =
                omni_proto::proto::trojan::outbound::connect_tcp_raw(underlay, &tcfg, &target).await?;
            Ok(stream)
        })
    }
}

pub struct SsConnector {
    pub tag_name: String,
    pub config: omni_proto::proto::shadowsocks::outbound::SsOutboundConfig,
}

impl OutboundConnector for SsConnector {
    fn tag(&self) -> &str {
        &self.tag_name
    }

    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_> {
        let cfg = self.config.clone();
        let target = target.clone();
        Box::pin(async move {
            let addr = resolve_server_addr(&dialer, &cfg.server, cfg.server_port).await?;
            let raw = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dial: timeout"))??;
            let _ = raw.set_nodelay(true);
            let (r, w) =
                omni_proto::proto::shadowsocks::outbound::connect_tcp(raw, &cfg, &target).await?;
            Ok(ss_duplex(r, w))
        })
    }
}

pub struct VlessConnector {
    pub tag_name: String,
    pub config: omni_proto::proto::vless::outbound::VlessOutboundConfig,
    pub tls: Option<TlsClientSpec>,
    pub transport: Option<TransportSpec>,
    pub mux_pool: Option<Arc<omni_mux::pool::MuxPool>>,
}

impl OutboundConnector for VlessConnector {
    fn tag(&self) -> &str {
        &self.tag_name
    }

    fn supports_udp(&self) -> bool {
        true
    }

    fn connect_udp(
        &self,
        dialer: Arc<Dialer>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<omni_domain::stream::UdpHandle>> + Send + '_>>
    {
        let cfg = self.config.clone();
        let tls = self.tls.clone();
        Box::pin(async move {
            let underlay =
                dial_with_transport(dialer, cfg.server.as_str(), cfg.server_port, tls.as_ref(), None, None).await?;
            omni_proto::proto::vless::outbound::connect_udp(underlay, &cfg).await
        })
    }

    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_> {
        let cfg = self.config.clone();
        let tls = self.tls.clone();
        let target = target.clone();
        Box::pin(async move {
            let underlay =
                dial_with_transport(
                dialer,
                cfg.server.as_str(),
                cfg.server_port,
                tls.as_ref(),
                self.transport.as_ref(),
                self.mux_pool.as_ref(),
            )
            .await?;
            let stream = omni_proto::proto::vless::outbound::connect_tcp(underlay, &cfg, &target).await?;
            Ok(omni_domain::stream::boxed(stream))
        })
    }
}

pub struct VmessConnector {
    pub mux_pool: Option<Arc<omni_mux::pool::MuxPool>>,
    pub tag_name: String,
    pub config: omni_proto::proto::vmess::outbound::VmessOutboundConfig,
    pub tls: Option<TlsClientSpec>,
}

impl OutboundConnector for VmessConnector {
    fn tag(&self) -> &str {
        &self.tag_name
    }

    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_> {
        let cfg = self.config.clone();
        let tls = self.tls.clone();
        let target = target.clone();
        Box::pin(async move {
            let underlay = dial_underlay(dialer, cfg.base.server.as_str(), cfg.base.server_port, tls.as_ref()).await?;
            let (r, w) = omni_proto::proto::vmess::outbound::connect_tcp(underlay, &cfg, &target).await?;
            Ok(vmess_duplex(r, w))
        })
    }
}

pub struct MieruConnector {
    pub tag_name: String,
    pub config: omni_proto::proto::mieru::outbound::MieruOutboundConfig,
}

impl OutboundConnector for MieruConnector {
    fn tag(&self) -> &str {
        &self.tag_name
    }

    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_> {
        let cfg = self.config.clone();
        let target = target.clone();
        Box::pin(async move {
            let addr = resolve_server_addr(&dialer, &cfg.server, cfg.port).await?;
            let raw = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dial: timeout"))??;
            raw.set_nodelay(true).ok();
            omni_proto::proto::mieru::outbound::connect_tcp(raw, &cfg, &target).await
        })
    }
}

pub struct NaiveConnector {
    pub tag_name: String,
    pub server: String,
    pub port: u16,
    pub insecure: bool,
    pub sni: Option<String>,
}

impl OutboundConnector for NaiveConnector {
    fn tag(&self) -> &str {
        &self.tag_name
    }

    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_> {
        let server = self.server.clone();
        let port = self.port;
        let tls = Some(TlsClientSpec {
            skip_verify: self.insecure,
            alpn: vec!["h2".to_string()],
            sni_override: self.sni.clone(),
        });
        let target = target.clone();
        Box::pin(async move {
            let underlay =
                dial_with_transport(dialer, &server, port, tls.as_ref(), None, None).await?;
            let cfg = omni_proto::proto::naive::outbound::NaiveOutboundConfig {
                base: crate::common_alias::TargetedOutboundConfig {
                    server: String::new(),
                    server_port: 0,
                },
            };
            omni_proto::proto::naive::outbound::connect_tcp(underlay, &cfg, &target).await
        })
    }
}

pub struct AnytlsConnector {
    pub tag_name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub tls: Option<TlsClientSpec>,
    pub insecure: bool,
    pub sni: Option<String>,
    pub session_pool:
        Arc<tokio::sync::Mutex<Option<omni_proto::proto::anytls::client::SharedClientSession>>>,
}

impl AnytlsConnector {
    async fn get_session(
        &self,
        dialer: &Arc<Dialer>,
    ) -> std::io::Result<omni_proto::proto::anytls::client::SharedClientSession> {
        {
            let g = self.session_pool.lock().await;
            if let Some(s) = &*g {
                return Ok(s.clone());
            }
        }
        let underlay =
            dial_with_transport(dialer.clone(), &self.server, self.port, self.tls.as_ref(), None, None).await?;
        let session = omni_proto::proto::anytls::client::connect(underlay, &self.password).await?;
        *self.session_pool.lock().await = Some(session.clone());
        Ok(session)
    }

    fn evict_session(&self) {
        if let Ok(mut g) = self.session_pool.try_lock() {
            *g = None;
        }
    }
}

impl OutboundConnector for AnytlsConnector {
    fn tag(&self) -> &str {
        &self.tag_name
    }

    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_> {
        let target = target.clone();
        Box::pin(async move {
            for attempt in 0..2u8 {
                let session = self.get_session(&dialer).await?;
                let mut guard = session.lock().await;
                let wtx = guard.writer_tx.clone();
                match guard.open_stream_to(&wtx, &target).await {
                    Ok(stream) => return Ok(omni_domain::stream::boxed(stream)),
                    Err(e) if attempt == 0 => {
                        tracing::debug!(target: "internal.pipeline", "anytls pooled open failed, reconnecting: {}", e);
                        drop(guard);
                        self.evict_session();
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            unreachable!()
        })
    }
}

pub struct Hysteria2Connector {
    pub tag_name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub insecure: bool,
    pub sni: Option<String>,
    pub conn_pool: Arc<tokio::sync::Mutex<Option<Arc<omni_proto::proto::hysteria2::outbound::Hysteria2Conn>>>>,
}

impl Hysteria2Connector {
    async fn get_conn(
        &self,
        dialer: &Arc<Dialer>,
    ) -> std::io::Result<Arc<omni_proto::proto::hysteria2::outbound::Hysteria2Conn>> {
        {
            let g = self.conn_pool.lock().await;
            if let Some(c) = &*g {
                return Ok(c.clone());
            }
        }
        let cfg = omni_proto::proto::hysteria2::outbound::Hysteria2OutboundConfig {
            base: crate::common_alias::TargetedOutboundConfig {
                server: self.server.clone(),
                server_port: self.port,
            },
            password: self.password.clone(),
            insecure: self.insecure,
            sni: self.sni.clone(),
        };
        let addr = resolve_server_addr(dialer, &self.server, self.port).await?;
        let conn =
            Arc::new(omni_proto::proto::hysteria2::outbound::Hysteria2Conn::connect(&cfg, addr).await?);
        *self.conn_pool.lock().await = Some(conn.clone());
        Ok(conn)
    }

    fn evict_conn(&self) {
        if let Ok(mut g) = self.conn_pool.try_lock() {
            *g = None;
        }
    }
}

impl OutboundConnector for Hysteria2Connector {
    fn tag(&self) -> &str {
        &self.tag_name
    }

    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_> {
        let target = target.clone();
        Box::pin(async move {
            for attempt in 0..2u8 {
                let conn = self.get_conn(&dialer).await?;
                match conn.open_tcp(&target.host(), target.port()).await {
                    Ok(stream) => return Ok(omni_domain::stream::boxed(stream)),
                    Err(e) if attempt == 0 => {
                        tracing::debug!(target: "internal.pipeline", "hy2 pooled open failed, reconnecting: {}", e);
                        self.evict_conn();
                    }
                    Err(e) => return Err(e),
                }
            }
            unreachable!()
        })
    }
}

impl Hysteria2Connector {
    pub async fn udp_handle(
        &self,
        dialer: Arc<Dialer>,
    ) -> std::io::Result<omni_domain::stream::UdpHandle> {
        for attempt in 0..2u8 {
            let conn = self.get_conn(&dialer).await?;
            match conn.connect_udp().await {
                Ok(h) => return Ok(h),
                Err(e) if attempt == 0 => {
                    tracing::debug!(target: "internal.pipeline", "hy2 pooled udp failed, reconnecting: {}", e);
                    self.evict_conn();
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }
}

pub struct Socks5Connector {
    pub tag_name: String,
    pub config: omni_proto::proto::socks::client::SocksOutboundConfig,
}

impl OutboundConnector for Socks5Connector {
    fn tag(&self) -> &str {
        &self.tag_name
    }

    fn connect_tcp(&self, target: &ProxyTarget, _dialer: Arc<Dialer>) -> DialFut<'_> {
        let cfg = self.config.clone();
        let target = target.clone();
        Box::pin(async move {
            let stream = omni_proto::proto::socks::client::connect_tcp(&cfg, &target).await?;
            Ok(omni_domain::stream::boxed(stream))
        })
    }
}

pub struct HttpConnectConnector {
    pub tag_name: String,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl OutboundConnector for HttpConnectConnector {
    fn tag(&self) -> &str {
        &self.tag_name
    }

    fn connect_tcp(&self, target: &ProxyTarget, dialer: Arc<Dialer>) -> DialFut<'_> {
        let srv = self.server.clone();
        let port = self.port;
        let user = self.username.clone();
        let pass = self.password.clone();
        let target = target.clone();
        Box::pin(async move {
            let addr = resolve_server_addr(&dialer, &srv, port).await?;
            let mut s = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dial: timeout"))??;
            s.set_nodelay(true).ok();
            http_connect_handshake(&mut s, &target, user.as_deref(), pass.as_deref()).await?;
            Ok(omni_domain::stream::boxed(s))
        })
    }
}

async fn http_connect_handshake<S>(
    s: &mut S,
    target: &ProxyTarget,
    user: Option<&str>,
    pass: Option<&str>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use base64::Engine;
    let authority = format!("{}", target);
    let mut req = format!(
        "CONNECT {a} HTTP/1.1\r\nHost: {a}\r\n",
        a = authority
    );
    if let Some(u) = user {
        let creds = format!(
            "{}:{}",
            u,
            pass.unwrap_or("")
        );
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(creds)
        ));
    }
    req.push_str("\r\n");
    tokio::io::AsyncWriteExt::write_all(s, req.as_bytes()).await?;

    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        use tokio::io::AsyncReadExt;
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "http proxy: closed during CONNECT",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 32 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "http proxy: oversized response",
            ));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("500");
    if status != "200" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("http proxy: CONNECT refused ({})", status),
        ));
    }
    Ok(())
}

pub struct ChannelDuplex {
    rx: tokio::sync::mpsc::UnboundedReceiver<std::io::Result<Vec<u8>>>,
    pending: std::collections::VecDeque<u8>,
    eof: bool,
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

pub fn vmess_duplex<S>(
    r: omni_proto::proto::vmess::chunk::ChunkReader<tokio::io::ReadHalf<S>>,
    w: omni_proto::proto::vmess::chunk::ChunkWriter<tokio::io::WriteHalf<S>>,
) -> BoxProxyStream
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::sync::mpsc;
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut r = r;
        loop {
            let mut b = vec![0u8; 16384];
            match r.read_data(&mut b).await {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx.send(Ok(b[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = out_tx.send(Err(e));
                    break;
                }
            }
        }
        let _ = out_tx.send(Ok(Vec::new()));
    });

    let (in_tx, mut in_rx): (mpsc::UnboundedSender<Vec<u8>>, mpsc::UnboundedReceiver<Vec<u8>>) =
        mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut w = w;
        while let Some(v) = in_rx.recv().await {
            if v.is_empty() {
                continue;
            }
            if w.write_chunk(&v, true).await.is_err() {
                break;
            }
        }
        let _ = w.write_chunk(&[], false).await;
    });

    Box::new(ChannelDuplex {
        rx: out_rx,
        pending: std::collections::VecDeque::new(),
        eof: false,
        tx: in_tx,
    })
}

pub fn ss_duplex<R, W>(
    r: omni_proto::proto::shadowsocks::stream::AeadStreamReader<R>,
    w: omni_proto::proto::shadowsocks::stream::AeadStreamWriter<W>,
) -> BoxProxyStream
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::sync::mpsc;
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut r = r;
        loop {
            let mut b = vec![0u8; 16384];
            match r.read_data(&mut b).await {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx.send(Ok(b[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = out_tx.send(Err(e));
                    break;
                }
            }
        }
        let _ = out_tx.send(Ok(Vec::new()));
    });

    let (in_tx, mut in_rx): (mpsc::UnboundedSender<Vec<u8>>, mpsc::UnboundedReceiver<Vec<u8>>) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut w = w;
        while let Some(v) = in_rx.recv().await {
            if v.is_empty() {
                continue;
            }
            if w.write_chunk(&v, true).await.is_err() {
                break;
            }
        }
        let _ = w.write_chunk(&[], false).await;
    });

    Box::new(ChannelDuplex {
        rx: out_rx,
        pending: std::collections::VecDeque::new(),
        eof: false,
        tx: in_tx,
    })
}

impl tokio::io::AsyncRead for ChannelDuplex {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = out.remaining().min(self.pending.len());
                let data: Vec<u8> = self.pending.drain(..n).collect();
                out.put_slice(&data);
                return std::task::Poll::Ready(Ok(()));
            }
            if self.eof {
                return std::task::Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                std::task::Poll::Ready(Some(Ok(data))) => {
                    if data.is_empty() {
                        self.eof = true;
                    } else {
                        self.pending.extend(data);
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    self.eof = true;
                    return std::task::Poll::Ready(Err(e));
                }
                std::task::Poll::Ready(None) => {
                    self.eof = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

impl tokio::io::AsyncWrite for ChannelDuplex {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.tx.send(buf.to_vec()).is_err() {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "ss: writer closed",
            )));
        }
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Clone)]
pub struct MuxOutboundConfig {
    pub enabled: bool,
    pub kind: String,
}

#[derive(Debug, Clone, Default)]
pub struct TransportSpec {
    pub kind: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service_name: Option<String>,
}

impl TransportSpec {
    pub fn parse(v: Option<&serde_json::Value>) -> Option<TransportSpec> {
        let obj = v.as_ref()?.as_object()?;
        let kind = obj
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("tcp")
            .to_string();
        if kind == "tcp" || kind.is_empty() {
            return None;
        }
        Some(TransportSpec {
            kind,
            path: obj
                .get("path")
                .and_then(|p| p.as_str())
                .map(String::from),
            host: obj
                .get("host")
                .or_else(|| obj.get("host_header"))
                .and_then(|h| h.as_str())
                .map(String::from),
            service_name: obj
                .get("service_name")
                .and_then(|s| s.as_str())
                .map(String::from),
        })
    }
}

pub async fn dial_with_transport(
    dialer: Arc<Dialer>,
    server: &str,
    port: u16,
    tls: Option<&TlsClientSpec>,
    transport: Option<&TransportSpec>,
    mux_pool: Option<&Arc<omni_mux::pool::MuxPool>>,
) -> std::io::Result<BoxProxyStream> {
    let underlay: BoxProxyStream = match mux_pool {
        Some(pool) => {
            let mut entries_alive = true;
            let _ = &mut entries_alive;
            // Fast path handled by caller-supplied closure below; here we only
            // construct it lazily so existing healthy sessions skip dialing.
            let server_owned = server.to_string();
            let d2 = dialer.clone();
            let tls2 = tls.cloned();
            let connect = Box::pin(async move {
                dial_underlay(d2, &server_owned, port, tls2.as_ref()).await
            })
                as Pin<Box<dyn std::future::Future<Output = std::io::Result<BoxProxyStream>> + Send>>;
            let (stream, _lease) = pool.dial(connect).await?;
            stream
        }
        None => dial_underlay(dialer, server, port, tls).await?,
    };
    match transport {
        None => Ok(underlay),
        Some(t) => match t.kind.as_str() {
            "ws" | "websocket" => {
                let spec = omni_transport::ws::WsOutboundSpec {
                    host_header: t.host.clone(),
                    path: t.path.clone(),
                    skip_verify: false,
                };
                let target = ProxyTarget::Domain(server.to_string(), port);
                let ws = omni_transport::ws::connect_outbound(underlay, &spec, &target).await?;
                Ok(omni_domain::stream::boxed(omni_transport::ws::WsProxyStream::new(ws)))
            }
            "grpc" => {
                let spec = omni_transport::grpc::GrpcOutboundSpec {
                    service_name: t.service_name.clone().unwrap_or_else(|| "GunService".into()),
                    host_header: t.host.clone(),
                };
                let target = ProxyTarget::Domain(server.to_string(), port);
                omni_transport::grpc::connect_outbound(underlay, &spec, &target).await
            }
            "xhttp" => {
                let spec = omni_transport::xhttp::XhttpOutboundSpec {
                    path: t.path.clone(),
                    host: t.host.clone(),
                    mode: None,
                };
                omni_transport::xhttp::connect_outbound(underlay, &spec, &ProxyTarget::Domain(server.to_string(), port)).await
            }
            "h2" => {
                let mut conn = omni_transport::h2::client_handshake(underlay).await?;
                let authority = t.host.clone().unwrap_or_else(|| server.to_string());
                let path = t.path.clone().unwrap_or_else(|| "/".to_string());
                let stream = conn.open_proxy_stream("GET", &path, &authority, "").await?;
                Ok(omni_domain::stream::boxed(stream))
            }
            other => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("transport '{}' not yet implemented", other),
            )),
        },
    }
}

pub async fn dial_underlay(
    dialer: Arc<Dialer>,
    server: &str,
    port: u16,
    tls: Option<&TlsClientSpec>,
) -> std::io::Result<BoxProxyStream> {
    let addr = resolve_server_addr(&dialer, server, port).await?;
    let raw = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dial: timeout"))??;
    raw.set_nodelay(true).ok();

    match tls {
        None => Ok(omni_domain::stream::boxed(raw)),
        Some(spec) => {
            let settings = omni_transport::tls::ClientTlsSettings {
                skip_verify: spec.skip_verify,
                alpn: spec.alpn.clone(),
                server_name_override: spec.sni_override.clone(),
            };
            let cfg = omni_transport::tls::build_client_config(&settings)
                .map_err(std::io::Error::other)?;
            let name = omni_transport::tls::server_name_for(server, spec.sni_override.as_deref());
            let sni = rustls_pki_types::ServerName::try_from(name.clone())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("tls: bad server name '{}': {}", name, e)))?;
            let conn = tokio_rustls::TlsConnector::from(cfg);
            let stream = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                conn.connect(sni, raw),
            )
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tls: handshake timeout"))??;
            Ok(omni_domain::stream::boxed(stream))
        }
    }
}

pub async fn resolve_server_addr(
    dialer: &Arc<Dialer>,
    server: &str,
    port: u16,
) -> std::io::Result<std::net::SocketAddr> {
    dialer
        .resolve(&ProxyTarget::Domain(server.to_string(), port))
        .await
}

struct RouteEntry {
    rule: CompiledRule,
    action: EntryAction,
    hijack: Option<Vec<u8>>,
}

enum EntryAction {
    Tag(String),
}

pub struct Router {
    entries: Vec<RouteEntry>,
    connectors: HashMap<String, Arc<dyn OutboundConnector>>,
    default_tag: Option<String>,
    geo: Arc<crate::matching::geo::GeoRegistry>,
}

unsafe impl Send for Router {}
unsafe impl Sync for Router {}
unsafe impl Send for RouteEntry {}
unsafe impl Sync for RouteEntry {}

impl Router {
    pub fn route(
        &self,
        target: &ProxyTarget,
        sniffed_host: Option<&str>,
        inbound_tag: &str,
    ) -> RouteAction {
        let host = sniffed_host.map(String::from).or_else(|| match target {
            ProxyTarget::Domain(h, _) => Some(h.clone()),
            ProxyTarget::Tcp(_) => None,
        });
        let port = target.port();
        let ip = match target {
            ProxyTarget::Tcp(a) => Some(a.ip()),
            ProxyTarget::Domain(_, _) => None,
        };

        for e in &self.entries {
            if !e.rule.has_criteria {
                continue;
            }
            if e.rule.matches(host.as_deref(), ip, port, Some(inbound_tag), self.geo.as_ref()) {
                return self.entry_action(e);
            }
        }
        for e in &self.entries {
            if !e.rule.has_criteria {
                return self.entry_action(e);
            }
        }
        if let Some(tag) = &self.default_tag {
            if let Some(c) = self.connectors.get(tag) {
                return RouteAction::Proxy(c.clone());
            }
        }
        tracing::info!(target: "internal.policy", "no matching route; rejecting dest={}", target);
        RouteAction::Reject
    }

    pub fn first_udp_connector(&self) -> std::io::Result<Arc<dyn OutboundConnector>> {
        if let Some(c) = self.connectors.get("direct") {
            return Ok(c.clone());
        }
        self.connectors
            .values()
            .find(|c| c.supports_udp())
            .cloned()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "no udp-capable outbound configured",
                )
            })
    }

    fn entry_action(&self, e: &RouteEntry) -> RouteAction {
        if let Some(bytes) = &e.hijack {
            return RouteAction::Hijack(bytes::Bytes::copy_from_slice(bytes));
        }
        match &e.action {
            EntryAction::Tag(tag) => match self.connectors.get(tag) {
                Some(c) => RouteAction::Proxy(c.clone()),
                None => RouteAction::Reject,
            },
        }
    }
}

use std::collections::HashMap;

pub struct RouterBuilder {
    entries: Vec<RouteEntry>,
    connectors: HashMap<String, Arc<dyn OutboundConnector>>,
}

impl RouterBuilder {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            connectors: HashMap::new(),
        }
    }

    pub fn add_connector(&mut self, c: Arc<dyn OutboundConnector>) {
        self.connectors.insert(c.tag().to_string(), c);
    }

    pub fn has_connector(&self, tag: &str) -> bool {
        self.connectors.contains_key(tag)
    }

    pub fn add_rule_entry(
        &mut self,
        ast: omni_domain::matching::ast::RouteRuleAst,
        tag: String,
        hijack_b64: Option<String>,
    ) -> Result<(), String> {
        let rule = ast.compile()?;
        let hijack = match hijack_b64 {
            Some(b64) if !b64.is_empty() => {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .map_err(|e| format!("route hijack response_base64 decode failed: {}", e))?;
                if bytes.is_empty() {
                    None
                } else {
                    Some(bytes)
                }
            }
            _ => None,
        };
        self.entries.push(RouteEntry {
            rule,
            action: EntryAction::Tag(tag),
            hijack,
        });
        Ok(())
    }

    pub fn build(self, geo: Arc<crate::matching::geo::GeoRegistry>) -> Router {
        let default_tag: Option<String> = None;
        Router {
            entries: self.entries,
            connectors: self.connectors,
            default_tag,
            geo,
        }
    }
}
