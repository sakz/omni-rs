use super::decode_tcp_response;
use super::encode_tcp_request;
use crate::common::TargetedOutboundConfig;
use omni_domain::stream::ProxyTarget;
use quinn::Connection as QuinnConnection;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone)]
pub struct Hysteria2OutboundConfig {
    pub base: TargetedOutboundConfig,
    pub password: String,
    #[allow(dead_code)]
    pub insecure: bool,
    pub sni: Option<String>,
}

pub struct Hysteria2Conn {
    conn: QuinnConnection,
    _h3_keepalive: Option<h3::client::Connection<h3_quinn::Connection, bytes::Bytes>>,
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("hysteria2: {}", e))
}

async fn h3_auth(
    conn: &QuinnConnection,
    password: &str,
) -> io::Result<Option<h3::client::Connection<h3_quinn::Connection, bytes::Bytes>>> {
    let (h3_conn, mut send_request) = {
        let q = h3_quinn::Connection::new(conn.clone());
        match h3::client::new(q).await {
            Ok(x) => x,
            Err(e) => return Err(io_err(format!("h3 handshake failed: {}", e))),
        }
    };

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", "0")
        .header("Hysteria-Padding", crate::random_b64(64))
        .body(())
        .map_err(|e| io_err(format!("bad auth request: {}", e)))?;

    let mut stream = send_request.send_request(req).await.map_err(io_err)?;
    stream.finish().await.map_err(io_err)?;
    let resp = stream.recv_response().await.map_err(io_err)?;

    if resp.status() != 233 {
        return Err(io_err(format!(
            "authentication failed (status {})",
            resp.status().as_u16()
        )));
    }
    Ok(Some(h3_conn))
}

impl Hysteria2Conn {
    pub async fn connect(
        cfg: &Hysteria2OutboundConfig,
        addr: std::net::SocketAddr,
    ) -> io::Result<Self> {
        omni_transport::tls::init_crypto_provider();

        let builder = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| io_err(e.to_string()))?;
        let mut client_cfg = if cfg.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(omni_transport::tls::NoVerifier))
                .with_no_client_auth()
        } else {
            builder
                .with_root_certificates(default_roots())
                .with_no_client_auth()
        };
        client_cfg.alpn_protocols = vec![b"h3".to_vec()];

        let mut quinn_client_cfg = quinn::ClientConfig::new(std::sync::Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_cfg)
                .map_err(|e| io_err(e.to_string()))?,
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30))
                .map_err(|e| io_err(e.to_string()))?,
        ));
        transport.datagram_receive_buffer_size(Some(65535));
        transport.datagram_send_buffer_size(65535);
        quinn_client_cfg.transport_config(std::sync::Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(io_err)?;
        endpoint.set_default_client_config(quinn_client_cfg);

        let sni = cfg.sni.clone().unwrap_or_else(|| "hysteria".to_string());
        let conn = endpoint
            .connect(addr, &sni)
            .map_err(io_err)?
            .await
            .map_err(io_err)?;

        let h3_keepalive = h3_auth(&conn, &cfg.password).await?;

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        Ok(Hysteria2Conn {
            conn,
            _h3_keepalive: h3_keepalive,
        })
    }

    pub async fn open_tcp(&self, target_host: &str, target_port: u16) -> io::Result<QuinnStream> {
        let addr_str = if target_host.contains(':') && !target_host.starts_with('[') {
            format!("[{}]:{}", target_host, target_port)
        } else {
            format!("{}:{}", target_host, target_port)
        };
        let (mut send, mut recv) = self.conn.open_bi().await.map_err(io_err)?;
        let req = encode_tcp_request(&addr_str);
        send.write_all(&req).await.map_err(io_err)?;
        let mut resp_buf = vec![0u8; 512];
        let n = recv
            .read(&mut resp_buf)
            .await
            .map_err(io_err)?
            .ok_or_else(|| io_err("closed"))?;
        resp_buf.truncate(n);
        let (ok, msg) = decode_tcp_response(&resp_buf)?;
        tracing::debug!(target: "internal.pipeline", "hysteria2 outbound tcp resp ok={} msg={}", ok, msg);
        if !ok {
            return Err(io_err(format!("server refused TCP: {}", msg)));
        }
        Ok(QuinnStream { send, recv })
    }

    pub fn connection(&self) -> &QuinnConnection {
        &self.conn
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn default_roots() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

pub struct QuinnStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl AsyncRead for QuinnStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.recv).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io_err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for QuinnStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io_err(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.send.finish();
        Poll::Ready(Ok(()))
    }
}

impl Hysteria2Conn {
    pub async fn connect_udp(&self) -> io::Result<omni_domain::stream::UdpHandle> {
        use omni_domain::stream::{UdpHandle, UdpPacket};

        static SID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        let session_id = SID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let conn = self.conn.clone();

        let (tx_out, mut rx_out) = tokio::sync::mpsc::channel::<UdpPacket>(256);
        let (tx_in, rx_in) = tokio::sync::mpsc::channel(256);

        let conn_w = conn.clone();
        let mut packet_counter: u16 = 0;
        tokio::spawn(async move {
            while let Some(pkt) = rx_out.recv().await {
                packet_counter = packet_counter.wrapping_add(1);
                let msg = super::UdpMessage {
                    session_id,
                    packet_id: packet_counter,
                    frag_id: 0,
                    frag_count: 1,
                    addr: pkt.target.to_string(),
                    data: pkt.data.to_vec(),
                };
                let _ = conn_w.send_datagram(bytes::Bytes::from(msg.serialize()));
            }
        });

        let conn_r = conn.clone();
        tokio::spawn(async move {
            loop {
                match conn_r.read_datagram().await {
                    Ok(dgram) => match super::UdpMessage::parse(&dgram) {
                        Ok(msg) => {
                            if msg.session_id != session_id {
                                continue;
                            }
                            if msg.frag_count != 1 {
                                continue;
                            }
                            let source = parse_host_port(&msg.addr);
                            let pkt = UdpPacket {
                                source,
                                target: ProxyTarget::Domain(String::new(), 0),
                                data: bytes::Bytes::from(msg.data),
                            };
                            if tx_in.send(pkt).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => continue,
                    },
                    Err(_) => break,
                }
            }
        });

        Ok(UdpHandle::new(tx_out, rx_in))
    }
}

fn parse_host_port(addr: &str) -> Option<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    addr.to_socket_addrs().ok()?.next()
}
