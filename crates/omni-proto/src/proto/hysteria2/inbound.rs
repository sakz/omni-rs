use super::{decode_tcp_request, encode_tcp_response, AUTH_STATUS_OK};
use omni_transport::tls::{build_rustls_server_config, ServerCertMaterial};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct Hysteria2ServerConfig {
    pub listen: std::net::SocketAddr,
    pub password: String,
    pub tls_material: ServerCertMaterial,
}

pub struct Hysteria2Listener {
    endpoint: quinn::Endpoint,
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other( format!("hysteria2: {}", e))
}

impl Hysteria2Listener {
    pub fn bind(cfg: &Hysteria2ServerConfig) -> io::Result<Self> {
        omni_transport::tls::init_crypto_provider();

        let server_cfg = build_rustls_server_config(&cfg.tls_material, &["h3".to_string()])
            .map_err(io_err)?;

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60)).map_err(io_err)?,
        ));
        transport.datagram_receive_buffer_size(Some(65535));
        transport.datagram_send_buffer_size(65535);
        let mut server_cfg_quinn =
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_cfg).map_err(io_err)?,
            ));
        server_cfg_quinn.transport_config(Arc::new(transport));

        let endpoint = quinn::Endpoint::server(server_cfg_quinn, cfg.listen).map_err(io_err)?;
        Ok(Hysteria2Listener { endpoint })
    }

    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.endpoint.local_addr().map_err(io_err)
    }

    pub async fn run<F, Fut>(&self, on_tcp: F) -> io::Result<()>
    where
        F: Fn(omni_domain::stream::BoxProxyStream, String) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
    {
        loop {
            let conn = match self.endpoint.accept().await {
                Some(c) => c.await.map_err(io_err)?,
                None => return Ok(()),
            };

            let qconn_for_raw = conn.clone();
            let on_tcp = on_tcp.clone();

            tokio::spawn(async move {
                tracing::info!(target: "internal.pipeline", "hysteria2 quic conn established peer={}", conn.remote_address());
                let h3_conn = h3_quinn::Connection::new(conn.clone());
                let mut h3 = match h3::server::builder().build::<h3_quinn::Connection, bytes::Bytes>(h3_conn).await {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::warn!(target: "internal.pipeline", "hysteria2 h3 init failed: {}", e);
                        return;
                    }
                };

                let mut authenticated = false;
                while !authenticated {
                    let resolver = match h3.accept().await {
                        Ok(Some(r)) => r,
                        Ok(None) => {
                            tracing::info!(target: "internal.pipeline", "hysteria2 h3 accept none");
                            return;
                        }
                        Err(e) => {
                            tracing::warn!(target: "internal.pipeline", "hysteria2 h3 accept err: {}", e);
                            return;
                        }
                    };
                    let (req, mut req_stream) = match resolver.resolve_request().await {
                        Ok(x) => x,
                        Err(e) => {
                            tracing::warn!(target: "internal.pipeline", "hysteria2 resolve req failed: {}", e);
                            return;
                        }
                    };
                    tracing::info!(target: "internal.pipeline", "hysteria2 req {} {}", req.method(), req.uri());

                    let is_auth = req.method() == http::Method::POST
                        && req.uri().host() == Some("hysteria")
                        && req.uri().path() == "/auth";
                    if !is_auth {
                        continue;
                    }

                    let auth = req
                        .headers()
                        .get("Hysteria-Auth")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();

                    while req_stream.recv_data().await.ok().flatten().is_some() {}

                    if auth.is_empty() {
                        continue;
                    }

                    let resp = http::Response::builder()
                        .status(AUTH_STATUS_OK)
                        .header("Hysteria-UDP", "false")
                        .header("Hysteria-CC-RX", "0")
                        .body(())
                        .unwrap();
                    if req_stream.send_response(resp).await.is_err() {
                        return;
                    }
                    let _ = req_stream.finish().await;
                    authenticated = true;
                }

                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let _h3_park = Some(h3);

                {
                    let conn_udp = qconn_for_raw.clone();
                    tokio::spawn(async move { run_udp_dispatcher(conn_udp).await });
                }

                loop {
                    let (mut send, mut recv) = match qconn_for_raw.accept_bi().await {
                        Ok(x) => x,
                        Err(_) => return,
                    };
                    let on_tcp = on_tcp.clone();
                    tokio::spawn(async move {
                        let mut head = vec![0u8; 4096];
                        let mut total = 0usize;
                        let addr = loop {
                            match recv.read(&mut head[total..]).await {
                                Ok(Some(n)) => {
                                    total += n;
                                    match decode_tcp_request(&head[..total]) {
                                        Ok((addr, rest)) => {
                                            if !rest.is_empty() && send.write_all(rest).await.is_err() {
                                                return;
                                            }
                                            break addr;
                                        }
                                        Err(e)
                                            if e.kind()
                                                == std::io::ErrorKind::UnexpectedEof =>
                                        {
                                            if total >= head.len() {
                                                let _ =
                                                    send.write_all(&encode_tcp_response(false, "addr too long")).await;
                                                return;
                                            }
                                            continue;
                                        }
                                        Err(e) => {
                                            let _ = send.write_all(&encode_tcp_response(false, e.to_string().as_str())).await;
                                            return;
                                        }
                                    }
                                }
                                _ => return,
                            }
                        };

                        let (ok, msg) = (true, String::new());
                        let _ = msg;
                        if send.write_all(&encode_tcp_response(ok, "")).await.is_err() {
                            return;
                        }

                        tracing::info!(target: "internal.pipeline", "hysteria2 tcp stream target={}", addr);
                        let stream = HysteriaStream { send, recv };
                        match on_tcp(omni_domain::stream::boxed(stream), addr.clone()).await {
                            Ok(()) => tracing::debug!(target: "internal.pipeline", "hysteria2 stream done target={}", addr),
                            Err(e) => tracing::warn!(target: "internal.pipeline", "hysteria2 stream error target={} error={}", addr, e),
                        }
                    });
                }
            });
        }
    }
}

pub struct HysteriaStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl AsyncRead for HysteriaStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for HysteriaStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => std::task::Poll::Ready(Ok(n)),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(io::Error::other( e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let _ = self.send.finish();
        std::task::Poll::Ready(Ok(()))
    }
}

use std::collections::HashMap;

async fn run_udp_dispatcher(conn: quinn::Connection) {
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::Arc;

    let sessions: std::sync::Mutex<HashMap<u32, Arc<UdpSocket>>> =
        std::sync::Mutex::new(HashMap::new());

    loop {
        let dgram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(_) => return,
        };
        let msg = match super::UdpMessage::parse(&dgram) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if msg.frag_count != 1 {
            continue;
        }
        let sid = msg.session_id;
        let existing = sessions.lock().unwrap().get(&sid).cloned();
        let sock: Arc<UdpSocket> = match existing {
            Some(s) => s,
            None => {
                let s = match UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => Arc::new(s),
                    Err(_) => continue,
                };
                let s_task = s.clone();
                sessions.lock().unwrap().insert(sid, s.clone());
                let conn2 = conn.clone();
                tokio::spawn(async move {
                    let s = s_task;
                    let mut buf = vec![0u8; 65535];
                    loop {
                        let (n, from) = match sock2_recv(&s, &mut buf) {
                            Ok(x) => x,
                            Err(_) => return,
                        };
                        let reply = super::UdpMessage {
                            session_id: sid,
                            packet_id: 0,
                            frag_id: 0,
                            frag_count: 1,
                            addr: from.to_string(),
                            data: buf[..n].to_vec(),
                        };
                        let _ = conn2.send_datagram(bytes::Bytes::from(reply.serialize()));
                    }
                });
                s
            }
        };

        use std::net::ToSocketAddrs;
        let target: Option<SocketAddr> = msg
            .addr
            .to_socket_addrs()
            .ok()
            .and_then(|mut i| i.next());
        let target = match target {
            Some(t) => t,
            None => continue,
        };
        let _ = sock.send_to(&msg.data, target);
    }
}

fn sock2_recv(
    s: &std::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr)> {
    s.recv_from(buf)
}
