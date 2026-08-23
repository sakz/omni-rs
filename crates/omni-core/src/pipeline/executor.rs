use crate::pipeline::PipelineShared;
use bytes::Bytes;
use omni_domain::stream::{BoxProxyStream, ProxyTarget};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub enum RouteAction {
    Proxy(Arc<dyn crate::runtime::assembly::outbound_artifacts::OutboundConnector>),
    Reject,
    Hijack(Bytes),
}

pub fn resolve_action(
    shared: &PipelineShared,
    target: &ProxyTarget,
    sniffed_host: Option<&str>,
    inbound_tag: &str,
) -> RouteAction {
    shared.router.route(target, sniffed_host, inbound_tag)
}

pub async fn execute_tcp(
    shared: &PipelineShared,
    action: RouteAction,
    mut client: BoxProxyStream,
    target: ProxyTarget,
    pre_read: Vec<u8>,
    user: Option<String>,
) -> std::io::Result<()> {
    match action {
        RouteAction::Reject => Ok(()),
        RouteAction::Hijack(resp) => {
            client.write_all(&resp).await?;
            client.shutdown().await?;
            Ok(())
        }
        RouteAction::Proxy(connector) => {
            let mut remote = connector
                .connect_tcp(&target, shared.dialer.clone())
                .await?;
            if !pre_read.is_empty() {
                remote.write_all(&pre_read).await?;
            }
            let (up, down) = tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
            shared.counters.add_up(up);
            shared.counters.add_down(down);
            tracing::info!(
                target: "access",
                user = user.as_deref().unwrap_or(""),
                dest = %target,
                up_bytes = up,
                down_bytes = down,
                "connection closed"
            );
            Ok(())
        }
    }
}

pub struct UdpPump {
    pub sock: Arc<tokio::net::UdpSocket>,
}

pub async fn run_socks_udp_pump(
    sock: Arc<tokio::net::UdpSocket>,
    mut control: BoxProxyStream,
    handle: omni_domain::stream::UdpHandle,
) -> std::io::Result<()> {
    let peer = Arc::new(tokio::sync::Mutex::new(None::<std::net::SocketAddr>));

    {
        let sock = sock.clone();
        let peer = peer.clone();
        let tx = handle.to_remote.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        tracing::debug!(target: "internal.pipeline", "socks udp recv n={} from={}", n, from);
                        *peer.lock().await = Some(from);
                        match omni_proto::proto::socks::parse_udp_packet(&buf[..n]) {
                            Ok((addr, data)) => {
                                tracing::debug!(target: "internal.pipeline", "socks udp parsed target={} len={}", addr.to_proxy_target(), data.len());
                                let pkt = omni_domain::stream::UdpPacket {
                                    source: None,
                                    target: addr.to_proxy_target(),
                                    data,
                                };
                                if tx.send(pkt).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::debug!(target: "internal.pipeline", "socks udp parse failed: {}", e);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    {
        let sock = sock.clone();
        let rx = handle.from_remote;
        tokio::spawn(async move {
            while let Some(pkt) = rx.lock().await.recv().await {
                let src = pkt.source.unwrap_or_else(|| match pkt.target {
                    ProxyTarget::Tcp(a) => a,
                    ProxyTarget::Domain(ref h, p) => format!("{}:{}", h, p)
                        .parse()
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                });
                let sa = omni_domain::socks5::Socks5Addr::from_proxy_target(&pkt.target);
                let frame = omni_proto::proto::socks::encode_udp_packet(&sa, &pkt.data);
                let dst = peer.lock().await.unwrap_or(src);
                if sock.send_to(&frame, dst).await.is_err() {
                    break;
                }
            }
        });
    }

    let _ = control.read(&mut [0u8; 64]).await;
    Ok(())
}
