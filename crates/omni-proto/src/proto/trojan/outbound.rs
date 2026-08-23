use super::{encode_request_head, password_hash, udp_frame, CMD_CONNECT, CMD_UDP_ASSOCIATE};
use omni_domain::socks5::Socks5Addr;
use omni_domain::stream::{ProxyStream, ProxyTarget, UdpHandle, UdpPacket};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct TrojanOutboundConfig {
    pub server: String,
    pub server_port: u16,
    pub password: String,
}

impl TrojanOutboundConfig {
    pub fn hash(&self) -> String {
        password_hash(&self.password)
    }
}

pub async fn connect_tcp_raw<S>(
    mut underlay: S,
    cfg: &TrojanOutboundConfig,
    target: &ProxyTarget,
) -> std::io::Result<S>
where
    S: ProxyStream,
{
    let head = encode_request_head(CMD_CONNECT, target, &cfg.hash());
    underlay.write_all(&head).await?;
    Ok(underlay)
}

pub struct UdpRelayClient<S> {
    stream: S,
    decoder: udp_frame::Decoder,
}

impl<S> UdpRelayClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn start(mut stream: S, cfg: Arc<TrojanOutboundConfig>) -> std::io::Result<Self> {
        let zero = ProxyTarget::Domain("0.0.0.0".into(), 0);
        let head = encode_request_head(CMD_UDP_ASSOCIATE, &zero, &cfg.hash());
        stream.write_all(&head).await?;
        Ok(UdpRelayClient {
            stream,
            decoder: udp_frame::Decoder::new(),
        })
    }

    pub fn split(
        self,
    ) -> (
        UdpRelaySend<tokio::io::WriteHalf<S>>,
        UdpRelayRecv<tokio::io::ReadHalf<S>>,
    ) {
        let (rh, wh) = tokio::io::split(self.stream);
        (
            UdpRelaySend {
                inner: wh,
                fin_sent: false,
            },
            UdpRelayRecv {
                inner: rh,
                decoder: self.decoder,
                eof: false,
            },
        )
    }

    pub async fn send_to(&mut self, target: &ProxyTarget, data: &[u8]) -> std::io::Result<()> {
        let frame = udp_frame::encode(&Socks5Addr::from_proxy_target(target), data);
        self.stream.write_all(&frame).await
    }

    pub async fn recv_from(&mut self) -> std::io::Result<(Socks5Addr, bytes::Bytes)> {
        loop {
            if let Some(res) = self.decoder.next_packet() {
                return res;
            }
            let mut buf = vec![0u8; 65536];
            let n = self.stream.read(&mut buf).await?;
            if n == 0 {
                self.decoder.mark_eof();
                match self.decoder.next_packet() {
                    Some(r) => return r,
                    None => return Err(super::ioerr("trojan: UDP relay closed")),
                }
            }
            self.decoder.feed(&buf[..n]);
        }
    }
}

pub struct UdpRelaySend<S> {
    inner: S,
    fin_sent: bool,
}

impl<S> UdpRelaySend<S>
where
    S: AsyncWrite + Unpin + Send,
{
    pub async fn send_to(&mut self, target: &ProxyTarget, data: &[u8]) -> std::io::Result<()> {
        let frame = udp_frame::encode(&Socks5Addr::from_proxy_target(target), data);
        self.inner.write_all(&frame).await
    }

    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        if !self.fin_sent {
            self.fin_sent = true;
        }
        self.inner.shutdown().await
    }
}

pub struct UdpRelayRecv<S> {
    inner: S,
    decoder: udp_frame::Decoder,
    eof: bool,
}

impl<S> UdpRelayRecv<S>
where
    S: AsyncRead + Unpin + Send,
{
    pub async fn recv_from(&mut self) -> std::io::Result<(Socks5Addr, bytes::Bytes)> {
        loop {
            if let Some(res) = self.decoder.next_packet() {
                return res;
            }
            if self.eof {
                return Err(super::ioerr("trojan: UDP relay closed"));
            }
            let mut buf = vec![0u8; 65536];
            let n = self.inner.read(&mut buf).await?;
            if n == 0 {
                self.eof = true;
                continue;
            }
            self.decoder.feed(&buf[..n]);
        }
    }
}

pub async fn bridge_udp<S>(relay: UdpRelayClient<S>) -> std::io::Result<UdpHandle>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::sync::mpsc;

    let (tx_out, mut rx_out) = mpsc::channel::<UdpPacket>(256);
    let (tx_in, rx_in) = mpsc::channel(256);
    let (mut send_half, mut recv_half) = relay.split();

    tokio::spawn(async move {
        while let Some(pkt) = rx_out.recv().await {
            if send_half.send_to(&pkt.target, &pkt.data).await.is_err() {
                break;
            }
        }
        let _ = send_half.shutdown().await;
    });

    tokio::spawn(async move {
        loop {
            match recv_half.recv_from().await {
                Ok((addr, data)) => {
                    let pkt = UdpPacket {
                        source: None,
                        target: addr.to_proxy_target(),
                        data,
                    };
                    if tx_in.send(pkt).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    Ok(UdpHandle::new(tx_out, rx_in))
}
