use super::{encode_request, read_response, udp_frame, CMD_TCP, CMD_UDP};
use crate::crypto::parse_uuid;
use omni_domain::stream::{ProxyStream, ProxyTarget, UdpHandle, UdpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct VlessOutboundConfig {
    pub server: String,
    pub server_port: u16,
    pub uuid: String,
}

impl VlessOutboundConfig {
    pub fn uuid_bytes(&self) -> std::io::Result<[u8; 16]> {
        parse_uuid(&self.uuid).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("vless: invalid UUID '{}'", self.uuid),
            )
        })
    }
}

pub async fn connect_tcp<S>(
    mut underlay: S,
    cfg: &VlessOutboundConfig,
    target: &ProxyTarget,
) -> std::io::Result<S>
where
    S: ProxyStream,
{
    let uuid = cfg.uuid_bytes()?;
    let head = encode_request(&uuid, CMD_TCP, target, &[]);
    tracing::debug!(target: "internal.pipeline", "vless outbound writing head len={}", head.len());
    underlay.write_all(&head).await?;
    underlay.flush().await?;
    tracing::debug!(target: "internal.pipeline", "vless outbound head written, awaiting response");
    read_response(&mut underlay).await?;
    tracing::debug!(target: "internal.pipeline", "vless outbound response ok");
    Ok(underlay)
}

pub async fn connect_udp<S>(underlay: S, cfg: &VlessOutboundConfig) -> std::io::Result<UdpHandle>
where
    S: ProxyStream + 'static,
{
    let uuid = cfg.uuid_bytes()?;
    let mut stream = underlay;
    let zero = ProxyTarget::Domain(String::from("0.0.0.0"), 0);
    let head = encode_request(&uuid, CMD_UDP, &zero, &[]);
    stream.write_all(&head).await?;
    read_response(&mut stream).await?;

    let (tx_out, mut rx_out) = mpsc::channel::<UdpPacket>(256);
    let (tx_in, rx_in) = mpsc::channel::<UdpPacket>(256);
    let (mut rd, mut wr) = tokio::io::split(stream);

    tokio::spawn(async move {
        while let Some(pkt) = rx_out.recv().await {
            let frame = udp_frame::encode(&pkt.target, &pkt.data);
            if wr.write_all(&frame).await.is_err() || wr.flush().await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    tokio::spawn(async move {
        let mut dec = udp_frame::Decoder::new();
        let mut buf = vec![0u8; 65536];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => {
                    dec.mark_eof();
                    break;
                }
                Ok(n) => {
                    dec.feed(&buf[..n]);
                    loop {
                        match dec.next_packet() {
                            Some(Ok((target, data))) => {
                                let pkt = UdpPacket {
                                    source: None,
                                    target,
                                    data,
                                };
                                if tx_in.send(pkt).await.is_err() {
                                    return;
                                }
                            }
                            Some(Err(_)) => return,
                            None => break,
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx_in.closed().await;
    });

    Ok(UdpHandle::new(tx_out, rx_in))
}
