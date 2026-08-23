pub mod encryption;
pub mod inbound;
pub mod outbound;
pub mod vision;
pub mod xudp;

use omni_domain::socks5::Socks5Addr;
use omni_domain::stream::ProxyTarget;

pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x02;
pub const CMD_MUX: u8 = 0x03;

pub const ATYP_V4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x02;
pub const ATYP_V6: u8 = 0x03;

pub fn ioerr(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

pub fn encode_request(uuid_bytes: &[u8; 16], cmd: u8, target: &ProxyTarget, addons: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + addons.len());
    out.push(0);
    out.extend_from_slice(uuid_bytes);
    out.push(addons.len() as u8);
    out.extend_from_slice(addons);
    out.push(cmd);
    out.extend_from_slice(&target.port().to_be_bytes());
    match target {
        ProxyTarget::Tcp(a) => match a.ip() {
            std::net::IpAddr::V4(ip) => {
                out.push(ATYP_V4);
                out.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                out.push(ATYP_V6);
                out.extend_from_slice(&ip.octets());
            }
        },
        ProxyTarget::Domain(h, _) => {
            out.push(ATYP_DOMAIN);
            out.push(h.len() as u8);
            out.extend_from_slice(h.as_bytes());
        }
    }
    out
}

pub async fn read_request_head<S>(
    stream: &mut S,
) -> std::io::Result<([u8; 16], u8, ProxyTarget)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut ver = [0u8; 1];
    tracing::debug!(target: "internal.pipeline", "vless read: waiting ver");
    read_full(stream, &mut ver).await?;
    tracing::debug!(target: "internal.pipeline", "vless read: ver={}", ver[0]);
    if ver[0] != 0 {
        return Err(ioerr("vless: unsupported version"));
    }
    let mut uuid = [0u8; 16];
    read_full(stream, &mut uuid).await?;
    tracing::debug!(target: "internal.pipeline", "vless read: uuid ok");
    let mut alen = [0u8; 1];
    tracing::debug!(target: "internal.pipeline", "vless read: waiting alen");
    read_full(stream, &mut alen).await?;
    tracing::debug!(target: "internal.pipeline", "vless read: alen={}", alen[0]);
    if alen[0] > 0 {
        let mut addons = vec![0u8; alen[0] as usize];
        read_full(stream, &mut addons).await?;
        if !addons.is_empty() && !addons.is_empty() && addons.first() == Some(&0x01) {
            return Err(ioerr("vless: flow addon requires vision support"));
        }
    }
    let mut cmd_b = [0u8; 1];
    read_full(stream, &mut cmd_b).await?;
    tracing::debug!(target: "internal.pipeline", "vless read: cmd={}", cmd_b[0]);
    let cmd = cmd_b[0];
    let mut portb = [0u8; 2];
    read_full(stream, &mut portb).await?;
    tracing::debug!(target: "internal.pipeline", "vless read: port ok");
    let port = u16::from_be_bytes(portb);
    let mut atyp = [0u8; 1];
    read_full(stream, &mut atyp).await?;
    let addr = match atyp[0] {
        ATYP_V4 => {
            let mut b = [0u8; 4];
            read_full(stream, &mut b).await?;
            Socks5Addr::V4(b, port)
        }
        ATYP_DOMAIN => {
            let mut dl = [0u8; 1];
            read_full(stream, &mut dl).await?;
            let mut rest = vec![0u8; dl[0] as usize];
            read_full(stream, &mut rest).await?;
            let host = String::from_utf8_lossy(&rest).to_string();
            Socks5Addr::Domain(host, port)
        }
        ATYP_V6 => {
            let mut ip = [0u8; 16];
            read_full(stream, &mut ip).await?;
            Socks5Addr::V6(ip, port)
        }
        _ => return Err(ioerr("vless: unknown address type")),
    };
    tracing::debug!(target: "internal.pipeline", "vless head fully parsed port={} atyp_done", port);
    Ok((uuid, cmd, addr.to_proxy_target().with_port(port)))
}

pub async fn write_response<S>(stream: &mut S) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    stream.write_all(&[0x00, 0x00]).await
}

pub async fn read_response<S>(stream: &mut S) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut head = [0u8; 2];
    read_full(stream, &mut head).await?;
    if head[0] != 0x00 {
        return Err(ioerr("vless: bad response version"));
    }
    let alen = head[1] as usize;
    if alen > 0 {
        let mut buf = vec![0u8; alen];
        read_full(stream, &mut buf).await?;
    }
    Ok(())
}

async fn read_full<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut [u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    tracing::debug!(target: "internal.pipeline", "vless read_full want={}", buf.len());
    let r = s.read_exact(buf).await.map(|_| ());
    match &r {
        Ok(()) => tracing::debug!(target: "internal.pipeline", "vless read_full got={} hex={}", buf.len(), crate::crypto::hex_encode(buf)),
        Err(e) => tracing::debug!(target: "internal.pipeline", "vless read_full err={}", e),
    }
    r
}

pub mod udp_frame {
    use super::*;
    use bytes::Bytes;

    pub fn encode(target: &ProxyTarget, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 300);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        match target {
            ProxyTarget::Tcp(a) => match a.ip() {
                std::net::IpAddr::V4(ip) => {
                    out.push(ATYP_V4);
                    out.extend_from_slice(&ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    out.push(ATYP_V6);
                    out.extend_from_slice(&ip.octets());
                }
            },
            ProxyTarget::Domain(h, _) => {
                out.push(ATYP_DOMAIN);
                out.push(h.len() as u8);
                out.extend_from_slice(h.as_bytes());
            }
        }
        out.extend_from_slice(&target.port().to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    #[derive(Default)]
    pub struct Decoder {
        buf: bytes::BytesMut,
        eof: bool,
    }

    impl Decoder {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn feed(&mut self, data: &[u8]) {
            self.buf.extend_from_slice(data);
        }

        pub fn mark_eof(&mut self) {
            self.eof = true;
        }

        pub fn next_packet(&mut self) -> Option<std::io::Result<(ProxyTarget, Bytes)>> {
            loop {
                if self.buf.len() < 3 {
                    if self.eof {
                        return None;
                    }
                    return None;
                }
                let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                let need = 2 + frame_addr_len(&self.buf[2..]) + 2 + len;
                if self.buf.len() < need {
                    if self.eof {
                        return Some(Err(ioerr("vless: truncated UDP packet")));
                    }
                    return None;
                }
                let frame = self.buf.split_to(need);
                let mut off = 2;
                let atyp = frame[off];
                off += 1;
                let target = match atyp {
                    ATYP_V4 => {
                        let ip = [frame[off], frame[off + 1], frame[off + 2], frame[off + 3]];
                        let p = u16::from_be_bytes([frame[off + 4], frame[off + 5]]);
                        off += 6;
                        ProxyTarget::Tcp(std::net::SocketAddr::new(
                            std::net::IpAddr::V4(ip.into()),
                            p,
                        ))
                    }
                    ATYP_DOMAIN => {
                        let dl = frame[off] as usize;
                        let host =
                            String::from_utf8_lossy(&frame[off + 1..off + 1 + dl]).to_string();
                        let p = u16::from_be_bytes([frame[off + 1 + dl], frame[off + 2 + dl]]);
                        off += 1 + dl + 2;
                        ProxyTarget::Domain(host, p)
                    }
                    ATYP_V6 => {
                        let mut ip = [0u8; 16];
                        ip.copy_from_slice(&frame[off..off + 16]);
                        let p = u16::from_be_bytes([frame[off + 16], frame[off + 17]]);
                        off += 18;
                        ProxyTarget::Tcp(std::net::SocketAddr::new(
                            std::net::IpAddr::V6(ip.into()),
                            p,
                        ))
                    }
                    _ => {
                        return Some(Err(ioerr("vless: unknown UDP address type")));
                    }
                };
                let data = Bytes::copy_from_slice(&frame[off..]);
                return Some(Ok((target, data)));
            }
        }
    }

    fn frame_addr_len(buf: &[u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        match buf[0] {
            ATYP_V4 => 7,
            ATYP_V6 => 19,
            ATYP_DOMAIN => {
                if buf.len() > 1 {
                    1 + 1 + buf[1] as usize + 2
                } else {
                    2
                }
            }
            _ => 1,
        }
    }
}
