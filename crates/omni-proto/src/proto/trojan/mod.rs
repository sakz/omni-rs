pub mod inbound;
pub mod outbound;

use crate::crypto;
use omni_domain::socks5::Socks5Addr;
use omni_domain::stream::ProxyTarget;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub fn password_hash(password: &str) -> String {
    crypto::sha224_hex(password.as_bytes())
}

pub fn ioerr(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

async fn read_n<S>(stream: &mut S, n: usize) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut v = vec![0u8; n];
    stream.read_exact(&mut v).await?;
    Ok(v)
}

pub async fn read_request_head<S>(
    stream: &mut S,
    expect_hash_hex: Option<&str>,
) -> std::io::Result<(u8, ProxyTarget)>
where
    S: AsyncRead + Unpin,
{
    let head = read_n(stream, 56 + 2).await?;
    let hash = String::from_utf8_lossy(&head[..56]).to_string();
    if &head[56..58] != b"\r\n" {
        return Err(ioerr("trojan: malformed request"));
    }
    if let Some(expect) = expect_hash_hex {
        if !hash.eq_ignore_ascii_case(expect) {
            return Err(ioerr("trojan: authentication failed"));
        }
    }
    let cmd = read_n(stream, 1).await?[0];
    let addr = read_addr(stream).await?;
    let tail = read_n(stream, 2).await?;
    if &tail != b"\r\n" {
        return Err(ioerr("trojan: malformed request tail"));
    }
    Ok((cmd, addr.to_proxy_target()))
}

async fn read_addr<S>(stream: &mut S) -> std::io::Result<Socks5Addr>
where
    S: AsyncRead + Unpin,
{
    let atyp = read_n(stream, 1).await?[0];
    match atyp {
        0x01 => {
            let b = read_n(stream, 6).await?;
            let ip = [b[0], b[1], b[2], b[3]];
            let port = u16::from_be_bytes([b[4], b[5]]);
            Ok(Socks5Addr::V4(ip, port))
        }
        0x03 => {
            let dl = read_n(stream, 1).await?[0] as usize;
            let b = read_n(stream, dl + 2).await?;
            let host = String::from_utf8_lossy(&b[..dl]).to_string();
            let port = u16::from_be_bytes([b[dl], b[dl + 1]]);
            Ok(Socks5Addr::Domain(host, port))
        }
        0x04 => {
            let b = read_n(stream, 18).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[..16]);
            let port = u16::from_be_bytes([b[16], b[17]]);
            Ok(Socks5Addr::V6(ip, port))
        }
        _ => Err(ioerr("trojan: unknown address type")),
    }
}

pub fn encode_request_head(cmd: u8, target: &ProxyTarget, hash_hex: &str) -> Vec<u8> {
    let addr = Socks5Addr::from_proxy_target(target);
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(hash_hex.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.push(cmd);
    addr.encode_into(&mut out);
    out.extend_from_slice(b"\r\n");
    out
}

pub mod udp_frame {
    use super::*;
    use bytes::Bytes;

    pub fn encode(addr: &Socks5Addr, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 300);
        addr.encode_into(&mut out);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(payload);
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

        pub fn next_packet(&mut self) -> Option<std::io::Result<(Socks5Addr, Bytes)>> {
            loop {
                if self.buf.is_empty() && self.eof {
                    return None;
                }
                match try_parse(&self.buf) {
                    TryParse::Need => {
                        if self.eof {
                            return Some(Err(ioerr("trojan: truncated UDP frame")));
                        }
                        return None;
                    }
                    TryParse::Bad => {
                        return Some(Err(ioerr("trojan: invalid UDP frame")));
                    }
                    TryParse::Ok((addr, payload), used) => {
                        let _ = self.buf.split_to(used);
                        return Some(Ok((addr, payload)));
                    }
                }
            }
        }
    }

    enum TryParse {
        Need,
        Bad,
        Ok((Socks5Addr, Bytes), usize),
    }

    fn try_parse(buf: &[u8]) -> TryParse {
        let (addr, used) = match Socks5Addr::decode(buf) {
            Ok(x) => x,
            Err(_) => {
                if buf.len() < 260 {
                    return TryParse::Need;
                }
                return TryParse::Bad;
            }
        };
        let rest = &buf[used..];
        if rest.len() < 2 {
            return TryParse::Need;
        }
        if &rest[..2] != b"\r\n" {
            return TryParse::Bad;
        }
        if rest.len() < 4 {
            return TryParse::Need;
        }
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.len() < 6 + len {
            return TryParse::Need;
        }
        let payload = Bytes::copy_from_slice(&rest[6..6 + len]);
        TryParse::Ok((addr, payload), used + 6 + len)
    }
}
