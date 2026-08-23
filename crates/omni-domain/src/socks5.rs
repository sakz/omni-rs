use crate::stream::ProxyTarget;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VER: u8 = 0x05;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    NoAuth = 0x00,
    GssApi = 0x01,
    UserPass = 0x02,
    NoAcceptable = 0xFF,
}

impl Method {
    pub fn from_u8(b: u8) -> Option<Method> {
        match b {
            0x00 => Some(Method::NoAuth),
            0x01 => Some(Method::GssApi),
            0x02 => Some(Method::UserPass),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl Command {
    pub fn from_u8(b: u8) -> Option<Command> {
        match b {
            0x01 => Some(Command::Connect),
            0x02 => Some(Command::Bind),
            0x03 => Some(Command::UdpAssociate),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            Command::Connect => 0x01,
            Command::Bind => 0x02,
            Command::UdpAssociate => 0x03,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Addr {
    V4([u8; 4], u16),
    V6([u8; 16], u16),
    Domain(String, u16),
}

pub const MAX_DOMAIN_LEN: usize = 255;

impl Socks5Addr {
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            Socks5Addr::V4(ip, port) => {
                buf.push(0x01);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Socks5Addr::V6(ip, port) => {
                buf.push(0x04);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Socks5Addr::Domain(d, port) => {
                buf.push(0x03);
                buf.push(d.len() as u8);
                buf.extend_from_slice(d.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    pub fn decode(buf: &[u8]) -> Result<(Socks5Addr, usize), &'static str> {
        if buf.len() < 2 {
            return Err("socks5: empty address buffer");
        }
        let (atyp, rest) = (buf[0], &buf[1..]);
        match atyp {
            0x01 => {
                if rest.len() < 4 {
                    return Err("socks5: IPv4 address too short");
                }
                let ip = [rest[0], rest[1], rest[2], rest[3]];
                if rest.len() < 6 {
                    return Err("socks5: IPv4 address too short");
                }
                let port = u16::from_be_bytes([rest[4], rest[5]]);
                Ok((Socks5Addr::V4(ip, port), 7))
            }
            0x03 => {
                if rest.is_empty() {
                    return Err("socks5: domain length missing");
                }
                let dl = rest[0] as usize;
                if dl == 0 || dl > MAX_DOMAIN_LEN {
                    return Err("socks5: domain too short");
                }
                if rest.len() < 1 + dl + 2 {
                    return Err("socks5: domain too short");
                }
                let d = std::str::from_utf8(&rest[1..1 + dl])
                    .map_err(|_| "socks5: domain not UTF-8")?;
                let port = u16::from_be_bytes([rest[1 + dl], rest[2 + dl]]);
                Ok((Socks5Addr::Domain(d.to_string(), port), 1 + 1 + dl + 2))
            }
            0x04 => {
                if rest.len() < 16 + 2 {
                    return Err("socks5: IPv6 address too short");
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&rest[..16]);
                let port = u16::from_be_bytes([rest[16], rest[17]]);
                Ok((Socks5Addr::V6(ip, port), 19))
            }
            _ => Err("socks5: unknown address type"),
        }
    }

    pub fn to_proxy_target(&self) -> crate::stream::ProxyTarget {
        use std::net::SocketAddr;
        match self {
            Socks5Addr::V4(ip, p) => {
                ProxyTarget::Tcp(SocketAddr::new(std::net::IpAddr::V4((*ip).into()), *p))
            }
            Socks5Addr::V6(ip, p) => {
                ProxyTarget::Tcp(SocketAddr::new(std::net::IpAddr::V6((*ip).into()), *p))
            }
            Socks5Addr::Domain(d, p) => ProxyTarget::Domain(d.clone(), *p),
        }
    }

    pub fn from_proxy_target(t: &crate::stream::ProxyTarget) -> Socks5Addr {
        match t {
            crate::stream::ProxyTarget::Tcp(a) => match a.ip() {
                std::net::IpAddr::V4(ip) => Socks5Addr::V4(ip.octets(), a.port()),
                std::net::IpAddr::V6(ip) => Socks5Addr::V6(ip.octets(), a.port()),
            },
            crate::stream::ProxyTarget::Domain(h, p) => Socks5Addr::Domain(h.clone(), *p),
        }
    }
}

pub async fn read_exact<S: AsyncRead + Unpin>(s: &mut S, n: usize) -> std::io::Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    s.read_exact(&mut v).await?;
    Ok(v)
}

pub async fn read_greeting<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<Vec<u8>> {
    let first = read_exact(s, 2).await?;
    if first[0] != VER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "socks5: unsupported version",
        ));
    }
    let nmethods = first[1] as usize;
    if nmethods == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "socks5: no methods offered",
        ));
    }
    read_exact(s, nmethods).await
}

pub async fn write_method_choice<S: AsyncWrite + Unpin>(
    s: &mut S,
    m: Method,
) -> std::io::Result<()> {
    s.write_all(&[VER, m as u8]).await
}

pub async fn read_request<S: AsyncRead + Unpin>(
    s: &mut S,
) -> std::io::Result<(Command, Socks5Addr)> {
    let head = read_exact(s, 4).await?;
    if head[0] != VER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "socks5: unsupported version",
        ));
    }
    let cmd = Command::from_u8(head[1]).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "socks5: unknown command")
    })?;
    let atyp = head[3];
    let addr = match atyp {
        0x01 => {
            let b = read_exact(s, 6).await?;
            let ip = [b[0], b[1], b[2], b[3]];
            Socks5Addr::V4(ip, u16::from_be_bytes([b[4], b[5]]))
        }
        0x03 => {
            let dl = read_exact(s, 1).await?[0] as usize;
            let b = read_exact(s, dl + 2).await?;
            let host = String::from_utf8_lossy(&b[..dl]).to_string();
            Socks5Addr::Domain(host, u16::from_be_bytes([b[dl], b[dl + 1]]))
        }
        0x04 => {
            let b = read_exact(s, 18).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[..16]);
            Socks5Addr::V6(ip, u16::from_be_bytes([b[16], b[17]]))
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "socks5: unknown address type",
            ))
        }
    };
    Ok((cmd, addr))
}

pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

pub async fn write_reply<S: AsyncWrite + Unpin>(
    s: &mut S,
    rep: u8,
    bind: Option<&Socks5Addr>,
) -> std::io::Result<()> {
    let mut out = vec![VER, rep, 0x00];
    match bind {
        Some(a) => a.encode_into(&mut out),
        None => out.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0]),
    }
    s.write_all(&out).await
}

pub fn io_err(msg: &'static str) -> std::io::Error {
    std::io::Error::other(msg)
}

#[cfg(test)]
mod tests {
    use super::Socks5Addr;

    #[test]
    fn addr_roundtrip_v4() {
        let mut b = Vec::new();
        Socks5Addr::V4([10, 0, 0, 1], 443).encode_into(&mut b);
        assert_eq!(b.len(), 7);
        let (a, used) = Socks5Addr::decode(&b).unwrap();
        assert_eq!(used, 7);
        assert_eq!(a, Socks5Addr::V4([10, 0, 0, 1], 443));
    }

    #[test]
    fn addr_roundtrip_domain() {
        let mut b = Vec::new();
        Socks5Addr::Domain("example.com".into(), 8080).encode_into(&mut b);
        assert_eq!(b.len(), 1 + 1 + 11 + 2);
        let (a, _) = Socks5Addr::decode(&b).unwrap();
        assert_eq!(a, Socks5Addr::Domain("example.com".into(), 8080));
    }

    #[test]
    fn addr_rejects_short() {
        assert!(Socks5Addr::decode(&[]).is_err());
        assert!(Socks5Addr::decode(&[0x01, 1, 2]).is_err());
    }
}
