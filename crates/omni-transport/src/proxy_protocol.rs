use bytes::BytesMut;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocolHeader {
    V1 {
        src: SocketAddr,
        dst: SocketAddr,
    },
    V2 {
        src: SocketAddr,
        dst: SocketAddr,
    },
}

fn ioerr(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

pub async fn read_header_from<S>(stream: &mut S) -> std::io::Result<ProxyProtocolHeader>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(128);
    let mut tmp = [0u8; 256];
    loop {
        if buf.len() >= 16 {
            if let Ok((h, used)) = parse(&buf) {
                let _ = &buf[used..];
                return Ok(h);
            }
        }
        if buf.len() > 1024 {
            return Err(ioerr("proxy_protocol: header too large"));
        }
        match tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut tmp)).await
        {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return Err(ioerr("proxy_protocol: missing header")),
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

pub fn parse(buf: &[u8]) -> std::io::Result<(ProxyProtocolHeader, usize)> {
    if buf.len() >= 6 && &buf[..5] == b"PROXY" {
        let end = buf
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| ioerr("proxy_protocol: incomplete v1 header"))?
            + 2;
        let line = std::str::from_utf8(&buf[..end - 2])
            .map_err(|_| ioerr("proxy_protocol: invalid v1 header"))?;
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() != 6 || parts[0] != "PROXY" {
            return Err(ioerr("proxy_protocol: malformed v1 header"));
        }
        let parse_ip = |s: &str| -> std::io::Result<IpAddr> {
            s.parse::<IpAddr>()
                .map_err(|_| ioerr("proxy_protocol: bad address in v1 header"))
        };
        let src = SocketAddr::new(parse_ip(parts[2])?, parts[4].parse().map_err(|_| ioerr("proxy_protocol: bad port"))?);
        let dst = SocketAddr::new(parse_ip(parts[3])?, parts[5].parse().map_err(|_| ioerr("proxy_protocol: bad port"))?);
        Ok((ProxyProtocolHeader::V1 { src, dst }, end))
    } else if buf.len() >= 16 && buf[0] == 0x0D && buf[1] == 0x0A && buf[2] == 0x0D && buf[3] == 0x0A && buf[4] == 0x00 {
        let ver_cmd = buf[12];
        let fam = buf[13];
        if ver_cmd >> 4 != 2 {
            return Err(ioerr("proxy_protocol: unsupported v2 version"));
        }
        let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
        let total = 16 + len;
        if buf.len() < total {
            return Err(ioerr("proxy_protocol: incomplete v2 header"));
        }
        let addr_len = match fam {
            0x11 | 0x12 => 16,
            0x21 | 0x22 => 36,
            _ => 0,
        };
        if addr_len == 0 {
            return Ok((
                ProxyProtocolHeader::V2 {
                    src: "0.0.0.0:0".parse().unwrap(),
                    dst: "0.0.0.0:0".parse().unwrap(),
                },
                total,
            ));
        }
        let p = &buf[16..];
        match addr_len {
            16 => {
                let src = SocketAddr::new(
                    IpAddr::V4([p[0], p[1], p[2], p[3]].into()),
                    u16::from_be_bytes([p[8], p[9]]),
                );
                let dst = SocketAddr::new(
                    IpAddr::V4([p[4], p[5], p[6], p[7]].into()),
                    u16::from_be_bytes([p[10], p[11]]),
                );
                Ok((ProxyProtocolHeader::V2 { src, dst }, total))
            }
            _ => Err(ioerr("proxy_protocol: ipv6 v2 not parsed")),
        }
    } else {
        Err(ioerr("proxy_protocol: signature mismatch"))
    }
}

pub fn encode_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut out = BytesMut::new();
    out.extend_from_slice(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]);
    out.extend_from_slice(&[0x21]);
    let (fam, mut abuf) = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut a = Vec::with_capacity(12);
            a.extend_from_slice(&s.octets());
            a.extend_from_slice(&d.octets());
            (0x11u8, a)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut a = Vec::with_capacity(36);
            a.extend_from_slice(&s.octets());
            a.extend_from_slice(&d.octets());
            (0x21u8, a)
        }
        _ => (0x11u8, vec![0u8; 12]),
    };
    out.extend_from_slice(&[fam]);
    let len = abuf.len() + 4;
    out.extend_from_slice(&(len as u16).to_be_bytes());
    abuf.extend_from_slice(&src.port().to_be_bytes());
    abuf.extend_from_slice(&dst.port().to_be_bytes());
    out.extend_from_slice(&abuf);
    out.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn v2_encode_parse() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 5555);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80);
        let buf = encode_v2(src, dst);
        let (h, used) = parse(&buf).unwrap();
        assert_eq!(used, buf.len());
        match h {
            ProxyProtocolHeader::V2 { src: s, dst: d } => {
                assert_eq!(s, src);
                assert_eq!(d, dst);
            }
            _ => panic!("wrong version"),
        }
    }

    #[test]
    fn v1_parse() {
        let line = b"PROXY TCP4 1.2.3.4 5.6.7.8 1111 2222\r\n";
        let (h, used) = parse(line).unwrap();
        assert_eq!(used, line.len());
        match h {
            ProxyProtocolHeader::V1 { src, dst } => {
                assert_eq!(src.to_string(), "1.2.3.4:1111");
                assert_eq!(dst.to_string(), "5.6.7.8:2222");
            }
            _ => panic!("wrong version"),
        }
    }
}
