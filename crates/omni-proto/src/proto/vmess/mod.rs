pub mod aead_header;
pub mod chunk;
pub mod inbound;
pub mod outbound;
pub mod shake;
pub mod stream;

use crate::crypto::md5;
use omni_domain::stream::ProxyTarget;

pub const VERSION: u8 = 0x01;

pub const OPT_CHUNK_STREAM: u8 = 0x01;
pub const OPT_CHUNK_MASKING: u8 = 0x04;
pub const OPT_GLOBAL_PADDING: u8 = 0x08;
pub const OPT_AUTHENTICATED_LENGTH: u8 = 0x10;

pub const SEC_LEGACY: u8 = 1;
pub const SEC_AUTO: u8 = 2;
pub const SEC_AES128_GCM: u8 = 3;
pub const SEC_CHACHA20_POLY1305: u8 = 4;
pub const SEC_NONE: u8 = 5;

pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x02;

const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_V6: u8 = 0x03;

pub fn cmd_key(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    md5::digest(&[uuid_bytes])
}

pub fn ioerr(msg: &'static str) -> std::io::Error {
    std::io::Error::other( msg)
}

pub fn encode_request_command(
    request_iv: &[u8; 16],
    request_key: &[u8; 16],
    response_v: u8,
    options: u8,
    security: u8,
    cmd: u8,
    target: &ProxyTarget,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    buf.push(VERSION);
    buf.extend_from_slice(request_iv);
    buf.extend_from_slice(request_key);
    buf.push(response_v);
    buf.push(options);

    let pad_len = 0u8;
    buf.push((pad_len << 4) | (security & 0x0F));
    buf.push(0x00);
    buf.push(cmd);
    buf.extend_from_slice(&target.port().to_be_bytes());
    match target {
        ProxyTarget::Tcp(a) => match a.ip() {
            std::net::IpAddr::V4(ip) => {
                buf.push(ATYP_V4);
                buf.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                buf.push(ATYP_V6);
                buf.extend_from_slice(&ip.octets());
            }
        },
        ProxyTarget::Domain(h, _) => {
            buf.push(ATYP_DOMAIN);
            buf.push(h.len() as u8);
            buf.extend_from_slice(h.as_bytes());
        }
    }

    let checksum = crate::crypto::fnv1a32(&buf);
    buf.extend_from_slice(&checksum.to_be_bytes());
    buf
}

#[derive(Debug)]
pub struct DecodedRequest {
    pub request_iv: [u8; 16],
    pub request_key: [u8; 16],
    pub response_v: u8,
    pub options: u8,
    pub security: u8,
    pub cmd: u8,
    pub target: ProxyTarget,
}

pub fn decode_request_command(buf: &[u8]) -> std::io::Result<DecodedRequest> {
    if buf.len() < 41 {
        return Err(ioerr("vmess: command buffer too short"));
    }
    let expected_fnv = u32::from_be_bytes([
        buf[buf.len() - 4],
        buf[buf.len() - 3],
        buf[buf.len() - 2],
        buf[buf.len() - 1],
    ]);
    if crate::crypto::fnv1a32(&buf[..buf.len() - 4]) != expected_fnv {
        return Err(ioerr("vmess: command fnv mismatch"));
    }
    if buf[0] != VERSION {
        return Err(ioerr("vmess: unsupported version"));
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&buf[1..17]);
    let mut key = [0u8; 16];
    key.copy_from_slice(&buf[17..33]);
    let response_v = buf[33];
    let options = buf[34];
    let security = buf[35] & 0x0F;
    let _pad_hint = buf[35] >> 4;
    let _reserved = buf[36];
    let cmd = buf[37];
    let port = u16::from_be_bytes([buf[38], buf[39]]);
    let atyp = buf[40];

    let mut pos = 41usize;
    let target = match atyp {
        ATYP_V4 => {
            if buf.len() < pos + 4 {
                return Err(ioerr("vmess: short ipv4"));
            }
            let ip = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
            pos += 4;
            ProxyTarget::Tcp(std::net::SocketAddr::new(
                std::net::IpAddr::V4(ip.into()),
                port,
            ))
        }
        ATYP_DOMAIN => {
            if buf.len() < pos + 1 {
                return Err(ioerr("vmess: short domain len"));
            }
            let dl = buf[pos] as usize;
            pos += 1;
            if buf.len() < pos + dl {
                return Err(ioerr("vmess: short domain"));
            }
            let host = String::from_utf8_lossy(&buf[pos..pos + dl]).to_string();
            pos += dl;
            ProxyTarget::Domain(host, port)
        }
        ATYP_V6 => {
            if buf.len() < pos + 16 {
                return Err(ioerr("vmess: short ipv6"));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[pos..pos + 16]);
            pos += 16;
            ProxyTarget::Tcp(std::net::SocketAddr::new(
                std::net::IpAddr::V6(ip.into()),
                port,
            ))
        }
        _ => return Err(ioerr("vmess: unknown address type")),
    };
    if pos != buf.len() - 4 {
        return Err(ioerr("vmess: trailing garbage in command"));
    }

    Ok(DecodedRequest {
        request_iv: iv,
        request_key: key,
        response_v,
        options,
        security,
        cmd,
        target,
    })
}
