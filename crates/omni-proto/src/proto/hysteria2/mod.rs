pub mod inbound;
pub mod outbound;

pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
pub const MAX_ADDRESS_LENGTH: usize = 2048;
pub const MAX_MESSAGE_LENGTH: usize = 2048;
pub const MAX_PADDING_LENGTH: usize = 4096;
pub const AUTH_STATUS_OK: u16 = 233;

pub fn write_varint(buf: &mut Vec<u8>, mut v: u64) {
    let mut tmp = [0u8; 8];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = (v & 0xFF) as u8;
        v >>= 8;
        if v == 0 {
            break;
        }
    }
    let len = tmp.len() - i;
    let first = tmp[i];
    match len {
        1 => buf.push(first),
        2 => {
            buf.push((first & 0x3F) | 0x40);
            buf.extend_from_slice(&tmp[i + 1..]);
        }
        4 => {
            buf.push((first & 0x3F) | 0x80);
            buf.extend_from_slice(&tmp[i + 1..]);
        }
        _ => {
            buf.push((first & 0x3F) | 0xC0);
            buf.extend_from_slice(&tmp[i + 1..]);
        }
    }
}

pub fn encode_varint(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, v);
    out
}

pub fn read_varint(data: &[u8]) -> std::io::Result<(u64, usize)> {
    if data.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "hysteria2: empty varint",
        ));
    }
    let first = data[0];
    let prefix = first >> 6;
    let len = match prefix {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if data.len() < len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "hysteria2: truncated varint",
        ));
    }
    let mut value = u64::from(first & 0x3F);
    for i in 1..len {
        value = (value << 8) | u64::from(data[i]);
    }
    Ok((value, len))
}

pub fn encode_tcp_request(addr: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(addr.len() + 16);
    write_varint(&mut out, FRAME_TYPE_TCP_REQUEST);
    write_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    write_varint(&mut out, 0);
    out
}

pub fn decode_tcp_request(buf: &[u8]) -> std::io::Result<(String, &[u8])> {
    let (frame_type, n) = read_varint(buf)?;
    if frame_type != FRAME_TYPE_TCP_REQUEST {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("hysteria2: unexpected frame type {:#x}", frame_type),
        ));
    }
    let rest = &buf[n..];
    let (addr_len, n1) = read_varint(rest)?;
    if addr_len == 0 || addr_len as usize > MAX_ADDRESS_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "hysteria2: invalid address length",
        ));
    }
    let rest = &rest[n1..];
    if rest.len() < addr_len as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "hysteria2: truncated address",
        ));
    }
    let addr = String::from_utf8_lossy(&rest[..addr_len as usize]).to_string();
    let rest = &rest[addr_len as usize..];
    let (pad_len, n2) = read_varint(rest)?;
    if pad_len as usize > MAX_PADDING_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "hysteria2: padding too large",
        ));
    }
    let rest = &rest[n2..];
    if rest.len() < pad_len as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "hysteria2: truncated padding",
        ));
    }
    Ok((addr, &rest[pad_len as usize..]))
}

pub fn encode_tcp_response(ok: bool, msg: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 12);
    out.push(if ok { 0 } else { 1 });
    write_varint(&mut out, msg.len() as u64);
    out.extend_from_slice(msg.as_bytes());
    write_varint(&mut out, 0);
    out
}

pub fn decode_tcp_response(buf: &[u8]) -> std::io::Result<(bool, String)> {
    if buf.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "hysteria2: empty response",
        ));
    }
    let ok = buf[0] == 0;
    let (msg_len, n) = read_varint(&buf[1..])?;
    if msg_len as usize > MAX_MESSAGE_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "hysteria2: message too long",
        ));
    }
    let rest = &buf[1 + n..];
    if rest.len() < msg_len as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "hysteria2: truncated message",
        ));
    }
    let msg = String::from_utf8_lossy(&rest[..msg_len as usize]).to_string();
    let rest = &rest[msg_len as usize..];
    let (pad_len, n2) = read_varint(rest)?;
    if pad_len as usize > MAX_PADDING_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "hysteria2: padding too large",
        ));
    }
    let _ = n2;
    Ok((ok, msg))
}

#[derive(Debug, Clone)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub data: Vec<u8>,
}

impl UdpMessage {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.addr.len() + self.data.len());
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.packet_id.to_be_bytes());
        out.push(self.frag_id);
        out.push(self.frag_count);
        write_varint(&mut out, self.addr.len() as u64);
        out.extend_from_slice(self.addr.as_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn parse(buf: &[u8]) -> std::io::Result<UdpMessage> {
        if buf.len() < 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "hysteria2: short udp message",
            ));
        }
        let session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let packet_id = u16::from_be_bytes([buf[4], buf[5]]);
        let frag_id = buf[6];
        let frag_count = buf[7];
        let (addr_len, n) = read_varint(&buf[8..])?;
        if addr_len == 0 || addr_len as usize > MAX_MESSAGE_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "hysteria2: invalid udp address length",
            ));
        }
        let rest = &buf[8 + n..];
        if rest.len() < addr_len as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "hysteria2: truncated udp address",
            ));
        }
        let addr = String::from_utf8_lossy(&rest[..addr_len as usize]).to_string();
        let data = rest[addr_len as usize..].to_vec();
        Ok(UdpMessage {
            session_id,
            packet_id,
            frag_id,
            frag_count,
            addr,
            data,
        })
    }
}
