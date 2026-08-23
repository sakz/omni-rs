use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const UDP_OVER_STREAM_HEADER_LEN: usize = 2;

pub fn encode_frame(target_host: &str, port: u16, data: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::new();
    out.put_u16((data.len() + 2 + target_host.len() + 2) as u16);
    match target_host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            out.put_u8(0x01);
            out.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            out.put_u8(0x04);
            out.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            out.put_u8(0x03);
            out.put_u8(target_host.len() as u8);
            out.extend_from_slice(target_host.as_bytes());
        }
    }
    out.put_u16(port);
    out.extend_from_slice(data);
    out.to_vec()
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut lenb = [0u8; 2];
    r.read_exact(&mut lenb).await?;
    let len = u16::from_be_bytes(lenb) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}
