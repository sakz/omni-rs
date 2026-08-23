use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Default)]
pub struct HttpUpSpec {
    pub path: Option<String>,
    pub host: Option<String>,
}

pub async fn handshake_inbound<S>(mut raw: S, spec: &HttpUpSpec) -> std::io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(ioerr("httpup: oversized handshake"));
        }
        let n = raw.read(&mut tmp).await?;
        if n == 0 {
            return Err(ioerr("httpup: closed during handshake"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(&buf).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("httpup: {}", e))
    })?;
    if req.path.unwrap_or("").is_empty() {
        return Err(ioerr("httpup: missing path"));
    }
    if let Some(want) = &spec.path {
        let actual = req.path.unwrap_or("/");
        if normalize(actual) != normalize(want)
            && !normalize(actual)
                .starts_with(&format!("{}/", normalize(want).trim_end_matches('/')))
        {
            return Err(ioerr("httpup: path mismatch"));
        }
    }
    raw.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    )
    .await?;
    Ok(raw)
}

fn normalize(p: &str) -> String {
    let p = p.split('?').next().unwrap_or(p);
    if p.is_empty() || p == "/" {
        "/".into()
    } else {
        p.trim_end_matches('/').to_string()
    }
}

pub fn ioerr(msg: &'static str) -> std::io::Error {
    std::io::Error::other(msg)
}
