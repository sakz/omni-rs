use omni_transport::routing as rt;

pub struct SniffOutcome {
    pub host: Option<String>,
    pub protocol: &'static str,
    pub consumed: Vec<u8>,
}

pub async fn inspect_stream<S>(stream: &mut S, timeout: std::time::Duration) -> SniffOutcome
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];

    loop {
        if let Some(out) = try_classify(&buf) {
            return out;
        }
        match tokio::time::timeout(timeout, read_once(stream, &mut tmp)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
        }
        if buf.len() > 8 * 1024 {
            break;
        }
    }

    tracing::debug!(target: "internal.inspector", "sniff done host=None bytes={}", buf.len());
    SniffOutcome {
        host: None,
        protocol: "unknown",
        consumed: buf,
    }
}

fn try_classify(buf: &[u8]) -> Option<SniffOutcome> {
    if !buf.is_empty() {
        tracing::debug!(target: "internal.inspector", "sniff classify len={} b0={:#x}", buf.len(), buf[0]);
    }
    if buf.len() >= 5 && buf[0] == 0x16 && buf[1] == 0x03 && rt::parse_sni(buf).is_some() {
        return Some(SniffOutcome {
            host: rt::parse_sni(buf),
            protocol: "tls",
            consumed: buf.to_vec(),
        });
    }
    if rt::looks_like_http(buf) {
        if let Some(host) = rt::parse_http_host_header(buf) {
            return Some(SniffOutcome {
                host: Some(host),
                protocol: "http",
                consumed: buf.to_vec(),
            });
        }
    }
    None
}

async fn read_once<S>(s: &mut S, buf: &mut [u8]) -> std::io::Result<usize>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    s.read(buf).await
}
