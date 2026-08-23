use base64::Engine;
use omni_domain::stream::ProxyTarget;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};

pub mod sha1 {
    struct Sha1 {
        h: [u32; 5],
        len: u64,
        buf: [u8; 64],
        buflen: usize,
    }

    impl Sha1 {
        fn new() -> Self {
            Sha1 {
                h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
                len: 0,
                buf: [0; 64],
                buflen: 0,
            }
        }

        fn update(&mut self, mut data: &[u8]) {
            self.len = self.len.wrapping_add(data.len() as u64);
            while !data.is_empty() {
                let take = (64 - self.buflen).min(data.len());
                self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
                self.buflen += take;
                data = &data[take..];
                if self.buflen == 64 {
                    let b = self.buf;
                    self.block(&b);
                    self.buflen = 0;
                }
            }
        }

        fn block(&mut self, block: &[u8; 64]) {
            let mut w = [0u32; 80];
            for (i, chunk) in block.chunks_exact(4).enumerate() {
                w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let (mut a, mut b, mut c, mut d, mut e) =
                (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]);
            #[allow(clippy::needless_range_loop)]
            for i in 0..80 {
                let (f, k) = match i / 20 {
                    0 => ((b & c) | (!b & d), 0x5A827999u32),
                    1 => (b ^ c ^ d, 0x6ED9EBA1),
                    2 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                    _ => (b ^ c ^ d, 0xCA62C1D6),
                };
                let tmp = a.rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = tmp;
            }
            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
        }

        fn finalize(mut self) -> [u8; 20] {
            let bitlen = self.len.wrapping_mul(8);
            self.update(&[0x80]);
            while self.buflen != 56 {
                self.update(&[0]);
            }
            self.update(&bitlen.to_be_bytes());
            let mut out = [0u8; 20];
            for i in 0..5 {
                out[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_be_bytes());
            }
            out
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut s = Sha1::new();
        s.update(data);
        s.finalize()
    }
}

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn accept_key(key: &str) -> String {
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(sha1::digest(&input))
}

fn ioerr(msg: &'static str) -> std::io::Error {
    std::io::Error::other( msg)
}

#[derive(Debug, Clone, Default)]
pub struct WsInboundSpec {
    pub path: Option<String>,
    pub host: Option<String>,
    pub max_concurrent_streams: Option<u32>,
}

pub type WsStream<S> = tokio_tungstenite::WebSocketStream<S>;

pub async fn handshake_inbound<S>(mut raw: S, spec: &WsInboundSpec) -> std::io::Result<WsStream<S>>
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
            return Err(ioerr("ws: oversized handshake"));
        }
        let n = raw.read(&mut tmp).await?;
        if n == 0 {
            return Err(ioerr("ws: closed during handshake"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| ioerr("ws: malformed request"))?;
    let leftover = buf[header_end..].to_vec();

    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(&buf[..header_end])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("ws: {}", e)))
        .and_then(|st| {
            if st.is_complete() {
                Ok(())
            } else {
                Err(ioerr("ws: incomplete request"))
            }
        })?;

    let path = req.path.unwrap_or("/").to_string();
    if let Some(want) = &spec.path {
        if !path_matches(&path, want) {
            return Err(ioerr("ws: path mismatch"));
        }
    }
    let mut key: Option<String> = None;
    let mut upgrade_ok = false;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("sec-websocket-key") {
            key = Some(String::from_utf8_lossy(h.value).to_string());
        }
        if h.name.eq_ignore_ascii_case("upgrade") {
            upgrade_ok = String::from_utf8_lossy(h.value).eq_ignore_ascii_case("websocket");
        }
    }
    if !upgrade_ok {
        return Err(ioerr("ws: not an upgrade request"));
    }
    let key = key.ok_or_else(|| ioerr("ws: missing sec-websocket-key"))?;

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept_key(&key)
    );
    raw.write_all(response.as_bytes()).await?;
    if !leftover.is_empty() {
        raw.write_all(&leftover).await?;
    }

    Ok(tokio_tungstenite::WebSocketStream::from_raw_socket(
        raw,
        tungstenite::protocol::Role::Server,
        None::<WebSocketConfig>,
    )
    .await)
}

fn path_matches(actual: &str, want: &str) -> bool {
    let a = normalize(actual);
    let w = normalize(want);
    a == w || a.starts_with(&format!("{}/", w.trim_end_matches('/')))
}

fn normalize(p: &str) -> String {
    let p = p.split('?').next().unwrap_or(p);
    if p.is_empty() || p == "/" {
        "/".into()
    } else {
        p.trim_end_matches('/').to_string()
    }
}

#[derive(Debug, Clone, Default)]
pub struct WsOutboundSpec {
    pub host_header: Option<String>,
    pub path: Option<String>,
    pub skip_verify: bool,
}

pub async fn connect_outbound<S>(
    tcp: S,
    spec: &WsOutboundSpec,
    target: &ProxyTarget,
) -> std::io::Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let host = match &spec.host_header {
        Some(h) => h.clone(),
        None => match target {
            ProxyTarget::Domain(h, _) => h.clone(),
            ProxyTarget::Tcp(a) => a.ip().to_string(),
        },
    };
    let port_hint = match target {
        ProxyTarget::Tcp(a) => a.port(),
        ProxyTarget::Domain(_, p) => *p,
    };
    let addr_host = match target {
        ProxyTarget::Domain(h, _) => h.clone(),
        ProxyTarget::Tcp(a) => a.ip().to_string(),
    };
    let url = format!("ws://{}:{}{}", addr_host, port_hint, spec.path.clone().unwrap_or_else(|| "/".into()));
    let mut req = url.into_client_request().map_err(ws_err)?;
    req.headers_mut()
        .insert("Host", host.parse().map_err(|_| ioerr("ws: bad host header"))?);
    let (ws, _resp) = tokio_tungstenite::client_async(req, tcp)
        .await
        .map_err(ws_err)?;
    Ok(ws)
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> std::io::Error {
    std::io::Error::other( format!("ws: {}", e))
}

pub struct WsProxyStream<S> {
    inner: WsStream<S>,
    read_buf: bytes::BytesMut,
    write_buf: Vec<u8>,
}

impl<S> WsProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: WsStream<S>) -> Self {
        WsProxyStream {
            inner,
            read_buf: bytes::BytesMut::with_capacity(16 * 1024),
            write_buf: Vec::new(),
        }
    }
}

impl<S> AsyncRead for WsProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        use futures_util::Stream;
        if self.read_buf.is_empty() {
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(b) => {
                        self.read_buf.extend_from_slice(&b);
                    }
                    Message::Text(t) => {
                        self.read_buf.extend_from_slice(t.as_bytes());
                    }
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                },
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(
                        format!("ws: {}", e),
                    )))
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = out.remaining().min(self.read_buf.len());
        out.put_slice(&self.read_buf.split_to(n));
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for WsProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        use futures_util::Sink;
        if !self.write_buf.is_empty() {
            let data = std::mem::take(&mut self.write_buf);
            match Pin::new(&mut self.inner).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return ws_poll_err(e),
                Poll::Pending => {
                    self.write_buf = data;
                    return Poll::Pending;
                }
            }
            if let Err(e) = Pin::new(&mut self.inner).start_send(Message::Binary(data)) {
                return ws_poll_err(e);
            }
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => ws_poll_err(e),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        use futures_util::Sink;
        match Pin::new(&mut self.inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(
                format!("ws: {}", e),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn ws_poll_err(e: tungstenite::Error) -> Poll<std::io::Result<()>> {
    Poll::Ready(Err(std::io::Error::other(
        format!("ws: {}", e),
    )))
}
