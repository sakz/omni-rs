use super::frame::HEADER_SIZE;
use super::session::{read_loop, spawn_writer, AnytlsStream, Registry};
use crate::crypto;
use omni_domain::stream::ProxyStream;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

pub struct ServerConfig {
    pub password: String,
}

fn io_err(msg: &str) -> io::Error {
    io::Error::other(msg.to_string())
}

pub type RouteCallback =
    Arc<dyn Fn(PrefixedStream, omni_domain::stream::ProxyTarget) + Send + Sync>;

async fn read_auth<S>(stream: &mut S, password: &str) -> io::Result<()>
where
    S: AsyncReadExt + Unpin,
{
    let mut token = [0u8; 32];
    stream.read_exact(&mut token).await?;
    let mut pad_len_b = [0u8; 2];
    stream.read_exact(&mut pad_len_b).await?;
    let pad_len = u16::from_be_bytes(pad_len_b) as usize;
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        stream.read_exact(&mut pad).await?;
    }

    let expect = auth_digest(password);
    if token != expect {
        return Err(io_err("anytls: authentication failed"));
    }
    Ok(())
}

fn auth_digest(password: &str) -> [u8; 32] {
    crypto::sha256_digest(password.as_bytes())
}

pub async fn accept_session<S>(
    mut tls_stream: S,
    cfg: &ServerConfig,
    route: RouteCallback,
) -> io::Result<()>
where
    S: ProxyStream + 'static,
{
    read_auth(&mut tls_stream, &cfg.password).await?;
    tracing::info!(target: "internal.pipeline", "anytls auth ok");

    let (rh, wh) = tokio::io::split(tls_stream);
    let (writer_tx, _close_tx, _task) = spawn_writer(wh).await;

    let registry: Registry = Arc::new(Mutex::new(Default::default()));

    let on_stream = move |mut stream: AnytlsStream| {
        let route = route.clone();
        tokio::spawn(async move {
            let mut buf: Vec<u8> = Vec::with_capacity(280);
            let mut tmp = [0u8; 512];
            loop {
                if let Ok((addr, used)) = omni_domain::socks5::Socks5Addr::decode(&buf) {
                    let target = addr.to_proxy_target();
                    let leftover = buf[used..].to_vec();
                    let stream = PrefixedStream {
                        inner: stream,
                        prefix: Some(leftover),
                    };
                    tracing::debug!(target: "internal.pipeline", "anytls stream target={} sid={}", target, stream.inner.sid);
                    route(stream, target);
                    return;
                }
                if buf.len() > 4096 {
                    return;
                }
                let n = match stream.read(&mut tmp).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
        });
    };

    read_loop(rh, registry, writer_tx, true, on_stream).await
}

pub struct PrefixedStream {
    pub inner: AnytlsStream,
    pub prefix: Option<Vec<u8>>,
}

impl tokio::io::AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::Poll;
        if self.prefix.is_some() && !self.prefix.as_ref().unwrap().is_empty() {
            let pre = self.prefix.as_mut().unwrap();
            let n = out.remaining().min(pre.len());
            out.put_slice(&pre[..n]);
            pre.drain(..n);
            return Poll::Ready(Ok(()));
        }
        self.prefix = None;
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl tokio::io::AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Unpin for PrefixedStream {}
const _: usize = HEADER_SIZE;
