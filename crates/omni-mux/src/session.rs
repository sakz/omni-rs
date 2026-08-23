use omni_domain::stream::BoxProxyStream;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxKind {
    Smux,
    Yamux,
}

impl MuxKind {
    pub fn parse(s: &str) -> Option<MuxKind> {
        match s.to_ascii_lowercase().as_str() {
            "smux" => Some(MuxKind::Smux),
            "yamux" => Some(MuxKind::Yamux),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MuxKind::Smux => "smux",
            MuxKind::Yamux => "yamux",
        }
    }
}

fn ioerr(msg: &str) -> io::Error {
    io::Error::other(format!("mux: {}", msg))
}

struct TokioToFut<T>(T);

unsafe impl<T: Send> Sync for TokioToFut<T> {}

impl<T: tokio::io::AsyncRead + Unpin + Send> futures_util::AsyncRead for TokioToFut<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut rb = tokio::io::ReadBuf::new(buf);
        match Pin::new(&mut self.0).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: tokio::io::AsyncWrite + Unpin + Send> futures_util::AsyncWrite for TokioToFut<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub(crate) struct WakeDriverIo<T> {
    pub inner: T,
    pub waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
}

fn poke_driver(waker: &Arc<std::sync::Mutex<Option<std::task::Waker>>>) {
    if let Ok(g) = waker.lock() {
        if let Some(w) = &*g {
            w.wake_by_ref();
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for WakeDriverIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for WakeDriverIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        poke_driver(&self.waker);
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_flush(cx);
        poke_driver(&self.waker);
        r
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_shutdown(cx);
        poke_driver(&self.waker);
        r
    }
}

enum Backend {
    Smux(smux::Session),
    Yamux {
        open_tx: mpsc::Sender<OpenReq>,
        accept_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<io::Result<BoxProxyStream>>>>,
    },
}

type OpenReq = tokio::sync::oneshot::Sender<io::Result<BoxProxyStream>>;

pub struct MuxSession {
    backend: Backend,
}

impl MuxSession {
    pub async fn client(stream: BoxProxyStream, kind: MuxKind) -> io::Result<MuxSession> {
        match kind {
            MuxKind::Smux => {
                let inner = smux::Session::client(stream, smux::Config::default())
                    .await
                    .map_err(|e| ioerr(&e.to_string()))?;
                Ok(MuxSession {
                    backend: Backend::Smux(inner),
                })
            }
            MuxKind::Yamux => {
                let mut cfg = yamux::Config::default();
                cfg.set_read_after_close(true);
                let conn = yamux::Connection::new(TokioToFut(stream), cfg, yamux::Mode::Client);
                let (open_tx, accept_rx) = spawn_yamux_driver(conn);
                Ok(MuxSession {
                    backend: Backend::Yamux {
                        open_tx,
                        accept_rx: Arc::new(tokio::sync::Mutex::new(accept_rx)),
                    },
                })
            }
        }
    }

    pub async fn server(stream: BoxProxyStream, kind: MuxKind) -> io::Result<MuxSession> {
        match kind {
            MuxKind::Smux => {
                let inner = smux::Session::server(stream, smux::Config::default())
                    .await
                    .map_err(|e| ioerr(&e.to_string()))?;
                Ok(MuxSession {
                    backend: Backend::Smux(inner),
                })
            }
            MuxKind::Yamux => {
                let mut cfg = yamux::Config::default();
                cfg.set_read_after_close(true);
                let conn = yamux::Connection::new(TokioToFut(stream), cfg, yamux::Mode::Server);
                let (open_tx, accept_rx) = spawn_yamux_driver(conn);
                Ok(MuxSession {
                    backend: Backend::Yamux {
                        open_tx,
                        accept_rx: Arc::new(tokio::sync::Mutex::new(accept_rx)),
                    },
                })
            }
        }
    }

    pub async fn open_stream(&self) -> io::Result<BoxProxyStream> {
        match &self.backend {
            Backend::Smux(s) => {
                let st = s.open_stream().await.map_err(|e| ioerr(&e.to_string()))?;
                Ok(omni_domain::stream::boxed(st))
            }
            Backend::Yamux { open_tx, .. } => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                open_tx
                    .clone()
                    .send(tx)
                    .await
                    .map_err(|_| ioerr("yamux driver closed"))?;
                rx.await.map_err(|_| ioerr("yamux driver dropped result"))?
            }
        }
    }

    pub async fn accept_stream(&self) -> io::Result<Option<BoxProxyStream>> {
        match &self.backend {
            Backend::Smux(s) => match s.accept_stream().await {
                Ok(st) => Ok(Some(omni_domain::stream::boxed(st))),
                Err(_) => Ok(None),
            },
            Backend::Yamux { accept_rx, .. } => {
                let mut rx = accept_rx.lock().await;
                match rx.recv().await {
                    Some(Ok(st)) => Ok(Some(st)),
                    Some(Err(e)) => Err(e),
                    None => Ok(None),
                }
            }
        }
    }
}

fn spawn_yamux_driver(
    mut conn: yamux::Connection<TokioToFut<BoxProxyStream>>,
) -> (
    mpsc::Sender<OpenReq>,
    mpsc::Receiver<io::Result<BoxProxyStream>>,
) {
    let (open_tx, mut open_rx) = mpsc::channel::<OpenReq>(64);
    let (accept_tx, accept_rx) = mpsc::channel::<io::Result<BoxProxyStream>>(64);
    let mut pending_open: Option<OpenReq> = None;
    let driver_waker: Arc<std::sync::Mutex<Option<std::task::Waker>>> =
        Arc::new(std::sync::Mutex::new(None));
    let dw = driver_waker.clone();

    tokio::spawn(std::future::poll_fn(move |cx| {
        *dw.lock().unwrap() = Some(cx.waker().clone());
        loop {
            if let Some(_cb_slot) = pending_open.as_mut() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        if let Some(cb) = pending_open.take() {
                            use tokio_util::compat::FuturesAsyncReadCompatExt;
                            let wrapped = omni_domain::stream::boxed(WakeDriverIo {
                                inner: stream.compat(),
                                waker: dw.clone(),
                            });
                            let _ = cb.send(Ok(wrapped));
                        }
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        if let Some(cb) = pending_open.take() {
                            let _ = cb.send(Err(ioerr(&e.to_string())));
                        }
                        return Poll::Ready(());
                    }
                    Poll::Pending => {}
                }
            }

            match open_rx.poll_recv(cx) {
                Poll::Ready(Some(cb)) => {
                    pending_open = Some(cb);
                    continue;
                }
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => {}
            }

            match conn.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    use tokio_util::compat::FuturesAsyncReadCompatExt;
                    let wrapped = omni_domain::stream::boxed(WakeDriverIo {
                        inner: stream.compat(),
                        waker: dw.clone(),
                    });
                    if accept_tx.try_send(Ok(wrapped)).is_err() {
                        return Poll::Ready(());
                    }
                    continue;
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => {}
            }

            return Poll::Pending;
        }
    }));

    (open_tx, accept_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn smux_roundtrip() {
        run_roundtrip(MuxKind::Smux).await;
    }

    #[tokio::test]
    async fn yamux_roundtrip() {
        run_roundtrip(MuxKind::Yamux).await;
    }

    async fn run_roundtrip(kind: MuxKind) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (ca, cb) = tokio::io::duplex(65536);
        let client = MuxSession::client(omni_domain::stream::boxed(ca), kind)
            .await
            .unwrap();
        let server = MuxSession::server(omni_domain::stream::boxed(cb), kind)
            .await
            .unwrap();

        let server_task = tokio::spawn(async move {
            if let Some(mut stream) = server.accept_stream().await.unwrap() {
                let mut buf = vec![0u8; 5];
                stream.read_exact(&mut buf).await.unwrap();
                stream.write_all(b"OK:").await.unwrap();
                stream.write_all(&buf).await.unwrap();
                stream.shutdown().await.ok();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });

        let mut st = client.open_stream().await.unwrap();
        st.write_all(b"hello").await.unwrap();
        let mut out = Vec::new();
        st.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"OK:hello", "{:?} roundtrip failed", kind);
        server_task.await.unwrap();
    }
}
