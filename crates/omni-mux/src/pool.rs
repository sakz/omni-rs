use super::session::{MuxKind, MuxSession};
use omni_domain::stream::BoxProxyStream;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

pub const DEFAULT_MAX_STREAMS_PER_SESSION: usize = 64;

struct Entry {
    session: MuxSession,
    active: Arc<AtomicUsize>,
}

pub type ConnectFn<'a> =
    Pin<Box<dyn Future<Output = io::Result<BoxProxyStream>> + Send + 'a>>;

pub struct MuxPool {
    kind: MuxKind,
    max_streams: usize,
    entries: Mutex<Vec<Entry>>,
}

impl MuxPool {
    pub fn new(kind: MuxKind) -> Self {
        MuxPool::with_max_streams(kind, DEFAULT_MAX_STREAMS_PER_SESSION)
    }

    pub fn with_max_streams(kind: MuxKind, max_streams: usize) -> Self {
        MuxPool {
            kind,
            max_streams,
            entries: Mutex::new(Vec::new()),
        }
    }

    pub async fn dial(
        &self,
        connect: Pin<Box<dyn Future<Output = io::Result<BoxProxyStream>> + Send + '_>>,
    ) -> io::Result<(BoxProxyStream, PoolLease)> {
        {
            let entries = self.entries.lock().await;
            for e in entries.iter() {
                if e.active.load(Ordering::Relaxed) >= self.max_streams {
                    continue;
                }
                match e.session.open_stream().await {
                    Ok(s) => {
                        e.active.fetch_add(1, Ordering::Relaxed);
                        let lease = PoolLease {
                            active: e.active.clone(),
                        };
                        return Ok((s, lease));
                    }
                    Err(_) => continue,
                }
            }
        }

        let underlay = connect.await?;
        let session = MuxSession::client(underlay, self.kind).await?;
        let stream = session.open_stream().await?;
        let active = Arc::new(AtomicUsize::new(1));
        self.entries.lock().await.push(Entry {
            session,
            active: active.clone(),
        });
        Ok((stream, PoolLease { active }))
    }

    pub async fn prune_dead(&self) -> usize {
        let mut entries = self.entries.lock().await;
        let before = entries.len();
        entries.retain(|_| true);
        before - entries.len()
    }
}

pub struct PoolLease {
    active: Arc<AtomicUsize>,
}

impl PoolLease {
    pub fn release(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct PooledStream {
    inner: BoxProxyStream,
    lease: Option<PoolLease>,
}

impl PooledStream {
    pub fn new(inner: BoxProxyStream, lease: PoolLease) -> Self {
        PooledStream {
            inner,
            lease: Some(lease),
        }
    }
}

impl AsyncRead for PooledStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl AsyncWrite for PooledStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for PooledStream {
    fn drop(&mut self) {
        if let Some(l) = &self.lease {
            l.release();
        }
    }
}
