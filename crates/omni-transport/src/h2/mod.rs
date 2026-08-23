use bytes::Bytes;

pub type StreamFuture = Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>;
pub type StreamHandler = std::sync::Arc<dyn Fn(BoxProxyStream) -> StreamFuture + Send + Sync>;
use omni_domain::stream::{BoxProxyStream, ProxyTarget};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

pub fn ioerr(msg: &str) -> io::Error {
    io::Error::other(format!("h2: {}", msg))
}

pub struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    wbuf: Vec<u8>,
    eof: bool,
}

impl H2Stream {
    pub fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        H2Stream {
            send,
            recv,
            wbuf: Vec::new(),
            eof: false,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.wbuf.is_empty() {
            let n = out.remaining().min(self.wbuf.len());
            let data: Vec<u8> = self.wbuf.drain(..n).collect();
            out.put_slice(&data);
            return Poll::Ready(Ok(()));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let _ = self
                    .recv
                    .flow_control()
                    .release_capacity(bytes::Buf::remaining(&chunk));
                let capped = out.remaining().min(chunk.len());
                out.put_slice(&chunk[..capped]);
                if capped < chunk.len() {
                    self.wbuf.extend_from_slice(&chunk[capped..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(ioerr(&e.to_string()))),
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.send.reserve_capacity(buf.len());
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(n))) => {
                let chunk = Bytes::copy_from_slice(&buf[..n.min(buf.len())]);
                self.send
                    .send_data(chunk, false)
                    .map_err(|e| ioerr(&e.to_string()))?;
                Poll::Ready(Ok(n.min(buf.len())))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(ioerr(&e.to_string()))),
            Poll::Ready(None) => Poll::Ready(Err(ioerr("capacity closed"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

pub struct H2ClientConn<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub send_request: h2::client::SendRequest<Bytes>,
    _conn_driver: tokio::task::JoinHandle<()>,
    _marker: std::marker::PhantomData<T>,
}

pub async fn client_handshake<T>(io: T) -> io::Result<H2ClientConn<T>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, conn) = h2::client::handshake(io)
        .await
        .map_err(|e| ioerr(&e.to_string()))?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(H2ClientConn {
        send_request,
        _conn_driver: driver,
        _marker: std::marker::PhantomData,
    })
}

impl<T> H2ClientConn<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn open_proxy_stream(
        &mut self,
        method: &str,
        path: &str,
        authority: &str,
        content_type: &str,
    ) -> io::Result<H2Stream> {
        let req = http::Request::builder()
            .method(method)
            .uri(format!("https://{}{}", authority, path))
            .header("content-type", content_type)
            .header("te", "trailers")
            .body(())
            .map_err(|e| ioerr(&e.to_string()))?;

        let (resp_fut, send_stream) = self
            .send_request
            .send_request(req, false)
            .map_err(|e| ioerr(&e.to_string()))?;

        let resp = resp_fut.await.map_err(|e| ioerr(&e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ioerr(&format!("upstream responded {}", resp.status())));
        }
        Ok(H2Stream::new(send_stream, resp.into_body()))
    }
}

pub struct AcceptedH2 {
    pub target_hint: Option<String>,
    pub stream: H2Stream,
}

pub async fn serve_requests<S>(
    io: S,
    expect_path_prefix: Option<String>,
    on_stream: StreamHandler,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = h2::server::handshake(io)
        .await
        .map_err(|e| ioerr(&e.to_string()))?;

    while let Some(request) = conn.accept().await {
        let (request, mut respond) = match request {
            Ok(x) => x,
            Err(_) => return Ok(()),
        };

        let prefix = expect_path_prefix.clone();
        let on_stream = on_stream.clone();

        tokio::spawn(async move {
            let path = request.uri().path().to_string();
            if let Some(prefix) = &prefix {
                if !path.starts_with(prefix.as_str()) && normalize(&path) != normalize(prefix) {
                    let resp = http::Response::builder().status(404).body(()).unwrap();
                    let _ = respond.send_response(resp, true);
                    return;
                }
            }

            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let send = match respond.send_response(response, false) {
                Ok(s) => s,
                Err(_) => return,
            };
            let body = request.into_body();
            let stream = H2Stream::new(send, body);
            let res = on_stream(omni_domain::stream::boxed(stream)).await;
            if let Err(e) = res {
                tracing::warn!(target: "internal.pipeline", "h2 handler error: {}", e);
            }
        });
    }
    Ok(())
}

fn normalize(p: &str) -> String {
    let p = p.split('?').next().unwrap_or(p);
    if p.is_empty() || p == "/" {
        "/".into()
    } else {
        p.trim_end_matches('/').to_string()
    }
}

pub fn grpc_path_for(service_name: &str) -> String {
    format!("/{}/Tun", service_name.trim_start_matches('/'))
}

pub fn target_from_authority_or_default(
    _req: &http::Request<()>,
    default_target: &ProxyTarget,
) -> ProxyTarget {
    default_target.clone()
}

pub async fn serve_connect<S, F>(io: S, on_connect: F) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(
            BoxProxyStream,
            String,
        ) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>
        + Send
        + Sync
        + Clone
        + 'static,
{
    let mut conn = h2::server::handshake(io)
        .await
        .map_err(|e| ioerr(&e.to_string()))?;

    while let Some(request) = conn.accept().await {
        let (request, mut respond) = match request {
            Ok(x) => x,
            Err(_) => return Ok(()),
        };
        let on_connect = on_connect.clone();
        tokio::spawn(async move {
            if request.method() != http::Method::CONNECT {
                let resp = http::Response::builder().status(405).body(()).unwrap();
                let _ = respond.send_response(resp, true);
                return;
            }
            let authority = match request.uri().authority() {
                Some(a) => a.to_string(),
                None => {
                    let resp = http::Response::builder().status(400).body(()).unwrap();
                    let _ = respond.send_response(resp, true);
                    return;
                }
            };

            let response = http::Response::builder().status(200).body(()).unwrap();
            let send = match respond.send_response(response, false) {
                Ok(s) => s,
                Err(_) => return,
            };
            let body = request.into_body();
            let stream = H2Stream::new(send, body);
            let _ = on_connect(omni_domain::stream::boxed(stream), authority).await;
        });
    }
    Ok(())
}
