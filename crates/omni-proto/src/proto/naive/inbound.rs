use omni_domain::stream::BoxProxyStream;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn serve<S>(
    stream: S,
    on_connect: impl Fn(BoxProxyStream, String) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>> + Send + Sync + 'static + Clone,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    omni_transport::h2::serve_connect(stream, on_connect).await
}
