use std::io;
use tokio::net::{TcpListener, TcpStream};

pub async fn bind_listener(addr: &str) -> io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

pub fn set_stream_opts(stream: &TcpStream, keepalive_secs: u32, nodelay: bool) {
    let _ = stream.set_nodelay(nodelay);
    let _ = crate::ktls::apply_keepalive(stream, keepalive_secs);
}
