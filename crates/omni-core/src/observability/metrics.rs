use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub async fn serve_metrics(
    port: u16,
    counters: Arc<crate::observability::Counters>,
    online: Arc<crate::observability::online_tracker::OnlineTracker>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(target: "internal.metrics", "metrics listening port={}", port);
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let c = counters.clone();
        let o = online.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 4096];
            while let Ok(n) = sock.read(&mut buf).await {
                if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let body = render(&c, &o);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}

fn render(
    c: &crate::observability::Counters,
    o: &crate::observability::online_tracker::OnlineTracker,
) -> String {
    let snap = c.snapshot();
    format!(
        "# TYPE omni_connections_total counter\nomni_connections_total {}\n# TYPE omni_bytes_total counter\nomni_bytes_total{{direction=\"up\"}} {}\nomni_bytes_total{{direction=\"down\"}} {}\n# TYPE omni_online gauge\nomni_online {}\n",
        snap.get("connections").unwrap_or(&0),
        snap.get("bytes_up").unwrap_or(&0),
        snap.get("bytes_down").unwrap_or(&0),
        o.online_total()
    )
}
