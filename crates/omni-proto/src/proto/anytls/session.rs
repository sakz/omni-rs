use super::frame::{
    try_decode, DecodeOutcome, Frame, CMD_ALERT, CMD_FIN, CMD_PSH, CMD_SETTINGS, CMD_SYN, CMD_WASTE,
};
use bytes::Bytes;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

const STREAM_BUF: usize = 256;
const FRAME_BUF: usize = 256;
pub const MAX_PAYLOAD: usize = 16384;

#[derive(Debug)]
pub enum StreamMsg {
    Data(Bytes),
    Eof,
}

pub type Registry = Arc<tokio::sync::Mutex<HashMap<u32, mpsc::Sender<StreamMsg>>>>;

pub struct AnytlsStream {
    pub sid: u32,
    writer_tx: mpsc::Sender<Frame>,
    rx: mpsc::Receiver<StreamMsg>,
    leftover: Option<Bytes>,
    fin_sent: bool,
    eof: bool,
}

impl AnytlsStream {
    pub fn new(sid: u32, writer_tx: mpsc::Sender<Frame>, rx: mpsc::Receiver<StreamMsg>) -> Self {
        AnytlsStream {
            sid,
            writer_tx,
            rx,
            leftover: None,
            fin_sent: false,
            eof: false,
        }
    }

    fn send_psh(&self, data: Bytes) -> io::Result<()> {
        if self.fin_sent {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "anytls: closed"));
        }
        self.writer_tx
            .try_send(Frame::with_data(CMD_PSH, self.sid, data))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "anytls: session closed"))
    }

    pub fn send_fin(&mut self) {
        if !self.fin_sent {
            self.fin_sent = true;
            let _ = self.writer_tx.try_send(Frame::new(CMD_FIN, self.sid));
        }
    }
}

impl AsyncRead for AnytlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::Poll;
        if let Some(data) = self.leftover.take() {
            let capped = out.remaining().min(data.len());
            out.put_slice(&data[..capped]);
            if capped < data.len() {
                self.leftover = Some(data.slice(capped..));
            }
            return Poll::Ready(Ok(()));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(StreamMsg::Data(data))) => {
                if data.is_empty() {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                let capped = out.remaining().min(data.len());
                out.put_slice(&data[..capped]);
                if capped < data.len() {
                    self.leftover = Some(data.slice(capped..));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(StreamMsg::Eof)) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnytlsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        for chunk in buf.chunks(MAX_PAYLOAD) {
            self.send_psh(Bytes::copy_from_slice(chunk))?;
        }
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.send_fin();
        std::task::Poll::Ready(Ok(()))
    }
}

pub async fn spawn_writer<W>(
    mut write_half: W,
) -> (
    mpsc::Sender<Frame>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Frame>(FRAME_BUF);
    let (close_tx, _close_rx) = tokio::sync::oneshot::channel::<()>();
    use tokio::io::AsyncWriteExt;
    let task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(frame) => {
                    tracing::debug!(
                        target: "internal.pipeline",
                        "anytls writer sending cmd={} sid={} len={}",
                        frame.cmd,
                        frame.sid,
                        frame.data.len() + 7
                    );
                    let encoded = frame.encode();
                    if AsyncWriteExt::write_all(&mut write_half, &encoded)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                None => break,
            }
        }
        let _ = write_half.shutdown().await;
    });
    (tx, close_tx, task)
}

pub async fn read_loop<S>(
    mut read_half: S,
    registry: Registry,
    writer_tx: mpsc::Sender<Frame>,
    is_server: bool,
    on_new_stream: impl Fn(AnytlsStream) + Send + 'static,
) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(16384);
    let mut tmp = vec![0u8; MAX_PAYLOAD];
    let mut got_settings = false;

    loop {
        match try_decode(&buf)? {
            DecodeOutcome::Frame(frame, consumed) => {
                tracing::debug!(target: "internal.pipeline", "anytls frame cmd={} sid={} len={}", frame.cmd, frame.sid, frame.data.len());
                buf.drain(..consumed);

                match frame.cmd {
                    CMD_WASTE => {}
                    CMD_SETTINGS => {
                        got_settings = true;
                    }
                    CMD_SYN => {
                        if is_server && !got_settings {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "anytls: SYN before settings",
                            ));
                        }
                        let (msg_tx, msg_rx) = mpsc::channel(STREAM_BUF);
                        registry.lock().await.insert(frame.sid, msg_tx);
                        let stream = AnytlsStream {
                            sid: frame.sid,
                            writer_tx: writer_tx.clone(),
                            rx: msg_rx,
                            leftover: None,
                            fin_sent: false,
                            eof: false,
                        };
                        on_new_stream(stream);
                    }
                    CMD_PSH => {
                        let tx = registry.lock().await.get(&frame.sid).cloned();
                        if let Some(tx) = tx {
                            let msg = if frame.data.is_empty() {
                                StreamMsg::Eof
                            } else {
                                StreamMsg::Data(frame.data)
                            };
                            let _ = tx.send(msg).await;
                        }
                    }
                    CMD_FIN => {
                        let removed = registry.lock().await.remove(&frame.sid);
                        if let Some(tx) = removed {
                            let _ = tx.send(StreamMsg::Eof).await;
                        }
                    }
                    CMD_ALERT => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "anytls: alert from peer: {}",
                                String::from_utf8_lossy(&frame.data)
                            ),
                        ));
                    }
                    _ => {}
                }
            }
            DecodeOutcome::NeedMore => {
                use tokio::io::AsyncReadExt;
                let n = AsyncReadExt::read(&mut read_half, &mut tmp).await?;
                if n == 0 {
                    if !buf.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "anytls: truncated frame",
                        ));
                    }
                    return Ok(());
                }
                buf.extend_from_slice(&tmp[..n]);
            }
        }
    }
}
