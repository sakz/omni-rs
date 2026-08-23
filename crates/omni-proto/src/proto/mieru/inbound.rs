use super::crypto;
use super::{build_metadata, parse_metadata, METADATA_SIZE, NONCE_SIZE, TAG_SIZE};
use omni_domain::stream::{BoxProxyStream, ProxyStream, ProxyTarget};
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

pub struct MieruInboundConfig {
    pub username: String,
    pub password: String,
}

fn io_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("mieru: {}", msg))
}

fn epoch_minute() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0)
}

struct SegmentState {
    key: [u8; 32],
    nonce: [u8; 24],
    seq: u32,
}

impl SegmentState {
    fn encrypt_segment(&mut self, proto_type: u8, payload: &[u8], first: bool) -> Vec<u8> {
        let em = epoch_minute() as u32;
        let metadata =
            build_metadata(proto_type, em, 0, self.seq, 0, payload.len() as u16, 0);
        let enc_meta = crypto::seal(&self.key, &self.nonce, &metadata);

        let nonce_len = if first { NONCE_SIZE } else { 0 };
        let mut out =
            Vec::with_capacity(4 + nonce_len + METADATA_SIZE + TAG_SIZE + payload.len() + TAG_SIZE);
        out.extend_from_slice(
            &(4 + nonce_len + METADATA_SIZE + TAG_SIZE + payload.len() + TAG_SIZE).to_be_bytes(),
        );
        if first {
            out.extend_from_slice(&self.nonce);
        }
        out.extend_from_slice(&enc_meta);
        if !payload.is_empty() {
            let mut n = self.nonce;
            crypto::increment_nonce(&mut n);
            out.extend_from_slice(&crypto::seal(&self.key, &n, payload));
            crypto::increment_nonce(&mut self.nonce);
        }
        crypto::increment_nonce(&mut self.nonce);
        self.seq += 1;
        out
    }
}

/// Accept a mieru session on `tls_stream`, verify credentials,
/// extract proxy target, and return (target, plaintext duplex).
///
/// Spawns background pump tasks for encryption/decryption.
pub async fn accept_session<S>(
    mut tls_stream: S,
    cfg: &MieruInboundConfig,
) -> io::Result<(ProxyTarget, BoxProxyStream)>
where
    S: ProxyStream + 'static,
{
    // Read first segment length.
    let mut len_buf = [0u8; 4];
    tls_stream.read_exact(&mut len_buf).await?;
    let seg_len = u32::from_be_bytes(len_buf) as usize;

    // Read first segment body.
    let mut seg_buf = vec![0u8; seg_len];
    tls_stream.read_exact(&mut seg_buf).await?;

    // Derive key.
    let key = crypto::derive_key(
        cfg.username.as_bytes(),
        cfg.password.as_bytes(),
        epoch_minute(),
    );

    // Decrypt openSessionRequest (first segment has visible nonce).
    if seg_buf.len() < NONCE_SIZE + METADATA_SIZE + TAG_SIZE {
        return Err(io_err("mieru: short open session segment"));
    }

    let client_nonce: [u8; 24] = seg_buf[..NONCE_SIZE].try_into().unwrap();
    let meta_plain = {
        let c = crypto::open(&key, &client_nonce, &seg_buf[NONCE_SIZE..NONCE_SIZE + METADATA_SIZE + TAG_SIZE])
            .ok_or_else(|| io_err("mieru: authentication failed"))?;
        c
    };
    let md = parse_metadata(meta_plain.as_slice().try_into().unwrap());

    // Extract SOCKS address from payload.
    let payload_start = NONCE_SIZE + METADATA_SIZE + TAG_SIZE;
    let payload_end = (payload_start + md.payload_len as usize).min(seg_buf.len());
    let addr_bytes = &seg_buf[payload_start..payload_end];

    use omni_domain::socks5::Socks5Addr;
    let (addr, _) = Socks5Addr::decode(addr_bytes).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("mieru: socks addr: {e}"))
    })?;
    let target = addr.to_proxy_target();

    // Generate response nonce and send openSessionResponse.
    let resp_nonce: [u8; 24] = rand::thread_rng().gen();

    let mut st_resp = SegmentState { key, nonce: resp_nonce, seq: 0 };
    let resp_seg = st_resp.encrypt_segment(super::PROTO_OPEN_SESSION_RESP, &[], false);
    tls_stream.write_all(&resp_seg).await?;

    // Set up bidirectional encrypted relay via pump tasks.
    // Server reads C2S segments (client's implicit nonce), writes S2C (resp nonce).
    let client_read_state = Arc::new(Mutex::new(SegmentReadState {
        key,
        nonce: client_nonce,
    }));
    let server_write_state = Arc::new(Mutex::new(st_resp));

    let (mut rh, mut wh) = tokio::io::split(tls_stream);
    let (out_tx, out_rx) = mpsc::unbounded_channel::<io::Result<Vec<u8>>>();
    let (in_tx, mut in_rx): (
        mpsc::UnboundedSender<Vec<u8>>,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) = mpsc::unbounded_channel();

    // Read pump: decrypt client→server data segments.
    let crs = client_read_state.clone();
    tokio::spawn(async move {
        let mut buf: Vec<u8> = Vec::with_capacity(16384);
        let mut tmp = vec![0u8; 65536];
        loop {
            match rh.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
            while buf.len() >= METADATA_SIZE + TAG_SIZE {
                let mut st = crs.lock().await;
                let mut nonce = st.nonce;
                if buf.len() < METADATA_SIZE + TAG_SIZE { break; }
                let Some(meta_plain) = crypto::open(&st.key, &nonce, &buf[..METADATA_SIZE + TAG_SIZE]) else {
                    return;
                };
                let md = parse_metadata(meta_plain.as_slice().try_into().unwrap());
                crypto::increment_nonce(&mut nonce);

                let payload_start = METADATA_SIZE + TAG_SIZE;
                let payload_end = payload_start + md.payload_len as usize + TAG_SIZE;
                let payload = if md.payload_len > 0 && buf.len() >= payload_end {
                    let mut n2 = nonce;
                    crypto::increment_nonce(&mut n2);
                    match crypto::open(&st.key, &n2, &buf[payload_start..payload_end]) {
                        Some(d) => d,
                        None => return,
                    }
                } else {
                    Vec::new()
                };

                crypto::increment_nonce(&mut st.nonce);
                if md.payload_len > 0 {
                    crypto::increment_nonce(&mut st.nonce);
                }
                drop(st);
                buf.drain(..payload_end);

                if !payload.is_empty() && out_tx.send(Ok(payload)).is_err() {
                    return;
                }
            }
        }
        let _ = out_tx.send(Ok(Vec::new()));
    });

    // Write pump: encrypt server→client data segments.
    let sws_arc = server_write_state.clone();
    tokio::spawn(async move {
        let mut sws = sws_arc.lock().await;
        while let Some(data) = in_rx.recv().await {
            if data.is_empty() { continue; }
            let seg = sws.encrypt_segment(super::PROTO_DATA_S2C, &data, false);
            if wh.write_all(&seg).await.is_err() {
                break;
            }
        }
        let _ = wh.shutdown().await;
    });
    drop(server_write_state);

    Ok((target, Box::new(ChannelDuplex {
        rx: out_rx,
        pending: std::collections::VecDeque::new(),
        eof: false,
        tx: in_tx,
    }) as BoxProxyStream))
}

struct SegmentReadState {
    key: [u8; 32],
    nonce: [u8; 24],
}

struct ChannelDuplex {
    rx: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    pending: std::collections::VecDeque<u8>,
    eof: bool,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncRead for ChannelDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = out.remaining().min(self.pending.len());
                let data: Vec<u8> = self.pending.drain(..n).collect();
                out.put_slice(&data);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    if data.is_empty() {
                        self.eof = true;
                    } else {
                        self.pending.extend(data);
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    self.eof = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for ChannelDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.tx.send(buf.to_vec()).is_err() {
            return Poll::Ready(Err(io_err("mieru: writer closed")));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
