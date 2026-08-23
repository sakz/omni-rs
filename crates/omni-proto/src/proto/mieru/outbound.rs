use super::crypto;
use super::{build_metadata, parse_metadata, ParsedMetadata, METADATA_SIZE, NONCE_SIZE, TAG_SIZE};
use omni_domain::stream::{BoxProxyStream, ProxyStream, ProxyTarget};
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Clone)]
pub struct MieruOutboundConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

fn io_err(msg: &str) -> io::Error {
    io::Error::other(format!("mieru: {}", msg))
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
        let metadata = build_metadata(proto_type, em, 0, self.seq, 0, payload.len() as u16, 0);
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

    fn decrypt_segment(
        &mut self,
        data: &[u8],
        has_nonce: bool,
    ) -> Option<(ParsedMetadata, Vec<u8>)> {
        let mut off = 0usize;
        let mut nonce = self.nonce;
        if has_nonce {
            if data.len() < NONCE_SIZE {
                return None;
            }
            nonce.copy_from_slice(&data[..NONCE_SIZE]);
            off = NONCE_SIZE;
        }
        if data.len() < off + METADATA_SIZE + TAG_SIZE {
            return None;
        }

        let meta_plain = crypto::open(
            &self.key,
            &nonce,
            &data[off..off + METADATA_SIZE + TAG_SIZE],
        )?;
        let md = parse_metadata(meta_plain.as_slice().try_into().ok()?);

        let payload_start = off + METADATA_SIZE + TAG_SIZE;
        let payload_end = payload_start + md.payload_len as usize + TAG_SIZE;
        let mut n2 = nonce;
        crypto::increment_nonce(&mut n2);
        let payload =
            if md.payload_len > 0 && data.len() >= payload_start && data.len() >= payload_end {
                crypto::open(&self.key, &n2, &data[payload_start..payload_end])?
            } else {
                Vec::new()
            };

        crypto::increment_nonce(&mut self.nonce);
        if md.payload_len > 0 {
            crypto::increment_nonce(&mut self.nonce);
        }
        Some((md, payload))
    }
}

fn encode_socks_addr(target: &ProxyTarget) -> Vec<u8> {
    use omni_domain::socks5::Socks5Addr;
    match Socks5Addr::from_proxy_target(target) {
        Socks5Addr::V4(ip, port) => {
            let mut v = vec![1u8];
            v.extend_from_slice(&ip);
            v.extend_from_slice(&port.to_be_bytes());
            v
        }
        Socks5Addr::Domain(h, port) => {
            let mut v = vec![3u8, h.len() as u8];
            v.extend_from_slice(h.as_bytes());
            v.extend_from_slice(&port.to_be_bytes());
            v
        }
        Socks5Addr::V6(ip, port) => {
            let mut v = vec![4u8];
            v.extend_from_slice(&ip);
            v.extend_from_slice(&port.to_be_bytes());
            v
        }
    }
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

pub async fn connect_tcp<S>(
    mut underlay: S,
    cfg: &MieruOutboundConfig,
    target: &ProxyTarget,
) -> io::Result<BoxProxyStream>
where
    S: ProxyStream + 'static,
{
    let key = crypto::derive_key(
        cfg.username.as_bytes(),
        cfg.password.as_bytes(),
        epoch_minute(),
    );
    let nonce: [u8; NONCE_SIZE] = rand::thread_rng().gen();

    let mut st = SegmentState { key, nonce, seq: 0 };

    // Send openSessionRequest with target address.
    let addr_payload = encode_socks_addr(target);
    let open_seg = st.encrypt_segment(super::PROTO_OPEN_SESSION_REQ, &addr_payload, true);
    underlay.write_all(&open_seg).await?;

    // Read openSessionResponse (first segment from server has visible nonce).
    let mut hdr = vec![0u8; 512];
    let n = underlay.read(&mut hdr).await?;
    if n == 0 {
        return Err(io_err("connection closed during open"));
    }
    hdr.truncate(n);

    if hdr.len() < NONCE_SIZE + METADATA_SIZE + TAG_SIZE {
        return Err(io_err("short openSessionResponse"));
    }
    let server_nonce: [u8; NONCE_SIZE] = hdr[..NONCE_SIZE].try_into().unwrap();
    let meta_plain = crypto::open(
        &key,
        &server_nonce,
        &hdr[NONCE_SIZE..NONCE_SIZE + METADATA_SIZE + TAG_SIZE],
    )
    .ok_or_else(|| io_err("open response decrypt failed"))?;
    let md = parse_metadata(meta_plain.as_slice().try_into().unwrap());
    if md.status != 0 {
        return Err(io_err("mieru: open rejected"));
    }

    // Set up pump states.
    let client_state = Arc::new(Mutex::new(st));
    let server_state = Arc::new(Mutex::new(SegmentState {
        key,
        nonce: server_nonce,
        seq: 0,
    }));

    let (rh, wh) = tokio::io::split(underlay);
    let (out_tx, out_rx) = mpsc::unbounded_channel::<io::Result<Vec<u8>>>();
    let (in_tx, mut in_rx): (
        mpsc::UnboundedSender<Vec<u8>>,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) = mpsc::unbounded_channel();

    // Read pump: decrypt incoming segments.
    tokio::spawn(async move {
        let st = server_state;
        let mut rh = rh;
        let mut buf: Vec<u8> = Vec::with_capacity(16384);
        let mut tmp = vec![0u8; 65536];
        loop {
            match rh.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
            while buf.len() >= METADATA_SIZE + TAG_SIZE {
                let mut stg = st.lock().await;
                match stg.decrypt_segment(&buf, false) {
                    Some((md, payload)) => {
                        let consumed =
                            METADATA_SIZE + TAG_SIZE + md.payload_len as usize + TAG_SIZE;
                        drop(stg);
                        buf.drain(..consumed.min(buf.len()));
                        if !payload.is_empty() && out_tx.send(Ok(payload)).is_err() {
                            return;
                        }
                    }
                    None => break,
                }
            }
        }
        let _ = out_tx.send(Ok(Vec::new()));
    });

    // Write pump: encrypt outgoing data as segments.
    let c_state = client_state.clone();
    tokio::spawn(async move {
        let mut wh = wh;
        while let Some(data) = in_rx.recv().await {
            if data.is_empty() {
                continue;
            }
            let mut cst = c_state.lock().await;
            let seg = cst.encrypt_segment(super::PROTO_DATA_C2S, &data, false);
            drop(cst);
            if wh.write_all(&seg).await.is_err() {
                break;
            }
        }
        let _ = wh.shutdown().await;
    });

    Ok(Box::new(ChannelDuplex {
        rx: out_rx,
        pending: std::collections::VecDeque::new(),
        eof: false,
        tx: in_tx,
    }) as BoxProxyStream)
}
