use super::frame::{Frame, CMD_PSH, CMD_SETTINGS, CMD_SYN};
use super::session::{read_loop, spawn_writer, AnytlsStream, Registry};
use crate::crypto;
use omni_domain::socks5::Socks5Addr;
use omni_domain::stream::{ProxyStream, ProxyTarget};
use std::io;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

pub fn auth_token(password: &str) -> [u8; 32] {
    let out: [u8; 32] = crypto::sha256_digest(password.as_bytes());
    out
}

fn io_err(msg: &str) -> io::Error {
    io::Error::other(msg.to_string())
}

pub struct ClientSession {
    registry: Registry,
    pub writer_tx: mpsc::Sender<Frame>,
    next_sid: u32,
}

pub type SharedClientSession = Arc<Mutex<ClientSession>>;

pub async fn connect<S>(mut underlay: S, password: &str) -> io::Result<SharedClientSession>
where
    S: ProxyStream + 'static,
{
    use tokio::io::AsyncWriteExt;

    underlay.write_all(&auth_token(password)).await?;
    underlay.write_all(&0u16.to_be_bytes()).await?;

    let settings = format!(
        "v=2\nclient=omni-rs/{}\npadding-md5={}",
        env!("CARGO_PKG_VERSION"),
        crypto::hex_encode(&crypto::md5::digest(&[b""]))
    );

    let (rh, wh) = tokio::io::split(underlay);
    eprintln!("anytls-client: about to spawn writer");
    let (writer_tx, _close_tx, _task) = spawn_writer(wh).await;
    eprintln!("anytls-client: writer spawned");

    eprintln!("anytls-client: sending settings");
    writer_tx
        .send(Frame::with_data(CMD_SETTINGS, 0, settings.into_bytes()))
        .await
        .map_err(|_| io_err("anytls: session closed"))?;

    let registry: Registry = Arc::new(Mutex::new(Default::default()));
    {
        let reg = registry.clone();
        let wtx = writer_tx.clone();
        tokio::spawn(async move {
            if read_loop(rh, reg, wtx, false, |_stream| {}).await.is_err() {
                // session terminated; streams will observe EOF via registry removal
            }
        });
    }

    Ok(Arc::new(Mutex::new(ClientSession {
        registry,
        writer_tx,
        next_sid: 1,
    })))
}

impl ClientSession {
    pub async fn open_stream_to(
        &mut self,
        writer_tx: &mpsc::Sender<Frame>,
        target: &ProxyTarget,
    ) -> io::Result<AnytlsStream> {
        let sid = self.next_sid;
        self.next_sid += 1;

        let (msg_tx, msg_rx) = mpsc::channel(256);
        self.registry.lock().await.insert(sid, msg_tx);

        eprintln!("anytls-client: sending syn sid={}", sid);
        self.writer_tx
            .send(Frame::new(CMD_SYN, sid))
            .await
            .map_err(|_| io_err("anytls: session closed"))?;
        eprintln!("anytls-client: syn sent");

        let mut addr_bytes = Vec::with_capacity(280);
        Socks5Addr::from_proxy_target(target).encode_into(&mut addr_bytes);
        self.writer_tx
            .send(Frame::with_data(CMD_PSH, sid, addr_bytes))
            .await
            .map_err(|_| io_err("anytls: session closed"))?;

        Ok(AnytlsStream::new(sid, writer_tx.clone(), msg_rx))
    }
}
