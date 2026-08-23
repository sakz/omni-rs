use super::{read_request_head, CMD_CONNECT, CMD_UDP_ASSOCIATE};
use omni_domain::stream::ProxyStream;
use tokio::io::AsyncWriteExt;

pub struct TrojanInboundConfig {
    pub password_hash_hex: String,
}

pub enum Accepted<S> {
    Tcp {
        target: omni_domain::stream::ProxyTarget,
        stream: S,
    },
    UdpAssociate {
        stream: S,
    },
}

pub async fn handshake<S>(stream: S, cfg: &TrojanInboundConfig) -> std::io::Result<Accepted<S>>
where
    S: ProxyStream,
{
    let mut stream = stream;
    let (cmd, target) = read_request_head(&mut stream, Some(&cfg.password_hash_hex)).await?;
    match cmd {
        CMD_CONNECT => Ok(Accepted::Tcp { target, stream }),
        CMD_UDP_ASSOCIATE => Ok(Accepted::UdpAssociate { stream }),
        _ => Err(super::ioerr("trojan: unsupported command")),
    }
}

pub async fn reject_and_close<S>(mut stream: S)
where
    S: ProxyStream,
{
    let _ = stream.shutdown().await;
}
