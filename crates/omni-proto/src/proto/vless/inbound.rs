use super::{read_request_head, write_response, CMD_TCP, CMD_UDP};
use omni_domain::stream::ProxyStream;

pub struct VlessInboundConfig {
    pub allowed_uuids: Vec<[u8; 16]>,
}

pub enum Accepted<S> {
    Tcp {
        target: omni_domain::stream::ProxyTarget,
        stream: S,
    },
    Udp {
        stream: S,
    },
}

pub async fn handshake<S>(mut stream: S, cfg: &VlessInboundConfig) -> std::io::Result<Accepted<S>>
where
    S: ProxyStream,
{
    let (uuid, cmd, target) = read_request_head(&mut stream).await?;
    if !cfg.allowed_uuids.contains(&uuid) {
        return Err(super::ioerr("vless: authentication failed"));
    }
    tracing::debug!(target: "internal.pipeline", "vless inbound auth ok cmd={}", cmd);
    match cmd {
        CMD_TCP => {
            write_response(&mut stream).await?;
            tracing::debug!(target: "internal.pipeline", "vless response written");
            Ok(Accepted::Tcp { target, stream })
        }
        CMD_UDP => {
            write_response(&mut stream).await?;
            Ok(Accepted::Udp { stream })
        }
        _ => Err(super::ioerr("vless: unsupported command")),
    }
}
