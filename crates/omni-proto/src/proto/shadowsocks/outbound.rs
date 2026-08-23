use super::stream::{AeadStreamReader, AeadStreamWriter};
use super::{derive_subkey, evp_bytes_to_key, Method, SsAead};
use omni_domain::socks5::Socks5Addr;
use omni_domain::stream::{ProxyStream, ProxyTarget};
use rand::RngCore;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone)]
pub struct SsOutboundConfig {
    pub server: String,
    pub server_port: u16,
    pub method: String,
    pub password: String,
}

impl SsOutboundConfig {
    pub fn parsed_method(&self) -> std::io::Result<Method> {
        Method::parse(&self.method).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("shadowsocks: unsupported method '{}'", self.method),
            )
        })
    }

    pub fn master_key(&self) -> std::io::Result<Vec<u8>> {
        let m = self.parsed_method()?;
        Ok(evp_bytes_to_key(self.password.as_bytes(), m.key_len()))
    }
}

pub type SsOutboundConn<S> = (
    AeadStreamReader<tokio::io::ReadHalf<S>>,
    AeadStreamWriter<tokio::io::WriteHalf<S>>,
);

pub async fn connect_tcp<S>(
    mut underlay: S,
    cfg: &SsOutboundConfig,
    target: &ProxyTarget,
) -> std::io::Result<SsOutboundConn<S>>
where
    S: ProxyStream,
{
    let method = cfg.parsed_method()?;
    let master = cfg.master_key()?;

    let mut salt = vec![0u8; method.salt_len()];
    rand::thread_rng().fill_bytes(&mut salt);
    underlay.write_all(&salt).await?;

    let sub = derive_subkey(&master, &salt);
    let cipher = SsAead::new(method, &sub);

    let (rh, wh) = tokio::io::split(underlay);

    let mut addr = Vec::with_capacity(280);
    Socks5Addr::from_proxy_target(target).encode_into(&mut addr);
    let mut writer = AeadStreamWriter::new(wh, cipher.clone(), [0u8; 12]);

    let reader = AeadStreamReader::new(rh, cipher, [0u8; 12]);
    writer.write_chunk(&addr, false).await?;
    Ok((reader, writer))
}
