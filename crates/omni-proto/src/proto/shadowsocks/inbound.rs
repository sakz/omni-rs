use super::stream::{AeadStreamReader, AeadStreamWriter};
use super::{derive_subkey, evp_bytes_to_key, Method, SsAead};
use omni_domain::stream::ProxyStream;
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct SsInboundConfig {
    pub method: String,
    pub password: String,
}

impl SsInboundConfig {
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

pub type SsInboundConn<S> = (
    AeadStreamReader<tokio::io::ReadHalf<S>>,
    AeadStreamWriter<tokio::io::WriteHalf<S>>,
);

pub async fn accept_tcp<S>(
    mut underlay: S,
    cfg: &SsInboundConfig,
) -> std::io::Result<SsInboundConn<S>>
where
    S: ProxyStream,
{
    use tokio::io::AsyncReadExt;
    let method = cfg.parsed_method()?;
    let master = cfg.master_key()?;

    let mut salt = vec![0u8; method.salt_len()];
    underlay.read_exact(&mut salt).await?;
    let sub = derive_subkey(&master, &salt);
    let cipher = SsAead::new(method, &sub);

    let (rh, wh) = tokio::io::split(underlay);
    let reader = AeadStreamReader::new(rh, cipher.clone(), [0u8; 12]);
    let writer = AeadStreamWriter::new(wh, cipher, [0u8; 12]);
    Ok((reader, writer))
}

pub fn random_salt(method: Method) -> Vec<u8> {
    let mut v = vec![0u8; method.salt_len()];
    rand::thread_rng().fill_bytes(&mut v);
    v
}
