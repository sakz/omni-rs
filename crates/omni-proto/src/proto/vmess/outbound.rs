use super::aead_header::{
    kdf, kdf16, seal_vmess_aead_header, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
    KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
    KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
};
use super::chunk::{ChunkKeys, ChunkReader, ChunkSecurity, ChunkWriter};
use super::{cmd_key, encode_request_command};
use crate::common::TargetedOutboundConfig;
use omni_domain::stream::ProxyStream;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct VmessOutboundConfig {
    pub base: TargetedOutboundConfig,
    pub uuid: String,
    pub security: String,
}

fn security_byte(s: &str) -> io::Result<u8> {
    match s.to_ascii_lowercase().as_str() {
        "auto" | "" => Ok(super::SEC_AES128_GCM),
        "aes-128-gcm" => Ok(super::SEC_AES128_GCM),
        "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(super::SEC_CHACHA20_POLY1305),
        "none" => Ok(super::SEC_NONE),
        other => Err(io_err(format!("vmess: unsupported security '{}'", other))),
    }
}

fn io_err(msg: String) -> std::io::Error {
    std::io::Error::other(msg)
}

pub type VmessConn<S> = (
    ChunkReader<tokio::io::ReadHalf<S>>,
    ChunkWriter<tokio::io::WriteHalf<S>>,
);

pub async fn connect_tcp<S>(
    mut underlay: S,
    cfg: &VmessOutboundConfig,
    target: &omni_domain::stream::ProxyTarget,
) -> io::Result<VmessConn<S>>
where
    S: ProxyStream,
{
    let uuid = crate::crypto::parse_uuid(&cfg.uuid)
        .ok_or_else(|| io_err(format!("vmess: invalid UUID '{}'", cfg.uuid)))?;
    let ck = cmd_key(&uuid);
    let sec = security_byte(&cfg.security)?;

    let mut request_iv = [0u8; 16];
    let mut request_key = [0u8; 16];
    {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut request_iv);
        rand::thread_rng().fill_bytes(&mut request_key);
    }
    let response_v = crate::random_bytes::<1>()[0];

    let options = super::OPT_CHUNK_STREAM | super::OPT_CHUNK_MASKING | super::OPT_GLOBAL_PADDING;

    let cmd_buf = encode_request_command(
        &request_iv,
        &request_key,
        response_v,
        options,
        sec,
        super::CMD_TCP,
        target,
    );

    let sealed = seal_vmess_aead_header(&ck, &cmd_buf);
    underlay.write_all(&sealed).await?;
    underlay.flush().await?;

    let resp_keys = {
        use sha2::Digest;
        let rk = sha2::Sha256::digest(request_key);
        let ri = sha2::Sha256::digest(request_iv);
        let mut k = [0u8; 16];
        k.copy_from_slice(&rk[..16]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&ri[..16]);
        ChunkKeys { key: k, iv }
    };

    let rl_key = kdf16(
        &resp_keys.key,
        &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY.as_bytes()],
    );
    let rl_nonce_full = kdf(
        &resp_keys.iv,
        &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV.as_bytes()],
    );
    let mut rl_nonce = [0u8; 12];
    rl_nonce.copy_from_slice(&rl_nonce_full[..12]);

    let rp_key = kdf16(
        &resp_keys.key,
        &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY.as_bytes()],
    );
    let rp_nonce_full = kdf(
        &resp_keys.iv,
        &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV.as_bytes()],
    );
    let mut rp_nonce = [0u8; 12];
    rp_nonce.copy_from_slice(&rp_nonce_full[..12]);

    let mut enc_len = [0u8; 18];
    tracing::debug!(target: "internal.pipeline", "vmess outbound awaiting resp len");
    underlay.read_exact(&mut enc_len).await?;
    tracing::debug!(target: "internal.pipeline", "vmess outbound resp len ok");
    let len_plain = gcm_open(&rl_key, &rl_nonce, &enc_len, b"")
        .ok_or_else(|| io_err("vmess: response length decrypt failed".into()))?;
    if len_plain.len() != 2 {
        return Err(io_err("vmess: bad response length block".into()));
    }
    let hdr_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

    tracing::debug!(target: "internal.pipeline", "vmess outbound resp hdr_len={}", hdr_len);
    let mut enc_payload = vec![0u8; hdr_len + 16];
    underlay.read_exact(&mut enc_payload).await?;
    tracing::debug!(target: "internal.pipeline", "vmess outbound resp payload read");
    let payload = gcm_open(&rp_key, &rp_nonce, &enc_payload, b"")
        .ok_or_else(|| io_err("vmess: response payload decrypt failed".into()))?;
    if payload.is_empty() || payload[0] != response_v {
        return Err(io_err("vmess: response auth mismatch".into()));
    }

    let req_keys = ChunkKeys {
        key: request_key,
        iv: request_iv,
    };

    let masking = options & super::OPT_CHUNK_MASKING != 0;
    let padding = options & super::OPT_GLOBAL_PADDING != 0;
    let chunk_sec = security_byte(&cfg.security)?;
    let chunk_sec = match chunk_sec {
        super::SEC_CHACHA20_POLY1305 => ChunkSecurity::ChaCha,
        super::SEC_NONE => ChunkSecurity::None,
        _ => ChunkSecurity::Gcm,
    };

    let (rh, wh) = tokio::io::split(underlay);
    let reader = ChunkReader::new(rh, resp_keys.clone(), chunk_sec, masking, padding);
    let writer = ChunkWriter::new(wh, req_keys, chunk_sec, masking, padding);
    Ok((reader, writer))
}

fn gcm_open(key: &[u8; 16], nonce: &[u8; 12], data: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    if data.len() < 16 {
        return None;
    }
    let c = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    let mut buf_v = data[..data.len() - 16].to_vec();
    let tag = aes_gcm::Tag::from_slice(&data[data.len() - 16..]);
    c.decrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut buf_v, tag)
        .ok()?;
    Some(buf_v)
}
