use super::aead_header::{
    kdf, kdf16, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
    KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
    KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY,
};
use super::chunk::{ChunkKeys, ChunkReader, ChunkSecurity, ChunkWriter};
use super::{cmd_key, decode_request_command, DecodedRequest};
use aes::cipher::KeyInit;
use omni_domain::stream::ProxyStream;
use sha2::{Digest, Sha256};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct VmessInboundConfig {
    pub users: Vec<[u8; 16]>,
}

pub struct AcceptedVm<S> {
    pub target: omni_domain::stream::ProxyTarget,
    pub reader: ChunkReader<tokio::io::ReadHalf<S>>,
    pub writer: ChunkWriter<tokio::io::WriteHalf<S>>,
}

fn aes_ecb_decrypt_one(key16: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = aes::Aes128::new_from_slice(key16).unwrap();
    let mut b = aes::Block::clone_from_slice(block);
    use aes::cipher::BlockDecrypt;
    cipher.decrypt_block(&mut b);
    let mut out = [0u8; 16];
    out.copy_from_slice(b.as_slice());
    out
}

fn gcm_seal(key: &[u8; 16], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    let c = aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| ioerr("vmess: gcm init"))?;
    let mut buf_v = plaintext.to_vec();
    let tag = c
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut buf_v)
        .map_err(|_| ioerr("vmess: seal failed"))?;
    buf_v.extend_from_slice(tag.as_slice());
    Ok(buf_v)
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

pub fn resp_chunk_keys(req: &DecodedRequest) -> ChunkKeys {
    let rk = Sha256::digest(req.request_key);
    let ri = Sha256::digest(req.request_iv);
    let mut key = [0u8; 16];
    key.copy_from_slice(&rk[..16]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&ri[..16]);
    ChunkKeys { key, iv }
}

pub fn req_chunk_keys(req: &DecodedRequest) -> ChunkKeys {
    ChunkKeys {
        key: req.request_key,
        iv: req.request_iv,
    }
}

fn chunk_security_of(security: u8) -> io::Result<ChunkSecurity> {
    match security {
        super::SEC_AES128_GCM | super::SEC_AUTO => Ok(ChunkSecurity::Gcm),
        super::SEC_CHACHA20_POLY1305 => Ok(ChunkSecurity::ChaCha),
        super::SEC_NONE => Ok(ChunkSecurity::None),
        super::SEC_LEGACY => Err(ioerr("vmess: legacy security not supported")),
        _ => Err(ioerr("vmess: unknown security")),
    }
}

pub async fn handshake<S>(mut stream: S, cfg: &VmessInboundConfig) -> io::Result<AcceptedVm<S>>
where
    S: ProxyStream,
{
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut auth_id = [0u8; 16];
    stream.read_exact(&mut auth_id).await?;

    let id_keys: Vec<([u8; 16], [u8; 16])> = cfg
        .users
        .iter()
        .map(|u| {
            let ck = cmd_key(u);
            let ik = kdf16(&ck, &[KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY.as_bytes()]);
            (ck, ik)
        })
        .collect();

    let mut matched: Option<[u8; 16]> = None;
    for (ck, ik) in &id_keys {
        let plain = aes_ecb_decrypt_one(ik, &auth_id);
        let ts = i64::from_be_bytes(plain[..8].try_into().unwrap());
        if (now - ts).abs() <= 120 {
            matched = Some(*ck);
            break;
        }
    }
    let found_cmd_key = matched.ok_or_else(|| ioerr("vmess: authentication failed"))?;

    let mut enc_len = [0u8; 18];
    stream.read_exact(&mut enc_len).await?;

    let mut nonce8 = [0u8; 8];
    stream.read_exact(&mut nonce8).await?;

    let len_key = kdf16(
        &found_cmd_key,
        &[
            super::aead_header::KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let len_nonce_full = kdf(
        &found_cmd_key,
        &[
            super::aead_header::KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let mut len_nonce = [0u8; 12];
    len_nonce.copy_from_slice(&len_nonce_full[..12]);

    let len_plain = gcm_open(&len_key, &len_nonce, &enc_len, &auth_id)
        .ok_or_else(|| ioerr("vmess: header length decrypt failed"))?;
    if len_plain.len() != 2 {
        return Err(ioerr("vmess: bad header length block"));
    }
    let hdr_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

    let hdr_key = kdf16(
        &found_cmd_key,
        &[
            super::aead_header::KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let hdr_nonce_full = kdf(
        &found_cmd_key,
        &[
            super::aead_header::KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let mut hdr_nonce = [0u8; 12];
    hdr_nonce.copy_from_slice(&hdr_nonce_full[..12]);

    let mut enc_hdr = vec![0u8; hdr_len + 16];
    stream.read_exact(&mut enc_hdr).await?;
    let cmd_buf = gcm_open(&hdr_key, &hdr_nonce, &enc_hdr, &auth_id)
        .ok_or_else(|| ioerr("vmess: header payload decrypt failed"))?;

    let req = decode_request_command(&cmd_buf)?;

    if req.cmd != super::CMD_TCP {
        return Err(ioerr("vmess: UDP command not supported in this build"));
    }
    if req.options & super::OPT_AUTHENTICATED_LENGTH != 0 {
        return Err(ioerr("vmess: authenticated-length option not supported"));
    }
    if req.options & super::OPT_CHUNK_STREAM == 0 {
        return Err(ioerr("vmess: non-chunked body not supported"));
    }

    let security = chunk_security_of(req.security)?;
    let masking = req.options & super::OPT_CHUNK_MASKING != 0;
    let global_padding = req.options & super::OPT_GLOBAL_PADDING != 0;

    let rkeys = req_chunk_keys(&req);
    let wkeys = resp_chunk_keys(&req);
    let response_v = req.response_v;
    let options_echo = req.options;

    let (rh, mut wh) = tokio::io::split(stream);

    let resp_payload = [response_v, options_echo, 0x00];

    let rl_key = kdf16(
        &wkeys.key,
        &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY.as_bytes()],
    );
    let rl_nonce_full = kdf(
        &wkeys.iv,
        &[KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV.as_bytes()],
    );
    let mut rl_nonce = [0u8; 12];
    rl_nonce.copy_from_slice(&rl_nonce_full[..12]);

    let rp_key = kdf16(
        &wkeys.key,
        &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY.as_bytes()],
    );
    let rp_nonce_full = kdf(
        &wkeys.iv,
        &[KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV.as_bytes()],
    );
    let mut rp_nonce = [0u8; 12];
    rp_nonce.copy_from_slice(&rp_nonce_full[..12]);

    let enc_len = gcm_seal(
        &rl_key,
        &rl_nonce,
        &(resp_payload.len() as u16).to_be_bytes(),
        b"",
    )?;
    let enc_payload = gcm_seal(&rp_key, &rp_nonce, &resp_payload, b"")?;
    tracing::debug!(target: "internal.pipeline", "vmess inbound writing resp len={} payload={}", enc_len.len(), enc_payload.len());
    wh.write_all(&enc_len).await?;
    wh.write_all(&enc_payload).await?;
    tracing::debug!(target: "internal.pipeline", "vmess inbound resp header flushed");

    let reader = ChunkReader::new(rh, rkeys, security, masking, global_padding);
    let writer = ChunkWriter::new(wh, wkeys, security, masking, global_padding);

    Ok(AcceptedVm {
        target: req.target,
        reader,
        writer,
    })
}

fn ioerr(msg: &'static str) -> std::io::Error {
    std::io::Error::other(msg)
}
