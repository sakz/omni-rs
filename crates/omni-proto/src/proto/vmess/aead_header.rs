use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

pub const KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY: &str = "AES Auth ID Encryption";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY: &str = "AEAD Resp Header Len Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV: &str = "AEAD Resp Header Len IV";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY: &str = "AEAD Resp Header Key";
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV: &str = "AEAD Resp Header IV";
pub const KDF_SALT_CONST_VMESS_AEAD_KDF: &str = "VMess AEAD KDF";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY: &str = "VMess Header AEAD Key";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV: &str = "VMess Header AEAD Nonce";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &str = "VMess Header AEAD Key_Length";
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &str = "VMess Header AEAD Nonce_Length";

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

pub fn kdf(_key: &[u8], path: &[&[u8]]) -> Vec<u8> {
    let mut value = Vec::from(KDF_SALT_CONST_VMESS_AEAD_KDF.as_bytes());
    for p in path {
        value = hmac_sha256(&value, p).to_vec();
    }
    hmac_sha256(&value, b"").to_vec()
}

pub fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn create_auth_id(cmd_key: &[u8], ts_secs: i64) -> [u8; 16] {
    let key = kdf16(cmd_key, &[KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY.as_bytes()]);
    let cipher = Aes128::new_from_slice(&key).expect("auth id key");
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&(ts_secs as u64).to_be_bytes());
    let rand_part = crate::random_bytes::<4>();
    block[8..12].copy_from_slice(&rand_part);
    let mut enc_block = aes::Block::clone_from_slice(&block);
    cipher.encrypt_block(&mut enc_block);
    let mut out = [0u8; 16];
    out.copy_from_slice(enc_block.as_slice());
    out
}

fn gcm_seal(key: &[u8; 16], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    let c = aes_gcm::Aes128Gcm::new_from_slice(key).expect("gcm key");
    let mut buf_v = plaintext.to_vec();
    let tag = c
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut buf_v)
        .expect("gcm seal");
    let mut out = buf_v;
    out.extend_from_slice(tag.as_slice());
    out
}

fn gcm_open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    if ciphertext_with_tag.len() < 16 {
        return None;
    }
    let c = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    let ct_len = ciphertext_with_tag.len() - 16;
    let mut buf_v = ciphertext_with_tag[..ct_len].to_vec();
    let tag = aes_gcm::Tag::from_slice(&ciphertext_with_tag[ct_len..]);
    c.decrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut buf_v, tag)
        .ok()?;
    Some(buf_v)
}

pub fn seal_vmess_aead_header(cmd_key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let auth_id = create_auth_id(cmd_key, now);

    let nonce8 = crate::random_bytes::<8>();

    let len_key = kdf16(
        cmd_key,
        &[
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let len_nonce_full = kdf(
        cmd_key,
        &[
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let mut len_nonce = [0u8; 12];
    len_nonce.copy_from_slice(&len_nonce_full[..12]);

    let hdr_key = kdf16(
        cmd_key,
        &[
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let hdr_nonce_full = kdf(
        cmd_key,
        &[
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let mut hdr_nonce = [0u8; 12];
    hdr_nonce.copy_from_slice(&hdr_nonce_full[..12]);

    let enc_len =
        gcm_seal(&len_key, &len_nonce, &(data.len() as u16).to_be_bytes(), &auth_id);
    let enc_hdr = gcm_seal(&hdr_key, &hdr_nonce, data, &auth_id);

    let mut out = Vec::with_capacity(16 + 18 + 8 + enc_hdr.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&enc_len);
    out.extend_from_slice(&nonce8);
    out.extend_from_slice(&enc_hdr);
    out
}

pub fn open_vmess_aead_header(
    cmd_key: &[u8; 16],
    stream: &mut dyn std::io::Read,
) -> std::io::Result<Vec<u8>> {
    let mut auth_and_len = [0u8; 34];
    stream.read_exact(&mut auth_and_len)?;
    let auth_id: [u8; 16] = auth_and_len[..16].try_into().unwrap();

    let ts_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    {
        let id_key = kdf16(cmd_key, &[KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY.as_bytes()]);
        let cipher = Aes128::new_from_slice(&id_key).unwrap();
        let mut dec = aes::Block::clone_from_slice(&auth_id);
        use aes::cipher::BlockDecrypt;
        cipher.decrypt_block(&mut dec);
        let bytes = dec.as_slice();
        let ts = i64::from_be_bytes(bytes[..8].try_into().unwrap());
        if (ts_now - ts).abs() > 120 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "vmess: auth id timestamp expired",
            ));
        }
    }

    let mut nonce8 = [0u8; 8];
    stream.read_exact(&mut nonce8)?;

    let len_key = kdf16(
        cmd_key,
        &[
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let len_nonce_full = kdf(
        cmd_key,
        &[
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let mut len_nonce = [0u8; 12];
    len_nonce.copy_from_slice(&len_nonce_full[..12]);

    let mut enc_len = [0u8; 18];
    stream.read_exact(&mut enc_len)?;
    let len_plain = gcm_open(&len_key, &len_nonce, &enc_len, &auth_id)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "vmess: failed to decrypt header length"))?;
    if len_plain.len() != 2 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "vmess: bad length block"));
    }
    let hdr_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

    let hdr_key = kdf16(
        cmd_key,
        &[
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let hdr_nonce_full = kdf(
        cmd_key,
        &[
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV.as_bytes(),
            &auth_id,
            &nonce8,
        ],
    );
    let mut hdr_nonce = [0u8; 12];
    hdr_nonce.copy_from_slice(&hdr_nonce_full[..12]);

    let mut enc_hdr = vec![0u8; hdr_len + 16];
    stream.read_exact(&mut enc_hdr)?;
    gcm_open(&hdr_key, &hdr_nonce, &enc_hdr, &auth_id).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "vmess: failed to decrypt header payload")
    })
}
