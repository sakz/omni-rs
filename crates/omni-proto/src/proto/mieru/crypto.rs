use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};

pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

/// Derive encryption key from credentials + epoch minute.
pub fn derive_key(username: &[u8], password: &[u8], epoch_minute: u64) -> [u8; KEY_LEN] {
    let mut pw_input = Vec::with_capacity(password.len() + 1 + username.len());
    pw_input.extend_from_slice(password);
    pw_input.push(0x00);
    pw_input.extend_from_slice(username);
    let password_hash = Sha256::digest(&pw_input);

    let salt = epoch_minute.to_be_bytes();
    let out = pbkdf2_sha256(&password_hash, &salt, 64, KEY_LEN);
    let mut result = [0u8; KEY_LEN];
    result.copy_from_slice(&out);
    result
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32, dk_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut block_index: u32 = 1;
    while out.len() < dk_len {
        let mut input = salt.to_vec();
        input.extend_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_sha256(password, &input);
        let mut acc = u;
        for _ in 1..rounds {
            u = hmac_sha256(password, &u);
            for (a, b) in acc.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        out.extend_from_slice(&acc);
        block_index += 1;
    }
    out.truncate(dk_len);
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    <HmacSha256 as Mac>::update(&mut mac, data);
    <HmacSha256 as Mac>::finalize(mac).into_bytes().into()
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("xchacha20 key")
}

pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    let c = cipher(key);
    let mut buf = plaintext.to_vec();
    let tag = c
        .encrypt_in_place_detached(chacha20poly1305::XNonce::from_slice(nonce), b"", &mut buf)
        .expect("seal");
    buf.extend_from_slice(tag.as_slice());
    buf
}

pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext_with_tag: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext_with_tag.len() < 16 {
        return None;
    }
    let c = cipher(key);
    let ct_len = ciphertext_with_tag.len() - 16;
    let mut buf = ciphertext_with_tag[..ct_len].to_vec();
    let tag = chacha20poly1305::Tag::from_slice(&ciphertext_with_tag[ct_len..]);
    c.decrypt_in_place_detached(
        chacha20poly1305::XNonce::from_slice(nonce),
        b"",
        &mut buf,
        tag,
    )
    .ok()?;
    Some(buf)
}

pub fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for i in nonce.iter_mut() {
        *i = i.wrapping_add(1);
        if *i != 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_deterministic() {
        let k1 = derive_key(b"user", b"pass", 1000);
        let k2 = derive_key(b"user", b"pass", 1000);
        assert_eq!(k1, k2);
        let k3 = derive_key(b"user", b"pass", 1001);
        assert_ne!(k1, k3);
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = derive_key(b"u", b"p", 42);
        let nonce = [7u8; NONCE_LEN];
        let plaintext = b"hello mieru";
        let ct = seal(&key, &nonce, plaintext);
        assert_ne!(ct, plaintext.to_vec());
        let pt = open(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn nonce_increment() {
        let mut n = [0u8; NONCE_LEN];
        increment_nonce(&mut n);
        assert_eq!(n[0], 1);
        assert!(n[1..].iter().all(|&b| b == 0));
    }
}
