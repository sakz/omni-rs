pub mod inbound;
pub mod outbound;
pub mod stream;

use aes_gcm::aead::{AeadInPlace, KeyInit};

pub const MAX_PAYLOAD: usize = 0x3FFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20IetfPoly1305,
}

impl Method {
    pub fn parse(s: &str) -> Option<Method> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Some(Method::Aes128Gcm),
            "aes-256-gcm" => Some(Method::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Method::ChaCha20IetfPoly1305),
            _ => None,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Method::Aes128Gcm => 16,
            _ => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }
}

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(key_len + 15);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut input = prev.clone();
        input.extend_from_slice(password);
        let d = crate::crypto::md5::digest(&[&input]);
        prev = d.to_vec();
        out.extend_from_slice(&d);
    }
    out.truncate(key_len);
    out
}

pub mod hkdf_sha1 {
    pub fn sha1(data: &[u8]) -> [u8; 20] {
        struct Sha1 {
            h: [u32; 5],
            len: u64,
            buf: [u8; 64],
            buflen: usize,
        }
        impl Sha1 {
            fn new() -> Self {
                Sha1 {
                    h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
                    len: 0,
                    buf: [0; 64],
                    buflen: 0,
                }
            }
            fn update(&mut self, mut data: &[u8]) {
                self.len = self.len.wrapping_add(data.len() as u64);
                while !data.is_empty() {
                    let take = (64 - self.buflen).min(data.len());
                    self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
                    self.buflen += take;
                    data = &data[take..];
                    if self.buflen == 64 {
                        let b = self.buf;
                        self.block(&b);
                        self.buflen = 0;
                    }
                }
            }
            fn block(&mut self, block: &[u8; 64]) {
                let mut w = [0u32; 80];
                for i in 0..16 {
                    w[i] = u32::from_be_bytes([
                        block[i * 4],
                        block[i * 4 + 1],
                        block[i * 4 + 2],
                        block[i * 4 + 3],
                    ]);
                }
                for i in 16..80 {
                    w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
                }
                let (mut a, mut b, mut c, mut d, mut e) =
                    (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]);
                for i in 0..80 {
                    let (f, k) = match i / 20 {
                        0 => ((b & c) | (!b & d), 0x5A827999u32),
                        1 => (b ^ c ^ d, 0x6ED9EBA1),
                        2 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                        _ => (b ^ c ^ d, 0xCA62C1D6),
                    };
                    let tmp = a
                        .rotate_left(5)
                        .wrapping_add(f)
                        .wrapping_add(e)
                        .wrapping_add(k)
                        .wrapping_add(w[i]);
                    e = d;
                    d = c;
                    c = b.rotate_left(30);
                    b = a;
                    a = tmp;
                }
                self.h[0] = self.h[0].wrapping_add(a);
                self.h[1] = self.h[1].wrapping_add(b);
                self.h[2] = self.h[2].wrapping_add(c);
                self.h[3] = self.h[3].wrapping_add(d);
                self.h[4] = self.h[4].wrapping_add(e);
            }
            fn finalize(mut self) -> [u8; 20] {
                let bitlen = self.len.wrapping_mul(8);
                self.update(&[0x80]);
                while self.buflen != 56 {
                    self.update(&[0]);
                }
                self.update(&bitlen.to_be_bytes());
                let mut out = [0u8; 20];
                for i in 0..5 {
                    out[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_be_bytes());
                }
                out
            }
        }

        let mut s = Sha1::new();
        s.update(data);
        s.finalize()
    }

    pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            let d = sha1(key);
            k[..20].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
        let mut inner = ipad;
        inner.extend_from_slice(data);
        let ih = sha1(&inner);
        let mut outer = opad;
        outer.extend_from_slice(&ih);
        sha1(&outer)
    }

    pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 20] {
        hmac_sha1(salt, ikm)
    }

    pub fn expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut okm = Vec::with_capacity(len.max(20));
        let mut t: Vec<u8> = Vec::new();
        let mut counter: u8 = 1;
        while okm.len() < len {
            let mut input = t.clone();
            input.extend_from_slice(info);
            input.push(counter);
            let ti = hmac_sha1(prk, &input);
            t = ti.to_vec();
            okm.extend_from_slice(&ti);
            counter = counter.wrapping_add(1);
        }
        okm.truncate(len);
        okm
    }
}

pub fn derive_subkey(master_key: &[u8], salt: &[u8]) -> Vec<u8> {
    let prk = hkdf_sha1::extract(salt, master_key);
    hkdf_sha1::expand(&prk, b"ss-subkey", master_key.len())
}

pub fn increment_nonce(nonce: &mut [u8]) {
    for b in nonce.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

#[derive(Clone)]
pub enum SsAead {
    Aes128(aes_gcm::Aes128Gcm),
    Aes256(aes_gcm::Aes256Gcm),
    ChaCha(chacha20poly1305::ChaCha20Poly1305),
}

impl SsAead {
    pub fn new(method: Method, key: &[u8]) -> SsAead {
        match method {
            Method::Aes128Gcm => SsAead::Aes128(aes_gcm::Aes128Gcm::new_from_slice(key).unwrap()),
            Method::Aes256Gcm => SsAead::Aes256(aes_gcm::Aes256Gcm::new_from_slice(key).unwrap()),
            Method::ChaCha20IetfPoly1305 => {
                SsAead::ChaCha(chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).unwrap())
            }
        }
    }

    pub fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Option<Vec<u8>> {
        match self {
            SsAead::Aes128(c) => {
                let n = aes_gcm::Nonce::from_slice(nonce);
                c.encrypt_in_place_detached(n, aad, plaintext)
                    .ok()
                    .map(|t| t.to_vec())
            }
            SsAead::Aes256(c) => {
                let n = aes_gcm::Nonce::from_slice(nonce);
                c.encrypt_in_place_detached(n, aad, plaintext)
                    .ok()
                    .map(|t| t.to_vec())
            }
            SsAead::ChaCha(c) => {
                let n = chacha20poly1305::Nonce::from_slice(nonce);
                c.encrypt_in_place_detached(n, aad, plaintext)
                    .ok()
                    .map(|t| t.to_vec())
            }
        }
    }

    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8],
    ) -> bool {
        let tag = aes_gcm::Tag::from_slice(tag);
        match self {
            SsAead::Aes128(c) => c
                .decrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, ciphertext, tag)
                .is_ok(),
            SsAead::Aes256(c) => c
                .decrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, ciphertext, tag)
                .is_ok(),
            SsAead::ChaCha(c) => c
                .decrypt_in_place_detached(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    aad,
                    ciphertext,
                    tag,
                )
                .is_ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_sha1_rfc2202_case1() {
        let key = [0x0bu8; 20];
        let mac = hkdf_sha1::hmac_sha1(&key, b"Hi There");
        assert_eq!(hex_of(&mac), "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    #[test]
    fn sha1_vector() {
        assert_eq!(
            hex_of(&hkdf_sha1::sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn ss_aead_roundtrip() {
        for m in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20IetfPoly1305,
        ] {
            let key = vec![7u8; m.key_len()];
            let cipher = SsAead::new(m, &key);
            let mut pt = b"hello shadowsocks aead payload".to_vec();
            let mut nonce = [0u8; 12];
            let tag = cipher.seal(&nonce, b"", &mut pt).unwrap();
            assert!(cipher.open(&nonce, b"", &mut pt, &tag));
            assert_eq!(pt, b"hello shadowsocks aead payload");
            increment_nonce(&mut nonce);
        }
    }

    #[test]
    fn evp_key_len() {
        assert_eq!(evp_bytes_to_key(b"pw", 16).len(), 16);
        assert_eq!(evp_bytes_to_key(b"pw", 32).len(), 32);
    }
}
