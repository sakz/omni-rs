use aes::cipher::{BlockEncrypt, KeyInit};

pub mod md5 {
    pub struct Md5 {
        state: [u32; 4],
        len: u64,
        buf: [u8; 64],
        buflen: usize,
    }

    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    impl Default for Md5 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Md5 {
        pub fn new() -> Self {
            Md5 {
                state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
                len: 0,
                buf: [0u8; 64],
                buflen: 0,
            }
        }

        pub fn update(&mut self, mut data: &[u8]) {
            self.len = self.len.wrapping_add(data.len() as u64);
            while !data.is_empty() {
                let take = (64 - self.buflen).min(data.len());
                self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
                self.buflen += take;
                data = &data[take..];
                if self.buflen == 64 {
                    let block = self.buf;
                    self.compress(&block);
                    self.buflen = 0;
                }
            }
        }

        fn compress(&mut self, block: &[u8; 64]) {
            let mut m = [0u32; 16];
            for i in 0..16 {
                m[i] = u32::from_le_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
                ]);
            }
            let (mut a, mut b, mut c, mut d) =
                (self.state[0], self.state[1], self.state[2], self.state[3]);
            for i in 0..64 {
                let (f, g) = match i / 16 {
                    0 => ((b & c) | (!b & d), i),
                    1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                    2 => (b ^ c ^ d, (3 * i + 5) % 16),
                    _ => (c ^ (b | !d), (7 * i) % 16),
                };
                let tmp = d;
                d = c;
                c = b;
                let x = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
                b = b.wrapping_add(x.rotate_left(S[i]));
                a = tmp;
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
        }

        pub fn finalize(mut self) -> [u8; 16] {
            let bitlen = self.len.wrapping_mul(8);
            self.update(&[0x80]);
            while self.buflen != 56 {
                self.update(&[0]);
            }
            self.update(&bitlen.to_le_bytes());
            let mut out = [0u8; 16];
            for i in 0..4 {
                out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_le_bytes());
            }
            out
        }
    }

    pub fn digest(parts: &[&[u8]]) -> [u8; 16] {
        let mut h = Md5::new();
        for p in parts {
            h.update(p);
        }
        h.finalize()
    }
}

pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 2166136261;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(16777619);
    }
    hash
}

pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

pub fn sha224_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha224};
    let out = Sha224::digest(data);
    hex_encode(&out)
}

pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xF) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

pub struct Cfb128Encryptor {
    cipher: aes::Aes128,
    iv: [u8; 16],
}

impl Cfb128Encryptor {
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Cfb128Encryptor {
            cipher: aes::Aes128::new_from_slice(key).unwrap(),
            iv: *iv,
        }
    }

    pub fn apply_xor(&mut self, data: &mut [u8]) {
        let mut feedback = self.iv;
        for chunk in data.chunks_mut(16) {
            let mut block = aes::Block::clone_from_slice(&feedback);
            self.cipher.encrypt_block(&mut block);
            let ks: [u8; 16] = block.into();
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= ks[i];
            }
            feedback = shift_feedback(feedback, chunk.len(), chunk);
        }
        self.iv = feedback;
    }
}

pub struct Cfb128Decryptor {
    cipher: aes::Aes128,
    iv: [u8; 16],
}

impl Cfb128Decryptor {
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Cfb128Decryptor {
            cipher: aes::Aes128::new_from_slice(key).unwrap(),
            iv: *iv,
        }
    }

    pub fn apply_xor(&mut self, data: &mut [u8]) {
        let mut feedback = self.iv;
        for chunk in data.chunks_mut(16) {
            let mut block = aes::Block::clone_from_slice(&feedback);
            self.cipher.encrypt_block(&mut block);
            let ks: [u8; 16] = block.into();
            let cipher_chunk: Vec<u8> = chunk.to_vec();
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= ks[i];
            }
            feedback = shift_feedback(feedback, chunk.len(), &cipher_chunk);
        }
        self.iv = feedback;
    }
}

fn shift_feedback(fb: [u8; 16], used: usize, ct_chunk: &[u8]) -> [u8; 16] {
    if used >= 16 {
        return ct_chunk[..16].try_into().unwrap();
    }
    let mut out = [0u8; 16];
    out[..16 - used].copy_from_slice(&fb[used..]);
    out[16 - used..].copy_from_slice(&ct_chunk[..used]);
    out
}

pub struct Aes128Ctr {
    cipher: aes::Aes128,
    counter: [u8; 16],
    keystream: [u8; 16],
    pos: usize,
}

impl Aes128Ctr {
    pub fn new(key: &[u8; 16], nonce_counter: &[u8; 16]) -> Self {
        Aes128Ctr {
            cipher: aes::Aes128::new_from_slice(key).unwrap(),
            counter: *nonce_counter,
            keystream: [0u8; 16],
            pos: 16,
        }
    }

    fn refill(&mut self) {
        let mut block = aes::Block::clone_from_slice(&self.counter);
        self.cipher.encrypt_block(&mut block);
        self.keystream.copy_from_slice(block.as_slice());
        for i in (0..16).rev() {
            self.counter[i] = self.counter[i].wrapping_add(1);
            if self.counter[i] != 0 {
                break;
            }
        }
        self.pos = 0;
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            if self.pos == 16 {
                self.refill();
            }
            *b ^= self.keystream[self.pos];
            self.pos += 1;
        }
    }
}

pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn uuid_to_string(u: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13],
        u[14], u[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_vectors() {
        assert_eq!(
            hex_encode(&md5::digest(&[b"abc"])),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex_encode(&md5::digest(&[b""])),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        let long = vec![b'a'; 1000];
        assert_eq!(
            hex_encode(&md5::digest(&[&long])),
            "cabe45dcc9ae5b66ba86600cca6b8ba8"
        );
    }

    #[test]
    fn sha224_vector() {
        assert_eq!(
            sha224_hex(b"abc"),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[test]
    fn fnv_vector() {
        assert_eq!(fnv1a32(b""), 2166136261);
        assert_eq!(fnv1a32(b"a"), 0xe40c292c);
    }

    #[test]
    fn uuid_roundtrip() {
        let u = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        assert_eq!(uuid_to_string(&u), "b831381d-6324-4d53-ad4f-8cda48b30811");
        assert!(parse_uuid("bad").is_none());
    }

    #[test]
    fn cfb128_roundtrip() {
        let key = [7u8; 16];
        let iv = [9u8; 16];
        let mut pt = b"hello cfb mode!!".to_vec();
        let orig = pt.clone();
        Cfb128Encryptor::new(&key, &iv).apply_xor(&mut pt);
        assert_ne!(pt, orig);
        Cfb128Decryptor::new(&key, &iv).apply_xor(&mut pt);
        assert_eq!(pt, orig);
    }

    #[test]
    fn ctr_keystream_symmetry() {
        let key = [3u8; 16];
        let nonce = [5u8; 16];
        let mut data = vec![1u8; 100];
        let orig = data.clone();
        Aes128Ctr::new(&key, &nonce).apply_keystream(&mut data);
        assert_ne!(data, orig);
        Aes128Ctr::new(&key, &nonce).apply_keystream(&mut data);
        assert_eq!(data, orig);
    }
}
