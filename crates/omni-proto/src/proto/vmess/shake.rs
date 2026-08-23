pub struct Shake128 {
    state: [u64; 25],
    pos: usize,
    finalized: bool,
}

const RATE: usize = 168;
const ROUND_CONSTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in ROUND_CONSTS.iter() {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    state[x + 5 * y].rotate_left((((x + 1) * (y + 2)) % 64) as u32);
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        state[0] ^= rc;
    }
}

impl Shake128 {
    pub fn new() -> Self {
        Shake128 {
            state: [0u64; 25],
            pos: 0,
            finalized: false,
        }
    }

    fn xor_byte(&mut self, idx: usize, byte: u8) {
        self.state[idx / 8] ^= (byte as u64) << ((idx % 8) * 8);
    }

    pub fn absorb(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (RATE - self.pos).min(data.len());
            for (i, &byte) in data[..take].iter().enumerate() {
                self.xor_byte(self.pos + i, byte);
            }
            self.pos += take;
            data = &data[take..];
            if self.pos == RATE {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    fn finalize(&mut self) {
        let pad_pos = self.pos;
        self.xor_byte(pad_pos, 0x1F);
        self.xor_byte(RATE - 1, 0x80);
        keccak_f1600(&mut self.state);
        self.pos = 0;
        self.finalized = true;
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.finalized {
            self.finalize();
        }
        for slot in out.iter_mut() {
            if self.pos == RATE {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            let idx = self.pos;
            *slot = ((self.state[idx / 8] >> ((idx % 8) * 8)) & 0xFF) as u8;
            self.pos += 1;
        }
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ShakeSizeParser {
    shake: Shake128,
}

impl ShakeSizeParser {
    pub fn new(nonce: &[u8]) -> Self {
        let mut s = Shake128::new();
        s.absorb(nonce);
        ShakeSizeParser { shake: s }
    }

    fn next(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.shake.squeeze(&mut b);
        u16::from_be_bytes(b)
    }

    pub fn next_padding_len(&mut self) -> u16 {
        self.next() % 64
    }

    pub fn max_padding_len(&self) -> u16 {
        64
    }

    pub fn encode(&mut self, size: u16) -> [u8; 2] {
        (size ^ self.next()).to_be_bytes()
    }

    pub fn decode(&mut self, b: &[u8; 2]) -> u16 {
        u16::from_be_bytes(*b) ^ self.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake128_empty_vector() {
        let mut s = Shake128::new();
        let mut out = [0u8; 32];
        s.squeeze(&mut out);
        let hex: String = out.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    }

    #[test]
    fn shake128_absorb_squeeze_consistency() {
        let mut a = Shake128::new();
        a.absorb(b"omni test nonce");
        let mut o1 = [0u8; 32];
        a.squeeze(&mut o1);

        let mut b = Shake128::new();
        b.absorb(b"omni test nonce");
        let mut chunked = Vec::new();
        for _ in 0..4 {
            let mut t = [0u8; 8];
            b.squeeze(&mut t);
            chunked.extend_from_slice(&t);
        }

        assert_eq!(o1.to_vec(), chunked);

        let mut c = Shake128::new();
        c.absorb(b"different");
        let mut o2 = [0u8; 32];
        c.squeeze(&mut o2);
        assert_ne!(o1.to_vec(), o2.to_vec());
    }
}
