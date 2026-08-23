use crate::proto::vmess::shake::ShakeSizeParser;
use std::io;

async fn read_exact_vec<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    n: usize,
) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut v = vec![0u8; n];
    r.read_exact(&mut v).await?;
    Ok(v)
}

pub const MAX_CHUNK: usize = 0x3FFF;

#[derive(Clone)]
pub struct ChunkKeys {
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

impl ChunkKeys {
    fn nonce_for(&self, counter: u16) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&counter.to_be_bytes());
        n[2..].copy_from_slice(&self.iv[2..12]);
        n
    }
}

pub fn chacha_key(key16: &[u8; 16]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let out: [u8; 32] = Sha256::digest(key16).into();
    out
}

#[derive(Clone, Copy)]
pub enum ChunkSecurity {
    None,
    Gcm,
    ChaCha,
}

pub struct ChunkReader<R> {
    inner: R,
    keys: ChunkKeys,
    security: ChunkSecurity,
    masking: bool,
    padding: bool,
    size_parser: ShakeSizeParser,
    counter: u16,
    pending: Vec<u8>,
    ppos: usize,
    eof: bool,
}

impl<R: tokio::io::AsyncRead + Unpin> ChunkReader<R> {
    pub fn new(
        inner: R,
        keys: ChunkKeys,
        security: ChunkSecurity,
        masking: bool,
        global_padding: bool,
    ) -> Self {
        let parser_src = keys.iv;
        ChunkReader {
            inner,
            keys,
            security,
            masking,
            padding: global_padding,
            size_parser: ShakeSizeParser::new(&parser_src),
            counter: 0,
            pending: Vec::new(),
            ppos: 0,
            eof: false,
        }
    }

    fn next_nonce(&mut self) -> Option<[u8; 12]> {
        match self.security {
            ChunkSecurity::None => None,
            _ => {
                let n = self.keys.nonce_for(self.counter);
                self.counter = self.counter.wrapping_add(1);
                Some(n)
            }
        }
    }

    pub async fn read_data(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.ppos < self.pending.len() {
                let avail = self.pending.len() - self.ppos;
                let n = out.len().min(avail);
                out[..n].copy_from_slice(&self.pending[self.ppos..self.ppos + n]);
                self.ppos += n;
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            self.fill_chunk().await?;
        }
    }

    async fn fill_chunk(&mut self) -> io::Result<()> {
        let padding_len = if self.padding {
            self.size_parser.next_padding_len() as usize
        } else {
            0
        };

        let masked_size = read_exact_vec(&mut self.inner, 2).await?;
        let decoded_size = if self.masking {
            let arr: [u8; 2] = masked_size.try_into().unwrap();
            self.size_parser.decode(&arr)
        } else {
            u16::from_be_bytes(masked_size.try_into().unwrap())
        };

        let overhead = match self.security {
            ChunkSecurity::None => 0,
            _ => 16,
        };

        if decoded_size as usize == overhead + padding_len {
            self.eof = true;
            return Ok(());
        }

        if (decoded_size as usize) < overhead + padding_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vmess: invalid chunk size",
            ));
        }

        let payload_ct = decoded_size as usize - padding_len;
        let mut buf = read_exact_vec(&mut self.inner, payload_ct).await?;
        if padding_len > 0 {
            read_exact_vec(&mut self.inner, padding_len).await?;
        }

        let is_none_sec = matches!(self.security, ChunkSecurity::None);
        let plain = if is_none_sec {
            buf
        } else {
            let nonce = self.next_nonce().unwrap();
            let ok = match self.security {
                ChunkSecurity::Gcm => aead_open_gcm(&self.keys.key, &nonce, &mut buf),
                ChunkSecurity::ChaCha => {
                    aead_open_chacha(&chacha_key(&self.keys.key), &nonce, &mut buf)
                }
                ChunkSecurity::None => unreachable!(),
            };
            if !ok {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vmess: chunk decrypt failed",
                ));
            }
            buf.truncate(payload_ct - overhead);
            buf
        };

        self.pending = plain;
        self.ppos = 0;
        Ok(())
    }
}

pub struct ChunkWriter<W> {
    inner: W,
    keys: ChunkKeys,
    security: ChunkSecurity,
    masking: bool,
    padding: bool,
    size_parser: ShakeSizeParser,
    counter: u16,
}

impl<W> ChunkWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    pub fn new(
        inner: W,
        keys: ChunkKeys,
        security: ChunkSecurity,
        masking: bool,
        global_padding: bool,
    ) -> Self {
        let parser_src = keys.iv;
        ChunkWriter {
            inner,
            keys,
            security,
            masking,
            padding: global_padding,
            size_parser: ShakeSizeParser::new(&parser_src),
            counter: 0,
        }
    }

    fn next_nonce(&mut self) -> Option<[u8; 12]> {
        match self.security {
            ChunkSecurity::None => None,
            _ => {
                let n = self.keys.nonce_for(self.counter);
                self.counter = self.counter.wrapping_add(1);
                Some(n)
            }
        }
    }

    pub async fn write_chunk(&mut self, data: &[u8], flush: bool) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        for piece in data.chunks(MAX_CHUNK) {
            let overhead = match self.security {
                ChunkSecurity::None => 0,
                _ => 16,
            };
            let padding_len = if self.padding && !piece.is_empty() {
                self.size_parser.next_padding_len() as usize
            } else {
                0
            };
            let total = piece.len() + overhead + padding_len;
            if total > u16::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vmess: chunk too large",
                ));
            }

            let size_field = total as u16;
            let size_bytes = if self.masking {
                self.size_parser.encode(size_field).to_vec()
            } else {
                size_field.to_be_bytes().to_vec()
            };
            self.inner.write_all(&size_bytes).await?;

            let nonce = self.next_nonce();
            match &self.security {
                ChunkSecurity::None => self.inner.write_all(piece).await?,
                sec => {
                    let nonce = nonce.unwrap();
                    let mut payload = piece.to_vec();
                    match sec {
                        ChunkSecurity::Gcm => aead_seal_gcm(&self.keys.key, &nonce, &mut payload)?,
                        ChunkSecurity::ChaCha => {
                            aead_seal_chacha(&chacha_key(&self.keys.key), &nonce, &mut payload)?
                        }
                        ChunkSecurity::None => unreachable!(),
                    }
                    self.inner.write_all(&payload).await?;
                }
            }

            if padding_len > 0 {
                let pad = crate::random_bytes::<64>();
                self.inner.write_all(&pad[..padding_len]).await?;
            }
        }

        if data.is_empty() {
            let overhead = match self.security {
                ChunkSecurity::None => 0,
                _ => 16,
            };
            let is_none = matches!(self.security, ChunkSecurity::None);
            let padding_len = if self.padding {
                self.size_parser.next_padding_len() as usize
            } else {
                0
            };
            let total = (overhead + padding_len) as u16;
            let size_bytes = if self.masking {
                self.size_parser.encode(total).to_vec()
            } else {
                total.to_be_bytes().to_vec()
            };
            self.inner.write_all(&size_bytes).await?;
            if !is_none {
                let nonce = self.keys.nonce_for(self.counter);
                self.counter = self.counter.wrapping_add(1);
                let mut empty = Vec::new();
                match self.security {
                    ChunkSecurity::Gcm => aead_seal_gcm(&self.keys.key, &nonce, &mut empty)?,
                    ChunkSecurity::ChaCha => {
                        aead_seal_chacha(&chacha_key(&self.keys.key), &nonce, &mut empty)?
                    }
                    ChunkSecurity::None => {}
                }
                self.inner.write_all(&empty).await?;
            }
            if padding_len > 0 {
                let pad = crate::random_bytes::<64>();
                self.inner.write_all(&pad[..padding_len]).await?;
            }
        }

        if flush {
            self.inner.flush().await?;
        }
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

fn aead_seal_gcm(key: &[u8; 16], nonce: &[u8; 12], plaintext: &mut Vec<u8>) -> io::Result<()> {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    let cipher =
        aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| io::Error::other("vmess: gcm init"))?;
    let tag = cipher
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), b"", plaintext)
        .map_err(|_| io::Error::other("vmess: encrypt failed"))?;
    plaintext.extend_from_slice(tag.as_slice());
    Ok(())
}

fn aead_seal_chacha(key: &[u8; 32], nonce: &[u8; 12], plaintext: &mut Vec<u8>) -> io::Result<()> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| io::Error::other("vmess: chacha init"))?;
    let tag = cipher
        .encrypt_in_place_detached(chacha20poly1305::Nonce::from_slice(nonce), b"", plaintext)
        .map_err(|_| io::Error::other("vmess: encrypt failed"))?;
    plaintext.extend_from_slice(tag.as_slice());
    Ok(())
}

fn aead_open_gcm(key: &[u8; 16], nonce: &[u8; 12], data: &mut [u8]) -> bool {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    let Ok(cipher) = aes_gcm::Aes128Gcm::new_from_slice(key) else {
        return false;
    };
    let Some(ct_len) = data.len().checked_sub(16) else {
        return false;
    };
    let (ct, tag_bytes) = data.split_at_mut(ct_len);
    let tag = aes_gcm::Tag::clone_from_slice(tag_bytes);
    cipher
        .decrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), b"", ct, &tag)
        .is_ok()
}

fn aead_open_chacha(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) -> bool {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    let Ok(cipher) = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key) else {
        return false;
    };
    let Some(ct_len) = data.len().checked_sub(16) else {
        return false;
    };
    let (ct, tag_bytes) = data.split_at_mut(ct_len);
    let tag = chacha20poly1305::Tag::clone_from_slice(tag_bytes);
    cipher
        .decrypt_in_place_detached(chacha20poly1305::Nonce::from_slice(nonce), b"", ct, &tag)
        .is_ok()
}
