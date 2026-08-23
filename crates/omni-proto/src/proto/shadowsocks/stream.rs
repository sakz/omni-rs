use super::{increment_nonce, SsAead, NONCE_LEN};
use omni_domain::socks5::Socks5Addr;
use omni_domain::stream::ProxyTarget;
use tokio::io::{AsyncRead, AsyncReadExt};

pub struct AeadStreamReader<R> {
    inner: R,
    cipher: SsAead,
    nonce: [u8; NONCE_LEN],
    rbuf: Vec<u8>,
    rpos: usize,
    eof: bool,
}

impl<R: AsyncRead + Unpin> AeadStreamReader<R> {
    pub fn new(inner: R, cipher: SsAead, nonce: [u8; NONCE_LEN]) -> Self {
        AeadStreamReader {
            inner,
            cipher,
            nonce,
            rbuf: Vec::new(),
            rpos: 0,
            eof: false,
        }
    }

    pub fn take_stream(&mut self) -> &mut R {
        &mut self.inner
    }

    pub async fn read_target(&mut self) -> std::io::Result<ProxyTarget> {
        if self.rpos >= self.rbuf.len() && !self.eof {
            self.fill_chunk().await?;
        }
        let (addr, used) = Socks5Addr::decode(&self.rbuf[self.rpos..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.rpos += used;
        Ok(addr.to_proxy_target())
    }

    pub async fn read_data(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.rpos < self.rbuf.len() {
                let avail = self.rbuf.len() - self.rpos;
                let n = out.len().min(avail);
                out[..n].copy_from_slice(&self.rbuf[self.rpos..self.rpos + n]);
                self.rpos += n;
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            self.fill_chunk().await?;
        }
    }

    async fn fill_chunk(&mut self) -> std::io::Result<()> {
        let mut hdr = vec![0u8; 2 + 16];
        read_full(&mut self.inner, &mut hdr).await?;

        let mut len_ct = [hdr[0], hdr[1]];
        if !self.cipher.open(&self.nonce, b"", &mut len_ct, &hdr[2..18]) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "shadowsocks: length decrypt failed",
            ));
        }
        increment_nonce(&mut self.nonce);
        let len = u16::from_be_bytes(len_ct) as usize;
        if len > super::MAX_PAYLOAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "shadowsocks: payload too large",
            ));
        }

        let mut body = vec![0u8; len + 16];
        read_full(&mut self.inner, &mut body).await?;
        let tag = body.split_off(len);
        if !self.cipher.open(&self.nonce, b"", &mut body, &tag) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "shadowsocks: payload decrypt failed",
            ));
        }
        increment_nonce(&mut self.nonce);

        self.rbuf = body;
        self.rpos = 0;
        if len == 0 {
            self.eof = true;
        }
        Ok(())
    }
}

pub(crate) async fn read_full<R: AsyncRead + Unpin>(
    inner: &mut R,
    buf: &mut [u8],
) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let n = inner.read(&mut buf[off..]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "shadowsocks: stream closed mid-chunk",
            ));
        }
        off += n;
    }
    Ok(())
}

pub struct AeadStreamWriter<W> {
    inner: W,
    cipher: SsAead,
    nonce: [u8; NONCE_LEN],
}

impl<W: tokio::io::AsyncWrite + Unpin> AeadStreamWriter<W> {
    pub fn new(inner: W, cipher: SsAead, nonce: [u8; NONCE_LEN]) -> Self {
        AeadStreamWriter {
            inner,
            cipher,
            nonce,
        }
    }

    pub async fn write_chunk(&mut self, data: &[u8], flush: bool) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        for piece in data.chunks(super::MAX_PAYLOAD) {
            let mut hdr = (piece.len() as u16).to_be_bytes().to_vec();
            let ltag = self.seal(&mut hdr).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "shadowsocks: encrypt failed")
            })?;
            let mut payload = piece.to_vec();
            let ptag = self.seal(&mut payload).unwrap();

            self.inner.write_all(&hdr).await?;
            self.inner.write_all(&ltag).await?;
            self.inner.write_all(&payload).await?;
            self.inner.write_all(&ptag).await?;
        }
        if flush {
            self.inner.flush().await?;
        }
        Ok(())
    }

    fn seal(&mut self, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
        let t = self.cipher.seal(&self.nonce, b"", buf)?;
        increment_nonce(&mut self.nonce);
        Some(t)
    }
}
