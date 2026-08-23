use bytes::{BufMut, Bytes};

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;

pub const HEADER_SIZE: usize = 7;

#[derive(Debug, Clone)]
pub struct Frame {
    pub cmd: u8,
    pub sid: u32,
    pub data: Bytes,
}

impl Frame {
    pub fn new(cmd: u8, sid: u32) -> Self {
        Frame {
            cmd,
            sid,
            data: Bytes::new(),
        }
    }

    pub fn with_data(cmd: u8, sid: u32, data: impl Into<Bytes>) -> Self {
        Frame {
            cmd,
            sid,
            data: data.into(),
        }
    }

    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.put_u8(self.cmd);
        buf.put_u32(self.sid);
        buf.put_u16(self.data.len() as u16);
        buf.extend_from_slice(&self.data);
    }

    pub fn encode(self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_SIZE + self.data.len());
        self.encode_into(&mut v);
        v
    }
}

pub enum DecodeOutcome {
    NeedMore,
    Frame(Frame, usize),
}

pub fn try_decode(buf: &[u8]) -> std::io::Result<DecodeOutcome> {
    if buf.len() < HEADER_SIZE {
        return Ok(DecodeOutcome::NeedMore);
    }
    let cmd = buf[0];
    let sid = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let dlen = u16::from_be_bytes([buf[5], buf[6]]) as usize;
    if buf.len() < HEADER_SIZE + dlen {
        return Ok(DecodeOutcome::NeedMore);
    }
    let data = Bytes::copy_from_slice(&buf[HEADER_SIZE..HEADER_SIZE + dlen]);
    Ok(DecodeOutcome::Frame(
        Frame { cmd, sid, data },
        HEADER_SIZE + dlen,
    ))
}
