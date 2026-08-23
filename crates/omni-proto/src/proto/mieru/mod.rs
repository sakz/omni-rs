pub mod crypto;
pub mod inbound;
pub mod outbound;

pub const METADATA_SIZE: usize = 32;
pub const TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 24;
pub const MAX_FRAGMENT: usize = 32768;
pub const OPEN_SESSION_PAYLOAD_MAX: usize = 1024;

pub const PROTO_DATA_C2S: u8 = 0;
pub const PROTO_DATA_S2C: u8 = 1;
pub const PROTO_OPEN_SESSION_REQ: u8 = 2;
pub const PROTO_OPEN_SESSION_RESP: u8 = 3;
pub const PROTO_CLOSE_SESSION_REQ: u8 = 4;
pub const PROTO_CLOSE_SESSION_RESP: u8 = 5;


/// Build a 32-byte metadata block (big-endian).
pub fn build_metadata(
    proto_type: u8,
    epoch_minute: u32,
    session_id: u32,
    seq: u32,
    status: u8,
    payload_len: u16,
    suffix_len: u8,
) -> [u8; METADATA_SIZE] {
    let mut m = [0u8; METADATA_SIZE];
    m[0] = proto_type;
    m[2..6].copy_from_slice(&epoch_minute.to_be_bytes());
    m[6..10].copy_from_slice(&session_id.to_be_bytes());
    m[10..14].copy_from_slice(&seq.to_be_bytes());
    m[14] = status;
    m[15..17].copy_from_slice(&payload_len.to_be_bytes());
    m[17] = suffix_len;
    m
}

#[derive(Debug, Clone)]
pub struct ParsedMetadata {
    pub proto_type: u8,
    pub epoch_minute: u32,
    pub session_id: u32,
    pub seq: u32,
    pub status: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

pub fn parse_metadata(m: &[u8; METADATA_SIZE]) -> ParsedMetadata {
    ParsedMetadata {
        proto_type: m[0],
        epoch_minute: u32::from_be_bytes([m[2], m[3], m[4], m[5]]),
        session_id: u32::from_be_bytes([m[6], m[7], m[8], m[9]]),
        seq: u32::from_be_bytes([m[10], m[11], m[12], m[13]]),
        status: m[14],
        payload_len: u16::from_be_bytes([m[15], m[16]]),
        suffix_len: m[17],
    }
}
