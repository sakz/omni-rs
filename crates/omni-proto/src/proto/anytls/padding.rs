pub const DEFAULT_EMPTY_SCHEME_MD5_INPUT: &[u8] = b"";

pub fn scheme_md5(raw: &[u8]) -> String {
    crate::crypto::hex_encode(&crate::crypto::md5::digest(&[raw]))
}
