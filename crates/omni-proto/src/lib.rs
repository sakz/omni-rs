
pub mod common;
pub mod crypto;
pub mod mux_cool;
pub mod proto;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut v = [0u8; N];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut v);
    v
}

pub fn random_b64(len: usize) -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::STANDARD.encode(buf)
}
