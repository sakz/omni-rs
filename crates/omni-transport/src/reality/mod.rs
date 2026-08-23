use crate::unsupported_transport;

pub async fn unsupported() -> std::io::Error {
    unsupported_transport("crates")
}
