pub mod accept;
pub mod dial;
pub mod grpc;
pub mod h2;
pub mod httpup;
pub mod ktls;
pub mod proxy_protocol;
pub mod quic;
pub mod quiche_naive;
pub mod reality;
pub mod routing;
pub mod tls;
pub mod ws;
pub mod xhttp;

pub fn unsupported_transport(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("transport '{}' not yet implemented", what),
    )
}
