use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

pub fn init_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct ServerCertMaterial {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

pub struct TlsSpecView<'a> {
    pub cert_mode: Option<&'a str>,
    pub cert_domain: Option<&'a str>,
    pub cert_file: Option<&'a str>,
    pub key_file: Option<&'a str>,
    pub cert_content: Option<&'a str>,
    pub key_content: Option<&'a str>,
}

pub fn resolve_tls_pems(
    spec: &TlsSpecView<'_>,
    email_present: bool,
) -> Result<ServerCertMaterial, String> {
    match spec.cert_mode {
        Some("file") => {
            let cert_file = spec.cert_file.unwrap_or_default();
            let key_file = spec.key_file.unwrap_or_default();
            if cert_file.is_empty() || key_file.is_empty() {
                return Err("cert_mode=file requires cert_file and key_file paths".to_string());
            }
            let cert = std::fs::read(cert_file)
                .map_err(|e| format!("cert: failed to read {}: {}", cert_file, e))?;
            let key = std::fs::read(key_file)
                .map_err(|e| format!("cert: failed to read {}: {}", key_file, e))?;
            Ok(ServerCertMaterial { cert_pem: cert, key_pem: key })
        }
        Some("content") => {
            let cert = spec.cert_content.unwrap_or_default();
            let key = spec.key_content.unwrap_or_default();
            if cert.is_empty() {
                return Err("cert_mode=content requires cert_content".to_string());
            }
            if key.is_empty() {
                return Err("cert_mode=content requires key_content".to_string());
            }
            Ok(ServerCertMaterial {
                cert_pem: cert.as_bytes().to_vec(),
                key_pem: key.as_bytes().to_vec(),
            })
        }
        Some("self") => {
            let domain = spec.cert_domain.unwrap_or_default();
            if domain.is_empty() {
                return Err("cert_mode=self requires cert_domain".to_string());
            }
            generate_self_signed(domain).map_err(|e| format!("cert.generate: {}", e))
        }
        Some("acme") => {
            if !email_present {
                return Err("acme.email must not be empty".to_string());
            }
            Err("acme: no DNS provider configured in this build".to_string())
        }
        other => Err(format!(
            "cert: unsupported cert_mode: {}",
            other.unwrap_or("")
        )),
    }
}

pub fn generate_self_signed(domain: &str) -> Result<ServerCertMaterial, String> {
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| format!("invalid domain '{}': {}", domain, e))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain.to_string());
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| format!("key generation failed: {}", e))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("signing failed: {}", e))?;
    Ok(ServerCertMaterial {
        cert_pem: cert.pem().into_bytes(),
        key_pem: key_pair.serialize_pem().into_bytes(),
    })
}

pub fn build_rustls_server_config(
    material: &ServerCertMaterial,
    alpn: &[String],
) -> Result<Arc<rustls::ServerConfig>, String> {
    init_crypto_provider();
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> = rustls_pemfile::certs(
        &mut material.cert_pem.as_slice(),
    )
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| format!("tls: failed to parse certificate PEM: {}", e))?;
    if certs.is_empty() {
        return Err("tls: no certificates found in PEM".to_string());
    }
    let key_der = rustls_pemfile::private_key(&mut material.key_pem.as_slice())
        .map_err(|e| format!("tls: failed to parse private key PEM: {}", e))?
        .ok_or_else(|| "tls: no private key found in PEM".to_string())?;

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .map_err(|e| format!("tls: invalid certificate/key pair: {}", e))?;
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    }
    Ok(Arc::new(cfg))
}

pub fn build_server_config(
    material: &ServerCertMaterial,
    alpn: &[String],
) -> Result<TlsAcceptor, String> {
    let cfg = build_rustls_server_config(material, alpn)?;
    Ok(TlsAcceptor::from(cfg))
}


pub struct ClientTlsSettings {
    pub skip_verify: bool,
    pub alpn: Vec<String>,
    pub server_name_override: Option<String>,
}

pub fn build_client_config(settings: &ClientTlsSettings) -> Result<Arc<rustls::ClientConfig>, String> {
    init_crypto_provider();
    let builder = rustls::ClientConfig::builder();
    let cfg = if settings.skip_verify {
        let mut c = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        apply_alpn(&mut c, &settings.alpn);
        c
    } else {
        let mut c = builder
            .with_root_certificates(default_roots())
            .with_no_client_auth();
        apply_alpn(&mut c, &settings.alpn);
        c
    };
    Ok(Arc::new(cfg))
}

fn apply_alpn(c: &mut rustls::ClientConfig, alpn: &[String]) {
    if !alpn.is_empty() {
        c.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    }
}

fn default_roots() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

#[derive(Debug)]
pub struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

pub fn server_name_for(host: &str, override_name: Option<&str>) -> String {
    let name = override_name.unwrap_or(host);
    name.split(':').next().unwrap_or(name).to_string()
}
