use instant_acme::{Account, ChallengeType, Identifier, NewAccount, NewOrder};
use rcgen::{CertificateParams, DnType, KeyPair};
use sha2::Digest;
use std::io;


fn ioerr(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

pub fn key_authorization(token: &str, thumbprint_b64: &str) -> String {
    format!("{}.{}", token, thumbprint_b64)
}

pub fn tls_alpn_01_cert_value(key_auth: &str) -> [u8; 32] {
    use sha2::Sha256;
    Sha256::digest(key_auth.as_bytes()).into()
}

pub fn generate_validation_cert(
    domain: &str,
    key_auth_sha256: &[u8; 32],
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| ioerr(format!("acme: invalid domain: {}", e)))?;
    params
        .distinguished_name
        .push(DnType::CommonName, domain.to_string());

    let mut ext_der = vec![0x04, 0x20];
    ext_der.extend_from_slice(key_auth_sha256);
    params.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
        &[0x1B, 0x21, 0x57, 0x4A, 0x47, 0x44],
        ext_der,
    ));

    let key_pair = KeyPair::generate().map_err(|e| ioerr(format!("acme: keygen: {}", e)))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ioerr(format!("acme: sign: {}", e)))?;
    Ok((cert.pem().into_bytes(), key_pair.serialize_pem().into_bytes()))
}

pub async fn create_account(
    directory_url: &str,
    contact_email: &str,
) -> io::Result<Account> {
    let builder = Account::builder().map_err(|e| ioerr(e.to_string()))?;
    let contact = format!("mailto:{}", contact_email);
    let new_account = NewAccount {
        contact: &[contact.as_str()],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (account, _creds) = builder
        .create(&new_account, directory_url.to_string(), None)
        .await
        .map_err(|e| ioerr(format!("acme: account create failed: {}", e)))?;
    Ok(account)
}

pub async fn new_order_tls_alpn(
    account: &Account,
    domain: &str,
) -> io::Result<(instant_acme::Order, String)> {
    let mut order = account
        .new_order(&NewOrder::new(&[Identifier::Dns(domain.to_string())]))
        .await
        .map_err(|e| ioerr(format!("acme: order create failed: {}", e)))?;

    let mut authorizations = order.authorizations();

    while let Some(authz) = authorizations.next().await {
        let mut authz =
            authz.map_err(|e| ioerr(format!("acme: authorization fetch failed: {}", e)))?;
        if let Some(challenge) = authz.challenge(ChallengeType::TlsAlpn01) {
            let token = challenge.token.clone();
            return Ok((order, token));
        }
    }
    Err(ioerr("acme: no tls-alpn-01 challenge offered".to_string()))
}
