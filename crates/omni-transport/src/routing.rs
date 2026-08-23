use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, Default)]
pub struct SniffResult {
    pub host: Option<String>,
    pub protocol: &'static str,
}

const SNI_MAX_READ: usize = 1024;
const HTTP_MAX_READ: usize = 8 * 1024;

pub async fn sniff<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<SniffResult> {
    let mut buf = Vec::with_capacity(SNI_MAX_READ);
    let mut tmp = [0u8; 512];

    loop {
        if let Some(res) = try_sniff(&buf) {
            return Ok(res);
        }
        if buf.len() > HTTP_MAX_READ {
            return Ok(SniffResult {
                host: None,
                protocol: "unknown",
            });
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(SniffResult {
                host: None,
                protocol: "unknown",
            });
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn try_sniff(buf: &[u8]) -> Option<SniffResult> {
    if buf.len() >= 5 && buf[0] == 0x16 && buf[1] == 0x03 {
        if let Some(host) = parse_sni(buf) {
            return Some(SniffResult {
                host: Some(host),
                protocol: "tls",
            });
        }
    }
    if looks_like_http(buf) {
        if let Some(host) = parse_http_host_header(buf) {
            return Some(SniffResult {
                host: Some(host),
                protocol: "http",
            });
        }
    }
    None
}

pub fn looks_like_http(buf: &[u8]) -> bool {
    for method in [
        b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"OPTI", b"PATC", b"CONN",
    ] {
        if buf.starts_with(method) {
            return true;
        }
    }
    false
}

pub fn parse_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 43 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + rec_len {
        return None;
    }
    let hs_type = buf[5];
    if hs_type != 0x01 {
        return None;
    }
    let p = 43usize;
    let sid_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    let mut q = p + 2 + sid_len;
    if q + 2 > buf.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[q], buf[q + 1]]) as usize;
    q += 2 + cs_len;
    if q >= buf.len() {
        return None;
    }
    let cm_len = buf[q] as usize;
    q += 1 + cm_len;
    if q + 2 > buf.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([buf[q], buf[q + 1]]) as usize;
    q += 2;
    let ext_end = (q + ext_len).min(buf.len());
    while q + 4 <= ext_end {
        let etype = u16::from_be_bytes([buf[q], buf[q + 1]]);
        let elen = u16::from_be_bytes([buf[q + 2], buf[q + 3]]) as usize;
        let body_start = q + 4;
        if etype == 0x0000 {
            if body_start + 5 > body_start + elen || body_start + elen > buf.len() {
                return None;
            }
            let list_len = u16::from_be_bytes([buf[body_start], buf[body_start + 1]]) as usize;
            let mut r = body_start + 2;
            let list_end = (body_start + 2 + list_len).min(body_start + elen);
            while r + 3 <= list_end {
                let name_type = buf[r];
                let nlen = u16::from_be_bytes([buf[r + 1], buf[r + 2]]) as usize;
                let ns = r + 3;
                if name_type == 0 && ns + nlen <= list_end {
                    if let Ok(s) = std::str::from_utf8(&buf[ns..ns + nlen]) {
                        return Some(s.to_string());
                    }
                    return None;
                }
                r = ns + nlen;
            }
            return None;
        }
        q = body_start + elen;
    }
    None
}

pub fn parse_http_host_header(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = strip_prefix_ci(line, "host:") {
            let h = rest.trim().to_string();
            if !h.is_empty() {
                return Some(strip_port(&h));
            }
        }
    }
    None
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn strip_port(host: &str) -> String {
    if let Some(start) = host.find('[') {
        if let Some(end) = host[start..].find(']') {
            return host[start + 1..start + end].to_string();
        }
        return host.to_string();
    }
    match host.split_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => h.to_string(),
        _ => host.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_parse_min_clienthello() {
        let host = b"example.com";

        let entry_len = 1 + 2 + host.len();
        let mut list = (entry_len as u16).to_be_bytes().to_vec();
        list.push(0x00);
        list.extend_from_slice(&(host.len() as u16).to_be_bytes());
        list.extend_from_slice(host);

        let mut sni_ext_body = (list.len() as u16).to_be_bytes().to_vec();
        sni_ext_body.truncate(0);
        sni_ext_body.extend_from_slice(&(list.len() as u16).to_be_bytes());
        sni_ext_body.extend_from_slice(&list);
        let _ = sni_ext_body.clone();

        let mut ext = vec![0x00u8, 0x00];
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let blen = body.len() as u32;
        let mut hs = vec![0x01u8, 0x00, (blen >> 8) as u8, blen as u8];
        hs.extend_from_slice(&body);

        let mut msg = vec![0x16, 0x03, 0x01];
        msg.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&hs);

        assert_eq!(parse_sni(&msg).as_deref(), Some("example.com"));
    }

    #[test]
    fn http_host_parse() {
        let req = b"GET / HTTP/1.1\r\nHost: www.Example.COM:8443\r\n\r\n";
        assert_eq!(
            parse_http_host_header(req).as_deref(),
            Some("www.Example.COM")
        );
    }

    #[test]
    fn strip_port_cases() {
        assert_eq!(strip_port("a.com:99"), "a.com");
        assert_eq!(strip_port("[::1]:80"), "::1");
        assert_eq!(strip_port("plain"), "plain");
    }
}
