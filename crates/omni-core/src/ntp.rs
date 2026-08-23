use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct NtpResult {
    pub offset_ms: f64,
    pub rtt_ms: f64,
}

const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

fn now_ntp() -> u64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() + NTP_UNIX_OFFSET;
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

fn ntp_to_unix_secs(raw: &[u8]) -> f64 {
    if raw.len() < 8 {
        return 0.0;
    }
    let secs = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as f64;
    let frac = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) as f64 / 2f64.powi(32);
    secs - NTP_UNIX_OFFSET as f64 + frac
}

pub fn query(server: &str, timeout: Duration) -> std::io::Result<NtpResult> {
    let host = server.trim_start_matches("ntp://");
    let addr = if host.parse::<std::net::SocketAddr>().is_ok() {
        host.to_string()
    } else if host.contains(':') && !host.contains(']') {
        host.to_string()
    } else {
        format!("{}:123", host)
    };
    use std::net::ToSocketAddrs;
    let resolved = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "ntp: resolve failed"))?;

    let bind_local = if resolved.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind_local)?;
    sock.connect(resolved)?;

    let mut packet = [0u8; 48];
    packet[0] = 0x23;
    let t1 = now_ntp();
    packet[40..48].copy_from_slice(&t1.to_be_bytes());
    sock.send(&packet)?;

    sock.set_read_timeout(Some(timeout))?;
    let mut buf = [0u8; 48];
    let (n, _) = sock.recv_from(&mut buf)?;
    if n < 48 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ntp: short response",
        ));
    }

    let t4_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let t2 = ntp_to_unix_secs(&buf[32..40]);
    let t3 = ntp_to_unix_secs(&buf[40..48]);

    let offset = ((t2 - t4_unix) + (t3 - t4_unix)) / 2.0;
    let rtt = (t4_unix - t1_unix_f(t1)) - (t3 - t2);

    Ok(NtpResult {
        offset_ms: offset * 1000.0,
        rtt_ms: rtt.max(0.0) * 1000.0,
    })
}

fn t1_unix_f(ntp: u64) -> f64 {
    let secs = (ntp >> 32) as f64 - NTP_UNIX_OFFSET as f64;
    let frac = (ntp & 0xFFFF_FFFF) as f64 / 2f64.powi(32);
    secs + frac
}
