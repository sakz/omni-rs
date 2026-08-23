use omni_domain::socks5::{self, read_greeting, read_request, write_method_choice, write_reply, Command, Method, Socks5Addr};
use omni_domain::stream::{ProxyStream, ProxyTarget};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Default, Clone)]
pub struct SocksInboundConfig {
    pub username: Option<String>,
    pub password: Option<String>,
}

pub enum Accepted<S> {
    Tcp {
        target: ProxyTarget,
        stream: S,
    },
    UdpAssociate {
        stream: S,
    },
}

pub async fn handshake<S>(mut stream: S, cfg: &SocksInboundConfig) -> std::io::Result<Accepted<S>>
where
    S: ProxyStream,
{
    let methods = read_greeting(&mut stream).await?;
    let need_auth = cfg.username.is_some();
    let chosen = if need_auth && methods.contains(&0x02) {
        Method::UserPass
    } else if !need_auth && methods.contains(&0x00) {
        Method::NoAuth
    } else {
        write_method_choice(&mut stream, Method::NoAcceptable).await?;
        return Err(socks5::io_err("socks5: no acceptable auth method offered"));
    };
    write_method_choice(&mut stream, chosen).await?;

    if need_auth {
        let hdr = socks5::read_exact(&mut stream, 2).await?;
        if hdr[0] != 0x01 {
            return Err(socks5::io_err("socks5: bad subnegotiation version"));
        }
        let user = String::from_utf8_lossy(&socks5::read_exact(&mut stream, hdr[1] as usize).await?).to_string();
        let plen = socks5::read_exact(&mut stream, 1).await?[0] as usize;
        let pass = String::from_utf8_lossy(&socks5::read_exact(&mut stream, plen).await?).to_string();
        let ok = cfg.username.as_deref() == Some(user.as_str())
            && cfg.password.as_deref() == Some(pass.as_str());
        stream.write_all(&[0x01, u8::from(!ok)]).await?;
        if !ok {
            return Err(socks5::io_err("socks5: authentication failed"));
        }
    }

    let (cmd, addr) = read_request(&mut stream).await?;
    match cmd {
        Command::Connect => {
            write_reply(&mut stream, socks5::REP_SUCCEEDED, Some(&addr)).await?;
            Ok(Accepted::Tcp {
                target: addr.to_proxy_target(),
                stream,
            })
        }
        Command::UdpAssociate => Ok(Accepted::UdpAssociate { stream }),
        Command::Bind => {
            write_reply(&mut stream, socks5::REP_COMMAND_NOT_SUPPORTED, None).await?;
            Err(socks5::io_err("socks5: BIND not supported"))
        }
    }
}

pub fn parse_udp_packet(buf: &[u8]) -> std::io::Result<(Socks5Addr, bytes::Bytes)> {
    if buf.len() < 4 {
        return Err(socks5::io_err("socks5: empty address buffer"));
    }
    if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        return Err(socks5::io_err("socks5: bad UDP RSV/FRAG"));
    }
    let (addr, used) = Socks5Addr::decode(&buf[3..])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if buf.len() < 3 + used {
        return Err(socks5::io_err("socks5: UDP packet truncated"));
    }
    Ok((addr, bytes::Bytes::copy_from_slice(&buf[3 + used..])))
}

pub fn encode_udp_packet(addr: &Socks5Addr, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8, 0, 0];
    addr.encode_into(&mut out);
    out.extend_from_slice(data);
    out
}

pub mod client {
    use super::*;
    use omni_domain::stream::{UdpHandle, UdpPacket};
    use std::sync::Arc;
    use tokio::net::{TcpStream, UdpSocket};
    use tokio::sync::mpsc;

    #[derive(Debug, Clone, Default)]
    pub struct SocksOutboundConfig {
        pub server: String,
        pub server_port: u16,
        pub username: Option<String>,
        pub password: Option<String>,
    }

    async fn dial_server(cfg: &SocksOutboundConfig) -> std::io::Result<TcpStream> {
        let addr = resolve_sock_addr(&cfg.server, cfg.server_port).await?;
        TcpStream::connect(addr).await
    }

    pub(crate) async fn resolve_sock_addr(
        host: &str,
        port: u16,
    ) -> std::io::Result<std::net::SocketAddr> {
        if let Ok(a) = host.parse::<std::net::IpAddr>() {
            return Ok(std::net::SocketAddr::new(a, port));
        }
        let mut addrs = tokio::net::lookup_host((host, port)).await?;
        addrs.next().ok_or_else(|| socks5::io_err("dns: no address records found"))
    }

    async fn negotiate(stream: &mut TcpStream, cfg: &SocksOutboundConfig) -> std::io::Result<()> {
        let mut methods: Vec<u8> = vec![0x00];
        if cfg.username.is_some() {
            methods.insert(0, 0x02);
        }
        stream.write_all(&[socks5::VER, methods.len() as u8]).await?;
        stream.write_all(&methods).await?;
        let resp = socks5::read_exact(stream, 2).await?;
        if resp[0] != socks5::VER {
            return Err(socks5::io_err("socks5: bad version in method reply"));
        }
        match Method::from_u8(resp[1]) {
            Some(Method::NoAuth) => Ok(()),
            Some(Method::UserPass) => {
                let u = cfg.username.as_deref().unwrap_or("");
                let p = cfg.password.as_deref().unwrap_or("");
                let mut msg = vec![0x01, u.len() as u8];
                msg.extend_from_slice(u.as_bytes());
                msg.push(p.len() as u8);
                msg.extend_from_slice(p.as_bytes());
                stream.write_all(&msg).await?;
                let st = socks5::read_exact(stream, 2).await?;
                if st[1] != 0x00 {
                    return Err(socks5::io_err("socks5: authentication failed"));
                }
                Ok(())
            }
            _ => Err(socks5::io_err("socks5: no acceptable auth method offered")),
        }
    }

    async fn request(
        stream: &mut TcpStream,
        cmd: Command,
        addr: &Socks5Addr,
    ) -> std::io::Result<Socks5Addr> {
        let mut req = vec![socks5::VER, cmd.to_u8(), 0x00];
        addr.encode_into(&mut req);
        stream.write_all(&req).await?;
        let head = socks5::read_exact(stream, 4).await?;
        if head[1] != socks5::REP_SUCCEEDED {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("socks5: connect refused rep=0x{:02x}", head[1]),
            ));
        }
        let (bind, used) = Socks5Addr::decode(&head[3..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if used > 4 {
            socks5::read_exact(stream, used - 4).await?;
        }
        Ok(bind)
    }

    pub async fn connect_tcp(
        cfg: &SocksOutboundConfig,
        target: &ProxyTarget,
    ) -> std::io::Result<TcpStream> {
        let mut s = dial_server(cfg).await?;
        negotiate(&mut s, cfg).await?;
        request(&mut s, Command::Connect, &Socks5Addr::from_proxy_target(target)).await?;
        Ok(s)
    }

    pub async fn connect_udp(cfg: &SocksOutboundConfig) -> std::io::Result<UdpHandle> {
        let mut ctrl = dial_server(cfg).await?;
        negotiate(&mut ctrl, cfg).await?;
        let zero = Socks5Addr::V4([0, 0, 0, 0], 0);
        let bind = request(&mut ctrl, Command::UdpAssociate, &zero).await?;
        let bind_ip = match bind {
            Socks5Addr::V4(ip, _) => std::net::IpAddr::V4(ip.into()),
            Socks5Addr::V6(ip, _) => std::net::IpAddr::V6(ip.into()),
            _ => return Err(socks5::io_err("socks5: bad UDP relay bind address")),
        };
        let local = UdpSocket::bind("0.0.0.0:0").await?;
        {
            let bind_port = udp_relay_port(&bind);
            let server_addr = resolve_sock_addr(&cfg.server, cfg.server_port).await?;
            let ip = if bind_ip.is_unspecified() { server_addr.ip() } else { bind_ip };
            local.connect(std::net::SocketAddr::new(ip, bind_port)).await?;
        }

        let (tx_out, mut rx_out) = mpsc::channel::<UdpPacket>(256);
        let (tx_in, rx_in) = mpsc::channel::<UdpPacket>(256);

        let sock = Arc::new(local);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    r = sock.recv(&mut buf) => {
                        match r {
                            Ok(n) => {
                                if n < 4 { continue; }
                                match parse_udp_packet(&buf[..n]) {
                                    Ok((addr, data)) => {
                                        let pkt = UdpPacket { source: None, target: addr.to_proxy_target(), data };
                                        if tx_in.send(pkt).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => continue,
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    p = rx_out.recv() => {
                        match p {
                            Some(pkt) => {
                                let sa = Socks5Addr::from_proxy_target(&pkt.target);
                                let frame = encode_udp_packet(&sa, &pkt.data);
                                if sock.send(&frame).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            let _ = ctrl.shutdown().await;
        });

        Ok(UdpHandle::new(tx_out, rx_in))
    }

    fn udp_relay_port(bind: &Socks5Addr) -> u16 {
        match bind {
            Socks5Addr::V4(_, p) | Socks5Addr::V6(_, p) | Socks5Addr::Domain(_, p) => *p,
        }
    }
}
