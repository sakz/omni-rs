use super::node_builder::{InboundProto, NodePlan, WrapTransport};
use crate::pipeline::executor as pipe_exec;
use crate::pipeline::inspector;
use crate::pipeline::PipelineShared;
use omni_domain::stream::BoxProxyStream;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct ListenerSet {
    pub tasks: Vec<tokio::task::JoinHandle<std::io::Result<()>>>,
}

pub async fn spawn_listeners(
    plans: Vec<Arc<NodePlan>>,
    shared_of: impl Fn(&str) -> PipelineShared,
) -> std::io::Result<ListenerSet> {
    let mut tasks = Vec::new();
    for plan in plans {
        for addr in &plan.listen_addrs {
            let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("listener '{}' bind {}: {}", plan.tag, addr, e),
                )
            })?;
            tracing::info!(
                target: "internal.listener",
                "listening inbound={} proto={} addr={}",
                plan.tag,
                proto_name(&plan.proto),
                addr
            );
            let plan = plan.clone();
            let shared = shared_of(&plan.tag);
            tasks.push(tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((sock, peer)) => {
                            let _ = sock.set_nodelay(true);
                            let plan = plan.clone();
                            let shared = shared.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_stream(plan, shared, sock, peer).await
                                {
                                    tracing::debug!(
                                        target: "internal.pipeline",
                                        "stream ended error={}", e
                                    );
                                }
                            });
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
            }));
        }
    }
    Ok(ListenerSet { tasks })
}

fn proto_name(p: &InboundProto) -> &'static str {
    match p {
        InboundProto::Socks(_) => "socks",
        InboundProto::Trojan(_) => "trojan",
        InboundProto::Shadowsocks(_) => "shadowsocks",
        InboundProto::Vless(_) => "vless",
        InboundProto::Vmess(_) => "vmess",
        InboundProto::Hysteria2 { .. } => "hysteria2",
        InboundProto::Anytls { .. } => "anytls",
        InboundProto::Naive => "naive",
        InboundProto::Mieru { .. } => "mieru",
    }
}

async fn accept_tls(
    raw: tokio::net::TcpStream,
    setup: &super::node_builder::TlsServerSetup,
) -> std::io::Result<BoxProxyStream> {
    let material = omni_transport::tls::ServerCertMaterial {
        cert_pem: setup.material_cert.clone(),
        key_pem: setup.material_key.clone(),
    };
    let acceptor = omni_transport::tls::build_server_config(&material, &setup.alpn)
        .map_err(std::io::Error::other)?;
    let s = acceptor.accept(raw).await?;
    Ok(omni_domain::stream::boxed(s))
}

async fn handle_stream(
    plan: Arc<NodePlan>,
    shared: PipelineShared,
    mut sock: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
) -> std::io::Result<()> {
    if matches!(plan.proto, InboundProto::Naive) {
        let stream: BoxProxyStream = match &plan.tls {
            Some(setup) => accept_tls(sock, setup).await?,
            None => omni_domain::stream::boxed(sock),
        };
        // sock moved into the branch above; subsequent code unreachable for Naive
        shared.counters.add_conn();
        let shared2 = shared.clone();
        omni_transport::h2::serve_connect(stream, move |s: BoxProxyStream, authority| {
            let shared = shared2.clone();
            Box::pin(async move {
                let target = crate::runtime::core::parse_naive_authority(&authority);
                run_tcp_route(shared, s, target, Vec::new(), None).await
            })
        })
        .await?;
        return Ok(());
    }

    if plan.accept_proxy_protocol {
        let header = omni_transport::proxy_protocol::read_header_from(&mut sock).await?;
        tracing::debug!(target: "internal.transport", "proxy-protocol src={:?}", header);
    }

    let plan_proto = plan.proto.clone();
    match (&plan.tls, &plan.wrap) {
        (_, WrapTransport::Grpc(service)) => {
            let stream: BoxProxyStream = match &plan.tls {
                Some(setup) => accept_tls(sock, setup).await?,
                None => omni_domain::stream::boxed(sock),
            };
            let shared2 = shared.clone();
            let handler: omni_transport::h2::StreamHandler =
                Arc::new(move |s: BoxProxyStream| {
                    let shared = shared2.clone();
                    let proto = plan_proto.clone();
                    Box::pin(async move { run_proto_pipeline(shared, &proto, s).await })
                });
            omni_transport::grpc::serve(stream, service, handler)
            .await?;
            return Ok(());
        }
        (_, WrapTransport::H2 { path, .. }) => {
            let stream: BoxProxyStream = match &plan.tls {
                Some(setup) => accept_tls(sock, setup).await?,
                None => omni_domain::stream::boxed(sock),
            };
            let shared2 = shared.clone();
            omni_transport::h2::serve_requests(
                stream,
                path.clone(),
                {
                    let handler: omni_transport::h2::StreamHandler =
                        Arc::new(move |s: BoxProxyStream| {
                            let shared = shared2.clone();
                            let proto = plan_proto.clone();
                            Box::pin(async move { run_proto_pipeline(shared, &proto, s).await })
                        });
                    handler
                },
            )
            .await?;
            return Ok(());
        }
        _ => {}
    }

    let stream: BoxProxyStream = match (&plan.tls, &plan.wrap) {
        (Some(setup), WrapTransport::None) => accept_tls(sock, setup).await?,
        (Some(setup), WrapTransport::Ws(spec)) => {
            let tls_stream = accept_tls(sock, setup).await?;
            let ws = omni_transport::ws::handshake_inbound(tls_stream, spec).await?;
            Box::new(omni_transport::ws::WsProxyStream::new(ws))
        }
        (None, WrapTransport::Ws(spec)) => {
            let ws = omni_transport::ws::handshake_inbound(sock, spec).await?;
            Box::new(omni_transport::ws::WsProxyStream::new(ws))
        }
        (Some(setup), WrapTransport::HttpUp(spec)) => {
            let tls_stream = accept_tls(sock, setup).await?;
            let raw = omni_transport::httpup::handshake_inbound(tls_stream, spec).await?;
            omni_domain::stream::boxed(raw)
        }
        (None, WrapTransport::HttpUp(spec)) => {
            let raw = omni_transport::httpup::handshake_inbound(sock, spec).await?;
            omni_domain::stream::boxed(raw)
        }
        (None, WrapTransport::None) => omni_domain::stream::boxed(sock),
        _ => unreachable!("grpc/h2 handled above"),
    };

    shared.counters.add_conn();
    tracing::debug!(target: "internal.pipeline", "conn accepted inbound={} peer={}", plan.tag, peer);

    if matches!(plan.proto, InboundProto::Anytls { .. }) && !matches!(plan.wrap, WrapTransport::None) {
        return Err(std::io::Error::other(
            "anytls requires bare TLS transport",
        ));
    }

    if let Some(mux_kind) = plan.inbound_mux {
        let session = omni_mux::MuxSession::server(stream, mux_kind).await?;
        tracing::info!(
            target: "internal.pipeline",
            "mux session established inbound={} kind={}",
            plan.tag, mux_kind.as_str()
        );
        while let Some(sub) = session.accept_stream().await? {
            let shared = shared.clone();
            let proto = plan.proto.clone();
            tokio::spawn(async move {
                if let Err(e) = run_proto_pipeline(shared, &proto, sub).await {
                    tracing::debug!(target: "internal.pipeline", "mux substream ended error={}", e);
                }
            });
        }
        return Ok(());
    }

    match &plan.proto {
        InboundProto::Mieru { username, password } => {
            let cfg = omni_proto::proto::mieru::inbound::MieruInboundConfig {
                username: username.clone(),
                password: password.clone(),
            };
            let (target, duplex) =
                omni_proto::proto::mieru::inbound::accept_session(stream, &cfg).await?;
            run_tcp_route(shared, duplex, target, Vec::new(), None).await
        }
        InboundProto::Naive => Err(std::io::Error::other(
            "naive handled by dedicated CONNECT path",
        )),
        InboundProto::Anytls { password } => {
            let cfg = omni_proto::proto::anytls::inbound::ServerConfig {
                password: password.clone(),
            };
            let route: omni_proto::proto::anytls::server::RouteCallback =
                Arc::new(move |stream, target| {
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            crate::runtime::assembly::listener_executor::run_tcp_route(
                                shared,
                                Box::new(stream),
                                target,
                                Vec::new(),
                                None,
                            )
                            .await
                        {
                            tracing::debug!(target: "internal.pipeline", "anytls stream ended error={}", e);
                        }
                    });
                });
            omni_proto::proto::anytls::inbound::accept_session(stream, &cfg, route).await
        }
        InboundProto::Socks(cfg) => {
            use omni_proto::proto::socks::Accepted;
            match omni_proto::proto::socks::handshake(stream, cfg).await? {
                Accepted::Tcp { target, stream } => {
                    run_tcp_route(shared, omni_domain::stream::boxed(stream), target, Vec::new(), None).await
                }
                Accepted::UdpAssociate { stream } => {
                    handle_socks_udp(shared, omni_domain::stream::boxed(stream)).await
                }
            }
        }
        InboundProto::Trojan(hash) => {
            use omni_proto::proto::trojan::inbound::Accepted;
            let cfg = omni_proto::proto::trojan::inbound::TrojanInboundConfig {
                password_hash_hex: hash.clone(),
            };
            match omni_proto::proto::trojan::inbound::handshake(stream, &cfg).await? {
                Accepted::Tcp { target, stream } => {
                    run_tcp_route(shared, omni_domain::stream::boxed(stream), target, Vec::new(), None).await
                }
                Accepted::UdpAssociate { stream } => {
                    handle_trojan_udp(shared, omni_domain::stream::boxed(stream)).await
                }
            }
        }
        InboundProto::Vmess(uuids) => {
            let cfg = omni_proto::proto::vmess::inbound::VmessInboundConfig {
                users: uuids.clone(),
            };
            let acc = omni_proto::proto::vmess::inbound::handshake(stream, &cfg).await.map_err(|e| {
                tracing::warn!(target: "internal.pipeline", "vmess handshake failed: {}", e);
                e
            })?;
            let duplex = crate::runtime::assembly::outbound_artifacts::vmess_duplex(acc.reader, acc.writer);
            run_tcp_route(shared, duplex, acc.target, Vec::new(), None).await
        }
        InboundProto::Hysteria2 { .. } => {
            Err(std::io::Error::other(
                "hysteria2 inbound must run on the QUIC listener path",
            ))
        }
        InboundProto::Shadowsocks(cfg) => {
            let (mut reader, writer) =
                omni_proto::proto::shadowsocks::inbound::accept_tcp(stream, cfg).await?;
            let target = reader.read_target().await?;
            let duplex = crate::runtime::assembly::outbound_artifacts::ss_duplex(reader, writer);
            run_tcp_route(shared, duplex, target, Vec::new(), None).await
        }
        InboundProto::Vless(uuids) => {
            use omni_proto::proto::vless::inbound::Accepted;
            tracing::debug!(target: "internal.pipeline", "vless inbound awaiting head");
            let cfg = omni_proto::proto::vless::inbound::VlessInboundConfig {
                allowed_uuids: uuids.clone(),
            };
            let stream = match omni_proto::proto::vless::inbound::handshake(stream, &cfg).await {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(target: "internal.pipeline", "vless inbound handshake failed: {}", e);
                    return Err(e);
                }
            };
            tracing::debug!(target: "internal.pipeline", "vless inbound handshake ok");
            match stream {
                Accepted::Tcp { target, stream } => {
                    run_tcp_route(shared, stream, target, Vec::new(), None).await
                }
                Accepted::Udp { stream } => {
                    handle_vless_udp(shared, omni_domain::stream::boxed(stream)).await
                }
            }
        }
    }
}

pub(crate) async fn run_tcp_route(
    shared: PipelineShared,
    mut stream: BoxProxyStream,
    target: omni_domain::stream::ProxyTarget,
    pre_read: Vec<u8>,
    user: Option<String>,
) -> std::io::Result<()> {
    let sniffed = inspector::inspect_stream(
        &mut stream,
        std::time::Duration::from_millis(150),
    )
    .await;

    let host_owned: Option<String> = sniffed.host.clone().or_else(|| domain_of(&target));
    let action = pipe_exec::resolve_action(
        &shared,
        &target,
        host_owned.as_deref(),
        &shared.inbound_tag,
    );

    let mut pre = pre_read;
    pre.extend_from_slice(&sniffed.consumed);

    pipe_exec::execute_tcp(&shared, action, stream, target, pre, user).await
}

fn domain_of(t: &omni_domain::stream::ProxyTarget) -> Option<String> {
    match t {
        omni_domain::stream::ProxyTarget::Domain(h, _) => Some(h.clone()),
        _ => None,
    }
}

async fn handle_socks_udp(
    shared: PipelineShared,
    control: BoxProxyStream,
) -> std::io::Result<()> {
    let bind_ip: std::net::IpAddr = "0.0.0.0".parse().unwrap();
    let sock = tokio::net::UdpSocket::bind((bind_ip, 0)).await?;
    let local = sock.local_addr()?;
    tracing::info!(target: "internal.pipeline", "socks udp relay bound addr={}", local);

    let mut reply = vec![5u8, 0, 0, 1];
    reply.extend_from_slice(&octets_v4(bind_ip));
    reply.extend_from_slice(&local.port().to_be_bytes());
    let mut control = control;
    tokio::io::AsyncWriteExt::write_all(&mut control, &reply).await?;

    let connector: Arc<dyn crate::runtime::assembly::outbound_artifacts::OutboundConnector> =
        shared.router.first_udp_connector()?;
    let handle = connector
        .connect_udp(shared.dialer.clone())
        .await
        .map_err(|e| {
            tracing::warn!(target: "internal.pipeline", "udp outbound unavailable: {}", e);
            e
        })?;

    pipe_exec::run_socks_udp_pump(Arc::new(sock), control, handle).await
}

fn octets_v4(ip: std::net::IpAddr) -> [u8; 4] {
    match ip {
        std::net::IpAddr::V4(v) => v.octets(),
        std::net::IpAddr::V6(_) => [0, 0, 0, 0],
    }
}

pub(crate) async fn run_proto_pipeline(
    shared: PipelineShared,
    proto: &InboundProto,
    stream: BoxProxyStream,
) -> std::io::Result<()> {
    tracing::debug!(target: "internal.pipeline", "run_proto_pipeline enter proto={}", match proto {
        InboundProto::Naive => "naive",
        InboundProto::Mieru { .. } => "mieru",
        InboundProto::Socks(_) => "socks",
        InboundProto::Trojan(_) => "trojan",
        InboundProto::Shadowsocks(_) => "ss",
        InboundProto::Vless(_) => "vless",
        InboundProto::Vmess(_) => "vmess",
        InboundProto::Hysteria2 { .. } => "hy2",
        InboundProto::Anytls { .. } => "anytls",
    });
    let res: std::io::Result<()> = match proto {
        InboundProto::Socks(cfg) => {
            use omni_proto::proto::socks::Accepted;
            match omni_proto::proto::socks::handshake(stream, cfg).await? {
                Accepted::Tcp { target, stream } => {
                    run_tcp_route(shared, omni_domain::stream::boxed(stream), target, Vec::new(), None)
                        .await
                }
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "socks UDP not supported on multiplexed transports",
                )),
            }
        }
        InboundProto::Trojan(hash) => {
            use omni_proto::proto::trojan::inbound::Accepted;
            let cfg = omni_proto::proto::trojan::inbound::TrojanInboundConfig {
                password_hash_hex: hash.clone(),
            };
            match omni_proto::proto::trojan::inbound::handshake(stream, &cfg).await? {
                Accepted::Tcp { target, stream } => {
                    run_tcp_route(shared, omni_domain::stream::boxed(stream), target, Vec::new(), None)
                        .await
                }
                Accepted::UdpAssociate { .. } => Err(super::super::super::runtime::assembly::node_builder::io_err_pub(
                    "trojan UDP not supported on multiplexed transports",
                )),
            }
        }
        InboundProto::Shadowsocks(cfg) => {
            let (mut reader, writer) =
                omni_proto::proto::shadowsocks::inbound::accept_tcp(stream, cfg).await?;
            let target = reader.read_target().await?;
            let duplex =
                crate::runtime::assembly::outbound_artifacts::ss_duplex(reader, writer);
            run_tcp_route(shared, duplex, target, Vec::new(), None).await
        }
        InboundProto::Vless(uuids) => {
            use omni_proto::proto::vless::inbound::Accepted;
            let cfg = omni_proto::proto::vless::inbound::VlessInboundConfig {
                allowed_uuids: uuids.clone(),
            };
            match omni_proto::proto::vless::inbound::handshake(stream, &cfg).await? {
                Accepted::Tcp { target, stream } => {
                    run_tcp_route(shared, omni_domain::stream::boxed(stream), target, Vec::new(), None)
                        .await
                }
                Accepted::Udp { .. } => Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "vless UDP not supported on multiplexed transports",
                )),
            }
        }
        InboundProto::Vmess(uuids) => {
            let cfg = omni_proto::proto::vmess::inbound::VmessInboundConfig {
                users: uuids.clone(),
            };
            let acc = omni_proto::proto::vmess::inbound::handshake(stream, &cfg).await?;
            let duplex = crate::runtime::assembly::outbound_artifacts::vmess_duplex(acc.reader, acc.writer);
            run_tcp_route(shared, duplex, acc.target, Vec::new(), None).await
        }
        InboundProto::Hysteria2 { .. } => Err(std::io::Error::other(
            "hysteria2 runs on the QUIC path only",
        )),
        InboundProto::Anytls { .. } => Err(std::io::Error::other(
            "anytls handled by dedicated session path",
        )),
        InboundProto::Mieru { .. } => Err(std::io::Error::other(
            "mieru handled by dedicated session path",
        )),
        InboundProto::Naive => Err(std::io::Error::other(
            "naive handled by dedicated CONNECT path",
        )),
    };
    if let Err(e) = &res {
        tracing::warn!(target: "internal.pipeline", "proto pipeline failed: {}", e);
    }
    res
}

async fn resolve_udp_outbound(
    shared: &PipelineShared,
) -> std::io::Result<Arc<dyn crate::runtime::assembly::outbound_artifacts::OutboundConnector>> {
    shared.router.first_udp_connector()
}

async fn handle_trojan_udp(
    shared: PipelineShared,
    control: BoxProxyStream,
) -> std::io::Result<()> {
    let connector: Arc<dyn crate::runtime::assembly::outbound_artifacts::OutboundConnector> =
        resolve_udp_outbound(&shared).await?;
    let handle = connector.connect_udp(shared.dialer.clone()).await?;

    let (mut rh, mut wh) = tokio::io::split(control);
    let tx = handle.to_remote.clone();

    tokio::spawn(async move {
        let mut dec = omni_proto::proto::trojan::udp_frame::Decoder::new();
        let mut buf = vec![0u8; 65536];
        loop {
            match AsyncReadExt::read(&mut rh, &mut buf).await {
                Ok(0) => {
                    dec.mark_eof();
                    break;
                }
                Ok(n) => {
                    dec.feed(&buf[..n]);
                    loop {
                        match dec.next_packet() {
                            Some(Ok((addr, data))) => {
                                let pkt = omni_domain::stream::UdpPacket {
                                    source: None,
                                    target: addr.to_proxy_target(),
                                    data,
                                };
                                if tx.send(pkt).await.is_err() {
                                    return;
                                }
                            }
                            Some(Err(e)) => {
                                tracing::debug!(target: "internal.pipeline", "trojan udp decode err: {}", e);
                                return;
                            }
                            None => break,
                        }
                    }
                }
                Err(_) => return,
            }
        }
    });

    let from_remote = handle.from_remote;
    tokio::spawn(async move {
        while let Some(pkt) = from_remote.lock().await.recv().await {
            let sa = omni_domain::socks5::Socks5Addr::from_proxy_target(&pkt.target);
            let frame = omni_proto::proto::trojan::udp_frame::encode(&sa, &pkt.data);
            if AsyncWriteExt::write_all(&mut wh, &frame).await.is_err() {
                break;
            }
        }
    });

    Ok(())
}

async fn handle_vless_udp(
    shared: PipelineShared,
    control: BoxProxyStream,
) -> std::io::Result<()> {
    let connector: Arc<dyn crate::runtime::assembly::outbound_artifacts::OutboundConnector> =
        resolve_udp_outbound(&shared).await?;
    let handle = connector.connect_udp(shared.dialer.clone()).await?;

    let (mut rh, mut wh) = tokio::io::split(control);
    let tx = handle.to_remote.clone();

    tokio::spawn(async move {
        let mut dec = omni_proto::proto::vless::udp_frame::Decoder::new();
        let mut buf = vec![0u8; 65536];
        loop {
            match AsyncReadExt::read(&mut rh, &mut buf).await {
                Ok(0) => {
                    dec.mark_eof();
                    break;
                }
                Ok(n) => {
                    dec.feed(&buf[..n]);
                    loop {
                        match dec.next_packet() {
                            Some(Ok((target, data))) => {
                                let pkt = omni_domain::stream::UdpPacket {
                                    source: None,
                                    target,
                                    data,
                                };
                                if tx.send(pkt).await.is_err() {
                                    return;
                                }
                            }
                            Some(Err(e)) => {
                                tracing::debug!(target: "internal.pipeline", "vless udp decode err: {}", e);
                                return;
                            }
                            None => break,
                        }
                    }
                }
                Err(_) => return,
            }
        }
    });

    let from_remote = handle.from_remote;
    tokio::spawn(async move {
        while let Some(pkt) = from_remote.lock().await.recv().await {
            let frame = omni_proto::proto::vless::udp_frame::encode(&pkt.target, &pkt.data);
            if AsyncWriteExt::write_all(&mut wh, &frame).await.is_err() {
                break;
            }
        }
    });

    Ok(())
}
