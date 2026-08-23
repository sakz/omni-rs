use omni_config::wire::RuntimeConfigWire;

pub fn validate(wire: &RuntimeConfigWire) -> Result<(), String> {
    let mut tags: Vec<&str> = Vec::new();
    for ob in &wire.outbounds {
        let label = if ob.tag.is_empty() {
            "<untagged>".to_string()
        } else {
            ob.tag.clone()
        };
        validate_outbound(ob).map_err(|e| format!("config validation failed for outbound {}: {}", label, e))?;
        if ob.tag.is_empty() {
            return Err("config validation failed for outbound <untagged>: outbound tag cannot be empty".to_string());
        }
        if tags.contains(&ob.tag.as_str()) {
            return Err(format!(
                "config validation failed for outbound {}: duplicate tag (tags must be unique across inbounds and outbounds)",
                ob.tag
            ));
        }
        tags.push(&ob.tag);
    }
    for node in &wire.nodes {
        let label = if node.tag.is_empty() {
            "<untagged>".to_string()
        } else {
            node.tag.clone()
        };
        validate_node(node)
            .map_err(|e| format!("config validation failed for inbound {}: {}", label, e))?;
        if !node.tag.is_empty() {
            if tags.contains(&node.tag.as_str()) {
                return Err(format!(
                    "config validation failed for inbound {}: duplicate tag (tags must be unique across inbounds and outbounds)",
                    node.tag
                ));
            }
            tags.push(&node.tag);
        }
    }
    Ok(())
}

fn require_nonempty(spec: &str, field: &str, value: Option<&String>) -> Result<(), String> {
    match value {
        Some(v) if !v.trim().is_empty() => Ok(()),
        _ => Err(format!(
            "{} outbound requires a non-empty '{}'",
            spec, field
        )),
    }
}

fn validate_target(
    proto: &str,
    target: &Option<omni_config::wire::TargetSpecWire>,
) -> Result<(), String> {
    match target {
        None => Err(format!(
            "protocol {} requires target.server and target.server_port",
            proto
        )),
        Some(t) => {
            if t.server.as_deref().map(str::is_empty).unwrap_or(true)
                || t.server_port.is_none()
            {
                return Err(format!(
                    "protocol {} requires target.server and target.server_port",
                    proto
                ));
            }
            Ok(())
        }
    }
}

fn validate_outbound(ob: &omni_config::wire::OutboundSpecWire) -> Result<(), String> {
    let get = |k: &str| ob.rest.get(k).and_then(|v| v.as_str()).map(String::from);
    match ob.outbound_type.as_str() {
        "trojan" => {
            validate_target("trojan", &ob.target)?;
            require_nonempty("trojan", "password", get("password").as_ref())?;
        }
        "vless" => {
            validate_target("vless", &ob.target)?;
            require_nonempty("vless", "uuid", get("uuid").as_ref())?;
        }
        "vmess" => {
            validate_target("vmess", &ob.target)?;
            require_nonempty("vmess", "uuid", get("uuid").as_ref())?;
        }
        "shadowsocks" => {
            validate_target("shadowsocks", &ob.target)?;
            require_nonempty("shadowsocks", "method", get("method").as_ref())?;
            require_nonempty("shadowsocks", "password", get("password").as_ref())?;
        }
        "anytls" => {
            validate_target("anytls", &ob.target)?;
            require_nonempty("anytls", "password", get("password").as_ref())?;
        }
        "mieru" => {
            validate_target("mieru", &ob.target)?;
            require_nonempty("mieru", "username", get("username").as_ref())?;
            require_nonempty("mieru", "password", get("password").as_ref())?;
        }
        "" => return Err("outbound protocol cannot be empty".to_string()),
        _ => {}
    }
    Ok(())
}

fn validate_node(node: &omni_config::wire::NodeConfigWire) -> Result<(), String> {
    if node.r#type.as_str() == "" { return Err("protocol cannot be empty".to_string()) }
    if !node.mux_enabled {
        if let Some(mux) = &node.mux {
            if mux.kind.is_some() {
                return Err("mux is disabled but a mux kind is configured".to_string());
            }
        }
    }
    if let Some(tls) = &node.tls {
        validate_tls(tls)?;
    }
    Ok(())
}

fn validate_tls(tls: &omni_config::wire::TlsInboundSpecWire) -> Result<(), String> {
    match tls.cert_mode.as_deref() {
        None | Some("") => {}
        Some("file") => {
            if tls.cert_file.is_none()
                || tls.cert_file.as_deref().unwrap_or("").is_empty()
                || tls.key_file.is_none()
                || tls.key_file.as_deref().unwrap_or("").is_empty()
            {
                return Err("cert_mode=file requires cert_file and key_file paths".to_string());
            }
        }
        Some("content") => {
            if tls
                .cert_content
                .as_deref()
                .map(str::is_empty)
                .unwrap_or(true)
            {
                return Err("cert_mode=content requires cert_content".to_string());
            }
            if tls
                .key_content
                .as_deref()
                .map(str::is_empty)
                .unwrap_or(true)
            {
                return Err("cert_mode=content requires key_content".to_string());
            }
        }
        Some("self") => {
            if tls
                .cert_domain
                .as_deref()
                .map(str::is_empty)
                .unwrap_or(true)
            {
                return Err("cert_mode=self requires cert_domain".to_string());
            }
        }
        other => {
            return Err(format!("cert: unsupported cert_mode: {}", other.unwrap_or("")));
        }
    }
    if let Some(reality) = &tls.reality {
        for sid in &reality.short_ids {
            if !hex_decode_check(sid) {
                return Err(format!("reality.short_ids entry '{}' is not valid hex", sid));
            }
        }
    }
    Ok(())
}

fn hex_decode_check(s: &str) -> bool {
    s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
}
