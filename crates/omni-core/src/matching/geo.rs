use omni_domain::matching::compiler::GeoLookup;
use omni_domain::matching::ir::{DomainMatcher, DomainPattern, IpMatcher};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::RwLock;

#[derive(Default)]
pub struct GeoRegistry {
    domains: RwLock<BTreeMap<String, DomainMatcher>>,
    ips: RwLock<BTreeMap<String, IpMatcher>>,
}

impl GeoRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install_domains(&self, site: &str, patterns: Vec<DomainPattern>) {
        let mut m = DomainMatcher::new();
        for p in patterns {
            m.insert(p);
        }
        self.domains
            .write()
            .unwrap()
            .insert(site.to_ascii_lowercase(), m);
        tracing::info!(target: "internal.geo", "geosite loaded code={}", site);
    }

    pub fn install_cidrs(&self, country: &str, cidrs: Vec<String>) -> Result<(), String> {
        let m = IpMatcher::from_cidrs(&cidrs)?;
        self.ips
            .write()
            .unwrap()
            .insert(country.to_ascii_lowercase(), m);
        tracing::info!(target: "internal.geo", "geoip loaded code={}", country);
        Ok(())
    }

    pub fn load_dat(&self, path: &str) -> Result<(usize, usize), String> {
        let data = std::fs::read(path).map_err(|e| format!("geo: read {}: {}", path, e))?;
        let (sites, countries) = parse_v2ray_dat(&data)?;
        let ns = sites.len();
        let nc = countries.len();
        for (code, pats) in sites {
            self.install_domains(&code, pats);
        }
        for (code, cidrs) in countries {
            self.install_cidrs(&code, cidrs)?;
        }
        Ok((ns, nc))
    }

    pub fn load_list_file(&self, path: &str, kind: &str, code: &str) -> Result<usize, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("geo: read {}: {}", path, e))?;
        let mut n = 0usize;
        match kind {
            "geosite" => {
                let mut pats = Vec::new();
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let (t, v) = line
                        .split_once(' ')
                        .map(|(a, b)| (a.trim(), b.trim()))
                        .unwrap_or(("full", line));
                    match t {
                        "domain" | "suffix" => {
                            pats.push(DomainPattern::Suffix(v.to_string()))
                        }
                        "keyword" => pats.push(DomainPattern::Keyword(v.to_string())),
                        "regex" => {
                            let re = regex::Regex::new(v)
                                .map_err(|e| format!("regex.compile: {}", e))?;
                            pats.push(DomainPattern::Regex(re));
                        }
                        _ => pats.push(DomainPattern::Full(v.to_string())),
                    }
                    n += 1;
                }
                self.install_domains(code, pats);
            }
            "geoip" => {
                let cidrs: Vec<String> = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from)
                    .collect();
                n = cidrs.len();
                self.install_cidrs(code, cidrs)?;
            }
            other => return Err(format!("geo: unknown list kind '{}'", other)),
        }
        Ok(n)
    }
}

fn parse_v2ray_dat(
    data: &[u8],
) -> Result<(Vec<(String, Vec<DomainPattern>)>, Vec<(String, Vec<String>)>), String> {
    let mut sites: Vec<(String, Vec<DomainPattern>)> = Vec::new();
    let mut countries: Vec<(String, Vec<String>)> = Vec::new();

    let mut r = PbReader::new(data);
    while r.has_more() {
        let (tag, wire) = r.read_key()?;
        if tag == 1 && wire == 2 {
            let entry = r.read_bytes()?;
            if let Some((code, is_site, pats_or_cidrs)) = parse_geo_entry(&entry) {
                if is_site {
                    sites.push((code.to_string(), pats_or_cidrs.0.unwrap_or_default()));
                } else {
                    countries.push((code.to_string(), pats_or_cidrs.1.unwrap_or_default()));
                }
            }
        } else {
            r.skip_field(wire)?;
        }
    }
    Ok((sites, countries))
}

fn parse_geo_entry(entry: &[u8]) -> Option<(String, bool, (Option<Vec<DomainPattern>>, Option<Vec<String>>))> {
    let mut r = PbReader::new(entry);
    let mut code = String::new();
    let mut pats: Vec<DomainPattern> = Vec::new();
    let mut cidrs: Vec<String> = Vec::new();
    while r.has_more() {
        let (tag, wire) = r.read_key().ok()?;
        match (tag, wire) {
            (1, 2) => code = String::from_utf8_lossy(&r.read_bytes().ok()?).to_string(),
            (2, 2) => {
                let sub = r.read_bytes().ok()?;
                if let Some(p) = parse_pb_cidr(&sub) {
                    cidrs.push(p);
                }
            }
            (3, 2) => {
                let sub = r.read_bytes().ok()?;
                if let Some(p) = parse_geosite_domain(&sub) {
                    pats.push(p);
                }
            }
            _ => {
                r.skip_field(wire).ok()?;
            }
        }
    }
    if code.is_empty() {
        return None;
    }
    let is_site = !pats.is_empty();
    let out_pats = if is_site { Some(pats) } else { None };
    let out_cidrs = if !cidrs.is_empty() { Some(cidrs) } else { None };
    Some((code, is_site, (out_pats, out_cidrs)))
}

fn parse_pb_cidr(buf: &[u8]) -> Option<String> {
    let mut r = PbReader::new(buf);
    let mut ip = Vec::new();
    let mut prefix = 0u32;
    while r.has_more() {
        let (tag, wire) = r.read_key().ok()?;
        match (tag, wire) {
            (1, 2) => ip = r.read_bytes().ok()?,
            (2, 0) => prefix = r.read_varint().ok()? as u32,
            _ => r.skip_field(wire).ok()?,
        }
    }
    match ip.len() {
        4 => {
            let a = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
            Some(format!("{}/{}", a, prefix))
        }
        16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&ip);
            Some(format!("{}/{}", std::net::Ipv6Addr::from(o), prefix))
        }
        _ => None,
    }
}

fn parse_geosite_domain(buf: &[u8]) -> Option<DomainPattern> {
    let mut r = PbReader::new(buf);
    let mut dtype = 0u64;
    let mut value = String::new();
    while r.has_more() {
        let (tag, wire) = r.read_key().ok()?;
        match (tag, wire) {
            (1, 0) => dtype = r.read_varint().ok()?,
            (2, 2) => value = String::from_utf8_lossy(&r.read_bytes().ok()?).to_string(),
            _ => r.skip_field(wire).ok()?,
        }
    }
    if value.is_empty() {
        return None;
    }
    match dtype {
        0 => Some(DomainPattern::Keyword(value.to_ascii_lowercase())),
        1 => {
            let re = regex::Regex::new(&value).ok()?;
            Some(DomainPattern::Regex(re))
        }
        2 => Some(DomainPattern::Suffix(value.to_ascii_lowercase())),
        3 => Some(DomainPattern::Full(value.to_ascii_lowercase())),
        _ => None,
    }
}

pub struct PbReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PbReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        PbReader { buf, pos: 0 }
    }

    pub fn has_more(&self) -> bool {
        self.pos < self.buf.len()
    }

    pub fn read_varint(&mut self) -> Result<u64, &'static str> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = *self.buf.get(self.pos).ok_or("pb: eof")?;
            self.pos += 1;
            result |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift > 63 {
                return Err("pb: varint overflow");
            }
        }
    }

    fn read_key(&mut self) -> Result<(u32, u8), &'static str> {
        let key = self.read_varint()?;
        Ok(((key >> 3) as u32, (key & 7) as u8))
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>, &'static str> {
        let len = self.read_varint()? as usize;
        if self.pos + len > self.buf.len() {
            return Err("pb: truncated");
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    pub fn skip_field(&mut self, wire: u8) -> Result<(), &'static str> {
        match wire {
            0 => {
                self.read_varint()?;
            }
            2 => {
                self.read_bytes()?;
            }
            5 => {
                if self.pos + 4 > self.buf.len() {
                    return Err("pb: truncated");
                }
                self.pos += 4;
            }
            1 => {
                if self.pos + 8 > self.buf.len() {
                    return Err("pb: truncated");
                }
                self.pos += 8;
            }
            _ => return Err("pb: bad wire type"),
        }
        Ok(())
    }
}

impl GeoLookup for GeoRegistry {
    fn geoip_contains(&self, code: &str, ip: IpAddr) -> bool {
        self.ips
            .read()
            .unwrap()
            .get(&code.to_ascii_lowercase())
            .map(|m| m.matches(ip))
            .unwrap_or(false)
    }

    fn geosite_matches(&self, code: &str, domain: &str) -> bool {
        self.domains
            .read()
            .unwrap()
            .get(&code.to_ascii_lowercase())
            .map(|m| m.matches(domain))
            .unwrap_or(false)
    }
}
