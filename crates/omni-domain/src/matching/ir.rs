use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum DomainPattern {
    Full(String),
    Suffix(String),
    Keyword(String),
    Regex(regex::Regex),
}

impl DomainPattern {
    pub fn matches(&self, domain: &str) -> bool {
        let d = domain.to_ascii_lowercase();
        match self {
            DomainPattern::Full(f) => &d == f,
            DomainPattern::Suffix(s) => d == *s || d.ends_with(&format!(".{}", s)),
            DomainPattern::Keyword(k) => d.contains(k),
            DomainPattern::Regex(r) => r.is_match(&d),
        }
    }
}

#[derive(Debug, Default)]
pub struct DomainMatcher {
    full: BTreeMap<String, ()>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    regex: Vec<regex::Regex>,
}

impl DomainMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, p: DomainPattern) {
        match p {
            DomainPattern::Full(s) => {
                self.full.insert(s.to_ascii_lowercase(), ());
            }
            DomainPattern::Suffix(s) => self.suffix.push(s.to_ascii_lowercase()),
            DomainPattern::Keyword(k) => self.keyword.push(k.to_ascii_lowercase()),
            DomainPattern::Regex(r) => self.regex.push(r),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.full.is_empty()
            && self.suffix.is_empty()
            && self.keyword.is_empty()
            && self.regex.is_empty()
    }

    pub fn matches(&self, domain: &str) -> bool {
        let d = domain.to_ascii_lowercase();
        if self.full.contains_key(&d) {
            return true;
        }
        for s in &self.suffix {
            if d == *s || d.ends_with(&format!(".{}", s)) {
                return true;
            }
        }
        for k in &self.keyword {
            if d.contains(k) {
                return true;
            }
        }
        for r in &self.regex {
            if r.is_match(&d) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct IpMatcher {
    v4: Vec<(std::net::Ipv4Addr, u8)>,
    v6: Vec<(std::net::Ipv6Addr, u8)>,
}

impl IpMatcher {
    pub fn from_cidrs(cidrs: &[String]) -> Result<Self, String> {
        let mut m = IpMatcher {
            v4: Vec::new(),
            v6: Vec::new(),
        };
        for c in cidrs {
            let (addr, len) = c
                .split_once('/')
                .map(|(a, l)| (a.to_string(), l.parse::<u8>()))
                .unwrap_or_else(|| (c.clone(), Ok(u8::MAX)));
            match addr.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(a)) => {
                    let len = len.map_err(|e| format!("invalid prefix in {}: {}", c, e))?;
                    if len > 32 {
                        return Err(format!("invalid ipv4 prefix length in {}", c));
                    }
                    m.v4.push((a, len));
                }
                Ok(std::net::IpAddr::V6(a)) => {
                    let len = len.map_err(|e| format!("invalid prefix in {}: {}", c, e))?;
                    if len > 128 {
                        return Err(format!("invalid ipv6 prefix length in {}", c));
                    }
                    m.v6.push((a, len));
                }
                Err(e) => return Err(format!("invalid cidr {}: {}", c, e)),
            }
        }
        Ok(m)
    }

    pub fn matches(&self, ip: std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(a) => self.v4.iter().any(|(n, l)| mask4(a, *n, *l)),
            std::net::IpAddr::V6(a) => self.v6.iter().any(|(n, l)| mask6(a, *n, *l)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

fn mask4(a: std::net::Ipv4Addr, n: std::net::Ipv4Addr, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    let x = u32::from(a);
    let y = u32::from(n);
    let m = u32::MAX << (32 - len as u32);
    (x & m) == (y & m)
}

fn mask6(a: std::net::Ipv6Addr, n: std::net::Ipv6Addr, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    let x = u128::from(a);
    let y = u128::from(n);
    let m = u128::MAX << (128 - len as u32);
    (x & m) == (y & m)
}

#[derive(Debug, Default)]
pub struct PortMatcher {
    exact: std::collections::BTreeSet<u16>,
    ranges: Vec<(u16, u16)>,
}

impl PortMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_port(&mut self, p: u16) {
        self.exact.insert(p);
    }

    pub fn insert_range(&mut self, from: u16, to: u16) {
        self.ranges.push((from, to));
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.ranges.is_empty()
    }

    pub fn matches(&self, port: u16) -> bool {
        if self.exact.contains(&port) {
            return true;
        }
        self.ranges.iter().any(|(a, b)| port >= *a && port <= *b)
    }
}

pub type SharedDomainMatcher = Arc<DomainMatcher>;
