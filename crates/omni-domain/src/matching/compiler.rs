use crate::matching::ir::{DomainMatcher, IpMatcher, PortMatcher};
use std::net::IpAddr;

pub trait GeoLookup: Send + Sync {
    fn geoip_contains(&self, code: &str, ip: IpAddr) -> bool;
    fn geosite_matches(&self, code: &str, domain: &str) -> bool;
}

pub struct CompiledRule {
    pub domains: DomainMatcher,
    pub ips: IpMatcher,
    pub geoip: Vec<String>,
    pub geosite: Vec<String>,
    pub ports: PortMatcher,
    pub inbound_tags: Vec<String>,
    pub has_criteria: bool,
}

impl CompiledRule {
    pub fn matches(
        &self,
        host: Option<&str>,
        ip: Option<IpAddr>,
        port: u16,
        inbound_tag: Option<&str>,
        geo: &dyn GeoLookup,
    ) -> bool {
        if !self.has_criteria {
            return true;
        }
        if !self.inbound_tags.is_empty() {
            match inbound_tag {
                Some(t) if self.inbound_tags.iter().any(|x| x == t) => {}
                _ => return false,
            }
        }
        if !self.ports.is_empty() && !self.ports.matches(port) {
            return false;
        }
        if !self.domains.is_empty() {
            match host {
                Some(h) if self.domains.matches(h) => {}
                _ => return false,
            }
        }
        if !self.geosite.is_empty() {
            match host {
                Some(h) if self.geosite.iter().any(|c| geo.geosite_matches(c, h)) => {}
                _ => return false,
            }
        }
        if !self.ips.is_empty() {
            match ip {
                Some(i) if self.ips.matches(i) => {}
                _ => return false,
            }
        }
        if !self.geoip.is_empty() {
            match ip {
                Some(i) if self.geoip.iter().any(|c| geo.geoip_contains(c, i)) => {}
                _ => return false,
            }
        }
        true
    }

    pub fn needs_ip(&self) -> bool {
        !self.ips.is_empty() || !self.geoip.is_empty()
    }
}
