use crate::matching::compiler::CompiledRule;
use crate::matching::ir::{DomainMatcher, DomainPattern, IpMatcher, PortMatcher};

#[derive(Debug, Clone, Default)]
pub struct RouteRuleAst {
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub ip_cidr: Vec<String>,
    pub geoip: Vec<String>,
    pub geosite: Vec<String>,
    pub ports: Vec<u16>,
    pub port_ranges: Vec<(u16, u16)>,
    pub inbound_tags: Vec<String>,
}

impl RouteRuleAst {
    pub fn has_criteria(&self) -> bool {
        !(self.domain_suffix.is_empty()
            && self.domain_keyword.is_empty()
            && self.domain_regex.is_empty()
            && self.ip_cidr.is_empty()
            && self.geoip.is_empty()
            && self.geosite.is_empty()
            && self.ports.is_empty()
            && self.port_ranges.is_empty()
            && self.inbound_tags.is_empty())
    }

    pub fn compile(&self) -> Result<CompiledRule, String> {
        let mut domains = DomainMatcher::new();
        for d in &self.domain_suffix {
            validate_domain_item(d)?;
            domains.insert(DomainPattern::Suffix(d.to_ascii_lowercase()));
        }
        for d in &self.domain_keyword {
            if d.trim().is_empty() {
                return Err(
                    "route rule[i].domain_keyword[j] is empty or whitespace-only".to_string(),
                );
            }
            domains.insert(DomainPattern::Keyword(d.to_ascii_lowercase()));
        }
        for r in &self.domain_regex {
            let re = regex::Regex::new(r)
                .map_err(|e| format!("regex.compile: regex pattern compilation failed: {}", e))?;
            domains.insert(DomainPattern::Regex(re));
        }
        let ips = IpMatcher::from_cidrs(&self.ip_cidr)?;
        let mut ports = PortMatcher::new();
        for p in &self.ports {
            ports.insert_port(*p);
        }
        for (a, b) in &self.port_ranges {
            ports.insert_range(*a, *b);
        }
        Ok(CompiledRule {
            domains,
            ips,
            geoip: self.geoip.clone(),
            geosite: self.geosite.clone(),
            ports,
            inbound_tags: self.inbound_tags.clone(),
            has_criteria: self.has_criteria(),
        })
    }
}

fn validate_domain_item(d: &str) -> Result<(), String> {
    if d.trim().is_empty() {
        return Err("route rule domain entry is empty or whitespace-only".to_string());
    }
    Ok(())
}
