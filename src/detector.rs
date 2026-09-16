use crate::types::{Flow, IocKind, Signature};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Pre-indexed signature set so matching is a lookup, not a linear scan.
pub struct SignatureIndex {
    ips: HashSet<IpAddr>,
    domains: HashSet<String>,
    urls: HashSet<String>,
    by_kind: HashMap<IocKind, HashMap<String, Signature>>,
}

impl SignatureIndex {
    pub fn from_signatures(signatures: Vec<Signature>) -> Self {
        let mut ips = HashSet::new();
        let mut domains = HashSet::new();
        let mut urls = HashSet::new();
        let mut by_kind: HashMap<IocKind, HashMap<String, Signature>> = HashMap::new();

        for signature in signatures {
            let key = match signature.kind {
                IocKind::Ip => {
                    if let Ok(ip) = signature.indicator.parse::<IpAddr>() {
                        ips.insert(ip);
                    }
                    signature.indicator.clone()
                }
                IocKind::Domain => {
                    let key = normalize_domain(&signature.indicator);
                    domains.insert(key.clone());
                    key
                }
                IocKind::Url => {
                    let key = normalize_url(&signature.indicator);
                    urls.insert(key.clone());
                    key
                }
                IocKind::Hash => continue,
            };

            by_kind
                .entry(signature.kind)
                .or_default()
                .entry(key)
                .or_insert(signature);
        }

        Self {
            ips,
            domains,
            urls,
            by_kind,
        }
    }

    fn lookup(&self, kind: IocKind, key: &str) -> Option<&Signature> {
        self.by_kind.get(&kind)?.get(key)
    }
}

/// Matches IP, domain, and URL indicators against one flow.
pub fn match_flow<'a>(flow: &Flow, signatures: &'a SignatureIndex) -> Option<&'a Signature> {
    if signatures.ips.contains(&flow.src_ip) {
        return signatures.lookup(IocKind::Ip, &flow.src_ip.to_string());
    }
    if signatures.ips.contains(&flow.dst_ip) {
        return signatures.lookup(IocKind::Ip, &flow.dst_ip.to_string());
    }

    if let Some(hostname) = flow.hostname.as_deref() {
        let key = normalize_domain(hostname);
        if signatures.domains.contains(&key) {
            return signatures.lookup(IocKind::Domain, &key);
        }
    }

    if let Some(url) = flow.url.as_deref() {
        let key = normalize_url(url);
        if signatures.urls.contains(&key) {
            return signatures.lookup(IocKind::Url, &key);
        }
    }

    None
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn flow(hostname: Option<&str>, url: Option<&str>) -> Flow {
        Flow {
            src_ip: "10.0.0.5".parse::<IpAddr>().unwrap(),
            dst_ip: "8.8.8.8".parse::<IpAddr>().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: "TCP".to_string(),
            hostname: hostname.map(str::to_string),
            url: url.map(str::to_string),
        }
    }

    fn signature(indicator: &str, kind: IocKind) -> Signature {
        Signature {
            indicator: indicator.to_string(),
            kind,
            source: "test".to_string(),
            confidence: 90,
        }
    }

    fn index(signatures: Vec<Signature>) -> SignatureIndex {
        SignatureIndex::from_signatures(signatures)
    }

    #[test]
    fn ip_matches() {
        let signatures = index(vec![signature("8.8.8.8", IocKind::Ip)]);
        assert!(match_flow(&flow(None, None), &signatures).is_some());
    }

    #[test]
    fn domain_matches_case_insensitively() {
        let signatures = index(vec![signature("malware.test", IocKind::Domain)]);
        assert!(match_flow(&flow(Some("MALWARE.TEST."), None), &signatures).is_some());
    }

    #[test]
    fn url_matches() {
        let signatures = index(vec![signature("http://malware.test/payload", IocKind::Url)]);

        assert!(match_flow(
            &flow(Some("malware.test"), Some("HTTP://MALWARE.TEST/PAYLOAD/")),
            &signatures
        )
        .is_some());
    }

    #[test]
    fn clean_flow_does_not_match() {
        let signatures = index(vec![signature("malware.test", IocKind::Domain)]);
        assert!(match_flow(&flow(Some("example.com"), None), &signatures).is_none());
    }
}
