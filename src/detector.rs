use crate::types::{Flow, IocKind, Signature};

/// Matches IP, domain, and URL indicators against one flow.
pub fn match_flow<'a>(flow: &Flow, signatures: &'a [Signature]) -> Option<&'a Signature> {
    signatures.iter().find(|signature| match signature.kind {
        IocKind::Ip => {
            signature.indicator == flow.src_ip.to_string()
                || signature.indicator == flow.dst_ip.to_string()
        }

        IocKind::Domain => flow.hostname.as_deref().is_some_and(|hostname| {
            normalize_domain(hostname) == normalize_domain(&signature.indicator)
        }),

        IocKind::Url => flow
            .url
            .as_deref()
            .is_some_and(|url| normalize_url(url) == normalize_url(&signature.indicator)),

        IocKind::Hash => false,
    })
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

    #[test]
    fn ip_matches() {
        let signatures = vec![signature("8.8.8.8", IocKind::Ip)];
        assert!(match_flow(&flow(None, None), &signatures).is_some());
    }

    #[test]
    fn domain_matches_case_insensitively() {
        let signatures = vec![signature("malware.test", IocKind::Domain)];
        assert!(match_flow(&flow(Some("MALWARE.TEST."), None), &signatures).is_some());
    }

    #[test]
    fn url_matches() {
        let signatures = vec![signature("http://malware.test/payload", IocKind::Url)];

        assert!(match_flow(
            &flow(Some("malware.test"), Some("HTTP://MALWARE.TEST/PAYLOAD/")),
            &signatures
        )
        .is_some());
    }

    #[test]
    fn clean_flow_does_not_match() {
        let signatures = vec![signature("malware.test", IocKind::Domain)];
        assert!(match_flow(&flow(Some("example.com"), None), &signatures).is_none());
    }
}
