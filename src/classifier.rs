/// Assigns Benign, Suspicious, or Malicious verdict per flow



use crate::types::{Detection, Flow, Signature, Verdict};

/// AbuseIPDB's blacklist is filtered at confidence >= 90, so a cutoff of 75
/// would mark every IP hit Malicious and never emit Suspicious. High-confidence
/// feeds stay Malicious; URLhaus (fixed 60) and similar land as Suspicious.
const MALICIOUS_CONFIDENCE: u8 = 90;

/// Module 6 (verdict logic): turns a match result into a Detection.
/// Module 5 (simulated IPS action): logs a would-block line for Malicious.
pub fn classify(flow: Flow, matched: Option<&Signature>) -> Detection {
    let verdict = match matched {
        Some(sig) if sig.confidence >= MALICIOUS_CONFIDENCE => Verdict::Malicious,
        Some(_) => Verdict::Suspicious,
        None => Verdict::Benign,
    };
    if verdict == Verdict::Malicious {
        // Simulated IPS action — no actual packet drop, just a log line.
        println!(
            "[BLOCKED] {} -> {} matched {:?}",
            flow.src_ip, flow.dst_ip, matched
        );
    }

    Detection {
        flow,
        verdict,
        matched_signature: matched.cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IocKind;
    use std::net::IpAddr;

    fn flow() -> Flow {
        Flow {
            src_ip: "10.0.0.5".parse::<IpAddr>().unwrap(),
            dst_ip: "8.8.8.8".parse::<IpAddr>().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: "TCP".to_string(),
            hostname: None,
            url: None,
        }
    }

    fn signature(source: &str, confidence: u8) -> Signature {
        Signature {
            indicator: "8.8.8.8".to_string(),
            kind: IocKind::Ip,
            source: source.to_string(),
            confidence,
        }
    }

    #[test]
    fn abuseipdb_high_confidence_is_malicious() {
        let sig = signature("AbuseIPDB", 90);
        let detection = classify(flow(), Some(&sig));
        assert_eq!(detection.verdict, Verdict::Malicious);
    }

    #[test]
    fn urlhaus_lower_confidence_is_suspicious() {
        let sig = signature("URLhaus", 60);
        let detection = classify(flow(), Some(&sig));
        assert_eq!(detection.verdict, Verdict::Suspicious);
    }

    #[test]
    fn unmatched_flow_is_benign() {
        let detection = classify(flow(), None);
        assert_eq!(detection.verdict, Verdict::Benign);
    }
}
