use crate::types::{Detection, Flow, Signature, Verdict};

/// Module 6 (verdict logic): turns a match result into a Detection.
/// Module 5 (simulated IPS action): logs a would-block line for Malicious.
pub fn classify(flow: Flow, matched: Option<&Signature>) -> Detection {
    let verdict = match matched {
        Some(sig) if sig.confidence >= 75 => Verdict::Malicious,
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
