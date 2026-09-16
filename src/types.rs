use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A single network flow extracted from a packet/pcap.
/// This is the unit the detector matches signatures against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String, // "TCP" | "UDP" | "ICMP" etc.
    // Populated later once DNS/SNI resolution (module 9) is implemented.
    pub hostname: Option<String>,
    pub url: Option<String>,
}

/// Verdict assigned to a flow after matching against signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Benign,
    Suspicious,
    Malicious,
}

/// A single threat-intel signature pulled from the AbuseIPDB feed
/// (or any future feed — kept generic so other APIs can plug in later).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub indicator: String, // the IP/domain/URL/hash value
    pub kind: IocKind,
    pub source: String, // e.g. "AbuseIPDB"
    pub confidence: u8, // 0-100 abuse confidence score
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocKind {
    Ip,
    Domain,
    Url,
    Hash,
}

/// Result of matching one flow against the signature set — what gets
/// logged, reported, and exported to JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub flow: Flow,
    pub verdict: Verdict,
    pub matched_signature: Option<Signature>,
}
