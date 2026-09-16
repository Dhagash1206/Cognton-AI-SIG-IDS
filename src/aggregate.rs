use crate::types::Flow;
use std::collections::HashMap;
use std::net::IpAddr;

type Endpoint = (IpAddr, u16);

/// Direction-independent connection identity: ordered (ip, port) pair + protocol.
type ConnectionKey = (Endpoint, Endpoint, String);

/// Collapses per-packet Flow records into one Flow per connection.
///
/// Packets in either direction share a key of min/max (ip, port) plus protocol.
/// Hostname and URL keep the first non-null value seen on that connection.
pub fn aggregate(flows: Vec<Flow>) -> Vec<Flow> {
    let mut order = Vec::new();
    let mut by_key: HashMap<ConnectionKey, Flow> = HashMap::new();

    for flow in flows {
        let key = connection_key(&flow);

        match by_key.get_mut(&key) {
            Some(existing) => {
                if existing.hostname.is_none() {
                    existing.hostname = flow.hostname;
                }
                if existing.url.is_none() {
                    existing.url = flow.url;
                }
            }
            None => {
                order.push(key.clone());
                by_key.insert(key, flow);
            }
        }
    }

    order
        .into_iter()
        .map(|key| by_key.remove(&key).expect("key inserted with flow"))
        .collect()
}

fn connection_key(flow: &Flow) -> ConnectionKey {
    let a = (flow.src_ip, flow.src_port);
    let b = (flow.dst_ip, flow.dst_port);

    if a <= b {
        (a, b, flow.protocol.clone())
    } else {
        (b, a, flow.protocol.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn flow(
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        hostname: Option<&str>,
        url: Option<&str>,
    ) -> Flow {
        Flow {
            src_ip: src_ip.parse::<IpAddr>().unwrap(),
            dst_ip: dst_ip.parse::<IpAddr>().unwrap(),
            src_port,
            dst_port,
            protocol: "TCP".to_string(),
            hostname: hostname.map(str::to_string),
            url: url.map(str::to_string),
        }
    }

    #[test]
    fn same_direction_packets_collapse() {
        let packets = vec![
            flow("10.0.0.1", 12345, "8.8.8.8", 80, None, None),
            flow(
                "10.0.0.1",
                12345,
                "8.8.8.8",
                80,
                Some("example.com"),
                Some("http://example.com/"),
            ),
        ];

        let aggregated = aggregate(packets);
        assert_eq!(aggregated.len(), 1);
        assert_eq!(aggregated[0].src_ip.to_string(), "10.0.0.1");
        assert_eq!(aggregated[0].dst_ip.to_string(), "8.8.8.8");
        assert_eq!(aggregated[0].hostname.as_deref(), Some("example.com"));
        assert_eq!(aggregated[0].url.as_deref(), Some("http://example.com/"));
    }

    #[test]
    fn reverse_direction_packets_collapse() {
        let packets = vec![
            flow("10.0.0.1", 12345, "8.8.8.8", 80, Some("example.com"), None),
            flow("8.8.8.8", 80, "10.0.0.1", 12345, None, Some("http://example.com/")),
        ];

        let aggregated = aggregate(packets);
        assert_eq!(aggregated.len(), 1);
        assert_eq!(aggregated[0].hostname.as_deref(), Some("example.com"));
        assert_eq!(aggregated[0].url.as_deref(), Some("http://example.com/"));
    }

    #[test]
    fn distinct_connections_stay_separate() {
        let packets = vec![
            flow("10.0.0.1", 12345, "8.8.8.8", 80, Some("a.test"), None),
            flow("10.0.0.1", 12346, "8.8.8.8", 80, Some("b.test"), None),
            flow("10.0.0.2", 12345, "1.1.1.1", 443, Some("c.test"), None),
        ];

        let aggregated = aggregate(packets);
        assert_eq!(aggregated.len(), 3);
    }
}
