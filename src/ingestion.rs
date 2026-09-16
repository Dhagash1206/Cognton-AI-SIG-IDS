use crate::types::Flow;
use anyhow::{Context, Result};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::path::Path;

pub fn read_pcap<P: AsRef<Path>>(path: P) -> Result<Vec<Flow>> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("opening pcap file {:?}", path.as_ref()))?;

    let mut reader = PcapReader::new(file).context("parsing pcap global header")?;
    let mut flows = Vec::new();

    while let Some(packet) = reader.next_packet() {
        let packet = match packet {
            Ok(packet) => packet,
            Err(_) => continue,
        };

        if let Some(flow) = flow_from_ethernet_frame(&packet.data) {
            flows.push(flow);
        }
    }

    Ok(flows)
}

fn flow_from_ethernet_frame(data: &[u8]) -> Option<Flow> {
    let sliced = SlicedPacket::from_ethernet(data).ok()?;

    let (src_ip, dst_ip) = match sliced.net.as_ref()? {
        NetSlice::Ipv4(ip) => (
            ip.header().source_addr().into(),
            ip.header().destination_addr().into(),
        ),
        NetSlice::Ipv6(ip) => (
            ip.header().source_addr().into(),
            ip.header().destination_addr().into(),
        ),
    };

    let (src_port, dst_port, protocol, payload) = match sliced.transport.as_ref()? {
        TransportSlice::Tcp(tcp) => (
            tcp.source_port(),
            tcp.destination_port(),
            "TCP",
            tcp.payload(),
        ),
        TransportSlice::Udp(udp) => (
            udp.source_port(),
            udp.destination_port(),
            "UDP",
            udp.payload(),
        ),
        _ => return None,
    };

    let mut hostname = extract_http_host(payload);
    let mut url = None;

    if let Some((host, path)) = extract_http_request(payload) {
        hostname = Some(host.clone());

        let scheme = if dst_port == 443 { "https" } else { "http" };

        url = Some(format!("{scheme}://{host}{path}"));
    }

    if hostname.is_none() && (src_port == 53 || dst_port == 53) {
        hostname = extract_dns_qname(payload);
    }

    Some(Flow {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: protocol.to_string(),
        hostname,
        url,
    })
}

fn extract_http_request(payload: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(payload).ok()?;
    let first_line = text.lines().next()?;
    let mut parts = first_line.split_whitespace();

    let method = parts.next()?;

    if !matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS"
    ) {
        return None;
    }

    let path = parts.next()?.to_string();
    let host = extract_http_host(payload)?;

    Some((host, path))
}

fn extract_http_host(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;

    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;

        if name.eq_ignore_ascii_case("host") {
            Some(
                value
                    .trim()
                    .split(':')
                    .next()?
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
            )
        } else {
            None
        }
    })
}

fn extract_dns_qname(payload: &[u8]) -> Option<String> {
    if payload.len() < 13 {
        return None;
    }

    let mut offset = 12;
    let mut labels = Vec::new();

    while offset < payload.len() {
        let length = payload[offset] as usize;
        offset += 1;

        if length == 0 {
            break;
        }

        if length > 63 || offset + length > payload.len() {
            return None;
        }

        let label = std::str::from_utf8(&payload[offset..offset + length]).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset += length;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}
