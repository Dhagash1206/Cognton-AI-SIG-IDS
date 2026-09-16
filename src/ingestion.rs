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

    if hostname.is_none() {
        hostname = extract_tls_sni(payload);
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

/// Pulls the server_name (SNI) from a TLS ClientHello handshake record.
fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    let mut offset = 0;

    while offset + 5 <= payload.len() {
        let content_type = payload[offset];
        let record_len = u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;
        let body_start = offset + 5;
        let body_end = body_start.saturating_add(record_len).min(payload.len());

        if content_type == 0x16 {
            if let Some(sni) = parse_handshake_sni(&payload[body_start..body_end]) {
                return Some(sni);
            }
        }

        if body_start + record_len > payload.len() {
            break;
        }
        offset = body_start + record_len;
    }

    None
}

fn parse_handshake_sni(data: &[u8]) -> Option<String> {
    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }

    let hello_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
    let hello_end = (4 + hello_len).min(data.len());
    parse_client_hello_sni(&data[4..hello_end])
}

fn parse_client_hello_sni(hello: &[u8]) -> Option<String> {
    // version (2) + random (32)
    if hello.len() < 34 {
        return None;
    }

    let mut offset = 34;
    let session_id_len = *hello.get(offset)? as usize;
    offset += 1 + session_id_len;

    let cipher_len = u16::from_be_bytes([*hello.get(offset)?, *hello.get(offset + 1)?]) as usize;
    offset += 2 + cipher_len;

    let compression_len = *hello.get(offset)? as usize;
    offset += 1 + compression_len;

    if offset + 2 > hello.len() {
        return None;
    }

    let extensions_len = u16::from_be_bytes([hello[offset], hello[offset + 1]]) as usize;
    offset += 2;
    let extensions_end = (offset + extensions_len).min(hello.len());

    while offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let ext_len = u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len > extensions_end {
            break;
        }

        if ext_type == 0x0000 {
            return parse_sni_extension(&hello[offset..offset + ext_len]);
        }

        offset += ext_len;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut offset = 2;
    let list_end = (2 + list_len).min(data.len());

    while offset + 3 <= list_end {
        let name_type = data[offset];
        let name_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;

        if offset + name_len > list_end {
            return None;
        }

        if name_type == 0 {
            let host = std::str::from_utf8(&data[offset..offset + name_len]).ok()?;
            return Some(host.trim_end_matches('.').to_ascii_lowercase());
        }

        offset += name_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn ethernet_ipv4_tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(src_port, dst_port, 1, 4096);

        let mut buffer = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut buffer, payload).expect("tcp packet");
        buffer
    }

    fn ethernet_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(src_port, dst_port);

        let mut buffer = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut buffer, payload).expect("udp packet");
        buffer
    }

    fn dns_query(name: &str) -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        for label in name.split('.') {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }

        payload.push(0);
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        payload
    }

    fn tls_client_hello_with_sni(hostname: &str) -> Vec<u8> {
        let host = hostname.as_bytes();

        let mut sni_body = Vec::new();
        let list_len = 1 + 2 + host.len();
        sni_body.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_body.push(0);
        sni_body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_body);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x00, 0x2f]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let hello_len = hello.len();
        handshake.push(((hello_len >> 16) & 0xff) as u8);
        handshake.push(((hello_len >> 8) & 0xff) as u8);
        handshake.push((hello_len & 0xff) as u8);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn http_host_header_is_extracted() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: Malware.TEST:8080\r\n\r\n";
        assert_eq!(
            extract_http_host(payload).as_deref(),
            Some("malware.test")
        );

        let flow = flow_from_ethernet_frame(&ethernet_ipv4_tcp(
            51234,
            80,
            payload,
        ))
        .unwrap();
        assert_eq!(flow.hostname.as_deref(), Some("malware.test"));
        assert_eq!(
            flow.url.as_deref(),
            Some("http://malware.test/index.html")
        );
    }

    #[test]
    fn dns_qname_is_extracted() {
        let payload = dns_query("Evil.Example.COM");
        assert_eq!(
            extract_dns_qname(&payload).as_deref(),
            Some("evil.example.com")
        );

        let flow = flow_from_ethernet_frame(&ethernet_ipv4_udp(55555, 53, &payload)).unwrap();
        assert_eq!(flow.hostname.as_deref(), Some("evil.example.com"));
    }

    #[test]
    fn tls_sni_is_extracted_from_client_hello() {
        let payload = tls_client_hello_with_sni("Malware.TEST");
        assert_eq!(extract_tls_sni(&payload).as_deref(), Some("malware.test"));

        let flow = flow_from_ethernet_frame(&ethernet_ipv4_tcp(51234, 443, &payload)).unwrap();
        assert_eq!(flow.hostname.as_deref(), Some("malware.test"));
    }
}
