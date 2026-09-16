use etherparse::PacketBuilder;
use pcap_file::pcap::{PcapPacket, PcapWriter};
use std::fs::File;
use std::time::Duration;

fn build_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 1, 4096);

    let mut buffer = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut buffer, payload)
        .expect("building packet");
    buffer
}

fn main() -> anyhow::Result<()> {
    let file = File::create("sample.pcap")?;
    let mut writer = PcapWriter::new(file)?;

    let packets = vec![
        // Malicious IP and domain
        build_tcp_packet(
            [10, 0, 0, 5],
            [1, 2, 3, 4],
            51234,
            80,
            b"GET /payload HTTP/1.1\r\nHost: malware.test\r\n\r\n",
        ),
        // Malicious IP
        build_tcp_packet(
            [10, 0, 0, 5],
            [45, 155, 205, 233],
            51235,
            80,
            b"GET / HTTP/1.1\r\nHost: unknown.test\r\n\r\n",
        ),
        // Malicious domain and URL
        build_tcp_packet(
            [10, 0, 0, 6],
            [93, 184, 216, 34],
            51236,
            80,
            b"GET /payload HTTP/1.1\r\nHost: malware.test\r\n\r\n",
        ),
        // Benign
        build_tcp_packet(
            [10, 0, 0, 7],
            [8, 8, 8, 8],
            51237,
            80,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
        // Benign
        build_tcp_packet(
            [10, 0, 0, 8],
            [1, 1, 1, 1],
            51238,
            80,
            b"GET /docs HTTP/1.1\r\nHost: example.org\r\n\r\n",
        ),
        // Benign
        build_tcp_packet(
            [10, 0, 0, 9],
            [9, 9, 9, 9],
            51239,
            443,
            b"GET / HTTP/1.1\r\nHost: rust-lang.org\r\n\r\n",
        ),
        // Benign
        build_tcp_packet(
            [10, 0, 0, 10],
            [142, 250, 72, 14],
            51240,
            80,
            b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n",
        ),
    ];

    for (index, data) in packets.iter().enumerate() {
        let packet = PcapPacket::new(Duration::from_secs(index as u64), data.len() as u32, data);
        writer.write_packet(&packet)?;
    }

    println!("wrote sample.pcap with 7 packets");
    Ok(())
}
