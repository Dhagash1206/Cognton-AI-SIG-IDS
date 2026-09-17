# Cognton-AI-SIG-IDS

A signature-based network traffic detection engine written in Rust. It reads
packets from a pcap file, matches them against real threat-intelligence
indicators (IPs, domains, URLs), and classifies each connection as Benign,
Suspicious, or Malicious.

Built for the Cognton AI Rust assignment, mirroring the detection-engine work
on Cognton's agentic platform.

## Features

- Pcap ingestion (no root required) via `pcap-file` and `etherparse`
- Flow aggregation: packets belonging to the same connection are merged into
  a single flow before classification, instead of being judged individually
- Threat intelligence from two feeds, merged into one signature set:
  - AbuseIPDB blacklist API (IPs, confidence >= 90)
  - URLhaus recent-URLs CSV (URLs and their extracted domains, confidence 60)
- Local JSON cache (1 hour TTL) so neither API is called per packet
- O(1) signature matching via a `HashMap`-indexed `SignatureIndex`, covering
  IP, domain, and URL indicators
- TLS SNI extraction from ClientHello records, plus HTTP `Host` header and
  DNS query name parsing, so HTTPS-only connections can still be attributed
  a hostname
- Verdict classification (Benign / Suspicious / Malicious) with a simulated
  IPS block-log for Malicious verdicts
- CLI summary output plus a full JSON export of all detections
- Unit tests covering matching, aggregation, and classification logic

## Architecture

| Module          | Responsibility                                                        |
| --------------- | --------------------------------------------------------------------- |
| `types.rs`      | Shared structs and enums: `Flow`, `Signature`, `Verdict`, `Detection` |
| `ingestion.rs`  | Parses pcap files into per-packet `Flow` records; extracts hostname via HTTP `Host`, DNS query names, and TLS SNI |
| `aggregate.rs`  | Merges per-packet records into per-connection flows                   |
| `signatures.rs` | AbuseIPDB + URLhaus clients, and the local signature cache             |
| `detector.rs`   | Builds a `HashMap`-indexed `SignatureIndex` and matches flows against it (O(1) lookup) |
| `classifier.rs` | Verdict assignment (confidence >= 90 -> Malicious, else Suspicious) and simulated IPS block logging |
| `report.rs`     | CLI summary and JSON export                                           |
| `main.rs`       | CLI argument parsing and pipeline wiring                              |

Pipeline: `ingest -> aggregate -> load signatures -> match -> classify -> report`

## Setup

```
export ABUSEIPDB_API_KEY=your_key_here   # get a free key at abuseipdb.com
cargo build
cargo test
```

## Generating test traffic

Two options for producing a `sample.pcap`:

**Real traffic** (captured, as the assignment requires):

```
sudo tcpdump -i any -w sample.pcap &
curl <a-known-bad-domain-from-your-feed>
curl google.com
# Ctrl+C tcpdump
```

**Synthetic traffic** (bundled generator, for quick local testing):

```
cargo run --bin gen_sample
```

This produces a small pcap with one flow to a known-bad IP and two to clean
IPs.

## Running

```
cargo run --bin sig-ids -- --pcap sample.pcap --output detections.json
```

### Offline mode

For environments without outbound access to AbuseIPDB/URLhaus, set
`SIG_IDS_OFFLINE=1` to load signatures from a bundled fixture
(`sample_signatures.json`) instead of calling the live APIs:

```
SIG_IDS_OFFLINE=1 cargo run --bin sig-ids -- --pcap sample.pcap --output detections.json
```

### Example output

```
[BLOCKED] 10.0.0.5 -> 1.2.3.4 matched Signature { ... confidence: 95 }
=== Detection Summary ===
Total flows:  3
Benign:       2
Suspicious:   0
Malicious:    1
```

## APIs used

- AbuseIPDB IP blacklist (`/v2/blacklist`), free tier: 1,000 checks/day.
  Returns only entries at confidence >= 90.
- URLhaus recent-URLs CSV feed (`urlhaus.abuse.ch/downloads/csv_recent`),
  no API key required. No per-entry confidence score, so entries are
  assigned a fixed confidence of 60.

## Technical Notes

- **Signature coverage**: `detector.rs` matches `IocKind::Ip`, `Domain`, and
  `Url`. All three are populated: AbuseIPDB supplies IPs, URLhaus supplies
  URLs and their derived domains.
- **Hostname resolution**: derived from HTTP `Host` headers, DNS query
  names, and TLS SNI (parsed from ClientHello handshake records) in
  `ingestion.rs`. A connection with none of these present in the pcap
  still has no hostname.
- **Hash matching**: `IocKind::Hash` exists in `types.rs` for AV-style
  payload-hash matching but has no populating source yet.
- **Matching complexity**: `SignatureIndex` (`detector.rs`) pre-indexes
  signatures into `HashMap`/`HashSet` structures at load time, so
  `match_flow()` is O(1) per flow rather than a linear scan.
- **Verdict thresholds**: `classifier.rs` maps confidence >= 90 to
  `Malicious`, otherwise `Suspicious`. AbuseIPDB entries (all >= 90) land
  as `Malicious`; URLhaus entries (fixed at 60) land as `Suspicious`, so
  both verdict tiers are reachable with the current feed set.
- **Capture mode**: traffic is read from pcap files via `pcap-file` (no
  root required). Live capture via `pnet`/`pcap` is not implemented.
- **Toolchain**: pinned to Rust 1.75. `reqwest` was swapped for
  `ureq`/`native-tls`, and `openssl`, `openssl-sys`, `clap`, and `url` are
  version-pinned in `Cargo.toml` to avoid transitive dependencies that
  require edition2024.
  
## Output

<img width="700" height="508" alt="image" src="https://github.com/user-attachments/assets/77d56f38-de86-44ea-b20d-66676aa80949" />
<img width="313" height="505" alt="image" src="https://github.com/user-attachments/assets/b8f30bb4-5b4f-47ff-bad4-f10349f05a1b" />


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for the full license text.

