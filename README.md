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
- Threat intelligence via the AbuseIPDB blacklist API, with a local JSON
  cache (1 hour TTL) so the API is never called per packet
- IP-based signature matching, with domain/URL matching implemented in the
  matcher and ready for a domain-capable feed
- Verdict classification (Benign / Suspicious / Malicious) with a simulated
  IPS block-log for Malicious verdicts
- CLI summary output plus a full JSON export of all detections
- Unit tests covering the core matching and aggregation logic

## Architecture

| Module | Responsibility |
|---|---|
| `types.rs` | Shared structs and enums: `Flow`, `Signature`, `Verdict`, `Detection` |
| `ingestion.rs` | Parses pcap files into per-packet `Flow` records |
| `aggregate.rs` | Merges per-packet records into per-connection flows |
| `signatures.rs` | AbuseIPDB client and local signature cache |
| `detector.rs` | Pure matching logic: flow vs. signature set |
| `classifier.rs` | Verdict assignment and simulated IPS block logging |
| `report.rs` | CLI summary and JSON export |
| `main.rs` | CLI argument parsing and pipeline wiring |

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

For environments without outbound access to AbuseIPDB, set
`SIG_IDS_OFFLINE=1` to load signatures from a bundled fixture
(`sample_signatures.json`) instead of calling the live API:

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

## API used

AbuseIPDB IP blacklist (`/v2/blacklist`), free tier: 1,000 checks/day.

## Technical Notes

- **Signature coverage**: `detector.rs` implements matching for `IocKind::Ip`,
  `Domain`, and `Url`. Only `Ip` is currently populated (AbuseIPDB
  blacklist). Domain/URL matching activates without code changes once a
  feed like URLhaus or ThreatFox is wired into `signatures.rs`
- **Hostname resolution**: derived from HTTP `Host` headers and DNS query
  names in `ingestion.rs`. TLS SNI parsing from ClientHello records is not
  yet implemented, so HTTPS connections without a preceding HTTP/DNS
  exchange in the same pcap have no hostname
- **Hash matching**: `IocKind::Hash` exists in `types.rs` for AV-style
  payload-hash matching but has no populating source
- **Matching complexity**: `match_flow()` is O(n) per flow — a linear scan
  over the signature `Vec`. Fine at AbuseIPDB blacklist scale (low
  thousands of IOCs); a `HashMap<String, Signature>` keyed by
  `(IocKind, indicator)` would give O(1) lookups for larger feeds
- **Verdict thresholds**: `classifier.rs` maps confidence >= 75 to
  `Malicious`, otherwise `Suspicious`. AbuseIPDB's blacklist endpoint only
  returns entries at confidence >= 90, so `Suspicious` is unreachable with
  this feed alone — it activates once a lower-confidence source is added
- **Capture mode**: traffic is read from pcap files via `pcap-file`
  (no root required). Live capture via `pnet`/`pcap` is not implemented
- **Toolchain**: pinned to Rust 1.75. `reqwest` was swapped for
  `ureq`/`native-tls`, and `openssl`, `openssl-sys`, `clap`, and `url` are
  version-pinned in `Cargo.toml` to avoid transitive dependencies that
  require edition2024
