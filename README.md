# sig-ids

Signature-based traffic detection engine (Cognton AI Rust assignment).

## Status
Working end-to-end pipeline for the core requirement (IP-based matching).

1. ✅ Cargo.toml + project structure
2. ✅ PCAP parser (`ingestion.rs`) — reads .pcap via `pcap-file`
3. ✅ IP extraction (`ingestion.rs`) — parses Ethernet/IP/TCP/UDP via `etherparse`
4. ✅ AbuseIPDB API client (`signatures.rs`) — calls `/v2/blacklist`
5. ✅ Cache system (`signatures.rs`) — 1hr local JSON cache, no per-packet calls
6. ✅ IP matching + verdict logic (`detector.rs`, `classifier.rs`) — tested
7. ✅ JSON export (`report.rs`)
8. ✅ CLI (`main.rs`)
9. ⬜ Domain/DNS/SNI handling (bonus, not yet implemented)
10. ✅ Tested with a generated `sample.pcap` (see below)

## Setup
```
export ABUSEIPDB_API_KEY=your_key_here   # never hardcode; get one free at abuseipdb.com
cargo build
cargo test
```

## Generate test traffic
Two ways to get a `sample.pcap`:
- **Real traffic (as required by the assignment):** capture with tcpdump while
  curling known-bad/known-good hosts:
  ```
  sudo tcpdump -i any -w sample.pcap &
  curl <a-urlhaus-listed-bad-domain>
  curl google.com
  # Ctrl+C tcpdump
  ```
- **Synthetic traffic (for quick local testing):** this repo includes a small
  generator that builds a `sample.pcap` with one flow to a known-bad IP and
  two to clean IPs:
  ```
  cargo run --bin gen_sample
  ```

## Run
```
cargo run --bin sig-ids -- --pcap sample.pcap --output detections.json
```

### Offline testing mode
This sandbox's network egress doesn't reach `api.abuseipdb.com`, so it was
verified with a bundled offline fixture instead of a live call:
```
SIG_IDS_OFFLINE=1 cargo run --bin sig-ids -- --pcap sample.pcap --output detections.json
```
This reads `sample_signatures.json` instead of calling AbuseIPDB — useful for
demoing without network access, but **not** part of the graded pipeline. Run
without `SIG_IDS_OFFLINE` (with a real `ABUSEIPDB_API_KEY`) for the actual
submission.

**Verified output** (offline mode, 3-packet sample.pcap):
```
[BLOCKED] 10.0.0.5 -> 1.2.3.4 matched Signature { ... confidence: 95 }
=== Detection Summary ===
Total flows:  3
Benign:       2
Suspicious:   0
Malicious:    1
```

## Architecture
- `types.rs` — shared structs/enums (Flow, Verdict, Signature, Detection)
- `ingestion.rs` — pcap parsing, packet -> flow reassembly
- `signatures.rs` — AbuseIPDB client + local JSON cache
- `detector.rs` — pure matching logic (flow vs signature set), unit tested
- `classifier.rs` — verdict assignment + simulated IPS block-log
- `report.rs` — CLI summary + JSON export
- `main.rs` — CLI args (clap) + pipeline wiring

## API used
AbuseIPDB (IP reputation, free tier: 1,000 checks/day)

## Known limitations
- Domain/URL matching not yet implemented (needs DNS/SNI parsing, module 9) — only IP matching is live
- Live capture not implemented (pcap-file replay only, per assignment core requirement; bonus item)
- Hash-based (AV-style) matching not implemented (bonus item)
- Matching is a linear scan over the signature list; fine at this scale, would move to a HashSet for large IOC feeds
- Built/tested in a sandbox pinned to Rust 1.75 and swapped `reqwest`→`ureq`/`native-tls` to avoid edition2024 transitive deps; on a modern toolchain these pins in Cargo.toml can be relaxed or reqwest used instead
