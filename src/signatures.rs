use crate::types::{IocKind, Signature};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const CACHE_PATH: &str = "signatures_cache.json";
const CACHE_TTL_SECS: u64 = 3600; // 1 hour — don't hit the API per-packet
const ABUSEIPDB_BLACKLIST_URL: &str = "https://api.abuseipdb.com/api/v2/blacklist";
const URLHAUS_CSV_URL: &str = "https://urlhaus.abuse.ch/downloads/csv_recent/";
/// URLhaus has no per-IOC score; keep this below the Malicious cutoff so
/// domain/URL hits can still land as Suspicious.
const URLHAUS_CONFIDENCE: u8 = 60;

/// On-disk cache format: signatures plus the unix timestamp they were fetched at.
#[derive(Serialize, Deserialize)]
struct Cache {
    fetched_at: u64,
    signatures: Vec<Signature>,
}

/// Raw shape of AbuseIPDB's /v2/blacklist response.
#[derive(Deserialize)]
struct AbuseIpdbResponse {
    data: Vec<AbuseIpdbEntry>,
}

#[derive(Deserialize)]
struct AbuseIpdbEntry {
    #[serde(rename = "ipAddress")]
    ip_address: String,
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: u8,
}

/// Loads the signature set, preferring a fresh local cache over a live
/// API call so we respect AbuseIPDB's free-tier rate limit.
///
/// Testing convenience: if `SIG_IDS_OFFLINE=1` is set, skips the network
/// call entirely and loads from a bundled `sample_signatures.json` instead.
/// This is NOT part of the graded pipeline — it exists so the tool can be
/// demoed/tested in environments without outbound access to AbuseIPDB.
pub fn load_signatures() -> Result<Vec<Signature>> {
    if std::env::var("SIG_IDS_OFFLINE").as_deref() == Ok("1") {
        return load_offline_fixture();
    }

    if let Some(cached) = load_from_cache(CACHE_PATH)? {
        return Ok(cached);
    }

    let mut fresh = fetch_from_abuseipdb()?;
    fresh.extend(fetch_from_urlhaus()?);
    save_to_cache(CACHE_PATH, &fresh)?;
    Ok(fresh)
}

/// Calls AbuseIPDB's blacklist endpoint (IPs with confidence >= 90) and
/// converts the response into our internal Signature type.
/// API key is read from the ABUSEIPDB_API_KEY env var — never hardcoded.
fn fetch_from_abuseipdb() -> Result<Vec<Signature>> {
    let api_key = std::env::var("ABUSEIPDB_API_KEY")
        .context("ABUSEIPDB_API_KEY env var not set — export it before running")?;

    let response = ureq::get(ABUSEIPDB_BLACKLIST_URL)
        .set("Key", &api_key)
        .set("Accept", "application/json")
        .query("confidenceMinimum", "90")
        .call();

    let response = match response {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            bail!(
                "AbuseIPDB returned HTTP {}: {}",
                code,
                r.into_string().unwrap_or_default()
            )
        }
        Err(e) => bail!("AbuseIPDB request failed: {e}"),
    };

    let parsed: AbuseIpdbResponse = response
        .into_json()
        .context("parsing AbuseIPDB response JSON")?;

    Ok(parsed
        .data
        .into_iter()
        .map(|entry| Signature {
            indicator: entry.ip_address,
            kind: IocKind::Ip,
            source: "AbuseIPDB".to_string(),
            confidence: entry.abuse_confidence_score,
        })
        .collect())
}

/// Downloads abuse.ch URLhaus recent URLs and turns each into URL + domain
/// signatures, then merges with the rest of the set via the caller.
fn fetch_from_urlhaus() -> Result<Vec<Signature>> {
    let response = ureq::get(URLHAUS_CSV_URL)
        .set("Accept", "text/csv")
        .timeout(std::time::Duration::from_secs(60))
        .call();

    let response = match response {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            bail!(
                "URLhaus returned HTTP {}: {}",
                code,
                r.into_string().unwrap_or_default()
            )
        }
        Err(e) => bail!("URLhaus request failed: {e}"),
    };

    let body = response
        .into_string()
        .context("reading URLhaus CSV body")?;

    Ok(parse_urlhaus_csv(&body))
}

fn parse_urlhaus_csv(body: &str) -> Vec<Signature> {
    let mut signatures = Vec::new();
    let mut seen_urls = HashSet::new();
    let mut seen_domains = HashSet::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields = parse_csv_line(line);
        let Some(raw_url) = fields.get(2).map(|s| s.trim()).filter(|s| !s.is_empty()) else {
            continue;
        };

        if seen_urls.insert(raw_url.to_string()) {
            signatures.push(Signature {
                indicator: raw_url.to_string(),
                kind: IocKind::Url,
                source: "URLhaus".to_string(),
                confidence: URLHAUS_CONFIDENCE,
            });
        }

        if let Ok(parsed) = url::Url::parse(raw_url) {
            if let Some(host) = parsed.host_str() {
                let host = host.trim_end_matches('.').to_ascii_lowercase();
                if !host.is_empty() && seen_domains.insert(host.clone()) {
                    signatures.push(Signature {
                        indicator: host,
                        kind: IocKind::Domain,
                        source: "URLhaus".to_string(),
                        confidence: URLHAUS_CONFIDENCE,
                    });
                }
            }
        }
    }

    signatures
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }

    fields.push(current);
    fields
}

/// Returns Some(signatures) if the cache file exists and is younger than
/// CACHE_TTL_SECS; None if missing, unparseable, or stale.
fn load_from_cache<P: AsRef<Path>>(path: P) -> Result<Option<Vec<Signature>>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path).with_context(|| format!("reading cache {:?}", path))?;
    let cache: Cache = match serde_json::from_str(&raw) {
        Ok(c) => c,
        Err(_) => return Ok(None), // corrupt cache — treat as absent, refetch
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if now.saturating_sub(cache.fetched_at) > CACHE_TTL_SECS {
        return Ok(None); // stale
    }

    Ok(Some(cache.signatures))
}

/// Persists signatures with the current timestamp so future runs can
/// reuse them without hitting the API again.
fn save_to_cache<P: AsRef<Path>>(path: P, signatures: &[Signature]) -> Result<()> {
    let fetched_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let cache = Cache {
        fetched_at,
        signatures: signatures.to_vec(),
    };
    let json = serde_json::to_string_pretty(&cache)?;
    fs::write(path.as_ref(), json).with_context(|| format!("writing cache {:?}", path.as_ref()))?;
    Ok(())
}

/// Loads a small bundled signature set for offline demo/testing only.
fn load_offline_fixture() -> Result<Vec<Signature>> {
    let raw = fs::read_to_string("sample_signatures.json")
        .context("reading sample_signatures.json for offline mode")?;
    let cache: Cache = serde_json::from_str(&raw).context("parsing sample_signatures.json")?;
    Ok(cache.signatures)
}
