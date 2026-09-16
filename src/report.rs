use crate::types::{Detection, Verdict};
use anyhow::Result;
use std::fs::File;

/// Module 7: prints a human-readable CLI summary table.
pub fn print_summary(detections: &[Detection]) {
    let benign = detections
        .iter()
        .filter(|d| d.verdict == Verdict::Benign)
        .count();
    let suspicious = detections
        .iter()
        .filter(|d| d.verdict == Verdict::Suspicious)
        .count();
    let malicious = detections
        .iter()
        .filter(|d| d.verdict == Verdict::Malicious)
        .count();

    println!("=== Detection Summary ===");
    println!("Total flows:  {}", detections.len());
    println!("Benign:       {}", benign);
    println!("Suspicious:   {}", suspicious);
    println!("Malicious:    {}", malicious);

    for d in detections.iter().filter(|d| d.verdict != Verdict::Benign) {
        println!(
            "  [{:?}] {} -> {} ({}:{})",
            d.verdict, d.flow.src_ip, d.flow.dst_ip, d.flow.src_port, d.flow.dst_port
        );
    }
}

/// Module 7: exports all detections to a JSON file.
pub fn export_json(detections: &[Detection], path: &str) -> Result<()> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, detections)?;
    Ok(())
}
