mod classifier;
mod detector;
mod ingestion;
mod report;
mod signatures;
mod types;

use anyhow::Result;
use clap::Parser;

/// Module 8: CLI entry point wiring the full pipeline together.
#[derive(Parser, Debug)]
#[command(name = "sig-ids", about = "Signature-based traffic detection engine")]
struct Args {
    /// Path to the .pcap file to analyze
    #[arg(short, long)]
    pcap: String,

    /// Path to write the JSON detection report
    #[arg(short, long, default_value = "detections.json")]
    output: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Pipeline: ingest -> load signatures -> match each flow -> classify -> report
    let flows = ingestion::read_pcap(&args.pcap)?;
    let signatures = signatures::load_signatures()?;

    let detections: Vec<_> = flows
        .into_iter()
        .map(|flow| {
            let matched = detector::match_flow(&flow, &signatures).cloned();
            classifier::classify(flow, matched.as_ref())
        })
        .collect();

    report::print_summary(&detections);
    report::export_json(&detections, &args.output)?;

    Ok(())
}
