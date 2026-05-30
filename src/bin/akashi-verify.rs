//! Standalone, offline ledger verifier — the trustless half of アカシ.
//!
//! Re-derives every content id, chain link and Ed25519 signature from a
//! `ledger.jsonl` file alone. No server, no network, no trust in akashi.
//!
//!   akashi-verify <ledger.jsonl>
//!
//! Exit code 0 = intact, 1 = tampering/破損 detected.

use akashi::ledger::verify_chain;
use pact::model::Envelope;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: akashi-verify <ledger.jsonl>");
        std::process::exit(2);
    });
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        std::process::exit(2);
    });

    let mut records = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Envelope>(line) {
            Ok(env) => records.push(env),
            Err(e) => {
                eprintln!("line {}: parse error: {e}", i + 1);
                std::process::exit(1);
            }
        }
    }

    let report = verify_chain(&records);
    println!("records: {}", report.records);
    if report.ok {
        println!("RESULT: OK intact — every version's content, chain link and signature verifies");
        std::process::exit(0);
    } else {
        println!("RESULT: TAMPERING DETECTED");
        for e in &report.errors {
            let short = &e.id[..e.id.len().min(28)];
            println!("  [#{}] {short} — {}", e.index, e.message);
        }
        std::process::exit(1);
    }
}
