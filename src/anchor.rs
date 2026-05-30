//! Blockchain anchoring of the ledger head id.
//!
//! Two independent anchors, per the design:
//!   * OpenTimestamps (Bitcoin) — the authoritative, trustless, free anchor.
//!     We shell out to the battle-tested `ots` client; proofs upgrade to a
//!     Bitcoin block over a few hours.
//!   * Solana memo — an *instant* convenience anchor. Built here as a minimal
//!     legacy transaction so we don't pull in the heavy solana-sdk. Devnet by
//!     default; mainnet requires a funded key and explicit opt-in.

use std::path::PathBuf;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};

// ── OpenTimestamps (Bitcoin) ─────────────────────────

fn ots_dir(data_dir: &str) -> PathBuf {
    std::path::Path::new(data_dir).join("ots")
}

fn head_hex(head_id: &str) -> String {
    head_id.strip_prefix("sha256:").unwrap_or(head_id).to_string()
}

/// Paths (.head original, .ots proof) for a head id.
pub fn ots_paths(data_dir: &str, head_id: &str) -> (PathBuf, PathBuf) {
    let h = head_hex(head_id);
    let base = ots_dir(data_dir).join(format!("{h}.head"));
    let ots = ots_dir(data_dir).join(format!("{h}.head.ots"));
    (base, ots)
}

/// Create a pending OTS proof committing to `head_id`. Writes a `.head` file
/// (content = the head id, so anyone can reproduce the digest) and runs
/// `ots stamp`. Returns the proof path on success.
pub fn ots_stamp(data_dir: &str, head_id: &str) -> Result<PathBuf, String> {
    let (base, ots) = ots_paths(data_dir, head_id);
    std::fs::create_dir_all(ots_dir(data_dir)).map_err(|e| e.to_string())?;
    std::fs::write(&base, head_id.as_bytes()).map_err(|e| e.to_string())?;
    let out = Command::new("ots")
        .arg("stamp")
        .arg(&base)
        .output()
        .map_err(|e| format!("ots not available: {e}"))?;
    if !ots.exists() {
        return Err(format!(
            "ots stamp produced no proof: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(ots)
}

/// Try to upgrade a pending proof, then report whether it now carries a Bitcoin
/// attestation. Returns Ok(true) when confirmed on-chain.
pub fn ots_check(data_dir: &str, head_id: &str) -> Result<bool, String> {
    let (_, ots) = ots_paths(data_dir, head_id);
    if !ots.exists() {
        return Err("no ots proof".into());
    }
    // upgrade (no-op if already complete; contacts calendars for Bitcoin attestation)
    let _ = Command::new("ots").arg("upgrade").arg(&ots).output();
    let info = Command::new("ots")
        .arg("info")
        .arg(&ots)
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&info.stdout);
    Ok(text.contains("BitcoinBlockHeaderAttestation"))
}

// ── Solana memo (instant convenience anchor) ─────────

const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// shortvec / compact-u16 length prefix (single byte for len < 128, which
/// always holds here: ≤2 accounts, ≤1 instruction, memo ≤ ~80 bytes).
fn shortvec_len(n: usize) -> Vec<u8> {
    assert!(n < 128, "shortvec fast-path only handles len < 128");
    vec![n as u8]
}

/// Parse SOLANA_SECRET (hex of a 32-byte ed25519 seed) into a signing key.
pub fn solana_key(secret_hex: &str) -> Result<SigningKey, String> {
    let raw = hex::decode(secret_hex.trim()).map_err(|e| format!("bad SOLANA_SECRET hex: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("SOLANA_SECRET must be 32-byte hex seed, got {} bytes", raw.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&raw);
    Ok(SigningKey::from_bytes(&seed))
}

pub fn solana_pubkey_b58(key: &SigningKey) -> String {
    bs58::encode(key.verifying_key().to_bytes()).into_string()
}

/// Send a single-memo legacy transaction and return its signature (base58).
pub async fn solana_send_memo(
    http: &reqwest::Client,
    rpc_url: &str,
    key: &SigningKey,
    memo: &str,
) -> Result<String, String> {
    // 1. recent blockhash
    let bh_resp: serde_json::Value = http
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "getLatestBlockhash",
            "params": [{"commitment": "confirmed"}]
        }))
        .send()
        .await
        .map_err(|e| format!("rpc blockhash: {e}"))?
        .json()
        .await
        .map_err(|e| format!("rpc blockhash decode: {e}"))?;
    let blockhash_b58 = bh_resp["result"]["value"]["blockhash"]
        .as_str()
        .ok_or_else(|| format!("no blockhash in response: {bh_resp}"))?;
    let blockhash = bs58::decode(blockhash_b58)
        .into_vec()
        .map_err(|e| format!("blockhash b58: {e}"))?;

    // 2. build message
    let fee_payer = key.verifying_key().to_bytes().to_vec();
    let memo_prog = bs58::decode(MEMO_PROGRAM_ID).into_vec().unwrap();
    let memo_bytes = memo.as_bytes();

    let mut msg = Vec::new();
    msg.extend_from_slice(&[1, 0, 1]); // header: req_sigs=1, ro_signed=0, ro_unsigned=1
    msg.extend(shortvec_len(2)); // account_keys
    msg.extend_from_slice(&fee_payer);
    msg.extend_from_slice(&memo_prog);
    msg.extend_from_slice(&blockhash); // 32 bytes
    msg.extend(shortvec_len(1)); // instructions
    msg.push(1u8); // program_id_index -> memo program
    msg.extend(shortvec_len(0)); // accounts for the instruction
    msg.extend(shortvec_len(memo_bytes.len()));
    msg.extend_from_slice(memo_bytes);

    // 3. sign + assemble wire transaction
    let sig = key.sign(&msg).to_bytes();
    let mut tx = Vec::new();
    tx.extend(shortvec_len(1)); // signature count
    tx.extend_from_slice(&sig);
    tx.extend_from_slice(&msg);
    let tx_b64 = STANDARD.encode(&tx);

    // 4. send
    let send: serde_json::Value = http
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "sendTransaction",
            "params": [tx_b64, {"encoding": "base64", "skipPreflight": false}]
        }))
        .send()
        .await
        .map_err(|e| format!("rpc send: {e}"))?
        .json()
        .await
        .map_err(|e| format!("rpc send decode: {e}"))?;
    if let Some(sig) = send["result"].as_str() {
        Ok(sig.to_string())
    } else {
        Err(format!("send failed: {send}"))
    }
}
