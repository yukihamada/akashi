//! Identifiers, edit tokens and per-work signing keys.
//!
//! Design choice (MVP): we never store private key material in the DB. Each
//! work's signing seed and owner edit-token are *derived* from server master
//! secrets via HMAC-SHA256(secret, lid). Compromise surface is the env secret,
//! not the database. Client-held keys (WebCrypto) are a Phase-2 upgrade.

use hmac::{Hmac, Mac};
use pact::crypto::Identity;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn hmac32(secret: &str, msg: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(msg.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..32]);
    seed
}

/// A random url-safe id (base58, 16 bytes of entropy).
pub fn random_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("os rng");
    bs58::encode(buf).into_string()
}

/// Deterministic Ed25519 identity for a work, derived from the master secret.
pub fn work_identity(master_signing_secret: &str, lid: &str) -> Identity {
    Identity::from_seed(&hmac32(master_signing_secret, lid))
}

/// Owner edit token = hex(HMAC(edit_secret, lid)). Stateless proof-of-authority.
pub fn edit_token(edit_secret: &str, lid: &str) -> String {
    hex::encode(hmac32(edit_secret, lid))
}

/// Constant-time-ish comparison for the edit token.
pub fn verify_edit_token(edit_secret: &str, lid: &str, presented: &str) -> bool {
    let expected = edit_token(edit_secret, lid);
    // length check first, then byte-accumulating compare
    if expected.len() != presented.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(presented.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}
