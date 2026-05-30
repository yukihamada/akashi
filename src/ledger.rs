//! Document ledger: append-only, content-addressed, Ed25519-chained.
//!
//! Built directly on PACT's generic primitives (Envelope / canonical JSON /
//! sha256 / Ed25519). Each document version is one `Envelope` with kind="doc";
//! `prev` chains every record so the head id transitively commits to the whole
//! history. `verify_chain` re-derives every property from the records alone —
//! no trust in this server required.

use pact::canonical::canonical;
use pact::crypto::{verify_sig, Identity};
use pact::hash::sha256_hex;
use pact::ledger::core_value;
use pact::model::{Actor, Envelope};
use serde_json::Value;

pub const PACT_VERSION: &str = "0.1";
pub const ERA: &str = "akashi/2026";

/// Append a new envelope to a work's chain. `prev` is the current head id (None
/// for the genesis record). Returns the fully-formed, signed envelope.
#[allow(clippy::too_many_arguments)]
pub fn append(
    lid: &str,
    prev: Option<String>,
    kind: &str,
    payload: Value,
    ts: &str,
    actor: Actor,
    identity: &Identity,
) -> Envelope {
    let cid = sha256_hex(canonical(&payload).as_bytes());
    let mut env = Envelope {
        pact: PACT_VERSION.to_string(),
        cid,
        id: String::new(),
        prev,
        kind: kind.to_string(),
        ledger: lid.to_string(),
        ts: ts.to_string(),
        era: ERA.to_string(),
        actor,
        payload,
        sig: String::new(),
    };
    let id = sha256_hex(canonical(&core_value(&env)).as_bytes());
    env.id = id.clone();
    env.sig = identity.sign_hex(id.as_bytes());
    env
}

/// The standard human actor for a work (key resolves the signature offline).
pub fn human_actor(lid: &str, identity: &Identity) -> Actor {
    Actor {
        kind: "human".to_string(),
        id: format!("urn:akashi:work:{lid}"),
        key: identity.pubkey_hex(),
        model: None,
    }
}

#[derive(Debug, Default, serde::Serialize)]
pub struct ChainReport {
    pub records: usize,
    pub ok: bool,
    pub errors: Vec<ChainError>,
}

#[derive(Debug, serde::Serialize)]
pub struct ChainError {
    pub index: usize,
    pub id: String,
    pub message: String,
}

/// Independently re-derive content ids, chain links and signatures. This is the
/// generic integrity check (PACT's `verify` adds accounting-gate checks we don't
/// need for documents). Catches: payload tampering (cid mismatch), broken chain
/// links, forged/invalid signatures.
pub fn verify_chain(records: &[Envelope]) -> ChainReport {
    let mut rep = ChainReport {
        records: records.len(),
        ok: true,
        errors: Vec::new(),
    };
    let mut err = |i: usize, id: &str, msg: String| {
        rep.ok = false;
        rep.errors.push(ChainError {
            index: i,
            id: id.to_string(),
            message: msg,
        });
    };

    let mut expected_prev: Option<String> = None;
    for (i, env) in records.iter().enumerate() {
        // 1. content id must match the payload bytes
        let cid = sha256_hex(canonical(&env.payload).as_bytes());
        if cid != env.cid {
            err(i, &env.id, format!("cid mismatch: payload was altered (got {cid})"));
        }
        // 2. chain link must point at the previous record's id
        if env.prev != expected_prev {
            err(
                i,
                &env.id,
                format!("broken chain: prev={:?} expected={:?}", env.prev, expected_prev),
            );
        }
        // 3. the id must be the hash of the canonical core (binds prev+cid+actor+ts)
        let id = sha256_hex(canonical(&core_value(env)).as_bytes());
        if id != env.id {
            err(i, &env.id, format!("id mismatch: core was altered (got {id})"));
        }
        // 4. signature must verify against the actor's embedded key
        if !verify_sig(&env.actor.key, env.id.as_bytes(), &env.sig) {
            err(i, &env.id, "signature does not verify".to_string());
        }
        expected_prev = Some(env.id.clone());
    }
    rep
}
