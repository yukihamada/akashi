//! アカシ (Akashi) library: tamper-evident document ledger primitives, shared
//! by the server binary (`main.rs`) and the standalone offline verifier
//! (`bin/akashi-verify.rs`).

pub mod anchor;
pub mod ids;
pub mod ledger;
pub mod store;
