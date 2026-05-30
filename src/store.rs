//! Persistence: SQLite index + file-based content-addressed blob store (CAS).
//!
//! The canonical source of truth is the append-only chain of envelopes
//! (`records.env_json`). The other columns are just a queryable index; CAS
//! stores the actual document bytes by their sha256.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use pact::model::Envelope;
use rusqlite::{params, Connection, OptionalExtension};

pub type Db = Arc<Mutex<Connection>>;

pub fn init(db_path: &str) -> Connection {
    let conn = Connection::open(db_path).expect("open sqlite");
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS works (
            lid           TEXT PRIMARY KEY,
            title         TEXT NOT NULL DEFAULT '',
            owner_email   TEXT NOT NULL DEFAULT '',
            signer_pubkey TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS records (
            lid        TEXT NOT NULL,
            seq        INTEGER NOT NULL,
            env_id     TEXT NOT NULL,
            prev       TEXT,
            cid        TEXT NOT NULL,
            kind       TEXT NOT NULL,
            doc_sha256 TEXT,
            ts         TEXT NOT NULL,
            env_json   TEXT NOT NULL,
            PRIMARY KEY (lid, seq)
         );
         CREATE INDEX IF NOT EXISTS idx_records_env_id  ON records(env_id);
         CREATE INDEX IF NOT EXISTS idx_records_dochash ON records(doc_sha256);
         CREATE TABLE IF NOT EXISTS anchors (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            lid          TEXT NOT NULL,
            head_id      TEXT NOT NULL,
            kind         TEXT NOT NULL,        -- 'solana' | 'ots'
            ref          TEXT NOT NULL DEFAULT '',
            status       TEXT NOT NULL,        -- 'pending' | 'confirmed' | 'failed'
            created_at   TEXT NOT NULL,
            confirmed_at TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_anchors_lid ON anchors(lid);",
    )
    .expect("init schema");
    conn
}

// ── works ───────────────────────────────────────────

pub fn insert_work(db: &Db, lid: &str, title: &str, email: &str, pubkey: &str, now: &str) {
    let c = db.lock().unwrap();
    c.execute(
        "INSERT INTO works (lid, title, owner_email, signer_pubkey, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![lid, title, email, pubkey, now],
    )
    .expect("insert work");
}

pub fn work_exists(db: &Db, lid: &str) -> bool {
    let c = db.lock().unwrap();
    c.query_row("SELECT 1 FROM works WHERE lid=?1", params![lid], |_| Ok(()))
        .optional()
        .unwrap()
        .is_some()
}

// ── records (append-only) ────────────────────────────

/// Current head (last env_id, highest seq) of a work, plus next seq number.
pub fn head(db: &Db, lid: &str) -> (Option<String>, i64) {
    let c = db.lock().unwrap();
    c.query_row(
        "SELECT env_id, seq FROM records WHERE lid=?1 ORDER BY seq DESC LIMIT 1",
        params![lid],
        |r| Ok((Some(r.get::<_, String>(0)?), r.get::<_, i64>(1)? + 1)),
    )
    .optional()
    .unwrap()
    .unwrap_or((None, 0))
}

pub fn append_record(db: &Db, lid: &str, seq: i64, env: &Envelope, doc_sha256: Option<&str>) {
    let c = db.lock().unwrap();
    let env_json = serde_json::to_string(env).expect("serialize env");
    c.execute(
        "INSERT INTO records (lid, seq, env_id, prev, cid, kind, doc_sha256, ts, env_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![lid, seq, env.id, env.prev, env.cid, env.kind, doc_sha256, env.ts, env_json],
    )
    .expect("append record");
}

/// All envelopes of a work, in chain order.
pub fn records(db: &Db, lid: &str) -> Vec<Envelope> {
    let c = db.lock().unwrap();
    let mut stmt = c
        .prepare("SELECT env_json FROM records WHERE lid=?1 ORDER BY seq ASC")
        .unwrap();
    let rows = stmt
        .query_map(params![lid], |r| r.get::<_, String>(0))
        .unwrap();
    rows.filter_map(|j| j.ok())
        .filter_map(|j| serde_json::from_str::<Envelope>(&j).ok())
        .collect()
}

/// Raw JSONL (one envelope per line) for offline verification.
pub fn ledger_jsonl(db: &Db, lid: &str) -> String {
    let c = db.lock().unwrap();
    let mut stmt = c
        .prepare("SELECT env_json FROM records WHERE lid=?1 ORDER BY seq ASC")
        .unwrap();
    let rows = stmt
        .query_map(params![lid], |r| r.get::<_, String>(0))
        .unwrap();
    rows.filter_map(|j| j.ok()).collect::<Vec<_>>().join("\n")
}

/// Find the work + envelope that sealed a given document hash (`sha256:<hex>`).
pub fn find_by_doc_hash(db: &Db, doc_sha256: &str) -> Option<(String, String)> {
    let c = db.lock().unwrap();
    c.query_row(
        "SELECT lid, env_id FROM records WHERE doc_sha256=?1 ORDER BY seq ASC LIMIT 1",
        params![doc_sha256],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .optional()
    .unwrap()
}

// ── anchors ──────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct Anchor {
    pub kind: String,
    pub reference: String,
    pub status: String,
    pub created_at: String,
    pub confirmed_at: Option<String>,
}

pub fn record_anchor(db: &Db, lid: &str, head_id: &str, kind: &str, reference: &str, status: &str, now: &str) -> i64 {
    let c = db.lock().unwrap();
    c.execute(
        "INSERT INTO anchors (lid, head_id, kind, ref, status, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![lid, head_id, kind, reference, status, now],
    )
    .expect("insert anchor");
    c.last_insert_rowid()
}

pub fn anchors_for(db: &Db, lid: &str) -> Vec<Anchor> {
    let c = db.lock().unwrap();
    let mut stmt = c
        .prepare("SELECT kind, ref, status, created_at, confirmed_at FROM anchors WHERE lid=?1 ORDER BY id ASC")
        .unwrap();
    let rows = stmt
        .query_map(params![lid], |r| {
            Ok(Anchor {
                kind: r.get(0)?,
                reference: r.get(1)?,
                status: r.get(2)?,
                created_at: r.get(3)?,
                confirmed_at: r.get(4)?,
            })
        })
        .unwrap();
    rows.filter_map(|a| a.ok()).collect()
}

/// (id, lid, head_id, ref) of anchors still pending for a given kind.
pub fn pending_anchors(db: &Db, kind: &str) -> Vec<(i64, String, String, String)> {
    let c = db.lock().unwrap();
    let mut stmt = c
        .prepare("SELECT id, lid, head_id, ref FROM anchors WHERE kind=?1 AND status='pending'")
        .unwrap();
    let rows = stmt
        .query_map(params![kind], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?))
        })
        .unwrap();
    rows.filter_map(|a| a.ok()).collect()
}

pub fn confirm_anchor(db: &Db, id: i64, reference: &str, now: &str) {
    let c = db.lock().unwrap();
    c.execute(
        "UPDATE anchors SET status='confirmed', ref=?2, confirmed_at=?3 WHERE id=?1",
        params![id, reference, now],
    )
    .expect("confirm anchor");
}

// ── CAS (file-based) ─────────────────────────────────

pub fn cas_dir(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("cas")
}

/// Store bytes under their sha256 hex. Returns "sha256:<hex>".
pub fn cas_put(data_dir: &str, bytes: &[u8]) -> std::io::Result<String> {
    let hex = sha256_hex_raw(bytes);
    let dir = cas_dir(data_dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(&hex);
    if !path.exists() {
        std::fs::write(&path, bytes)?;
    }
    Ok(format!("sha256:{hex}"))
}

pub fn cas_get(data_dir: &str, hash: &str) -> Option<Vec<u8>> {
    let hex = hash.strip_prefix("sha256:").unwrap_or(hash);
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) || hex.len() != 64 {
        return None;
    }
    std::fs::read(cas_dir(data_dir).join(hex)).ok()
}

/// sha256 of raw bytes -> 64-char hex (no prefix).
pub fn sha256_hex_raw(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
