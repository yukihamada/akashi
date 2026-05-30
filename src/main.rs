//! アカシ (Akashi) — document version control with tamper-evident,
//! blockchain-anchored evidence.
//!
//! Every document version is appended to a per-work, Ed25519-signed,
//! content-addressed chain (PACT primitives). The chain head is anchored to
//! Bitcoin (OpenTimestamps) and Solana (instant memo). Anyone — no account —
//! can verify a file's existence, authorship and timeline offline.

use akashi::{anchor, ids, ledger, store};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Multipart, Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    services::ServeDir,
};
use tracing::{error, info, warn};

#[derive(Clone)]
struct Config {
    data_dir: String,
    static_dir: String,
    base_url: String,
    master_signing_secret: String,
    edit_token_secret: String,
    solana_rpc_url: String,
    solana_secret: Option<String>,
}

#[derive(Clone)]
struct AppState {
    db: store::Db,
    http: reqwest::Client,
    cfg: Arc<Config>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.into());
    let cfg = Config {
        data_dir: env("DATA_DIR", "data"),
        static_dir: env("STATIC_DIR", "frontend"),
        base_url: env("BASE_URL", "http://localhost:8080"),
        master_signing_secret: env("MASTER_SIGNING_SECRET", "dev-signing-secret-change-me"),
        edit_token_secret: env("EDIT_TOKEN_SECRET", "dev-edit-secret-change-me"),
        solana_rpc_url: env("SOLANA_RPC_URL", "https://api.devnet.solana.com"),
        solana_secret: std::env::var("SOLANA_SECRET").ok().filter(|s| !s.trim().is_empty()),
    };
    let db_path = env("DATABASE_PATH", "akashi.db");
    let port: u16 = env("PORT", "8080").parse().unwrap_or(8080);

    std::fs::create_dir_all(&cfg.data_dir).ok();
    let state = AppState {
        db: Arc::new(std::sync::Mutex::new(store::init(&db_path))),
        http: reqwest::Client::builder()
            .user_agent("akashi/0.1")
            .timeout(Duration::from_secs(20))
            .build()
            .expect("http client"),
        cfg: Arc::new(cfg),
    };

    if let Some(sec) = &state.cfg.solana_secret {
        match anchor::solana_key(sec) {
            Ok(k) => info!("solana anchor enabled, pubkey={}", anchor::solana_pubkey_b58(&k)),
            Err(e) => warn!("solana key invalid: {e}"),
        }
    }

    // Background worker: upgrade pending OpenTimestamps proofs once Bitcoin
    // confirms them (~hours). Runs every 10 minutes.
    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(600));
            loop {
                tick.tick().await;
                upgrade_pending_ots(&st).await;
            }
        });
    }

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/app", get(serve_app))
        .route("/verify", get(serve_verify))
        .route("/api/works", post(create_work))
        .route("/api/works/:lid", get(get_work))
        .route("/api/works/:lid/versions", post(add_version))
        .route("/api/works/:lid/ledger.jsonl", get(get_ledger))
        .route("/api/works/:lid/proof.ots", get(get_proof))
        .route("/api/cas/:hash", get(cas_get))
        .route("/api/cas/:hash/verify", get(cas_verify))
        .route("/api/verify", post(verify_doc))
        .fallback_service(ServeDir::new(&state.cfg.static_dir).append_index_html_on_directories(true))
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("bind");
    info!(port, "akashi up");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("serve");
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ── static pages ─────────────────────────────────────

async fn serve_app(State(s): State<AppState>) -> Html<String> {
    Html(std::fs::read_to_string(format!("{}/app.html", s.cfg.static_dir)).unwrap_or_default())
}
async fn serve_verify(State(s): State<AppState>) -> Html<String> {
    Html(std::fs::read_to_string(format!("{}/verify.html", s.cfg.static_dir)).unwrap_or_default())
}

// ── create work ──────────────────────────────────────

#[derive(serde::Deserialize)]
struct CreateWork {
    title: String,
    #[serde(default)]
    email: String,
}

async fn create_work(State(s): State<AppState>, Json(req): Json<CreateWork>) -> Response {
    let lid = ids::random_id();
    let identity = ids::work_identity(&s.cfg.master_signing_secret, &lid);
    let pubkey = identity.pubkey_hex();
    let now = now_iso();
    store::insert_work(&s.db, &lid, &req.title, &req.email, &pubkey, &now);

    // genesis envelope binds the work metadata into the chain
    let payload = json!({ "work": { "title": req.title, "created": now } });
    let actor = ledger::human_actor(&lid, &identity);
    let env = ledger::append(&lid, None, "work", payload, &now, actor, &identity);
    store::append_record(&s.db, &lid, 0, &env, None);

    let token = ids::edit_token(&s.cfg.edit_token_secret, &lid);
    Json(json!({
        "lid": lid,
        "signer_pubkey": pubkey,
        "edit_token": token,
        "owner_link": format!("{}/app?lid={}&token={}", s.cfg.base_url, lid, token),
        "public_link": format!("{}/app?lid={}", s.cfg.base_url, lid),
    }))
    .into_response()
}

// ── add version ──────────────────────────────────────

async fn add_version(
    State(s): State<AppState>,
    Path(lid): Path<String>,
    mut mp: Multipart,
) -> Response {
    if !store::work_exists(&s.db, &lid) {
        return (StatusCode::NOT_FOUND, "no such work").into_response();
    }
    let mut token = String::new();
    let mut title = String::new();
    let mut note = String::new();
    let mut doc_type = String::from("file");
    let mut filename = String::new();
    let mut mime = String::from("application/octet-stream");
    let mut bytes: Vec<u8> = Vec::new();

    while let Ok(Some(field)) = mp.next_field().await {
        match field.name().unwrap_or("") {
            "token" => token = field.text().await.unwrap_or_default(),
            "title" => title = field.text().await.unwrap_or_default(),
            "note" => note = field.text().await.unwrap_or_default(),
            "doc_type" => doc_type = field.text().await.unwrap_or_default(),
            "file" => {
                filename = field.file_name().unwrap_or("upload").to_string();
                if let Some(ct) = field.content_type() {
                    mime = ct.to_string();
                }
                bytes = field.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
            }
            _ => {}
        }
    }

    if !ids::verify_edit_token(&s.cfg.edit_token_secret, &lid, &token) {
        return (StatusCode::FORBIDDEN, "invalid edit token").into_response();
    }
    if bytes.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty file").into_response();
    }

    // 1. store bytes in CAS
    let doc_hash = match store::cas_put(&s.cfg.data_dir, &bytes) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("cas: {e}")).into_response(),
    };

    // 2. append signed envelope to the chain
    let (prev, seq) = store::head(&s.db, &lid);
    let now = now_iso();
    let identity = ids::work_identity(&s.cfg.master_signing_secret, &lid);
    let payload = json!({
        "doc": {
            "title": title,
            "doc_type": doc_type,
            "sha256": doc_hash,
            "size": bytes.len(),
            "mime": mime,
            "filename": filename,
            "note": note,
            "supersedes": prev,
        }
    });
    let actor = ledger::human_actor(&lid, &identity);
    let env = ledger::append(&lid, prev, "doc", payload, &now, actor, &identity);
    store::append_record(&s.db, &lid, seq, &env, Some(&doc_hash));
    let head_id = env.id.clone();

    // 3. anchor the new head. OTS = authoritative (pending → Bitcoin).
    let mut anchors = Vec::new();
    {
        let dd = s.cfg.data_dir.clone();
        let h = head_id.clone();
        match tokio::task::spawn_blocking(move || anchor::ots_stamp(&dd, &h)).await {
            Ok(Ok(_)) => {
                store::record_anchor(&s.db, &lid, &head_id, "ots", "", "pending", &now);
                anchors.push(json!({"kind":"ots","status":"pending"}));
            }
            Ok(Err(e)) => warn!("ots stamp: {e}"),
            Err(e) => warn!("ots task: {e}"),
        }
    }
    // Solana = instant convenience (only if a funded key is configured).
    if let Some(secret) = &s.cfg.solana_secret {
        match anchor::solana_key(secret) {
            Ok(key) => match anchor::solana_send_memo(&s.http, &s.cfg.solana_rpc_url, &key, &head_id).await {
                Ok(sig) => {
                    store::record_anchor(&s.db, &lid, &head_id, "solana", &sig, "confirmed", &now);
                    anchors.push(json!({"kind":"solana","status":"confirmed","ref":sig}));
                }
                Err(e) => {
                    warn!("solana memo: {e}");
                    store::record_anchor(&s.db, &lid, &head_id, "solana", &e, "failed", &now);
                    anchors.push(json!({"kind":"solana","status":"failed"}));
                }
            },
            Err(e) => warn!("solana key: {e}"),
        }
    }

    Json(json!({
        "ok": true,
        "lid": lid,
        "seq": seq,
        "env_id": head_id,
        "doc_sha256": doc_hash,
        "anchors": anchors,
    }))
    .into_response()
}

// ── read work / verification ─────────────────────────

async fn get_work(State(s): State<AppState>, Path(lid): Path<String>) -> Response {
    if !store::work_exists(&s.db, &lid) {
        return (StatusCode::NOT_FOUND, "no such work").into_response();
    }
    let records = store::records(&s.db, &lid);
    let report = ledger::verify_chain(&records);
    let versions: Vec<_> = records
        .iter()
        .enumerate()
        .filter(|(_, e)| e.kind == "doc")
        .map(|(seq, e)| {
            json!({
                "seq": seq,
                "env_id": e.id,
                "cid": e.cid,
                "ts": e.ts,
                "doc": e.payload.get("doc"),
            })
        })
        .collect();
    let anchors = store::anchors_for(&s.db, &lid);
    Json(json!({
        "lid": lid,
        "chain_ok": report.ok,
        "chain_errors": report.errors,
        "signer_key": records.first().map(|e| e.actor.key.clone()),
        "versions": versions,
        "anchors": anchors,
    }))
    .into_response()
}

async fn get_ledger(State(s): State<AppState>, Path(lid): Path<String>) -> Response {
    if !store::work_exists(&s.db, &lid) {
        return (StatusCode::NOT_FOUND, "no such work").into_response();
    }
    let jsonl = store::ledger_jsonl(&s.db, &lid);
    ([(header::CONTENT_TYPE, "application/x-ndjson")], jsonl).into_response()
}

async fn get_proof(State(s): State<AppState>, Path(lid): Path<String>) -> Response {
    // serve the OTS proof for the work's most recent head
    let anchors = store::anchors_for(&s.db, &lid);
    let records = store::records(&s.db, &lid);
    let head = match records.last() {
        Some(e) => e.id.clone(),
        None => return (StatusCode::NOT_FOUND, "empty").into_response(),
    };
    if !anchors.iter().any(|a| a.kind == "ots") {
        return (StatusCode::NOT_FOUND, "no ots proof").into_response();
    }
    let (_, ots) = anchor::ots_paths(&s.cfg.data_dir, &head);
    match std::fs::read(&ots) {
        Ok(b) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{lid}.head.ots\""),
                ),
            ],
            b,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "proof not ready").into_response(),
    }
}

async fn cas_get(State(s): State<AppState>, Path(hash): Path<String>) -> Response {
    match store::cas_get(&s.cfg.data_dir, &hash) {
        Some(b) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            b,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn cas_verify(State(s): State<AppState>, Path(hash): Path<String>) -> Response {
    match store::cas_get(&s.cfg.data_dir, &hash) {
        Some(b) => {
            let recomputed = format!("sha256:{}", store::sha256_hex_raw(&b));
            let want = if hash.starts_with("sha256:") { hash.clone() } else { format!("sha256:{hash}") };
            Json(json!({ "hash": want, "present": true, "recomputed": recomputed, "ok": recomputed == want }))
                .into_response()
        }
        None => Json(json!({ "present": false, "ok": false })).into_response(),
    }
}

/// Public verification: upload a file (multipart `file`) OR pass `?hash=` /
/// `?id=`. Returns the certificate: where/when the bytes were sealed, by which
/// key, the chain integrity status, and the anchors.
async fn verify_doc(State(s): State<AppState>, mut mp: Multipart) -> Response {
    let mut bytes: Vec<u8> = Vec::new();
    while let Ok(Some(field)) = mp.next_field().await {
        if field.name() == Some("file") {
            bytes = field.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
        }
    }
    if bytes.is_empty() {
        return (StatusCode::BAD_REQUEST, "no file").into_response();
    }
    let doc_hash = format!("sha256:{}", store::sha256_hex_raw(&bytes));
    match store::find_by_doc_hash(&s.db, &doc_hash) {
        None => Json(json!({ "found": false, "sha256": doc_hash })).into_response(),
        Some((lid, env_id)) => {
            let records = store::records(&s.db, &lid);
            let report = ledger::verify_chain(&records);
            let env = records.iter().find(|e| e.id == env_id);
            let anchors = store::anchors_for(&s.db, &lid);
            Json(json!({
                "found": true,
                "sha256": doc_hash,
                "lid": lid,
                "env_id": env_id,
                "sealed_at": env.map(|e| e.ts.clone()),
                "signer_key": env.map(|e| e.actor.key.clone()),
                "doc": env.and_then(|e| e.payload.get("doc").cloned()),
                "chain_ok": report.ok,
                "anchors": anchors,
                "note": "Verify trustlessly offline: download ledger.jsonl + proof.ots, then run `ots verify` and re-derive the chain.",
            }))
            .into_response()
        }
    }
}

// ── background: upgrade pending OTS proofs ────────────

async fn upgrade_pending_ots(s: &AppState) {
    let pending = store::pending_anchors(&s.db, "ots");
    for (id, _lid, head_id, _) in pending {
        let dd = s.cfg.data_dir.clone();
        let h = head_id.clone();
        match tokio::task::spawn_blocking(move || anchor::ots_check(&dd, &h)).await {
            Ok(Ok(true)) => {
                store::confirm_anchor(&s.db, id, "bitcoin", &now_iso());
                info!("ots confirmed for head {head_id}");
            }
            Ok(Ok(false)) => {} // still pending
            Ok(Err(e)) => warn!("ots check: {e}"),
            Err(e) => error!("ots task: {e}"),
        }
    }
}
