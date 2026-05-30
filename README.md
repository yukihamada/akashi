# アカシ (Akashi)

Document version control with **tamper-evident, blockchain-anchored evidence** —
"GitHub for documents" where every version is provable.

For: 発明者・クリエイター who need to prove *when* they made something
(特許30条 / 著作 / 先願), and **anyone** who needs to verify it — no account.

## How it works

- Each **work** is a per-work, Ed25519-signed, content-addressed append-only
  chain (PACT primitives, vendored in `src/pact_core.rs`). Each document version
  is one envelope; `prev` chains every record so the head id transitively
  commits to the whole history.
- The chain head is **anchored to two chains**: OpenTimestamps (Bitcoin —
  authoritative, free, trustless) and a Solana memo (instant convenience).
- **Trustless verification**: download `ledger.jsonl` + `proof.ots` and verify
  offline with `akashi-verify` and `ots verify` — no trust in this server.

## Personas

1. **発明者・クリエイター** — create a work, upload versions, get a public proof URL.
2. **検証者 (no account)** — drop a file at `/verify` → certificate of existence/authorship/timeline.
3. Co-authors / 士業・法人 — roadmap (multi-signer attestations, matters).

## Run locally

```bash
cargo run                       # http://localhost:8080
bash scripts/e2e.sh             # full end-to-end test
```

## API

| Method | Path | |
|---|---|---|
| POST | `/api/works` | create a work → `{lid, edit_token, owner_link}` |
| POST | `/api/works/:lid/versions` | upload a version (multipart, `token` required) |
| GET  | `/api/works/:lid` | versions + chain status + anchors |
| GET  | `/api/works/:lid/ledger.jsonl` | offline-verifiable ledger |
| GET  | `/api/works/:lid/proof.ots` | OpenTimestamps proof |
| GET  | `/api/cas/:hash` (+`/verify`) | content-addressed blob |
| POST | `/api/verify` | verify an uploaded file → certificate |

## Offline verification

```bash
curl -s $BASE/api/works/$LID/ledger.jsonl > ledger.jsonl
akashi-verify ledger.jsonl          # re-derives every cid / chain link / signature
curl -s $BASE/api/works/$LID/proof.ots > p.ots
ots verify p.ots                    # Bitcoin attestation (once confirmed)
```

## Notes / MVP scope

- Signing keys are **server-custodied** (derived from `MASTER_SIGNING_SECRET`).
  Client-held keys (WebCrypto) are a Phase-2 upgrade.
- Solana runs on **devnet**. Mainnet incurs real cost — opt-in only.
- An OpenTimestamps proof reaches Bitcoin confirmation in ~hours; until then it
  shows `pending` and is upgraded by a background worker.

PACT primitives reused under Apache-2.0 (github.com/yukihamada/pact).
株式会社イネブラ / Enabler Inc.
