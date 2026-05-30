#!/usr/bin/env bash
# End-to-end test for アカシ. Writes a PASS/FAIL summary to /tmp/akashi_e2e.txt.
set -u
cd "$(dirname "$0")/.."
OUT=/tmp/akashi_e2e.txt
: > "$OUT"
say(){ echo "$@" | tee -a "$OUT"; }
DATA=/tmp/akashi_data
rm -rf "$DATA"; mkdir -p "$DATA"

say "=== 1. build ==="
if cargo build >/tmp/akashi_build.log 2>&1; then say "build: OK"; else say "build: FAIL"; tail -20 /tmp/akashi_build.log >>"$OUT"; exit 1; fi

# Solana devnet key (best-effort instant anchor)
SEED=$(openssl rand -hex 32)
say "=== 2. start server ==="
DATA_DIR="$DATA" DATABASE_PATH="$DATA/akashi.db" STATIC_DIR=frontend \
  BASE_URL=http://localhost:8765 PORT=8765 \
  MASTER_SIGNING_SECRET=e2e-sign EDIT_TOKEN_SECRET=e2e-edit \
  SOLANA_RPC_URL=https://api.devnet.solana.com SOLANA_SECRET="$SEED" \
  ./target/debug/akashi >/tmp/akashi_srv.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
for i in $(seq 1 40); do curl -fsS http://localhost:8765/health >/dev/null 2>&1 && break; sleep 0.25; done
if curl -fsS http://localhost:8765/health >/dev/null 2>&1; then say "health: OK"; else say "health: FAIL"; tail -20 /tmp/akashi_srv.log >>"$OUT"; exit 1; fi

# best-effort devnet airdrop so the Solana anchor can confirm
PUB=$(grep -o 'pubkey=[^ ]*' /tmp/akashi_srv.log | head -1 | cut -d= -f2)
say "solana pubkey: ${PUB:-none}"
if [ -n "${PUB:-}" ]; then
  curl -fsS https://api.devnet.solana.com -X POST -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"requestAirdrop\",\"params\":[\"$PUB\",1000000000]}" >/tmp/akashi_air.json 2>&1
  say "airdrop req: $(cat /tmp/akashi_air.json)"
  sleep 12
fi

say "=== 3. create work ==="
curl -fsS -X POST http://localhost:8765/api/works -H 'content-type: application/json' \
  -d '{"title":"研究ノート E2E","email":"e2e@example.com"}' >/tmp/akashi_work.json
LID=$(python3 -c 'import json;print(json.load(open("/tmp/akashi_work.json"))["lid"])')
TOK=$(python3 -c 'import json;print(json.load(open("/tmp/akashi_work.json"))["edit_token"])')
PUBKEY=$(python3 -c 'import json;print(json.load(open("/tmp/akashi_work.json"))["signer_pubkey"])')
say "lid=$LID"; say "signer=$PUBKEY"
[ -n "$LID" ] && say "create: OK" || { say "create: FAIL"; exit 1; }

say "=== 4. upload version ==="
echo "アカシ — 私が最初に作った原稿 v1 ($(date))" > "$DATA/manuscript.txt"
curl -fsS -X POST "http://localhost:8765/api/works/$LID/versions" \
  -F "token=$TOK" -F "title=v1 初稿" -F "note=first draft" \
  -F "file=@$DATA/manuscript.txt" >/tmp/akashi_up.json
cat /tmp/akashi_up.json >>"$OUT"; echo >>"$OUT"
UPOK=$(python3 -c 'import json;print(json.load(open("/tmp/akashi_up.json")).get("ok"))')
[ "$UPOK" = "True" ] && say "upload: OK" || { say "upload: FAIL"; exit 1; }

say "=== 5. get work (chain status + anchors) ==="
curl -fsS "http://localhost:8765/api/works/$LID" >/tmp/akashi_get.json
python3 - <<'PY' | tee -a "$OUT"
import json
w=json.load(open("/tmp/akashi_get.json"))
print("chain_ok:", w["chain_ok"])
print("versions:", len(w["versions"]))
print("anchors:", [(a["kind"],a["status"],a.get("ref","")[:24]) for a in w["anchors"]])
PY

say "=== 6. download ledger + OFFLINE verify (intact) ==="
curl -fsS "http://localhost:8765/api/works/$LID/ledger.jsonl" > "$DATA/ledger.jsonl"
say "ledger lines: $(wc -l < "$DATA/ledger.jsonl")"
if ./target/debug/akashi-verify "$DATA/ledger.jsonl" >>"$OUT" 2>&1; then say "offline verify (clean): OK (intact)"; else say "offline verify (clean): FAIL"; fi

say "=== 7. tamper a byte -> must be detected ==="
python3 - "$DATA/ledger.jsonl" "$DATA/tampered.jsonl" <<'PY'
import sys
lines=open(sys.argv[1]).read().splitlines()
# alter the doc record's note silently (no re-hash/re-sign)
out=[]
for ln in lines:
    if '"first draft"' in ln:
        ln=ln.replace('"first draft"','"FORGED edit"')
    out.append(ln)
open(sys.argv[2],"w").write("\n".join(out))
PY
if ./target/debug/akashi-verify "$DATA/tampered.jsonl" >/tmp/akashi_tamper.txt 2>&1; then
  say "tamper detection: FAIL (verifier said intact!)"; cat /tmp/akashi_tamper.txt >>"$OUT"
else
  say "tamper detection: OK (rejected)"; grep -i "tamper\|mismatch" /tmp/akashi_tamper.txt | tee -a "$OUT"
fi

say "=== 8. public verify by file (no account) ==="
curl -fsS -X POST http://localhost:8765/api/verify -F "file=@$DATA/manuscript.txt" >/tmp/akashi_ver.json
python3 - <<'PY' | tee -a "$OUT"
import json
v=json.load(open("/tmp/akashi_ver.json"))
print("found:", v.get("found"), "chain_ok:", v.get("chain_ok"), "sealed_at:", v.get("sealed_at"))
print("signer:", (v.get("signer_key") or "")[:40])
PY

say "=== 9. OTS proof file present ==="
ls -la "$DATA/ots/" 2>/dev/null | tee -a "$OUT"
[ -n "$(ls "$DATA"/ots/*.ots 2>/dev/null)" ] && say "ots proof: OK" || say "ots proof: (pending/none)"

say "=== 10. solana anchor outcome ==="
grep -i "solana" /tmp/akashi_srv.log | tail -3 | tee -a "$OUT"

say ""; say "=== SUMMARY ==="; grep -E ": OK| FAIL|detection:" "$OUT" | tee -a "$OUT".sum
