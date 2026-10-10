#!/usr/bin/env bash
# Smoke test for MCP over streamable HTTP (W7-VERIFY r5 #14): build the CLI, ingest the testdata
# estate into a scratch DB, start `serve --mcp` on a free loopback port with two scoped tokens (read
# from the environment), and walk: unauthenticated → 401; reader: initialize, tools/list (no
# draft_fix), sql; fixer: tools/list (draft_fix listed); reader's session under the fixer's token
# → 404; DELETE ends the session.
#
#   internal/mcp/testdata/smoke_http.sh       # from the repo root
set -euo pipefail
cd "$(dirname "$0")/../../.."
export PATH="$PATH:/opt/homebrew/bin" CLOUD_POSTURE_NO_NETWORK=1 CLOUD_POSTURE_PYTHON=/nonexistent/python
tmp="$(mktemp -d)"
pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$tmp"' EXIT
go build -o "$tmp/cp" ./cmd/cloud-posture
"$tmp/cp" --db "$tmp/p.db" ingest testdata -q -o summary >/dev/null
port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
export SMOKE_READER="reader-$(openssl rand -hex 12)" SMOKE_FIXER="fixer-$(openssl rand -hex 12)"
"$tmp/cp" --db "$tmp/p.db" serve --addr "127.0.0.1:$port" --mcp --mcp-token SMOKE_READER=read --mcp-token SMOKE_FIXER=read,fix >"$tmp/serve.log" 2>&1 &
pid=$!
for _ in $(seq 50); do curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
U="http://127.0.0.1:$port/mcp"
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
post() { curl -sS -o "$tmp/body" -D "$tmp/hdr" -w '%{http_code}' -X POST "$U" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' "$@"; }
sid() { tr -d '\r' <"$tmp/hdr" | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}'; }
tools() { python3 -c 'import json,sys; print(",".join(t["name"] for t in json.load(open(sys.argv[1]))["result"]["tools"]))' "$tmp/body"; }

echo "unauthenticated initialize: $(post --data "$INIT")"
echo "reader initialize: $(post -H "Authorization: Bearer $SMOKE_READER" --data "$INIT")"; RS=$(sid)
echo "reader initialized notification: $(post -H "Authorization: Bearer $SMOKE_READER" -H "Mcp-Session-Id: $RS" --data '{"jsonrpc":"2.0","method":"notifications/initialized"}')"
post -H "Authorization: Bearer $SMOKE_READER" -H "Mcp-Session-Id: $RS" --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' >/dev/null; echo "reader tools: $(tools)"
echo "reader sql: $(post -H "Authorization: Bearer $SMOKE_READER" -H "Mcp-Session-Id: $RS" --data '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sql","arguments":{"query":"SELECT count(*) AS n FROM findings"}}}') $(head -c 160 "$tmp/body")"
post -H "Authorization: Bearer $SMOKE_FIXER" --data "$INIT" >/dev/null; FS=$(sid)
post -H "Authorization: Bearer $SMOKE_FIXER" -H "Mcp-Session-Id: $FS" --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' >/dev/null; echo "fixer tools: $(tools)"
echo "reader session under the fixer token: $(post -H "Authorization: Bearer $SMOKE_FIXER" -H "Mcp-Session-Id: $RS" --data '{"jsonrpc":"2.0","id":4,"method":"tools/list"}')"
echo "cross-origin: $(post -H "Authorization: Bearer $SMOKE_READER" -H "Mcp-Session-Id: $RS" -H 'Origin: https://evil.example' --data '{"jsonrpc":"2.0","id":5,"method":"ping"}')"
echo "delete reader session: $(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$U" -H "Authorization: Bearer $SMOKE_READER" -H "Mcp-Session-Id: $RS")"
echo "audit (http records): $(grep -c '"transport":"http"' "$tmp/mcp-audit.jsonl" || true); tokens in audit: $(grep -c -e "$SMOKE_READER" -e "$SMOKE_FIXER" "$tmp/mcp-audit.jsonl" || true)"
