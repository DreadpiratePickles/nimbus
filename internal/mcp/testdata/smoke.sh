#!/usr/bin/env bash
# Smoke test for the nimbus MCP server: build a test-only main (internal/cli wiring of
# `cloud-posture mcp` belongs to the integration pass), pipe initialize + tools/list + a sql call
# + an out-of-scope call into it over stdio, and print every response line.
#
#   internal/mcp/testdata/smoke.sh            # from the repo root
#
# Once `cloud-posture mcp` exists, the same frames work against it:
#   printf '%s\n' "$INIT" "$INITIALIZED" "$LIST" "$SQL" | cloud-posture mcp --scope read
set -euo pipefail
cd "$(dirname "$0")/../../.."
export PATH="$PATH:/opt/homebrew/bin"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
go build -o "$tmp/nimbus-mcp" ./internal/mcp/testdata/smokemain

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
INITIALIZED='{"jsonrpc":"2.0","method":"notifications/initialized"}'
LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
SQL='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sql","arguments":{"query":"SELECT canonical_id, severity, account, title FROM findings ORDER BY severity"}}}'
EVIL='{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sql","arguments":{"query":"DELETE FROM findings"}}}'
DRAFT='{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"draft_fix","arguments":{"finding_id":"x"}}}'

echo "== session 1: default scope, redaction on"
printf '%s\n' "$INIT" "$INITIALIZED" "$LIST" "$SQL" "$EVIL" | "$tmp/nimbus-mcp" -db "$tmp/posture.db" -seed
echo
echo "== session 2: --scope read (draft_fix hidden and refused)"
printf '%s\n' "$INIT" "$INITIALIZED" "$LIST" "$DRAFT" | "$tmp/nimbus-mcp" -db "$tmp/posture.db" -scope read |
  python3 -c 'import json,sys
for l in sys.stdin:
    m=json.loads(l); r=m.get("result") or {}
    if "tools" in r: print("tools:", [t["name"] for t in r["tools"]])
    else: print(l.strip()[:300])'
echo
echo "== audit log ($tmp/mcp-audit.jsonl)"
cat "$tmp/mcp-audit.jsonl"
