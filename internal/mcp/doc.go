// Package mcp is nimbus's read-only Model Context Protocol server: newline-delimited JSON-RPC 2.0
// over stdio implementing initialize, ping, tools/list, tools/call, resources/list and
// resources/read. The transport is implemented here directly (no SDK dependency).
//
// Tools: sql, schema, paths (attack-path Issues with their variants), issue, explain, coverage,
// who_can, prioritize, verify (read-only report), summary (store.Headline) — the default "read"
// scope — plus simulate_fix and draft_fix (scope "fix" or "all").
//
// Trust boundary (see docs/data-flow.md):
//
//   - Read-only by construction. Tool handlers receive a Reader, whose method set has no
//     write-shaped method (TestReadOnlyByConstruction). The sql tool runs only through
//     store.QueryReadOnly (the hardened lexer + read-only connection + bytecode allowlist +
//     deadline path); simulate_fix runs attackpath.SimulateWith on an in-memory clone of the
//     graph; draft_fix returns remediation.Generate output as text and never writes a file.
//   - Scope. Options.Scopes (the `--scope` list, later an HTTP token's scopes) filters
//     tools/list and resources/list, and a call outside scope is refused exactly like an
//     unknown tool, so an out-of-scope tool is not discoverable.
//   - Untrusted data. Everything a tool returns came from the scanned estate. It is returned as
//     JSON data: encoding/json escapes <, >, &, U+2028 and U+2029, and this package escapes
//     every Unicode format rune (bidi overrides, zero-width characters, BOM), so a hostile
//     title cannot inject a frame, a tool marker or invisible text. Text content carries a
//     banner saying the strings are data, not instructions. Nothing the server does depends on
//     data content: tool selection is the client's, and filter values are compared in Go,
//     never spliced into SQL.
//   - Redaction (default on, Options.NoRedact to disable). Account ids, ARN account segments,
//     GCP project ids, Azure subscription ids, AWS resource ids (sg-, rtb-, acl-, i-, ...),
//     IPv4 addresses and tag values leave as stable per-session placeholders (ACCT_xxxxxxxx,
//     RES_…, IP_…, SUB_…, TAG_…), also inside verdict and "because" text; names (roles,
//     buckets, hosts) stay readable unless they embed an account id. Placeholders sent back in
//     non-sql arguments are re-hydrated before anything runs; raw ids in arguments are refused
//     (an oracle). SQL is never re-hydrated: it runs over redacted views (sqlview.go).
//   - Audit. Every tools/call and resources/read (including refusals) is appended to a JSONL
//     file (default <db dir>/mcp-audit.jsonl, mode 0600) before the response is written; if the
//     record cannot be written the call fails. Migration: the same fields become the
//     agent_audit table once the store owner adds it (see auditRecord).
//
// CLI wiring belongs to internal/cli (`cloud-posture mcp --scope read,fix`), which calls
// Serve(ctx, store, Options{...}) with os.Stdin/os.Stdout.
package mcp
