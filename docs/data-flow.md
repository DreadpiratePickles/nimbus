# Data flow: what leaves the machine

_Status: 2026-10-09 (P1-MCP). This page states what nimbus (`cloud-posture` Go binary and the `nimbus` Python package) sends off the machine in each mode, which fields go to an LLM provider, how to run fully offline, and the MCP server's trust boundary. Every statement points at the code that enforces it. Anything not yet verified is marked **unverified**._

Plan reference: `.planning/IMPLEMENTATION_PLAN_v3.md` §5.2 (LLM data-egress statement and outbound minimisation), council decision 7.

## 1. Summary by mode

| Mode | What leaves the machine | Destination | Controlled by |
|---|---|---|---|
| IaC scan (`scan --iac`, pre-commit, VS Code) | Nothing from nimbus itself. External scanners it runs may download their own databases (see §5) | Scanner vendors (trivy DB) | Install / pre-populate the scanner; nimbus does not pass offline flags to them today |
| Cloud scan (`scan`, collectors) | Read-only API calls signed with **your** credentials; the requests carry your account/resource identifiers, as any SDK call does | AWS / Azure / GCP / Kubernetes API server / GitHub / Okta / M365 endpoints you configured | Your credentials and the read-only scan policies (`docs/iam/`) |
| External scanner runs (Prowler, ScoutSuite, Checkov, Trivy) | Whatever those tools send (their own cloud API calls, DB downloads) | As per each tool | Whether the tool is installed (`internal/scanner/runner.go`) |
| Exploit intel (KEV / EPSS) | HTTPS GET of the public feeds; no estate data is sent | `www.cisa.gov`, `epss.cyentia.com` | `--no-network` or `CLOUD_POSTURE_NO_NETWORK=1` stops it (embedded snapshot / local cache used instead; `internal/cli/root.go` `noNetwork`, `internal/intel`) |
| Integrations (alerts, tickets, SIEM) | Finding and path summaries (§4) | Only sinks you configured: Slack, Teams, PagerDuty, Jira, GitHub Issues, Datadog, Microsoft Sentinel, Splunk HEC / Elastic / webhook / syslog | Configuration only; none is on by default (`internal/integrations`, `python/nimbus/integrations`) |
| AI features (Python `nimbus ask`, `explain`, `fix --ai`, copilot API) | Minimised, redacted prompts (§2) | The LLM provider you chose: Anthropic API, any OpenAI-compatible endpoint (may be local), or Amazon Bedrock | `NIMBUS_LLM_PROVIDER`, `NIMBUS_OFFLINE`, `CLOUD_POSTURE_NO_NETWORK`, `NIMBUS_REDACT_LLM` (`python/nimbus/ai/providers.py`, `redact.py`) |
| MCP server (`cloud-posture mcp`) | Nothing: it answers its MCP client over stdio. **The client** (Claude Code, Cursor, ...) then sends the tool results to **its** model provider | Your MCP client's model provider | `--scope` (default `read`: no simulate_fix / draft_fix), redaction (default on) (§3) |
| Dashboard / API server | Nothing; it serves localhost | Your browser | Bind address / token (`internal/server`) |

`--no-network` / `CLOUD_POSTURE_NO_NETWORK=1` today governs the intel feeds (Go) and, on the Python side, every LLM provider that is not on a loopback address. It does **not** stop cloud collection, external scanners or configured integrations: those only run when you invoke or configure them.

## 2. LLM provider: exactly what is sent

Provider selection (`python/nimbus/ai/providers.py`):

| `NIMBUS_LLM_PROVIDER` | Endpoint | Needs |
|---|---|---|
| `anthropic` (default) | Anthropic Messages API via the official SDK | `ANTHROPIC_API_KEY` |
| `openai` | `<NIMBUS_LLM_BASE_URL>/chat/completions` (Ollama, vLLM, llama.cpp, LM Studio, a gateway) | `NIMBUS_LLM_BASE_URL`, optional `NIMBUS_LLM_API_KEY` |
| `bedrock` | Amazon Bedrock `converse` (boto3) | AWS credentials + `AWS_REGION` |
| `none` | none | — |

`NIMBUS_MODEL` names the model for every provider. **For sensitive estates the recommended default is a local model behind a loopback OpenAI-compatible endpoint** (e.g. `NIMBUS_LLM_PROVIDER=openai NIMBUS_LLM_BASE_URL=http://127.0.0.1:11434/v1`): nothing leaves the machine, and it keeps working under `CLOUD_POSTURE_NO_NETWORK=1`.

### 2.1 Outbound minimisation (applies to every prompt below)

Implemented in `python/nimbus/ai/redact.py` and `guardrails.py`; tested by `python/tests/test_ai_guardrails.py` with a recording provider.

* **Field allowlist.** Query results: only columns in `OUTBOUND_COLUMNS` (ids, canonical/check id, source, severity, status, provider, account, region, resource id/name/type, title, weaknesses, compliance, score/band, path name/rule/impact/steps, control id, failing checks, namespace/pod, kind/state/confidence, first/last seen, remediation) plus columns whose values are all numbers (aggregates). Every other column — `doc`, `raw`, `tags`, `attributes`, `description`, policy JSON — is withheld; the prompt names the withheld columns. Findings and paths sent to `explain`/`fix` are reduced to `FINDING_FIELDS` + `resource{id,type,name}` and `PATH_FIELDS` + `STEP_FIELDS`.
* **Redaction (`--redact-llm`, default on; `NIMBUS_REDACT_LLM=0` disables).** Replaced by stable per-process placeholders keyed with a random HMAC key: any value under an account/subscription/project column and any bare 12-digit number (`ACCT_…`), the account segment of every ARN, Azure `/subscriptions/<guid>` (`SUB_…`), IPv4 addresses except `0.0.0.0` (`IP_…`). Tag values are never sent (tags are withheld outright). Placeholders in the model's SQL, tool arguments and answer are re-hydrated locally before anything runs and before the answer is shown.
* **Untrusted-data wrapping.** Estate data is sent inside `<untrusted_data>…</untrusted_data>` as ASCII-only JSON with `<`, `>`, `&` escaped, so titles, names and descriptions written by an attacker cannot close the wrapper, imitate a tool call or hide text with bidi / zero-width characters. The system prompt says the wrapped content is data, never instructions.
* **Not redacted (sent in clear when the feature needs it):** resource names and ids other than the account segment (including S3 bucket names, which carry no account), finding titles, check ids, regions, file paths and line numbers of IaC findings, scanner remediation text, and the IaC code you pass to `fix --ai`. If those are sensitive, use a local model.

### 2.2 Per feature

| Feature | Fields sent to the model |
|---|---|
| `ask` (NL → SQL), step 1 | Table and view names with column names (`Store.schema_text`, no data); the weakness vocabulary; your question, redacted. Pasted identifiers (ARN, CVE, IP/CIDR, instance/SG id, Azure/GCP resource path) never reach the model: they map to a canned query (`copilot.identifier_sql`). |
| `ask`, step 2 (summary) | Your question (redacted); the SQL that ran (redacted); row count; at most 50 rows after the allowlist and redaction; the names of withheld columns. |
| Copilot `agent` (tool loop) | As `ask` step 1, plus each step's tool name and arguments and its result: `sql` rows as in step 2; `finding` = finding without `raw`, `doc`, `tags`, `attributes`, `description`, `evidence`; `attack_paths` = id, name, score, severity, finding ids, steps (resource, weakness, title); `blast_radius` = reachable node ids, names, types, classes, hop counts, edge paths; `remediation_guidance` = catalog title, severity, open-finding count, steps (incl. affected resource names). |
| `explain` (finding) | `FINDING_FIELDS` + resource id/type/name, redacted and wrapped; attack paths containing it as `PATH_FIELDS` + steps. |
| `explain` (attack path) | The path (`PATH_FIELDS` + `STEP_FIELDS`) and its findings (`FINDING_FIELDS`), redacted and wrapped. |
| `fix --ai` | The finding (`FINDING_FIELDS` + resource), redacted and wrapped; the requested format and framework; the current IaC code if you pass it (text-redacted: account ids and IPs). |
| Remediation guidance (copilot) | Catalog entry (title, severity, weaknesses, compliance mapping), open-finding count, the scanner's remediation text. |
| Policy generation | Your requirement text only. |

Per-turn caps (`TurnBudget`, env-tunable): tool calls (default 8, refused calls count), model calls (10), tokens (200k), wall time (90 s), and cost when `NIMBUS_LLM_USD_PER_MTOK_IN/OUT` and `NIMBUS_AI_MAX_COST_USD` are set. Every answer ends with `Sources:` listing the SQL run and the finding / Issue / path ids it rests on (`Citations`).

## 3. MCP server trust boundary (`internal/mcp`)

* **Transport.** Newline-delimited JSON-RPC 2.0 over the stdio of the process that launched it. No listening socket, no outbound connection. (An HTTP transport with per-token scopes is deferred.)
* **Read-only by construction.** Tools receive a `Reader` interface with no write-shaped method (checked by `TestReadOnlyByConstruction`, which also hashes every table before and after a full session). `sql` runs only through `store.QueryReadOnly` (lexer, `mode=ro` connection with `query_only`, engine limits, bytecode allowlist, timeout, row cap). `simulate_fix` works on an in-memory clone of the graph. `draft_fix` returns text and a new-file diff and never writes (`TestDraftFixNeverWrites`). Nothing applies changes to the cloud.
* **Scope.** The default scope is `read`: `sql`, `schema`, `paths`, `issue`, `explain`, `coverage`, `who_can`, `prioritize`, `verify` and `summary`. The change-shaped tools `simulate_fix` and `draft_fix` are listed only with `--scope fix` (or `all`). `--scope` takes a comma list of scope or tool names; it filters `tools/list` and `resources/list`, and an out-of-scope call is refused exactly like an unknown tool. Unknown scope names fail start-up. No scope grants a write: `verify` reports what `cloud-posture verify` would re-check and the stored verification state, and never re-collects or changes an Issue.
* **What the client receives.** Tool results as JSON (`structuredContent`) and the same JSON as text under a banner saying the strings are untrusted estate data. `paths` and `issue` return attack-path Issues with their hop variants, not one row per variant. Evidence findings omit raw provider JSON and resource attributes. With redaction on (default; `--no-redact` disables) account ids, ARN account segments, GCP project ids, Azure subscription ids, AWS resource ids (`sg-`, `rtb-`, `acl-`, `i-`, `subnet-`, ...), IPv4 addresses and tag values are per-session placeholders, also inside verdict labels, reasons and hop `because` text; names (roles, buckets, hosts) stay readable unless they embed an account id. Placeholders sent back in **non-SQL** arguments are re-hydrated before execution, and a raw identifier in an argument is refused (it would be an oracle). SQL is never re-hydrated: it runs over redacted views, so a query sees only placeholders. **Your MCP client forwards these results to its own model provider** — that is the egress to reason about, and redaction exists for it.
* **Hostile content.** Strings collected from the estate are returned as data: `<`, `>`, `&`, U+2028/2029 and every Unicode format character are JSON-escaped, so no frame, tool marker or invisible text can be injected into the stream; the server never chooses tools or builds SQL from data (`TestInjectionCorpus`).
* **Audit.** Every `tools/call` and `resources/read`, including refusals, is appended to `<db dir>/mcp-audit.jsonl` (mode 0600; directory 0700 when created) before the response is sent; if the record cannot be written the call fails. It holds arguments and the SQL that ran — keep it with the same care as the database. Migration to an `agent_audit` table is documented on `auditRecord`.

## 4. Integrations payloads (when configured)

Slack / Teams / PagerDuty / Jira / GitHub Issues / Datadog / Sentinel / SIEM sinks send, per finding (the Slack payload is the reference; the other sinks carry the same fields in their own shapes — check each sink's code before relying on an exact field list): severity, canonical id, title, provider, account, region, resource id/name, source, check id, remediation (truncated), and the names, impacts and scores of attack paths that include it (`internal/integrations/integrations.go`, `python/nimbus/integrations/clients.py`). Webhook URLs are redacted from errors and logs (`internal/integrations/redact.go`). There is no redaction of account ids in these payloads today.

## 5. Running fully offline

1. Model: `NIMBUS_OFFLINE=1` (or `NIMBUS_LLM_PROVIDER=none`) — all AI features fall back to rule-based mode (`ask` intents, identifier paste, template explanations and fixes). Or keep AI with a local model on a loopback endpoint (§2).
2. Intel feeds: `--no-network` or `CLOUD_POSTURE_NO_NETWORK=1` — uses the cached or embedded KEV/EPSS snapshot.
3. Data in: scan IaC (`scan --iac`) or import existing scanner output (`ingest` / adapters) instead of live cloud collection.
4. Scanners: Trivy downloads its vulnerability/misconfiguration DB on first use; nimbus runs `trivy config` and `trivy fs` without offline flags (**unverified** whether a pre-populated cache avoids all network). Checkov and Prowler/ScoutSuite behaviour is per their docs.
5. Integrations: configure none.
6. MCP: stdio only; nothing leaves unless your MCP client sends it to a remote model.

## 6. What is not covered yet

* An executable "network-silent" test for the Go binary under `--no-network` plus an IaC scan.
* Redaction for integration payloads and for the dashboard export.
* HTTP transport for the MCP server with token → scope mapping.
* Re-recording the copilot eval suite against live providers (the suite replays scripted model outputs through each provider's transport; `python/nimbus/ai/evals.py`).
