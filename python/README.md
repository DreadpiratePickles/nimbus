# nimbus-cspm

The Python intelligence layer of **cloud-posture** (the `cloud-posture` Go CLI): compliance packs,
audit-ready reports, context-aware risk scoring, an AI security copilot, a FastAPI dashboard API,
alert integrations and a plugin SDK. Everything works offline with rule-based fallbacks; set
`ANTHROPIC_API_KEY` to have Claude write explanations, fixes, SQL and policies.

## Install

```bash
pip install -e "python[all]"        # from the repo root; extras: server, ai, pdf, checks, ml, dev
nimbus version
```

The database is the one the Go CLI writes: `./.cloud-posture/posture.db`, or `$CLOUD_POSTURE_DB`, or `--db PATH`.

## Commands

| Command | What it does |
|---|---|
| `nimbus report --framework soc2 --format html\|pdf\|md\|json --out FILE [--custom file.yaml]` | Audit report (executive summary + score gauge, control status, remediation roadmap, attack paths, methodology, evidence appendix). `--framework all` renders the multi-framework executive summary. |
| `nimbus frameworks` | List built-in frameworks (`cis_aws`, `cis_azure`, `cis_gcp`, `cis_k8s`, `cis_github`, `nist_800_53`, `pci_dss`, `hipaa`, `gdpr`, `soc2`, `iso_27001`). Aliases: `cis`, `nist`, `pci`, `iso`, `soc-2`. |
| `nimbus risk [--top 50] [--json] [--model weights.json]` | Context-aware prioritisation. |
| `nimbus ask "which buckets are public?"` | Copilot: NL -> read-only SQL -> answer. |
| `nimbus explain <finding-id \| attack-path-id>` | "An attacker could ..." narrative. |
| `nimbus investigate <finding-id>` | Finding + attack paths + blast radius (BFS over `graph_edges`, <= 4 hops, sensitive targets). |
| `nimbus fix <finding-id> --format terraform\|cloudformation\|bicep\|kubernetes` | IaC fix (Claude -> `cloud-posture fix` -> built-in template -> documented stub). |
| `nimbus guidance <CANONICAL_ID>` | Remediation guidance from the catalog (+ Claude). |
| `nimbus policy "deny public S3 buckets" [--out p.rego]` | OPA/Rego policy (offline templates in `nimbus/policies/`). |
| `nimbus query --list` / `--named NAME` / `"SELECT ..."` `[-o table\|json\|csv]` | Query library (`nimbus/queries/index.yaml`) or ad-hoc read-only SQL. |
| `nimbus alert --finding ID --target slack\|teams\|jira\|github\|datadog\|pagerduty` | Send alerts (config from env). |
| `nimbus ingest findings.json` | Load native findings (array or JSON lines) from Python. |
| `nimbus serve --host 127.0.0.1 --port 8765 [--db PATH]` | FastAPI dashboard API + WebSocket. |
| `nimbus plugin run PATH [--jsonl] [--ingest DB]` | Run a plugin and print native findings. |

### Offline copilot intents

public buckets / databases / instances, unencrypted X (buckets, databases, volumes), users without
MFA, attack paths to databases/RDS, top risks, findings by account/provider/severity/region/type,
critical/high findings, stale keys, privileged pods, and "compliance status for <control>"
(e.g. `CIS 1.10`, `soc2 CC6.2`, `AC-6`). All SQL - from rules or from Claude - must be a single
`SELECT`/`WITH` statement; comments are stripped, `LIMIT 200` is enforced and it runs on a
read-only SQLite connection.

## Go <-> Python subprocess contracts

| Go calls | stdout |
|---|---|
| `python3 -m nimbus.risk --db PATH --top 50 --json` | JSON array (single line) of `{finding_id, risk_score (0-100), severity, canonical_id, resource (resource id string), resource_name, resource_type, title, provider, account, reasons [str], features {name: 0..1}, attack_paths [ids]}` sorted by `risk_score` desc. Only `status=FAIL` findings. Missing DB -> `[]`. |
| `python3 -m nimbus.plugin PATH [--json \| --jsonl]` | Native findings (same JSON as `internal/model.Finding`, Go `omitempty` semantics, RFC3339 `Z` times) for `cloud-posture ingest --source native`. Default `--json` = array. |
| `nimbus report --framework F --format html\|pdf\|md\|json --out FILE` | Writes FILE; status line on stderr; exit 1 if PDF support is missing. |
| `nimbus serve --db PATH` | HTTP API below. |

Python reads Go's DB directly. Python's `Store` writes the same columns + `doc` JSON and creates the
`<type>s` inventory views and `findings_summary` like `store.EnsureViews`; it creates
`attack_path_summary`, `compliance_controls` and the per-framework views
(`cis_aws_benchmark`, ..., `soc2`, `iso_27001`) **only if they do not exist**, so Go's definitions win.

`Finding.fingerprint()` equals Go's `model.Finding.Fingerprint`:
`hex(sha256("source|check_id|provider|account|region|resource.id|file")[:16])`.

## HTTP API (`nimbus.server.create_app(db_path)`)

`GET /api/summary`, `/api/findings?status=&severity=&provider=&account=&canonical_id=&limit=`,
`/api/findings/{id}`, `/api/attack-paths`, `/api/graph` (Cytoscape `{nodes:[{data:{id,label,class,...}}], edges:[{data:{source,target,kind}}]}`),
`/api/risk/top?n=`, `/api/frameworks`, `/api/compliance/{framework}`, `/api/reports/{framework}.{html|pdf|md|json}`,
`/api/queries`, `/api/queries/{name}`; `POST /api/query {sql}`, `/api/copilot {question}`, `/api/explain {finding_id}`,
`/api/investigate {finding_id}`, `/api/fix {finding_id, format}`, `/api/alerts {finding_ids, targets}`;
`WS /ws` pushes `{"type":"findings_updated","scan_id":...}` when the DB (or WAL) mtime changes (poll `NIMBUS_WS_POLL`, default 2 s).
`GET /` serves `$CLOUD_POSTURE_DASHBOARD_HTML` if set, else a compact built-in page.

## Compliance

`nimbus/frameworks/frameworks.yaml` = `internal/compliance/frameworks.yaml` + SOC 2 (CC6.1-CC8.1, A1.2, C1.1)
+ ISO/IEC 27001:2022 Annex A + `weakness_mappings` (21 weaknesses -> SOC 2 / ISO controls). A control is
FAIL if any failing finding maps to it (explicitly via `finding.compliance` or through a weakness),
PASS if only passing ones map, NOT_ASSESSED otherwise; score = pass / (pass + fail).

Custom framework (`--custom acme.yaml`):

```yaml
name: Acme Cloud Baseline
version: "1.0"
controls:
  ACME-1: {title: No public data stores, canonical_ids: [S3_PUBLIC_BUCKET, GCP_BUCKET_PUBLIC]}
  ACME-2: {title: Encrypt everything, weaknesses: [UNENCRYPTED_AT_REST]}
```

## Risk model

Features (0-1): severity, exposure, identity_risk, data_sensitivity, criticality, vulnerability_count,
compliance_weight, recent_change, ownership, attack_path. `score = 100 * sigmoid(bias + Σ wᵢ·xᵢ)`;
weights and their documentation live in `nimbus/risk_weights.json`. A trained linear model can be
supplied as JSON (`{"intercept": b, "coefficients": {feature: w}}`) via `--model` or `NIMBUS_RISK_MODEL`; pickles are never loaded.

## Plugins

```python
import nimbus

@nimbus.plugin.check("acme_bucket_owner", "Buckets carry an owner tag", severity="LOW", provider="aws",
                     weaknesses=[], compliance={"soc2": ["CC6.1"]}, resource_type="aws_s3_bucket")
def bucket_owner(client=None):
    yield {"resource_id": "arn:aws:s3:::b1", "account": "123", "passed": False, "message": "no owner tag"}
```

See `nimbus/plugins/example_okta.py` (env `OKTA_ORG_URL`, `OKTA_API_TOKEN`).

## AI

Uses the official `anthropic` SDK with model `claude-opus-5-5` (override with `NIMBUS_MODEL`). Requests
enable the server-side refusal fallback (`fallbacks="default"`), and `NIMBUS_OFFLINE=1` forces the rule-based paths.
If the API is unreachable or returns an error, every feature falls back to its offline path.

## Alert integrations (env)

`SLACK_WEBHOOK_URL`, `TEAMS_WEBHOOK_URL`, `JIRA_URL`/`JIRA_EMAIL`/`JIRA_API_TOKEN`/`JIRA_PROJECT`,
`GITHUB_TOKEN`/`GITHUB_REPOSITORY`, `DD_API_KEY`/`DD_SITE`, `PAGERDUTY_ROUTING_KEY`.

## Tests

```bash
cd python && python3 -m pytest -q --ignore=tests/checks
```
