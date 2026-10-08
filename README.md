# nimbus · `cloud-posture`

**The open-source, unified Cloud Security Posture Manager.** One binary aggregates Prowler, ScoutSuite, Checkov, Trivy, Steampipe and its own agentless collectors into a single security graph, then shows you the attack paths that matter, the one fix that breaks the most of them, the IaC patch (and PR) that applies it, the SQL to prove it, and the audit report to ship.

```text
$ cloud-posture onboard
✓ Connected to AWS (3 accounts, 12 regions)   ✓ Azure (2 subscriptions)   ✓ GCP (1 project)   ✓ k8s (prod-eks)

$ cloud-posture scan --accounts aws-prod,azure-dev,gcp-staging --output dashboard
Scan complete! Found 847 open findings:
- 12 Critical (19 attack paths)
- 89 High
Break the path (top fixes):
- overprivileged identity on AdministratorAccess → removes 11 path(s): cloud-posture fix --id 3f9c… --generate-terraform
View dashboard: file:///…/cloud-posture-report/index.html      Live mode: cloud-posture serve

$ cloud-posture fix --finding S3_PUBLIC_BUCKET --generate-terraform
$ cloud-posture fix --all --patch --iac ./infra --auto-pr          # opens a PR with explanation, risk, rollback, diff
$ cloud-posture query "SELECT * FROM aws_s3_buckets WHERE public_access = true"
$ cloud-posture ask "show me all public databases with no encryption"
```

## Why

Teams run 45 security tools and none of them talk. Prowler reports, Checkov reports, Trivy reports; nobody correlates. nimbus is the single pane of glass that **also fixes things**:

| | nimbus | Prowler | Wiz / Orca / Prisma |
|---|---|---|---|
| Aggregates every open-source scanner into one model | ✅ | – | – |
| Attack-path graph (6 hops, choke points, break-the-path, cheapest fix set) | ✅ | – | ✅ ($$$) |
| Context-aware risk score with a **published** formula | ✅ | partial | ✅ (secret formula) |
| IaC fixes: Terraform / CloudFormation / Bicep / Kubernetes + in-place patch + auto-PR | ✅ | – | partial |
| SQL over your cloud (zero-ETL views + Steampipe passthrough) | ✅ | – | ✅ |
| AI copilot (NL→SQL, explain, investigate, Rego policy) with offline fallback | ✅ | – | ✅ |
| Cost + security (zombies, rightsizing, breach-cost ROI) | ✅ | – | partial |
| Compliance packs + custom frameworks + evidence ZIP + PDF reports | ✅ | ✅ | ✅ |
| Real-time change detection → Slack/Teams/PagerDuty/Jira/SIEM, auto-close | ✅ | – | ✅ |
| VS Code inline + quick fix, pre-commit, GitHub Action, SARIF | ✅ | – | partial |
| Price | free | free | $100k+/yr |

Competitor research that set the bar for each feature: [`docs/research/competitors.md`](docs/research/competitors.md).

## Install

```bash
# binary (Linux/macOS/Windows)
curl -fsSL https://raw.githubusercontent.com/DreadpiratePickles/nimbus/main/install.sh | sh
# or from source (Go 1.26)
go install github.com/DreadpiratePickles/nimbus/cmd/cloud-posture@latest
# Python intelligence layer (compliance reports, AI copilot, boto3 checks, FastAPI)
pip install -e "python[all]"
# everything incl. prowler/checkov/trivy/steampipe
docker run --rm -v ~/.aws:/root/.aws -v $PWD:/work ghcr.io/dreadpiratepickles/cloud-posture scan --accounts aws:default
```

Credentials are never stored: the CLI uses your existing AWS/Azure/GCP/kubectl sessions, or env vars (`GITHUB_TOKEN`, `OKTA_API_TOKEN`, `M365_*`, `SLACK_WEBHOOK_URL`, `ANTHROPIC_API_KEY`). A `.env` / `nimbus.env` in the working directory is loaded automatically and is git-ignored.

## Commands

| Command | What it does |
|---|---|
| `onboard` | Detect credentials for AWS, Azure, GCP, Kubernetes, GitHub, Okta, M365; write `cloud-posture.yaml`; `--aws-org` prints a StackSet that creates a read-only role (External ID) in every account |
| `scan` | Native SDK collectors + Prowler/ScoutSuite/Checkov/Trivy/Steampipe/python-checks/plugins per account; `--iac` for Terraform/CloudFormation/Bicep/K8s/Helm/CDK/Pulumi/Ansible; `--output table\|json\|sarif\|dashboard\|markdown`; `--fail-on`; `--alert` |
| `ingest` | Import existing scanner output files/dirs (auto-detected format) |
| `paths` | Attack paths with likelihood × priority scores, MITRE tags, `--fixes` (choke points, break vs lower-risk, min fix set), `--blast-radius`, `--format mermaid\|dot\|json` |
| `prioritize` | Top-N risks (1–10, Critical ≥ 9) with the reasons, owner and SLA |
| `fix` | Generate IaC remediation; `--patch` rewrites the HCL block in place (validated, never widens access); `--auto-pr`; `--tfstate` maps cloud findings to code; `--ai` LLM fixes |
| `query` | SQL over `findings`, `<type>s` inventory views, `attack_path_summary`, `cis_aws_benchmark`, `soc2`, `graph_nodes`…; `--engine steampipe` for live cloud tables; `--describe` |
| `report` | CIS / NIST 800-53 / PCI DSS / SOC 2 / HIPAA / GDPR / ISO 27001 / custom YAML; `--format md\|json\|html\|pdf`; `--evidence-zip` |
| `alert` | Slack, Teams, PagerDuty, Jira, GitHub Issues, Datadog, Splunk HEC, Microsoft Sentinel, Elastic, webhook, syslog/CEF; dedup, rules, suppressions with expiry, auto-close on fix |
| `serve` | Live dashboard + JSON API + WebSocket; `--scan-interval` for continuous compliance; `--monitor` for change detection; `--copilot` wires the Python API |
| `monitor` | CloudTrail / Azure Activity Log / GCP audit log change detection (public bucket, open SG, admin policy, root login, logging disabled…) |
| `cost` | Zombie resources, rightsizing, security + cost wins, breach-risk ROI |
| `graph` | `export --format json\|cypher\|mermaid\|dot`, `push` to Neo4j (Cartography-style labels) |
| `ask` | Copilot: questions, investigations, remediation guidance, OPA/Rego policy generation |
| `learn` | Tutorials that use your own findings (public buckets, open SSH, IMDSv1, admin policies, MFA, logging, privileged pods) |
| `hook install` / `action init` / `pr-comment` | Pre-commit hook, GitHub Actions workflow, sticky PR comment |
| `dashboard` / `catalog` | Static HTML report; the 75-check canonical catalog |

Run `cloud-posture <cmd> --help` for flags. Example config: [`cloud-posture.example.yaml`](cloud-posture.example.yaml).

## How it works

```
Prowler ─┐                                       ┌─ attack paths (rules + 6-hop traversal)
ScoutSuite│  adapters   ┌────────────┐  graph    │  choke points · break-the-path · min fix set
Checkov ──┼───────────▶ │ canonical  │ ────────▶ ├─ risk score (published formula)
Trivy ────┤  catalog    │ findings   │  SQLite   ├─ IaC fixes · HCL patch · auto-PR
Steampipe ┤  (75 IDs)   │ + security │  views    ├─ SQL / Steampipe · AI copilot (Python)
AWS/Azure/│  SDK        │   graph    │           ├─ compliance packs · evidence · PDF
GCP/K8s/  │  collectors └────────────┘           ├─ Slack · Jira · PagerDuty · SIEM · auto-close
GitHub/Okta/M365                                 └─ dashboard (static + live WS) · Neo4j · VS Code · CI
```

- **Zero-ETL:** findings land in SQLite with JSON docs; inventory views (`aws_s3_buckets.public_access`, `aws_instances.imdsv1_enabled`…), compliance views and `attack_path_summary` are derived on the fly. Tables you don't have locally are proxied to Steampipe.
- **Attack paths** follow Google SCC's transparent model: `score = likelihood × priority` on 0–10, likelihood = Π step exploitability (AND along a path), priority from a 4-tier crown-jewel catalog (tags, names, `scan.crown_jewels` overrides). Fixes are split into *break the path* and *lower risk only*, plus a greedy min-cut fix set. See [`internal/attackpath`](internal/attackpath).
- **Risk** = severity × context (exposure, identity, data sensitivity, criticality, CVEs, compliance scope, 24h change, orphaned ownership, attack paths) → 1–10 with Orca-style bands and per-item reasons. Weights are published in [`internal/risk`](internal/risk/risk.go) and [`python/nimbus/risk_weights.json`](python/nimbus/risk_weights.json).
- **Fix PRs** carry what changed and why, the attack paths closed, re-scan validation, a never-widen-access guardrail, risk & rollback, and the diff.
- **Python layer** (`pip install -e "python[all]"`): `nimbus` package with 58 Prowler-style boto3 CIS AWS checks, compliance engine (SOC 2/ISO derived from weaknesses, custom frameworks), HTML/PDF audit reports, Claude-powered copilot/explanations/fix generation with offline fallbacks, FastAPI server, plugin SDK (`@nimbus.plugin.check`). See [`python/README.md`](python/README.md).

## Development

```bash
make build && make test          # go vet + go test ./...
make python-test                 # cd python && pytest
./bin/cloud-posture ingest testdata -o summary && ./bin/cloud-posture serve
```

Design notes for contributors and agents: [`CLAUDE_CONTEXT.md`](CLAUDE_CONTEXT.md), [`.planning/`](.planning). Graph schema and Cypher examples: [`docs/neo4j-queries.cypher`](docs/neo4j-queries.cypher). Canonical checks: [`docs/checks.md`](docs/checks.md).

## Status

v0.1.0 — every feature above is implemented and covered by unit tests (Go: adapters, store, query, attack paths, risk, IaC, remediation, compliance, integrations, collectors with fake SDK clients, monitor, cost, Neo4j statement generation, server; Python: 157 tests incl. moto). Nothing has been validated against a live cloud account yet; treat collector output as beta until it has.

Apache-2.0.
