# Architecture

nimbus has two halves that share one data contract.

- **Go core** (`cloud-posture`): collectors, scanner adapters, the security graph, attack-path analysis, the SQL engine, the CLI, the live server, change monitoring, cost analysis and alert sinks.
- **Python intelligence layer** (`nimbus-cspm`): compliance packs, the AI copilot and LLM fixes, risk scoring, audit reports, the FastAPI dashboard API, Prowler-style boto3 checks and the plugin SDK.
- **SQLite** is the zero-ETL local store. **Neo4j** export and push are there for graph exploration.

```text
Prowler ─┐                                       ┌─ attack paths (rules + 6-hop traversal)
ScoutSuite│  adapters   ┌────────────┐  graph    │  choke points · break-the-path · min fix set
Checkov ──┼───────────▶ │ canonical  │ ────────▶ ├─ risk score (published formula)
Trivy ────┤  catalog    │ findings   │  SQLite   ├─ IaC fixes · HCL patch · auto-PR
Steampipe ┤  (75 IDs)   │ + security │  views    ├─ SQL / Steampipe · AI copilot (Python)
AWS/Azure/│  SDK        │   graph    │           ├─ compliance packs · evidence · PDF
GCP/K8s/  │  collectors └────────────┘           ├─ Slack · Jira · PagerDuty · SIEM · auto-close
GitHub/Okta/M365                                 └─ dashboard (static + live WS) · Neo4j · VS Code · CI
```

## Data flow

1. **Collect.** Agentless SDK collectors (AWS, Azure, GCP, Kubernetes, GitHub, Okta, M365) and the open-source scanners run for each account. You can also import output you already have with `ingest`.
2. **Normalise.** Adapters for Prowler (OCSF and v3), ScoutSuite, Checkov, Trivy, Steampipe and native JSON map each tool's check IDs onto the [canonical catalog](checks.md). Each catalog entry carries aliases per tool, weaknesses, compliance mappings and fix templates.
3. **Store.** Findings land in SQLite as JSON documents. Inventory views (`aws_s3_buckets.public_access`, `aws_instances.imdsv1_enabled`, …), compliance views and `attack_path_summary` are derived when you query them. Tables you don't have locally go through to Steampipe.
4. **Graph.** Resources and relationships form an in-memory security graph with Cartography/BloodHound-style labels. The weaknesses from findings are what make edges exploitable.
5. **Analyse.** The [attack-path](attack-paths.md) traversal and [risk](risk-scoring.md) scoring run over the graph.
6. **Act.** The results feed fixes, PRs, alerts, reports, the dashboard and the copilot.

## Source layout

| Path | Role |
|---|---|
| `cmd/cloud-posture` | CLI entry point |
| `internal/model` | the unified Finding / Resource / AttackPath contract (its JSON is shared with Python) |
| `internal/catalog` | canonical check catalog: aliases, weaknesses, compliance, templates |
| `internal/adapters` | Prowler, ScoutSuite, Checkov, Trivy, Steampipe, native JSON parsers |
| `internal/store` | SQLite persistence, inventory views, graph tables |
| `internal/graph` | in-memory security graph, Cypher export |
| `internal/attackpath` | rule chains, multi-hop traversal, choke points, blast radius, break-the-path |
| `internal/collector` | agentless SDK collectors |
| `internal/risk` | context-aware scoring (Go fallback) |
| `internal/remediation`, `internal/iac` | fix templates; native HCL scanner and patcher |
| `internal/compliance` | framework inventories, report builder, evidence ZIP |
| `internal/integrations` | Slack, Teams, PagerDuty, Jira, GitHub Issues, Splunk, Datadog, Sentinel, ELK, webhook, syslog |
| `internal/monitor`, `internal/cost` | change detection; cost and security wins |
| `internal/server`, `internal/dashboard` | HTTP + WebSocket API; single-file HTML dashboard |
| `python/nimbus` | Python package: compliance, ai, risk, reports, server, checks, plugin SDK |
| `vscode-extension/` | inline IaC diagnostics |

## Contracts

- **Finding JSON** is defined in `internal/model/model.go` and mirrored in `python/nimbus/models.py`. The fingerprint is `sha256(source|check_id|provider|account|region|resource.id|file)[:16]`.
- **Native findings** from plugins and Python checks go in with `cloud-posture ingest --source native file.json`, as a JSON array or JSON lines.
- **Plugins** are Python functions decorated with `@nimbus.plugin.check`, run with `nimbus plugin run PATH`.
- **Secrets** come only from environment variables.

## Graph schema

Nodes include `AWSAccount`, `EC2Instance`, `S3Bucket`, `IAMRole`, `IAMUser`, `IAMPolicy`, `SecurityGroup`, `RDSInstance`, `LambdaFunction`, `EKSCluster`, `AzureVM`, `AzureStorageAccount`, `KeyVault`, `GCEInstance`, `GCSBucket`, `CloudSQLInstance`, `KubernetesPod`, `KubernetesServiceAccount`, `ClusterRoleBinding`, `GitHubRepository`, `OktaUser`, `Internet`, and more. Every node also carries `:Resource`. Relationships include `STS_ASSUME_ROLE_ALLOWS`, `GRANTS_ACCESS_TO`, `ALLOWS_TRAFFIC_TO`, `EXPOSED_TO_INTERNET`, `RUNS_AS`, `BOUND_TO`, `MEMBER_OF` and `TRUSTS`. Push it with `cloud-posture graph push` and query it with Cypher.
