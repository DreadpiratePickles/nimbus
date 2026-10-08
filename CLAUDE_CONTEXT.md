# Project: nimbus (`cloud-posture`) — Unified Cloud Security Posture Manager

## Goal
The best open-source CSPM: beats Prowler/ScoutSuite on visibility and Wiz/Lacework/Prisma on price by combining
- **Go** for collectors, the security graph, attack-path analysis, SQL engine, CLI, live server, monitor, cost, alert sinks
- **Python** for compliance packs (CIS, NIST 800-53, PCI DSS, SOC 2, HIPAA, GDPR, ISO 27001), AI copilot/LLM fixes, risk scoring, audit reports, FastAPI dashboard API, Prowler-style boto3 checks, plugin SDK
- **SQLite** as the zero-ETL local store (findings-derived SQL views) and **Neo4j** export/push for graph exploration

## Layout
```
cmd/cloud-posture/            Go CLI entrypoint (binary: cloud-posture)
internal/model                unified Finding/Resource/AttackPath contract (JSON shared with Python)
internal/catalog              canonical check catalog (catalog.yaml): aliases per tool, weaknesses, compliance, templates
internal/adapters             Prowler (OCSF+v3), ScoutSuite, Checkov, Trivy, Steampipe, native JSON parsers
internal/store                SQLite persistence + findings-derived inventory views + graph tables
internal/graph                in-memory security graph (nodes/edges/classes), Cypher export
internal/attackpath           rule chains + multi-hop traversal, choke points, blast radius, break-the-path
internal/collector            agentless SDK collectors: AWS, Azure, GCP, Kubernetes, GitHub, Okta, M365
internal/cost                 zombie/rightsizing/security+cost wins/ROI
internal/monitor              CloudTrail / Azure Activity Log / GCP audit log change detection
internal/remediation          Terraform / CloudFormation / Bicep / Kubernetes fix templates
internal/iac                  native HCL scanner + patcher, IaC type detection
internal/compliance           framework inventories + report builder
internal/integrations         Slack, Teams, PagerDuty, Jira, GitHub Issues, Splunk HEC, Datadog, Sentinel, ELK, webhook, syslog
internal/neo4j                Cartography-style Neo4j push
internal/server               HTTP + WebSocket live dashboard API
internal/risk                 context-aware scoring (Go fallback; Python model preferred)
internal/dashboard            single-file HTML dashboard (Cytoscape attack graph)
python/nimbus                 Python package `nimbus-cspm` (compliance, ai, risk, reports, server, checks, plugin SDK)
vscode-extension/             inline IaC diagnostics
.planning/                    GSD-style PROJECT / ROADMAP / STATE
```

## Reference implementations (study and model on; do not vendor)
- prowler-cloud/prowler — check.py + metadata.json structure, provider collection, compliance mappings
- cartography-cncf/cartography — Neo4j labels/relationships, sync engine, Cypher attack-path queries
- turbot/steampipe — SQL over cloud APIs, plugin architecture
- nccgroup/ScoutSuite — HTML report, rules engine
- bridgecrewio/checkov — IaC parsing, policy-as-code
- m8r1us/BloodHoundAz — BloodHound-style cloud graph schema and Cypher attack queries
- Rema2003/cloud-security-graph — multi-hop shortest path, blast radius
- aws/aws-sdk-go-v2, googleapis/google-cloud-go, Azure/azure-sdk-for-go, boto/boto3 — SDK patterns
- Methodology: gsd-build/get-shit-done (planning docs), obra/superpowers (TDD, verify before done)

## Graph schema (Neo4j labels, Cartography/BloodHound style)
Nodes: AWSAccount, AzureSubscription, GCPProject, EC2Instance, S3Bucket, IAMRole, IAMUser, IAMPolicy, SecurityGroup, RDSInstance,
LambdaFunction, EKSCluster, AzureVM, AzureStorageAccount, AzureNSG, AzureSQLServer, KeyVault, GCEInstance, GCSBucket, GCPFirewall,
CloudSQLInstance, KubernetesPod, KubernetesNamespace, KubernetesServiceAccount, ClusterRoleBinding, GitHubRepository, GitHubOrganization, OktaUser, Internet (+ :Resource on all).
Relationships: RESOURCE, MEMBER_OF_SECURITY_GROUP, ATTACHED_TO, STS_ASSUME_ROLE_ALLOWS, POLICY, GRANTS_ACCESS_TO, ALLOWS_TRAFFIC_TO,
EXPOSED_TO_INTERNET, RUNS_AS, BOUND_TO, MEMBER_OF, TRUSTS, RUNS_ON.
Internal Go edge kinds map 1:1 (see internal/graph/graph.go).

## Contracts
- Finding JSON: internal/model/model.go (Python mirrors it in python/nimbus/models.py). Fingerprint = sha256(source|check_id|provider|account|region|resource.id|file)[:16] hex.
- Native findings (plugins, Python checks): `cloud-posture ingest --source native file.json` accepts an array or JSON lines.
- SQL views: `<resource_type>s` inventory views, `findings_summary`, `attack_path_summary`, `compliance_controls`, per-framework views (`cis_aws_benchmark`, `nist_800_53`, `pci_dss`, `hipaa`, `gdpr`, `soc2`, `iso_27001` ...), tables `graph_nodes`, `graph_edges`.

## Rules for contributors (human or agent)
- Tests first where practical; `go build ./... && go test ./...` and `cd python && pytest` must pass before claiming done.
- Never `go mod tidy` in parallel work sessions; add deps with `go get pkg@version`.
- Secrets only from environment variables (`GITHUB_TOKEN`, `SLACK_WEBHOOK_URL`, `ANTHROPIC_API_KEY`, ...); `nimbus.env`/`.env` are git-ignored.
