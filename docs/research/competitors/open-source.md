# Open-source competitor cluster: deep dive

_Research date: 2026-10-09. This extends `docs/research/competitors.md` (2026-10-08) and does not repeat it. That file already covers Prowler ThreatScore and mutelist semantics, the Prowler onboarding (CFN with External ID, StackSet), the Steampipe FDW architecture, the Powerpipe HCL benchmark tree, KICS `remediate`, the Checkov/Trivy/KICS SARIF GitHub Actions pattern, Custodian's mark-for-op lifecycle and Prowler's HTML-report XSS CVE. Read that file for those details._

**Method and evidence rules**
- Stars, licences, languages, last push and release dates come from the GitHub REST API (`gh api repos/<repo>` and `/releases`), pulled 2026-10-09. They are cited as the repo URL.
- Check counts marked "tree count" come from listing files in each repo's git tree on 2026-10-09 (for example, counting `*.metadata.json` files). These are file counts, not vendor marketing numbers.
- Tags: **[sourced: URL]** means the claim was read at that URL. **[inferred]** means my reading or prior knowledge that I did not re-verify today. Numbers are never inferred.
- Limit: the session's web-search budget ran out partway through. Later facts come from GitHub API reads and direct doc fetches. Where a fact could not be checked (for example Fix Security's corporate status), the text says so.

## Snapshot table (2026-10-09)

| Project | Repo | Stars | Licence | Lang | Latest release | Cadence (last ~10 releases) | Status |
|---|---|---|---|---|---|---|---|
| Prowler | prowler-cloud/prowler | 14,992 | Apache-2.0 | Python | 5.44.0 (2026-09-29) | about every 1–2 weeks | very active |
| Steampipe | turbot/steampipe | 7,980 | AGPL-3.0 | Go | v2.4.7 (2026-09-16) | about monthly | active |
| Powerpipe | turbot/powerpipe | 523 | AGPL-3.0 | TypeScript/Go | v1.5.5 (2026-09-16) | about monthly | active |
| Flowpipe | turbot/flowpipe | 482 | AGPL-3.0 | Go | v1.2.2 (2026-05-19) | every few months | slow |
| Cloud Custodian | cloud-custodian/cloud-custodian | 6,079 | Apache-2.0 | Python | 0.9.53.0 (2026-10-01) | about every 1–3 months | active, CNCF Incubating |
| Cartography | cartography-cncf/cartography | 4,128 | Apache-2.0 | Python | 0.142.0 (2026-10-07) | about monthly | very active, CNCF |
| CloudQuery | cloudquery/cloudquery | 6,542 | MPL-2.0 (framework) | Go | cli-v6.47.0 (2026-10-09) | several per week (monorepo) | active, plugins mostly closed |
| Fix Inventory | someengineering/fixinventory | 2,078 | Apache-2.0 | Python | 4.2.0 (2024-12-05) | stalled | maintenance only |
| Checkov | bridgecrewio/checkov | 9,061 | Apache-2.0 | Python | 3.3.26 (2026-10-07) | several per week | active |
| KICS | Checkmarx/kics | 2,717 | Apache-2.0 | Go/Rego | v2.2.0 (2026-09-17) | about monthly | active |
| Trivy | aquasecurity/trivy | 38,313 | Apache-2.0 | Go | v0.75.0 (2026-10-01) | about every 2–6 weeks | very active |
| Trivy Operator | aquasecurity/trivy-operator | 1,961 | Apache-2.0 | Go | v0.35.0 (2026-10-05) | about monthly | active |
| ScoutSuite | nccgroup/ScoutSuite | 7,839 | GPL-2.0 | Python | 5.14.0 (2024-05-10) | stalled | dormant |
| Kubescape | kubescape/kubescape | 11,787 | Apache-2.0 | Go | v4.0.15 (2026-09-29) | about every 2–3 weeks | very active, CNCF Incubating |
| CloudSploit | aquasecurity/cloudsploit | 3,777 | GPL-3.0 | JavaScript | v3.10.0 (2024-11-15) | no tags since 2024 (commits continue) | active commits, no releases |
| Magpie | openraven/magpie | 205 | Apache-2.0 | Java | none tagged | n/a | dormant (last push 2024-08-29) |
| Matano | matanolabs/matano | 1,699 | Apache-2.0 | Rust | `nightly` (2022-08-31) | n/a | dormant (last push 2025-01-08) |
| ThreatMapper | deepfence/ThreatMapper | 5,324 | Apache-2.0 | TypeScript/Go | v2.5.8 (2026-03-07) | about once a year now | low activity |
| Cloudsplaining | salesforce/cloudsplaining | 2,250 | BSD-3-Clause | Python | 0.9.1 (2026-06-14) | a few per year | maintained |
| PMapper | nccgroup/PMapper | 1,583 | AGPL-3.0 | Python | v1.1.5 (2022-01-13) | stalled | dormant |
| Parliament | duo-labs/parliament | 1,127 | BSD-3-Clause | Python | 1.64 (2025-03-18) | about yearly | low activity |
| kube-bench | aquasecurity/kube-bench | 8,221 | Apache-2.0 | Go | v0.16.0 (2026-08-05) | about monthly | active |
| OpenCSPM | OpenCSPM/opencspm | 347 | MIT | Ruby | 0.1.23 (2021-05-28) | n/a | **archived** |
| cnspec | mondoohq/cnspec | 440 | **BUSL-1.1** (GitHub shows NOASSERTION) | Go | v14.5.0 (2026-10-09) | several per week | very active |
| Powerpipe AWS Compliance mod | turbot/steampipe-mod-aws-compliance | 416 | Apache-2.0 | HCL | (mods use git tags) | — | active (push 2026-10-07) |

Sources for the table: each repo at `https://github.com/<repo>` and its `/releases` page, read via the GitHub API on 2026-10-09.

**Cluster headline findings**
1. **Prowler is now a graph-and-AI platform, not only a CLI.** Prowler Local Server runs Next.js, Django, Celery, Postgres, Valkey and Neo4j. It adds about 100 AWS openCypher attack-path queries over a Cartography graph, an MCP server and the Lighthouse AI agent. It covers 23 providers [sourced: https://github.com/prowler-cloud/prowler]. Cloud costs $99 per account per month [sourced: https://prowler.com/pricing]. Prowler is nimbus's most direct rival.
2. **Cartography is the de facto open-source security graph.** It has 76 intel modules (tree count) and is used as an ingestion engine inside Prowler [sourced: https://github.com/prowler-cloud/prowler]. Its Neo4j schema is a first-class interop target.
3. **The 2026 supply-chain attacks hit two cluster members.** On 2026-03-19, Trivy had a malicious v0.69.4 release and 76 of 77 `trivy-action` tags were force-pushed to credential stealers [sourced: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23]. On 2026-04-22, KICS Docker images were backdoored, attributed to TeamPCP [sourced: https://socket.dev/blog/checkmarx-supply-chain-compromise]. Signed releases and digest pinning are now table stakes for nimbus's own distribution.
4. **Licensing is a differentiator.** Steampipe, Powerpipe and Flowpipe are AGPL-3.0 with a CLA. cnspec is BUSL-1.1 with a non-compete grant. CloudQuery's AWS, GCP and Azure plugins went paid per row. Fix Inventory flipped AGPL to Apache-2.0 and back. A permissively licensed (Apache-2.0) nimbus with no paywalled core features is a real wedge.
5. **Many "classic" tools are dormant**: ScoutSuite, PMapper, Magpie, Matano, OpenCSPM (archived), Fix Inventory, and CloudSploit (no releases since 2024). Their users are migration targets.

---

## 1. Prowler (incl. Prowler App / Local Server / Cloud, Attack Paths, Lighthouse AI)

### Project facts
- GitHub: https://github.com/prowler-cloud/prowler. 14,992 stars, 2,425 forks, Apache-2.0, Python (UI is Next.js) [sourced: GitHub API].
- Last release 5.44.0 on 2026-09-29. Recent releases: 5.43.0 (09-21), 5.42.0 (09-11), 5.41.0 (09-02), 5.40.0 (08-28), so about every 1–2 weeks [sourced: https://github.com/prowler-cloud/prowler/releases].
- Maintainer: Prowler (company, formerly ProwlerPro/Verica) [inferred about corporate history].
- Commercial tiers:
  - OSS: free, Apache-2.0 CLI, SDK and self-hosted Local Server.
  - **Prowler Cloud**: $99 per cloud account per month, 20% off annually. One "account" is an AWS account, GCP project, Azure subscription, GitHub repo or M365 tenant.
  - **Prowler Private Cloud**: custom price, runs in your cloud, data centre or air-gapped.
  - Paid-only per the pricing page: Lighthouse AI side chat and skills, "Autonomous Fixer", scheduled scans, custom scan config, Jira, Power BI, SAML SSO, "attack path analysis", triage workflow, and org-level onboarding (AWS Organizations, Azure management groups, GCP orgs).
  - [sourced: https://prowler.com/pricing]
  - **Note the conflict:** the OSS README documents Attack Paths running in the self-hosted Local Server [sourced: https://github.com/prowler-cloud/prowler], and docs say Lighthouse is in OSS too [sourced: https://docs.prowler.com/getting-started/products/prowler-lighthouse-ai]. The gating may cover only enhanced versions. Treat it as unresolved.

### Deployment
- Four forms [sourced: https://github.com/prowler-cloud/prowler]:
  - CLI: `pip install prowler`, `prowler <provider>`.
  - Local dashboard: `prowler dashboard`.
  - Prowler Local Server via Docker Compose: UI on :3000, API on :8080.
  - GitHub Action `prowler-cloud/prowler@5.x`.
- The server stack is Next.js UI, Django REST API, Celery worker and beat, Postgres, Valkey and Neo4j, plus a Prowler MCP Server [sourced: same].
- Agentless, API-based.
- **23 providers** in the README table (2026-10). Official checks:
  - AWS 662 checks / 86 services / 50 frameworks; Azure 191; GCP 110; Kubernetes 92; GitHub 24; M365 144; OCI 52; Alibaba 63; Cloudflare 29; MongoDB Atlas 10; Google Workspace 65; OpenStack 34; Vercel 26; Okta 29.
  - IaC is delegated to Trivy, LLM red-teaming to promptfoo, and Image scanning is supported.
  - Unofficial: Linode 10, Huawei 25, E2E 27, Scaleway 1, StackIT 8, NHN 6.
  - [sourced: https://github.com/prowler-cloud/prowler]
- Tree count: 1,616 `*.metadata.json` check files and 105 compliance JSON files [sourced: repo tree, https://github.com/prowler-cloud/prowler/tree/master/prowler].
- The pricing page markets "2,500+ checks across providers" [sourced: https://prowler.com/pricing]. That is higher than the tree count. It probably counts per-framework mappings or includes Private Cloud content [inferred].
- 5.42 added AWS ISO partitions (`aws-iso`, `-iso-b`, `-iso-e`, `-iso-f`) and connect/read timeout flags. 5.44 added S3-compatible (MinIO) output storage and air-gapped UI icons [sourced: https://github.com/prowler-cloud/prowler/releases/tag/5.42.0, https://github.com/prowler-cloud/prowler/releases/tag/5.44.0].

### Inventory & graph
- Findings and resources live in Postgres (Django models) [sourced: README architecture].
- For the graph, every completed AWS scan runs Cartography ingestion into a **temporary Neo4j DB** and then writes to a long-lived sink. The sink is Neo4j (default) or **Amazon Neptune** (SigV4 auth), set with `ATTACK_PATHS_SINK_DATABASE` [sourced: https://github.com/prowler-cloud/prowler].
- Query language: openCypher (read-only) for attack paths. There is no SQL interface. The API is JSON:API REST at `/api/v1/docs` [sourced: README].

### Attack paths
- AWS only today. "Other cloud providers will be added in future iterations" [sourced: https://github.com/prowler-cloud/prowler].
- Built-in queries live in `api/src/backend/api/attack_paths/queries/aws.py`, about 4,950 lines with about 100 query `id`s [sourced: https://github.com/prowler-cloud/prowler/blob/master/api/src/backend/api/attack_paths/queries/aws.py].
  - Exposure examples: `aws-internet-exposed-ec2-sensitive-s3-access`, `aws-security-groups-open-internet-facing`.
  - Inventory examples: `aws-rds-instances`.
  - Privilege-escalation examples, one per pathfinding.cloud technique: `aws-iam-privesc-create-policy-version`, `aws-ecs-privesc-passrole-run-task`, `aws-bedrock-privesc-passrole-code-interpreter`, and more.
- Custom queries: read-only openCypher, at most 10,000 characters, auto-scoped to the selected scan [sourced: https://docs.prowler.com/user-guide/tutorials/prowler-app-attack-paths].
- Graph UI: nodes are resources, findings, internet exposure and outcomes. You can expand groups, click a finding to focus its path, hover to highlight, export PNG, and go fullscreen. Caveat: "a scan can complete without producing graph data" [sourced: same].
- The MCP server has an `attack_paths.py` tool module, so Lighthouse can run path queries [sourced: repo tree].
- 5.44 added a periodic sweep for orphaned temporary Neo4j databases after crashes, which points to operational fragility [sourced: https://github.com/prowler-cloud/prowler/releases/tag/5.44.0].

### Risk prioritization
- ThreatScore (weighted) is covered in the base doc.
- Finding Groups and Manual Pass triage overlay in Cloud [sourced: 5.44.0 release notes].
- New Inspector2 checks include `inspector2_active_findings_no_known_exploited_vulnerabilities` and `..._kev_within_due_date`, so KEV appears as a posture check rather than a score input [sourced: https://github.com/prowler-cloud/prowler/releases/tag/5.43.0].
- No published EPSS- or graph-weighted risk score [inferred from absence in docs read].

### CIEM/identity
- IAM checks per provider.
- About 70 IAM privilege-escalation path queries modelled on pathfinding.cloud techniques (query ids above).
- Identity providers as scan targets: Okta (29 checks), M365/Entra, Google Workspace [sourced: README].
- No effective-permissions calculator is documented [inferred].

### DSPM
- None beyond configuration checks such as public buckets and encryption [inferred]. The graph query `aws-internet-exposed-ec2-sensitive-s3-access` uses a "sensitive" notion from tags or parameters (`tag_key`, `tag_value` parameters appear in the file) [sourced: aws.py].

### Vulnerability & secrets
- "Image" provider for container images. It uses Trivy under the hood and honours `TRIVY_CACHE_DIR` for a reusable vulnerability DB [sourced: https://github.com/prowler-cloud/prowler/releases/tag/5.42.0].
- Secrets checks exist in cloud configs, for example Lambda env and EC2 user data [inferred].
- TruffleHog is used only in their own pre-commit [sourced: README].

### Code-to-cloud / IaC
- IaC provider delegates to Trivy misconfiguration scanning and outputs SARIF [sourced: README, https://docs.prowler.com/user-guide/cli/tutorials/reporting].
- No cloud-resource-to-source mapping [inferred].

### Remediation
- Every check's metadata carries remediation text, CLI, Terraform and other snippets [inferred from check metadata format].
- **CLI fixers**: 56 `*_fixer.py` files (55 AWS, 1 M365) for automatic fixes [sourced: repo tree].
- Cloud tier markets an "Autonomous Fixer" [sourced: https://prowler.com/pricing]. No public docs found on whether it opens PRs.
- 5.44 added **partial scans**: `POST /api/v1/scans` with up to 10 `resource_uids`. Lighthouse can re-scan a resource to confirm a fix [sourced: https://github.com/prowler-cloud/prowler/releases/tag/5.44.0].

### Compliance
- 105 framework JSON files (tree count).
- README groups them as CIS, NIST 800/CSF, CISA, MITRE ATT&CK, RBI, FedRAMP, PCI-DSS, NIS2, GDPR, HIPAA, FFIEC, SOC2, GxP, ISO 27001, AWS FTR/WAF, BSI C5, ENS, KISA ISMS-P, and custom.
- 5.43 added `fedramp_20x_ksi_2026` (46 KSIs across AWS/Azure/GCP/K8s/M365) and `fedramp_20x_frr_class_c_2026` (158 rules) as **"universal" cross-provider frameworks** [sourced: https://github.com/prowler-cloud/prowler/releases/tag/5.43.0].
- 5.42 added a **catalog integrity test** after finding duplicate requirement IDs and stale check references in frameworks [sourced: 5.42.0 notes].
- Paid tiers have 70+ frameworks including NATO D32. Private adds VMware VCF and a "Local Registry" [sourced: pricing].

### Real-time
- Scheduled scans only (Celery beat; paid per pricing page).
- No event-driven detection is documented. CloudTrail timelines are queryable by Lighthouse (base doc).

### Integrations/outputs
- Formats: CSV and JSON-OCSF (default), JSON-ASFF, HTML, and SARIF (IaC only) [sourced: https://docs.prowler.com/user-guide/cli/tutorials/reporting].
- Output modules in tree: `asff`, `csv`, `html`, `ocsf`, `sarif`, `jira`, `slack`, `compliance` [sourced: repo tree `prowler/lib/outputs`].
- S3 upload, Security Hub, GitHub Action with SARIF upload, Jira, Slack, Power BI and email (paid), AWS Security Lake (Private) [sourced: pricing, reporting docs].
- Findings import ("Import Findings" in the UI, Cloud ingestion worker) [sourced: 5.42/5.44 notes].

### UI/dashboard
- Prowler App (Next.js) has a findings table with Finding Group filter, scans page (Launch Scan, Import Findings, Configure Mutelist), compliance views with per-provider breakdown and OCSF download, an attack-path graph explorer, a provider wizard (5.44 made AWS one step), invitations, RBAC and API keys [sourced: release notes 5.42–5.44].
- `prowler dashboard` is a local Dash app over CSV output [inferred].

### AI features
- **Lighthouse AI**, added in 5.8.0, is a chatbot "Cloud Security Analyst". It uses OpenAI, Amazon Bedrock or any OpenAI-compatible endpoint (OpenRouter, Ollama) and filters to tool-calling models.
- Data access goes through the **Prowler MCP Server**. Add tools to MCP and "Lighthouse AI discovers them automatically".
- Strictly read-only, and limited to data the logged-in user can view.
- Cloud adds persistent sessions, a default GPT model, an agentic view and visible reasoning [sourced: https://docs.prowler.com/getting-started/products/prowler-lighthouse-ai].
- MCP tool modules: attack_paths, compliance, finding_groups, findings, integrations, muting, providers, resources, roles, scans, users [sourced: repo tree].
- The repo ships `AGENTS.md` files and a `.claude-plugin/marketplace.json`, so it is agent-friendly for contributors [sourced: repo tree].

### Extensibility
- Python check classes with JSON metadata per check.
- Custom checks folder, custom compliance JSON and mutelist YAML.
- "Registry marketplace and external provider onboarding" for Private Cloud with schema-driven credentials [sourced: 5.43.0 notes].
- Prowler Hub (https://hub.prowler.com) is the catalogue.

### Unique strengths
- Widest provider breadth (23).
- Fastest release cadence.
- OCSF-native.
- Full self-hostable app with a graph and AI.
- FedRAMP 20x "universal" frameworks.
- Neptune sink option.
- Air-gapped readiness work (5.44).

### Documented weaknesses
- Top open issues: "Stop a running scan" (12 👍, open since 2025-02) [sourced: https://github.com/prowler-cloud/prowler/issues/6893]. "Configure Data Retention" [sourced: https://github.com/prowler-cloud/prowler/issues/8687]. "Region selection in Prowler UI" [sourced: https://github.com/prowler-cloud/prowler/issues/7387].
- Attack paths are AWS-only and can complete with no graph data. Orphaned temporary Neo4j DBs needed a sweeper.
- Overlapping scans made findings, compliance and mute rules read different scans until 5.44 [sourced: 5.44.0 notes].
- The heavy stack (Postgres + Valkey + Neo4j + Celery + Next.js) is many moving parts [inferred].
- Python CLI pinned to >=3.10, <3.13 [sourced: README].
- Earlier stored XSS in the HTML report (base doc).
- Pricing page and OSS README disagree on what is gated.

### Sources
https://github.com/prowler-cloud/prowler · https://github.com/prowler-cloud/prowler/releases · https://docs.prowler.com/user-guide/tutorials/prowler-app-attack-paths · https://docs.prowler.com/getting-started/products/prowler-lighthouse-ai · https://docs.prowler.com/user-guide/cli/tutorials/reporting · https://prowler.com/pricing · https://github.com/prowler-cloud/prowler/blob/master/api/src/backend/api/attack_paths/queries/aws.py

---

## 2. Steampipe + Powerpipe + Flowpipe (+ Tailpipe) — Turbot

### Project facts
- Steampipe: https://github.com/turbot/steampipe. 7,980 stars, AGPL-3.0, Go. v2.4.7 on 2026-09-16, about monthly (v2.4.0 Feb, .1 Apr, .2 Apr, .3/.4 May, .5 Aug, .6/.7 Sep). A v2.5.0 beta ran in June 2026 [sourced: GitHub API].
- Powerpipe: https://github.com/turbot/powerpipe. 523 stars, AGPL-3.0. v1.5.5 on 2026-09-16 [sourced].
- Flowpipe: https://github.com/turbot/flowpipe. 482 stars, AGPL-3.0. v1.2.2 on 2026-05-19, previously v1.2.0 on 2025-08-01, so slow [sourced].
- Tailpipe (log SIEM): https://github.com/turbot/tailpipe. 582 stars, AGPL-3.0. v0.7.4 on 2026-05-19 [sourced].
- Contributors sign a CLA. The binaries are distributed by Turbot HQ under commercial terms. Others can redistribute but not use the trademark [sourced: Powerpipe README].
- Commercial: **Turbot Pipes** (hosted Steampipe/Powerpipe/Flowpipe workspaces) and **Turbot Guardrails** (enterprise) [sourced: READMEs; Guardrails inferred].
- Plugins and mods are mostly Apache-2.0, for example the aws_compliance mod [sourced: mod README].

### Deployment
- Single binaries for the CLI, plus `steampipe service start` (embedded Postgres) and `powerpipe server` (dashboards on :9033) [sourced: mod README].
- Plugin distributions: Steampipe CLI, **native Postgres FDW**, **SQLite extension**, and **standalone export binaries** that need no DB [sourced: https://github.com/turbot/steampipe].
- Agentless with live API calls.
- Turbot org has 127 `steampipe-plugin-*` repos. The hub also has community plugins. "More than 2000 tables" [sourced: Steampipe README; GitHub search API].
- AWS plugin: 590 `table_*.go`. Azure: 179. GCP: 123 (tree counts) [sourced: https://github.com/turbot/steampipe-plugin-aws].

### Inventory & graph
- Data model: one Postgres foreign table per API resource (`aws_s3_bucket`), with JSONB columns for nested data.
- Query language: **PostgreSQL SQL** with live querying and a cache.
- No persisted graph. Powerpipe draws "relationship diagrams" (`graph`/`node`/`edge` HCL) from SQL at render time [sourced: https://github.com/turbot/powerpipe].
- No history or time travel unless you export [inferred].

### Attack paths
- None as a product.
- Relationship graphs are visual and resource-centric, not path analysis [inferred].

### Risk prioritization
- Severity tags on controls only. No contextual scoring [inferred].

### CIEM/identity
- SQL over IAM tables, for example `aws_iam_policy_simulator`.
- The AWS Insights / AWS Perimeter mods give IAM dashboards [inferred, mod names not re-verified].

### DSPM
- None [inferred].

### Vulnerability & secrets
- No native scanner.
- Plugins exist for Trivy, NVD and others [inferred]. Flowpipe has an NVD library mod (`flowpipe-mod-nvd`) [sourced: GitHub search, turbot org].

### Code-to-cloud / IaC
- Terraform plugin queries HCL as tables [inferred].
- Powerpipe mods exist for Terraform/IaC compliance [inferred].

### Remediation
- **Flowpipe** runs HCL pipelines with steps (http, query, message, input/human approval, container, function) and triggers (http webhook, query, schedule) [sourced: https://github.com/turbot/flowpipe].
- 41 `flowpipe-mod-*` repos in the turbot org, including `aws-compliance`, `aws-cis`, `azure-compliance`, `azure-cis`, `aws-thrifty`, `aws-tags`, `detect-correct`, `jira`, `slack`, `teams`, `pagerduty` [sourced: GitHub search].
- The AWS Compliance Flowpipe mod is "Pipelines to detect and remediate misconfigurations in AWS resources". It imports Steampipe connections and needs Docker [sourced: https://github.com/turbot/flowpipe-mod-aws-compliance].
- Human-in-the-loop approvals happen through `input` steps in Slack or email [sourced: Flowpipe README].

### Compliance
- "5,000+ open-source controls from CIS, NIST, PCI, HIPAA, FedRamp and more" on hub.powerpipe.io [sourced: Powerpipe README].
- AWS Compliance mod README says "540+ checks" and includes CIS v4.0.0, PCI DSS 3.2.1/4.0 and AWS FSBP. The repo has 550 `.pp`/`.sp` files (tree count) [sourced: https://github.com/turbot/steampipe-mod-aws-compliance].
- The base doc cited 1,229 controls from the hub. The difference is probably controls versus benchmark memberships [inferred].
- Benchmark output formats: `asff`, `brief`, `csv`, `html`, `json`, `md`, `none`, `nunit3`, `pps`/`snapshot`, `pretty`, `plain`.
- Filtering: `--tag` (keys ANDed, duplicate keys ORed) and `--where` (SQL where-clause over control metadata) [sourced: https://powerpipe.io/docs/reference/cli/benchmark].
- Dimensions are configurable via vars (`common_dimensions`, `tag_dimensions`) [sourced: mod README].

### Real-time
- Steampipe is query-time live data, not event-driven.
- Flowpipe query triggers poll on a schedule.
- Tailpipe handles logs (CloudTrail and others) with 23 `tailpipe-plugin-*` repos [sourced: GitHub search]. Its detection model was not verified.

### Integrations/outputs
- ASFF/CSV/JSON/HTML/MD/NUnit3 (above).
- Flowpipe library mods for Slack, Teams, Jira, PagerDuty, Opsgenie, ServiceNow, and more [sourced: GitHub search].
- Postgres wire protocol, so any BI tool works.
- **Steampipe MCP server** (April 2025, Node.js) lets AI assistants list tables and run SQL; it works locally or against Pipes [sourced: https://steampipe.io/blog/steampipe-mcp; https://github.com/turbot/steampipe-mcp, 48 stars].

### UI/dashboard
- Powerpipe server serves HCL-defined dashboards: cards, charts, tables, graphs, flows, hierarchies, inputs/filters.
- The benchmark dashboard has a control tree with alarm/ok/info/skip/error counters, grouping and filtering, and snapshots you can share via Pipes [sourced: Powerpipe README].
- Screenshot description: a dark/light dashboard with a summary card row and a collapsible benchmark tree [inferred from prior viewing].

### AI features
- Steampipe MCP server (above).
- Flowpipe `openai` library mod [sourced: GitHub search].
- Turbot Pipes AI features were not verified.

### Extensibility
- **Plugin SDK in Go** over gRPC: define tables, columns, hydrate functions, list/get calls and key-column quals [inferred, base doc covers the architecture].
- Mods in HCL: query, control, benchmark, dashboard, pipeline.
- Mods are installed from git (`powerpipe mod install github.com/...`) [sourced: mod README].

### Unique strengths
- Biggest API-to-SQL catalogue (about 2,000+ tables).
- Zero-ETL live queries.
- Same plugins ship as FDW, SQLite extension or export binary.
- Code-first dashboards and benchmarks.
- Detect-and-correct pipelines with human approval.

### Documented weaknesses
- AGPL plus CLA deters embedding [sourced: READMEs].
- No persisted graph or attack paths. Live queries against large estates are slow and rate-limited [inferred].
- Four tools to learn (Steampipe, Powerpipe, Flowpipe, Tailpipe).
- Flowpipe releases are slow (8 months between 1.2.0 and 1.2.1).
- Steampipe's open issues are mostly internal error-handling bugs (12 open) [sourced: https://github.com/turbot/steampipe/issues].

### Sources
https://github.com/turbot/steampipe · https://github.com/turbot/powerpipe · https://github.com/turbot/flowpipe · https://github.com/turbot/tailpipe · https://powerpipe.io/docs/reference/cli/benchmark · https://steampipe.io/blog/steampipe-mcp · https://github.com/turbot/steampipe-mod-aws-compliance · https://github.com/turbot/flowpipe-mod-aws-compliance

---

## 3. Powerpipe benchmarks (Steampipe-based compliance mods) — as a product surface

### Project facts
- Example: https://github.com/turbot/steampipe-mod-aws-compliance. 416 stars, Apache-2.0, last push 2026-10-07 [sourced: GitHub API].
- 66 `steampipe-mod-*` and 9 `powerpipe-mod-*` repos in the turbot org [sourced: GitHub search].

### Deployment
- `powerpipe mod install`.
- Needs Steampipe plus the provider plugin as the data source. Powerpipe itself can also query Postgres, SQLite, DuckDB or MySQL [sourced: Powerpipe README].

### Inventory & graph
- Named SQL queries per control. No graph.

### Attack paths
- None.

### Risk prioritization
- Control `severity` and tags only.

### CIEM/identity
- IAM controls inside the CIS benchmarks.

### DSPM
- None.

### Vulnerability & secrets
- None.

### Code-to-cloud / IaC
- Separate Terraform mods [inferred].

### Remediation
- Control docs carry remediation markdown [inferred].
- Execution goes through Flowpipe mods.

### Compliance
- Benchmarks are nested HCL `benchmark { children = [...] }` with `control { sql = ... }`.
- A control returns `resource, status (ok|alarm|info|skip|error), reason` plus dimensions [inferred from Powerpipe control spec].
- AWS mod covers CIS v4.0.0, CIS Compute Services, PCI DSS 3.2.1 and 4.0, AWS FSBP and more [sourced: mod README].

### Real-time
- None.

### Integrations/outputs
- Same exporters as Powerpipe benchmark, including `asff` and `nunit3` [sourced: powerpipe docs].

### UI/dashboard
- Benchmark dashboards in `powerpipe server`.

### AI features
- None.

### Extensibility
- Fork the mod, add HCL controls, and override vars (`powerpipe.ppvars`, `PP_VAR_*`) [sourced: mod README].

### Unique strengths
- The control result contract (`resource/status/reason/dimensions`) is simple, SQL-portable and ideal for nimbus to emulate.

### Documented weaknesses
- Coupled to Steampipe table names.
- Duplicated control logic across many mods [inferred].

### Sources
https://github.com/turbot/steampipe-mod-aws-compliance · https://github.com/turbot/powerpipe · https://powerpipe.io/docs/reference/cli/benchmark

---

## 4. Cloud Custodian (c7n)

### Project facts
- https://github.com/cloud-custodian/cloud-custodian. 6,079 stars, 1,660 forks, Apache-2.0, Python. **CNCF Incubating** [sourced: README].
- Release 0.9.53.0 on 2026-10-01. Earlier releases: 0.9.52 (09-03), .51 (05-28), .50 (03-18), .49 (01-16), so about every 1–3 months [sourced: GitHub API].
- Community-led. Originated at Capital One [inferred]. Stacklet sells a commercial platform [inferred].
- 1,446 open issues [sourced: GitHub search API].

### Deployment
- `pip install c7n` or Docker. Runs as a CLI or cron, or **auto-provisions serverless functions** with event sources: CloudWatch Events, AWS Config rules, Azure Event Grid, GCP Audit Log and Pub/Sub [sourced: README].
- Providers: AWS (127 resource modules in `c7n/resources`), Azure (109 modules), GCP (40), Kubernetes (4), OCI (7), OpenStack (10), Tencent Cloud (21), and AWS Cloud Control (`c7n_awscc`) (tree counts) [sourced: repo tree].
- No fixed check count. It is a policy engine plus community policy libraries.

### Inventory & graph
- Resource-type-centric. No graph.
- `c7n_traildb` and `c7n_salactus` (S3 at scale) are side tools [sourced: tree `tools/`].
- Query language is YAML filters: value, nested boolean, JMESPath, cross-account, etc.

### Attack paths
- None.

### Risk prioritization
- None beyond policy metadata [inferred].

### CIEM/identity
- IAM filters such as `cross-account`, `has-inline-policy`, `unused`/`check-permissions` [inferred, not re-verified].

### DSPM
- None.

### Vulnerability & secrets
- None.

### Code-to-cloud / IaC
- **c7n-left** runs Custodian policies over Terraform, for example `resource: terraform.aws_s3_bucket` with `filters: - server_side_encryption_configuration: absent`.
- CLI: `c7n-left run -p policy_dir -d terraform_root --filters "severity=HIGH"`, with `--warn-on`, `--var-file`, `--output [cli|github|json]`, `--output-query` (JMESPath) and `--summary [policy|resource]`.
- Signed Wolfi-based images verified with cosign. "WARNING - CLI interface subject to change."
- [sourced: https://github.com/cloud-custodian/cloud-custodian/tree/main/tools/c7n_left]
- A separate `c7n_terraform` tool exists [sourced: tree].

### Remediation
- **Core strength**: actions such as remove cross-account access, encrypt, tag, stop, terminate, notify, and mark-for-op (base doc).
- Dry run of any policy [sourced: README].
- `c7n-mailer` for notifications and `c7n-org` for multi-account runs [sourced: tree `tools/`].

### Compliance
- No packaged frameworks in core [inferred]. Users map policies themselves. Stacklet and community repos provide CIS packs [inferred].

### Real-time
- **Yes, the best in cluster for enforcement.** Event-mode Lambda, Azure Functions and GCP Cloud Functions react to API events in seconds [sourced: README "real time enforcement"].
- `c7n_guardian` for GuardDuty [sourced: tree].

### Integrations/outputs
- Cloud-native metrics (CloudWatch and similar).
- Structured JSON resource outputs to S3, Blob or GCS.
- Mailer to email, Slack, SNS, Datadog and others [inferred].
- Security Hub post-finding action [inferred].
- c7n-left outputs GitHub annotations or JSON.

### UI/dashboard
- None in OSS [inferred]. Stacklet is the commercial UI [inferred].

### AI features
- None in OSS [inferred].

### Extensibility
- Python plugin model with filter and action registries per resource. YAML is the user surface.

### Unique strengths
- Event-driven real-time enforcement with automatic serverless provisioning.
- Mature action vocabulary.
- Dry-run.
- Very broad provider plugins, including Tencent and OpenStack.

### Documented weaknesses
- Top issues: "policy targeting multiple resource types" (38 👍, open since 2020) and "allow multiple resources to be specified on a policy" (27 👍, since 2017) [sourced: https://github.com/cloud-custodian/cloud-custodian/issues/5258, /issues/1244].
- "c7n-org: Support multiple policies files" [sourced: /issues/3991].
- "lambda functions need garbage collection if removed from policy file" (open since 2016) [sourced: /issues/48].
- c7n-left warns its CLI is unstable.
- 1,446 open issues.

### Sources
https://github.com/cloud-custodian/cloud-custodian · https://github.com/cloud-custodian/cloud-custodian/tree/main/tools/c7n_left · https://github.com/cloud-custodian/cloud-custodian/releases

---

## 5. Cartography (CNCF)

### Project facts
- https://github.com/cartography-cncf/cartography. 4,128 stars, Apache-2.0, Python. Org name `cartography-cncf` [sourced: GitHub API].
- Originally from Lyft [inferred]. CNCF maturity level not re-verified [inferred: Sandbox].
- Release 0.142.0 on 2026-10-07. Earlier: 0.141 (09-01), 0.140 (08-11), 0.139 (07-13), so about monthly [sourced: GitHub API].
- A `subimage_coverage.py` rule suggests SubImage (a commercial company by Cartography maintainers) is the main backer [inferred].
- Has an OpenSSF Scorecard badge [sourced: README].

### Deployment
- `pip install cartography` plus Neo4j 5 (Docker). `cartography --neo4j-uri bolt://... --selected-modules aws`.
- `cartography[neo4j-rust]` speeds sync by about 20–30% [sourced: README].
- 76 intel modules (tree count of `cartography/intel/*`) [sourced: repo tree].
- README lists AWS, GCP, Azure, K8s, GitHub, Okta, Entra (with Intune), Google Workspace, Keycloak, OCI (IAM), Cloudflare, CrowdStrike, Orca, Duo, Jira, Kandji, LastPass, Netlify, OpenAI, Anthropic, PagerDuty, Railway, Scaleway, Huntress, BigFix, Airbyte, Databricks, Tailscale, Zoom and others [sourced: README].
- Includes **AIBOM** (AI components linked to ECR images) and **CVE metadata enrichment with CVSS, EPSS and CISA KEV** [sourced: README].

### Inventory & graph
- Neo4j property graph with node labels like `AWSAccount`, `AWSRDSInstance`, `AWSEC2Instance{exposed_internet}` and relationships like `RESOURCE`.
- Query language: **Cypher**.
- Published data schema at docs.cartography.dev/usage/schema [sourced: README].
- Prowler uses Cartography as its ingestion engine [sourced: Prowler README].

### Attack paths
- No path engine of its own, but derived properties such as `exposed_internet`.
- README questions: "Which identities have access to which datastores?", "network paths in and out", "What AI agents are running in production, and what permissions do they have?" [sourced: README].

### Risk prioritization
- EPSS and KEV enrichment of CVE nodes [sourced: README].
- Rules are deliberately non-scoring: "We don't impose arbitrary thresholds... we surface facts" [sourced: https://docs.cartography.dev/usage/rules.html].

### CIEM/identity
- Strong cross-provider identity: Okta/Entra federation to AWS roles and Identity Center, GitHub, Keycloak, OpenAI and Anthropic API keys [sourced: README].
- Rules: `identity_administration_privileges`, `iam_role_external_account_trust`, `delegation_boundary_modifiable`, `workload_identity_admin_capabilities`, `inactive_user_active_accounts`, `mfa_missing` (rule filenames) [sourced: repo tree `cartography/rules/data/rules`].

### DSPM
- None (no content classification) [inferred].

### Vulnerability & secrets
- Ingests CrowdStrike Spotlight, Orca CVEs, ECR image layers and attestations, GitHub dependency manifests, and CVE metadata [sourced: README].
- Rule `malicious_npm_dependencies_shai_hulud` [sourced: tree].

### Code-to-cloud / IaC
- GitHub repos and dependencies plus `unpinned_github_actions` rule [sourced: tree]. No IaC scanning.

### Remediation
- None.

### Compliance
- `cartography-rules` CLI (`list`, `run`) has 39 rule files (tree count).
- Frameworks: CIS AWS 6.0.0, GCP 4.0, Google Workspace 1.3, Kubernetes 1.12, ISO 27001:2022, SOC 2 TSC 2022, NIST AI RMF 1.0, DISA Okta STIG v1r2.
- Output: text or JSON [sourced: https://docs.cartography.dev/usage/rules.html].

### Real-time
- None. Batch sync.

### Integrations/outputs
- Neo4j only. Neptune support is a top-requested issue [sourced: https://github.com/cartography-cncf/cartography/issues/1658]. Prowler built its own Neptune sink.
- Rules output JSON.

### UI/dashboard
- None. Use Neo4j Browser. Each rule ships a `cypher_visual_query` specifically for Neo4j Browser visualisation [sourced: rules docs].

### AI features
- None in the tool. It models AI assets (AIBOM, OpenAI, Anthropic, Bedrock) [sourced: README].

### Extensibility
- Intel modules in Python with a declarative data model (node/relationship schema classes) [inferred].
- **Rule authoring**: Rule → Facts. Each Fact has `cypher_query`, `cypher_visual_query` and `cypher_count_query` (the denominator for compliance ratios), plus a Pydantic `Finding` subclass with required `identity_fields` (stable identity across syncs), `asset_label` and `asset_id_field`. Maturity is `EXPERIMENTAL` or `STABLE` [sourced: https://docs.cartography.dev/usage/rules.html].

### Unique strengths
- Widest identity and SaaS graph coverage.
- Fact/Rule model with stable finding identity and count-query denominators.
- EPSS/KEV enrichment.
- The ecosystem standard (Prowler depends on it).

### Documented weaknesses
- Neo4j-only ("Add Support for Amazon Neptune", issue #1658).
- "Extend GCP support" is the top issue since 2020 [sourced: /issues/415].
- "Standardize and make ID fields consistent" [sourced: /issues/1024].
- S3 bucket policies not represented in the graph [sourced: /issues/759].
- No UI.

### Sources
https://github.com/cartography-cncf/cartography · https://docs.cartography.dev/usage/rules.html · https://github.com/cartography-cncf/cartography/issues

---

## 6. CloudQuery

### Project facts
- https://github.com/cloudquery/cloudquery. 6,542 stars, Go. **MPL-2.0 for framework, SDK and CLI. Most official source plugins are commercial and closed source** [sourced: README "Open source" section; https://www.cloudquery.io/blog/cloudquery-official-free-plugins-moving-to-paid].
- Monorepo releases several times a day. cli-v6.47.0 on 2026-10-09 [sourced: GitHub API].
- Commercial: plugins are free up to a monthly quota, then **pay per row synced**. AWS, GCP and Azure moved first. Previous free versions stay on GitHub without maintenance [sourced: CloudQuery blog].
- CloudQuery Platform is a managed offering with custom pricing [inferred from search snippet].

### Deployment
- `cloudquery init --source=aws --destination=postgresql`, then `cloudquery sync` (base doc).
- Runs on your infrastructure: "Your cloud data never touches CloudQuery's servers" [sourced: README].
- "AWS, Azure, GCP, and 70+ cloud and SaaS sources" [sourced: repo description].
- Open plugins left in the repo: source `aws` (limited), `airtable`, `bitbucket`, `hackernews`, `square`, `typeform`, `xkcd`. Destinations: azblob, bigquery, clickhouse, duckdb, elasticsearch, file, firehose, gcs, gremlin, kafka, meilisearch, mongodb, mssql, mysql, **neo4j**, postgresql, s3, snowflake, sqlite (tree) [sourced: repo tree].

### Inventory & graph
- Tables in your warehouse. The schema is normalised per plugin.
- Apache Arrow transport.
- Graph only via neo4j or gremlin destinations.
- Query language: your destination's SQL.

### Attack paths
- None [inferred].

### Risk prioritization
- None in OSS [inferred].

### CIEM/identity
- Tables only.

### DSPM
- None.

### Vulnerability & secrets
- Can sync scanner outputs as sources [inferred].

### Code-to-cloud / IaC
- None [inferred].

### Remediation
- None.

### Compliance
- Historically shipped SQL "policies" (CIS etc.) and moved them to transformations or Platform [inferred]. Not verified for 2026.

### Real-time
- CDC support exists for some sources (base doc).
- Issue: "Support CDC for tables that get created after the sync starts" [sourced: https://github.com/cloudquery/cloudquery/issues/9102].

### Integrations/outputs
- Around 20 destinations (above).
- "BI tools, Slack alerts, Jira ticketing" [sourced: README].

### UI/dashboard
- OSS has none. Platform has asset inventory UI [inferred]. Grafana CSPM blog recipe [sourced: README link "how-to-build-a-cspm-with-grafana-and-cloudquery"].

### AI features
- Platform advertises AI-powered querying [inferred from search snippet]. OSS has none.

### Extensibility
- **Multi-language plugin SDK** (Go, Python, JavaScript, Java), gRPC with Arrow [sourced: README "multi-language, open plugin system"; SDK repo https://github.com/cloudquery/plugin-sdk].

### Unique strengths
- Best ELT plumbing: Arrow, about 20 destinations, warehouse-native, rows stay in your environment.

### Documented weaknesses
- Paywalled plugins. Unmaintained legacy free versions.
- Top issues: "Windows support for DuckDB destination" (9 👍), "overwrite-delete-stale mark rows as deleted instead of deleting" (history loss) [sourced: https://github.com/cloudquery/cloudquery/issues/8854, /issues/8133].

### Sources
https://github.com/cloudquery/cloudquery · https://www.cloudquery.io/blog/cloudquery-official-free-plugins-moving-to-paid · https://github.com/cloudquery/plugin-sdk

---

## 7. Fix Inventory / Fix Security (ex-Resoto)

### Project facts
- https://github.com/someengineering/fixinventory. 2,078 stars, Apache-2.0, Python [sourced: GitHub API].
- Commits in March 2025 say "Fix some AGPL references that were left after returning to Apache2", so the licence went Apache → AGPL → Apache [sourced: commit log via GitHub API].
- Last release 4.2.0 on 2024-12-05. Last substantive code commits are from 2025, with README/Docker-domain housekeeping on 2026-09-03 (docs moved from `inventory.fix.security` to `fixinventory.org`) [sourced: GitHub API].
- Maintainer: Some Engineering (Hamburg).
- Commercial: Fix Security SaaS. **On 2026-10-09 `fix.security` did not resolve (DNS ENOTFOUND)** [sourced: direct fetch attempt]. Together with the docs domain move, this suggests the SaaS is discontinued [inferred, not confirmed by an announcement].

### Deployment
- Self-hosted (laptop or cloud) with a CLI.
- Agentless.
- AWS, GCP, Azure, Kubernetes, plus collectors for others.
- "Over 300 cloud services" [sourced: README].

### Inventory & graph
- Graph DB (ArangoDB) [inferred].
- **Unified data model with 40+ "base kinds"** (database, ip_address, volume) so one policy runs across clouds [sourced: README].
- Normalised properties: `id, name, kind, tags, age, last_access, last_update`.
- Own **search language** with relative times (`search age < "3d"`), kind predicates (`is(volume) and volume_encrypted=false`) and graph traversal with edge filters: `-iam[0:]{permissions[*].level==write}->`.
- Pipe output to DOT (`| format --dot`) [sourced: README].

### Attack paths
- Graph traversal queries ("is there a path to get from this resource to a privileged role?").
- Visualisations were in the SaaS [sourced: README].

### Risk prioritization
- Not documented in OSS [inferred].

### CIEM/identity
- **Access graph with permission levels on IAM edges**, for example "which S3 buckets user Matthias can write to".
- NHI and service-account risk [sourced: README].

### DSPM
- AI-SPM claims: "discovery of AI services... and the data sources they connect to" [sourced: README].

### Vulnerability & secrets
- None [inferred].

### Code-to-cloud / IaC
- None.

### Remediation
- Alerting and actions via jobs [sourced: README "alerting"].

### Compliance
- CIS AWS/Azure, ISO-27001 and NIS-2 via `report benchmark run iso27001` [sourced: README].

### Real-time
- **Hourly snapshots by default with per-resource change timeline and diff view** [sourced: README].

### Integrations/outputs
- Export to other DBs. Alerting to Slack and others [inferred].

### UI/dashboard
- OSS is CLI-first ("the user interface is our CLI"). Visual UI was in the SaaS [sourced: README].

### AI features
- None documented.

### Extensibility
- Collector plugins (example collector provided). Policies as queries [sourced: README].

### Unique strengths
- The **base-kind abstraction** (write a policy once for all clouds).
- Permission-weighted IAM edges.
- Hourly snapshots with diff.
- Concise graph search syntax.

### Documented weaknesses
- Effectively unmaintained since 2025.
- Licence churn.
- Commercial SaaS apparently offline [inferred].

### Sources
https://github.com/someengineering/fixinventory · GitHub commits API · fetch of https://fix.security (failed DNS, 2026-10-09)

---

## 8. Checkov

### Project facts
- https://github.com/bridgecrewio/checkov. 9,061 stars, Apache-2.0, Python [sourced: GitHub API].
- 3.3.26 on 2026-10-07, with several releases a week [sourced].
- Maintainer: Palo Alto Networks (Bridgecrew). Powers Prisma Cloud Application Security [sourced: README].
- Prisma Cloud is being rebranded to Cortex Cloud: check guide URLs now redirect to a generic Cortex docs landing page [sourced: https://github.com/bridgecrewio/checkov/issues/7631].

### Deployment
- CLI (pip/brew), Docker, GitHub Action, pre-commit, VS Code [inferred for IDE].
- Static, no cloud credentials.
- "Over 1000 built-in policies" [sourced: README].
- Tree count: 2,006 check files (`.py`/`.yaml`, excluding `__init__`). Terraform 1,183, ARM 174, CDK 172, CloudFormation 160, Kubernetes 127, Ansible 32, Dockerfile 28, OpenAPI 26, GitHub 26, Serverless 20, Bicep 14, plus CI pipeline checks [sourced: repo tree].

### Inventory & graph
- **In-memory graph of IaC resources** for "context-aware" composite policies [sourced: README].
- No cloud inventory.

### Attack paths
- None.

### Risk prioritization
- Severities come only from the Prisma platform API key [inferred].

### CIEM/identity
- IAM policy checks in IaC.

### DSPM
- None.

### Vulnerability & secrets
- SCA for packages and images (CVE).
- Secrets via regex, keyword and entropy.
- AWS credentials in EC2 user data, Lambda env and TF providers [sourced: README].

### Code-to-cloud / IaC
- Terraform (plus plan JSON), CloudFormation, SAM, K8s, Helm, Kustomize, Dockerfile, Serverless, Ansible, Bicep, ARM, OpenTofu.
- CI files: Argo Workflows, Azure Pipelines, Bitbucket, CircleCI, GitHub Actions, GitLab CI [sourced: README].
- Variable resolution to defaults [sourced: README].
- Yor tagging for code-to-cloud (base doc).

### Remediation
- Guide links (now broken, see above).
- Auto-fix PRs live in Prisma, not OSS [inferred].

### Compliance
- Policy index maps checks to benchmarks [inferred].
- Bridgecrew-era CIS mappings were platform-side [inferred].

### Real-time
- N/A.

### Integrations/outputs
- CLI, **CycloneDX, JSON, JUnit XML, CSV, SARIF, GitHub markdown** [sourced: README].

### UI/dashboard
- None in OSS.

### AI features
- None in OSS [inferred].

### Extensibility
- Custom policies in Python (attribute) or **YAML (attribute + composite/graph with `connection` blocks)** [sourced: README].
- Inline suppression `#checkov:skip=CKV_...` and global skips [sourced: README].

### Unique strengths
- Largest Terraform rule set.
- YAML graph policies.
- Terraform plan scanning.
- CI-pipeline config checks.

### Documented weaknesses
- "Unable to load module list index out of range" (11 👍) [sourced: https://github.com/bridgecrewio/checkov/issues/7314].
- Docs gap on `CKV2_GHA_1` [sourced: /issues/6977].
- Broken guide links after the Cortex rebrand [sourced: /issues/7631].
- Python version cap (>=3.9, <=3.12) [sourced: README].

### Sources
https://github.com/bridgecrewio/checkov · https://github.com/bridgecrewio/checkov/issues

---

## 9. KICS (Checkmarx)

### Project facts
- https://github.com/Checkmarx/kics. 2,717 stars, Apache-2.0. Go with Rego queries [sourced: GitHub API].
- v2.2.0 on 2026-09-17. Earlier: v2.1.21 (07-30), v2.1.20 (03-03), so about monthly to quarterly [sourced].
- Maintainer: Checkmarx. Commercial: Checkmarx One [inferred].

### Deployment
- CLI or Docker. Static.
- Tree count: 1,840 query `metadata.json` files. Terraform 763, CloudFormation 284, Ansible 226, OpenAPI 194, K8s 142, Dockerfile 48, ARM 43, Google Deployment Manager 35, Pulumi 21, Docker Compose 21, Crossplane 18, Serverless 10, plus others [sourced: repo tree].

### Inventory & graph
- None.

### Attack paths
- None.

### Risk prioritization
- Six severities: CRITICAL, HIGH, MEDIUM, LOW, INFO, TRACE [sourced: https://docs.kics.io/latest/results/].

### CIEM/identity
- IAM-in-IaC queries.

### DSPM
- None.

### Vulnerability & secrets
- Secrets queries [inferred].

### Code-to-cloud / IaC
- Core function, including Pulumi and Crossplane, which others lack [sourced: tree].

### Remediation
- `kics remediate` for simple single-line Terraform fixes (base doc).

### Compliance
- Query metadata has category and CWE [inferred]. No framework packs.

### Real-time
- N/A.

### Integrations/outputs
- **JSON, SARIF 2.1.0, GitLab SAST, JUnit, SonarQube, HTML, PDF, CycloneDX, ASFF, CSV, Code Climate** [sourced: https://docs.kics.io/latest/results/].

### UI/dashboard
- HTML and PDF reports.

### AI features
- None.

### Extensibility
- Rego queries with `metadata.json`. Pluggable parsers for new IaC types [sourced: README].

### Unique strengths
- Broadest output format list in the cluster.
- Pulumi and Crossplane coverage.

### Documented weaknesses
- **Supply-chain compromise 2026-04-22.** Docker tags `v2.1.20`, `v2.1.21`, `alpine`, `debian` and `latest` were replaced with a binary carrying "data collection and exfiltration capabilities", attributed to TeamPCP [sourced: https://socket.dev/blog/checkmarx-supply-chain-compromise]. Images briefly disappeared from Docker Hub [sourced: https://github.com/Checkmarx/kics/issues/8044].
- False positives: "KMS Key With Full Permissions" [sourced: /issues/6844]. No Kustomize support [sourced: /issues/6746].

### Sources
https://github.com/Checkmarx/kics · https://docs.kics.io/latest/results/ · https://socket.dev/blog/checkmarx-supply-chain-compromise

---

## 10. Trivy (incl. trivy-aws plugin)

### Project facts
- https://github.com/aquasecurity/trivy. **38,313 stars** (largest in cluster), Apache-2.0, Go [sourced: GitHub API].
- v0.75.0 on 2026-10-01. Earlier: v0.74.0 (08-14), v0.73.0 (08-03), v0.72.0 (06-30) [sourced].
- Maintainer: Aqua Security. Commercial: Aqua platform [sourced: README].

### Deployment
- CLI binary, Docker, server mode, GitHub Action, VS Code, K8s operator [sourced: README].
- Targets: container image, filesystem, remote git repo, VM image, Kubernetes.
- Scanners: SBOM, CVEs, IaC misconfig, secrets, licences [sourced: README].
- **Cloud (AWS) scanning lives in a separate plugin** (`trivy plugin install github.com/aquasecurity/trivy-aws`), last pushed 2026-04-20 [sourced: https://github.com/aquasecurity/trivy-aws].

### Inventory & graph
- None. SBOM is the inventory of packages.

### Attack paths
- None.

### Risk prioritization
- Severity, plus VEX support [inferred].

### CIEM/identity
- K8s RBAC assessment via `trivy k8s` [inferred].

### DSPM
- None.

### Vulnerability & secrets
- Best-in-class open-source vulnerability DB and secrets scanner [sourced: README].
- Top issue: "Trivy Java DB as part of server mode" (58 👍) [sourced: https://github.com/aquasecurity/trivy/issues/3560].

### Code-to-cloud / IaC
- Misconfiguration scanning of Terraform, CloudFormation, K8s, Helm, Dockerfile and others. Prowler uses it for its IaC provider [sourced: Prowler README].

### Remediation
- None beyond advisory text.

### Compliance
- `--compliance` specs for K8s (CIS, NSA, PSS) and AWS CIS [inferred].

### Real-time
- Via Trivy Operator (below).

### Integrations/outputs
- Table, **JSON (schema v2)**, **SARIF 2.1.0**, Go template (JUnit, **ASFF**, HTML templates), CycloneDX/SPDX SBOM, GitHub dependency snapshot.
- `trivy convert` turns a JSON report into other formats with filters [sourced: https://trivy.dev/latest/docs/configuration/reporting/].

### UI/dashboard
- None (Aqua is the commercial UI).

### AI features
- None in OSS [inferred].

### Extensibility
- Rego custom checks, plugin manager and modules [inferred].
- 2026-06 advisory: "Path Traversal in Trivy Plugin Manager Allows Arbitrary File Write" [sourced: GitHub advisories API].

### Unique strengths
- Ubiquity (38k stars).
- Single binary for vulnerabilities, misconfigurations, secrets, licences and SBOM.
- `convert` re-rendering from one JSON.

### Documented weaknesses
- **2026-03-19 supply-chain compromise.** Malicious v0.69.4 release. 76 of 77 `trivy-action` tags and all 7 `setup-trivy` tags were force-pushed to credential-stealers. Malicious Docker Hub v0.69.5 and v0.69.6 appeared on 2026-03-22 [sourced: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23].
- 2026-06 path traversal via a crafted vulnerability DB [sourced: advisories API].
- Cloud scanning was demoted to a plugin [sourced: trivy-aws].

### Sources
https://github.com/aquasecurity/trivy · https://trivy.dev/latest/docs/configuration/reporting/ · https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23 · https://github.com/aquasecurity/trivy-aws

---

## 11. Trivy Operator

### Project facts
- https://github.com/aquasecurity/trivy-operator. 1,961 stars, Apache-2.0, Go.
- v0.35.0 on 2026-10-05, about monthly. README Helm example pins chart 0.37.0 [sourced: GitHub API, README].
- Self-described "incubating; APIs and CRDs may change" [sourced: README].

### Deployment
- Helm in-cluster operator that runs scan jobs [sourced: README].

### Inventory & graph
- Results stored as **Kubernetes CRDs** (VulnerabilityReport, ConfigAuditReport, ExposedSecretReport, RbacAssessmentReport, InfraAssessmentReport, ClusterComplianceReport, SBOM) [sourced: README, CRD names inferred].

### Attack paths
- None.

### Risk prioritization
- Severity only.

### CIEM/identity
- RBAC assessment scans [sourced: README].

### DSPM
- None.

### Vulnerability & secrets
- Workload, control-plane and node vulnerability scans. Exposed-secret scans [sourced: README].

### Code-to-cloud / IaC
- None.

### Remediation
- None.

### Compliance
- NSA/CISA hardening v1.1, CIS K8s v1.23, PSS baseline and restricted [sourced: README].
- Outdated API detection [sourced: README].

### Real-time
- **Event-driven rescans on workload changes** [sourced: README].

### Integrations/outputs
- CRDs, Prometheus metrics, webhook "alternate report storage" [inferred].
- Issue: "Alternate Report Storage doesn't provide metrics" [sourced: https://github.com/aquasecurity/trivy-operator/issues/2610].

### UI/dashboard
- None. Use Lens, Headlamp or Grafana [inferred].

### AI features
- None.

### Extensibility
- Custom OPA policies [sourced: README].

### Unique strengths
- K8s-native result storage and change-triggered scanning.

### Documented weaknesses
- "Operator blocked by jobs with error: unexpected end of JSON input" (18 👍, 2025-11) [sourced: /issues/2806].
- Large VulnerabilityReports fail to create (etcd size) [sourced: /issues/757].
- Ignore file can't be stored externally [sourced: /issues/1223].

### Sources
https://github.com/aquasecurity/trivy-operator · its issues

---

## 12. ScoutSuite (NCC Group)

### Project facts
- https://github.com/nccgroup/ScoutSuite. 7,839 stars, **GPL-2.0**, Python.
- **Last release 5.14.0 on 2024-05-10**. Last commit to the default branch 2024-05-10. Repo push 2025-09-23 [sourced: GitHub API].
- 246 open issues. No commercial tier.

### Deployment
- CLI producing an **offline HTML report**. "Point-in-time... all usage may be performed offline" [sourced: README].
- Providers: AWS, Azure, GCP. Alpha: Alibaba, OCI, K8s, DigitalOcean [sourced: README].
- Tree count of finding rule JSONs: 578 total. AWS 147, GCP 119, Azure 81, Kubernetes 174, DigitalOcean 29, Aliyun 18, OCI 10 [sourced: repo tree].

### Inventory & graph
- Raw JSON config dump embedded in the report. No query language.

### Attack paths
- None.

### Risk prioritization
- danger/warning levels [inferred].

### CIEM/identity
- IAM findings only.

### DSPM
- None.

### Vulnerability & secrets
- None.

### Code-to-cloud / IaC
- None.

### Remediation
- None.

### Compliance
- Rulesets (custom JSON) [inferred]. No formal frameworks.

### Real-time
- None.

### Integrations/outputs
- HTML report and JSON results. Partial SQLite [inferred].

### UI/dashboard
- Single-page HTML report: a dashboard listing services with finding counts, colour-coded by severity, drill-down to resources and raw config [sourced: README description; visual details inferred].

### AI features
- None.

### Extensibility
- JSON rule definitions with conditions [inferred].

### Unique strengths
- Auditor-friendly offline report that includes all collected config.

### Documented weaknesses
- Dormant.
- "support for AWS Organizations" open since 2019 [sourced: https://github.com/nccgroup/ScoutSuite/issues/249].
- Stuck on Secrets Manager [sourced: /issues/1427].
- No container support [sourced: /issues/1491].

### Sources
https://github.com/nccgroup/ScoutSuite

---

## 13. Kubescape (ARMO, CNCF)

### Project facts
- https://github.com/kubescape/kubescape. 11,787 stars, Apache-2.0, Go. **CNCF Incubating**, created by ARMO [sourced: README].
- v4.0.15 on 2026-09-29, about every 2–3 weeks [sourced].
- Commercial: ARMO Platform [inferred].

### Deployment
- CLI (`kubescape scan`), or the in-cluster operator via Helm [sourced: README].
- K8s plus YAML and Helm, plus images.
- regolibrary has **290 controls** and frameworks: allcontrols, armobest, devopsbest, mitre, nsa, security, soc2, ism, cis-v1.10/1.12, cis-aks 1.2/1.8, cis-eks 1.7/1.8, cis-gke 1.9, workloadscan, clusterscan, **agent-runtime-hardening** [sourced: https://github.com/kubescape/regolibrary tree].

### Inventory & graph
- K8s object model. No general graph [inferred].

### Attack paths
- ARMO platform has K8s "attack chains" [inferred]. Not documented in the OSS README.

### Risk prioritization
- Compliance scores per framework [sourced: README].

### CIEM/identity
- "Access control risks" [sourced: README].

### DSPM
- None.

### Vulnerability & secrets
- Image scans via **Grype** [sourced: README].

### Code-to-cloud / IaC
- Manifests and Helm.

### Remediation
- **`kubescape fix results.json`** rewrites manifests [sourced: README].
- **Copacetic image patching** [sourced: README].
- **VAP**: `kubescape vap deploy-library` (CEL Validating Admission Policies) [sourced: README].

### Compliance
- Frameworks above.

### Real-time
- **eBPF runtime monitoring via Inspektor Gadget** in operator mode [sourced: README].

### Integrations/outputs
- JSON, JUnit, **SARIF**, HTML, **PDF**, CSV, plus `--encrypt` reports. Offline artefacts via `kubescape download` [sourced: README].

### UI/dashboard
- OSS has no web UI (ARMO Platform does) [inferred]. Headlamp plugin work is ongoing [sourced: https://github.com/kubescape/kubescape/issues/1982].

### AI features
- **`kubescape mcpserver`** with tools such as `list_vulnerability_manifests` and `get_configuration_security_scan_manifest` [sourced: README].

### Extensibility
- Rego controls in regolibrary. SecurityException CRD in progress [sourced: /issues/1982].

### Unique strengths
- Spans posture, admission (VAP), eBPF runtime, image patching and MCP in one CNCF project.

### Documented weaknesses
- Bugs such as "SecurityException apiGroup is silently unmatchable" [sourced: /issues/3655].
- Cloud-API coverage gaps ("Add Azure support for DescribeRepositories") [sourced: /issues/3901].

### Sources
https://github.com/kubescape/kubescape · https://github.com/kubescape/regolibrary

---

## 14. CloudSploit (Aqua)

### Project facts
- https://github.com/aquasecurity/cloudsploit. 3,777 stars, **GPL-3.0**, JavaScript (Node).
- Last tagged release v3.10.0 on 2024-11-15. Commits continue: 2026-09-22 "azure-plugins-draft-2", "sync_22_09" [sourced: GitHub API].
- Commercial: "Hosted at Aqua Wave" [sourced: README].

### Deployment
- Node CLI or Docker. Read-only credentials. AWS, Azure, GCP, OCI. GitHub is in the tree [sourced: README, tree].
- Plugin `.js` files excluding specs: AWS 618, Azure 527, Google 273, Oracle 99, Alibaba 71, GitHub 10 (tree count) [sourced: repo tree].

### Inventory & graph
- Two phases: **collection** (raw API JSON, savable with `--collection=file.json`) then **plugins** evaluate it [sourced: README].

### Attack paths
- None.

### Risk prioritization
- Status levels [inferred].

### CIEM/identity
- IAM plugins.

### DSPM
- None.

### Vulnerability & secrets
- None.

### Code-to-cloud / IaC
- None.

### Remediation
- **`--remediate <plugins>`** runs remediation for named plugins (developer guide) [sourced: README].

### Compliance
- `--compliance=hipaa|pci|cis` [sourced: README].
- Issue: CIS missing in Azure and GCP [sourced: https://github.com/aquasecurity/cloudsploit/issues/812].

### Real-time
- None.

### Integrations/outputs
- Console, CSV, JSON, JUnit XML, collection JSON. `--ignore-ok`, `--exit-code`, `--suppress` [sourced: README].

### UI/dashboard
- None in OSS.

### AI features
- None.

### Extensibility
- JS plugins with `run(cache, settings, callback)` [inferred].

### Unique strengths
- Separate collect and evaluate phases with a saved collection, so you can re-run offline.

### Documented weaknesses
- No releases in about 2 years. GPL-3.0.
- Old crashes such as "newData.forEach is not a function" [sourced: /issues/762].

### Sources
https://github.com/aquasecurity/cloudsploit

---

## 15. Magpie (Open Raven)

### Project facts
- https://github.com/openraven/magpie. 205 stars, Apache-2.0, Java. No tagged releases. **Last push 2024-08-29** [sourced: GitHub API].
- Open Raven (DSPM vendor) [sourced: README].

### Deployment
- Maven-built CLI. Layers separated by FIFOs: Java queues by default or **Kafka** for distributed scale. AWS, GCP, Azure [sourced: README].

### Inventory & graph
- Plugins emit JSON to PostgreSQL ("Saving data to PostgreSQL") [sourced: README].

### Attack paths
- None.

### Risk prioritization
- None.

### CIEM/identity
- None documented.

### DSPM
- None in OSS (commercial Open Raven has it) [inferred].

### Vulnerability & secrets
- None.

### Code-to-cloud / IaC
- None.

### Remediation
- None.

### Compliance
- None in OSS.

### Real-time
- None.

### Integrations/outputs
- Postgres and Kafka.

### UI/dashboard
- None.

### AI features
- None.

### Extensibility
- Plugin layers (origin, intermediate, terminal) [sourced: README "relies on plugins"].

### Unique strengths
- Kafka-layered discovery pipeline design.

### Documented weaknesses
- Dormant. Never reached CSPM features.

### Sources
https://github.com/openraven/magpie

---

## 16. Matano

### Project facts
- https://github.com/matanolabs/matano. 1,699 stars, Apache-2.0, Rust.
- Only a `nightly` tag (2022-08-31). **Last push 2025-01-08** [sourced: GitHub API].
- Commercial "managed Cloud SIEM" at matanosecurity.com [sourced: README].

### Deployment
- Serverless on AWS (your account) [sourced: README].

### Inventory & graph
- Security data lake on **Apache Iceberg** with **ECS** schema. Queried via Athena (default), Snowflake, Spark or Trino [sourced: README].

### Attack paths
- None.

### Risk prioritization
- None.

### CIEM/identity
- Identity logs (Okta, Duo).

### DSPM
- None.

### Vulnerability & secrets
- Ingests Amazon Inspector and Snyk [sourced: README].

### Code-to-cloud / IaC
- None.

### Remediation
- None.

### Compliance
- None.

### Real-time
- **Real-time Python detections-as-code with Sigma import**. VRL transforms at ingest [sourced: README].

### Integrations/outputs
- 50+ log sources (CloudTrail, VPC Flow, Config, Route53, WAF, Okta, GitHub, O365, Zeek, Suricata and more). Alerts to SNS and Slack [sourced: README].

### UI/dashboard
- None in OSS.

### AI features
- None.

### Extensibility
- Python detections, VRL, custom log sources.

### Unique strengths
- Open lakehouse format (Iceberg + ECS) for security telemetry.

### Documented weaknesses
- Dormant. AWS-only.

### Sources
https://github.com/matanolabs/matano

---

## 17. ThreatMapper (Deepfence)

### Project facts
- https://github.com/deepfence/ThreatMapper. 5,324 stars, Apache-2.0, TypeScript/Go.
- v2.5.8 on 2026-03-07. Before that, v2.5.7 on 2025-04-11 [sourced: GitHub API].
- The v2.5.8 notes say "Remove License requirement for Threat Intelligence feeds" [sourced: https://github.com/deepfence/ThreatMapper/releases].
- README: "This project is maintained by https://threatmapper.org" [sourced: README]. Deepfence's corporate status was not verified [inferred: reduced vendor backing].
- Last commit 2026-05-13 (a typo fix) [sourced].

### Deployment
- Management Console (Docker or K8s).
- **Agentless Cloud Scanner tasks deployed via Terraform** for posture.
- **Agent-based sensors** for K8s, Docker, ECS, Fargate and VMs. Privileged containers with host PID and net [sourced: README].

### Inventory & graph
- Topology graph (Neo4j-based in v2) [inferred].

### Attack paths
- **ThreatGraph**: ranks threats by "risk-of-exploit". "Attack Path Enumeration" is in the tagline [sourced: README].

### Risk prioritization
- Exploitability ranking that combines vulnerabilities, secrets, misconfigurations and network exposure [sourced: README].

### CIEM/identity
- Not documented.

### DSPM
- None.

### Vulnerability & secrets
- Vulnerability, secret and malware scanning of running workloads [sourced: README; malware inferred].

### Code-to-cloud / IaC
- None.

### Remediation
- None.

### Compliance
- Cloud and K8s compliance benchmarks via Cloud Scanner [sourced: README].

### Real-time
- Runtime telemetry via sensors.

### Integrations/outputs
- Slack, Jira, S3, Splunk and others [inferred].

### UI/dashboard
- Console with ThreatGraph and topology views. Live demo sandbox [sourced: README].

### AI features
- None documented.

### Extensibility
- Limited [inferred].

### Unique strengths
- Combines runtime topology with exposure ranking.

### Documented weaknesses
- Slowing cadence. Needs privileged agents.
- Open requests for AD auth and Windows agent [sourced: https://github.com/deepfence/ThreatMapper/issues/569, /issues/1442].

### Sources
https://github.com/deepfence/ThreatMapper

---

## 18. Cloudsplaining (Salesforce)

### Project facts
- https://github.com/salesforce/cloudsplaining. 2,250 stars, BSD-3-Clause, Python with a JS report.
- 0.9.1 on 2026-06-14. Earlier: 0.8.2 (2025-10), 0.8.1 (2025-09), so a few per year [sourced: GitHub API].

### Deployment
- CLI over `aws iam get-account-authorization-details` output or a single policy file. Multi-account supported [sourced: README].

### Inventory & graph
- None.

### Attack paths
- Privilege escalation detection "based on Pathfinding.cloud" [sourced: README].

### Risk prioritization
- **Risk-prioritised HTML report**: Data Exfiltration, Infrastructure Modification, Resource Exposure, Privilege Escalation, Credentials Exposure.
- Flags roles assumable by compute services [sourced: README].

### CIEM/identity
- Core: finds actions without resource constraints (least-privilege violations) [sourced: README].

### DSPM
- None.

### Vulnerability & secrets
- None.

### Code-to-cloud / IaC
- None.

### Remediation
- Guidance only.

### Compliance
- None.

### Real-time
- None.

### Integrations/outputs
- HTML, JSON, CSV [inferred].

### UI/dashboard
- Example report: a single-page app with tabs for customer-managed policies, inline policies, AWS-managed policies and principals, each with risk columns [sourced: README link https://opensource.salesforce.com/cloudsplaining/; layout inferred].

### AI features
- None.

### Extensibility
- Exclusions file for false positives [sourced: README].

### Unique strengths
- The clearest IAM risk taxonomy (5 categories) and readable report.

### Documented weaknesses
- "False negatives on multi policy privesc paths" [sourced: https://github.com/salesforce/cloudsplaining/issues/188].
- Principals page lags [sourced: /issues/187].

### Sources
https://github.com/salesforce/cloudsplaining

---

## 19. PMapper (Principal Mapper) and Parliament

### Project facts
- **PMapper**: https://github.com/nccgroup/PMapper. 1,583 stars, AGPL-3.0, Python. Last release v1.1.5 on 2022-01-13. Last push 2024-08-02 [sourced: GitHub API].
- **Parliament**: https://github.com/duo-labs/parliament. 1,127 stars, BSD-3-Clause. Release 1.64 on 2025-03-18 [sourced].

### Deployment
- Both are pip CLIs and libraries.

### Inventory & graph
- **PMapper models IAM users and roles as a directed graph**, account- or org-wide. Graphviz output [sourced: README].

### Attack paths
- PMapper finds privilege escalation and **alternate paths**. For example, a user can't read S3 but can launch EC2 with a role that can [sourced: README].

### Risk prioritization
- None.

### CIEM/identity
- PMapper uses a **local simulation of AWS authorisation**: `query "can X do Y on Z"` including transitive access [sourced: README].
- Parliament **lints IAM policy JSON**: malformed JSON, bad prefixes and actions, resource/condition mismatches, type mismatches, bad patterns. Example: `MEDIUM - No resources match for the given action` [sourced: https://github.com/duo-labs/parliament].

### DSPM
- None.

### Vulnerability & secrets
- None.

### Code-to-cloud / IaC
- Parliament can lint policies in IaC pipelines [inferred].

### Remediation
- None.

### Compliance
- None.

### Real-time
- None.

### Integrations/outputs
- PMapper: graph files, DOT/SVG. Parliament: text and JSON [inferred].

### UI/dashboard
- None.

### AI features
- None.

### Extensibility
- Parliament custom auditors (Python) [inferred].

### Unique strengths
- PMapper's authorisation simulator plus transitive reachability.
- Parliament's action/resource-format validation against IAM metadata.

### Documented weaknesses
- PMapper breaks on Python 3.10 [sourced: https://github.com/nccgroup/PMapper/issues/140, /issues/130]. Hangs generating Lambda edges [sourced: /issues/115]. Dormant.

### Sources
https://github.com/nccgroup/PMapper · https://github.com/duo-labs/parliament

---

## 20. kube-bench (Aqua)

### Project facts
- https://github.com/aquasecurity/kube-bench. 8,221 stars, Apache-2.0, Go.
- v0.16.0 on 2026-08-05, about monthly [sourced: GitHub API].

### Deployment
- K8s Job or pod with host PID [sourced: README].
- Config folders for CIS 1.5–1.12 and 2.0, AKS, EKS (incl. **EKS STIG v1r6**), GKE, ACK, k3s, RKE/RKE2, OpenShift (rh-*), TKGI, microk8s (tree) [sourced: repo tree `cfg/`].

### Inventory & graph
- None.

### Attack paths
- None.

### Risk prioritization
- PASS/FAIL/WARN/INFO.

### CIEM/identity
- None.

### DSPM
- None.

### Vulnerability & secrets
- None.

### Code-to-cloud / IaC
- None.

### Remediation
- Remediation text per check.

### Compliance
- CIS Kubernetes and distribution variants (above).

### Real-time
- None.

### Integrations/outputs
- `--json`, `--junit`, `--outputfile`, **`--pgsql`** (save to PostgreSQL), **`--asff`** (send to AWS Security Hub) [sourced: https://github.com/aquasecurity/kube-bench/blob/main/docs/flags-and-commands.md].

### UI/dashboard
- None.

### AI features
- None.

### Extensibility
- YAML test definitions [sourced: README].

### Unique strengths
- The node-level CIS K8s reference implementation, also reused by Trivy [sourced: README].

### Documented weaknesses
- Needs privileged host access. Not agentless [sourced: README].

### Sources
https://github.com/aquasecurity/kube-bench

---

## 21. OpenCSPM (Darkbit)

### Project facts
- https://github.com/OpenCSPM/opencspm. 347 stars, MIT, Ruby. **Archived**. Last release 0.1.23 on 2021-05-28 [sourced: GitHub API].

### Deployment
- Self-hosted. GCP Cloud Asset Inventory plus the K8s API [sourced: README].

### Inventory & graph
- Graph database (RedisGraph) [inferred].

### Attack paths
- None (graph queries only).

### Risk prioritization
- "Campaigns" to track remediation of control groups [sourced: README].

### CIEM/identity
- GCP IAM in graph.

### DSPM
- None.

### Vulnerability & secrets
- None.

### Code-to-cloud / IaC
- None.

### Remediation
- Tracking only.

### Compliance
- "Control packs" [sourced: README].

### Real-time
- None.

### Integrations/outputs
- Notifications [sourced: README].

### UI/dashboard
- Web UI [sourced: README].

### AI features
- None.

### Extensibility
- Control packs.

### Unique strengths
- The **campaign** concept: group findings into a remediation effort and track risk reduction over time.

### Documented weaknesses
- Archived. GCP-only.

### Sources
https://github.com/OpenCSPM/opencspm

---

## 22. cnspec (Mondoo)

### Project facts
- https://github.com/mondoohq/cnspec. 440 stars, Go.
- v14.5.0 on 2026-10-09. v14.0.0 shipped 2026-09-23, with several releases a week [sourced: GitHub API].
- **Licence: Business Source License 1.1.** It allows production use except "offering the Licensed Work to third parties as part of... an offering that is competitive with any of Mondoo's products". It converts to MPL 2.0 four years after each version [sourced: https://github.com/mondoohq/cnspec/blob/main/LICENSE].
- Companion cnquery (412 stars) shows NOASSERTION too [sourced: GitHub API].
- Commercial: Mondoo Platform.

### Deployment
- Single binary: `cnspec scan local|aws|k8s|docker image|github repo|ssh|winrm|vsphere`, and more [sourced: README].
- Covers cloud, K8s, containers, registries, servers, endpoints and SaaS [sourced: README].

### Inventory & graph
- **MQL (Mondoo Query Language)** over a resource model, for example `ports.listening.none( port == 23 )`.
- **Interactive shell with autocomplete and `help <resource>`** [sourced: README].

### Attack paths
- None in OSS [inferred].

### Risk prioritization
- Platform-side [inferred].

### CIEM/identity
- Resource fields only.

### DSPM
- None.

### Vulnerability & secrets
- `cnspec vuln ...`, but "**Vulnerability scanning requires the client to be logged into Mondoo Platform**" [sourced: README].

### Code-to-cloud / IaC
- Terraform and K8s manifest scanning [inferred / partially sourced via `k8s manifest.yaml`].

### Remediation
- Policy remediation text [inferred].

### Compliance
- Default policies in the `content/` dir. Mondoo publishes CIS-based packs [inferred].

### Real-time
- None in OSS.

### Integrations/outputs
- JSON, JUnit and others [inferred].

### UI/dashboard
- Platform only.

### AI features
- Not verified.

### Extensibility
- Policy-as-code YAML bundles with MQL checks. Providers are plugins (cnquery providers) [inferred].

### Unique strengths
- One query language across OS, cloud and SaaS. A great exploratory shell.

### Documented weaknesses
- BUSL licence (non-compete).
- Vulnerability scanning tied to SaaS login [sourced].

### Sources
https://github.com/mondoohq/cnspec · https://github.com/mondoohq/cnspec/blob/main/LICENSE

---

## Best-in-class per capability (this cluster)

| Capability | Project | What makes it best | Source |
|---|---|---|---|
| Provider breadth (CSPM) | Prowler | 23 providers: AWS 662 checks / 50 frameworks, plus M365, Okta, Workspace, Cloudflare, Vercel, MongoDB Atlas, OpenStack | https://github.com/prowler-cloud/prowler |
| Security graph / identity breadth | Cartography | 76 intel modules spanning cloud, IdP, EDR, SaaS and AI providers. Federation edges (Okta/Entra to AWS roles). EPSS/KEV CVE enrichment | https://github.com/cartography-cncf/cartography |
| Attack-path query library | Prowler Attack Paths | About 100 AWS openCypher queries with stable ids, about 70 of them pathfinding.cloud privesc techniques. Custom read-only Cypher with a 10k-char cap and scan scoping | https://github.com/prowler-cloud/prowler/blob/master/api/src/backend/api/attack_paths/queries/aws.py |
| IAM authorisation simulation | PMapper | Local AWS authZ simulation with transitive principal reachability | https://github.com/nccgroup/PMapper |
| IAM risk taxonomy / report | Cloudsplaining | 5 risk categories, compute-assumable roles, exclusions file | https://github.com/salesforce/cloudsplaining |
| IAM policy linting | Parliament | Validates action, resource format and conditions against IAM metadata | https://github.com/duo-labs/parliament |
| SQL over cloud APIs | Steampipe | About 2,000+ tables (AWS alone 590). Ships as CLI, Postgres FDW, SQLite extension or export binary | https://github.com/turbot/steampipe |
| Cross-cloud normalised model | Fix Inventory | 40+ base kinds so one policy runs on every cloud. Relative-time search | https://github.com/someengineering/fixinventory |
| Change history | Fix Inventory | Hourly snapshots with per-resource timeline and diff | https://github.com/someengineering/fixinventory |
| ELT / warehouse export | CloudQuery | Arrow transport, about 20 destinations including Neo4j and Gremlin. Multi-language SDK | https://github.com/cloudquery/cloudquery |
| Real-time enforcement | Cloud Custodian | Auto-provisioned serverless policies on CloudTrail, Event Grid and Audit Log. Dry-run. Rich action set | https://github.com/cloud-custodian/cloud-custodian |
| Remediation workflows with approval | Flowpipe | HCL pipelines with `input` (human approval) steps. Detect-and-correct mods for AWS/Azure compliance | https://github.com/turbot/flowpipe |
| Compliance content volume | Powerpipe mods | "5,000+ open-source controls". `--where` SQL filtering of controls | https://github.com/turbot/powerpipe |
| Cross-provider frameworks | Prowler | "Universal" FedRAMP 20x KSI (46) and Class C (158) mapped across AWS/Azure/GCP/K8s/M365. Catalogue integrity test | https://github.com/prowler-cloud/prowler/releases/tag/5.43.0 |
| Terraform rule depth | Checkov | 1,183 Terraform check files. YAML graph (composite) policies. TF plan scanning | https://github.com/bridgecrewio/checkov |
| IaC format breadth + outputs | KICS | Pulumi, Crossplane, OpenAPI, Ansible. 11 output formats (GitLab SAST, SonarQube, Code Climate, ASFF and more) | https://docs.kics.io/latest/results/ |
| Vulnerabilities / SBOM / secrets | Trivy | One binary for CVE, misconfig, secrets, licence and SBOM. `trivy convert` re-renders saved JSON | https://trivy.dev/latest/docs/configuration/reporting/ |
| K8s posture to runtime | Kubescape | 290 controls, VAP admission, eBPF runtime, `fix` and Copacetic patching, MCP server | https://github.com/kubescape/kubescape |
| K8s-native result storage | Trivy Operator | Findings as CRDs, rescans on workload change | https://github.com/aquasecurity/trivy-operator |
| Node CIS K8s | kube-bench | Widest distro coverage (EKS STIG, RKE2, k3s, OpenShift). `--asff`, `--pgsql` | https://github.com/aquasecurity/kube-bench |
| Offline auditor report | ScoutSuite | Self-contained HTML with all collected config | https://github.com/nccgroup/ScoutSuite |
| AI copilot | Prowler Lighthouse | BYO LLM (OpenAI, Bedrock, OpenAI-compatible or Ollama). MCP-backed tools auto-discovered. Strictly read-only. Can trigger partial re-scans to verify fixes | https://docs.prowler.com/getting-started/products/prowler-lighthouse-ai |
| Exploratory query shell | cnspec | MQL interactive shell with autocomplete and `help <resource>` | https://github.com/mondoohq/cnspec |
| Security log lake | Matano | Iceberg + ECS, Sigma import, Python detections (dormant) | https://github.com/matanolabs/matano |

## Features nimbus should steal (ranked)

1. **Read-only Cypher/SQL "custom path query" box scoped to a snapshot** (Prowler Attack Paths). Users paste a query, nimbus checks it is read-only, applies a size cap (10k chars) and auto-scopes it to the selected scan. Results show as a graph with PNG export and click-to-focus on a finding. *Why:* power users expect to ask their own graph questions, and this is the scariest feature to get wrong safely.
2. **Path queries as versioned, attributed content with stable ids** (Prowler `aws-ec2-privesc-passrole-iam` attributing pathfinding.cloud). Every path type nimbus ships has an id, name, description, attribution link and parameters, and shows in a browsable catalogue. *Why:* explainable, citeable findings that community PRs can extend.
3. **Rule = Facts with a count-query denominator and stable `identity_fields`** (Cartography rules). Each control returns failing assets plus a total-assets count, so the UI shows "7 of 212 buckets (3.3%)". Finding identity stays stable across syncs, so first-seen, resolved and reopened states are reliable. *Why:* accurate compliance ratios and trend lines.
4. **Partial re-scan to verify a fix** (Prowler 5.44 `resource_uids`, up to 10). A "Re-check now" button on a finding re-collects only that resource and its edges, then closes the finding or the path within seconds. The copilot can call the same API. *Why:* closes the remediation loop without a full scan. Defender takes up to 24h by comparison.
5. **Cross-cloud base kinds** (Fix Inventory). Write `is(database) and public=true` once and match RDS, Cloud SQL and Azure SQL. nimbus SQL exposes unified views (`nimbus.database`, `nimbus.bucket`, `nimbus.identity`) beside native tables. *Why:* one policy per intent, not per cloud.
6. **Permission-weighted identity edges** (Fix Inventory `-iam[0:]{permissions[*].level==write}->` and PMapper's simulator). The "who can write to s3://pii?" view answers with direct and transitive principals, each with the policy statement that grants it. *Why:* core CIEM question. Most tools answer only the direct case.
7. **IAM risk taxonomy badges** (Cloudsplaining). Every over-permissive policy gets tagged Data Exfiltration, Infra Modification, Resource Exposure, Privilege Escalation or Credentials Exposure, and compute-assumable roles are highlighted. *Why:* turns an IAM wall of text into triage buckets.
8. **IAM policy lint in PRs** (Parliament). nimbus IaC scanning flags malformed actions, impossible resource ARNs (`s3:GetObject` without `/*`) and condition mismatches, inline. *Why:* catches broken least-privilege before deploy at low cost.
9. **Hourly snapshot timeline and per-resource diff** (Fix Inventory). A resource page shows a configuration timeline with a JSON diff, linked to the finding open and close events. *Why:* "what changed?" is the first question in triage and audit.
10. **Event-driven re-evaluation with dry-run actions** (Cloud Custodian modes). An optional CloudTrail, Event Grid or Audit Log subscriber re-evaluates touched resources within a minute. Any action runs `--dry-run` first and shows what would change. *Why:* real-time without agents. Dry-run builds trust.
11. **Detect → approve → correct pipelines** (Flowpipe `input` step). A remediation becomes a workflow that posts to Slack or Teams with Approve/Skip buttons, then applies a fix or opens an IaC PR. *Why:* safe auto-remediation that security teams will actually turn on.
12. **`--where` SQL filter over control metadata** (Powerpipe). `nimbus benchmark run cis_aws --where "severity in ('high','critical') and tags->>'service'='s3'"`. *Why:* precise CI gating and scoped audits.
13. **"Universal" frameworks mapped across providers plus a catalogue integrity test** (Prowler FedRAMP 20x). One framework view spans all clouds with a per-provider breakdown. CI fails on duplicate requirement ids or dangling check references. *Why:* multi-cloud audits, and framework rot is a real bug class.
14. **One JSON, many renderings via `convert`** (Trivy). `nimbus convert results.json --format sarif|ocsf|asff|csv|html|junit --severity high`. *Why:* re-render without rescanning, and simple CI plumbing.
15. **Broad CI output formats** (KICS). Emit GitLab SAST, SonarQube, Code Climate and JUnit besides SARIF. *Why:* GitLab, Sonar and Jenkins shops get native annotations for free.
16. **Saved collection for offline re-evaluation** (CloudSploit `--collection`, ScoutSuite offline report). `nimbus collect -o snap.tar.zst`, then `nimbus evaluate snap.tar.zst` with new rules, air-gapped. *Why:* auditors, rule developers and air-gapped customers. This fits nimbus's DuckDB snapshot design.
17. **Self-contained offline HTML report with raw config drill-down** (ScoutSuite). The report embeds escaped config JSON per resource. *Why:* the consultant and audit deliverable. The base doc's XSS lesson applies.
18. **MCP server as the copilot's only data path, with auto-discovered tools** (Prowler MCP, Steampipe MCP, Kubescape `mcpserver`). Ship `nimbus mcp` exposing query, findings, paths, compliance and re-check tools. The in-app copilot uses the same server. *Why:* parity between the built-in copilot and Claude Desktop or other agents, plus a read-only guarantee by construction.
19. **BYO-LLM including local models** (Lighthouse: OpenAI, Bedrock, OpenAI-compatible or Ollama, filtered to tool-calling models). *Why:* regulated and air-gapped users.
20. **Interactive query shell with autocomplete and `help <table>`** (cnspec shell). `nimbus shell` gives a DuckDB REPL with table and column completion and inline docs. *Why:* a faster learning curve than reading schema docs.
21. **EPSS + KEV enrichment on CVE nodes feeding path scores** (Cartography CVE metadata). *Why:* KEV/EPSS-weighted toxic combinations beat raw CVSS. Cartography has the data but no scoring, so nimbus can add the scoring.
22. **Remediation campaigns** (OpenCSPM). Group findings into a named campaign with an owner, target date and burndown chart of risk reduced. *Why:* how security teams actually run fix-work. No live open-source tool has it.
23. **Admission-time guardrails from the same rules** (Kubescape `vap deploy-library`). Export nimbus K8s controls as CEL ValidatingAdmissionPolicies. *Why:* prevent as well as detect, from one rule source.
24. **Cosign-signed images and SLSA provenance, with digest-pinned Actions in docs** (c7n-left signed Wolfi images; lesson of the Trivy and KICS 2026 compromises). *Why:* security buyers now check this first, and nimbus would hold cloud read credentials.
25. **Graph sink choice: embedded by default, Neptune or Neo4j optional** (Prowler sink abstraction; Cartography's top Neptune issue). *Why:* enterprises on AWS ask for managed Neptune. Keep embedded for laptop use.

## Interop targets

| Direction | Format / API | Why it matters | Reference |
|---|---|---|---|
| Write and read | **OCSF Detection Finding JSON** (Prowler's default `json-ocsf`) | Prowler's lingua franca. Security Lake, SIEMs and Prowler App "Import Findings" consume it. nimbus findings should validate against the same OCSF class so they can be imported into Prowler and vice versa | https://docs.prowler.com/user-guide/cli/tutorials/reporting |
| Read | **Prowler CSV/OCSF output and `output/compliance/*.csv`** | Migration path: import a user's Prowler history and map Prowler check ids to nimbus control ids | Prowler reporting docs; base doc §8 |
| Read | **Prowler compliance framework JSON** (`prowler/compliance/<provider>/*.json`, 105 files) | Reuse requirement-to-check mappings (Apache-2.0) as seed content, crediting Prowler | https://github.com/prowler-cloud/prowler/tree/master/prowler/compliance |
| Write | **ASFF** | Security Hub ingestion. Prowler, Powerpipe, KICS, Trivy (template) and kube-bench all emit it | Powerpipe and KICS docs above |
| Write | **SARIF 2.1.0** | GitHub code scanning for IaC findings and path-diffs (Checkov, KICS, Trivy, Kubescape, Prowler IaC) | https://trivy.dev/latest/docs/configuration/reporting/ |
| Write | GitLab SAST, JUnit, SonarQube, Code Climate | CI-native annotations beyond GitHub (KICS list) | https://docs.kics.io/latest/results/ |
| Read | **Checkov JSON** (`results.failed_checks[]` with `check_id`, `file_path`, `file_line_range`, `resource`) | Ingest existing IaC scan results into the code-to-cloud graph rather than re-scan | https://github.com/bridgecrewio/checkov |
| Read | **KICS JSON** (`queries[].files[]` with `line`, `severity`) | Same purpose. Also input for `kics remediate`-style patches | https://docs.kics.io/latest/results/ |
| Read | **Trivy JSON (SchemaVersion 2)** and **CycloneDX/SPDX SBOM** | Attach CVEs and packages to image and workload nodes. Trivy is the most common vulnerability source in this ecosystem | https://trivy.dev/latest/docs/configuration/reporting/ |
| Read | **Trivy Operator CRDs** (VulnerabilityReport, ConfigAuditReport, ExposedSecretReport, RbacAssessmentReport) | Pull in-cluster vulnerability data agentlessly via the K8s API | https://github.com/aquasecurity/trivy-operator |
| Read | **Kubescape JSON results** and kube-bench `--json` | K8s posture enrichment | https://github.com/kubescape/kubescape · https://github.com/aquasecurity/kube-bench |
| Read and write | **Cartography Neo4j schema** (labels such as `AWSAccount`, `AWSEC2Instance`, rel `RESOURCE`, property `exposed_internet`) | (a) Import an existing Cartography graph so nimbus runs on day one. (b) Export nimbus's graph in Cartography-compatible labels so Prowler Attack Paths queries and Cartography rules run against it | https://docs.cartography.dev/usage/schema.html |
| Read | **Prowler Attack Paths query definitions** (`id`, `name`, `description`, `attribution`, `provider`, `cypher`, `parameters`) | Port the about-100 AWS query library (Apache-2.0) to nimbus's path engine. Keep ids for cross-tool comparability | https://github.com/prowler-cloud/prowler/blob/master/api/src/backend/api/attack_paths/queries/aws.py |
| Read | **pathfinding.cloud** technique catalogue | Shared source of truth behind Prowler and Cloudsplaining privesc detection | referenced in Prowler query attribution and Cloudsplaining README |
| Compatible | **Steampipe table naming** (`aws_s3_bucket`, …) and Postgres wire protocol | Optional compatibility views so Powerpipe mods and users' saved Steampipe SQL run against nimbus snapshots (base doc §4 already commits to this). Plugin gRPC protocol is a stretch target | https://github.com/turbot/steampipe |
| Write | **Powerpipe control result shape** (`resource`, `status` ok/alarm/info/skip/error, `reason`, dimensions) and `nunit3` | Lets nimbus controls feed Powerpipe dashboards. The status vocabulary is a good internal standard | https://powerpipe.io/docs/reference/cli/benchmark |
| Read | **Cloud Custodian policy YAML** (`resource`, `filters`, `actions`, `mode`) | Import users' existing guardrail policies as nimbus detections (filters) and suggested remediations (actions). c7n-left Terraform policies too | https://github.com/cloud-custodian/cloud-custodian |
| Write | **CloudQuery destination-style export** (Arrow → Postgres, Snowflake, BigQuery, S3/Parquet) | Warehouse users expect nimbus snapshots to land beside CloudQuery tables. Parquet/Iceberg export covers most | https://github.com/cloudquery/cloudquery |
| Write | **Iceberg + ECS/OCSF** for event data | Matano-style lake compatibility for real-time events (Athena, Trino, Snowflake) | https://github.com/matanolabs/matano |
| Expose | **MCP server** (tool parity with Prowler MCP, Steampipe MCP, Kubescape MCP) | Agents already speak MCP to these tools, so nimbus must too | https://steampipe.io/blog/steampipe-mcp · Kubescape README |
| Read | `aws iam get-account-authorization-details` JSON (Cloudsplaining and PMapper input) | Offline IAM analysis from a single file, and fixture compatibility with those tools | https://github.com/salesforce/cloudsplaining |
| Write | **CEL ValidatingAdmissionPolicy** manifests | Push K8s controls to admission, as Kubescape VAP does | https://github.com/kubescape/kubescape |
