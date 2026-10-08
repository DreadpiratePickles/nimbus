# Competitor Research: CSPM / CNAPP Feature Bars for nimbus

_Research date: 2026-10-08. Scope: 10 feature areas. Each area covers (a) what competitors do, (b) the bar to clear, (c) nimbus design decisions, (d) open-source prior art. Where a vendor does not publish a detail (for example Wiz's severity formula), this file says so instead of guessing._

---

## 1. Attack path analysis & visualization

**(a) What competitors do**
- **Microsoft Defender CSPM / Exposure Management.** The attack-paths experience has an **Overview tab** ("attack paths over time, top 5 choke points, top 5 attack path scenarios, top targets, and top entry points"), a filterable **Attack paths list** (Risk level H/M/L, Asset type, Remediation status, Time frame), and a **Choke points** list ("nodes where multiple attack paths converge, flagged as high-risk bottlenecks"). The **Attack Path Map** marks Vulnerable nodes, Entry points, Target assets, and Choke points. Selecting a node shows MITRE ATT&CK tactics and techniques, Risk factors, Insights, and Recommendations. The Remediation tab separates **"Recommendations" (steps that fix the path)** from **"Additional recommendations" (lower risk but don't fully fix the path)**. Paths only start from real external entry points, and a resolved path takes up to 24h to drop off the list. ([MS Learn: manage attack paths](https://learn.microsoft.com/en-us/azure/defender-for-cloud/how-to-manage-attack-path))
- **Google SCC Risk Engine** publishes the most transparent algorithm in the market. A virtual attacker starts from the public internet and runs simulations about every 6 hours (at least daily) against a read-only graph model. **Resource score = % of successful simulated attacks × priority value** (HIGH=10, MEDIUM=5, LOW=1, NONE=0 excludes), giving a range of 0-10. **Finding score = same × number of high-value resources exposed** (no upper bound). CVEs count only if they have exploitation activity (Mandiant) plus attack vector and complexity. Edges carry **AND/OR semantics** (an attacker needs both upstream nodes, or either one). The high-value set holds at most 1,000 resources per cloud and up to 100 resource-value configs (type, scope, tags), and Sensitive Data Protection can auto-promote resources. **Toxic combinations** each get a score. **Chokepoints** are "common resources where multiple attack paths converge — remediating one might remediate multiple toxic combinations". ([GCP attack exposure](https://docs.cloud.google.com/security-command-center/docs/attack-exposure-learn), [toxic combos & chokepoints](https://docs.cloud.google.com/security-command-center/docs/toxic-combinations-overview))
- **Wiz Security Graph.** An Issue is a **toxic combination** (type `TOXIC_COMBINATION`) linked to a source Control. A *critical* Issue is "a resource with a very high likelihood of being compromised **and** a significant business impact if compromised". Wiz's example is a sensitive DB reachable from a public VM with an exploitable critical CVE. Wiz markets this as cutting "tens of thousands of vulnerabilities" to "tens of critical attack paths" and runs a "Zero Criticals" program. Wiz does not publish a formula. ([Wiz blog](https://wiz.io/blog/the-anatomy-of-a-toxic-combination-of-risk), [Sekoia payload](https://docs.sekoia.com/integration/categories/network_security/wiz_issues/))
- **Orca** has an **Attack Path Analysis + Business Impact Score of 0-99** per path. Inputs are vuln severity and accessibility, lateral movement risk, and access to crown jewels (PII, secrets, entitlements, IP). The **Risk Dashboard shows the top 5 paths** by score, and each opens as a step-by-step graph. ([Orca blog](https://orca.security/resources/blog/cloud-attack-path-analysis/), [HelpNetSecurity](https://www.helpnetsecurity.com/2022/04/04/orca-security-attack-path-analysis/))
- **Prisma Cloud / Cortex Cloud** splits alerts into **Incidents, Attack Paths, Risks**. An attack-path alert opens to an evidence graph. Custom attack-path policies are saved asset searches that require Asset Type (1 value) and Finding Name (up to 10 findings). ([Prisma attack path policies](https://docs.prismacloud.io/content-collections/governance/attack-path-policies), [explore data](https://docs.prismacloud.io/content-collections/search-and-investigate/explore-data))
- **Tenable Cloud Security** uses the "toxic cloud trilogy": public exposure + critical CVE + over-privileged IAM. 29% of orgs had at least one in its 2025 report. CIEM maps effective permissions. ([Tenable](https://www.tenable.com/blog/the-toxic-cloud-trilogy-why-your-workloads-are-a-ticking-time-bomb))
- **BloodHound** defines a choke point as an *edge* into a node collection. "Any edge into Tier Zero is a Tier Zero choke point… the optimal location to block the largest number of attack paths." Enterprise computes **exposure** per choke point. ([SpecterOps glossary](https://bloodhound.specterops.io/resources/glossary/overview))

**(b) Bar to clear:** Google SCC's explicit scoring and simulation model combined with Defender's UX: overview tiles, a choke-point list, and the "fixes the path" vs "reduces risk" split.

**(c) nimbus design decisions**
1. **Graph model with typed edges and AND/OR gates.** Edges are `CAN_ASSUME`, `CAN_ACCESS(net)`, `HAS_PERMISSION(action, resource)`, `EXPOSES`, `RUNS_AS`, and `HAS_FINDING`. Multi-precondition steps use AND nodes, as in SCC, so path counts aren't inflated.
2. **Deterministic, published score.** `path_score = P(exploit) × impact(target)`. `P` is the product of per-edge exploitability: KEV=0.9, EPSS percentile, auth required ×0.3, internet entry ×1.0 vs internal ×0.5, and a hop-decay of 0.85^hops. Impact comes from crown-jewel tier (10/5/1). Document the formula in `docs/`, unlike Wiz and Orca, which keep theirs closed.
3. **Min-cut "break the path" recommender.** Compute a weighted minimum edge cut between `Internet` and the crown-jewel set, where edge weight = remediation cost (tag/SG change=1, IAM policy edit=2, patch=3, re-architecture=8). Output a ranked list of fixes with **"paths broken: N/M, risk removed: X%"**. This is more than Defender (lists choke points) and SCC (chokepoint findings) offer. Neither tells you the cheapest set.
4. **Crown jewels via config + auto-detect.** Use a `nimbus.yaml` `crown_jewels:` block (selectors by type, tag, account, name regex) with HIGH/MED/LOW/NONE. Auto-promote datastores with DSPM-classified data. Cap and warn like SCC does.
5. **Outputs in CLI, JSON, and graph.** `cloud-posture paths --top 5` prints an ASCII path (`Internet → sg-123:22 → i-abc (CVE-2024-x, KEV) → role/app → s3://pii`). Also emit JSON and Mermaid/Cytoscape for the UI, and a "paths over time" series.
6. **Path diffing** shows new and closed paths since the last scan, which feeds alerting (area 9).

**(d) Open source to learn from:** [Cartography](https://github.com/cartography-cncf/cartography) (Neo4j graph, 30+ sources). [Prowler Attack Paths](https://docs.prowler.com/developer-guide/attack-paths-queries) uses read-only openCypher over Cartography, with query defs carrying `id/name/short_description/description/attribution/provider/cypher/parameters`, ids like `aws-ec2-privesc-passrole-iam`, attribution to pathfinding.cloud, and Neptune-safe Cypher. [PMapper](https://github.com/Fennerr/PMapper) handles transitive IAM privesc (e.g. "can launch EC2 with a role that reads S3"), including SCPs and permission boundaries.

---

## 2. Context-aware risk prioritization

**(a) What competitors do**
- **Defender CSPM.** Risk factors are **Internet exposure, Data sensitivity, Lateral movement, Attack paths**. Risk levels are **Critical / High / Medium / Low / Not evaluated**. Recommendation list columns are Title, Affected resource, Risk level, Risk factors, **# Attack paths**, Owner, Status (unassigned/on time/overdue), and Insights. There are views by asset, by title, and **by resource (for single owners)**. Governance rules auto-route by tag (e.g. `Team: DataPlatform`), set due dates and SLAs, and send owners a weekly email. A **"New" tag** marks rules younger than 30 days, and Secure Score has a changelog. ([recommendations](https://learn.microsoft.com/en-us/azure/defender-for-cloud/security-recommendations), [review](https://learn.microsoft.com/en-us/azure/defender-for-cloud/review-security-recommendations))
- **Microsoft Exposure Management critical assets.** Four criticality levels (**Very high, High, Medium, Low**). A predefined classification catalog covers DBs with sensitive data, privileged roles, and similar. The highest matching rule wins. Custom rules come from a query builder. ([critical asset mgmt](https://learn.microsoft.com/en-us/security-exposure-management/critical-asset-management), [predefined levels](https://learn.microsoft.com/security-exposure-management/predefined-classification-rules-and-levels))
- **Orca Risk Score** runs **1.0-10.0 with one decimal**. Bands are Critical 9-10, High 7-8.9, Medium 5-6.9, Low 3-4.9, based on probability × business impact. Example: a public bucket with PII is High. The API shows a base score plus weighted features (e.g. "Mitre Category" weight 0.5). ([Orca granular scoring](https://orca.security/resources/blog/simplify-cloud-risk-prioritization-with-granular-alert-scoring/), [Chronicle integration](https://docs.cloud.google.com/chronicle/docs/soar/marketplace-integrations/orca-security))
- **Wiz** separates **Findings** (raw rule results) from **Issues** (toxic combinations). The context is network exposure, unprotected data, excessive permissions, and exploitable vulns.
- **Datadog Security Inbox** uses a fixed, documented order: **severity → # correlated risks → # impacted resources/services**. Vulnerabilities are boosted by exploit availability and production `env` tags. ([Security Inbox](https://docs.datadoghq.com/es/security/security_inbox/))
- **EPSS/KEV.** The common practice is KEV first, then EPSS plus CVSS. EPSS is refreshed daily by FIRST. ([DefectDojo EPSS/KEV](https://docs.defectdojo.com/triage_findings/epss_kev/))

**(b) Bar to clear:** Defender's explainable risk-factor columns plus Orca's single 1-10 number. Every top-N item must show *why* it ranks there.

**(c) nimbus design decisions**
1. **Two-tier object model.** `Finding` is a rule × resource result. `Issue` is a correlated set of Findings on a path or asset, scored. Only Issues appear in "Top N".
2. **Transparent score, 0-10 with one decimal**: `base_severity × exposure_mult × identity_mult × data_mult × exploit_mult × criticality_mult`, clamped. Each multiplier appears as a chip in the UI and CLI (`internet-exposed ×1.6`, `KEV ×1.5`, `admin-role ×1.4`, `PII ×1.5`, `prod ×1.2`). Expose a `--explain` flag.
3. **Context signals**: internet exposure (effective reachability, not "has public IP"), effective IAM, data class (DSPM sampler), CVE with EPSS and KEV (daily feed cache), environment from tags, compliance scope (PCI/HIPAA tag), **recent change** (resource modified less than 7d ago raises the score), owner (tag/CODEOWNERS).
4. **Critical-asset rules** follow Microsoft's 4 levels, with highest-wins resolution and a catalog of built-ins (prod DBs, KMS keys, org-admin roles, CI deploy roles).
5. **"Top 10 that matter" view** grouped by resource and by fix. Show the delta since the last scan and an "accepted risk/mute with expiry" action.
6. **Severity calibration test suite**: golden scenarios in `testdata/` assert ranking order, so scores don't drift silently.

**(d) Open source to learn from:** Prowler's mutelist uses AND logic across account, region, and resource, supports tags (AND/OR) and regex, and keeps muted findings marked `Suppressed` in OCSF instead of dropping them. ([mutelist](https://docs.prowler.com/user-guide/cli/tutorials/mutelist)) DefectDojo has EPSS/KEV scoring.

---

## 3. Auto-remediation / IaC fixes / auto-PRs

**(a) What competitors do**
- **Prisma Cloud Code Security (Checkov-based).** It posts PR comments with **one-click "commit suggestion"** fixes, and the comment updates once the fix is committed. "Fix and Submit" in the console opens a fix PR. **Yor** tags IaC with `yor_trace` UUIDs that carry to cloud resources for cloud-to-code mapping and **drift detection** (TF and CFN on AWS, Azure, GCP). Drift can trigger auto-PRs in HCL. ([Prisma drift](https://docs.prismacloud.io/content-collections/application-security/risk-management/monitor-and-manage-code-build/drift-detection), [Yor workshop](https://bridgecrew.awsworkshop.io/terraform/40_module_two/2002_yor_github_action.html))
- **Wiz Code.** It maps cloud resources to code **via Terraform state**, pointing to the "exact file, line of code, and module… along with the author and code owners". It has a **Code-to-Cloud tab** on Issues and an *Inventory → Source mappings* table. **AI remediation 2.0** lets the user *choose a strategy* (patch, narrow role, remove exposure, which network hop to close) and output format (console, CLI, IaC), backed by a research-team strategy knowledge base. The Issues Agent can raise a *suggested* PR, with the link shared in Slack. ([Wiz+HCP TF](https://wiz.io/blog/wiz-hcp-terraform-close-the-cloud-security-gap), [code-to-cloud](https://www.wiz.io/blog/the-missing-link-in-code-to-cloud-visibility-is-finally-here), [AI remediation 2.0](https://www.wiz.io/blog/introducing-ai-powered-remediation-2-0))
- **Snyk** maps cloud issues to IaC via a minimal TF-state **mapping artifact** (it does not upload tfstate). Prerequisites are AWS and TF 0.11 or later. ([Snyk docs](https://docs.snyk.io/~/changes/TzxJRMARwBuZNPcIpizY/scan-cloud-configurations/integrated-iac-with-cloud-context/fix-cloud-issues-in-integrated-iac))
- **Defender + Copilot.** "Reduce risk with Copilot → Help me remediate" generates a PR in Azure DevOps, and "a developer should review and approve". ([MS Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/remediate-code-with-copilot))
- **Semgrep Assistant** suggests autofix only for true positives without a human-written fix. It has a confidence threshold, a GitHub "Commit suggestion", and **Memories** for org-specific fix preferences. ([Semgrep](https://semgrep.dev/docs/semgrep-assistant/overview))
- **KICS** has `kics remediate --results results.json [--include-ids]`, but only for simple single-line replacements or additions in Terraform. ([KICS](https://docs.kics.io/latest/kics_auto_remediation/))

**(b) Bar to clear:** Wiz Code's file/line/owner trace plus strategy choice, delivered in Prisma's one-click PR suggestion format.

**(c) nimbus design decisions**
1. **Cloud→code resolver.** Order of preference: (i) `nimbus_trace`/`yor_trace` tag, (ii) TF state address → module/file/line via HCL parse, (iii) CFN logical ID, (iv) heuristic name match with a confidence score. Never upload tfstate. Extract only ids and addresses locally.
2. **Fix PR template**: title `fix(nimbus): <rule> on <address>`. The body contains Why (path or score chips), Diff, **Blast radius** (what else references this resource, plus a `terraform plan` summary), **Risk of change** (low/med/high plus breaking-change notes), **Rollback** (`git revert` plus the prior value), the Evidence link, and a test plan. Label `nimbus-autofix`.
3. **Deterministic fixes first, LLM second.** Use a curated fix library (HCL AST edits) for the top ~100 rules. LLM fixes only when no template exists. They must pass `terraform validate`, nimbus re-scan of the patched file, and a **no-widening check** (a diff may only restrict). Otherwise downgrade to a comment.
4. **Strategy picker** (as in Wiz): for an Issue, offer alternatives ranked by min-cut weight (area 1), for example "close SG 0.0.0.0/0:22" vs "remove role from instance".
5. **Guardrails**: PR only, never push to the default branch. Use a per-repo allowlist and a max of N open nimbus PRs. Never auto-merge. Use a `dry-run` default for live-cloud remediation, which requires `--apply` and prints the CLI/SDK call.
6. **Drift loop**: when a cloud finding has no IaC origin, flag it "ClickOps drift" and offer an `import` block plus the fixed resource.

**(d) Open source to learn from:** Yor (trace tags), KICS remediate (JSON results → patch), Checkov/Trivy SARIF.

---

## 4. SQL / query engines over cloud

**(a) What competitors do**
- **Steampipe** uses a Postgres FDW, with plugins over gRPC. It has 116 plugins and 44 mods at v1.0. "Zero-ETL" plugin builds exist for your own Postgres or SQLite. **Powerpipe** runs HCL mods (benchmarks, controls, dashboards) against Postgres, SQLite, DuckDB, or MySQL. AWS Compliance has **1,229 controls and 30 dashboards**. Output formats: JSON, CSV, HTML, ASFF. ([Steampipe arch](https://steampipe.io/docs/develop/overview), [unbundled](https://www.steampipe.io/blog/steampipe-unbundled), [InfoWorld](https://www.infoworld.com/article/3714921/steampipe-dashboards-and-benchmarks-for-your-data.html))
- **CloudQuery**: `cloudquery init --source=aws --destination=postgresql`, then `cloudquery sync`. It streams Apache Arrow to many destinations and supports CDC. The data stays in your environment. ([CloudQuery hub](https://www.cloudquery.io/hub/export-data/aws/postgresql))
- **GCP Cloud Asset Inventory** offers a BigQuery-dialect `gcloud asset query`. It has one table per type (`compute_googleapis_com_Instance`), a `STANDARD_METADATA` cross-type table, and 35 days of change history. ([GCP](https://docs.cloud.google.com/asset-inventory/docs/query-assets-with-sql))
- **Wiz** has a schemaless graph and a **Wiz Query Language** (JSON). **AskAI** turns text into graph queries (e.g. "VMs with unencrypted disks" → VM -uses→ Volume{encrypted=false}). ([Wiz AskAI](https://www.wiz.io/blog/askai-text-to-security-graph-query))
- **Defender** has an **"Open query"** button on every recommendation that generates the Azure Resource Graph KQL ("affected resources" or "security findings"). ([MS Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/review-security-recommendations))
- **Datadog** has facet search (`evaluation:fail`), group by any tag, and 15 months of misconfig history. ([Datadog](https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/findings/))

**(b) Bar to clear:** Steampipe's "every API is a table, every control is a query" model combined with Defender's "Open query" from any finding.

**(c) nimbus design decisions**
1. **Embedded DuckDB** over the normalized snapshot (Parquet per scan). It needs no server, gives cross-cloud joins for free, and supports time travel across scans (`scan_id`).
2. **Unified tables** (`nimbus.resources`, `findings`, `identities`, `edges`, `exposures`) alongside provider-native tables. Cross-cloud joins work on normalized columns (`cloud`, `account`, `region`, `type`, `tags`, `public`).
3. **Controls are queries.** Every rule is SQL (or Rego) with metadata, and `cloud-posture query --from-rule <id>` prints the SQL. Every UI finding has "Open query".
4. **Graph queries** via a `paths()` table function or openCypher passthrough for area 1.
5. **Delight features**: schema autocomplete in the REPL and VS Code (column docs from the schema), saved and shared queries in `.nimbus/queries/*.sql` with front-matter, NL→SQL with the generated SQL always shown and editable, and `--format json|csv|table|parquet`.
6. **Export compatibility** to Postgres via `COPY` and to Steampipe-style table names, so existing mods partially work.

**(d) Open source to learn from:** Steampipe and Powerpipe (HCL mod format, benchmark tree), CloudQuery (Arrow streaming), Cartography.

---

## 5. Multi-cloud + SaaS unified dashboards

**(a) What competitors do**
- **Defender** summary cards are **Cloud secure score, Score history (7d), Recommendations by risk level, How risk level is calculated**, plus category tabs (Misconfigurations, Vulnerabilities, Exposed Secrets) and filters (Exposed asset, Asset risk factors, Environment, Workload). ([MS Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/review-security-recommendations))
- **Prowler** has a coverage table: AWS 615 checks / 47 frameworks, M365 109 checks / 6 frameworks, Kubernetes 90 / 8, GitHub 24 / 2, plus Azure, GCP, and others. There is **Prowler App** (web UI) and the `prowler dashboard` CLI. The **ThreatScore** PDF breaks the score down by pillar (e.g. Encryption 94%, Attack Surface 77%). ([Prowler GitHub](https://github.com/prowler-cloud/prowler), [ThreatScore](https://docs.prowler.com/user-guide/compliance/tutorials/threatscore))
- **Orca SideScanning** reads block storage out-of-band and covers AWS, Azure, GCP, Kubernetes, Alibaba, and **Snowflake** (90+ data classifiers). ([Orca Snowflake](https://www.businesswire.com/news/home/20241210260009/en))
- **Wiz SaaS** coverage largely comes through partners and acquisition (Adaptive Shield, AppOmni, Valence for M365, Slack). ([AppOmni+Wiz](https://appomni.com/blog/appomni-and-wiz-enable-cloud-and-saas-security-control/))
- **Trend Vision One** widgets: Cloud Risk Index, Asset Coverage, Security Posture, Compliance, Assets at Risk, Cloud Accounts Breakdown. ([Trend](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-cloud-overview-dashboard))

**(b) Bar to clear:** Defender's four summary cards with drill-through, plus Prowler's breadth (AWS/Azure/GCP/K8s/M365/GitHub) in one view.

**(c) nimbus design decisions**
1. **Home panels**: (1) Risk score and 30d trend, (2) Top 5 attack paths and choke points, (3) Issues by severity with a "new since last scan" count, (4) Coverage (accounts and providers scanned, last-scan age, permission errors), (5) Compliance % per framework, (6) Owners leaderboard (open criticals by team, overdue SLA), (7) Security-driven savings (area 7).
2. **Every number is a link** to a pre-filtered list, then to the resource drawer (config JSON, findings, paths through it, code origin, owner, history).
3. **Coverage honesty panel**: list API calls denied or skipped per account so silent gaps are visible. Competitors hide these.
4. **Provider roadmap**: AWS/Azure/GCP/K8s first, then GitHub, Okta, Entra ID, M365, Google Workspace, Slack, and Snowflake via read-only API tokens. Each provider declares checks/services/frameworks counts the way Prowler does.
5. **Static HTML report** (single file, no CDN, escaped). Note Prowler's HTML report shipped a **stored XSS via unescaped tags** ([CVE-2026-73262](https://corgea.com/advisories/vulnerabilities/CVE-2026-73262)), so treat every cloud string as hostile.

**(d) Open source to learn from:** Prowler App, ScoutSuite's offline HTML report, Powerpipe dashboards (HCL `card`/`chart`/`table`).

---

## 6. AI copilot features

**(a) What competitors do**
- **Wiz.** **Mika (Ask AI)** answers across the UI. The **Issues Agent** ("Investigate") suggests remediation path, owners, and sequence. The **SecOps Agent** returns a **verdict + confidence + investigation summary**. Wiz also has an MCP server, IDE extension, and Claude Code / Cursor skills. AskAI does text → WQL JSON. ([Wiz AI agents](https://wiz.io/blog/wiz-ai-agents), [itbrief](https://itbrief.co.uk/story/wiz-expands-ai-security-coverage-across-cloud-edge))
- **Orca** offers NL search ("Do I have any log4j vulnerabilities that are public-facing?") and AI remediation code for CLI, Terraform, Pulumi, CFN, CDK, ARM, and OPA. It supports multiple LLM backends (OpenAI, Azure OpenAI, Bedrock, Vertex). ([Orca Bedrock](https://orca.security/resources/press-releases/orca-security-generative-ai-integration-amazon-bedrock/), [CSO](https://www.csoonline.com/article/575261/orca-integrates-cloud-app-security-platform-with-gpt-4.html))
- **Microsoft Security Copilot in Defender for Cloud** offers **"Summarize with Copilot"**, NL remediation with scripts, IaC PRs, and "Delegate recommendations". It is billed via Security Compute Units. ([MS Learn](https://learn.microsoft.com/en-us/azure/defender-for-cloud/remediate-with-copilot))
- **Prowler Lighthouse AI** searches findings, inspects configs and CloudTrail timelines, runs attack-path queries, and schedules scans. It is **strictly read-only** cloud access. ([Prowler July 2026](https://prowler.com/blog/prowler-july-2026-newsletter))
- **Semgrep Assistant** triages with explanations, uses an autofix confidence threshold and Memories, and claims more than 95% FP-classification accuracy. ([Semgrep](https://semgrep.dev/docs/semgrep-assistant/customize))

**(b) Bar to clear:** Wiz's verdict + confidence + reasoning pattern, with Lighthouse's read-only guarantee and Semgrep's org memory.

**(c) nimbus design decisions**
1. **Tool-using agent over nimbus's own query layer.** The LLM never sees raw creds and never calls cloud write APIs. Tools are `sql()`, `paths()`, `explain_finding()`, and `draft_fix()`.
2. **Show your work**: every answer shows the SQL or Cypher it ran, row counts, and cited finding IDs. Answers without citations are refused.
3. **Structured outputs**: `{verdict, confidence, evidence[], next_steps[]}` for triage, and `{strategy, diff, risk, rollback}` for fixes, validated by schema.
4. **Guardrails**: secret redaction before prompts, a tenant data-residency switch, a BYO model (Anthropic/OpenAI/Bedrock/local), and fixes routed through the area-3 validators. Use a prompt-injection boundary: treat resource tags and descriptions as data.
5. **Memories**: org-level instructions such as "we use gp3, never public S3, module X for SGs", scoped per repo or rule, with suggestions derived from mute and fix feedback.
6. **Offline-useful**: explanations for top rules are pre-generated and shipped, so the CLI works without an LLM.

**(d) Open source to learn from:** Prowler Lighthouse (read-only agent), Steampipe/CloudQuery MCP servers.

---

## 7. Cost + security

**(a) What competitors do**
- **Infracost** posts PR comments with monthly cost delta, **FinOps policy** violations (e.g. gp2→gp3), and tagging policy issues expanded first. Cost expands only when it exceeds the budget guardrail. Rego policies can fail CI. Budgets are scoped by tags and show spend to date, PR impact, and headroom. ([Infracost policies](https://www.infracost.io/resources/blog/new-finops-policies-tfsec-creators-join-infracost), [budgets](https://www.infracost.io/docs/infracost_cloud/budgets/))
- **Cloud Custodian** uses YAML filters and actions for off-hours and garbage collection of unused resources, with a **mark-for-op → notify → stop → terminate** lifecycle. It runs in Lambda or CI. ([cloudcustodian.io](https://cloudcustodian.io/))
- **AWS Trusted Advisor** has 6 pillars: Cost optimization, Performance, Security, Fault tolerance, Service limits, and Operational excellence. About 480 checks on Business Support+. Status is Green/Yellow/Red. ([AWS](https://docs.aws.amazon.com/awssupport/latest/user/get-started-with-aws-trusted-advisor.md))
- **Vantage** does anomaly detection per Cost Report and service category, trained on full history, with resource attribution and $-threshold alerts to Slack/Teams/email. ([Vantage](https://docs.vantage.sh/cost_anomaly_alerts))
- **Breach-cost framing (IBM 2025):** global average **$4.44M** (first decline in 5 years), **US $10.22M** (all-time high, +9%), **241 days** to identify and contain, about **$1.9M saved** with extensive security AI and automation, and shadow AI adds **$670K**. ([Baker Donelson PDF of IBM report](https://www.bakerdonelson.com/webfiles/Publications/20250822_Cost-of-a-Data-Breach-Report-2025.pdf), [Morgan Lewis](https://www.morganlewis.com/blogs/sourcingatmorganlewis/2026/04/study-finds-average-cost-of-data-breaches-decreased-globally-in-2025))

**(b) Bar to clear:** Infracost's PR-time cost and policy comment, plus Custodian's safe, staged action lifecycle.

**(c) nimbus design decisions**
1. **"Security-driven savings" findings** where the security fix also saves money: unattached EBS/disks and old snapshots (data-leak risk), idle public IPs and LBs (attack surface), unused IAM users and keys, stale NAT and open dev instances, unused KMS keys. Each carries `monthly_usd` from the public pricing API, cached offline.
2. **Expected-loss framing, labeled as an estimate**: `issue_exposure_usd = P(exploit) × impact_tier × breach_baseline`. The baseline is user-configurable and defaults to IBM's $4.44M global or $10.22M US. It always shows inputs and never presents a single "ROI" number as fact.
3. **PR comment** combines cost delta and security delta ("+$212/mo, closes 2 attack paths").
4. **Custodian-style staged actions** for cleanup: tag → notify owner → wait N days → stop. Never delete without `--apply`.
5. **Trend card**: "risk removed this month" and "$ saved this month" side by side.

**(d) Open source to learn from:** Infracost CLI (pricing API), Cloud Custodian (mark-for-op lifecycle).

---

## 8. Compliance-as-code & audit reports

**(a) What competitors do**
- **Vanta** runs **hourly** tests across 400+ integrations (1,200-1,300+ tests/hour cited). **Drata** runs a daily or nightly sweep plus real-time events and has an **Audit Hub** for auditors. ([Vanta vs Drata](https://vanta.com/compare/drata), [CPO Magazine](https://www.cpomagazine.com/digital/vanta-vs-drata-for-enterprise-compliance/))
- **AWS Audit Manager** report ZIP layout: report folder (summary PDF, `digest.txt`, README) → evidence **by control**, **by data source** (CloudTrail, Security Hub), and **by collection date**. Evidence folders are per day. It "does not assess compliance", it supplies evidence. ([Audit Manager](https://docs.aws.amazon.com/audit-manager/latest/userguide/assessment-reports.html))
- **Prowler** maps each requirement to 0..n checks. It writes `output/compliance/` with one CSV per framework (e.g. `cis_6.0_aws`) plus OCSF JSON and HTML. ThreatScore = `Σ(rate×total×weight×risk)/Σ(total×weight×risk)×100`, with weight 1-1000 and risk 1-5. Bands: ≥90 Excellent, 80-89 Good, 70-79 Acceptable, 60-69 Needs Improvement, <60 Critical. ([Prowler compliance](https://docs.prowler.com/user-guide/cli/tutorials/compliance), [ThreatScore](https://docs.prowler.com/user-guide/compliance/tutorials/threatscore))
- **Powerpipe** benchmarks use an HCL benchmark → control tree. AWS Compliance has 1,229 controls.

**(b) Bar to clear:** an Audit Manager-style evidence package (by control, source, and date, with a digest) generated continuously, the way Vanta does, from open-source controls.

**(c) nimbus design decisions**
1. **Framework mapping files** (YAML): `framework → requirement → [rule_ids] + manual_evidence[]`. Ship CIS (AWS/Azure/GCP/K8s), SOC 2 TSC, PCI DSS 4.0, HIPAA Security Rule, ISO 27001:2022 Annex A, and NIST 800-53. Manual requirements are explicitly marked "requires attestation" and never shown as pass.
2. **Evidence bundle** `cloud-posture evidence --framework soc2 --period 2026-Q3` produces a ZIP: `summary.pdf/html`, `manifest.json` with a SHA-256 per file and a **signed digest**, `by-control/`, `by-source/`, `by-date/`. Each evidence item records the raw API response, timestamp, account, query, and tool version (the reproducibility auditors ask for).
3. **Period coverage for SOC 2 Type II and PCI.** Store daily snapshots and report "control effective X of Y days in period" with gaps. This is what auditors need for operating effectiveness.
4. **Cadence**: hourly lightweight checks (IAM, public exposure) via events (area 9), plus a full daily scan, configurable.
5. **Formats**: OCSF JSON (Security Hub ingests OCSF 1.6), ASFF, CSV per framework, SARIF for IaC, and an auditor-friendly PDF/HTML with exceptions and mutes listed with justification and expiry.
6. **Weighted posture score** like ThreatScore, with the formula documented and per-pillar breakdown.

**(d) Open source to learn from:** Prowler compliance JSON specs and ThreatScore, Powerpipe mods.

---

## 9. Real-time detection & alert routing

**(a) What competitors do**
- **Wiz Defend** ingests cloud logs, "filters out noise and duplicate alerts, and groups connected events into high-fidelity threats". It shows a per-threat timeline across telemetry sources. ([Wiz Defend](https://www.wiz.io/blog/wiz-defend-for-gov), [Macnica](https://www.macnica.co.jp/en/business/security/manufacturers/wiz/wiz_defend.html))
- **Lacework (FortiCNAPP) Polygraph** builds behavioral baselines. **Composite alerts** combine low-criticality signals plus Labs attack sequences into one alert (compromised creds, cryptomining, ransomware). ([HelpNetSecurity](https://www.helpnetsecurity.com/2023/02/23/lacework-composite-alerts/))
- **Datadog** has **suppression rules** across detection rules with an **expiration date** and a "Never trigger signals for" button on any attribute. **Notification rules** span rules (e.g. any CRITICAL/HIGH → Slack, Jira, PagerDuty, webhook). Case Management syncs to Jira **two-way per field** (title, description, assignee, comments, status, priority). **The ticket auto-closes when the finding is remediated or muted.** Misconfig re-evaluation runs every 15 min to 4 h. ([suppressions](https://docs.datadoghq.com/ko/security/suppressions), [notifications](https://docs.datadoghq.com/security/notifications/), [ticketing](https://docs.datadoghq.com/security/ticketing_integrations))
- **Defender** continuous export streams to Event Hubs, Log Analytics, or Logic Apps (stream on state change plus weekly snapshot). Governance rules route by tag. ([continuous export](https://learn.microsoft.com/en-us/azure/defender-for-cloud/continuous-export))
- **Event sources**: AWS CloudTrail → EventBridge; Azure Activity Log / **Event Grid Resource Notifications** system topic (use CloudEvents v1.0 schema); GCP Audit Logs → Pub/Sub sink. ([Azure Event Grid](https://azure.microsoft.com/de-de/updates/azure-event-grid-system-topics-support-for-resource-management-and-health-resources-now-in-public-preview/))
- **Cortex** issue sync supports Inbound, Outbound, Bi-directional, or None. ([Cortex](https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/cases-and-issues/investigation-and-response/investigate-issues/issue-syncing))

**(b) Bar to clear:** Datadog's routing model (cross-rule notification rules, expiring suppressions, field-level two-way Jira sync, auto-close on fix) on top of event-driven re-evaluation within minutes.

**(c) nimbus design decisions**
1. **Event-driven re-scan**: subscribe to write events (EventBridge rule on `"readOnly": false`, Event Grid, Pub/Sub) → re-evaluate only the touched resource and its graph neighbors in under 2 min. Diff the paths and alert only on **new or worsened** Issues.
2. **Dedup key** = `rule_id + resource_id + path_hash`. Collapse repeats into one alert with an `occurrences` count and a time window. Group correlated events (same principal, ~15-min window) into a composite "incident".
3. **Routing rules (YAML)**: `match: {severity>=high, tags.env: prod, framework: pci}` → `route: [slack:#sec, jira:SEC, pagerduty:svc]`. Owners resolve from tags or CODEOWNERS.
4. **Suppression with mandatory expiry and reason**, audited, so nothing is muted forever by default.
5. **Ticket lifecycle**: create → sync status, assignee, and comments both ways (configurable per field) → **auto-close when nimbus verifies the fix** → reopen on regression.
6. **Ship-ready deploy**: Terraform modules for the EventBridge/Event Grid/Pub/Sub wiring, the same IaC users already trust.

**(d) Open source to learn from:** Cloud Custodian (`mode: cloudtrail` Lambda policies), Falco/Sigma rule formats, Prowler CloudTrail timelines.

---

## 10. Developer experience

**(a) What competitors do**
- **Checkov / Trivy / KICS GitHub Actions** emit SARIF, then `github/codeql-action/upload-sarif` with `if: always()` and a per-tool `category`. They use `soft_fail` or `--hard-fail-on CRITICAL` gating. KICS has `enable_comments` (PR comment) and `enable_jobs_summary`. ([GitHub SARIF](https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github), [Checkov SARIF](https://www.checkov.io/8.Outputs/SARIF.html))
- **Semgrep PR comments** support slash-command triage (`/fp`, `/ar`, `/other`), an explanation of why something is likely an FP, and a one-click Commit suggestion. ([Semgrep](https://semgrep.dev/docs/for-developers/resolve-findings-through-comments))
- **Snyk VS Code** shows inline IaC issues, hover detail, and a Quick Fix panel (description, impact, path, remediation). **Snyk Learn** lessons follow basics → "in action" interactive widget → under the hood → mitigation. ([Snyk VS Code](https://docs.snyk.io/developer-tools/snyk-ide-plugins-and-extensions/visual-studio-code-extension/view-analysis-results-from-visual-studio-code-extension/analysis-results-snyk-iac-configuration), [Snyk Learn](https://learn.snyk.io))
- **Wiz Code** posts PR scan comments with remediation links. One policy engine is shared between `wizcli` and the VCS integration. A JetBrains plugin exists. ([Wiz Code](https://www.wiz.io/blog/wiz-code-unify-security-across-github-gitlab-and-azure-repos))
- **Prowler onboarding** uses a CloudFormation stack with a tenant-generated **External ID** (confused-deputy protection), or Terraform. Org-wide setup is a management role plus a **StackSet** to every member account. ([Prowler AWS](https://docs.prowler.com/user-guide/providers/aws/getting-started-aws), [Orgs](https://docs.prowler.com/user-guide/providers/aws/organizations))

**(b) Bar to clear:** Semgrep's PR comment UX plus Snyk's in-IDE Quick Fix, with Prowler's org-wide StackSet onboarding.

**(c) nimbus design decisions**
1. **Zero-to-first-finding in under 5 min**: `cloud-posture init` detects local creds and prints the minimal read-only policy. `cloud-posture onboard aws --org` emits a CFN/TF StackSet with External ID. For CI, use **GitHub OIDC** (no static keys) with a documented trust policy.
2. **GitHub Action** `nimbus/scan-action`: SARIF upload with `category: nimbus`, one sticky PR comment (updated, never spammed) with a severity table, top 3 issues with a collapsible diff suggestion, and a "paths opened by this PR" section (unique: plan-time attack-path diff).
3. **PR slash commands**: `/nimbus mute <id> reason:… expires:30d`, `/nimbus fix <id>` (opens a fix commit), `/nimbus explain <id>`.
4. **VS Code extension** (already in `vscode-extension/`): inline diagnostics from the same engine, a Quick Fix that applies the template fix, hover text with "why it matters" and a **live-cloud context** chip ("this SG is attached to 3 internet-facing instances in prod").
5. **Exit-code contract**: `--fail-on high`, `--baseline <file>` (only new findings fail), and stable finding IDs across runs.
6. **Learn-by-doing**: `cloud-posture tutorial` spins up an intentionally vulnerable local Terraform plan (no cloud needed) and walks through find → path → fix → re-scan, similar to Snyk Learn's "in action" step.

**(d) Open source to learn from:** Checkov, Trivy, KICS actions; Semgrep comment UX; Prowler onboarding templates ([prowlerpro-permissions-templates-public](https://github.com/prowler-cloud/prowlerpro-permissions-templates-public/)).

---

## Where nimbus can win (prioritized)

1. **Published, explainable risk math.** Wiz and Orca keep scoring closed. nimbus publishes the formulas (path score, issue score, posture score) and shows the multiplier chips on every item.
2. **"Cheapest fix set" via min-cut.** Defender lists choke points and SCC flags chokepoints. Neither computes the minimum-cost set of changes that breaks *all* paths to the crown jewels. nimbus can.
3. **Plan-time attack-path diff in PRs**: "this PR opens 1 new path to `s3://pii`". This joins IaC scanning (Checkov/Trivy) with graph analysis (Wiz), which no OSS tool does.
4. **Validated, guard-railed auto-fix PRs.** Deterministic HCL templates first. LLM fixes must pass validate + re-scan + no-widening checks, and every PR carries blast radius and rollback.
5. **Local-first query engine.** DuckDB over snapshots gives cross-cloud SQL, time travel, and "Open query" from every finding, with no Postgres to run (simpler than Steampipe and CloudQuery).
6. **Auditor-grade evidence bundles** (signed manifest, by control, source, and date, period coverage %), the format Audit Manager uses but free and multi-cloud.
7. **Honest coverage**: surface denied or skipped APIs per account. Competitors silently under-report.
8. **Read-only, cite-everything AI**: answers include the query and the finding IDs, with BYO model and org Memories. The CLI stays fully useful offline.
9. **Event-driven deltas with sane routing**: re-evaluate in under 2 min, alert only on new or worse items, suppressions that expire, and Jira auto-close on verified fix.
10. **Security-driven savings with honest breach-cost framing**: dollars saved plus expected-loss estimates with visible inputs (IBM 2025: $4.44M global / $10.22M US).

## Feature → competitor bar → nimbus commitment

| Feature | Competitor bar (who) | nimbus commitment |
|---|---|---|
| Attack paths | SCC simulation score (0-10, priority 10/5/1, AND/OR edges, ~6h); Defender Overview with top-5 choke points and entry points | Typed graph with AND/OR gates, published path score, min-cut fix set, top-5 paths/choke points/entry points, path diff per scan |
| Choke points / break the path | Defender "Recommendations vs Additional recommendations"; BloodHound Tier-Zero choke edges | Ranked fixes showing "paths broken N/M, risk removed X%", with cost-weighted edges |
| Risk prioritization | Defender risk factors (internet, data, lateral, paths) + # attack paths column; Orca 1-10 with one decimal | 0-10 score with multiplier chips (exposure, IAM, data, KEV/EPSS, criticality, recent change), `--explain` |
| Crown jewels | MS 4-level criticality catalog; SCC resource-value configs (≤1,000 resources) | `crown_jewels:` selectors with 4 levels, DSPM auto-promotion, built-in catalog |
| Cloud→code + fix PRs | Wiz Code file/line/owner via TF state; Prisma one-click PR suggestion + Yor trace | Trace via tag → state → HCL line, PR template with diff/blast radius/rollback/test plan, validators, no auto-merge |
| Query engine | Steampipe 116 plugins, 1,229 AWS controls; Defender "Open query" | Embedded DuckDB, unified + native tables, controls-as-SQL, "Open query" everywhere, NL→SQL shown |
| Dashboards | Defender 4 summary cards; Prowler multi-provider coverage table | 7 home panels, drill-through on every number, coverage-honesty panel, XSS-safe static HTML |
| SaaS coverage | Prowler M365 (109 checks) and GitHub (24); Orca Snowflake | GitHub, Okta, Entra ID, M365, Workspace, Slack, Snowflake via read-only tokens |
| AI copilot | Wiz verdict + confidence + summary; Lighthouse read-only; Semgrep Memories | Tool-using read-only agent, mandatory citations, JSON-schema outputs, BYO model, Memories |
| Cost + security | Infracost PR cost/policy comment; Custodian mark-for-op lifecycle | Security-driven savings findings, combined cost/security PR delta, staged cleanup, configurable breach baseline |
| Compliance evidence | Audit Manager ZIP (by control/source/date + digest); Vanta hourly tests | Signed evidence bundle, period-coverage %, 7 frameworks mapped, manual items never auto-pass |
| Posture score | Prowler ThreatScore (weight 1-1000 × risk 1-5, bands) | Documented weighted score with pillar breakdown |
| Real-time & routing | Datadog expiring suppressions, cross-rule notification rules, two-way Jira, auto-close | Event re-scan <2 min, dedup key, YAML routing, mandatory-expiry mutes, verified auto-close |
| DevEx / CI | Semgrep PR slash commands; Checkov/Trivy SARIF; Prowler StackSet + External ID | Sticky PR comment with path diff, `/nimbus` commands, SARIF, OIDC, `--baseline`, 5-min onboarding |
| IDE & learning | Snyk Quick Fix panel; Snyk Learn interactive lessons | VS Code Quick Fix with live-cloud context chip, offline `cloud-posture tutorial` |
