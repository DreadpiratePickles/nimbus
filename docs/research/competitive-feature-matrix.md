# Competitive feature matrix: CSPM / CNAPP capabilities vs nimbus

_Written 2026-10-09. One consolidated capability taxonomy (91 capabilities in 16 groups) built from the four cluster docs and the earlier 10-area research, scored against what nimbus really has today._

**Inputs**
- `docs/research/competitors/cnapp-leaders.md` (CL): Wiz, Orca, Cortex Cloud, FortiCNAPP, CrowdStrike, SentinelOne, Sysdig, Aqua, Upwind, Sweet.
- `docs/research/competitors/platforms.md` (PL): Defender, Google SCC, Datadog, AWS Security Hub, Tenable, Rapid7, Qualys, Zscaler, Sonrai, JupiterOne, Check Point.
- `docs/research/competitors/open-source.md` (OS): Prowler, Steampipe/Powerpipe/Flowpipe, Cloud Custodian, Cartography, CloudQuery, Fix Inventory, Checkov, KICS, Trivy, Kubescape and others.
- `docs/research/competitors/compliance-and-adjacent.md` (CA): GRC, DSPM, CIEM, CDR, CTEM, analyst/RFP criteria.
- `docs/research/competitors.md` (BASE): the 2026-10-08 10-area research.
- `docs/research/nimbus-capability-inventory.md` (INV): what nimbus really has. Section numbers below (`§1`…`§20`) refer to INV.
- `docs/research/strategy-how-to-win.md` (STRAT): present at start and at finish of this work; used for wedge weighting in the companion gap analysis.

**How to read the status column**
- Status words are INV's legend: `real` (wired end to end and tested against fakes or golden files), `partial`, `stub`, `absent`.
- **INV states that nothing in the repo has ever run against a live AWS, Azure or GCP account.** Every `real` means real against fakes.
- Where INV rates a whole area (for example "§7 Remediation: partial") and the capability maps one-to-one, the status is copied verbatim.
- Where a capability is narrower or wider than an INV area, the status carries a dagger (`†`). That means INV does not rate this exact capability, and I applied INV's own legend to the evidence INV cites. Nothing marked `†` is a new code reading.
- `not audited` means INV excluded it (`internal/dashboard/*` was being rewritten during the audit).

**Vendor abbreviations:** Wiz · Orca · Cortex (Palo Alto Cortex Cloud, ex-Prisma) · FCN (Fortinet FortiCNAPP, ex-Lacework) · CS (CrowdStrike) · S1 (SentinelOne) · Sysdig · Aqua · Upwind · Sweet · MDC (Microsoft Defender for Cloud + Exposure Management) · SCC (Google Security Command Center) · ASH (AWS Security Hub + Inspector/GuardDuty/Macie/Access Analyzer) · DD (Datadog) · Ten (Tenable) · R7 (Rapid7) · Qua (Qualys) · ZS (Zscaler) · Son (Sonrai) · J1 (JupiterOne) · CP (Check Point) · Prow (Prowler) · SP (Steampipe/Powerpipe/Flowpipe) · C7N (Cloud Custodian) · Carto (Cartography) · CQ (CloudQuery) · FixInv (Fix Inventory) · Chk (Checkov) · KICS · Trivy · Kube (Kubescape) · PMap (PMapper) · XM (XM Cyber).

---

## 1. Inventory & graph

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| IG1 | Agentless multi-cloud collection (AWS/Azure/GCP/K8s) | **Prow**: 23 providers; AWS 662 checks across 86 services | https://github.com/prowler-cloud/prowler | Wiz, Orca, Cortex, MDC, DD, CS, Qua, R7, SP (2,000+ tables), CQ, C7N | **partial** | §1: 48 native checks (AWS 21, Azure 7, GCP 6, K8s 7, GitHub 3, Okta 2, M365 2); fakes only; `internal/collector/**` |
| IG2 | SaaS and identity-provider coverage, incl. IdP→cloud federation | **Carto**: 76 intel modules; Okta/Entra federation edges to AWS roles and Identity Center | https://github.com/cartography-cncf/cartography | Prow (M365 144, Okta 29, Workspace 65 checks), Wiz (Okta, Snowflake, Workspace), Upwind, J1 (200+ sources), Cortex (unified human identity) | **partial** | §1: GitHub/Okta/M365 collectors; false passes at `saas/m365.go:90-103`, `saas/okta.go:233-239`; no identity edges to cloud |
| IG3 | Org-wide onboarding and account enumeration | **Prow**: CloudFormation with External ID, StackSet to every member account (BASE §10) | https://docs.prowler.com/user-guide/providers/aws/organizations | MDC (org connectors), FCN (Control Tower, rollback), Qua (OU/MG/folder filters), Son | **partial†** | §1: "No Organizations enumeration" (AWS); GCP one project per spec; Azure subscriptions enumerated but collected sequentially |
| IG4 | Typed, persisted security graph | **Wiz** Security Graph: typed nodes and relationships with properties and attached findings | https://www.securityscientist.net/blog/12-questions-and-answers-about-wiz-security-graph-wiz/ | Orca (Unified Data Model), Sysdig, MDC, J1 (100+ classes), Carto, CP | **partial** | §5: 13 edge kinds, 9 node classes; `ClassFor` misclassifies service accounts (`graph.go:365`); findings-only graphs are mostly co-occurrence |
| IG5 | SQL over inventory and findings, incl. cross-cloud normalized kinds | **SP**: every API a table (2,000+ tables), shipped as CLI, Postgres FDW, SQLite extension or export binary. Cross-cloud kinds: **FixInv** 40+ base kinds | https://github.com/turbot/steampipe ; https://github.com/someengineering/fixinventory | CQ, ASH Config advanced query (no JOIN), DD (SQL via MCP), FCN LQL | **partial (critical defects)** | §4: SQLite views work; read-only guard bypassable (`query.go:35-58`); SQL injection in view DDL (`store.go:404-408`); only per-type views, no unified kinds |
| IG6 | Graph query language and no-code builder | **Sysdig** SysQL: Cypher-like `MATCH/WHERE`, API, Simplified SysQL, NL→SysQL, read-only MCP skill. Readability: **J1QL** negated edges and `RETURN tree` | https://docs.sysdig.com/en/sysdig-secure/sysql-reference/ ; https://docs.jupiterone.io/j1ql/basic-queries | MDC (KQL `graph-match`), SCC (verb-phrase builder), Ten Explorer, DD Search for/Where/That, CP SGQL, Prow (read-only openCypher), Upwind Query Builder | **partial†** | §5: Neo4j push uses parameterised Cypher with Cartography-style labels; no native graph DSL or builder |
| IG7 | Change history, snapshots and raw source data | **FixInv**: hourly snapshots with per-resource timeline and diff. Raw data: **R7** Source Data pane showing provider JSON | https://github.com/someengineering/fixinventory ; https://docs.rapid7.com/insightcloudsec/layered-context-user-guide/ | GCP CAI (35 days), DD (15-month misconfig history), ASH (config at finding time vs now), Upwind (13-month lookback), ScoutSuite (embedded config) | **absent†** | §4: writes are upsert only, no migrations or versioning; findings never resolved (`store.go:130`) |
| IG8 | Coverage honesty: denied/skipped APIs and scan failure reasons | **FCN** Agentless dashboard: per-account and per-resource scan status with the failure reason | https://docs.fortinet.com/document/forticnapp/latest/release-notes/499403/august-2026-platform-releases | ASH (Security Coverage widget), MDC | **partial†** | §1: collector error becomes a failed ToolRun; §2: runner discards valid output when stderr contains "error" (`runner.go:317`); GitHub 403 silently skips checks (`rest.go:97`) |
| IG9 | AI asset inventory (models, agents, MCP servers) as graph nodes | **ASH** AI inventory from managed services, SBOM-detected self-hosted inference, and DNS evidence. **SCC** makes agents attack-path nodes | https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-ai/ ; https://docs.cloud.google.com/security-command-center/docs/ai-protection-overview | Wiz (AI-BOM, MCP discovery), MDC AI-SPM, Carto AIBOM, Ten, Sweet, Upwind | **absent†** | §1 lists no AI resource types |

## 2. Attack paths & toxic combinations

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| AP1 | Multi-hop attack-path engine | **SCC** Risk Engine: simulated attacker from the internet about every 6 h, AND/OR edge semantics. **Cortex 2.2**: graph-powered multi-hop detections across identity, code, data, workloads | https://docs.cloud.google.com/security-command-center/docs/attack-exposure-learn ; https://www.paloaltonetworks.com/blog/cloud-security/cortex-cloud-2-2/ | Wiz, Orca, MDC/MSEM (hybrid), ASH, Sysdig, FCN (2-hop AWS, 1-hop Azure/GCP), R7 (fixed catalog), Prow (AWS only) | **partial** | §5: DFS up to 6 hops; K8s and GCP service-account chains never fire; claimed OR semantics not implemented |
| AP2 | Published path scoring with per-hop justification | **SCC** formula (share of successful simulations × priority 10/5/1); **ASH** Likelihood × Impact matrix; **ASH** Impact tab labels each hop with the permission used | https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-severity.html ; https://docs.aws.amazon.com/securityhub/latest/userguide/potential-attack-path-graph.html | Orca 0–99 (closed formula), FCN per-node breakdown, CP evidence path | **partial** | §5: traversal and rule scores are different scales merged into one sort (`traversal.go:628-640`); prefix paths inflate counts; edges carry kind only, no action sets |
| AP3 | Toxic-combination Issues (findings vs issues) | **Wiz** Issues: a correlated toxic combination; critical = high likelihood **and** high impact | https://wiz.io/blog/the-anatomy-of-a-toxic-combination-of-risk | SCC issues, Sysdig risks, Qua TruRisk Insights, Ten trilogy, ASH exposures, CP | **partial†** | §5: 11 rule chains, mostly linked by `same_account`; §4 lists no issues table |
| AP4 | User-authored combination rules, test-before-save, and an attributed query library | **Sysdig** risk definitions (SysQL, one anchor resource, Managed/Custom, Live <3h and New <7d badges, auto-close). **Prow** ~100 AWS path queries with stable ids, ~70 attributed to pathfinding.cloud | https://docs.sysdig.com/en/sysdig-secure/risks/ ; https://github.com/prowler-cloud/prowler/blob/master/api/src/backend/api/attack_paths/queries/aws.py | Cortex (rule + Search before save), FCN Explorer policies (max 40), J1 alert rules, Carto rules (39), Qua numbered insights | **partial†** | §5: `internal/attackpath/rules.yaml` (11 rules); §19 `scan.attack_rules_file` key; no preview, no privesc library |
| AP5 | Choke points and blast-radius drill-in | **MDC/MSEM**: choke point → "View blast radius" of every path through it. **SCC** chokepoint issues: "fix one → closes many" | https://learn.microsoft.com/en-us/security-exposure-management/work-attack-paths-overview | Orca, Upwind, XM, BloodHound (BASE §1) | **partial** | §5: choke points = 10 nodes on most paths (inflated by prefix paths); blast radius BFS; Python copilot has a different implementation |
| AP6 | Minimum fix set ("break the path") | No vendor computes the minimum-cost set of changes that breaks all paths (BASE "Where nimbus can win" #2). Nearest: SCC/MDC choke points, Upwind hotspots | https://docs.cloud.google.com/security-command-center/docs/toxic-combinations-overview | — | **partial** | §5: greedy weighted set cover (`MinFixSet`, `traversal.go:530-562`), not max-flow; never re-verified; fix attributed to the edge target (INV defect 18) |
| AP7 | Exposure accuracy and noise cuts (width, trusted ranges, dead ends) | **MDC** exposure width (wide/narrow) + Trusted IPs. **XM**: "74% of identified exposures are dead ends" filter | https://learn.microsoft.com/en-us/azure/defender-for-cloud/internet-exposure-analysis ; https://xmcyber.com/blog/xm-cybers-2025-milestones-and-what-they-mean-for-you/ | Ten (trusted vendor), FCN (internet exposure yes/no/unknown) | **absent†** | §1: every LoadBalancer/NodePort counted internet-exposed (`k8s.go:451-468`); Azure NIC/subnet NSG combined with OR (`build.go:236-255`) |
| AP8 | Network reachability engine (routes, NACLs, LBs) | **ASH** reachability trait from CSPM/GuardDuty/Inspector; plan bar is Wiz network exposure (IMPLEMENTATION_PLAN 2.2) | https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-supported-traits.html | MDC, Orca, Upwind (observed traffic), FCN (ignores NACLs) | **partial†** | §1: SG/NSG/firewall-rule edges only; GCP priority and deny rules ignored (`gcp.go:242-263`) |
| AP9 | Validated exploitability (probes with evidence) | **S1** Verified Exploit Paths: each issue has an "Exploit Evidence" tab. **ASH** Network Scanning probes from outside | https://www.sentinelone.com/platform/singularity-cloud-native-security/ ; https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-network-scanning/ | Wiz Red Agent, Orca Red Pod, Qua TruConfirm, Ten scanner, SCC External Exposure, Sweet Attack, Pentera | **absent†** | No probe code listed in INV |
| AP10 | Path diff: scan-to-scan and plan-time in PRs | Plan-time: **no vendor** (BASE "Where nimbus can win" #3; STRAT §4h). Over time: **MDC** attack paths over time | https://learn.microsoft.com/en-us/azure/defender-for-cloud/how-to-manage-attack-path | — | **absent†** | §4: no history; §7 HCL scanner reads HCL, not plan JSON |

## 3. Risk prioritization

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| RP1 | Contextual 0–10 score with explainability, calibration and versioning | **FCN** Explorer Risk Score: published bands, risk = max over paths, Factors icons, top-3 paths dialog, "no data" ≠ 0. Versioning: **MDC** "New" tag + change log | https://docs.fortinet.com/document/forticnapp/latest/administration-guide/630805/explorer-risk-score ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes | Orca 1–10, R7 0–1000 published factors, Cortex SmartScore, J1 0–10 with KEV floor | **partial** | §6: Go sigmoid (`risk.go:204`) and Python logistic (`risk.py:218`) are different formulas; Python score swapped in but Go band kept (`scan.go:444-450`); nothing tests the merge |
| RP2 | Exploit intel (EPSS, KEV, in-the-wild) | **Cortex** CVRS 0–100 daily: CVSS, EPSS, KEV, exploit maturity, exposure, package-in-use, compensating controls, with an Evidence breakdown | https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/vunerability-management/cortex-vulnerability-risk-score | Sysdig, DD, ASH (EPSS), Wiz (KEV), Carto (OSS enrichment), J1 | **absent†** | §6: "No EPSS, KEV or exploit availability" |
| RP3 | Asset criticality / crown jewels | **MDC/MSEM** critical assets: predefined + custom rules, dynamic reclassification from DLP activity | https://learn.microsoft.com/en-us/security-exposure-management/whats-new | SCC high-value configs (≤1,000 per cloud, BASE §1), CP Business Priority rules, CS AI criticality | **partial†** | §6: criticality guessed from names/tags; §19: `crown_jewels` read by a separate raw parse |
| RP4 | Compensating-control-aware scoring | **ZS** UVM lowers the score when a control already blocks the path; weights are user-tunable | https://www.zscaler.com/products-and-solutions/vulnerability-management | FCN (inline NGFW adjustment with explainability entry), CP (WAF coverage), Cortex (compensating controls add-on) | **absent†** | Not in §6 input table |
| RP5 | Finding lifecycle: resolve, reopen, auto-close | **Sysdig** risks close automatically when the condition clears; **SCC** issues auto-resolve | https://docs.sysdig.com/en/sysdig-secure/risks/ ; https://docs.cloud.google.com/security-command-center/docs/issues-overview | DD, ASH plan status (New/Updated/Resolved) | **absent†** | §4: "Findings are never resolved: writes are upsert only" |
| RP6 | Cross-tool dedup and normalization | **J1** UVM "one row per CVE per asset" across CrowdStrike, Qualys, S1, Tenable, Wiz | https://docs.jupiterone.io/features/vulnerability-management | R7 (normalizes Tenable/Qualys), MDC (Wiz/Prisma/Tenable connectors), ZS AnySource, ASH correlation | **real** (catalog) / **partial** (adapters) | §3: 75 canonical checks with per-tool aliases, no collisions; §2: Trivy CVEs collapse (`model.go:140`); some aliases semantically wrong |
| RP7 | Mutes with mandatory reason and expiry | **DD** suppressions with expiration date; **Prow** mutelist keeps muted findings as `Suppressed` (BASE §2, §9) | https://docs.datadoghq.com/ko/security/suppressions | MDC exemptions, SCC mute configs | **partial†** | §9: JSON suppressions with globs and expiry (`dispatch.go:69`) |
| RP8 | Governance: owner, SLA, due dates, digests | **MDC** governance rules: owner from tag, SLA 7/14/30/90 d, grace period, weekly owner email, on-time/overdue report | https://learn.microsoft.com/en-us/azure/defender-for-cloud/governance-rules | DD inbox due dates, J1 owner teams, ZS SLA exception workflow | **partial†** | §6: Go risk carries Band/SLA/DueAt; §19 account `owner` key |

## 4. Identity / CIEM

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| ID1 | Effective-permission evaluation (Deny, NotAction, conditions, SCP/RCP, boundaries) | **ASH** Impact trait: identity + resource policies + SCPs + RCPs, with privilege-escalation chains labelled per hop | https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-supported-traits.html | Wiz CIEM (SCPs, RCPs, boundaries), Ten, R7 Access Explorer, Cortex, PMap (OSS, dormant) | **partial†** | §1: `IsAdmin` ignores NotAction/NotResource (`policy.go:132-153`); `DataAccess` ignores Deny and Conditions (`policy.go:176-201`) |
| ID2 | Privilege-escalation path detection | **Prow** ~70 privesc queries modelled on pathfinding.cloud (AWS, OSS) | https://github.com/prowler-cloud/prowler/blob/master/api/src/backend/api/attack_paths/queries/aws.py | Wiz, ASH, DD trust paths, PMap, Cloudsplaining | **absent†** | §1 graph edges: `can_assume`, `has_policy`, `grants_access_to`; no escalation edges |
| ID3 | "Who can reach X" (direct + transitive, with granting statement) | **FixInv** permission-weighted IAM edges; **DD** Access Insights (direct/indirect principals) | https://github.com/someengineering/fixinventory ; https://docs.datadoghq.com/security/cloud_security_management/identity_risks/ | Orca, Wiz CIEM Explorer, ASH internal access analyzer ($9/resource/region/month) | **partial†** | §1: `grants_access_to` edges from `DataAccess`, which ignores Deny |
| ID4 | Least privilege: unused permissions → right-sized policy as code; policy lint and risk taxonomy | **Cortex** Review Unused Permissions → Adjust Policy as JSON/Terraform/CFN. **DD** Suggested Policy as Terraform PR. Lint: **Parliament**; taxonomy: **Cloudsplaining** (5 categories) | https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/cortex-cloud-identity-security/achieve-the-principle-of-least-privilege-access ; https://github.com/salesforce/cloudsplaining | FCN (180 d, % removed), Sysdig (3 strategies), Orca (90 d), R7 LPA (90 d), MDC CIEM (90 d) | **absent†** | §1: only `iam_user_accesskey_unused`; no CloudTrail/Access Advisor usage collection |
| ID5 | Azure RBAC and GCP IAM bindings | **Ten**: effective permissions across AWS, Azure, GCP, Entra ID, Google Workspace | https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-multi-cloud-risk-analysis-attack-surface-assessments | Wiz, MDC CIEM, R7, Cortex | **absent†** | §1: Azure "no identity/RBAC checks, and no identity edges"; GCP "Project IAM policy is never collected" |
| ID6 | Kubernetes RBAC and service-account analysis | **Kube**: 290 controls incl. access-control risks, VAP admission | https://github.com/kubescape/kubescape | Trivy Operator (RBAC assessment), Sysdig KSPM | **partial** (§1) | §1: 7 K8s checks; RoleBindings to admin/wildcard not checked (`k8s.go:408-415`); pod→SA→cluster-admin gives 0 paths (defect 9) |
| ID7 | Privilege enforcement: org guardrails, zombie quarantine, JIT | **Son** Cloud Permissions Firewall (SCP/RCP, quarantine, region/service lock, JIT that escalates at 1 h and expires at 24 h). JIT UX: **Ten** Slack/Teams with self-revoke | https://docs.sonraisecurity.com/cpf-public/overview/permissions-firewall-intro/ ; https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation | Orca (AWS JIT via Slack), CP IAM Safe leases, Britive, BeyondTrust Entitle | **absent†** | Not in INV |

## 5. Data / DSPM

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| DS1 | Sensitive-data classification, custody-safe | **Cortex**: 6 data profiles + custom, OCR on by default, masks three samples per pattern per object, masked before leaving the environment. Custody: **Sentra** in-account ephemeral scanners | https://cortex-docs.paloaltonetworks.com/cortex-xsiam/cloud-security/cortex-cloud-data-classification ; https://sentra.io/learn/wiz-dspm-alternatives | MDC (sampling up to 20 MB/file, 300–1,024 rows), Orca (OCR), Wiz, FCN (full-text, preview), Macie (S3 only), Cyera | **absent†** | §6: data sensitivity is "name/type/tag guesses only. 'hr' matches as a substring, e.g. 'three'" |
| DS2 | DSPM interop (ingest labels, push context) | **Proofpoint DSPM ↔ Wiz**: daily Wiz Issue pull, push of classification to raise Wiz severity | https://docs.public.analyze.proofpoint.com/dspm/guide/getting-started/integrations-setup/wiz.htm | CP ERM (Sentra/Cyera accounts), Sentra→Wiz, Cyera↔Wiz | **absent†** | No DSPM adapter in §2 |
| DS3 | Data-aware path scoring | **Sysdig**: sensitive data appears inside attack paths; **ASH** Sensitive Data trait (Macie, S3 only) | https://www.sysdig.com/blog/defending-sensitive-data-with-sysdig-secure | Wiz, Orca, FCN (Data impact column), R7 (via Symmetry) | **partial†** | §6 data weight from name heuristics; §5 `stores_data_in` edge is never emitted |

## 6. Vulnerabilities, secrets, SBOM

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| VS1 | CVE and image findings ingested from scanners | **Trivy**: one binary for CVE, misconfig, secrets, licence, SBOM; `convert` re-renders saved JSON | https://trivy.dev/latest/docs/configuration/reporting/ | Wiz UVM, J1 UVM, R7, MDC registries (daily rescans if pushed/pulled in 30 d) | **partial** (§2) | §2: Trivy adapter drops CVSS/PrimaryURL; CVEs labelled provider=kubernetes; package missing from fingerprint (`model.go:140`) |
| VS2 | Agentless workload snapshot scanning | **Orca** SideScanning: reads block storage out of band, rebuilds a read-only filesystem across VMs, containers, serverless | https://orca.security/platform/agentless-sidescanning/ | Wiz, MDC, DD (12 h), FCN AWLS, CS, Qua FlexScan, Ten (2–7 days), Sysdig, SCC | **absent†** | Not in INV (IMPLEMENTATION_PLAN 2.3 only) |
| VS3 | Reachability tiers for vulnerabilities | **Orca**: agentless "could execute", dynamic (loaded/executed), code (function called) | https://orca.security/resources/blog/dynamic-reachability-analysis/ | Sysdig In Use (no .NET/PHP/Rust), Upwind function-level, Cortex package-in-use | **absent†** | Not in INV |
| VS4 | Secrets detection with live validation | **S1**: 850+ secret types, each validated for active use | https://www.sentinelone.com/platform/singularity-cloud-native-security/ | DD secret scanning (validates), MDC VM secrets, Chk/Trivy (detect only) | **partial†** | §2: Checkov/Trivy secrets ingested ("every secret forced to CRITICAL"); §1: Secrets Manager collected but no check runs |
| VS5 | SBOM handling, feed re-evaluation, emerging threats | **Aqua** smart rescan of unchanged digests against new CVEs; **J1** Emerging Threats (escalation tiers, scanner-gap flag); **Cortex** Supply Chain Attack Threat Center | https://www.aquasec.com/blog/can-vulnerability-scanning-tell-you-what-youre-exposed-to-right-now/ ; https://www.jupiterone.com/blog/announcing-emerging-threats | DD SBOM export, FCN SBOM, Sysdig base-image allow/deny | **absent†** | No SBOM ingest in §2; §16 no release SBOM |

## 7. IaC & code-to-cloud

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| IC1 | IaC misconfiguration scanning (incl. plan JSON) | **Chk**: 1,183 Terraform check files, YAML graph policies, Terraform plan scanning. Breadth: **KICS** (Pulumi, Crossplane) | https://github.com/bridgecrewio/checkov ; https://docs.kics.io/latest/results/ | Trivy, Wiz Code, Orca, Cortex, DD, Sysdig, FCN, R7 IaC CLI | **partial** (§7) | §7: native HCL scanner 20 rules; vars/modules/`jsonencode` skipped; panics on unknown bool expressions (`iac.go:366-367`); other formats need checkov/trivy |
| IC2 | Cloud-to-code mapping (file, line, owner) | **Wiz Code** via Terraform state: exact file, line, module, author, code owners (BASE §3) | https://www.wiz.io/blog/the-missing-link-in-code-to-cloud-visibility-is-finally-here | Prisma/Cortex (Yor), Aqua tracing, MDC code-to-runtime, Sysdig, Upwind (developer + commit) | **partial** (§7) | §7: tfstate → `type.name`; module prefixes ignored; name collisions first-wins |
| IC3 | Code-to-cloud coverage gaps and ClickOps drift | **Cortex** Code-to-Cloud Coverage dashboard: shows untraced SDLC stages with one-click onboarding | https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/code-to-cloud/code-to-cloud/execute-remediation-workflows | Prisma Yor drift (BASE §3), Sysdig drift PRs | **absent†** | Not in INV |
| IC4 | CI integration: Action, SARIF, gating, baseline | **Trivy/Chk** Actions + SARIF upload (trivy-action used by 55,417 repos, checkov-action by 7,654 per STRAT §5.1) | https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning | KICS, Kube, Prow Action, Orca CLI, wizcli, Upwind | **partial** (§15) | §15: SARIF 2.1.0 real; Action broken by the stored-findings bug; installs `curl … main/install.sh \| bash` unpinned |
| IC5 | IDE, pre-commit and coding-agent hooks/hand-off | **FCN** Claude Code plugin: scans changed files, auto-fixes critical/high, blocks the commit. **DD** "send to coding agent" prompt | https://docs.fortinet.com/document/forticnapp/latest/release-notes/499403/august-2026-platform-releases ; https://docs.datadoghq.com/security/code_security/iac_security/ | Sysdig skills, Wiz guardrails, Prow Claude Code plugin, Vanta `/fix-test`, Snyk VS Code (BASE §10) | **partial** (§15) | §15: VS Code quick fix fails on a fresh workspace; 0 extension tests; hook omits `--no-store` |

## 8. Remediation

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| RM1 | Fix templates and AI fixes with structured plan content | **Qua** 2.28: Terraform/CLI/Python/native code + numbered steps + verification step. **CS**: permissions required, validation checks, compensating controls | https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_28.htm ; https://www.crowdstrike.com/en-us/blog/falcon-cloud-security-third-party-app-insights-ai-enhanced-remedation/ | ASH (8 snippet formats), Orca, Wiz AI remediation 2.0, Secureframe | **partial** (§7) | §7: 42 templates cover 36 of 75 IDs; dangerous templates; suggests `terraform apply -auto-approve`; §12 `fix --ai` shallow validation |
| RM2 | IaC patch + fix PR | **Prisma/Cortex** one-click commit suggestion; **Wiz** AI remediation 2.0 strategy choice; **DD** Terraform PR (BASE §3) | https://www.wiz.io/blog/introducing-ai-powered-remediation-2-0 | Orca one-click PR, Sysdig PR, Upwind Green agent PRs, MDC Copilot ADO PR, Cortex AppSec agent | **partial** (§7) | §7: patcher hits the wrong resource (`iac.go:556`); PR flow writes the wrong file (`fix.go:230` vs `gitops.go:121`); gitops 0% coverage |
| RM3 | Root-cause plans, hotspots, missions | **ASH** remediation plans: one plan per target resource, "resolves N / reduces M", phases Prerequisite→Snapshot→Fix→Verify→Done with rollback per step | https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-remediation-plans.html | Upwind hotspots, R7 Top Remediations, Orca Missions, SCC chokepoint issues, MSEM initiatives | **partial†** | §5: `MinFixSet` greedy set cover; no plan object |
| RM4 | Verified remediation (targeted rescan, confirmation) | **XM** Remediation Confirmation; **Prow** 5.44 partial scans (≤10 `resource_uids`); **Orca** Jira close → rescan | https://github.com/prowler-cloud/prowler/releases/tag/5.44.0 ; https://orca.security/partners/technology/jira-by-atlassian/ | Veza remediation validation, Qua verification, Ten Hexa verify | **absent†** | §4 no lifecycle; §7 `verifyPatch` passes when it cannot create its temp file and never runs `terraform validate` |
| RM5 | Policy-bound automation with simulate/approve modes | **Wiz** Workflows: confidence-gated auto vs Slack approval; runtime Simulate→Block | https://www.wiz.io/blog/introducing-wiz-agents | C7N event mode + dry-run, SP Flowpipe `input` approvals, CP CloudBots `AUTO:`, R7 Bots, Son Pending Changes, Qua Agent Sara waves | **absent†** | No remediation engine in INV |
| RM6 | Preventive guardrails (admission policies, org policies) | **Kube** `vap deploy-library` (CEL ValidatingAdmissionPolicies); **MDC** Enforce/Deny | https://github.com/kubescape/kubescape | Son SCP generation, CS admission controller, S1 admission | **stub†** | §12: 8 Rego files "never evaluated, so this is a stub" |

## 9. Compliance & evidence

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| CO1 | Framework breadth | **Orca** "185+" frameworks and 2,500+ controls (page counts vary: 150+/180+/185+) | https://orca.security/platform/cloud-infrastructure-entitlement-management-ciem/ | Cortex (151 standard rows), Wiz 100+, Prow 105 JSON files (tree count), SP "5,000+ controls", DD 1,300+ rules, MDC | **partial** (§8) | §8: 11 frameworks, hand-written; NIST 800-53 has 30 of ~1,000 controls |
| CO2 | Mapping accuracy, versioning and integrity tests | **Prow** 5.42 catalog integrity test; 5.43 "universal" cross-provider FedRAMP 20x frameworks | https://github.com/prowler-cloud/prowler/releases/tag/5.43.0 | Carto rules with count-query denominators | **partial** (§8) | §8: PCI labelled 4.0 uses 3.2.1 IDs; Go/Python counts differ (cis_aws 42 vs 19); 16 referenced controls absent |
| CO3 | Custom frameworks and control editor | **S1** Custom Compliance: control → sub-control → rule tree blending 45+ frameworks; **Drata** JSON advanced editor with line-level validation | https://www.sentinelone.com/blog/custom-compliance-for-cloud-security/ ; https://help.drata.com/en/articles/13403932-advanced-editor-in-the-test-builder | Cortex, FCN, SCC Compliance Manager, DD Test Rule, Wiz | **partial** (§8) | §8: custom frameworks lose their inventory (`cli/report.go:56`) |
| CO4 | Evidence packages for auditors | **AWS Audit Manager** layout (by control, by source, by date + digest) — closed to new customers since 2026-04-30; **Drata** Audit Hub | https://docs.aws.amazon.com/audit-manager/latest/userguide/doc-history.html | Cortex audit-ready evidence (May 2026), Aqua, Thoropass | **partial** (§8) | §8: evidence ZIP with per-control `evidence.json` + SHA-256 manifest; `zw.Close` errors ignored; unsigned |
| CO5 | Continuous cadence, period coverage and score progress | **Vanta** hourly, 1,200+ tests/hour; **Upwind** 13-month lookback and "Score Journey" with per-finding impact and difficulty | https://cipherssecurity.com/vanta-vs-drata/ ; https://www.upwind.io/feed/introducing-the-new-configurations-experience-in-upwind | SCC 16 h/38 h + near-real-time, Drata daily, MSEM initiatives | **absent†** | §4 no history; §10 polling only |
| CO6 | GRC export (Vanta/Drata) | **Vanta** custom resources API: full-state PUT, flat properties, custom tests re-run on push | https://developer.vanta.com/docs/concepts/resources.md | Wiz→Vanta connector | **absent†** | Not in §9 sink table |
| CO7 | Access-review campaigns | **Veza** access reviews with automatic remediation validation | https://veza.com/blog/veza-product-updates-june-2025/ | Drata (non-frozen snapshots), Saviynt | **absent†** | Not in INV |

## 10. Detection, real-time, CDR

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| DR1 | Event-driven change detection | **C7N**: auto-provisioned serverless policies on CloudTrail/Event Grid/Audit Log, seconds latency, dry-run | https://github.com/cloud-custodian/cloud-custodian | R7 EDH, Qua EventBridge/EventGrid, Trivy Operator, SCC near-real-time compliance | **partial** (§10) | §10: polling every 2 min; 20 CloudTrail / 5 Azure / 5 GCP events; errors swallowed; late events lost |
| DR2 | Cloud-log threat and identity detections | **ASH GuardDuty** Extended Threat Detection attack sequences; **Wiz Defend** detections on the posture graph | https://aws.amazon.com/about-aws/whats-new/2025/12/guardduty-extended-threat-detection-ec2-ecs/ ; https://www.wiz.io/blog/introducing-wiz-defend | FCN Polygraph v2, S1 Wayfinder, SCC ETD, Ten CDR, Permiso (ITDR) | **partial†** | §10: events become `monitor` findings; no correlation; GCP raises HIGH on every SetIamPolicy |
| DR3 | Runtime (eBPF) detection and response | **Sysdig** Falco with 5/5/5 benchmark and Cloud Response Actions + Response History | https://sysdig.com/555-benchmark/ | Wiz, Orca, Cortex, CS, S1, Aqua, Upwind, Sweet, DD, Qua, R7 (ARMO) | **absent** | Non-goal in `.planning/PROJECT.md` |
| DR4 | Runtime↔posture correlation and investigation timeline | **SCC** Correlated Threats (hourly graph rules); **CS** Timeline Explorer (beta) | https://docs.cloud.google.com/security-command-center/docs/correlated-threats-overview ; https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-industry-first-adversary-informed-cloud-risk-prioritization-to-stop-ai-powered-adversaries/ | Qua TruRisk Insights, Ten threat stories, Wiz Incident Stories, Upwind timeline | **absent†** | Not in INV |

## 11. Integrations & workflow

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| IW1 | Notification/SIEM sinks with routing and dedup | **DD** cross-rule notification rules; **J1** "newly discovered results only" alert mode | https://docs.datadoghq.com/security/notifications/ ; https://docs.jupiterone.io/features/insights-and-alerts/alerts | Upwind 100+ integrations, Sweet, Orca per-channel routing | **partial** (§9) | §9: 11 targets from 7 sinks; no retries; only `min_severity` reachable from config (`root.go:203`) |
| IW2 | Bidirectional ticketing with auto-close on fix | **DD** field-level two-way Jira; ticket auto-closes when remediated or muted (BASE §9) | https://docs.datadoghq.com/security/ticketing_integrations | Orca, ZS UVM (two-way, reopen), J1 (auto-resolve), Sysdig (status mapping) | **partial** (§9) | §9: auto-close works only for GitHub; PagerDuty resolve is dead code |
| IW3 | Third-party scanner ingestion into one model | In OSS, **no tool** puts Prowler, Checkov, Trivy and Steampipe output into one graph (STRAT §4a). Commercial: **MDC/MSEM** ingests Wiz/Prisma/Tenable | https://learn.microsoft.com/en-us/security-exposure-management/whats-new | R7, ZS AnySource, J1, ASH (AWS sources only) | **partial** (§2) | §2: 6 parsers with golden tests; no Prowler v3 fixture; runner 0% coverage |
| IW4 | Standard output formats (SARIF, OCSF, ASFF, CI formats) | **KICS** 11 formats incl. GitLab SAST, SonarQube, Code Climate, ASFF; **Prow** OCSF by default | https://docs.kics.io/latest/results/ ; https://docs.prowler.com/user-guide/cli/tutorials/reporting | Trivy, kube-bench (`--asff`), SP | **partial†** | §15 SARIF real; §14 scan outputs table/json/sarif/dashboard/markdown/summary — no OCSF or ASFF writer |

## 12. Dashboard & reporting UX

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| UX1 | Home dashboard with drill-through | **Cortex** Cloud Command Center: provider health, asset class at-risk, cases with created-vs-resolved trend, weaponized/fix-available vulns, compliance | https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/dashboards-and-reports/monitor-dashboards-and-reports/dashboard-reference/command-center-reference/cortex-cloud-command-center | MDC, ASH Executive/Triage tabs, FCN | **not audited** | INV header: `internal/dashboard/*` excluded |
| UX2 | Trends, MTTR, SLA | **J1** trend widgets (daily snapshots, sparkline + %) and UVM time-to-remediate | https://docs.jupiterone.io/features/insights-and-alerts/insights | MSEM initiatives (14-day trend), ASH (1 year history), DD | **absent†** | §4 no history |
| UX3 | Executive and offline reports | **MDC** CNAPP Executive Summary PDF (GA 2026-06-30); offline: **ScoutSuite** self-contained HTML with all config | https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes ; https://github.com/nccgroup/ScoutSuite | Qua report builder, R7 scheduled reports, SCC PDF | **partial†** | §8: Python HTML/PDF/MD/JSON; Go MD/JSON |
| UX4 | Cost + security | **Infracost** PR cost delta and FinOps policy (BASE §7) | https://www.infracost.io/resources/blog/new-finops-policies-tfsec-creators-join-infracost | C7N off-hours, Trusted Advisor | **partial** (§11) | §11: hard-coded single-region prices; ROI = `$4.88M × (1−e^(−Σscore/50))`; savings double counted |

## 13. AI assistant & agent interfaces

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| AI1 | NL→query assistant that shows its logic, incl. offline mode | **Upwind** Choppy AI compiles NL into editable Query Builder expressions. Offline: **FCN** identifier-paste search and NL templates without an LLM | https://www.01net.it/upwind-launches-choppy-ai-introducing-transparent-natural-language-intelligence-across-its-runtime-first-cloud-security-platform ; https://docs.fortinet.com/document/forticnapp/latest/release-notes/794745/june-2026-platform-releases | Wiz AskAI, Orca, Sysdig Sage, J1 (multiple candidates), MDC Copilot, Cortex AgentiX | **partial** (§12) | §12: NL→SQL + summary; 10+ regex intents offline; `_binary_fix` renders stored findings (`fix.py:221`) |
| AI2 | BYO-LLM including local models | **Prow** Lighthouse: OpenAI, Bedrock, OpenAI-compatible endpoints (OpenRouter, Ollama), tool-calling models only | https://docs.prowler.com/getting-started/products/prowler-lighthouse-ai | Orca (multiple backends), Aqua (customer OpenAI key) | **partial†** | §12: "Anthropic only" |
| AI3 | MCP server and agent skills | **Sysdig**: Go Apache-2.0 MCP server that filters tools by token permissions; Headless skills for Claude Code, weekly drops | https://github.com/sysdiglabs/sysdig-mcp-server ; https://www.sysdig.com/press-releases/sysdig-headless-cloud-security | Wiz, Orca, DD (SQL tools), ASH MCP App, J1, R7 (OSS bulk-export MCP), Prow, SP, Kube, Vanta, SCC (preview), Ten, S1, FCN plugin | **absent†** | Not in INV |
| AI4 | Agent guardrails (scope, approvals, plan view, audit) | **Cortex AgentiX**: invoking user's RBAC, assigned actions only, sensitive actions need approval, plan view, audit dataset | https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/get-started/agentic-ai-in-cortex-cloud/agentic-assistant-security | Wiz (evidence-backed, confidence gating), Son (Pending Changes), S1 (verdict justification), Prow (read-only) | **partial†** | §12: SQL on `mode=ro` + `query_only` but no timeout; finding JSON passed into prompts unwrapped |
| AI5 | Agentic triage/remediation routines | **Ten** Hexa AI always-on fleet with scheduled routines and Agent Center; **Wiz** Red/Blue/Green agents | https://www.tenablecloud.cn/press-releases/tenable-delivers-the-industrys-first-always-on-agentic-fleet-for-exposure-management ; https://www.wiz.io/blog/introducing-wiz-agents | Orca pods, Upwind Agentic Pack, Qua agent marketplace, CS Charlotte | **absent†** | Not in INV |

## 14. Platform (API, CLI, config-as-code, RBAC, SSO, multi-tenant, deploy)

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| PF1 | CLI and extensibility SDK | **Trivy/Prow** single CLIs; SDKs: **SP** Go plugin SDK, **CQ** multi-language SDK | https://github.com/cloudquery/plugin-sdk | Kube, cnspec (MQL shell) | **real** (§14) | §14: 22 top-level / 25 leaf commands; no `init`/`doctor`/`validate`; §19 Python `@check` SDK is real |
| PF2 | API server, secure by default | **Orca** OpenAPI REST + CLI; **Ten** GraphQL with cursor pagination | https://developer.tenable.com/docs/cloud-security-integrations | J1, Son GraphQL, R7 | **partial (insecure)** | §13: no auth on reads or `/api/query`; binds `:8080` on all interfaces; CSRF; no Host check |
| PF3 | Config-as-code and validation | **Orca** Terraform provider (users, Business Units, views, dashboards, alert rules, RBAC) | https://orca.security/resources/blog/expanding-cloud-security-automation-orca-terraform/ | Upwind provider, CP `dome9_ruleset`, FCN `codesec.yaml` | **partial** (§19) | §19: nothing validated; literal secrets allowed; `neo4j.*_env` keys silently ignored |
| PF4 | RBAC, SSO, multi-tenant | **Wiz** Tenant Manager: smart tenant groups, baseline policies with overrides, audited tenant access | https://www.wiz.io/ko-kr/blog/wiz-tenant-manager-multi-tenant-security | Orca Business Units, FCN orgs (max 100 accounts), MDC cloud scopes, Sysdig Zones | **absent** (§20) | §20: SQLite only; one optional shared token on `POST /api/scan` |
| PF5 | Packaging and deployment | **Trivy**: brew, Docker (128.3M pulls), every package manager (STRAT §2.1) | https://github.com/aquasecurity/trivy | Prow (PyPI/Docker/Compose), Kube (Helm), C7N | **stub** (§16) | §16: no goreleaser/tap/image; version hard-coded `0.1.0`; 212 MB binary |
| PF6 | Storage backends and scale | **Prow** sink choice Neo4j or Neptune; **CQ** ~20 destinations | https://github.com/prowler-cloud/prowler | Carto (Neo4j only) | **partial†** | §20 SQLite only; §5 traversal caps 20,000 frames per entry point with silent truncation |

## 15. Trust & supply chain

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| TS1 | Signed releases, SBOM, provenance | **C7N** c7n-left Wolfi images verified with cosign | https://github.com/cloud-custodian/cloud-custodian/tree/main/tools/c7n_left | Carto (Scorecard 8.4), Wiz (signed Helm charts) | **stub** (§16) | §16: "goreleaser, Homebrew tap, release workflow, signing, SBOM, provenance" all missing |
| TS2 | Immutable releases, pinned actions, verified installers | Lesson from **Trivy** GHSA-69fq-xp46-6x23: v0.69.3 and trivy-action 0.35.0 were safe because immutable releases were on; pin SHAs, verify cosign | https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23 | — | **stub** (§16) | §16: `install.sh` no checksum/signature; Action and Dockerfile `curl \| sh` from `main` (defect 13) |
| TS3 | Least-privilege read-only onboarding | **MDC** scoped scanner roles, snapshot actions tag-conditioned; **Prow** External ID | https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-data-collection | Son (read-only org role), Sysdig onboarding roles | **partial†** | §14: `onboard` shells out to cloud CLIs; no generated policy; §17: config allows literal tokens and `onboard` persists them |
| TS4 | Verified against live clouds / public benchmark | **No vendor or OSS project publishes path-level ground truth** (STRAT §7.3) | STRAT §7.3 (no URL; absence claim) | — | **absent** (§18) | §18: "E2E against real clouds: none" |

## 16. Ecosystem interop

| ID | Capability | Best-in-class and what "best" looks like | Source | Others with it | nimbus status | INV evidence |
|---|---|---|---|---|---|---|
| EI1 | Cartography schema import/export | **Carto** published schema; Prow runs its attack paths on it | https://docs.cartography.dev/usage/schema.html | Prow | **partial†** | §5: Neo4j push with Cartography-style labels (export only) |
| EI2 | Prowler content reuse (findings history, frameworks, path queries) | **Prow** OCSF default, 105 framework JSONs, ~100 path queries (all Apache-2.0) | https://github.com/prowler-cloud/prowler/tree/master/prowler/compliance | — | **partial†** | §2: Prowler OCSF/v3 adapter (no v3 fixture); §3: 58 catalog entries carry prowler aliases |
| EI3 | Steampipe compatibility | **SP** table names + Postgres wire protocol | https://github.com/turbot/steampipe | — | **partial** (§4) | §4: passthrough shells out to `steampipe query`, no timeout, random column order, not reachable over HTTP; §2 CIS tag mapping dead (`steampipe.go:119`) |
| EI4 | Policy and warehouse interop (Custodian YAML, Parquet/Iceberg, warehouses) | **CQ** Arrow transport to ~20 destinations; **Matano** Iceberg + ECS (dormant) | https://github.com/cloudquery/cloudquery | C7N policy YAML, Security Lake (OCSF Parquet) | **absent†** | Not in INV |

---

## Market signals

### Consolidation, rebrands and end-of-life events
| Event | Date | Source |
|---|---|---|
| Google closed the $32B Wiz acquisition; Wiz keeps its brand and says it stays multi-cloud | 2026-03-11 | https://www.googlecloudpresscorner.com/2026-03-11-Google-Completes-Acquisition-of-Wiz ; https://www.wiz.io/blog/google-closes-deal-to-acquire-wiz |
| Google SCC Enterprise (multi-cloud) tier deprecated; shutdown on or after 2027-05-21 | 2026-05-21 | https://docs.cloud.google.com/security-command-center/docs/deprecations |
| Google SCC DSPM deprecated; shutdown on or after 2027-02-01 | 2026-09-14 | https://docs.cloud.google.com/security-command-center/docs/deprecations |
| SCC Artifact guard CI/CD integration deprecated; shuts down 2026-10-30 | 2026-10-06 | https://docs.cloud.google.com/security-command-center/docs/release-notes |
| Zscaler Posture Control end-of-sale 2025-03-15, end-of-life 2026-03-15 (second Zscaler posture sunset after ZCSPM) | 2026-03-15 | https://help.zscaler.com/product-usage-terms/end-sale-end-life-notice-zscaler-posture-control-zpc |
| Check Point moving CloudGuard CNAPP customers to Wiz; combined offer GA | 2025-10-15 | https://www.channelinsider.com/security/check-point-wiz-cnapp-cloud-security/ |
| Prisma Cloud became Cortex Cloud; 2.0 GA 2025-10-28; 2.2 in July 2026 | 2025-02-13 | https://investors.paloaltonetworks.com/news-releases/news-release-details/palo-alto-networks-introduces-cortex-cloud-future-real-time |
| Fortinet closed Lacework (now FortiCNAPP) | 2024-08-01 | https://www.fortinet.com/corporate/about-us/newsroom/press-releases/2024/fortinet-completes-acquisition-of-lacework |
| AWS Audit Manager closed to new customers | 2026-04-30 | https://docs.aws.amazon.com/audit-manager/latest/userguide/doc-history.html |
| AWS split Security Hub: new Security Hub GA, old product renamed "Security Hub CSPM" | 2025-12-02 | https://docs.aws.amazon.com/securityhub/latest/userguide/doc-history.html |
| Defender CSPM folded into Exposure Management in the Defender portal; two Secure Score models | 2026-05-05 | https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes |
| Okta closed Permiso | 2026-08-26 | https://www.okta.com/newsroom/press-releases/okta-signs-definitive-agreement-to-acquire-permiso-security/ |
| ServiceNow signed to acquire Veza | 2025-12-01 | https://www.businesswire.com/news/home/20251201652471/en |
| Remediation M&A: Wiz ← Dazz ($450M), Orca ← Opus (undisclosed) | 2024-11 / 2025-05-13 | https://techcrunch.com/2024/11/21/wiz-acquires-dazz-for-450m-to-expand-its-cybersecurity-platform ; https://orca.security/resources/press-releases/orca-security-acquires-opus-ai-cloud-remediation/ |
| Sonrai pivoted from the Dig identity graph to the Cloud Permissions Firewall | 2025 | https://sonraisecurity.com/ |
| JupiterOne rebranded as an "AI Risk Management Platform" | 2026-05-13 | https://www.jupiterone.com/blog/say-hi-to-the-new-jupiterone-and-our-new-products |

### Pricing anchors (list or published only; third-party estimates labelled)
| Offering | Price | Source |
|---|---|---|
| Wiz Essential / Advanced (AWS Marketplace, 12 mo) | $24,000 / $38,000 per 100 workloads | https://aws.amazon.com/marketplace/pp/prodview-5geds7fc2wk7m |
| Wiz contracts (Vendr) | median $154,381/yr over 188 purchases (STRAT); a second source citing Vendr says ~$149k (CL) — see disagreements | https://www.vendr.com/marketplace/wiz ; https://cipherssecurity.com/wiz-pricing-guide-2026-cnapp-cost/ |
| Orca (AWS Marketplace) | $7,000–$30,000 per month in four bands; Vendr median $95,625/yr | https://aws.amazon.com/marketplace/pp/prodview-rogbt2k4b63xc ; https://www.vendr.com/marketplace/orca-security |
| Microsoft Defender CSPM | $0.007 per billable resource-hour (≈$5.11/resource/month, derived); Foundational CSPM free | https://prices.azure.com/api/retail/prices?$filter=contains(productName,'CSPM') |
| Google SCC Premium | 5% of annualized GCP spend, $15,000/yr minimum; or $0.0071 per vCPU-hour | https://cloud.google.com/security-command-center/pricing |
| AWS Security Hub Essentials | $3.75 per resource unit per month (plus ~8 other meters) | https://aws.amazon.com/security-hub/pricing/ |
| Datadog CSM Pro / Enterprise | $10 / $25 per host per month (annual) | https://www.datadoghq.com/pricing/list/ |
| Sysdig CNAPP Enterprise (AWS Marketplace) | $72 per host per month, min 20 | https://aws.amazon.com/marketplace/pp/prodview-of3ndsfqn2cwc |
| Prowler Cloud | $99 per cloud account per month | https://prowler.com/pricing |
| Sonrai | $150/account/month (site); $200/account/month reported on AWS Marketplace | https://sonraisecurity.com/pricing/ |
| JupiterOne | $25k / $50k / $100k tiers by ingested datapoints | https://www.jupiterone.com/pricing |
| Upwind (AWS Marketplace) | $30,000 per unit (unit undefined) | https://aws.amazon.com/marketplace/pp/prodview-ff3am62vjukrw |
| Qualys TotalCloud | Qualys Units; only VMs and serverless count for CSPM; $/QLU not public | https://www.qualys.com/qlu-pricing/ |

### Repeated buyer complaints
- **Price** — Wiz, Prisma/Cortex, CrowdStrike, SentinelOne, Aqua, Defender, AWS Security Hub (many meters). (CL "Cross-cluster complaints"; https://www.peerspot.com/products/wiz-pros-and-cons ; https://www.peerspot.com/products/aws-security-hub-reviews)
- **Noisy first scans and false positives** — Wiz, Orca, Aqua, Prisma, Rapid7, Drata. (https://www.rfp.wiki/vendors/orca-security ; https://www.peerspot.com/products/divvycloud-pros-and-cons ; https://soc2auditors.org/insights/drata-review/)
- **Weak executive dashboards and reporting** — Wiz, Upwind, SentinelOne, Sysdig, Aqua, Rapid7, Qualys, BigID. (https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ff3am62vjukrw ; https://www.peerspot.com/products/qualys-totalcloud-pros-and-cons)
- **Confusing UI** — Upwind, CrowdStrike, Lacework, Sysdig, Aqua, Tenable, Qualys, Defender. (CL/PL weakness sections)
- **Workflow gaps** — no bulk actions (Upwind), one-way ticketing (Aqua), Wiz tickets that "appear and disappear magically in hundreds", Jira rate limits dropping tickets (AWS). (https://hn.algolia.com/api/v1/items/43402941 ; https://docs.aws.amazon.com/securityhub/latest/userguide/jiracloud.html)
- **Opacity and churn** — Wiz closed docs and no public pricing; Google changed risk scores without notice on 2025-07-25 and 2026-03-27; Defender breaking changes. (https://hn.algolia.com/api/v1/items/43402941 ; https://docs.cloud.google.com/security-command-center/docs/release-notes)
- **Multi-cloud gaps in native tools** — Defender "has not helped me manage and secure multi-cloud"; Security Hub "only works for AWS" (now Azure-limited, no GCP). (https://www.peerspot.com/products/microsoft-defender-for-cloud-reviews ; https://www.peerspot.com/products/aws-security-hub-reviews)
- **"Which resource is failing?"** — Drata. (https://soc2auditors.org/insights/drata-review/)

### Supply-chain incidents touching security tooling
| Incident | Date | Source |
|---|---|---|
| Trivy v0.69.4 malicious release; 76 of 77 `trivy-action` tags and all 7 `setup-trivy` tags force-pushed; malicious Docker images v0.69.5/6 on 2026-03-22; root cause non-atomic credential rotation | 2026-03-19 | https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23 |
| KICS Docker tags replaced with an exfiltrating binary (attributed to TeamPCP) | 2026-04-22 | https://socket.dev/blog/checkmarx-supply-chain-compromise |
| Trivy plugin-manager path traversal (arbitrary file write) | 2026-06 | GitHub advisories API (OS §10) |
| Prowler HTML report stored XSS via unescaped tags (CVE-2026-73262) | 2026 | https://corgea.com/advisories/vulnerabilities/CVE-2026-73262 |

### Dormant, archived or relicensed OSS (migration targets)
| Project | State | Source |
|---|---|---|
| ScoutSuite | last release 5.14.0 on 2024-05-10; 0 commits in 12 months | https://github.com/nccgroup/ScoutSuite |
| PMapper | last release 2022-01-13; breaks on Python 3.10 | https://github.com/nccgroup/PMapper |
| OpenCSPM | archived | https://github.com/OpenCSPM/opencspm |
| Fix Inventory | last release 2024-12-05; fix.security did not resolve on 2026-10-09; licence churn | https://github.com/someengineering/fixinventory |
| Magpie, Matano | dormant (last push 2024-08-29 / 2025-01-08) | https://github.com/openraven/magpie ; https://github.com/matanolabs/matano |
| CloudSploit | no tagged release since 2024-11-15 | https://github.com/aquasecurity/cloudsploit |
| CloudMapper | network visualisation unmaintained; last push 2024-07-15 | https://github.com/duo-labs/cloudmapper |
| Terrascan | archived | STRAT §2.3 |
| Tracee | no release since 2025-11-19 | https://github.com/aquasecurity/tracee/releases |
| CloudQuery | official AWS/GCP/Azure plugins moved to paid (2024) | https://www.cloudquery.io/blog/cloudquery-official-free-plugins-moving-to-paid |
| Steampipe / Powerpipe / Flowpipe | AGPL-3.0 + CLA; cnspec is BUSL-1.1 | https://github.com/turbot/steampipe ; https://github.com/mondoohq/cnspec/blob/main/LICENSE |

### Analyst and RFP must-haves
- **Gartner Market Guide for CNAPP (2025-08-05):** artifact scanning, security guardrails, configuration and compliance management, risk detection and prioritization, behavioral analytics; SIEM/SOAR/TDIR integration now common; evaluate agentless visibility and runtime protection. (https://www.wiz.io/lp/2025-gartner-market-guide-for-cnapp ; https://start.paloaltonetworks.com/gartner-report-cloud-native-application-protection.html)
- **rfp.wiki CNAPP/CSPM template (21 criteria):** Product & Technology 43% (multi-cloud coverage, misconfig depth, identity posture, remediation automation, alert-noise control, IaC shift-left, runtime-to-posture, executive reporting, data residency); Security & Compliance 14%; Commercials 24%; Customer Experience 9%; Vendor Health 5%; Integration Ecosystem 5%. (https://www.rfp.wiki/vendors/wiz)
- **GigaOm 2026 CIEM Radar:** cloud ITDR, JIT access, lifecycle entitlements governance, compliance automation, AI anomaly detection, interoperability. (https://www.securitysolutionsmedia.com/2026/03/03/beyondtrust-recognised-as-a-leader-and-outperformer-in-the-2026-gigaom-radar-for-cloud-infrastructure-entitlement-management-ciem/)
- **Latio 2025:** "CNAPP is defined in the present by code-to-cloud and runtime capabilities." (https://www.latio.com/reports/2025-latio-cloud-security-report)
- **Forrester Wave CNAPP Q1 2026:** Sysdig a Leader; roadmap items cited include a "semantic attack graph". (https://www.sysdig.com/press-releases/sysdig-named-leader-forrester-wave-cnapp-2026)
- The synthesized 14-item checklist and OSS-feasibility table live in CA "Part F" and "Analyst/RFP checklist".

### Where the cluster docs disagree (not resolved here)
- **Prowler gating.** Prowler's pricing page lists attack-path analysis, Lighthouse AI and MCP as paid; the OSS README and docs show attack paths and Lighthouse in the self-hosted Local Server (OS §1). STRAT treats MCP as "Cloud-only". Treat Prowler OSS as having *some* attack paths and an MCP server.
- **Wiz contract median.** STRAT cites Vendr at $154,381 (188 purchases, range $30,309–$536,300); CL cites a blog citing Vendr at ~$149k (range $29.4k–$484k).
- **Prowler check count.** "2,500+ checks" (pricing) vs 1,616 metadata files (tree count) vs per-provider README counts (OS §1; STRAT §4 baseline).
- **Orca framework count.** 150+, 180+ and 185+ on different Orca pages (CL).
- **Tenable "toxic cloud trilogy" prevalence.** 38% (Oct 2024, PL) vs 29% (2025 report, BASE §1). Different years, not necessarily a conflict.
- **Lacework price.** Reported $152.3M cash vs Forrester ~$200–230M (STRAT).
- **Gem price.** ~$350M reported (STRAT) vs Forrester $300–400M (CA).
- **Sonrai price.** $150/account/month (site) vs $200/account/month (AWS Marketplace snippet) (PL).
- **Query engine design.** BASE §4 and OS ("DuckDB snapshot design") assume DuckDB; INV §4 shows nimbus uses SQLite (`modernc.org/sqlite`). The gap analysis assumes SQLite.
- **Permiso signal count.** 2,500+ signals (Okta) vs 1,500+ detection rules (Permiso page) (CA).
