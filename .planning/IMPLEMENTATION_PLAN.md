# nimbus implementation plan — v0.2 → v1.0
_Goal: the most advanced open-source cloud security platform on GitHub, measured feature-for-feature against Wiz, Orca, Prisma Cloud, Microsoft Defender CSPM, Tenable Cloud Security, Lacework, Datadog CSM, Vanta/Drata, Prowler, Steampipe, Cloud Custodian and Cartography._
_Written 2026-10-08 after the self-review in the session log. Every item has an owner track, files, acceptance criteria and the competitor bar it clears._

## 0. Principles (non-negotiable)
1. **Nothing ships unverified.** Every phase ends with a run against the live demo account (Phase 1 builds it). CI red = no merge.
2. **One source of truth per number.** Risk score, path score, compliance score: one implementation (Go), Python consumes it.
3. **Precision over volume.** Fewer, true attack paths and Issues beat inflated counts. Every scoring change is measured against the calibration set (Phase 3).
4. **Secure by default.** Localhost binding, auth on every endpoint, read-only tools for AI, approvals for writes, no secrets in config files.
5. **Agentless, open, reproducible.** Official SDKs, no vendored forks, pinned versions, SBOM + signed releases.
6. **Research first.** Each phase starts with a competitor delta check against docs/research/competitors.md (update it).

## Tracks and ownership
- **T1 Core/Graph (Go)** — model, store, graph, attack paths, risk, query.
- **T2 Collectors (Go)** — cloud/SaaS collection, reachability, IAM evaluation, workload scanning, monitoring.
- **T3 Remediation (Go)** — IaC patching, templates, PRs, policy generation, auto-remediation engine.
- **T4 Intelligence (Python)** — copilot agent, LLM mapping, reports, risk model training.
- **T5 Product (Go + web)** — dashboard, server, auth, UX, VS Code, CI integrations.
- **T6 Release/Community** — CI, releases, docs, demo, security of the project.
Workers: Opus 5.5 agents per track with self-contained briefs; Fable plans, reviews, integrates, verifies.

---

## Phase 1 — Truth: make it real (weeks 1–2)
**Why first:** nothing downstream is trustworthy until a real scan runs clean and CI is green.

### 1.1 Live demo + integration lab (T6, T2)
- Create `lab/terraform/` — a deliberately vulnerable multi-cloud estate (TerraGoat/CloudGoat-style) with: public S3 w/ PII tag, IMDSv1 EC2 behind 0.0.0.0/0 SG with admin instance profile, public RDS, cross-account trust role, user w/o MFA + stale key, Lambda URL public, EKS public endpoint with cluster-admin SA, Azure storage w/ public blob + NSG open RDP, GCP bucket allUsers + Cloud SQL public IP, GitHub repo w/o branch protection. `make lab-up / lab-down`. Cost ceiling tag + auto-destroy workflow nightly.
- `tests/e2e/` Go tests gated by `NIMBUS_E2E=1`: scan lab accounts, assert every seeded misconfiguration is found by the native collector **and** that the known attack paths (internet→EC2→role→RDS; user→policy→S3) exist with score ≥ 7.
- Capture **golden files** from real Prowler v5, Checkov 3, Trivy 0.6x, Steampipe/Powerpipe, ScoutSuite 5 runs against the lab → `testdata/golden/<tool>/<version>/`. Adapter tests run on golden files; fuzz tests for each parser (`go test -fuzz`).
- Nightly workflow `e2e.yml` with OIDC to the lab AWS/Azure/GCP; publishes a **coverage report** (API calls attempted/denied per account) as an artifact and badge.
- **Accept:** e2e green 3 nights in a row; coverage report shows 0 unexpected AccessDenied.
- **Bar:** Prowler ships without attack-path e2e; Wiz has internal labs. We publish ours.

### 1.2 Fix the correctness bugs (T1)
- **Finding lifecycle:** add `resolved_at`, `state` (open|resolved|suppressed|accepted) to findings. After each scan: findings for (account, source) not reported in that scan → `resolved` with `resolved_at`. Re-open on reappearance. `cloud-posture scan --diff` prints new/resolved since last scan. Views: `findings_open`, `findings_history(scan_id, finding_id, status)`.
- **Issues vs findings:** new table `issues(id, canonical_id, resource_id, provider, account, severity, state, first_seen, last_seen, finding_ids[])` — one Issue per (canonical_id, resource_id); findings are evidence. All counts, dashboards, alerts and risk run on Issues. Toxic combinations (Wiz term): an Issue of type `combination` created when ≥2 weaknesses co-occur on a resource/path (public+unencrypted+sensitive).
- **Scan history & trend:** `scans` carries per-severity counts; `cloud-posture history`, dashboard trend sparkline, MTTR and SLA-breach metrics.
- **Dedupe across tools:** when 3 tools agree, the Issue shows `sources: [prowler, steampipe, nimbus]` and confidence rises.
- **Accept:** lab fix of the public bucket → next scan shows it resolved; counts = Issues; e2e asserts.
- **Bar:** matches Wiz Issues/Findings, Orca alert lifecycle.

### 1.3 CI green + project hygiene (T6)
- Fix workflow: SARIF upload conditional on GHAS; `pip install -e "python[dev,server,pdf,ai]"`; Go `python()` probe imports `nimbus.risk` and checks deps; e2e separate.
- Add LICENSE (Apache-2.0), SECURITY.md (disclosure + supported versions), CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md (keep-a-changelog), CODEOWNERS, issue/PR templates, Dependabot/Renovate.
- `goreleaser`: linux/darwin/windows × amd64/arm64, Homebrew tap, Docker (ghcr), SBOM (syft), cosign signatures, SLSA provenance, `install.sh` verifies checksum + signature.
- Remove dead config fields or wire them (account `criticality`, `owner` → graph node defaults; `crown_jewels` into Config struct).
- **Accept:** `v0.2.0` release with signed binaries; `brew install`, `docker run`, `install.sh` all work from a clean VM.

### 1.4 Secure the product (T5)
- `serve`: default `127.0.0.1:8080`; `--addr 0.0.0.0` requires `--auth token|basic|oidc`; bearer token on all `/api/*`; CORS allowlist; CSP without `unsafe-inline` (move inline JS to a served file with nonce); rate limiting; SQL endpoint restricted to allowlisted tables/views (no `sqlite_master`, no attach/pragma); audit log of write actions (`.cloud-posture/audit.log`).
- Config: forbid literal `token:`/`password:` keys (error with guidance), support `*_env` and `secretsmanager://`, `vault://`, `keychain://` resolvers.
- Threat model doc `docs/threat-model.md`; `gosec` + `govulncheck` + `bandit` + `pip-audit` in CI.
- **Accept:** security review checklist in SECURITY.md passes; external `nmap`-style test from lab shows nothing listening off-localhost by default.

---

## Phase 2 — Depth: beat the graph leaders (weeks 3–6)
**Why:** attack paths are the product; today they are heuristic. Wiz/Tenable win on effective permissions and reachability.

### 2.1 Effective IAM permission engine (T2 → `internal/iam`)
- AWS: full policy evaluation per AWS logic — explicit deny, SCPs (Organizations), permission boundaries, session policies, resource policies (S3/KMS/SQS/Lambda/Secrets), group inheritance, `NotAction`/`NotResource`, condition keys (`aws:PrincipalArn`, `aws:SourceVpc`, `aws:MultiFactorAuthPresent`, `aws:PrincipalOrgID`, IP). Implement as a pure evaluator with a test corpus (≥200 cases from AWS docs + Parliament's test suite); cross-check sample results with `iam:SimulatePrincipalPolicy` in e2e.
- Privilege-escalation edges (PMapper/Rhino 21 methods): `iam:PassRole`+`lambda:CreateFunction`, `iam:AttachUserPolicy`, `sts:AssumeRole` chains, `iam:CreateAccessKey`, `iam:UpdateAssumeRolePolicy`, `ec2:RunInstances`+PassRole, `glue`, `cloudformation`… as graph edges `can_escalate_to` with technique attr.
- Azure: RBAC role assignments (built-in + custom, inherited scopes), PIM eligible roles, Entra directory roles, managed identities, app registrations with high-privilege Graph permissions, Key Vault access policies → `has_permission` edges with action sets; dangerous combos (Owner/UAA at subscription, `Microsoft.Authorization/roleAssignments/write`).
- GCP: IAM bindings with inheritance (org → folder → project), primitive roles, SA impersonation (`iam.serviceAccountTokenCreator`), `setIamPolicy`, default SAs with editor; use `cloudasset analyze-iam-policy` output when available.
- K8s: RBAC evaluation (ClusterRole/Role aggregation, `*` verbs, `escalate/bind/impersonate`, secrets read, pod create in kube-system), SA token mounts, IRSA/Workload Identity bridges cloud↔cluster.
- Graph edges carry **what** can be done (`actions`) so paths can say "role can `s3:GetObject` on 3 PII buckets".
- **Accept:** evaluator corpus 100% ; e2e: seeded PassRole escalation path found; false-positive guard: deny-SCP in lab removes the path.
- **Bar:** matches Tenable/Ermetic + PMapper; Prowler has nothing here.

### 2.2 Network reachability engine (T2 → `internal/reach`)
- AWS model: IGW/NAT/VPC peering/TGW routes, subnet route tables, NACLs (ordered rules), SGs (incl. referenced SGs), ENIs, public IPs/EIPs, ALB/NLB listeners→target groups→targets, CloudFront→origins, API Gateway→Lambda, Global Accelerator, VPC endpoints (private services). Compute `internet_reachable(resource, port, protocol)` with the path (edge list) and `via` (LB, direct).
- Azure: NSG at NIC+subnet (priority ordering), public IPs, Load Balancer/App Gateway/Front Door, Private Endpoints, service endpoints, Bastion. GCP: VPC firewall priorities, external IPs, Cloud NAT, HTTP(S) LB, IAP tunnels.
- Validate against AWS **VPC Reachability Analyzer** / **Network Access Analyzer**, Azure IP flow verify, GCP Connectivity Tests in e2e (sampled).
- **Validated exposure (safe, opt-in):** `cloud-posture verify --exposure` performs non-intrusive checks from the runner: anonymous `GET` on bucket listing, TCP connect to exposed ports, HTTP banner for Lambda URL/API Gateway — marks Issues `validated: true`. Explicit consent flag + allowlist of targets.
- **Accept:** lab seeds 6 exposure cases incl. a false positive (SG open but NACL denies, private subnet w/o IGW); engine gets all 6 right; reachability analyzer agreement ≥ 95% on sample.
- **Bar:** Wiz "network exposure analysis" + validated exposure (Wiz external scan).

### 2.3 Exploitability + workload intel (T2)
- EPSS (FIRST API, daily cache) and CISA KEV ingestion; CVE edge weight = f(EPSS, KEV, CVSS, fix available, internet-reachable). Vulnerability only enters a path if `exploitable` (KEV or EPSS ≥ 0.1 or network-reachable service match) — Google SCC's rule.
- **Snapshot (agentless workload) scanning:** `cloud-posture scan --workloads`: for each EC2/VM/GCE, create snapshot → scan with Trivy VM (`trivy vm ebs:snap-…` / disk image) for OS packages, language packages, secrets, malware-ish indicators (YARA optional) → delete snapshot. Azure: disk snapshot + SAS; GCP: disk image export. Rate/cost caps, opt-in per account, cleanup guaranteed (`defer` + nightly janitor). Registry scanning for ECR/ACR/GAR images deployed by running pods/tasks.
- Container runtime posture: pods→images→CVEs edges; "running" vs "deployed" distinction.
- Optional runtime signal ingestion: Falco/Tetragon alerts, GuardDuty/Defender/SCC findings as evidence on nodes (not duplicating their detection).
- **Accept:** lab EC2 with old OpenSSH gets CVE-2024-6387 (KEV) → path score reflects it; snapshot cleaned up (assert via API).
- **Bar:** Orca SideScanning (agentless workload), Wiz vuln context.

### 2.4 Data security (DSPM-lite) (T2, T4)
- Ingest Macie classification/findings, Purview labels, GCP DLP; tag-based classification; bucket/DB "data sensitivity" node property with source.
- **Sampling classifier (opt-in):** sample N objects per bucket (size-capped), run regex/entropy detectors (PAN w/ Luhn, SSN, IBAN, AWS/GCP/Azure keys, JWTs, PEM), Python layer may use the LLM on redacted snippets for document types; never stores samples, only counts.
- DB sensitivity from schema names (columns like ssn, card_number) via read-only metadata where possible (RDS Data API/`information_schema` with provided creds, optional).
- **Accept:** lab bucket with synthetic PII flagged sensitive via sampling; score of its paths rises accordingly.
- **Bar:** Wiz DSPM, Orca data security (lite but real, not name-matching).

### 2.5 Attack-path engine v2 (T1)
- Replace heuristic edges with engine outputs: reachability edges (2.2), permission edges (2.1), escalation edges, CVE-exploitable edges (2.3), data edges (2.4). Keep rule chains only for scanner-only mode and label them `confidence: inferred`.
- Scoring: likelihood = Π step probabilities (calibrated table per edge type + evidence), priority from 4-tier crown-jewel model (tags, DSPM, user rules, learned from names as fallback). Publish `docs/scoring.md` with every number. Add **confidence** (validated > evaluated > inferred).
- Choke points via betweenness over paths; **min-cut** exact via max-flow on node-split graph (cost = fix effort estimate), greedy as fallback for >5k paths.
- Path dedupe: collapse paths that differ only in interchangeable hops (same SG set) into one with `variants: n`.
- Narratives: deterministic template + LLM polish (T4) with the facts pinned.
- Performance: incremental graph (per-account rebuild), indexes, O(n log n) edge inference; 100k-node lab benchmark < 30 s.
- **Accept:** on the lab, path precision = 100% (every reported path reproducible by hand), recall = all seeded; demo data no longer shows "Internet → bucket" as a multi-hop path (it is an exposure Issue, not a path).
- **Bar:** Wiz Security Graph, Defender attack paths, SCC attack exposure — plus confidence labels and min-cut none of them expose.

### 2.6 Risk score v2 (T1, T4)
- Single Go implementation; Python calls it via `cloud-posture prioritize --json`. Delete the Python formula.
- Features re-cut: exposure(validated/evaluated/inferred), permission blast radius (count of sensitive targets reachable), data sensitivity (source-weighted), criticality (tags > account config > name), exploitability (EPSS/KEV), compliance scope, **change velocity** (resource changed in 24h AND finding new relative to previous scan, not first scan), ownership, path membership (max score, count), **age/SLA breach**. Logistic combination, bands 1–10.
- **Calibration set:** 300 hand-labeled Issues from the lab + public incident write-ups (Capital One, Uber, LastPass patterns) with expected band; CI asserts Spearman ≥ 0.8 and ≤ 15% of Issues in Critical on the lab.
- Explanations list top-3 contributing features with their weights.
- **Bar:** Orca 1–10 bands + Defender reasons + published formula (none of them publish).

---

## Phase 3 — Fix it for me: remediation that beats Snyk/Prisma/Custodian (weeks 7–9)
### 3.1 Patching across formats (T3)
- Terraform: cover every canonical ID with a deterministic patcher where one exists (target 60/75); module-aware (patch the module call or the module source with `--patch-modules`); variables added to `variables.tf` automatically; `terraform fmt`.
- CloudFormation (YAML/JSON structural patch preserving comments via yaml.v3 node tree), Bicep (ANTLR-free line-structured patcher for property assignment), Kubernetes/Helm (strategic merge on manifests; Helm: values.yaml override + comment where template is templated), CDK (TypeScript/Python AST edits for the common constructs via tree-sitter), Pulumi (same), Ansible (YAML).
- **Validation gate:** every template and every patch runs `terraform validate`, `cfn-lint`, `bicep build`, `kubeconform` in CI; PR includes `terraform plan` summary when credentials exist (OIDC) and `infracost` delta.
- **Never-widen guardrail v2:** semantic diff (parse before/after → compare exposure/permission sets), not string counting.
- **Accept:** patch coverage table in docs; all templates validate; lab IaC repo gets a PR for every seeded misconfig and `terraform plan` shows only narrowing changes.
- **Bar:** Snyk IaC fix PRs, Prisma commit suggestions, Wiz Code — plus plan/cost evidence in the PR.

### 3.2 Cloud-to-code everywhere (T3)
- tfstate (local/S3/Terraform Cloud/Spacelift APIs), CloudFormation stack resource mapping (`DescribeStackResources`), Azure Deployments, GCP Deployment Manager/Config Connector, Pulumi state, Yor traces, Git blame → **author + CODEOWNERS** on every Issue (owner resolution chain: tag → CODEOWNERS → git blame → account default).
- **Drift detection:** compare state vs live → `DRIFT_*` Issues ("made public in console, not in code").
- **Attack-path diff in PRs:** `cloud-posture scan --iac --baseline` builds the graph from plan JSON (`terraform show -json plan`) merged with the live graph; PR comment lists paths the change would open/close.
- **Bar:** Wiz Code cloud-to-code; Prisma drift; nobody shows path diffs on PRs.

### 3.3 Auto-remediation engine (T3 → `internal/remediate`)
- Cloud Custodian-style policies in YAML: `when: {canonical_id: S3_PUBLIC_BUCKET, account: prod-*}` → `actions: [put_public_access_block]` with modes `dry-run | approve | auto`, maintenance windows, rate limits, rollback snapshot (store prior config JSON), audit log, Slack approval buttons (interactive webhook) and GitHub issue approvals. ~25 safe cloud-side actions (PAB, SG revoke, IMDSv2 enforce, RDS no-public, EBS default encryption, key rotation, trail validation, bucket encryption, NSG rule delete, blob public off, GCS PAP enforce, SQL public IP off, Lambda URL auth).
- **Preventive controls generation:** from findings → AWS SCP / Azure Policy / GCP Org Policy / OPA Gatekeeper + Kyverno + Sentinel/Checkov custom policies ("never again"). `cloud-posture prevent --finding S3_PUBLIC_BUCKET --format scp`.
- **Bar:** Cloud Custodian (no graph context), Wiz "remediation guardrails" — we add approvals + rollback + prevention in one flow.

---

## Phase 4 — The copilot that works for you (weeks 8–11, overlaps)
### 4.1 Agentic copilot (T4 → `python/nimbus/agent/`, T5)
- Claude tool-use agent (Anthropic SDK tool runner, streaming) with tools: `sql(query)` (read-only, allowlisted views), `graph_neighbors(node)`, `blast_radius(node)`, `attack_paths(filter)`, `issue(id)`, `explain(issue)`, `generate_fix(issue, format)`, `open_pr(patch)`*, `create_ticket(issue, system)`*, `suppress(issue, reason, expiry)`*, `run_query_named`, `docs(search)` (RAG over docs/checks.md + vendor remediation docs cached). `*` = requires approval (dashboard button or `--approve`).
- Guardrails: cloud-controlled strings wrapped as untrusted data; prompt-injection tests; max cost/turn; every tool call logged; eval suite of 60 questions with expected SQL/answers run in CI with a recorded-cassette harness; offline rule-based mode retained.
- Served **inside** the Go server (`/api/copilot` proxies to the Python agent subprocess or `nimbus serve`), SSE streaming to the dashboard chat with tool-call trace visible; conversation memory per user in SQLite.
- **Autonomous jobs:** nightly triage (explain every new Critical, propose owner, draft fix PRs for the min fix set as drafts), weekly executive brief, catalog-mapping suggestions (4.2).
- **Bar:** Wiz AI, Microsoft Security Copilot — plus open tools, visible traces, offline mode and PR drafting.

### 4.2 LLM-assisted coverage expansion (T4, T1)
- Export every unmapped check (Prowler 500+, Steampipe 1,200+, Checkov 1,000+, Trivy, ScoutSuite) with description → LLM proposes canonical mapping + weaknesses + compliance → review queue (`docs/catalog-review.md`) → merged into catalog.yaml. Target: ≥ 90% of Prowler AWS/Azure/GCP checks mapped; new canonical IDs for uncovered areas (Organizations, Identity Center, Config, Backup, ECR, ECS, DynamoDB, SQS/SNS, Route53, ACM, WAF, Glue, Redshift, OpenSearch, SageMaker…).
- Native Go checks for the top 100 by exposure impact so scanner-only users still get attack paths.
- **Bar:** Prowler breadth with graph context.

---

## Phase 5 — Compliance that passes an audit (weeks 10–12)
- Control catalogs with **versions** (CIS AWS 1.5/2.0/3.0, Azure 2.1/3.0, GCP 2.0/3.0, K8s 1.8/1.9, PCI 4.0.1, NIST 800-53r5 + CSF 2.0, SOC 2 2017/2022 PoF, HIPAA, GDPR Art.25/30/32/33, ISO 27001:2022, **FedRAMP moderate, CMMC 2.0, NIS2, DORA, CCPA**); mapping provenance per control (vendor mapping vs weakness-derived vs manual).
- Evidence v2: per control, the raw API response (redacted) + timestamp + collector identity + hash; **screenshots** of console-equivalent via dashboard print-to-PDF; control narratives; owner & due date; exceptions/risk-acceptance register with approver and expiry; auditor read-only share (static site export with signed manifest).
- Continuous controls: hourly `serve --scan-interval 1h` on selected checks; control status history; SLA & drift alerts.
- Export to Vanta/Drata custom tests, Audit Manager evidence format, OSCAL.
- **Bar:** Vanta/Drata technical-control depth, AWS Audit Manager evidence format, Prowler compliance; we add graph context ("this failing control is on 4 attack paths").

---

## Phase 6 — Real-time + alerting that ops teams keep on (weeks 11–13)
- Push ingestion: EventBridge rule → HTTPS target (serve `/ingest/aws`), Azure Event Grid → webhook, GCP log sink → Pub/Sub push; signed/authenticated endpoints; fall back to polling.
- Detection content: Sigma-style rules for cloud events (root login, trail stop, policy attach, public access, key creation, MFA deactivate, console login from new country) with MITRE mapping; **event → Issue** linkage (the change that created the Issue); 5-minute "incident" timeline per resource.
- Routing: rules (severity, provider, account, path membership, owner), schedules/quiet hours, digests, dedup windows, expiring suppressions, **bidirectional Jira/ServiceNow sync** (status → Issue state), Opsgenie, email, Slack interactive actions (acknowledge, suppress 30d, open PR).
- **Bar:** Datadog CSM routing + Jira sync, Wiz Cloud Events; we add change→Issue causality.

---

## Phase 7 — Product polish and scale (weeks 12–16)
- Dashboard v2: API-backed (no embedded JSON), virtualized tables, saved views, Issue drawer with timeline/evidence/fix/PR status, path explorer with step details and "what if I fix this" simulation, trend/MTTR/SLA panels, owner/team filters, dark mode verified, keyboard shortcuts; **visual QA** via Playwright screenshots in CI across light/dark/narrow.
- Team mode: Postgres backend (pgx) behind the same store interface, users + SSO (OIDC), RBAC (viewer/analyst/admin), API tokens, multi-tenant accounts, Helm chart for `serve`.
- Scale targets: 1M findings, 250k graph nodes: scan ingest < 5 min, path analysis < 2 min, dashboard p95 < 500 ms (benchmarks in CI with synthetic generator).
- CLI UX: colored, progress bars, `--json` everywhere, shell completion, `doctor` command (creds, tools, permissions), `init` wizard with the spec's exact onboarding UX, helpful errors.
- VS Code v2: inline attack-path preview, hover docs, "fix all in file", status bar score; JetBrains plugin.
- SaaS coverage: Snowflake, Slack, Google Workspace, Salesforce, Atlassian, Identity Center/Entra/Workspace as identity sources; CI/CD posture (GitHub Actions permissions/OIDC trust, GitLab CI) with pipeline attack paths.
- Cost v2: Cost Explorer/Azure Cost/GCP Billing actuals, Infracost for fix PRs, savings tracking over time.

---

## Phase 8 — Launch (week 16+)
- Docs site (mkdocs-material): quickstart, per-check pages, scoring, architecture, API, comparisons table with evidence; 2-minute demo video; screenshots; blog "we published our attack-path scoring"; HN/Reddit/CNCF Slack; talk submissions (BSides, fwd:cloudsec, KubeCon, Black Hat Arsenal).
- Benchmarks page: nimbus vs Prowler/Steampipe coverage, vs Wiz features (public docs), run on the open lab so anyone can reproduce.
- Governance: roadmap public, RFC process, maintainers guide, security advisories, release cadence (monthly).

## Definition of done (every phase)
- e2e on the lab green; unit + golden + fuzz green; `govulncheck`/`gosec`/`pip-audit` clean; docs updated; CHANGELOG entry; competitor delta section updated in docs/research.

## Risks and mitigations
- **Cloud cost of lab/e2e:** budget alarms, nightly destroy, snapshot scanning capped.
- **Scope creep:** phases gate on acceptance criteria; anything without a criterion is not scheduled.
- **LLM dependence:** every AI feature has an offline mode and an eval suite.
- **Correctness of IAM/network engines:** corpus + cross-validation with provider analyzers; confidence labels on every edge.
- **Maintainer bandwidth:** collectors generated from a declarative spec where possible (service, API, pagination, field map) to keep 7 providers maintainable.
