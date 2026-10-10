# Competitive delta review 1 (2026-10-09)

This review checks what has landed (Phase 0 and Phase 1 waves 1–2) against the best-in-class bar in
`docs/research/competitive-feature-matrix.md`, as the owner's standing rule requires: "constantly compare the code
to the competitors so we don't come up short". The reviewer was read-only on code. Each verdict comes from
behaviour seen in this run unless it is marked "(log)", which means it is taken from
`docs/sessions/2026-10-09-cwm-ui.md`. Areas that two agents are still editing are marked **IN-FLIGHT**:
`internal/pathdiff`, `internal/cli/{devx,prcomment}`, the attackpath CI-entry change, the `internal/collector/aws`
change and the `internal/graph` IAM edges.

**Verdict scale.** BEATS: better than the named best-in-class product, with evidence seen here. MATCHES: the same
behaviour in substance. SHORT: present, but visibly behind the bar. ABSENT: not there. IN-FLIGHT: code exists in a
package being edited now, but users cannot reach it yet, or it was not finished at review time.

**Effort:** S ≤ 2 agent-days, M ≤ 1 week, L ≤ 3 weeks (plan v3 scale). **Plan:** cites the plan v3 §2 row or track.
"NEW" means plan v3 does not have it.

## Method and evidence

The working directory for this run was `scratchpad/delta/` (session scratchpad). `CLOUD_POSTURE_NO_NETWORK=1` was
set for every command.

- **Build:** `go build -o cp ./cmd/cloud-posture` at 22:05, rebuilt as `cp2` at about 22:12 to pick up in-flight
  `pr-comment` work. `cp version` prints `0.1.0-dev`, commit `unknown (dev build)`, score `2.1.0`.
- **Lab:** `go run ./lab/local/gen -in lab/local/estate.yaml -out <scratch>` produced output byte-identical to
  `lab/local/out/estate.findings.json`: 83 records, 62 weaknesses. It was ingested with
  `cp -c lab.yaml --db lab.db ingest estate.findings.json --source native`, using the `trusted_cidrs` from the lab
  config.
- **Commands exercised:**
  - `paths --explain --limit 0`, `paths --exposures`, `plan`, `plan --json`
  - `prioritize --explain`, `prioritize --json --top 0`
  - `issues`, `issues --kind path`, `issues show <path id>`, `issues show <single id>`, `issues history`
  - `ingest --diff` on a copy with `lab-W01` flipped to PASS
  - `scan --iac <copy of lab/terraform/aws> --diff`
  - `doctor`, `report --framework cis_aws`, `fix --id lab-W01 --generate-terraform`, `query --describe`
  - adapter auto-detection on `testdata/adapters/{kubescape,cartography,trivy-operator}`
  - `pr-comment --plan-json testdata/action-fixture/plans/{bad,create}.plan.json` (plan-only mode)
  - `who-can`, `convert` and `mcp`: all three return `unknown command`
- **Tests and harnesses:**
  - `go test ./internal/output -run 'Golden|Convert|OCSF|ASFF' -v`: 8/8 PASS.
  - `internal/mcp/testdata/smoke.sh`: exit 0.
  - `make ui-test`: 23 checks plus "no page errors", "all checks passed".
  - `GROUNDTRUTH_REPORT=… go test ./tests/groundtruth`: currently FAIL, but only on known-gaps housekeeping that
    the in-flight IAM edges changed (P13 is now found at 5.32; F02/F09 are now suppressed).
  - Python copilot offline: `python -m nimbus ask` with 4 questions.
  - An independent XSS probe. Hostile title, name and tag strings were loaded into the dashboard
    (6 sections × row click) and into the Python SOC 2 HTML report. Result: `__pwned=0`, 0 `<img>` elements,
    and 38 escaped occurrences in the HTML report.
- **Screenshots** of the dashboard rendered from the lab database are in `scratchpad/delta/{ov,fi,pa,co}.png`.

## Five things a Wiz-trained buyer notices in the first ten minutes

1. **The same risk has three different severity labels.**
   - `paths` prints `[CRITICAL 7.0]` (traversal: Critical ≥ 7, `internal/attackpath/traversal.go:944-952`).
   - It also prints `[CRITICAL 5.2]` and `[CRITICAL 5.9]` for rule chains (Critical at ≥ 5.5 or inherited,
     `engine.go:377-380`).
   - `issues` shows the same paths as `HIGH … band High` (risk bands: Critical ≥ 9, High ≥ 7).
   - `prioritize` calls 45 of 62 lab findings Critical, while `issues` shows 9 CRITICAL single Issues.
   - The dashboard header reads "31 attack paths, **25 critical**", but only 2 path Issues are Critical.
   - `docs/scoring.md` states "The band always comes from the same score it is displayed with". The CLI does not
     follow that rule.
2. **Two seeded false positives sit in the CISO's top 10.**
   - F04 (RDS flagged `PubliclyAccessible` with no IGW route) is rank #3 at 10.0 Critical, and is path #4
     `[CRITICAL 8.0]`.
   - F03 (an SG open on 22, but the NACL denies 22) appears twice at 7.0 and is rank #8.
   - The benchmark still publishes **precision 100% (31/31)**, because a reported `pending-feature` label counts as
     labelled (`docs/benchmark.md:219`).
   - Counted against real-world truth, precision is 27/31 = 87%, and 17/20 = 85% at ≥ 7.
3. **Scores saturate.** 40 of 62 lab findings score exactly **10.0**. The raw score goes up to 38.22 before the cap,
   so the top of the ranking is ordered by a hidden tie-breaker.
4. **The Issue page is skeletal.**
   - `issues show <path Issue>` gives title, entry, anchor, score, "2 hop list(s)" and four evidence findings.
   - It has no hops or "because", no fix, no owner or SLA, no score explanation, no ticket and no timeline.
   - `issues show <single Issue>` for the public PII bucket does not mention that the bucket sits on 2 attack paths,
     that its owner is `data-platform`, that its SLA ends 2026-10-17, or how to fix it. `prioritize` knows all four.
5. **The best new capabilities are not reachable from the binary.**
   - `who-can`, `mcp` and `convert` return `unknown command`.
   - `scan -o` lacks `ocsf|asff|gitlab|junit`.
   - No release exists to install: no brew, no image, version `0.1.0-dev`, and the binary is 218 MB.

---

## 1. Inventory & graph

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix (where, effort) | Plan |
|---|---|---|---|---|---|---|
| IG1 | **Prow**: "23 providers; AWS 662 checks across 86 services" | 48 native checks, against fakes only. `doctor` → "0 account(s)". The lab is native-ingest only; nothing has run against live AWS. | SHORT | Breadth, and no live run at all | Make Prowler ingest the documented breadth path; do the live AWS lab run (owner O1). M | IG1 [P1-GRAPH], TS4 |
| IG2 | **Carto**: "76 intel modules; Okta/Entra federation edges to AWS roles and Identity Center" | The Okta→group→SSO-admin chain exists only because the lab declares the edge. **P15 scores 1.44 LOW** (rank #46). No collector emits `federates_to`. | SHORT | IdP→cloud edges and an identity-entry rule | `saas/{okta,m365}.go` `federates_to`; an identity-entry floor in `attackpath`. L | IG2 [P2-MULTICLOUD]; floor NEW → P1-ENGINE |
| IG3 | **Prow**: "CloudFormation with External ID, StackSet to every member account" | `onboard --aws-org --deploy` and safe `offboard` (log, against fakes). `scan` does not fan out over `ListAccounts`. | SHORT | Org-wide scan fan-out | `collector/aws/org.go`. M | IG3 [P2-MULTICLOUD] |
| IG4 | **Wiz** Security Graph: "typed nodes and relationships with properties and attached findings" | Registry: 80 types / 115 aliases. Typed `relations`. Edge attributes `{actions, statement, confidence}` (log). IAM-evaluated edges are being edited now. | IN-FLIGHT | The graph is still finding-derived on ingest; no `BuildFromInventory` | P1-GRAPH / P1-IAM. M | IG4 |
| IG5 | **SP**: "every API a table (2,000+ tables)"; **FixInv** "40+ base kinds" | `query --describe` lists 53 tables/views. Per-type views cover only finding-bearing resources. The read-only path is hardened (`sqlite_master` is rejected). | SHORT | No normalised kinds; inventory = finding-bearing resources only | `store/kinds.go` `nimbus_{database,bucket,identity,workload,network_control}`. S | IG5 [P3-CONTENT] |
| IG6 | **Sysdig** SysQL / **J1QL** | No graph query. `paths` has `--choke` and `--blast-radius`, but no `--from/--to/--through`. | ABSENT | Path filtering by source, target or through-node | `cli/paths.go` filters. S | IG6 [P1-ENGINE] |
| IG7 | **FixInv** "hourly snapshots with per-resource timeline and diff"; **R7** "Source Data pane" | `issues history` records score and hop-list per scan (seen: 10.0 → 7.0 after the W01 fix). No `resource_versions`. The dashboard resource pane shows findings, paths and edges but no config JSON. | SHORT | No per-resource config history, diff or raw-source view | migration 7 `resource_versions` + `cloud-posture diff <resource>`. M | IG7 [P1-ISSUES] |
| IG8 | **FCN**: "per-account and per-resource scan status with the failure reason" | Coverage rows OK/DENIED/SKIPPED/ERROR/TIMEOUT (V2 verified, log; ui-smoke check 18 PASS). On ingest the panel says only "1 API calls / tool runs recorded". | MATCHES (fakes) | Ingested sources do not carry their own skip/error state, e.g. Prowler MUTED/ERROR | Adapters map source-tool errors and skips to coverage rows. S | IG8 partly; adapter part NEW |
| IG9 | **ASH** AI inventory; **SCC** "makes agents attack-path nodes" | `aws_bedrock_agent` is registered and shows only as an *exposure*. **P18 is MISSED**: the agent→role hop is priced at 0.1. | SHORT | Agents are nodes, but not path nodes | `attackpath/credhop.go`: likelihood for public agent `runs_as`. S | IG9 [P3-CONTENT] → pull into P1-ENGINE |

## 2. Attack paths & toxic combinations

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix (where, effort) | Plan |
|---|---|---|---|---|---|---|
| AP1 | **SCC** "simulated attacker … AND/OR edge semantics"; **Cortex** multi-hop | Lab: 31 reported paths; groundtruth recall 19/20 at any score and 15/20 at ≥ 7. Noise estate: 4/4 TP (log). There are two engines: traversal and 11 rule chains, each with its own severity scale. `MaxBranching: 25` truncates silently. No scale benchmark (largest seen: 381 nodes, log). | SHORT | One engine; a `Truncated` flag; a 50k-node benchmark | `attackpath/reach.go` backward pruning; migrate rules into traversal. L | AP1 [P1-ENGINE] |
| AP2 | **ASH** "Likelihood × Impact matrix … Impact tab labels each hop with the permission used" | `paths --explain`: every hop has `[p=…]` and a `because:`. Some hops name the grant ("via inline policy MediaRead"); many end at "declared by finding lab-inv-09". The printed severity disagrees with the score: `[CRITICAL 5.2]`, while Issues show `High` at 7.0. | SHORT | Statement on every permission hop; one band vocabulary | `traversal.go:944-952` and `engine.go:377-380` → `risk.BandFor`. S. `<arn>#<sid>` on permission hops (P1-IAM, in flight) | AP2 [P1-ENGINE]; band fix NEW |
| AP3 | **Wiz** Issues: "a correlated toxic combination; critical = high likelihood **and** high impact" | 91 Issues: 27 path, 2 combination, 62 single. Path Issue ids are stable sha values. The SG-entry and instance-entry variants fold into one Issue ("2 hop list(s)"). | MATCHES (model) | The Issue *page* (see §12 and top-15 #4) | — | AP3 [P1-ISSUES] |
| AP4 | **Sysdig** risk definitions: "Managed/Custom, Live <3h and New <7d badges, auto-close", test-before-save. **Prow**: "~100 AWS path queries with stable ids" | 11 rules in `internal/attackpath/rules.yaml`, plus the `scan.attack_rules_file` key. No dry run, no badges, no query library. | ABSENT | Rule authoring, preview and an attributed library | `rules/paths/*.yaml` + `cloud-posture risk test <file>`. M. Port Prowler queries (Apache-2.0). L | AP4 [P1-ENGINE], ID2 [P2-CIEM] |
| AP5 | **MDC** "choke point → 'View blast radius'"; **SCC** "fix one → closes many" | `paths --choke`, `--blast-radius`. The dashboard choke table shows PATHS/CLOSES (e.g. web-01 closes 2). | MATCHES | Choke points are not Issues (`kind='chokepoint'` is reserved but unused) | Emit chokepoint Issues in `store/path_issues.go`. S | AP5 [P1-ENGINE] |
| AP6 | "No vendor computes the minimum-cost set of changes that breaks all paths" | `plan`: "21 fix(es) — min_fix_exact=true (provably minimal), min_fix_verified=true (re-traversal confirmed), removes 92%". | **BEATS** | The 2 residual paths (12.3 score) are not named; `plan` covers 23 paths while `paths` lists 31 (rule chains are left out) | `cli/plan.go`: list residual paths with the reason, and include rule-chain paths. S | AP6 done; residual NEW |
| AP7 | **MDC** "exposure width (wide/narrow) + Trusted IPs"; **XM** "74% … are dead ends" | `suppressed (trusted): 3, suppressed (private): 2`, one reason per node ("auth required (function_url_auth_type AWS_IAM)", "org-conditioned (… aws:PrincipalOrgID)"). `Exposures (not attack paths): 14`. `Dead ends: 15`. Noise estate FP 23 → 0 (log). | MATCHES | Exposures-not-paths has no "X of Y exposures reach no jewel" headline; that is the XM bar | `paths` and dashboard header line. S | AP7 [P1-ENGINE] |
| AP8 | **ASH** reachability trait; **Wiz** network exposure | SG/NSG/firewall CIDR only. **F03** (NACL denies 22) is reported 2× at 7.0. **F04** (no IGW route) is reported at 8.0 and is prioritize #3 at 10.0. | SHORT | NACL, route table/IGW and LB evaluation | `internal/reach` (AWS route+NACL first). M | AP8 [P2-REACH] → **pull to Phase 1** |
| AP9 | **S1** "each issue has an 'Exploit Evidence' tab"; **ASH** Network Scanning | `model.ValidationStatus` reserved; no probe code. | ABSENT | Validated exploitability | `probe` with consent file. M | AP9 [P2-REACH] |
| AP10 | Plan-time path diff: "**no vendor**" | `pr-comment --plan-json create.plan.json` → "opens 1 / closes 0", with a redacted topology, why, fix and footer `nimbus-opens-paths: 1`. **But** `bad.plan.json` raises a path **1.9 → 7.0** and prints "opens 0 / closes 0"; `--fail-on-opened` exits **0**. | IN-FLIGHT | Escalations neither gate nor appear in the headline | `pathdiff.Result.Escalated` (band crossing) + `--fail-on-escalated`, counted in the headline. S | AP10 [P1-PLANDIFF]; escalation NEW |

## 3. Risk prioritization

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix (where, effort) | Plan |
|---|---|---|---|---|---|---|
| RP1 | **FCN** "published bands, risk = max over paths, Factors icons, top-3 paths dialog, 'no data' ≠ 0". **MDC** "New" tag + change log | `prioritize --explain`: a factor table (×mult, status, reason, evidence), `not scored` listed separately, top paths, a `cap` row, `score_version 2.1.0`. **But** 40/62 findings are 10.0 (raw up to 38.22), and 45/62 are Critical. | SHORT | Dynamic range: the top 40 are a tie | `internal/risk`: rank on an uncapped log-compressed score, or change "max over paths + bounded multipliers"; publish the change as 2.2.0 with an upgrade banner. M | RP1; saturation NEW |
| RP2 | **Cortex** CVRS "CVSS, EPSS, KEV, exploit maturity … with an Evidence breakdown" | KEV/EPSS from an embedded snapshot plus cache. Log4Shell (KEV) path P19 reaches 7.0. **The traversal still gives 0.95 to any `UNPATCHED` / `CVECount>0`** (`traversal.go:294-296,372-376`, `credhop.go:64`). For example, build-runner's non-KEV CVE gets "runs exploitable software [p=0.95]". | SHORT | KEV/EPSS gate (DEC decision 5) | A gate in `traversal.go`/`credhop.go`; threshold sourced in `SCORING`. S | RP2 [P1-ENGINE] |
| RP3 | **MDC/MSEM** "predefined + custom rules, dynamic reclassification" | `crown_jewels` with 4 levels; explanation shows `crown_jewels rule <name>`. The built-in name catalog is removed (log). | MATCHES (config) | No predefined critical-asset library | Registry `Crown` defaults per type. S | RP3 [P1-ENGINE] |
| RP4 | **ZS** "lowers the score when a control already blocks the path" | `auth-lb ×0.3` chip on paths (log). The `compensating_controls` factor always reads "no compensating control recorded". No WAF, private endpoint or NetworkPolicy model. | SHORT | Control catalogue | P2-REACH. M | RP4 |
| RP5 | **Sysdig** "risks close automatically when the condition clears" | `ingest --diff` → "1 resolved lab-W01"; the path Issue history moved 10.0 → 7.0. | MATCHES | `--diff` prints "Path Issues: 0 opened, 0 reopened, 0 resolved" and hides the 10.0 → 7.0 drop | `cli/lifecycle.go`: print path score and band changes. S | RP5; display NEW |
| RP6 | **J1** "one row per CVE per asset" across 5 scanners | Canonical catalog with aliases. **Trivy 0.75: 44/44 lab IaC findings stay `TRIVY:*`** (ids `AWS-0028` vs catalog `AVD-AWS-0028`), so they duplicate native `S3_PUBLIC_BUCKET` etc. Checkov maps 35/95 (log). | SHORT | Normalisation for the two most-used OSS scanners | `adapters/trivy.go` id normalisation + `catalog.yaml` aliases. S | Integration pass 3 (session log) |
| RP7 | **DD** suppressions with expiry; **Prow** muted kept as Suppressed | `issues suppress <id> --reason --expires --approved-by`; the DB CHECK requires a reason and expiry; expiry reopens (log). | MATCHES | — | — | RP7 |
| RP8 | **MDC** governance rules: "owner from tag, SLA 7/14/30/90 d, grace period, weekly owner email, on-time/overdue report" | Owner from a tag where present (`owner: data-platform`, SLA date). **48/62 ranked findings have no owner**; the dashboard shows "(no owner) 4" open criticals. No rules, digest or escalation. | SHORT | Rules, CODEOWNERS fallback, digest, overdue report | `internal/governance` (first-match YAML, CODEOWNERS). M | RP8 [P2-EVIDENCE] → pull forward |

## 4. Identity / CIEM

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix (where, effort) | Plan |
|---|---|---|---|---|---|---|
| ID1 | **ASH** "identity + resource policies + SCPs + RCPs, with privilege-escalation chains labelled per hop" | `internal/iam`: 147 corpus cases, 95.4% coverage, mutation-tested (log). Groundtruth now: F02 (explicit Deny) and F09 (SCP deny) SUPPRESSED; S01 drops 7.6 → 5.70. | IN-FLIGHT | Not run against live AWS; simulator parity fixtures not finished | P1-IAM items 2–4 | ID1 |
| ID2 | **Prow** "~70 privesc queries modelled on pathfinding.cloud" | **P13** (PassRole + RunInstances) is now found, but at **5.32 Medium**, prioritize rank #44. Only the first techniques are covered. | IN-FLIGHT | The technique library, and the scoring of escalation edges | P1-IAM `can_escalate_to`; port Prowler queries. L | ID2 [P1-IAM, P2-CIEM] |
| ID3 | **FixInv** permission-weighted edges; **DD** Access Insights "direct/indirect principals" | `graph.WhoCan` exists (principal, via-chain, statement, policy ARN, confidence). `cloud-posture who-can` → "unknown command". The copilot answers "who can read nimbus-lab-customer-pii?" with "could not map". | IN-FLIGHT | Not reachable by users | `cli/whocan.go` + MCP `who_can` tool + copilot intent. S | ID3 |
| ID4 | **Cortex** "Adjust Policy as JSON/Terraform/CFN"; **DD** "Suggested Policy as Terraform PR" | Absent. | ABSENT | Usage collection and right-sizing | `collector/aws/usage.go`, `iam/rightsize.go`. L | ID4 [P2-CIEM] |
| ID5 | **Ten** effective permissions across AWS/Azure/GCP/Entra/Workspace | GCP project IAM bindings collected (Track C, log); no Azure RBAC. | SHORT | Azure RBAC and GCP conditions | `azure/rbac.go`, `gcp/iam.go`. L | ID5 [P2-MULTICLOUD] |
| ID6 | **Kube** "290 controls incl. access-control risks" | 7 K8s checks. Lab pod→SA→CRB→cluster-admin (P08) and secrets-reader (P16) are found at 7.0. | SHORT | Effective verbs per subject | `k8s/rbac.go`. M | ID6 |
| ID7 | **Son** Cloud Permissions Firewall / JIT | Absent. | ABSENT | (cut) | — | ID7 cut |

## 5. Data / DSPM

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| DS1 | **Cortex** 6 data profiles, OCR, masked samples | Labels and explicit classification only; explicit classification beats name heuristics (log). | ABSENT | (cut by DEC 6) | — | DS1 cut |
| DS2 | **Proofpoint DSPM ↔ Wiz** label exchange | Absent. | ABSENT | — | `adapters/dspm/{macie,purview,…}`. M | DS2 [P2-TIMELINE] |
| DS3 | **Sysdig** "sensitive data appears inside attack paths" | `data_sensitivity ×1.50 [label pii]`; `exposed+sensitive` toxic tag on paths. No collector emits `stores_data_in`. | SHORT | App→datastore edges from real collection | `collector/aws/datastores.go`. S | DS3 |

## 6. Vulnerabilities, secrets, SBOM

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| VS1 | **Trivy** one binary + `convert` | Trivy adapter. **Trivy 0.75 ids are unmapped** (44/44). CVSS and PrimaryURL are dropped (INV). | SHORT | Mapping and CVSS | `adapters/trivy.go`. S | VS1 [P1-INTEROP] |
| VS2 | **Orca** SideScanning | Absent. | ABSENT | (cut) | Ingest Inspector or Trivy Operator (the adapter exists) | VS2 cut |
| VS3 | **Orca** reachability tiers | Absent. | ABSENT | — | P3-ADAPTERS | VS3 |
| VS4 | **S1** "850+ secret types, each validated" | Checkov/Trivy secrets ingested and forced CRITICAL (INV). | SHORT | Validation | P2-REACH | VS4 |
| VS5 | **Aqua** smart rescan; **J1** Emerging Threats | Absent. | ABSENT | — | P3-ADAPTERS | VS5 |

## 7. IaC & code-to-cloud

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| IC1 | **Chk** "1,183 Terraform check files … Terraform plan scanning" | Native HCL: 20 rules. `scan --iac` on `lab/terraform/aws` gives 10 native findings plus 44 Trivy. Unparseable files fail closed (log V3). Plan JSON is parsed (`iac/plan.go`, in flight). | SHORT | Rule breadth comes from Checkov/Trivy, but their ids map poorly | Fix the mappings (RP6). S | IC1 |
| IC2 | **Wiz Code** "exact file, line, module, author, code owners" | Module-aware `MapCloudToCode`; `fix` reports "mapped … → main.tf:1 (module…)" (log). No blame, no CODEOWNERS. | SHORT | Author and owner | `gitops/blame.go`. M | IC2 [P1-PLANDIFF] |
| IC3 | **Cortex** Code-to-Cloud Coverage | Absent. | ABSENT | — | `iac/coverage.go`. M | IC3 |
| IC4 | **Trivy/Chk** Actions + SARIF | SARIF 2.1.0 (`[]` on clean); `pr-comment --sarif` for opened paths; SHA-pinned `action.yml`; action e2e in flight. | IN-FLIGHT | No end-to-end run on a release | P1-PLANDIFF + P0-REL | IC4 |
| IC5 | **FCN** Claude Code plugin "scans changed files, auto-fixes, blocks the commit" | `skills/nimbus/SKILL.md`, Cursor rule, pre-commit hook with `--no-store`. The MCP server is not wired into the CLI. | SHORT | An agent hook that runs and blocks | Wire `mcp`; skill calls `scan --iac --changed-only --fail-on`. S | IC5 [P1-MCP] |

## 8. Remediation

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| RM1 | **Qua** "Terraform/CLI/Python + numbered steps + verification step"; **CS** "permissions required, validation checks, compensating controls" | Sidecars carry `actions_required`, `validation.sql`, `rollback`, `breaks_function`, `effort` and `confidence`; this is CrowdStrike-grade content. **`fix --generate-terraform` prints only the file and `terraform plan`**, and the `.tf` header has no steps, verification or rollback. | SHORT | The content exists but users never see it | `cli/fix.go` + `gitops.go:227`: render the sidecar (permissions, steps, verify SQL, rollback, breaks-function warning). S | RM1 [P2-VERIFY] → move to now |
| RM2 | **Prisma/Cortex** "one-click commit suggestion"; **DD** Terraform PR | `fix --patch/--auto-pr` with a port-aware verify oracle; refuses not-fixed patches (log V3-cli). The PR body has generic rollback text ("git revert"). No GitHub suggested-change blocks in `pr-comment`. | SHORT | Inline commit suggestions and sidecar rollback | `prcomment.go`: emit ```` ```suggestion ```` blocks from `PatchTerraformWith`. M | RM2 [P1-PLANDIFF] |
| RM3 | **ASH** remediation plans: "'resolves N / reduces M', phases Prerequisite→Snapshot→Fix→Verify→Done with rollback per step" | `plan`: "resolves 1 path(s) alone, remaining score 151.9 · steps 1–2 together: resolves 2". No grouping by root resource, no phases, no rollback, no "reduces". The order is not by leverage (step 1 resolves 1). The 2 residual paths are unexplained. | SHORT | A plan object | `remediate/plan.go` (group by SG/policy/module; phases from the sidecar). M | RM3 [P2-VERIFY] |
| RM4 | **XM** Remediation Confirmation; **Orca** "Jira close → rescan" | Absent (no `verify`). | ABSENT | Verified closure | `cloud-posture verify <issue>`. M | RM4 [P2-VERIFY] |
| RM5 | **Wiz** Workflows confidence-gated | Absent. | ABSENT | — | Not scheduled | RM5 |
| RM6 | **Kube** `vap deploy-library` | Rego stub. | ABSENT | — | P3-CONTENT | RM6 |

## 9. Compliance & evidence

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| CO1 | **Orca** "185+ frameworks" | 112 Prowler 5.44.0 framework files / 17,294 requirements imported, with CIS text withheld (log). `report --framework cis_aws` → "9 of 42 controls assessed. Coverage: 31 natively, 0 via Prowler ingest, 11 manual". The CIS AWS report is **3.0**. | MATCHES | Native assessability is low; CIS versions lag | Add `--framework-set` defaults; newest CIS ids. S | CO1 |
| CO2 | **Prow** catalog integrity test | `TestFrameworkIntegrity`, PCI 4.0 numbering, Go→Python generation (log). | MATCHES | — | — | CO2 |
| CO3 | **S1** Custom Compliance tree; **Drata** editor | `--custom` YAML; inventory loss (INV) not re-checked. | SHORT | Line-level validation and builder | P3-CONTENT | CO3 |
| CO4 | Audit Manager layout | `--evidence-zip`: per-control JSON + SHA-256 manifest, unsigned. | SHORT | Signature, by-source/by-date views, period coverage | `internal/evidence`. L | CO4 [P2-EVIDENCE] |
| CO5 | **Vanta** hourly; **Upwind** Score Journey | The trend panel says "scan history carries totals only". | ABSENT | — | P2-EVIDENCE | CO5 |
| CO6 | **Vanta** resources API | Absent. | ABSENT | — | `integrations/vanta.go`. M | CO6 |
| CO7 | **Veza** access reviews | Absent. | ABSENT | — | Not scheduled | CO7 |

## 10. Detection, real-time, CDR

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| DR1 | **C7N** event-driven, seconds | Polling every 2 min. **`--help` still says "Real-time change detection"**, while the README says experimental polling. | SHORT | Plus an overclaim in help text | Reword `monitor` help (S); P2-TIMELINE | DR1 |
| DR2 | **GuardDuty** attack sequences; **Wiz Defend** | Events become monitor findings. | SHORT | — | P2-TIMELINE ingest | DR2 |
| DR3 | **Sysdig** Falco | Non-goal. | ABSENT | — | — | DR3 |
| DR4 | **SCC** Correlated Threats | Absent. | ABSENT | — | `internal/timeline`. M | DR4 |

## 11. Integrations & workflow

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| IW1 | **DD** cross-rule notification rules; **J1** new-only | 11 sinks; non-zero exit on total failure (log); routing by `min_severity` only. | SHORT | Routing and one notification per Issue state change | `integrations/dispatch.go` YAML routes. M | IW1 [P2-VERIFY] |
| IW2 | **DD** "field-level two-way Jira; ticket auto-closes when remediated" | GitHub auto-close only. | SHORT | One ticket per Issue, closed on verified fix | P2-VERIFY. M | IW2 |
| IW3 | "**no tool** puts Prowler, Checkov, Trivy and Steampipe output into one graph" | Auto-detected ingest seen for kubescape (6), cartography APOC (17), trivy-operator (4), plus native, Prowler, Checkov and Trivy. | **BEATS** (ingest surface) | Normalisation (RP6) undercuts "one model" | See RP6 | IW3 |
| IW4 | **KICS** 11 formats; **Prow** OCSF by default | `internal/output`: OCSF 1.6 (validated against the official schema, lossless round trip), ASFF limits, GitLab SAST v15, JUnit, CSV, SARIF cap: 8/8 tests PASS. **`convert` → unknown command; `scan -o` lacks them.** | IN-FLIGHT | CLI wiring | `cli/convert.go`; `scan -o` formats. S | IW4, integration pass 3 |

## 12. Dashboard & reporting UX

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| UX1 | **Cortex** Command Center | 8 panels (`ov.png`), drill-through, ui-smoke 23/23. **Inconsistent numbers:** "31 attack paths, 25 critical" vs 2 Critical path Issues; "27 issues new since last scan" after an identical re-ingest. The path graph is an unreadable 31-spoke fan (`pa.png`). | SHORT | The numbers disagree with the CLI and Issues | The dashboard reads path Issue bands; "new since last scan" counts Issues whose `first_seen` is in this scan. S | UX1 frozen (maintenance covers correctness) |
| UX2 | **J1** trends, time-to-remediate | Sparklines; "totals only (no new/resolved counts per scan)". | ABSENT | MTTR, created vs resolved | Persist lifecycle counts per scan. S/M | UX2 [P2-EVIDENCE] |
| UX3 | **MDC** Executive Summary PDF; **ScoutSuite** offline HTML | Python HTML/PDF reports (escaping verified). No exec summary. | SHORT | Exec report | `report --exec`. M | UX3 |
| UX4 | **Infracost** PR cost delta | "no cost data; run cloud-posture cost". | SHORT | (cut to one card) | — | UX4 |

## 13. AI assistant & agent interfaces

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| AI1 | **Upwind** "compiles NL into editable Query Builder expressions"; **FCN** offline identifier-paste | Offline: answers print the SQL and "Sources: … findings: lab-W01, lab-W57, lab-W22". ARN paste → 3 findings. **Inconsistency:** it lists `nimbus-lab-shared-reports` as a public sensitive bucket, but the engine suppresses it as org-conditioned. "who can …" is unmapped. | MATCHES | It answers from findings, not the engine's verdict | Copilot queries `issues`/`paths` verdict views; add a who-can intent. S | AI1 [P1-MCP] |
| AI2 | **Prow** Lighthouse multi-provider incl. Ollama | Anthropic, OpenAI-compatible local, Bedrock; `NO_NETWORK` blocks remote providers (log). | MATCHES | — | — | AI2 |
| AI3 | **Sysdig** Go MCP server filtering tools by token permissions | `smoke.sh`: initialize, 8 tools, scope `read` hides `draft_fix`, DELETE refused, audit JSONL. **`cloud-posture mcp` → unknown command.** | IN-FLIGHT | CLI wiring and HTTP transport | `cli/mcp.go`. S | AI3, integration pass 3 |
| AI4 | **Cortex AgentiX**: RBAC, approvals, audit | Results wrapped as untrusted data; `</tool>` escaped; account ids redacted (`ACCT_1d255e3d`); per-call audit with SQL, rows and duration. | MATCHES | No approval step (none needed while read-only) | — | AI4 |
| AI5 | **Ten** Hexa; **Wiz** agents | Absent. | ABSENT | (cut) | — | AI5 |

## 14. Platform

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| PF1 | **Trivy/Prow** single CLIs; SDKs | 27 commands; `doctor` works. Its message "risk model … fall back to Go" is stale: Go is the only risk model now. | MATCHES | `init`/`validate` | P3-PACKAGE; reword doctor (S) | PF1 |
| PF2 | **Orca** OpenAPI REST | Hardened loopback server, token, Host/CSRF (log). No OpenAPI. | SHORT | Published API contract | P3-SERVER | PF2 |
| PF3 | **Orca** Terraform provider | Config validation; literal secrets rejected (log). | SHORT | Strict schema | P3-SERVER | PF3 |
| PF4 | **Wiz** Tenant Manager | One shared token. | ABSENT | (OIDC-lite Q2 2027) | — | PF4 |
| PF5 | **Trivy**: "brew, Docker (128.3M pulls), every package manager" | No release. `0.1.0-dev`, 218 MB binary. | ABSENT | Installability | `v0.2.0` (owner O3/O4). M | PF5 [P0-REL] |
| PF6 | **Prow** Neo4j or Neptune; **CQ** ~20 destinations | SQLite; Neo4j push. | SHORT | (kept without investment) | — | PF6 |

## 15. Trust & supply chain

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| TS1 | **C7N** cosign-verified images | goreleaser + cosign + syft configured, never run on a tag (log). | ABSENT (shipped) | A signed release | P0-REL | TS1 |
| TS2 | Pin SHAs, immutable releases (Trivy incident lesson) | 31/31 `uses:` pinned; `install.sh` refuses `main` (log). | MATCHES | Immutable-release repo setting (O4) | Owner action | TS2 |
| TS3 | **MDC** scoped scanner roles; **Prow** External ID | Generated `readonly-policy-aws.json` with a guard test (log). | MATCHES | Azure/GCP equivalents | §5.7 | TS3 |
| TS4 | "**No vendor or OSS project publishes path-level ground truth**" | `make groundtruth`: 20 labelled paths + independent 300-resource noise estate, re-runnable. **But** precision counts reported `pending-feature` false positives (F03, F04, S01) as hits. Never run live. | **BEATS** (with an honesty defect) | A real-world precision column | `tests/groundtruth`: add "precision vs real-world truth" counting pending-feature FP labels as FP; publish both. S | TS4; column NEW |

## 16. Ecosystem interop

| ID | Best-in-class (matrix) | nimbus today (observed) | Verdict | Short by | Fix | Plan |
|---|---|---|---|---|---|---|
| EI1 | **Carto** published schema; Prowler runs on it | Cartography APOC export ingested (17 records); export uses Cartography labels. | MATCHES | Full Neo4j dump import into registry types | `adapters/cartography.go` depth. M | EI1 |
| EI2 | **Prow** OCSF, 105 frameworks, ~100 path queries | Frameworks imported (112); Prowler adapter; no path queries. | SHORT | Path queries | P2-CIEM | EI2 |
| EI3 | **SP** table names + Postgres wire | Passthrough. | SHORT | (export only) | Timeout only | EI3 |
| EI4 | **CQ** Arrow to ~20 destinations | Absent. | ABSENT | — | P3-ADAPTERS | EI4 |

---

## Named head-to-heads (the comparisons a buyer will make)

| Competitor behaviour | nimbus, observed | Verdict |
|---|---|---|
| **AWS Security Hub remediation plan**: one plan per target, "resolves N / reduces M", phases Prerequisite→Snapshot→Fix→Verify→Done, rollback per step | `plan` gives resolves N and remaining score, plus an exact minimum set. It has no per-target grouping, no "reduces", no phases and no rollback. The rollback and verify SQL exist in the sidecars but are never printed. | SHORT (math BEATS, packaging SHORT) |
| **FortiCNAPP explain dialog**: top 3 paths, factors, compensating controls, "no data" ≠ 0 | `prioritize --explain` shows a factor table, `not scored` / `missing`, top paths with ids, and `compensating_controls ×1.00` shown explicitly. It is published and versioned, which FCN is not. Saturation (40 findings tied at 10.0) wastes it. | MATCHES (open formula is a plus; saturation a minus) |
| **Wiz Issue page**: evidence, graph, timeline, owner, ticket, remediation | `issues show`: title, ids, score, band, confidence, evidence findings, toxic tag. No hops, explanation, owner, SLA, fix, ticket or graph. `issues history` exists as a separate command. | SHORT |
| **Sysdig custom risk definitions**: SysQL, test-before-save, Live/New badges, auto-close | A YAML rules file, no preview, no badges. Path Issues do auto-resolve. | ABSENT (authoring) |
| **Prowler attack-path query box and ~100 queries** | 11 rule chains; SQL box in the dashboard and `query`; no graph query box; no privesc library. | ABSENT |
| **Datadog suggested policy PR** | None. | ABSENT |
| **Microsoft governance rules** | Owner from a tag, SLA date. No rules or digest; 48/62 findings unowned. | SHORT |
| **Vanta resource API** | None. | ABSENT |
| **Orca missions / verified closure** | No `verify`; closure is "the next scan doesn't see it". | ABSENT |
| **SentinelOne verified exploit paths** | `ValidationStatus` reserved; nothing probes. | ABSENT |
| **Upwind hotspots** | Choke table "closes N". No root-cause grouping (by SG, policy or module). | SHORT |
| **Checkov PR commit suggestions** | `pr-comment` prints a `cloud-posture fix …` command, not a suggested change. | SHORT |
| **Trivy `convert` and formats** | Library has 8 targets (validated); CLI `convert` absent. | IN-FLIGHT |
| **Cartography 76 modules** | ~7 collector providers, fakes only; Cartography *import* works. | SHORT (import MATCHES) |
| **Steampipe 2,000 tables** | 53 tables/views over findings. | SHORT (by design; Diff 2) |

## UX honesty items (competitors.md §5)

| Item | Bar | Observed | Verdict |
|---|---|---|---|
| 7 home panels | Risk + 30d trend; top 5 paths + choke points; Issues by severity with new-since-last-scan; coverage; compliance %; owners leaderboard; savings | All 7 are present (`ov.png`) plus an Issues × provider matrix. No posture *score* number (the risk panel shows the top risk only). The trend lacks new/resolved counts. "27 issues new since last scan" appears after an identical re-ingest. | SHORT (all present; two numbers wrong) |
| Every number is a link → resource drawer (config JSON, findings, paths through it, code origin, owner, history) | — | Overview numbers drill (smoke checks 5, 6, 12). The `node` pane shows findings, paths through it, edges, owner and Open query. **No config JSON, code origin or history.** | SHORT |
| Coverage-honesty panel: denied or skipped API calls per account | — | Per provider/account ok/denied/skipped/error/timeout with reasons, shown in red (smoke check 18; payload-driven). On an ingest the panel has 1 row and says nothing about what the source tool skipped. | MATCHES (for native scans) |
| XSS-safe static HTML (cf. Prowler CVE-2026-73262) | — | Independent probe: hostile title, name, description and tag in 5 records; 6 sections + pane clicks; `__pwned=0`, 0 `<img>`; Python SOC 2 HTML escaped (38 escaped hits, 0 raw). | **MATCHES** the bar, and beats Prowler, which shipped that CVE |

---

## (1) Top 15 shortfalls to fix next, ranked by buyer impact

| # | Shortfall (observed) | Fix | Effort | Owner track | Plan v3? |
|---|---|---|---|---|---|
| 1 | **Three severity scales for one risk.** `paths` shows `[CRITICAL 7.0]` and `[CRITICAL 5.2]`; `issues` shows `HIGH band High`; the dashboard says "25 critical" paths vs 2 Critical path Issues; `prioritize` has 45 Critical vs Issues' 9. This breaks `docs/scoring.md`'s own rule. | `internal/attackpath/traversal.go:944-952` and `engine.go:377-380` derive `Severity` from `risk.BandFor(score)`. The dashboard and copilot read the path band. A test asserts that `paths`, `issues`, `/api/summary` and the dashboard agree on one fixture. | S | P1-ENGINE (+ dashboard maintenance) | NEW |
| 2 | **Known false positives in the top 10, and a benchmark that hides them.** F04 is rank #3 at 10.0; F03 is reported 2× at 7.0, rank #8. Published precision is 100% where real-world precision is 87% (85% at ≥ 7). | (a) AWS route-table/IGW + NACL evaluation in `internal/reach`, pulled from Phase 2 into Phase 1 (M). (b) `tests/groundtruth` adds a "real-world precision" column that counts `pending-feature` FP labels as FP (S). | M + S | P2-REACH → P1; P1-LAB | AP8 yes (Phase 2); column NEW |
| 3 | **Score saturation.** 40 of 62 lab findings score 10.0 (raw ≤ 38.22) and 45 are Critical, so the top of `prioritize` is a tie. | `internal/risk`: bound multiplier stacking (FCN-style: max over paths plus a bounded context uplift) or rank on a log-compressed raw score shown beside the 0–10. Recalibrate on both estates; ScoreVersion 2.2.0 with an upgrade banner. | M | P1-RISK (2nd round) | RP1 partly; saturation NEW |
| 4 | **Skeletal Issue page versus Wiz.** `issues show` has no hops/because, explanation, owner/SLA, fix commands, linked path Issues, ticket or timeline. | `internal/cli/issues.go` `show` and `/api/issues/{id}`: render stored hops with `because`, `risk.Explain` of the top evidence, owner/due, fix commands with sidecar rollback, related Issues (single ↔ path) and inline history. Dashboard Issue pane reads the same. | M | Integration pass 3 + P1-ISSUES | RP1 "Issue-level explain" partly; rest NEW |
| 5 | **Nothing to install.** No release, no brew or image, `0.1.0-dev`, 218 MB binary. | Cut `v0.2.0` through the configured goreleaser/cosign pipeline after O3 (name) and O4 (repo settings); three-OS smoke; strip symbols and check binary size. | M | P0-REL (owner O3/O4) | PF5/TS1 yes |
| 6 | **Built capabilities that users cannot reach.** `who-can`, `mcp` and `convert` → unknown command; `scan -o` has no `ocsf/asff/gitlab/junit`. | `internal/cli/{whocan,mcp,convert}.go`; `scan -o` via `output.Render`; `ingest --list` from `adapters.Versions()`. | S | Integration pass 3 | Yes (session log) |
| 7 | **The plan-diff gate misses escalations.** `bad.plan.json` raises a path 1.9 → 7.0, the comment says "opens 0 / closes 0", and `--fail-on-opened` exits 0. | `internal/pathdiff`: an `Escalated` set (same Issue key, band rises to ≥ High). `prcomment.go`: headline "opens N · escalates E · closes M", footer `nimbus-escalates-paths`, and gate `--fail-on-opened` covers escalations unless `--opened-only`. | S | P1-PLANDIFF (in flight) | NEW (defect in AP10) |
| 8 | **Remediation content that is never shown.** Sidecars have `actions_required`, verify SQL, rollback and breaks-function. `fix` prints only a file path; the PR body says "git revert". `plan` ignores 8 rule-chain paths and never names its 2 residual paths. | `cli/fix.go`, `cli/plan.go`, `gitops.go:227`: render the sidecar as numbered steps (Qualys/CS bar); `plan` lists the residual paths with reasons and includes rule-chain paths; ASH-style "resolves N / reduces M" per step. | S | P2-VERIFY → now (render only) | RM1/RM3 yes (Phase 2); render NEW |
| 9 | **CVE exploitability is not gated.** Any `UNPATCHED` / `CVECount>0` gets p=0.95 (`traversal.go:294-296,372-376`, `credhop.go:64`); DEC decision 5 is unimplemented. | Gate on KEV, EPSS ≥ a sourced threshold, or "package is the exposed service"; otherwise a low documented value. Lab P19 (KEV) must stay ≥ 7. | S | P1-ENGINE | RP2 yes |
| 10 | **Trivy 0.75 ids are unmapped (44/44), so findings duplicate native ones.** Checkov maps 35/95. | `internal/adapters/trivy.go`: normalise `AWS-0028` → `AVD-AWS-0028`, `KSV-0111` → `KSV111`; add catalog aliases; review CKV_GCP_32/49 and CKV_AWS_260; golden gate requires ≥ 80% mapping. | S | Integration pass 3 / P1-INTEROP | Yes (session log) |
| 11 | **Duplicate paths in every listing.** `paths` prints SG-entry and instance-entry variants of one problem (31 rows for 23 Issues); the copilot and dashboard list raw paths. | `paths` defaults to one row per path Issue ("2 hop lists", expandable with `--all-hops`); dashboard and copilot read path Issues. | S | P1-ENGINE / P1-ISSUES | NEW |
| 12 | **Identity chains are under-scored.** P15 (Okta MFA-exempt → AWS admin) 1.44 LOW; P20 (chained external trust) 5.99; P13 (PassRole privesc) 5.32, rank #44. These are the paths Wiz and Cartography show first. | P1-ENGINE identity-entry floor for federated admin and chained external trust (documented as impact policy, like the toxic floor); score `can_escalate_to` edges; Okta ACTIVE user counts as a usable credential. | M | P1-ENGINE + P1-IAM | Lab known gaps yes; floor NEW |
| 13 | **No verified closure** (XM, Orca, Prowler partial scans). "Fix the path" is unproven until a re-collect confirms it. | `cloud-posture verify <issue>`: targeted AWS re-collect (S3/EC2/IAM/SG), re-traverse, `pending_verification → verified_fixed` after N checks with backoff. | M | P2-VERIFY | RM4 yes (Phase 2) → recommend Phase 1 |
| 14 | **Governance is thin.** 48/62 ranked findings have no owner; no rules, digest or overdue report (MDC bar). | `internal/governance`: first-match YAML (tag, account, CODEOWNERS fallback), `issues.owner/due_at`, a weekly digest through existing sinks, and an MTTR/on-time line in `/api/summary`. | M | P2-EVIDENCE → pull forward | RP8 yes |
| 15 | **No path-rule authoring and no privesc library.** 11 rules, no `risk test`, no Live/New badges; Prowler has ~100 attributed path queries. | `rules/paths/*.yaml` schema with `attribution/licence/since`; `cloud-posture risk test <file>` dry run against the stored graph; "New < 30 d" badge; port Prowler's AWS privesc queries keeping their ids. | M/L | P1-ENGINE + P2-CIEM | AP4/ID2 yes |

## (2) Where nimbus already beats everyone (observed evidence only)

1. **Exact, re-verified minimum fix set.** `plan` printed "Minimum fix set: 21 fix(es) — min_fix_exact=true (provably
   minimal), min_fix_verified=true (re-traversal confirmed)". `plan --json` gives `min_fix_coverage 92.4`. No vendor
   computes or publishes this; MDC and SCC stop at choke points.
2. **An open, re-runnable path-level benchmark with an independently written noise estate.** The groundtruth harness
   ran here with 20 labelled paths, `Unlabelled (extra) paths: 0`, recall 95%, and the noise estate result is in the
   log. No vendor or OSS project publishes path ground truth. Caveat: shortfall #2's precision definition.
3. **One graph from heterogeneous scanners in OSS.** Kubescape, Cartography APOC and Trivy Operator auto-detected and
   ingested alongside native, Prowler, Checkov and Trivy. The matrix records that no OSS tool does this. Caveat:
   normalisation (#10).
4. **Plan-time attack-path diff in a PR comment (IN-FLIGHT, already working on fixtures).** `create.plan.json` →
   "this PR opens 1 / closes 0 attack paths", with a redacted topology for public repos, a why line, a fix template
   and a machine-readable footer. No vendor has it. Caveat: the escalation gate (#7).
5. **A published, versioned score explanation down to "not scored".** `prioritize --explain` prints every
   multiplier with status and evidence, including `compensating_controls ×1.00 — no compensating control recorded`
   and `score_version 2.1.0`. FortiCNAPP's dialog is comparable in layout, but its formula is closed. This is a tie
   on UX and ahead on openness, held back by saturation (#3).
6. **Exposure honesty printed per node.** `suppressed (private): … auth required (function_url_auth_type AWS_IAM)`,
   `org-conditioned (Principal * limited by aws:PrincipalOrgID)`, `suppressed (trusted) … 203.0.113.0/24`, and
   "Exposures (not attack paths): 14". This is at parity with MDC width + trusted IPs, with explicit reasons that
   MDC does not print. Only the anonymous-reach check (IAM-auth URL, org-conditioned `*`) is, as far as the matrix
   shows, unique.
7. **XSS-hardened static reports.** An independent probe of the dashboard and the Python HTML report found no
   execution. Prowler shipped CVE-2026-73262 in exactly this surface.

## (3) Verdict

**No.** A CISO who has run Wiz would not call nimbus best-in-class on the wedge capabilities today. The reason is not
missing math: on the lab the engine is genuinely sharp. The precision story survived an independent noise estate,
the minimum fix set is exact and re-verified, every hop says why, and no vendor can show a plan-time path diff.

What the CISO would see in a first session undoes that:

- the same path labelled Critical in one view and High in another;
- a known false positive (an RDS with no internet route) at rank #3 with a perfect 10.0, next to 39 other 10.0s;
- an Issue page with no owner, no fix and no hops;
- headline features (`who-can`, MCP, `convert`) that the binary does not know;
- nothing to `brew install`.

Shortfalls #1, #3, #6, #7, #9, #10 and #11 are all S-sized and fixable in about two weeks. #2 (AWS route/NACL
reachability), #4 (the Issue page) and #5 (a signed release) are the M items that decide the bake-off. With those
landed, and one live AWS run behind the benchmark, nimbus would *beat* Wiz on three wedge claims: the exact minimum
fix set, the published path benchmark and the plan-time path diff. It would match Wiz on explainability. Until
then, the honest pitch is "best open-source attack-path math", not "best-in-class".
