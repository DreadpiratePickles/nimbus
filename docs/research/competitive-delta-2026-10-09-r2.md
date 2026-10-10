# Competitive delta review 2 (2026-10-09, round 2)

This is the second competitive review under the owner's standing rule: "constantly compare the code to the
competitors so we don't come up short". It re-checks round 1 (`docs/research/competitive-delta-2026-10-09.md`) after
wave 3 landed: Engine round 2, Integration passes 3 and 4, P2-REACH v1, Governance v1, Benchmark honesty, and the
wave-2 tracks P1-MCP, P1-INTEROP, P1-PLANDIFF and P1-IAM. The reviewer was read-only on code. Each verdict comes from
behaviour seen in this run unless it is marked "(log)", which means it was taken from
`docs/sessions/2026-10-09-cwm-ui.md` and not re-observed here.

**Verdict scale** (same as round 1). BEATS, MATCHES, SHORT, ABSENT, IN-FLIGHT. **Δ** shows the change against round 1:
↑ better verdict, ↓ worse, = unchanged, "(impr.)" means the same verdict but a smaller gap.
**Effort:** S ≤ 2 agent-days, M ≤ 1 week, L ≤ 3 weeks. **Plan:** the plan v3 row or track; "NEW" means plan v3 does
not have it.

## Method and evidence

Scratch directory: `scratchpad/delta2/`. `CLOUD_POSTURE_NO_NETWORK=1` was set for every command.

- **Build.** At 23:09 the binary was built with `go build -o cp ./cmd/cloud-posture`. `cp version` printed
  `0.1.0-dev`, commit `unknown (dev build)`, score `2.2.0`. The binary is 220 MB unstripped. Built as
  `-trimpath -ldflags "-s -w"` (the goreleaser flags) it is **148 MB, or 36 MB gzipped**.
- **Lab.** `go run ./lab/local/gen` produced output byte-identical to `lab/local/out/estate.findings.json`
  (83 records, 62 weaknesses). It was ingested as round 1 did:
  `cp -c lab.yaml --db lab.db ingest estate.findings.json --source native`, using `lab/local/cloud-posture.lab.yaml`.
- **Commands.**
  - Paths and planning: `paths`, `paths --explain --limit 0`, `paths --exposures`, `plan`, `prioritize --explain`,
    `prioritize --json --top 0`.
  - Issues: `issues`, `issues show <path Issue>`, `issues show <single Issue: nimbus-lab-ledger>`, `issues metrics`,
    `issues --overdue`.
  - Identity: `who-can` (3 queries).
  - Formats: `convert` (nimbus JSON → OCSF → SARIF), and `scan --iac <copy of lab/terraform/aws> -o ocsf`.
  - MCP over the CLI: initialize, `tools/list`, and calls to `paths`, `issue` and `sql DELETE`.
  - PR comments: `pr-comment --plan-json --fail-on-opened` on `testdata/action-fixture/plans/{bad,create,revert}`.
  - Operations: `alert --digest --dry-run`, `doctor`, and `ingest --diff` with `lab-W01` flipped to PASS.
  - First run in an empty `HOME`: `doctor`, then `scan`.
  - Other: `fix --id lab-W02 --generate-terraform`, and `make readme-check`.
- **Harnesses.**
  - `make ui-test`: 25 checks plus "no page errors", "all checks passed".
  - `GROUNDTRUTH_JSON=… go test ./tests/groundtruth -count=1 -v`: PASS.
  - The dashboard was rendered from the lab DB and captured with `shot.mjs` as
    `scratchpad/delta2/{ov,fi,pa,co}.png`, with 0 page errors.
  - The Python copilot was run offline (`python/.venv`, `python -m nimbus ask`) on 5 questions.

## Five things a Wiz-trained buyer now notices in the first ten minutes

1. **The engine got sharp and consistent.**
   - `paths` prints one row per path Issue: "25 attack path Issue(s) from 28 hop variant(s)".
   - The band now follows the score (`[HIGH 7.0]`, `[MEDIUM 5.2]`), and the dashboard says "2 critical", which equals
     the number of Critical path Issues.
   - Only 4 of 62 findings score 10.0 (round 1: 40).
   - Okta → AWS admin, PassRole privesc and the Bedrock agent paths all reach 7.0.
   - F03 and F04 are listed as `[blocked]`, with the exact NACL rule and route table that block them.
2. **The reachability verdict stops at `paths`.**
   - F04 (`nimbus-lab-ledger`, no IGW route) is **`prioritize` rank #7 at 9.8 Critical**, with
     `exposure ×1.40 internet exposed (wide)`.
   - Its Issue is CRITICAL with the same "internet exposed (wide)" factor. This happens even though the Issue title
     says "(flag only; its subnets have no internet-gateway route)".
   - The copilot answers "is nimbus-lab-ledger reachable from the internet?" with a list that includes the ledger.
   - The benchmark scores paths only, so it reports 100% real-world precision while this false positive sits in the
     top 10.
3. **The same risk still appears twice with two scores.** The 7 rule-chain path Issues duplicate traversal Issues:
   - vendor-access is HIGH 8.0 and MEDIUM 5.0;
   - the web IMDS chain is HIGH 7.6 and MEDIUM 5.9/5.7;
   - ops-jane is HIGH 7.0 and LOW 4.4.

   This is the residue of "two engines" (AP1).
4. **`who-can` does not mention the internet.** `who-can s3:GetObject arn:aws:s3:::nimbus-lab-customer-pii/*` lists
   20 principals with statement ids and confidence. It does not list anonymous or public access, although this bucket
   is the #1 attack path because it is "readable by anyone on the internet".
5. **Install and first run still fail the bake-off.**
   - There is no release (`0.1.0-dev`).
   - `make readme-check` FAILS on 3 bad anchors.
   - The README benchmark table is from Track B3 (12 labelled paths, 95.2% precision); the current figures are 20
     labelled paths at 100%.
   - In an empty `HOME`, `scan` prints "No findings. Scan complete! Found 0 open findings" and exits 0. A first-time
     user reads that as "clean".

---

## (1) Round-1 top 15, re-scored

| # | Round-1 shortfall | Status | Evidence seen in this run | What remains |
|---|---|---|---|---|
| 1 | Three severity scales for one risk | **IMPROVED** | `paths` shows `[CRITICAL 10.0]`, `[HIGH 8.0]`, `[MEDIUM 5.2]` and `[LOW 4.4]`: the band follows the score. The dashboard's "28 attack paths, **2** critical" matches the 2 CRITICAL path Issues in `issues`. Issue page: "score: 10.0 (band Critical, path score, version 2.2.0)". | Single Issues use the **scanner** severity (`issues`: 13 CRITICAL, of which 9 are single), while `prioritize` uses the risk band (20 Critical). The ledger Issue is "severity: CRITICAL". Rule-chain duplicates give one risk two bands (new #2). |
| 2 | Known FPs in the top 10, and a benchmark that hides them | **IMPROVED** | `paths --exposures`: "nimbus-lab-ledger [blocked aws_db_instance]: … route table rtb-0a1b2c3d4e5f60001 has no route to an internet gateway". sftp: "NACL acl-0a1b2c3d4e5f60001 rule 90 denies 22/tcp". Groundtruth: "precision labelled 100.0% (28/28) / real-world 100.0% (28/28) … recall@7 95.0% (19/20)". | **F04 is still `prioritize` #7 at 9.8 Critical** ("exposure ×1.40 internet exposed (wide) … no width data; treated as wide"), the ledger Issue is CRITICAL, and the copilot lists it as exposed. F03 dropped to #47 at 6.3 through `off_path`, but its exposure factor still says "wide". The benchmark does not measure the finding ranking (new #1). |
| 3 | Score saturation | **CLOSED** | `prioritize --json --top 0`: 4 of 62 findings at 10.0 (was 40), 20 Critical (was 45). The scores spread: 10, 9.9, 9.8, 9.6, 9.5, 9.4, … `combination ×0.26 diminishing returns above 7.0: raw 38.22 → 10.00`. | 20 of 62 are still Critical (32%). This is acceptable for a seeded estate. |
| 4 | Skeletal Issue page | **CLOSED** | `issues show 441264…` prints: owner `data-platform (tag)`, why, SLA 7d, due, grace, suppression, ticket, the factor table, hops with `because`, hop variants, linked evidence Issues, fixes with 5 phases, and a timeline. The dashboard pane matches (ui-smoke check 24). | LAMBDA_PUBLIC fix is a "generic stub". The verify note still says "Until finding lifecycle lands (Track G)", which is stale. |
| 5 | Nothing to install | **OPEN** | `0.1.0-dev`, `commit: unknown`. Stripped binary 148 MB (36 MB gz). There is no tag, and the README says "not yet published". | Everything (owner O3/O4). |
| 6 | Built capabilities users cannot reach | **CLOSED** | `who-can` answers. `mcp` serves 8 tools with redaction (`ACCT_6565d4b1`) and refuses `DELETE` ("only a single SELECT / WITH query is allowed"). `convert … --to ocsf` gives 83 records, class 2004, OCSF 1.6.0. `scan --iac -o ocsf` gives 57 records. | MCP has no `who_can` tool. MCP `paths` returns `matched: 28` variants, not 25 Issues. |
| 7 | Plan diff misses escalations | **CLOSED** | `bad.plan.json` gives "opens 0 / escalates 1 / closes 0", "1.9 → 7.0 (Low → High)", footer `nimbus-escalates-paths: 1`, and `--fail-on-opened` exits **3**. | `revert.plan.json` (7.0 → 1.9) says "closes 0 attack paths": a fixing PR gets no headline credit or footer (new #14). |
| 8 | Remediation content never shown | **CLOSED** | `fix --generate-terraform` and `plan` print prerequisite (permissions, breaks-function, mitigation) → snapshot → fix → verify (SQL, "expect no rows") → rollback. `plan` now reads "28 attack path(s) (21 traversal, 7 rule-chain)", adds R1–R4 rule-chain steps, and gives "remaining: 16 paths" with a reason for each. | No per-target grouping (ASH). P13 is "no cuttable weakness on the path (no fix template breaks it)" (new #12). |
| 9 | CVE exploitability ungated | **CLOSED** | build-runner: "CVE-2025-1974 not in KEV and no EPSS data: exploitability unknown (confidence hint)". media-01: "CVE-2021-44228 is in CISA KEV (known exploited) [p=0.90]". | — |
| 10 | Trivy ids unmapped (44/44) | **IMPROVED** | `scan --iac` on `lab/terraform/aws`: Trivy 22 mapped and 22 unmapped (round 1: 0/44). 5 canonical ids now merge native and Trivy (`S3_PUBLIC_BUCKET`, `RDS_PUBLIC`, `EC2_IMDSV1`, …). Log: Checkov 46.3%, Trivy 45.0%, lab detections 11/11. | About half of the scanner findings are still `TRIVY:*` or `CKV*` and do not dedupe. |
| 11 | Duplicate paths in every listing | **IMPROVED** | CLI `paths` gives one row per Issue with "(+1 more hop variant(s))" and `--all-variants`. | The dashboard path list shows 28 raw rows (customer-pii twice, at 10.0 and 7.0). The copilot ("28 result(s)") and MCP (28) also list variants. Rule-chain Issues duplicate traversal Issues (new #2). |
| 12 | Identity chains under-scored | **CLOSED** | Okta contractor → SSO admin: HIGH 7.0 (was 1.44). dev-sam PassRole+RunInstances: 7.0 (was 5.32). Bedrock agent: 7.0 with a "prompt injection … [p=0.70]" hop (was MISSED). auditor → break-glass: 7.0. | The P13 path has no fix (new #12). |
| 13 | No verified closure | **OPEN** | `cloud-posture --help` has no `verify`. `ingest --diff` gives "1 resolved lab-W01" but "Path Issues: 0 opened, 0 reopened, 0 resolved", which hides the path's drop from 10.0 to 7.0. | All of it. |
| 14 | Governance thin | **IMPROVED** | `issues metrics` (open/overdue/past grace, on-time, MTTR by severity, by owner). `issues --overdue`. `alert --digest --dry-run` gives a per-owner digest with fix commands. Dashboard owners panel (ui-smoke 25). Owner `why` trail on the Issue page. One ticket per Issue (log, unit-tested). | With the default config, **70 of 89 Issues are "(unassigned)"**, and the digest goes to "(unassigned)". The digest only sends to Slack and stdout. There is no Jira → nimbus sync. |
| 15 | No path-rule authoring or privesc library | **OPEN** | There are still 11 rules and no `risk test`. | All of it. |

**Tally:** 7 CLOSED (3, 4, 6, 7, 8, 9, 12) · 5 IMPROVED (1, 2, 10, 11, 14) · 3 OPEN (5, 13, 15). All three OPEN
items are M or L, or blocked on the owner.

---

## (2) Full capability table, round 2

The columns are: round-1 verdict → round-2 verdict, Δ, and the observed evidence or the remaining gap. The
best-in-class bar for each row is the round-1 row with the same ID.

### 1. Inventory & graph

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| IG1 | SHORT | SHORT | = | `doctor`: "0 account(s)". Fakes only. No live run (O1). |
| IG2 | SHORT | SHORT | (impr.) | The Okta→SSO-admin path now scores 7.0 (identity floor). `federates_to` is still lab-declared, and no collector emits it. |
| IG3 | SHORT | SHORT | = | No org fan-out. |
| IG4 | IN-FLIGHT | MATCHES | ↑ | IAM-evaluated edges landed: `who-can` gives `statement arn:aws:iam::aws:policy/AdministratorAccess#0`, `verified/inferred/hint`. Still no `BuildFromInventory`. |
| IG5 | SHORT | SHORT | = | Inventory comes only from finding-bearing resources. |
| IG6 | ABSENT | ABSENT | = | `paths --help` has no `--from/--to/--through`. |
| IG7 | SHORT | SHORT | = | `finding_history` and `path_issue_history` exist. No `resource_versions` or config diff. |
| IG8 | MATCHES (fakes) | MATCHES (fakes) | = | Ingest coverage panel: "1 API calls / tool runs recorded". REACH adds per-call rows (log). |
| IG9 | SHORT | MATCHES | ↑ | Bedrock agent → role is a path hop: "prompt injection through untrusted input … [p=0.70]", path 7.0. |

### 2. Attack paths & toxic combinations

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| AP1 | SHORT | SHORT | (impr.) | Recall 100%, recall@7 95%. **The two engines persist:** 7 rule-chain Issues duplicate traversal Issues at different scores. No `Truncated` flag and no scale benchmark. |
| AP2 | SHORT | MATCHES | ↑ | One band vocabulary, and `because` on every hop. Permission hops cite the grant ("via Okta SAML app …"). |
| AP3 | MATCHES | MATCHES | = | 89 Issues (25 path, 2 combination, 62 single). The Issue page is now complete. |
| AP4 | ABSENT | ABSENT | = | 11 rules, no dry run. |
| AP5 | MATCHES | MATCHES | = | `--choke`; dashboard "Choke points (10) … closes 2". `issues --kind chokepoint` → "must be single, combination or path". |
| AP6 | **BEATS** | **BEATS** | = | "19 fix(es) — min_fix_exact=true … min_fix_verified=true … removes 91%". The residual paths are now named with reasons. |
| AP7 | MATCHES | MATCHES | = | "Exposures (not attack paths): 16" now includes `[blocked]` entries with reasons. "Dead ends: 17". Still no "X of Y reach no jewel" headline. |
| AP8 | SHORT | MATCHES (AWS, paths only) | ↑ | Route, NACL and LB evaluator. F03 and F04 are blocked with the exact rule. **Not consumed by risk, Issues or the copilot** (F04 is #7 at 9.8). Azure and GCP: NSG/firewall only. |
| AP9 | ABSENT | ABSENT | = | No probes. |
| AP10 | IN-FLIGHT | **BEATS** | ↑ | opens / escalates / closes. `--fail-on-opened` exits 3 on an escalation. Redacted topology. Action e2e PASS locally with OpenTofu 1.13.1 (log). No vendor has this. |

### 3. Risk prioritization

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| RP1 | SHORT | MATCHES | ↑ | 4/62 at 10.0. The factor table includes `combination` and `not scored`. Score version 2.2.0. |
| RP2 | SHORT | MATCHES | ↑ | KEV/EPSS gate observed (KEV 0.9; unknown → hint). |
| RP3 | MATCHES | MATCHES | = | Crown-jewel rules via config. |
| RP4 | SHORT | SHORT | = | `compensating_controls ×1.00 — no compensating control recorded` on every row. REACH blockers do not reach the risk factor. |
| RP5 | MATCHES | MATCHES | = | Auto-resolve works. `--diff` still hides path score drops ("0 resolved"). |
| RP6 | SHORT | SHORT | (impr.) | Trivy 22/44 mapped (was 0/44). 5 canonical ids merge across sources. |
| RP7 | MATCHES | MATCHES | = | Suppression with reason and expiry. |
| RP8 | SHORT | MATCHES | ↑ | Rules → tag → CODEOWNERS → account → default. SLA and grace. Digest. Metrics. Overdue. The default config leaves 70/89 unassigned. |

### 4. Identity / CIEM

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| ID1 | IN-FLIGHT | MATCHES (offline) | ↑ | F02 (explicit Deny) and F09 (SCP) are suppressed. S01 is suppressed via `effective_admin` (log + groundtruth PASS). Not run live. |
| ID2 | IN-FLIGHT | SHORT | ↑ | P13 PassRole is found at 7.0. The technique library is small, and the path has no fix template. |
| ID3 | IN-FLIGHT | SHORT | ↑ | `who-can` works: chains, statements, confidence. It **omits anonymous/public access** on a public bucket. No MCP tool and no copilot intent. |
| ID4 | ABSENT | ABSENT | = | No right-sizing. |
| ID5 | SHORT | SHORT | = | No Azure RBAC. |
| ID6 | SHORT | SHORT | = | K8s paths are found at 7.0; no effective verbs. |
| ID7 | ABSENT | ABSENT | = | Cut. |

### 5–6. Data, vulnerabilities

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| DS1 | ABSENT | ABSENT | = | Cut. |
| DS2 | ABSENT | ABSENT | = | — |
| DS3 | SHORT | SHORT | = | Sensitivity ×1.50 on labels. No `stores_data_in` collector. |
| VS1 | SHORT | SHORT | (impr.) | Trivy mapping at about 50%. |
| VS2 | ABSENT | ABSENT | = | Cut. |
| VS3 | ABSENT | ABSENT | = | — |
| VS4 | SHORT | SHORT | = | No secret validation. |
| VS5 | ABSENT | ABSENT | = | — |

### 7. IaC & code-to-cloud

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| IC1 | SHORT | SHORT | (impr.) | 13 native + 44 Trivy findings on `lab/terraform/aws`; about half are mapped. |
| IC2 | SHORT | SHORT | (impr.) | CODEOWNERS is used for ownership. No blame or author. |
| IC3 | ABSENT | ABSENT | = | — |
| IC4 | IN-FLIGHT | SHORT | ↑ | Action e2e passes locally (log). It cannot be used without a release. |
| IC5 | SHORT | SHORT | (impr.) | `mcp` is wired, and the skill and Cursor rule reference it. No observed commit-blocking agent hook. |

### 8. Remediation

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| RM1 | SHORT | MATCHES | ↑ | `fix` prints permissions, breaks-function, mitigation, snapshot, verify SQL and rollback. |
| RM2 | SHORT | SHORT | = | `pr-comment` "fix:" prints a CLI command, not a ```` ```suggestion ```` block. |
| RM3 | SHORT | MATCHES | ↑ | "resolves N alone, reduces M", phases, rule-chain R-steps, remaining paths with reasons. No per-target grouping. |
| RM4 | ABSENT | ABSENT | = | No `verify`. |
| RM5 | ABSENT | ABSENT | = | — |
| RM6 | ABSENT | ABSENT | = | — |

### 9. Compliance & evidence

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| CO1 | MATCHES | MATCHES | = | `--framework-set default` (log). |
| CO2 | MATCHES | MATCHES | = | — |
| CO3 | SHORT | SHORT | = | — |
| CO4 | SHORT | SHORT | = | The evidence zip is unsigned. |
| CO5 | ABSENT | ABSENT | = | Trend: "totals only". |
| CO6 | ABSENT | ABSENT | = | — |
| CO7 | ABSENT | ABSENT | = | — |

### 10. Detection

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| DR1 | SHORT | SHORT | = | `monitor --help` **still says "Real-time change detection"**. |
| DR2 | SHORT | SHORT | = | — |
| DR3 | ABSENT | ABSENT | = | — |
| DR4 | ABSENT | ABSENT | = | — |

### 11. Integrations & workflow

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| IW1 | SHORT | SHORT | (impr.) | Per-owner digest with a dedup ledger. Routing is still by `min_severity` only. Teams, email and webhook digests are "not implemented yet". |
| IW2 | SHORT | MATCHES (log) | ↑ | One Jira/GitHub ticket per Issue with assignee and due date; close and reopen follow the Issue (unit-tested). No reverse sync. |
| IW3 | **BEATS** | **BEATS** | = | Multi-scanner ingest. Normalisation has improved. |
| IW4 | IN-FLIGHT | MATCHES | ↑ | `convert` and `scan -o ocsf` observed. OCSF 1.6, class 2004. |

### 12. Dashboard

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| UX1 | SHORT | SHORT | (impr.) | The numbers agree now ("2 critical", "0 issues new since last scan"). The paths view lists 28 raw variants, and the graph is still an unreadable 28-spoke fan (`pa.png`). |
| UX2 | ABSENT | SHORT | ↑ | MTTR by severity in the owners panel. The trend is still totals only. |
| UX3 | SHORT | SHORT | = | No exec report. |
| UX4 | SHORT | SHORT | = | — |

### 13. AI & agent interfaces

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| AI1 | MATCHES | **SHORT** | ↓ (re-scored) | The copilot contradicts the engine in 3 of 5 offline answers. It lists `nimbus-lab-shared-reports` (org-conditioned) as a public sensitive bucket. It returns the ledger as internet-exposed. "who can read …" gives "could not map". The code did not regress: the engine moved and the copilot did not. |
| AI2 | MATCHES | MATCHES | = | — |
| AI3 | IN-FLIGHT | MATCHES | ↑ | `cloud-posture mcp`: 8 tools, scopes, redaction, audit JSONL, refused DELETE. stdio only. |
| AI4 | MATCHES | MATCHES | = | Untrusted-data wrapper observed. |
| AI5 | ABSENT | ABSENT | = | Cut. |

### 14. Platform

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| PF1 | MATCHES | MATCHES | = | The `doctor` "risk model … fall back to Go" message is still stale. `scan` with 0 targets reports a clean result. |
| PF2 | SHORT | SHORT | = | — |
| PF3 | SHORT | SHORT | = | — |
| PF4 | ABSENT | ABSENT | = | — |
| PF5 | ABSENT | ABSENT | = | No release. 148 MB stripped. |
| PF6 | SHORT | SHORT | = | — |

### 15. Trust & supply chain

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| TS1 | ABSENT | ABSENT | = | The pipeline is configured but has never run on a tag. |
| TS2 | MATCHES | MATCHES | = | — |
| TS3 | MATCHES | MATCHES | = | The read-only policy was regenerated (+17 actions, log). |
| TS4 | **BEATS** | **BEATS** | = (defect fixed) | The labelled and real-world columns are both published (28/28; noise 4/4). New caveat: the benchmark is path-level only, so the F04 finding at #7 is not counted. |

### 16. Ecosystem interop

| ID | R1 | R2 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| EI1 | MATCHES | MATCHES | = | — |
| EI2 | SHORT | SHORT | = | No path queries. |
| EI3 | SHORT | SHORT | = | — |
| EI4 | ABSENT | ABSENT | = | — |

**Totals (91 rows).**

| | BEATS | MATCHES | SHORT | ABSENT | IN-FLIGHT |
|---|---|---|---|---|---|
| Round 2 | 4 | 28 | 35 | 24 | 0 |
| Round 1 | 3 | 16 | 39 | 25 | 8 |

Round-1 counts are re-tallied from its rows; "MATCHES (fakes)" and similar variants count as MATCHES. Changes since
round 1: 18 rows up, 1 down. The one down is AI1, which was re-scored, not regressed.

---

## (3) New top 15 shortfalls, ranked by buyer impact

This list repeats no CLOSED item. IMPROVED items appear only for what remains of them.

| # | Shortfall (observed) | Fix | Effort | Owner track | Plan v3? |
|---|---|---|---|---|---|
| 1 | **The reachability verdict does not reach risk, Issues or the copilot.** F04 `nimbus-lab-ledger` is `paths --exposures` `[blocked]` ("no route to an internet gateway"). Yet it is `prioritize` #7 at 9.8 Critical with "exposure ×1.40 internet exposed (wide)". Its Issue says "severity: CRITICAL" with the same factor, and the copilot returns it as exposed. F03's exposure factor also says "wide". | In `internal/risk`, the exposure factor reads `graph.ReachabilityOf`. Blocked gives ×1.00 with "blocked: <reach_blocker>" and the off-path cap. Unknown keeps "treated as wide" but is labelled `inferred`. A single Issue on a blocked exposure takes the risk band. The copilot reads the exposures verdict. Add a consistency test asserting F03 and F04 agree across `paths`, `prioritize`, `issues show`, `/api/risk/top` and the copilot. Add a finding-level row to the benchmark: "no pending-feature or FP resource in the prioritize top 10". | S | Engine round 3 + Integration | NEW |
| 2 | **Two engines produce the same risk twice with different scores.** Rule-chain Issues duplicate traversal Issues: vendor-access 8.0 HIGH vs 5.0 MEDIUM; web IMDS 7.6 vs 5.9 and 5.7; ops-jane 7.0 vs 4.4; gha-legacy 7.0 vs 5.6; auditor 7.0 vs 4.6. | When a rule chain's findings ⊆ a traversal path Issue's evidence, attach the rule as a `matched_rules` tag on that Issue and emit no separate Issue. Keep rule-chain Issues only where no traversal counterpart exists. The plan's R-steps then disappear for covered chains. | S/M | P1-ENGINE | AP1 (migrate rules) yes; dedup NEW |
| 3 | **Nothing to install.** `0.1.0-dev`, 148 MB stripped, no tag, no brew, no image. | Cut a signed `v0.2.0` (see the checklist in §6). | M | P0-REL (owner O3/O4) | yes (PF5/TS1) |
| 4 | **Never run against a live cloud.** Every wedge claim rests on a synthetic estate written by the same project. `doctor` → "0 account(s)". | Apply `lab/terraform/aws` in a sandbox account, scan live, and publish a "live" column in `benchmark.json` (`live_cloud: true`). | M | P1-LAB (owner O1) | yes (IG1/TS4) |
| 5 | **`who-can` omits the internet.** For the public PII bucket it lists 20 IAM principals and never says "anyone (anonymous)". | In `graph.WhoCan`, add a synthetic `*` (anonymous) principal from public-ACL or `Principal:*` statements. Conditions (`aws:PrincipalOrgID`) demote it to "org-wide". Add an MCP `who_can` tool and a copilot intent. | S | P1-IAM / P2-CIEM | who-can yes; anonymous NEW |
| 6 | **No verified closure.** There is no `verify`. `ingest --diff` hides the path score drop (customer-pii path 10.0 → 7.0 shows "0 resolved"). | `cloud-posture verify <issue>`: targeted re-collect plus re-traverse, `pending_verification → verified_fixed`. `--diff` prints path Issue score and band changes. | M | P2-VERIFY | RM4 yes; diff display NEW |
| 7 | **The dashboard paths view is raw and unreadable.** 28 variant rows (customer-pii at 10.0 and 7.0), a 28-spoke fan graph with overlapping labels, and "28 attack paths" against the CLI's "25 attack path Issue(s)". | The dashboard reads `Analysis.Grouped()` or path Issues. The graph renders only the selected Issue's hops (Wiz focused-path view), with the fan behind a toggle. | S/M | Dashboard maintenance | NEW (UX1 frozen) |
| 8 | **The copilot answers from raw findings and contradicts the engine.** shared-reports (org-conditioned) is listed as public, the ledger as exposed, "who can" is unmapped, and "top attack paths" returns 28 variants. | Offline intents query path Issues, the exposures verdict and Issue bands. The who-can intent calls the Go `who-can --json`. Add a parity test against `paths` and `issues`. | S | P1-MCP follow-up | NEW |
| 9 | **Out-of-box ownership is mostly empty.** 70 of 89 Issues are "(unassigned)", and the digest goes to "(unassigned)". | `onboard` writes a governance block from the tag keys it finds (`owner`/`team`) and the account owners. `doctor` warns "N% of open Issues unassigned". The digest sends unassigned Issues to `defaults.owner` or skips them. | S | Governance | NEW |
| 10 | **Docs and claims are stale, and the gate is red.** `make readme-check` FAILS: 3 refs to `docs/benchmark.md#cloud-lab-unverified`. The README benchmark is from B3 (12 paths, 95.2%). "no full policy evaluator yet" and "noise estate … not scored yet" are stale. The command table lacks `who-can`, `mcp`, `convert` and `issues`. `monitor --help` says "Real-time". `doctor` says "risk model … fall back to Go". The verify note says "Until finding lifecycle lands (Track G)". | Regenerate the README benchmark block from `benchmark.json`, fix the anchors, add the commands, reword the help, `doctor` and the sidecar notes. Make `readme-check` a CI gate on the release tag. | S | Docs / Integration | partly (DR1/PF1); rest NEW |
| 11 | **The first scan reports a false "clean".** In an empty `HOME`, `scan` prints "No findings. Scan complete! Found 0 open findings" and exits 0. | With 0 accounts and no `--iac`: exit 2, "nothing was scanned: no accounts configured (run cloud-posture onboard)", and a coverage row "no targets". `--fail-on` never passes a scan that had no targets. | S | CLI | NEW |
| 12 | **Privilege-escalation paths have no fix.** P13 (dev-sam PassRole + RunInstances, 7.0) gives "no cuttable weakness on the path (no fix template breaks it)". The minimum fix set removes 91%, not 100%. | A fix template for `iam:PassRole` (resource-scoped plus an `iam:PassedToService` condition) and an MFA-enforcement template for the user hop. In general, policy-diff fixes for permission edges. | M | P2-CIEM | ID4 yes; PassRole template NEW |
| 13 | **No path-rule authoring and no privesc library** (carried over). 11 rules, no `risk test`, no badges. | `rules/paths/*.yaml` with attribution, plus `cloud-posture risk test`, plus Prowler AWS privesc queries ported with their ids. | M/L | P1-ENGINE + P2-CIEM | yes (AP4/ID2) |
| 14 | **The PR comment does not credit fixes or offer commits.** `revert.plan.json` 7.0 → 1.9 gives "closes 0" and no footer credit. "fix:" is a CLI command, not a suggestion. Plan-only confidence is "hint". | Add `de-escalates N` to the headline, a `nimbus-reduces-paths` footer (`tools/northstar` counts it), and ```` ```suggestion ```` blocks from `PatchTerraformWith`. | M | P1-PLANDIFF | RM2 yes; de-escalation NEW |
| 15 | **About half of scanner findings are still unnormalised** (IMPROVED #10). On the lab IaC, 22 of 44 Trivy findings remain `TRIVY:*`; Checkov maps 46%. | Next alias tranche driven by the golden gate (raise the threshold to ≥ 80% mapped). Add a `catalog unmapped` report so users can see the gap. | S/M | P1-INTEROP | yes (session log) |

## (4) Where nimbus now beats everyone (observed evidence only)

1. **Exact, re-verified minimum fix set, with named residuals.** `plan` prints "Minimum fix set: 19 fix(es) —
   min_fix_exact=true (provably minimal), min_fix_verified=true (re-traversal confirmed)". It then gives every
   remaining path with its reason: "broken by a later fix of the minimum set" or "no cuttable weakness on the path".
   Each step has prerequisite → snapshot → fix → verify SQL → rollback. MDC and SCC stop at choke points. ASH has phases
   but no minimality proof.
2. **Plan-time attack-path diff that gates escalations.** `pr-comment --plan-json bad.plan.json` prints "this PR
   opens 0 / escalates 1 / closes 0", "1.9 → 7.0 (Low → High)", footer `nimbus-escalates-paths: 1`, and exit 3 under
   `--fail-on-opened`. `create.plan.json` gives "opens 1", with why, fix and a redacted topology. No vendor diffs
   attack paths at plan time.
3. **An open path-level benchmark with an honest real-world column.** `go test ./tests/groundtruth` prints
   "precision labelled 100.0% (28/28) / real-world 100.0% (28/28) | recall@7 95.0% (19/20)", plus an independently
   written noise estate at 4/4. It also writes `benchmark.json`. No vendor or OSS project publishes path ground truth.
   (Caveats: synthetic only, and the finding ranking is not covered; see #1 and #4.)
4. **Reachability verdicts with the exact blocking rule.** `paths --exposures` prints
   "nimbus-lab-sftp-01 [blocked …]: NACL acl-0a1b2c3d4e5f60001 rule 90 denies 22/tcp from 0.0.0.0/0" and
   "nimbus-lab-ledger [blocked …]: route table rtb-… has no route to an internet gateway (routes: 10.20.0.0/16 →
   local)". It also gives per-node "trusted" and "auth required" reasons. MDC shows wide or narrow without the rule,
   and ASH's reachability trait does not print the NACL rule number. This counts as BEATS on explanation only, until
   #1 propagates it everywhere.
5. **A published, versioned score explanation that shows its own compression.** `prioritize --explain` prints
   every factor with its status and evidence: "combination ×0.26 diminishing returns above 7.0: raw 38.22 → 10.00",
   `not scored: exploitability`, and `score_version 2.2.0`. FortiCNAPP's dialog has a similar layout, but its formula
   is closed.
6. **One graph from heterogeneous scanners in OSS.** Native, Prowler, Checkov, Trivy, Kubescape, Cartography and
   Trivy Operator are all ingested. Native and Trivy now merge on 5 canonical ids in a single `scan --iac`.
7. **XSS-hardened static reports.** ui-smoke check 16 (`</script><img onerror>`: `__pwned` undefined, 0 img) and
   0 page errors over 25 checks. Prowler shipped CVE-2026-73262 in this surface.

## (5) Verdict

**Not yet, but the reasons have changed.** In round 1 a Wiz-trained CISO would have rejected nimbus on its first
screen: three severity scales, 40 tied 10.0 scores, a skeletal Issue page, and headline commands that did not exist.
Those defects are gone.

The engine is now consistent within itself. Every hop says why, identity and agent chains score where Wiz would put
them, and `plan` proves its fix set minimal. Every wedge capability, including `who-can`, MCP, OCSF and the
escalation gate, is now reachable from the binary. On the wedge capabilities (attack-path math, plan-time diff,
explainability, an open benchmark), nimbus is now **ahead of every named competitor in substance**.

The CISO would still not say "best-in-class", for three reasons:

- **Nothing is verified against a real cloud.** Every number comes from a lab the project wrote itself.
- **The reachability verdict is local to `paths`.** The RDS that nimbus itself says is blocked is still a 9.8
  Critical in the risk list, the Issue and the copilot. A CISO who finds that in a demo stops trusting the rest.
- **There is nothing signed to install.**

**The single thing that would change the answer: a published live-account run.** Apply the lab twin to a real AWS
account, scan it with the shipped binary, and publish the labelled and real-world precision and recall next to the
synthetic ones, with `live_cloud: true`. That is the evidence a Wiz-trained buyer asks for first, and no competitor
publishes it. Shortfall #1 is S-sized and must land first, or the live run will expose exactly that inconsistency.

## (6) Release readiness: what must be true at install time for a signed v0.2.0 (buyer's view)

The "Today" column shows the state observed in this run. ✗ = not met, ~ = partly met, ✓ = met.

| # | Must be true at install time | Today |
|---|---|---|
| 1 | `brew install`, `docker run ghcr.io/…@sha256` and `install.sh --require-signature` each work on macOS arm64, Linux amd64 and Linux arm64, and `cosign verify-blob` succeeds against the documented identity. | ✗ no tag; the pipeline has never run |
| 2 | `cloud-posture version` prints `0.2.0`, a real commit, a build date and `score 2.2.0`. | ✗ `0.1.0-dev`, `commit: unknown` |
| 3 | The binary size is stated and reasonable. Archive ≤ 40 MB. An SBOM is attached. | ~ 148 MB stripped / 36 MB gz; the SBOM is configured but never produced |
| 4 | `doctor` on a clean machine has no stale messages, exits non-zero on a hard failure, and states the embedded KEV/EPSS snapshot date. | ~ The "risk model … fall back to Go" message is stale. The snapshot date is shown only on other commands. |
| 5 | **The first `scan` with no targets says nothing was scanned** and exits non-zero. It never prints "0 open findings". | ✗ "No findings. Scan complete!" exit 0 |
| 6 | The first `onboard` → `scan` on one AWS account produces findings, paths, coverage rows (including denied calls) and owners from tags in under 10 minutes, on the shipped read-only policy. | ✗ never run live (O1) |
| 7 | A quickstart demo works offline: `cloud-posture ingest <bundled lab>` → `paths`, `plan`, `issues show`, `dashboard`. The output matches the README. | ~ It works from a source checkout; it is not in the release archive |
| 8 | **One verdict everywhere:** `paths`, `prioritize`, `issues`, the dashboard, MCP and the copilot agree on the bands and on blocked exposures for the lab (shortfall #1), and path Issues are not duplicated by rule chains (#2). | ✗ F04 is #7 at 9.8; 7 duplicate rule-chain Issues |
| 9 | README claims are current, and `make readme-check` passes in the release workflow. | ✗ readme-check FAILS (3 bad anchors); the benchmark table is from B3 |
| 10 | The README benchmark numbers come from `benchmark.json` for that tag: labelled and real-world, lab and noise. "Synthetic, not live" is stated in the first screen. | ~ benchmark.json exists; the README is stale; the "not live" banner is present |
| 11 | Every command a buyer sees in `--help` is documented, and no help text overclaims ("Real-time"). | ✗ `monitor` help; the README command table lacks `who-can`, `mcp`, `convert`, `issues` |
| 12 | The GitHub Action pinned by SHA to the v0.2.0 commit passes the e2e workflow on GitHub, not only locally. | ~ local PASS (log); CI run pending a release |
| 13 | The MCP config snippet for Claude Desktop and Cursor works against the installed binary: tools listed, redaction on, audit file written. | ✓ observed (stdio) |
| 14 | `convert` and `scan -o ocsf\|sarif\|asff\|gitlab\|junit` outputs validate (OCSF 1.6 schema, SARIF 2.1.0). | ✓ observed / tests (log) |
| 15 | SECURITY.md verification steps, the immutable-release repository setting (O4), and a CHANGELOG with the 2.1.0 → 2.2.0 score change and the retired band-SLA due dates. | ~ the docs exist; O4 is undecided; changelog not checked |
| 16 | `go test ./...`, `pytest`, `make ui-test`, `make groundtruth` (strict) and govulncheck are green on the tagged commit. | ✓ on the live tree today (ui-test, groundtruth observed; the rest in the log) |
