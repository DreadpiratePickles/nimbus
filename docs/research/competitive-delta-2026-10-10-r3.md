# Competitive delta review 3 (2026-10-10, round 3)

This is the third competitive review under the owner's standing rule: "constantly compare the code to the
competitors so we don't come up short". It re-checks round 2 (`docs/research/competitive-delta-2026-10-09-r2.md`)
after wave 4 landed: V4-ENGINE, V4-SEC and V4-PRODUCT (`docs/sessions/2026-10-09-cwm-ui.md`, "Fix track V4-*").
The reviewer was read-only on code. A read-only verifier ran at the same time, and no code agents ran. Each verdict
comes from behaviour seen in this run unless it is marked "(log)". "(log)" means it was taken from the session log
and not re-observed here.

**Verdict scale** (same as rounds 1 and 2). BEATS, MATCHES, SHORT, ABSENT, IN-FLIGHT. **Δ** is measured against
round 2: ↑ better, ↓ worse, = unchanged, and "(impr.)" means the same verdict with a smaller gap.
**Effort:** S ≤ 2 agent-days, M ≤ 1 week, L ≤ 3 weeks. **Plan:** the plan v3 row or track
(`.planning/IMPLEMENTATION_PLAN_v3.md`). "NEW" means plan v3 does not have it.

## Method and evidence

Scratch directory: `scratchpad/delta3/`. `CLOUD_POSTURE_NO_NETWORK=1` was set for every command.

- **Build.** At 00:07 on 2026-10-10 the binary was built with `go build -o cp ./cmd/cloud-posture`.
  - `cp version` printed `0.1.0-dev`, `commit: unknown (dev build)`, `built: unknown`, `score: 2.3.0`.
  - Unstripped it is 220 MB. With `-trimpath -ldflags "-s -w"` it is **155 MB, or 38 MB gzipped** (round 2: 148 MB
    and 36 MB).
- **Lab.**
  - `go run ./lab/local/gen -out …` produced output byte-identical to `lab/local/out/estate.findings.json`
    (83 records).
  - It was ingested with `cp -c lab.yaml --db lab.db ingest estate.findings.json --source native`, using
    `lab/local/cloud-posture.lab.yaml`.
- **Commands run as in rounds 1 and 2.**
  - `paths` and `paths --exposures`
  - `plan`
  - `prioritize --explain` and `prioritize --json --top 0`
  - `issues`, `issues --json`, `issues show <PII path Issue>` and `issues --overdue`
  - `who-can`
  - `convert` (native → OCSF → SARIF)
  - `scan --iac lab/terraform/aws`
  - `mcp`
  - `pr-comment` on the three fixture plans
  - `doctor`
  - a first run in an empty `HOME`
  - `make readme-check` and `readme-bench -check`
  - `GROUNDTRUTH_STRICT=1 go test ./tests/groundtruth`
- **New surfaces in this round.**
  - **`verify --from-file` on a modified estate.**
    - `mod_w01.json` has lab-W01 flipped to PASS.
    - `mod_w01_w12.json` has W01 and W12 flipped to PASS.
    - Both were run on a copy of the lab DB, followed by `ingest --diff`.
  - `issues metrics`.
  - `governance init`.
  - `scan` with nothing configured.
  - **`pr-comment` with `--iac`.** It was run on the committed fixture and on two fixture copies:
    - `fx`: SSH source written as a literal `0.0.0.0/0`.
    - `fx` plus a `variables.tf` that already declares `allowed_cidrs`.
  - `who-can` on the PII bucket and on the org-conditioned bucket.
  - The grouped `paths` view.
  - **Dashboard.** It was rendered from the lab DB and captured with `shot.mjs`:
    - `ov.png` (overview)
    - `pa.png` (grouped paths, default focus)
    - `pa_focus.png` (row 12 selected)
    - `fi.png`
    - All four had 0 page errors.
  - **Copilot.** `python -m nimbus ask` was run offline on 5 questions, with and without `CLOUD_POSTURE_BIN`.
  - **MCP with a hostile client.**
    - `hex()`, `substr`, concatenation and `CAST` over `account`
    - a `LIKE '1111%'` / `'2222%'` oracle
    - `main.` qualification, `DELETE` and stacked statements
    - `unicode(substr())`
    - `paths`, and `issue` on the ledger Issue
  - `onboard` with no credentials.
- **First 30 minutes.** The repository was copied to `scratchpad/delta3/clone` (no `node_modules`, `.venv`, `bin`
  or DBs), and the README was followed from `make build`. See §7.

---

## (1) Round-2 top 15, re-scored

| # | Round-2 shortfall | Status | Evidence seen in this run | What remains |
|---|---|---|---|---|
| 1 | Reachability verdict does not reach risk, Issues or the copilot | **CLOSED** | F04 `nimbus-lab-ledger` is **`prioritize` #45 at 6.8 Medium** (round 2: #7 at 9.8 Critical). Its factor reads `exposure ×0.50 not exposed (blocked: route table rtb-0a1b2c3d4e5f60001 has no route to an internet gateway …) (overrides weakness PUBLIC_NETWORK_EXPOSURE …)`. Its Issue `bc4824d6…` is **MEDIUM**. The copilot says "Blocked … (1): nimbus-lab-ledger (route table rtb-… has no route …)". MCP `issue` carries `verdict.label "not exposed (blocked: …)"`. Groundtruth prints "finding-level: critical on non-exposed 0 … top 10: 0 of 62". | The MCP verdict text still names `rtb-…`/`acl-…` ids, which are not redacted (see new #7). jump-01's empty verdict (log) is still open. |
| 2 | Two engines produce the same risk twice | **CLOSED** | `paths`: "19 attack path Issue(s) from 22 hop variant(s)" (round 2: 25 from 28). The vendor-access, web IMDS, ops-jane, gha-legacy and auditor rule chains are gone as separate rows. One rule chain remains, "#19 [MEDIUM 5.2] Public control plane with over-permissive authorization", which has no traversal counterpart. Recall is unchanged (20/20, recall@7 19/20). | `ingest` and `plan` still count "22 attack paths" while `paths` and the dashboard say 19 Issues (see new #4). |
| 3 | Nothing to install | **OPEN** | `0.1.0-dev`, `commit: unknown`. 155 MB stripped, 38 MB gzipped. No tag. The archive contains only LICENSE, README, SECURITY and CHANGELOG (`.goreleaser.yaml:43`), so the offline demo is not in it. | Everything. Blocked on owner actions O3, O4 and O5. |
| 4 | Never run against a live cloud | **OPEN** | `doctor`: "0 account(s)". The README and `benchmark.json` say `live_cloud: false`. | Everything (owner action O1). |
| 5 | `who-can` omits the internet | **CLOSED** | `who-can s3:GetObject arn:aws:s3:::nimbus-lab-customer-pii/*` prints "21 principal(s) … **anonymous (internet)** inferred allow — because … bucket policy Principal *" first. The shared-reports bucket gives "anyone in the organisation (org-wide) verified conditional … Principal * limited by aws:PrincipalOrgID". The copilot "who can access nimbus-lab-customer-pii?" returns the same 21, with anonymous first. | No MCP `who_can` tool. The copilot's who-can needs `CLOUD_POSTURE_BIN` or the binary on PATH; otherwise it prints "binary is not available". |
| 6 | No verified closure | **IMPROVED** (large) | **W01 only:** `verify 441264… --from-file mod_w01.json` prints "✗ still open — path survives: Internet → nimbus-lab-export → nimbus-lab-export-lambda-role → nimbus-lab-customer-pii (score 10.0 CRITICAL → 7.0 HIGH)" and exits 2. The single S3 Issue gives "✓ verified-fixed … verified_by=file:mod_w01.json" and exits 0. **W01 + W12:** the path Issue is verified-fixed, with timeline row `verified file:mod_w01_w12.json`. **`ingest --diff`:** "rescored 441264… 10.0 CRITICAL → 7.0 HIGH", and "Verified fixed since the previous scan: 2". | **After the next ingest, both Issues read `state: resolved`, so the verified state is lost** (known V4-PRODUCT deferral, now observed). No `pending_verification` state, no verify MCP tool, and no Jira transition map. Targeted reads exist only for AWS S3/EC2/SG/IAM role, and every other type falls back to `--from-file`. The Issue page and the `plan` "verify" step still give SQL plus "Until finding lifecycle lands (Track G)" (42 sidecars), not `cloud-posture verify`. Never run live. |
| 7 | Dashboard paths view raw and unreadable | **CLOSED** | `pa.png` shows "19 attack path Issues from 22 hop variants": one row per Issue, a `+1` badge, and "graph: selected path (1 hops, 2 nodes) [show all paths]". `pa_focus.png` selects billing-exports and draws only Internet → media-01 → media-role → billing-exports, with every hop's `because`. 0 page errors. | Trend is still "totals only" (UX2). |
| 8 | Copilot contradicts the engine | **CLOSED** | "is nimbus-lab-ledger reachable" gives blocked plus the route-table reason. "top attack paths" gives "19 open attack-path Issue(s) (22 hop variant(s))". "which sensitive buckets are public" gives customer-pii and hrexports as exposed and shared-reports as "Not exposed (exposure suppressed) … org-conditioned". | Rough edges: the "Sources:" line prints about 3 KB of SQL twice; the ledger answer opens with "Nothing here is exposed to the internet"; the LLM agent mode lacks who-can and exposure tools (log). |
| 9 | Out-of-box ownership mostly empty | **IMPROVED** (tooling, not outcome) | `doctor`: "warn ownership 64 of 83 open Issues (77%) are unassigned; run `cloud-posture governance init --write` … or set governance.defaults.owner". `governance init` prints an honest starter block: "owner tag 'owner' on 14 of 79 resources … would assign 19 of 83 open Issues (23%); set defaults.owner for the other 64". | The outcome has not changed: **64 of 83 (77%) are still "(unassigned)"** in `issues metrics` and on the dashboard. `governance init` adds no assignment the lab config did not already have. It does not propose an owner per account or provider. |
| 10 | Docs stale, gate red | **IMPROVED** | `make readme-check`: "22 linked claim(s) … PASS". `readme-bench -check`: "README benchmark block is current" (22/22, 19/20, finding-level row, in-sample caveat). The command table lists `issues`, `verify`, `who-can`, `governance init`, `convert`, `mcp` and `pr-comment`. `monitor --help` says "polling … not real time". | `release.yml` does not run readme-check or readme-bench. The CHANGELOG stops at the 2026-10-09 summary, with no score 2.2.0/2.3.0 entries and no verify, who-can or MCP. The README says MCP is "read scope by default", but `mcp --help` says "default: every tool" (including `draft_fix`/`simulate_fix`). The 42 remediation sidecars are stale. |
| 11 | First scan reports a false "clean" | **CLOSED** | In an empty `HOME`, `scan` prints "✗ nothing scanned: no accounts configured, no IaC root and no tool ran; run `cloud-posture onboard` or pass --iac <dir>" and exits **2**. Nothing is written. | — |
| 12 | Privesc paths have no fix | **CLOSED** | `plan`: "Minimum fix set: 20 fix(es) … removes **95.5%**" (round 2: 19 and 91%). The PassRole step uses `remediation.PassRoleFix` (log) and `fix --passrole <principal> --role <role>` exists in `fix --help`. | Only ops-jane remains: two independent entry weaknesses, which is correct. |
| 13 | No path-rule authoring or privesc library | **OPEN** | One rule chain, no `risk test`, no `rules/paths/`. | All of it. |
| 14 | PR comment does not credit fixes or offer commits | **IMPROVED** | `revert.plan.json` gives "opens 0 / escalates 0 / **lowers 1** / closes 0", "### Lowered (1) … 7.0 → 1.9 (High → Low)", footer `nimbus-lowers-paths: 1`, exit 0. `bad` gives escalates 1, exit 3. `create` gives opens 1, exit 3. **With a declared `allowed_cidrs` variable**, the comment adds "### Suggested changes (1) … ```` ```suggestion ```` `cidr_blocks = var.allowed_cidrs` … (patch confidence 0.8, re-scan unverified: review the values)". | **Suggestions fire only in a narrow case.** The committed fixture (`var.ssh_cidr`) gets none, and a literal `0.0.0.0/0` without a pre-declared variable gets none, because the patch appends a `variable` block (two hunks). So the most common plan-time fix stays a CLI hint. `action.yml` does not pass `--iac` (line 133), so the Action never produces suggestions. No fixture exercises "closes". |
| 15 | About half of scanner findings unnormalised | **IMPROVED** | `scan --iac lab/terraform/aws`: **Trivy 41 of 44 mapped** (round 2: 22 of 44), plus 13 native findings. Log: Checkov 72.6%, Trivy 88.3% on the goldens (floor 70%). | Checkov is below the 80% bar. No `catalog unmapped` report. The 20 new canonical entries have not been reviewed (log). |

**Tally:** 7 CLOSED (1, 2, 5, 7, 8, 11, 12), 5 IMPROVED (6, 9, 10, 14, 15) and 3 OPEN (3, 4, 13).
Round 2 had 7 CLOSED as well, but these are new items: every round-2 S-sized shortfall closed. Two of the three
OPEN items (3, 4) are blocked on the owner, not on code.

---

## (2) Release readiness for a signed v0.2.0, re-scored (§6 of round 2)

✓ = met, ~ = partly met, ✗ = not met. "Δ" compares with round 2.

| # | Must be true at install time | Round 2 | Round 3 | Evidence seen in this run |
|---|---|---|---|---|
| 1 | `brew install`, `docker run …@sha256` and `install.sh --require-signature` work on macOS arm64, Linux amd64 and Linux arm64, and `cosign verify-blob` succeeds | ✗ | ✗ | No tag; the pipeline has never run (owner actions O3, O4, O5). |
| 2 | `version` prints `0.2.0`, a real commit, a build date and the score version | ✗ | ✗ | `0.1.0-dev` / `commit: unknown (dev build)` / `built: unknown` / `score: 2.3.0`. |
| 3 | Binary size stated and reasonable; archive ≤ 40 MB; SBOM attached | ~ | ~ | 155 MB stripped, 38 MB gzipped: under the bar, but it grew 7 MB since round 2 and has 2 MB of headroom left. The SBOM is configured (`.goreleaser.yaml` `sboms:`) but has never been produced. |
| 4 | `doctor` has no stale messages, exits non-zero on a hard failure, and states the KEV/EPSS snapshot date | ~ | **✓** | Empty `HOME`: "ok intel snapshot embedded KEV/EPSS snapshot 2026-10-09". The python row reads "optional; scanning, scoring and paths are Go-native". A malformed config gives "fail config … yaml: line 1" and exit **1**. A garbage DB gives "fail database init schema: file is not a database" and exit **1**. |
| 5 | The first `scan` with no targets says nothing was scanned and exits non-zero | ✗ | **✓** | "✗ nothing scanned …" and exit **2**. |
| 6 | First `onboard` → `scan` on one AWS account in under 10 minutes on the shipped read-only policy | ✗ | ✗ | Never run live (O1). Also, `onboard` detects AWS only through the `aws` CLI (`internal/devx/devx.go:31` `LookPath`). Without the CLI it prints "✗ aws  aws not installed … Nothing detected", even with SDK credentials in the environment. |
| 7 | Offline quickstart demo works and matches the README | ~ | ~ | It works from a source checkout: the README's ingest, `paths --limit 5` and `plan` output matches byte for byte. It is not in the release archive, because goreleaser `files:` has no lab estate. |
| 8 | **One verdict everywhere**: bands and blocked exposures agree across `paths`, `prioritize`, `issues`, dashboard, MCP and copilot; no rule-chain duplicates | ✗ | **✓** | F04 is #45 at 6.8 Medium, with a MEDIUM Issue; the copilot and MCP say blocked. 19 Issues in `paths`, the dashboard and the copilot. 0 Critical on non-exposed. (Count wording still differs; see new #4.) |
| 9 | README claims current, and `make readme-check` passes in the release workflow | ✗ | ~ | `readme-check` PASS (22 claims) and `readme-bench -check` current, but `.github/workflows/release.yml` runs neither. |
| 10 | README benchmark numbers come from `benchmark.json` for that tag; "synthetic, not live" on the first screen | ~ | **✓** | The block is generated between `BEGIN/END readme-bench` markers. "Status: pre-release … has not yet been run against a live cloud account" is in the first screen, and the in-sample caveat for the noise estate is stated. |
| 11 | Every command in `--help` is documented, and no help text overclaims | ✗ | ~ | `monitor` is fixed and the command table is complete. The README says MCP is "read scope by default", but the help and behaviour default to every tool. |
| 12 | The Action, pinned by SHA to the v0.2.0 commit, passes e2e on GitHub | ~ | ~ | Local PASS (log); the GitHub run is pending a release. `action.yml` does not pass `--iac`, so suggestions are unreachable from the Action. |
| 13 | MCP config for Claude Desktop and Cursor works against the installed binary | ✓ | ✓ | 8 tools listed. Hostile SQL: `hex(account)` returns the placeholder's hex, both LIKE guesses return 0, and `main.`, `DELETE` and stacked statements are refused. |
| 14 | `convert` and `scan -o` outputs validate | ✓ | ✓ | `convert estate → ocsf`: 83 records, `class_uid 2004`, version `1.6.0`. `→ sarif`: `2.1.0`, 62 results. |
| 15 | SECURITY.md verification steps, O4 setting, CHANGELOG with the score changes | ~ | ~ | SECURITY.md is present. O4 is undecided. **The CHANGELOG has no 2.2.0 or 2.3.0 score entry** and no wave 3/4 features. |
| 16 | `go test ./...`, `pytest`, `make ui-test`, strict groundtruth and govulncheck green on the tagged commit | ✓ | ✓ | `GROUNDTRUTH_STRICT=1` PASS here (22/22, 19/20, finding level 0, noise 4/4). The V4-PRODUCT end gates (log): `go test ./...` 40 ok, pytest 302, ui-test 26/26, readme-check PASS. |

**Score: 7 of 16 met (round 2: 3), 6 partly met, 3 not met.** The three not met (1, 2, 6) depend on owner actions:
O3, O4 and O5 for the release, O1 for the live run. Every partly met row except #3 and #12 can be closed in S effort
on the code side: wire the release gates, fix the CHANGELOG, align the MCP default with the README, and ship the lab
in the archive.

---

## (3) Full capability table, round 3 (91 rows)

The columns are: round-2 verdict → round-3 verdict, Δ against round 2, and the observed evidence or the remaining
gap. The best-in-class bar for each row is the matrix row with the same ID
(`docs/research/competitive-feature-matrix.md`).

### 1. Inventory & graph

| ID | R2 | R3 | Δ | Observed / remaining gap (best-in-class) |
|---|---|---|---|---|
| IG1 | SHORT | SHORT | = | `doctor` "0 account(s)". Fakes only (Prowler: 23 providers). |
| IG2 | SHORT | SHORT | = | `federates_to` is still declared by the lab. Okta → SSO admin at 7.0 (Cartography emits it). |
| IG3 | SHORT | SHORT | = | No org fan-out run. `onboard --aws-org` prints a StackSet only. |
| IG4 | MATCHES | MATCHES | = | Deterministic provider/account per path Issue: 0/540 diffs (log). |
| IG5 | SHORT | SHORT | = | Per-type views. No unified kinds (Fix Inventory). |
| IG6 | ABSENT | ABSENT | = | `paths --help` has no `--from/--to/--through` (Sysdig SysQL, Wiz Explorer). |
| IG7 | SHORT | SHORT | (impr.) | Migration 8 adds `issue_score_history` (`--diff` "rescored 10.0 → 7.0"). No per-resource versions or diffs (Fix Inventory). |
| IG8 | MATCHES (fakes) | MATCHES (fakes) | = | Dashboard coverage: "1 API calls / tool runs recorded". `scan` with no targets is now an explicit failure. |
| IG9 | MATCHES | MATCHES | = | Bedrock agent hop "[p=0.70]" at 7.0. |

### 2. Attack paths & toxic combinations

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| AP1 | SHORT | SHORT | (impr.) | One engine for covered chains: 6 rule chains folded, path Issues 25 → 19, recall unchanged. Still no `Truncated` flag and no 50k-node scale benchmark (SCC, Cortex). |
| AP2 | MATCHES | MATCHES | = | `because` on every hop, including the dashboard focused view. |
| AP3 | MATCHES | MATCHES | = | 83 Issues (19 path, 2 combination, 62 single). The Issue page has a verify timeline row. |
| AP4 | ABSENT | ABSENT | = | No user rules and no `risk test` (Sysdig custom risks, Prowler query library). |
| AP5 | MATCHES | MATCHES | = | Dashboard "Choke points (10) … closes 2". |
| AP6 | **BEATS** | **BEATS** | (impr.) | "20 fix(es) — min_fix_exact=true … min_fix_verified=true … removes 95.5%". |
| AP7 | MATCHES | MATCHES | = | Trusted 3 / private 2 suppressed with reasons. "Dead ends: 17". |
| AP8 | MATCHES (AWS) | MATCHES (AWS) | (impr.) | The verdict now feeds risk (×0.50 "not exposed (blocked: …)"), Issues, the copilot and MCP. In the lab, most AWS nodes are still "wide, inferred: subnet … not known". Azure/GCP: NSG/firewall only. Never live (ASH trait). |
| AP9 | ABSENT | ABSENT | = | No probes. |
| AP10 | **BEATS** | **BEATS** | (impr.) | opens / escalates / **lowers** / closes. Exit 3 on an escalation, exit 0 on a lowering. Entry-key D5 fix (log). |

### 3. Risk prioritization

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| RP1 | MATCHES | MATCHES | = | 4/62 at 10.0, 19 Critical. `score_version 2.3.0` in every explanation. |
| RP2 | MATCHES | MATCHES | = | KEV ×1.50 (Log4Shell). "exploitability unknown (confidence hint)". |
| RP3 | MATCHES | MATCHES | = | — |
| RP4 | SHORT | SHORT | (impr.) | Network blockers now lower the score (ledger 9.8 → 6.8). The `compensating_controls` factor is still "×1.00 no compensating control recorded" on every row. No WAF/EDR inputs (Zscaler UVM). |
| RP5 | MATCHES | MATCHES | (impr.) | `--diff` prints "rescored … 10.0 CRITICAL → 7.0 HIGH" and "Verified fixed since the previous scan" (Sysdig and SCC auto-close). |
| RP6 | SHORT | SHORT | (impr.) | Trivy 41/44 mapped on the lab IaC. Checkov 72.6% (log). Not at J1 "one row per CVE per asset" across tools. |
| RP7 | MATCHES | MATCHES | = | Suppression bounds: expiry ≤ 366 d, approver from the principal (log). |
| RP8 | MATCHES | MATCHES | (impr.) | `governance init`, a `doctor` ownership warning, and the expired-suppression clock fix (log). 77% unassigned out of the box (MDC rules start from tags, but MDC has a default owner per subscription). |

### 4. Identity / CIEM

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| ID1 | MATCHES (offline) | MATCHES (offline) | = | SCP exemptions are applied before deny; corpus 155 (log). |
| ID2 | SHORT | SHORT | (impr.) | PassRole is now fixable (95.5%). The technique library is still small (Prowler: ~70 privesc queries). |
| ID3 | SHORT | **MATCHES** | ↑ | `anonymous (internet)` first, org-wide demotion, statement ids and confidence, and a copilot intent. No MCP tool (Datadog Access Insights). |
| ID4 | ABSENT | SHORT | ↑ | A `ScopePassRole` policy-diff fix (`fix --passrole`). It does not use usage data and is not a general right-sizing PR (Cortex, Datadog suggested policy). |
| ID5 | SHORT | SHORT | = | No Azure RBAC. |
| ID6 | SHORT | SHORT | = | K8s paths at 7.0. No effective verbs. |
| ID7 | ABSENT | ABSENT | = | Cut. |

### 5–6. Data, vulnerabilities

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| DS1 | ABSENT | ABSENT | = | Cut. |
| DS2 | ABSENT | ABSENT | = | — |
| DS3 | SHORT | SHORT | = | Sensitivity ×1.50 from labels only. |
| VS1 | SHORT | SHORT | (impr.) | Trivy mapping is about 93% on the lab IaC. |
| VS2 | ABSENT | ABSENT | = | Cut. |
| VS3 | ABSENT | ABSENT | = | — |
| VS4 | SHORT | SHORT | = | — |
| VS5 | ABSENT | ABSENT | = | — |

### 7. IaC & code-to-cloud

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| IC1 | SHORT | SHORT | (impr.) | 13 native + 44 Trivy findings on `lab/terraform/aws`; 41 Trivy mapped. |
| IC2 | SHORT | SHORT | = | CODEOWNERS only. No blame or author. |
| IC3 | ABSENT | ABSENT | = | — |
| IC4 | SHORT | SHORT | = | No release. `action.yml` does not pass `--iac`. |
| IC5 | SHORT | SHORT | = | — |

### 8. Remediation

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| RM1 | MATCHES | MATCHES | = | LAMBDA_PUBLIC on the #1 path is still a "generic stub". |
| RM2 | SHORT | SHORT | (impr.) | ```` ```suggestion ```` blocks and review comments exist, but only when the patch is a single hunk. SG world-open without a pre-declared variable gets none, and the Action passes no `--iac` (Checkov, Cortex one-click). |
| RM3 | MATCHES | MATCHES | (impr.) | The PassRole step is wired. Still no per-target grouping (ASH remediation plans). |
| RM4 | ABSENT | **MATCHES (offline)** | ↑ | `verify` re-collects one Issue's resources, re-traverses, needs N consecutive confirmations with backoff, names the surviving hop, and closes the ticket only on verified (log). Defects: the next ingest overwrites `verified_fixed` with `resolved`; AWS has 4 types only; never live (XM confirmation, Prowler partial scans, Orca close → rescan). |
| RM5 | ABSENT | ABSENT | = | — |
| RM6 | ABSENT | ABSENT | = | — |

### 9. Compliance & evidence

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| CO1 | MATCHES | MATCHES | = | Dashboard shows 11 frameworks. Every score is 0% in the lab because it has no PASS results. |
| CO2 | MATCHES | MATCHES | = | — |
| CO3 | SHORT | SHORT | = | — |
| CO4 | SHORT | SHORT | = | Evidence zip is unsigned. |
| CO5 | ABSENT | ABSENT | = | Trend: "scan history carries totals only". |
| CO6 | ABSENT | ABSENT | = | No Vanta export. |
| CO7 | ABSENT | ABSENT | = | — |

### 10. Detection

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| DR1 | SHORT | SHORT | = (doc fixed) | `monitor --help` now says "minutes of delay, not real time". |
| DR2 | SHORT | SHORT | = | — |
| DR3 | ABSENT | ABSENT | = | — |
| DR4 | ABSENT | ABSENT | = | — |

### 11. Integrations & workflow

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| IW1 | SHORT | SHORT | (impr.) | Sinks: https-only, SSRF guard, no credential forwarding on redirect, `--allow-private-sinks` (log). Routing is still by `min_severity`. |
| IW2 | MATCHES | MATCHES | (impr.) | The ticket closes only on `verified_fixed` (log, unit-tested). No reverse sync from Jira (Datadog two-way). |
| IW3 | **BEATS** | **BEATS** | = | Multi-scanner ingest with better normalisation. |
| IW4 | MATCHES | MATCHES | = | OCSF 1.6.0, class 2004. SARIF 2.1.0. |

### 12. Dashboard

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| UX1 | SHORT | **MATCHES** | ↑ | Overview: "19 attack path Issues, 2 critical … min fix set 20 fixes remove 95.5%". Grouped paths, focused graph and `[show all paths]` (Wiz-style). The overview's "12 critical" Issues sits beside `prioritize`'s 19 Critical findings (see new #4). |
| UX2 | SHORT | SHORT | = | MTTR rows are present; trend is still totals only. `issue_score_history` is not charted (J1 trend widgets). |
| UX3 | SHORT | SHORT | = | No executive report. |
| UX4 | SHORT | SHORT | = | — |

### 13. AI & agent interfaces

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| AI1 | SHORT | **MATCHES** | ↑ | Offline answers now agree with the engine on all 5 questions and print the SQL. Rough edges: who-can needs the binary on PATH, and the Sources line is a 3 KB SQL dump printed twice (Upwind shows an editable query instead). |
| AI2 | MATCHES | MATCHES | = | — |
| AI3 | MATCHES | MATCHES | = | Redaction holds against hex, substr, CAST and the LIKE oracle. Still 8 tools: no `who_can`, `verify` or `prioritize`. `paths` returns 22 variants, not 19 Issues. Verdict text leaks `rtb-` ids. Over-redaction turns a name into `ACCT_16b2b5ff-ledger`. stdio only (Sysdig MCP). |
| AI4 | MATCHES | MATCHES | = | Untrusted-data wrapper on every result. |
| AI5 | ABSENT | ABSENT | = | Cut. |

### 14. Platform

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| PF1 | MATCHES | MATCHES | (impr.) | `doctor` is accurate and exits 1 on a hard failure. `scan` exits 2 when it scanned nothing. `ask` without the Python layer prints its error twice and exits 1. |
| PF2 | SHORT | SHORT | = | — |
| PF3 | SHORT | SHORT | = | — |
| PF4 | ABSENT | ABSENT | = | — |
| PF5 | ABSENT | ABSENT | = | No release. 155 MB stripped. |
| PF6 | SHORT | SHORT | = | — |

### 15. Trust & supply chain

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| TS1 | ABSENT | ABSENT | = | The pipeline has never run on a tag. |
| TS2 | MATCHES | MATCHES | = | — |
| TS3 | MATCHES | MATCHES | = | — |
| TS4 | **BEATS** | **BEATS** | (impr.) | Finding-level row (0 / 0 of 62) and the in-sample caveat are now in the README, generated from `benchmark.json`. |

### 16. Ecosystem interop

| ID | R2 | R3 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| EI1 | MATCHES | MATCHES | = | — |
| EI2 | SHORT | SHORT | = | No Prowler path queries imported. |
| EI3 | SHORT | SHORT | = | — |
| EI4 | ABSENT | ABSENT | = | — |

**Totals (91 rows).**

| | BEATS | MATCHES | SHORT | ABSENT | IN-FLIGHT |
|---|---|---|---|---|---|
| Round 3 | 4 | 32 | 33 | 22 | 0 |
| Round 2 | 4 | 28 | 35 | 24 | 0 |
| Round 1 | 3 | 16 | 39 | 25 | 8 |

Since round 2, 5 rows moved up (ID3, ID4, RM4, UX1, AI1), none moved down, and 21 rows narrowed their gap
("(impr.)"). The moves cluster in the wave-4 targets: verify, who-can, the dashboard and the copilot. The ABSENT
rows that matter most to a Wiz-trained buyer have not moved: IG6 (graph query), AP4 (custom rules), AP9 (probes),
CO5/CO6 (continuous evidence), PF5/TS1 (release).

---

## (4) New top 15 shortfalls, ranked by buyer impact

No CLOSED item is repeated. IMPROVED items appear only for what remains of them.

| # | Shortfall (observed) | Fix | Effort | Owner track | Plan v3 |
|---|---|---|---|---|---|
| 1 | **Never run against a live cloud.** Every claim rests on a lab the project wrote itself. `doctor` reports "0 account(s)", and `live_cloud: false`. | Apply `lab/terraform/aws` to a sandbox account. Scan it with the built binary and publish a live column in `benchmark.json`. Run `verify` on a real fix (W01 + W12) to exercise the targeted collector and its eventual-consistency window. | M | P1-LAB / P2-LAB (owner O1) | yes (rank 1, TS4; Phase 1 exit 10) |
| 2 | **Nothing to install.** `0.1.0-dev`, `commit: unknown`, 155 MB stripped / 38 MB gz (growing). The SBOM has never been produced. The release archive lacks the lab, so the offline quickstart cannot run from an install. | Cut a signed `v0.2.0` (owner actions O3, O4, O5). Add `lab/local/out/estate.findings.json` and the lab config to goreleaser `files:`. Add a size budget check to the release workflow (≤ 40 MB gz). | M | P0-REL | yes (PF5/TS1, 0-5); lab-in-archive NEW |
| 3 | **Verified closure is not durable or wired.** `verify` works, but the next `ingest` turns `verified_fixed` into `resolved`. No `pending_verification` state, no verify MCP tool, no Jira transition map. Targeted reads cover only AWS S3/EC2/SG/IAM role. The Issue page and `plan` "verify" step still print SQL plus "Until finding lifecycle lands (Track G)" (42 sidecars) instead of `cloud-posture verify <id>`. | Treat `verified_fixed` as a terminal resolved sub-state in `RebuildIssues`/`RebuildPathIssuesScoped`, reopening only when the problem reappears. Add `pending_verification` on ticket "Done". Add an MCP `verify` tool in dry-run, read scope. Replace the sidecar verify text with `cloud-posture verify <issue>`. Add targeted readers for RDS, Lambda, EKS and IAM user. | M | P2-VERIFY | yes (rank 5, RM4/IW2); durability NEW |
| 4 | **The headline numbers disagree on one screen.** `ingest` says "9 Critical (22 attack paths)". `plan` says "22 attack path(s)". MCP `paths` says `matched: 22`. `paths` and the dashboard say "19 attack path Issues". The dashboard shows "12 critical" Issues while `prioritize` shows 19 Critical findings. `issues` lists a single Azure-blob finding above the 10.0 path Issue. Credential-entry titles read "nimbus-lab-ops-jane → nimbus-lab-ops-jane". | Make the Issue the unit everywhere: `ingest`, `plan` and MCP say "N attack path Issues (M variants)". Label findings "findings" and Issues "Issues", each with one band source. Order `issues` by path/toxic score first, as Wiz's Issues queue does. Print "<principal> (credential) → <target>" for credential entries. | S | P1-ISSUES + P1-ENGINE | NEW |
| 5 | **Ownership stays mostly empty out of the box.** 64 of 83 Issues (77%) are "(unassigned)". `governance init` adds nothing beyond the 19 tag-owned Issues, and the digest goes to "(unassigned)". | `governance init` proposes `defaults.owner` per account or subscription (from `onboard` or the account alias) and per provider. It reads owner tags from IaC (`--iac`) and CODEOWNERS paths for cloud-to-code-mapped resources. The digest routes unassigned Issues to the account owner. Target: under 20% unassigned on the lab. | S | P2-EVIDENCE (governance) | RP8 yes; per-account default NEW |
| 6 | **PR one-click fixes rarely appear.** The most common plan-time fix (world-open SG) needs an appended `variable` block, so it is two hunks and gets no suggestion. `action.yml` never passes `--iac`. No fixture covers "closes". | Post each hunk as its own review suggestion (GitHub batches them), or put the variable block in a new `nimbus_vars.tf` suggestion. Pass `--iac "$CP_IAC"` in `action.yml:133`. Add a closing fixture plan. | S/M | P1-PLANDIFF | RM2 yes; multi-hunk NEW |
| 7 | **The MCP surface lags the CLI.** 8 tools: no `who_can`, `verify` or `prioritize`. `paths` returns hop variants (22), not Issues (19). Verdict reason and label text contain unredacted `rtb-…`/`acl-…` ids. Over-redaction mangles names (`db:ACCT_16b2b5ff-ledger`). The README says "read scope by default", but the default is every tool. Still stdio only. | Add `who_can`, `prioritize` and `verify` (dry-run) tools. Make `paths` return Issues with a `variants` array. Run verdict strings through `redactor.text`. Stop treating common tag values (`nimbus-lab`) as identifiers inside names. Either make `--scope read` the default or fix the README. | S | P1-MCP follow-up | AI3 yes (C1 `who_can`); rest NEW |
| 8 | **No graph query, so a buyer cannot ask the questions Wiz Explorer answers.** No `paths --from/--to/--through` and no saved path queries (IG6). | Implement plan v3's `paths --from/--to/--through` filters (S), then an MCP `paths` filter argument. Defer a DSL. | S | P1-ENGINE | yes (IG6) |
| 9 | **No path-rule authoring and no privesc library** (carried over). One rule chain, no `risk test`, no attributed queries. | `rules/paths/*.yaml` with an anchor, attribution and fixtures. `cloud-posture risk test` dry run. Port Prowler's AWS privesc queries with their ids. | M/L | P1-ENGINE + P2-CIEM | yes (rank 14, AP4/ID2) |
| 10 | **Fix content thins out past the top.** LAMBDA_PUBLIC, on the #1 path, is a "generic stub". `plan` has no per-target grouping (ASH remediation plans), and the verify step points to SQL. | Typed templates for the evidence weaknesses on lab paths (LAMBDA_PUBLIC first). Group `plan` by target resource with "resolves N / reduces M". Make the verify phase `cloud-posture verify`. | M | P2-VERIFY (RM3) | yes (RM3); templates NEW |
| 11 | **Copilot rough edges.** who-can fails unless `CLOUD_POSTURE_BIN` is set ("The cloud-posture binary is not available"). `cloud-posture ask` without the Python layer prints its error twice and exits 1. Every answer prints about 3 KB of SQL twice. LLM agent mode lacks who-can and exposure tools (log). | The Go `ask` sets `CLOUD_POSTURE_BIN` to its own executable when it spawns Python. Print the SQL once, folded. Add `who_can` and `exposure_verdict` to `ALLOWED_TOOLS`. Print the error once. | S | P1-MCP follow-up | AI1 partly; rest NEW |
| 12 | **The release gate and changelog lag the code.** `release.yml` runs neither readme-check nor readme-bench. The CHANGELOG stops at 2026-10-09 and has no score 2.2.0/2.3.0 entries. | Add both checks to `release.yml` before `goreleaser`. Write CHANGELOG entries for waves 3–4 and the score changes (2.1.0 → 2.2.0 → 2.3.0), and gate the tag on a CHANGELOG section for the version. | S | P0-REL / Docs | partly (0-5); rest NEW |
| 13 | **`onboard` needs the cloud CLIs.** AWS detection is `LookPath("aws")` then `aws sts get-caller-identity`. A CI runner or container with SDK environment credentials gets "aws not installed … Nothing detected", although the collectors use the SDK. | Detect through the SDK credential chain (env, profile, SSO cache, IMDS/IRSA) with an STS call. Fall back to the CLI only for `az` and `gcloud` device flows. | S | P3-PACKAGE / CLI | NEW |
| 14 | **Reachability is mostly "unknown" for AWS compute and RDS in the lab.** web-01, media-01, batch-01 and orders all read "wide, inferred: subnet … not known: route table and network ACL not evaluated". The top 3 `prioritize` rows are Critical on inferred exposure, and the reason text repeats the same clause 2–3 times. jump-01's verdict is empty (log), and suppressed buckets read "reachable (wide)" in `graph.Verdict` (log). | Add subnet, route and NACL data for every exposed instance and RDS to the lab estate (and confirm the live collector emits them). Show one short reason with the inferred tag. Fix the two `graph.Verdict` gaps. | S/M | P2-REACH + P1-LAB | AP8 yes; lab data NEW |
| 15 | **Scanner normalisation is below the bar for Checkov.** 72.6% mapped against the 80% target. No `catalog unmapped` report. The 20 new canonical entries are unreviewed. | Next alias tranche (ops/reliability ids). `cloud-posture catalog unmapped`. Raise `goldenMinMappedPct` to 80. Have a human review the 20 new entries. | S/M | P1-INTEROP | yes (RP6) |

## (5) Where nimbus now beats everyone (observed in this run only)

1. **Verification that knows which path survived.**
   - `verify 441264… --from-file mod_w01.json` does not just re-check the finding. It re-traverses and says:
     "still open — path survives: Internet → nimbus-lab-export → nimbus-lab-export-lambda-role →
     nimbus-lab-customer-pii (score 10.0 CRITICAL → 7.0 HIGH)".
   - The single bucket Issue is verified-fixed in the same run.
   - XM's Remediation Confirmation, Prowler's partial scans and Orca's close-then-rescan confirm that a finding is
     gone. None of them reports that the attack path survived through another hop.
   - Caveat: this was observed offline only, and the state is not yet durable (new #3).
2. **An exact, re-verified minimum fix set that now covers privilege escalation.**
   - "20 fix(es) — min_fix_exact=true … min_fix_verified=true … removes 95.5%". The PassRole policy-diff step is
     included.
   - ASH plans have phases but no minimality proof. MDC and SCC stop at choke points.
3. **A plan-time attack-path diff with credit as well as blame.**
   - "opens 0 / escalates 1 / lowers 0 / closes 0" exits 3. "lowers 1 (High → Low)" exits 0 with
     `nimbus-lowers-paths: 1`.
   - When the patch is single-hunk, a ```` ```suggestion ```` block is added.
   - No vendor diffs attack paths at plan time.
4. **One reachability verdict with the exact blocking rule, carried into the score.**
   - `prioritize` shows "exposure ×0.50 not exposed (blocked: route table rtb-0a1b2c3d4e5f60001 has no route to an
     internet gateway (routes: 10.20.0.0/16 → local))".
   - The same verdict appears in `paths --exposures`, the Issue, the copilot and MCP.
   - ASH's reachability trait and MDC's exposure width do not print the route or NACL rule, and do not show the
     score change it causes.
5. **`who-can` that includes the internet and the organisation, with statement ids.**
   - "anonymous (internet) … bucket policy Principal *" is listed first, then 20 principals with
     `policy-arn#index` and verified/inferred confidence.
   - "anyone in the organisation (org-wide) … conditional" appears for a `PrincipalOrgID` bucket.
   - Datadog Access Insights and Wiz's CIEM explorer list principals, but their public documentation describes no
     statement-level evidence with a confidence grade.
6. **An open benchmark that also scores the finding ranking.**
   - Strict groundtruth gives 22/22 precision, recall@7 19/20, and "finding-level: critical on non-exposed 0 …
     blocked/FP/pending resources in prioritize top 10: 0 of 62".
   - These numbers are regenerated into the README by `readme-bench`, with an in-sample caveat.
   - No vendor or OSS project publishes path ground truth.
7. **A published, versioned score explanation.**
   - Every `prioritize --explain` row ends with "= 10.0 (raw 38.22, score_version 2.3.0)" and lists each factor
     with its status and evidence, including the compression ("combination ×0.26 … raw 38.22 → 10.00").
   - FortiCNAPP's explain dialog has a similar layout, but its formula is closed.
8. **MCP redaction that survives a hostile client.**
   - `hex(account)` returns the hex of the placeholder, `LIKE '1111%'` and `'2222%'` both return 0, and `main.`
     and stacked statements are refused.
   - Sysdig's MCP server scopes tools by token. The cluster docs record no competitor that documents redaction at
     the SQL value layer.

## (6) Verdict

**Not yet. But for the first time, the remaining blockers are mostly not in the code.**

A Wiz-trained CISO running the lab today would see:

- one verdict everywhere: the blocked RDS is a Medium in every surface;
- one path Issue per risk, with no rule-chain duplicates;
- a focused path graph in the dashboard;
- `who-can` that starts with "anonymous (internet)";
- a copilot that agrees with the engine;
- a `verify` that says which hop keeps the path alive.

Those were the round-2 reasons to walk away, and they are fixed. On the wedge capabilities, nimbus is ahead of every
named competitor in substance: minimum fix set, plan-time diff, path-aware verification, explainable reachability
and an open benchmark.

The CISO would still not say "best-in-class", for three reasons:

- **Nothing has touched a real cloud.** `verify` has only ever re-read a JSON file.
- **There is nothing signed to install.**
- **The product is still rough at the edges a buyer meets first.** 77% of Issues have no owner, the "22 vs 19 paths"
  and "9 / 12 / 19 critical" counts disagree, and a verified fix reverts to "resolved" on the next scan.

**The single thing that would change the answer: one live AWS run with the signed binary.** That means a published
`v0.2.0`, applied to the lab twin in a real account. It produces a `live_cloud: true` column in `benchmark.json`, and
it records one fix closed by `verify` against the live API inside its eventual-consistency window. That is the
evidence a Wiz-trained buyer asks for first, and no competitor publishes it. The S-sized shortfalls #3 (durability),
#4 (one count vocabulary) and #5 (default owners) should land first, so that the live demo does not surface them.

## (7) First 30 minutes: a new user following the README (source install, today)

This was run in a copy of the repository (`scratchpad/delta3/clone`) on macOS arm64 with Go installed and
`CLOUD_POSTURE_NO_NETWORK=1`. Rough edges are numbered **[E#]** in the order the user meets them.

```text
00:00  Read the README. First screen: "Status: pre-release (0.1.0-dev). nimbus has not yet been run against a
       live cloud account." Honest and clear.
       [E1] The name banner says nimbus, but the binary, cask and image are all `cloud-posture` (O3). A new user
            has to keep two names in mind.
00:02  Install: "go install github.com/DreadpiratePickles/nimbus/cmd/cloud-posture@latest"
       [E2] Not exercised: no network, and no tag exists. @latest resolves to a pseudo-version of main, and the
            README does not say so.
       Clone path: `make build` → 41 s wall, bin/cloud-posture is 220 MB (unstripped dev build).
       [E3] No size warning. The release build would be 155 MB / 38 MB gz.
00:03  $ ./bin/cloud-posture ingest lab/local/out/estate.findings.json --source native --config lab/…lab.yaml
       "Scan complete! Found 62 open findings … 9 Critical (22 attack paths) … Attack paths: 22"
       It matches the README byte for byte.
       [E4] The verb is `ingest`, but the output says "Scan complete!".
       [E5] It writes `.cloud-posture/posture.db` into the clone without saying where.
00:04  $ ./bin/cloud-posture paths --config … --limit 5
       "19 attack path Issue(s) from 22 hop variant(s)". It matches the README.
       [E6] One command earlier, the user was told "22 attack paths". The README walkthrough shows both numbers
            without explaining the difference.
       [E7] Credential-entry paths read "nimbus-lab-vendor-access → nimbus-lab-vendor-access → Privilege
            escalation to nimbus-lab-vendor-access".
00:06  $ ./bin/cloud-posture plan --config …
       "Plan: 22 attack path(s) (21 traversal, 1 rule-chain) … 20 fix(es) … removes 95.5%". Matches the README.
       The steps (prerequisite → snapshot → fix → verify → rollback) are excellent.
       [E8] Each verify step says "Until finding lifecycle lands (Track G), a source that stops reporting the check
            leaves a stale FAIL row". This is stale, and it does not mention `cloud-posture verify`, which exists.
00:09  $ ./bin/cloud-posture issues --limit 3
       [E9] The header reads "3 Issue(s)", not "3 of 83".
       [E10] The first row is a single Azure-blob finding, not the 10.0 path Issue. A Wiz user expects the toxic
             path Issue at the top.
       [E11] Many rows show "owner (unassigned)": 64 of 83, which `doctor` later confirms.
00:11  $ ./bin/cloud-posture issues show 441264…   (the user copies the id from `paths`? No: `paths` prints no
       Issue ids.)
       [E12] To open the #1 path's Issue page, the user has to find the id in `issues` or the dashboard. `paths` does
             not print it.
       Issue page: owner (tag), why, SLA, factors, hops with because, evidence Issues, 5-phase fixes, timeline.
       Strong.
       [E13] The second fix on the page (LAMBDA_PUBLIC) is a "generic stub".
00:14  $ ./bin/cloud-posture dashboard --config …   → cloud-posture-report/index.html
       Overview: "19 attack path Issues, 2 critical; min fix set 20 fixes remove 95.5%". Paths view grouped, and
       the focused graph is readable.
       [E14] The overview says "12 critical" Issues. `prioritize` will say 19 Critical, and `ingest` said 9 Critical.
       [E15] Every compliance framework shows 0% (the lab has no PASS rows), with no note explaining why.
00:18  $ ./bin/cloud-posture ask "who can access nimbus-lab-customer-pii?"
       [E16] "Error: the copilot lives in the Python layer: pip install -e "python[ai]" …" is printed twice, with
             exit 1. The README's install section says `pip install -e "python[all]"`, so there are two different
             extras names.
       After the user installs Python (simulated with the repo venv): the who-can answer fails with
       "cloud-posture binary is not available (set CLOUD_POSTURE_BIN or put it on PATH)".
       [E17] The user just ran the binary from ./bin, and the copilot cannot find it.
       With CLOUD_POSTURE_BIN set, the answer is "21 principal(s) … anonymous (internet) …". Correct.
       [E18] Each answer is followed by about 3 KB of SQL, printed twice.
00:22  "Now my own account." $ ./bin/cloud-posture onboard
       [E19] With SDK credentials in env but no `aws` CLI: "✗ aws  aws not installed … Nothing detected".
             Detection goes through the CLI, not the SDK chain the collectors use.
       $ ./bin/cloud-posture scan   (nothing configured)
       "✗ nothing scanned: … run `cloud-posture onboard` or pass --iac <dir>", exit 2. Good (round 2 printed a
       false "clean").
00:25  $ ./bin/cloud-posture doctor
       Clear table: snapshot date, python optional, "warn ownership 64 of 83 … (77%) … run governance init".
       $ ./bin/cloud-posture governance init
       "would assign 19 of 83 open Issues (23%); set defaults.owner for the other 64".
       [E20] Honest, but it does not suggest a value. The user has to decide who owns 64 Issues by hand.
00:28  $ ./bin/cloud-posture mcp --help
       "default: every tool".
       [E21] The README says "read scope by default". A security-minded user notices this mismatch.
00:30  Verdict of a new user: the lab demo is convincing and fast (under 10 minutes to a meaningful path list and
       plan). The path to their own estate stops at E19 (CLI-only detection) and E2 (no release). Their trust is
       dented by E6/E14 (counts disagree) and E8 (stale verify text).
```

**Rough-edge count: 21.** Five of them are count or wording consistency (E4, E6, E7, E9, E14). Four are stale or
mismatched text (E2, E8, E16, E21). Three are reach problems: the copilot cannot find the binary (E17), `onboard`
needs the CLI (E19), and the Issue id is missing from `paths` (E12). Two are content gaps (E13, E15). Nothing
crashed, and every number the README prints was reproduced exactly.
