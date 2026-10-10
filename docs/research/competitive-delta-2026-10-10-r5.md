# Competitive delta review 5 (2026-10-10, round 5)

This is the fifth competitive review under the owner's standing rule: "constantly compare the code to the
competitors so we don't come up short". It re-checks round 4 (`docs/research/competitive-delta-2026-10-10-r4.md`)
after wave 6 landed: W6-POLISH, W6-ENGINE and W6-VERIFY (`docs/sessions/2026-10-10-wave5.md`, "## W6-*"). The
reviewer was read-only on code. A read-only verifier ran at the same time, and no code agents ran. Every verdict
comes from behaviour seen in this run unless it is marked "(log)", meaning it was taken from the session log and
not re-observed here.

**Verdict scale** (same as rounds 1–4). BEATS, MATCHES, SHORT, ABSENT, IN-FLIGHT. **Δ** is measured against
round 4: ↑ better, ↓ worse, = unchanged, "(impr.)" means the same verdict with a smaller gap, "(regr.)" the
same verdict with a new defect. **Effort:** S ≤ 2 agent-days, M ≤ 1 week, L ≤ 3 weeks. **Plan:** the plan v3
row or track (`.planning/IMPLEMENTATION_PLAN_v3.md`). "NEW" means plan v3 does not have it.

## Method and evidence

Scratch directory: `scratchpad/delta5/` (session scratchpad). `CLOUD_POSTURE_NO_NETWORK=1` was set for every
command.

- **Build** (03:06, 2026-10-10). `go build -o cp ./cmd/cloud-posture`. `cp version`: `0.1.0-dev`,
  `commit: unknown (dev build)`, `built: unknown`, `score: 2.4.0`. Unstripped 221.5 MB. With
  `-trimpath -ldflags "-s -w"`: **155.9 MB, 38.45 MB gzipped** (round 4: 155.6 MB / 38.35 MB).
- **Lab.** `go run ./lab/local/gen -out <scratch>` is byte-identical to `lab/local/out/estate.findings.json`
  (92 records: 62 FAIL, 30 PASS). Ingested with `lab/local/cloud-posture.lab.yaml`.
- **Commands re-run as in round 4.** `ingest`, `paths` (default, `--limit 0`, `--exposures`), `plan` (default
  and `--top 20`), `prioritize --explain`, `issues` / `--json` / `show`, `issues metrics`, `who-can` (bare name),
  `convert` (native → OCSF → SARIF), `scan --iac lab/terraform/aws --db <elsewhere>` from an empty cwd, `mcp`,
  `pr-comment` on the four fixture plans (r4's literal-`0.0.0.0/0` copy), `doctor`, `scan` and `onboard` in an
  empty `HOME` with `PATH=/usr/bin:/bin`, `readme-bench -check`, `readme-bench -transcript -check`,
  `make readme-check`, `GROUNDTRUTH_STRICT=1 go test ./tests/groundtruth`, the dashboard, the copilot, and a
  fresh-copy walk (`scratchpad/delta5/fresh`: no `node_modules`, `.venv`, `bin`, DBs, `.git`, egg-info; `make
  build` with an empty `HOME`, 64 s including module download).
- **New surfaces in this round.**
  - `risk list` (match counts), `risk test aws-ec2-privesc-passrole-iam` (by id), `risk test nosuch`.
  - The rule-match path Issue in `paths --limit 0`, `issues`, `issues show`, `plan`, the dashboard and strict
    groundtruth.
  - `plan --top 20` typed count, plus `fix --id` on six previously stubbed steps (W03, W19, W25, W44, W49, W51).
  - `catalog unmapped --tool checkov|trivy` from a DB holding only the Checkov / Trivy goldens, run outside the
    repo.
  - `verify --from-file --attempts 1`, each on its own DB copy: RDS path Issue (`rds_fixed.json` W06 PASS, r4's
    `forged.json`), RDS finding Issue (`rds_fixed.json`, `rds_absent.json`), customer-pii path Issue
    (`pii_partial.json` W01 PASS, `pii_clean.json` W01+W12 PASS), Lambda finding Issue (`lambda_only.json`).
    Then `ingest pii_clean.json --diff` and `ingest estate.findings.json --diff` (trend + regression).
  - `issues metrics` before and after `governance init --write` on a copy of the lab config; `doctor` after.
  - `ask` from a fresh venv with the base package only (no `[ai]`), from a clone layout with no Python deps, and
    with the lab config (`python.enabled: false`).
  - `paths --grouped --format json`; graph query errors (`--through nosuchrole`, `--max-hops 0`).
  - README transcript vs the binary (line by line for ingest, `paths --limit 3`, `plan` head).
  - MCP smoke (default scope): `tools/list`, `summary`, `paths` (plain, `from/to/through`, bad `through`,
    `to: type:aws_db_instance, max_hops: 3`), `who_can` by name, `prioritize`, `issue`, `verify`, `draft_fix`,
    `hex(account)`, `LIKE '1111%'`, `store_meta`.
  - Dashboard rendered from a 3-scan DB (ingest → verified clean → regression), captured with `shot.mjs` at
    `#overview`, `#compliance`, `#paths`, `#issues`: 0 page errors on all four.

---

## (1) Round-4 top 15, re-scored

| # | Round-4 shortfall | Status | Evidence seen in this run | What remains |
|---|---|---|---|---|
| 1 | Never run against a live cloud | **OPEN** | `doctor`: "warn credentials no accounts configured (run cloud-posture onboard)". `verify` without `--from-file`: "no aws account configured to re-collect … use --from-file". | Everything (owner action O1). |
| 2 | Nothing to install | **OPEN** | `0.1.0-dev`, `commit: unknown`; 155.9 MB stripped / **38.45 MB gz (1.55 MB under the 40 MB line)**. `.goreleaser.yaml` `files:` is still LICENSE/README/SECURITY/CHANGELOG; `release.yml` has no size step. | Everything (O3, O4, O5), plus lab-in-archive and a size gate. |
| 3 | README "real output" stale and ungated | **CLOSED** | README block between `BEGIN/END readme-transcript` matches the binary line for line (ingest "84 open Issues: 20 attack path Issues (23 hop variants) + 64 finding Issues; 12 critical (2 path, 10 finding)", `paths --limit 3`, `plan` head). `readme-bench -transcript -check`: "README quickstart transcript is current"; `release.yml:49-51` runs it. `make readme-check`: 24 claims PASS. Command table has `risk`, `catalog unmapped`, `paths --from/--to/--through`, `issues mark-pending`. `verify --help` now: "with --from-file the file must evaluate that check on that resource (a file that omits it is "unverified")". | The verify *outcome* line still says "is now PASS or absent" (new R6). |
| 4 | Residual count and title disagreements | **CLOSED** | `plan`: "Plan: 20 attack path Issues (23 hop variants: 22 traversal incl. 1 path-rule match, 1 rule-chain)". `paths`, `plan`, dashboard: "external trust abuse of nimbus-lab-vendor-access → AdministratorAccess". `scan --iac`: "0 critical (0 path, 0 finding)" then "Top-ranked finding: … 9.8 of 10 (severity HIGH; Issue counts above are by severity …)". Tie order hrexports-first in `ingest`, `issues`, `paths`, dashboard, copilot. CLI `who-can s3:GetObject nimbus-lab-customer-pii` (bare name): "21 principal(s)", anonymous first. `prioritize`: "Top 50 findings by risk score … `issues` lists Issues". | Small residuals: dashboard risk panel "12 critical (2 toxic)" vs CLI "(2 path, 10 finding)" (R4); `issues show` "Hop variants" line keeps "X → Y → Privilege escalation to Y" (R5). |
| 5 | Default owner by tie-break | **CLOSED** | `governance init`: "no proposed defaults.owner: the most common owner tag "finance" is on 2 of 14 tagged resources (14%), below the 50% min_owner_share"; account owner only where 1 of 1 (azure → people-ops). `--write`: "applied to 84 open Issues: 62 unassigned (74%)". `issues metrics`: "assigned by default: 3 · unassigned: 62". `doctor`: "warn ownership 62 of 84 open Issues (74%) are unassigned". | The honest outcome is that 74% of the lab is unowned out of the box (new #5). `doctor` still advises `governance init --write` after it ran (R9). |
| 6 | Copilot first run breaks | **CLOSED** | Clone layout, system Python without deps: one line, "the copilot's Python dependencies are missing (typer, rich, pydantic, yaml, jinja2, httpx): python3 -m pip install -e "<clone>/python[ai]"". Lab config: "the copilot lives in the Python layer, which python.enabled: false in ../lab.yaml turns off: set python.enabled: true there". Fresh venv with base package only: who-can "21 principal(s) … anonymous (internet) (inferred)" in **2.8 KB**; "top attack paths" "20 open attack-path Issue(s) (23 hop variant(s))" in 2.7 KB; ledger "nimbus-lab-ledger is not exposed to the internet." | Advice names `[ai]` although the offline copilot runs on the base package; `doctor` says `pip install "nimbus-cspm[ai]"`, a PyPI name with no published package (R3). |
| 7 | Path rules do not reach the product | **IMPROVED** | 55 embedded rules. `risk list`: per-rule "matches N (V verified)" (EC2-001 1/1; EC2INSTANCECONNECT-003, SSM-001, SSM-002 2/0; IAM-005 1/0). `risk test aws-ec2-privesc-passrole-iam` works by id; `risk test nosuch` → "no such file or library rule (cloud-posture risk list prints the library ids)", once. The verified match is a path Issue: `issues` row 6 "EC2 Instance Launch with Privileged Role (EC2-001): nimbus-lab-dev-sam → nimbus-lab-ec2-admin-role", `rule: aws-ec2-privesc-passrole-iam`, Prowler credit in `because`. | **The one rule Issue duplicates an existing traversal Issue**: row 11 "credential compromise of nimbus-lab-dev-sam → nimbus-lab-ec2-admin-role (AdministratorAccess)" has the same two hops, same evidence, same 7.0. Effects: the headline went 19 → 20 path Issues; `plan` step 1 "resolves 2 path(s)"; dashboard "breaks 2/23 removes 14.0"; strict groundtruth matches P13 twice ("FOUND … 2"), so precision 23/23 counts one chain twice (new #3). User rules (`--rules-dir`, `rules/paths`) are loaded only by `risk list/test`; traversal never sees them (`attackpath.TraversalOptions.PathRules` is not set by any command). The 7 inferred matches stay dry-run. |
| 8 | Verification narrow; MCP verify does not verify | **IMPROVED** | `verify --help` lists readers for S3, EC2, SG, IAM roles and users, RDS, Lambda, EKS, Azure storage and NSG. RDS path: `rds_fixed.json` → "✓ verified-fixed … no surviving path from the internet to nimbus-lab-orders", exit 0; forged → "? unverified … mentions none of the path's 1 hop resource(s)", exit 2; RDS finding with the record removed → "unverified — the file never mentions …db:nimbus-lab-orders", exit 2. Lambda: `pii_partial.json` → "✗ still open — path survives: Internet → nimbus-lab-export → nimbus-lab-export-lambda-role → nimbus-lab-customer-pii (score 10.0 CRITICAL → 7.0 HIGH)"; `lambda_only.json` verifies the LAMBDA_PUBLIC finding Issue. MCP `verify` returns `evaluation: {state: open, stored_evidence: present, summary: "the stored graph still yields 2 path(s) to the anchor (best 10.0) …"}`. | Readers never run live. MCP evaluates stored state only (no fresh read, by design). No GCP, Kubernetes, Azure SQL/VM/Key Vault, AWS Secrets/KMS readers (log). |
| 9 | Fix content thins out | **CLOSED** | `plan --top 20`: **0 of 20 "generic stub"**. `fix --id` on W03, W19, W25, W44, W51 prints a typed template (`ec2_instance_port_exposed.tf`, `gcp_instance_no_public_ip.tf`, `gh_branch_protection.tf`, `okta_signon_mfa.tf`, `bedrock_agent_private.tf`) with permissions, breaks-function and mitigation. | Step 11 (K8s LoadBalancer) headline says `cloud-posture fix --id lab-W49 --generate-terraform`, which prints "(generic stub — no typed template yet)"; the typed fix is `--format kubernetes`, and its `kubectl patch … -- pod report-worker-0` patches the pod with a Service change (new #7). |
| 10 | Graph query stays in the CLI | **IMPROVED** | MCP `paths` takes `from`/`to`/`through`/`max_hops`: `{from: internet, to: aws_s3_bucket, through: aws_iam_role}` → `matched_paths: 3`, 0 raw ids; bad `through` → `isError: true` with the selector help; `to: type:aws_db_instance, max_hops: 3` → 1 path (orders). CLI errors print once (`--max-hops must be 1..10 (got 0)`). | No dashboard query box, no saved queries, no property predicates (new #8). |
| 11 | Scanner ids unmapped; `catalog unmapped` repo-bound | **CLOSED** | From a scratch DB outside the repo: "checkov (stored database): 81/95 FAIL findings mapped … (85.3%), 14 unmapped across 13 distinct checks" — CKV_AWS_260 absent from the list, the rest are hygiene checks (EBS optimised, lifecycle, DLQ, probes). Trivy "55/60 … (91.7%)"; AZU-0047 absent. Empty DB names `--from` / `--golden`. | — |
| 12 | Trend is totals only | **CLOSED** | `ingest --diff`: "Issues this scan: 0 new, 2 resolved, 0 reopened, 1 verified fixed, 0 regressed after verify; 81 open, 33% of closures verified", then "… 2 reopened, 0 verified fixed, 1 regressed after verify". Dashboard trend panel: per-scan sparklines for new / resolved / reopened / verified / regressed / verified% over 3 scans. | No long lookback or per-Issue "score journey" (Upwind); folded into new #11. |
| 13 | Compliance 0% everywhere | **IMPROVED** | Dashboard: 9 of 11 frameworks non-zero (HIPAA 37.5%, SOC 2 36.3%, CIS AWS 25%, PCI 22.2% …), per-control PASS rows, legend "PASS = only passing checks map to the control …". | CIS Kubernetes and CIS GCP 0% (0 passing); evidence zip unsigned; no Vanta export (new #9). |
| 14 | `onboard` ignores no-network; runs beside cwd | **CLOSED** | Fake env keys, `CLOUD_POSTURE_NO_NETWORK=1`: "✗ aws skipped (no-network): detection calls the provider …", 0.25 s. `doctor` intel feeds "skipped (no-network)". `scan --iac … --db <scratch>/iac.db` from an empty cwd: the cwd stays empty, runs land in `<scratch>/runs`. | `onboard` then says "Nothing detected. Log in first …" although keys were present (R8). |
| 15 | Identifier residuals | **CLOSED** (log + partly observed) | MCP: 0 raw account / `rtb-`/`sg-` ids over 15 calls; `hex(account)` returns the placeholder's hex; `LIKE '1111%'` → 0; `store_meta` refused. Log: keyed external finding ids (HMAC per DB), verification-6 oracle probe recovers nothing; Python-built DB guard in root `PersistentPreRunE`; DB-less SARIF labelled `unkeyed`. | — |

**Tally: 9 CLOSED (3, 4, 5, 6, 9, 11, 12, 14, 15), 4 IMPROVED (7, 8, 10, 13), 2 OPEN (1, 2).** Both OPEN items
are owner actions (O1; O3/O4/O5). Every code-side item moved again; one IMPROVED item (#7) carries a new
credibility defect (the duplicate Issue).

---

## (2) Release readiness for a signed v0.2.0, re-scored

✓ = met, ~ = partly met, ✗ = not met.

| # | Must be true at install time | R3 | R4 | R5 | Evidence seen in this run |
|---|---|---|---|---|---|
| 1 | `brew install`, `docker run …@sha256`, `install.sh --require-signature`; `cosign verify-blob` succeeds | ✗ | ✗ | ✗ | No tag; pipeline never run (O3, O4, O5). |
| 2 | `version` prints `0.2.0`, a real commit, a build date and the score version | ✗ | ✗ | ✗ | `0.1.0-dev` / `commit: unknown (dev build)` / `built: unknown` / `score: 2.4.0`. |
| 3 | Binary size stated and reasonable; archive ≤ 40 MB; SBOM attached | ~ | ~ | ~ | README now states the strip flags. 38.45 MB gz (1.55 MB headroom, shrinking ~0.1 MB a wave); no size gate; SBOM never produced. |
| 4 | `doctor` has no stale messages, exits non-zero on a hard failure, states the KEV/EPSS date | ✓ | ✓ | ✓ | Empty `HOME`: "embedded KEV/EPSS snapshot 2026-10-09", feeds "skipped (no-network)", exit 0. (The `nimbus-cspm[ai]` pip hint is tracked as R3.) |
| 5 | The first `scan` with no targets says nothing was scanned and exits non-zero | ✓ | ✓ | ✓ | "✗ nothing scanned: no accounts configured, no IaC root and no tool ran …", exit 2. |
| 6 | First `onboard` → `scan` on one AWS account in under 10 minutes | ✗ | ✗ | ✗ | Never live (O1). |
| 7 | Offline quickstart demo works and matches the README | ~ | ~ (regr.) | ~ (impr.) | Matches line for line and is release-gated; works from a fresh copy. Still not runnable from an install: the lab estate and config are not in the archive. |
| 8 | One verdict everywhere | ✓ | ✓ | ✓ | 84 / 20 (23) / 64 / 12 (2+10) in ingest, `issues`, `paths`, `plan`, MCP `summary`, the copilot and the transcript; ledger 6.8 Medium "blocked: route table …" in `prioritize` and the copilot. Residual wording R4, R5. |
| 9 | README claims current; `make readme-check` in the release workflow | ~ | ✓ | ✓ | 24 claims PASS; transcript and benchmark gates current. |
| 10 | Benchmark numbers from `benchmark.json`; "synthetic, not live" on the first screen | ✓ | ✓ | ✓ | `readme-bench -check` current. |
| 11 | Every command in `--help` is documented; no help text overclaims | ~ | ~ | **✓** | Command table complete (risk, catalog unmapped, query flags, mark-pending); `verify --help` no longer says "PASS or absent"; `mcp` help matches README. |
| 12 | Action pinned by SHA passes e2e on GitHub | ~ | ~ | ~ | Locally: closes "opens 1 / escalates 0 / lowers 1 / closes 1" with 2 suggestion blocks; bad/create 2 each; revert "closes 1". Needs a release. |
| 13 | MCP config works against the installed binary | ✓ | ✓ | ✓ | 10 tools, default `read`, 0 leaks, `paths` query arguments. |
| 14 | `convert` and `scan -o` outputs validate | ✓ | ✓ | ✓ | OCSF 92 records, `class_uid 2004`, `1.6.0`; SARIF `2.1.0`, 62 results. |
| 15 | SECURITY.md steps, O4 setting, CHANGELOG with the score changes | ~ | ~ | ~ | CHANGELOG current (log: 2.4.0 list). O4 undecided. |
| 16 | `go test ./...`, `pytest`, `make ui-test`, strict groundtruth, govulncheck green | ✓ | ✓ | ✓ | Strict groundtruth PASS here (recall 20/20, recall@7 19/20, precision 23/23 — see new #3, p@7 22/22, finding-level 0 of 62). Log (W6-POLISH end gate): `go test` 41/41, pytest 438, ui-test PASS. |

**Score: 9 of 16 met (round 4: 8; round 3: 7), 4 partly met, 3 not met.** The three not met (1, 2, 6) are owner
actions. Of the four partly met, #7's last gap (lab in the archive) and #3's size gate are S code-side items; #12
and #15 need the release and O4.

---

## (3) Rough edges re-walked

Walk: fresh copy, `make build` (64 s with an empty `HOME`, module download included), README transcript commands,
`issues`, `issues show`, dashboard, `ask`, `onboard`, `scan`, `doctor`, `governance init`, `mcp`.

| Edge | Round 4 | Round 5 | Observed |
|---|---|---|---|
| E1 | remaining | remaining | Two names (nimbus / cloud-posture); explained in the README (O3). |
| E2 | remaining | **fixed** | README: "`go install …@latest` resolves a pseudo-version of the default branch". |
| E3 | remaining | partly | README names the strip flags; the dev build is still 221.5 MB. |
| E6 | partly | **fixed** | `plan` counts Issues ("20 attack path Issues (23 hop variants …)"); README transcript regenerated. |
| E7 | partly | mostly fixed | Fixed in `paths`, `plan`, dashboard; the `issues show` "Hop variants" line still prints "… → Privilege escalation to …" (R5). |
| E11 | remaining (changed) | **fixed** (honest) | No tie-break owner; 62 of 84 reported unassigned. The ownership gap itself is new #5. |
| E12 | partly | **fixed** | `paths` rows end "Issue <id> · cloud-posture issues show <id>". |
| E14 | mostly | **fixed** | `prioritize` header says "findings" and points to `issues`. |
| E15 | remaining | **fixed** | 9 of 11 frameworks non-zero, legend present; CIS K8s / GCP still 0%. |
| E16 | remaining (changed) | **fixed** | One actionable line in every case; README and the error both say `python[ai]`. |
| N1 | new | **fixed** | README transcript generated and gated. |
| N2 | new | **fixed** | No traceback; dependency list printed. |
| N3 | new | **fixed** | 2.7–2.8 KB answers (tables capped at 20 rows unless `--full`). |
| N4 | new | **fixed** | `risk test <id>` works. |
| N5 | new | **fixed** | Errors print once. Casing still mixed ("Error:" from `catalog unmapped`, `verify`; "error:" elsewhere). |
| N6 | new | **fixed** | CLI by name 21, anonymous first. |
| N7 | new | **fixed** | `onboard` skips STS under no-network. |
| N8 | new | **fixed** | Run files beside the DB. |
| N9 | new | **fixed** | Top-ranked finding labelled as a finding score. |
| N10 | new | **fixed** | `catalog unmapped` reads the stored DB. |

The 11 edges fixed by round 4 stay fixed. **Of the 31 tracked edges: 28 fixed, 2 partly (E3, E7), 1 remaining (E1).**

New edges seen in this walk:

- **R1** The rule-match path Issue duplicates traversal Issue "credential compromise of nimbus-lab-dev-sam →
  nimbus-lab-ec2-admin-role" (same hops, evidence, score); see new #3.
- **R2** K8s plan step headline points at `--generate-terraform` (stub); the typed Kubernetes fix patches the pod
  `report-worker-0` with a Service change.
- **R3** `doctor`: `python3 -m pip install "nimbus-cspm[ai]"` — no package of that name is published.
- **R4** Dashboard risk panel "12 critical (2 toxic)" next to the CLI's "12 critical (2 path, 10 finding)".
- **R5** `issues show` "Hop variants" line keeps the pre-W6 title shape.
- **R6** `verify` outcome "RDS_PUBLIC on nimbus-lab-orders is now PASS or absent" for a PASS read, while absence is
  (correctly) unverified.
- **R7** (low) The first `query` or MCP call adds 42 SQL views to the database file (schema only; data unchanged).
- **R8** `onboard` under no-network: after "skipped (no-network)" it prints "Nothing detected. Log in first".
- **R9** `doctor` ownership warning advises `governance init --write` after it already ran (it cannot fix a
  sub-50% plurality).

Nothing crashed. No page errors on four dashboard panels.

---

## (4) Full capability table, round 5 (91 rows)

Columns: round-4 → round-5 verdict, Δ against round 4, observed evidence or the remaining gap against the
best-in-class row with the same ID in `docs/research/competitive-feature-matrix.md`.

### 1. Inventory & graph

| ID | R4 | R5 | Δ | Observed / remaining gap (best-in-class) |
|---|---|---|---|---|
| IG1 | SHORT | SHORT | = | 0 accounts; fakes only (Prowler: 23 providers). |
| IG2 | SHORT | SHORT | = | `federates_to` declared by the lab (Cartography). |
| IG3 | SHORT | SHORT | = | No org fan-out run; `organization_id` not collected (log, C1). |
| IG4 | MATCHES | MATCHES | (impr.) | Keyed external finding ids too (log); Python-DB guard. |
| IG5 | SHORT | SHORT | = | No unified kinds (Fix Inventory). |
| IG6 | SHORT | SHORT | (impr.) | Query in CLI **and MCP** (`from/to/through/max_hops`). No dashboard builder, saved queries or property predicates (Sysdig SysQL, Wiz Explorer). |
| IG7 | SHORT | SHORT | (impr.) | Per-scan Issue trend columns (migration 11, log); no per-resource versions. |
| IG8 | MATCHES (fakes) | MATCHES (fakes) | = | Coverage panel "1 API calls / tool runs recorded"; empty scan exit 2. |
| IG9 | MATCHES | MATCHES | = | Bedrock agent hop; typed fix now. |

### 2. Attack paths & toxic combinations

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| AP1 | SHORT | SHORT | = | No `Truncated` flag, no 50k-node benchmark (SCC, Cortex). |
| AP2 | MATCHES | MATCHES | = | `because` per hop in CLI, MCP query, dashboard. |
| AP3 | MATCHES | MATCHES | (regr.) | Lifecycle intact; one chain now appears as two Issues (rule match + traversal). |
| AP4 | SHORT | SHORT | (impr.) | Library matches become Issues with credit and `risk list` counts; `risk test <id>`. User rules never reach traversal; the only lab Issue is a duplicate (Sysdig custom risks → Issues with badges). |
| AP5 | MATCHES | MATCHES | = | Choke points (10), "closes N". |
| AP6 | **BEATS** | **BEATS** | = | "20 fix(es) — min_fix_exact=true … min_fix_verified=true … removes 95.7%"; step 1's "resolves 2" is inflated by the duplicate. |
| AP7 | MATCHES | MATCHES | = | Trusted 3 / private 2 with reasons; dead ends 17. |
| AP8 | MATCHES (AWS) | MATCHES (AWS) | = | Ledger "blocked: route table … no route to an internet gateway". Never live. |
| AP9 | ABSENT | ABSENT | = | No probes. |
| AP10 | **BEATS** | **BEATS** | = | All four plan fixtures exercised; 2 suggestion blocks on closes/bad/create. |

### 3. Risk prioritization

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| RP1 | MATCHES | MATCHES | = | `score_version 2.4.0`. |
| RP2 | MATCHES | MATCHES | = | KEV ×1.50. |
| RP3 | MATCHES | MATCHES | = | — |
| RP4 | SHORT | SHORT | = | Compensating controls ×1.00 everywhere (Zscaler UVM). |
| RP5 | MATCHES | MATCHES | (impr.) | `--diff` "Issues this scan: … verified fixed … regressed after verify … % of closures verified". |
| RP6 | SHORT | SHORT | (impr.) | Checkov 85.3%, Trivy 91.7% from the stored DB; remaining unmapped are hygiene. No one-row-per-CVE-per-asset (J1). |
| RP7 | MATCHES | MATCHES | = | — |
| RP8 | MATCHES | MATCHES | (impr.) | No weak-plurality default; "assigned by default" reported; 74% unowned on the lab (MDC owner per subscription). |

### 4. Identity / CIEM

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| ID1 | MATCHES (offline) | MATCHES (offline) | = | Foreign `PrincipalOrgID` with unknown own org still partial (log, C1). |
| ID2 | SHORT | SHORT | (impr.) | 55 Prowler-credited rules (Prowler ~70); 1 verified, 7 inferred lab matches. |
| ID3 | MATCHES | MATCHES | (impr.) | CLI and MCP by name: 21, anonymous first. |
| ID4 | SHORT | SHORT | = | PassRole scoping only. |
| ID5 | SHORT | SHORT | = | No Azure RBAC. |
| ID6 | SHORT | SHORT | = | — |
| ID7 | ABSENT | ABSENT | = | Cut. |

### 5–6. Data, vulnerabilities

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| DS1 | ABSENT | ABSENT | = | Cut. |
| DS2 | ABSENT | ABSENT | = | — |
| DS3 | SHORT | SHORT | = | Labels only. |
| VS1 | SHORT | SHORT | (impr.) | Trivy 91.7% on goldens. |
| VS2 | ABSENT | ABSENT | = | Cut. |
| VS3 | ABSENT | ABSENT | = | — |
| VS4 | SHORT | SHORT | = | — |
| VS5 | ABSENT | ABSENT | = | — |

### 7. IaC & code-to-cloud

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| IC1 | SHORT | SHORT | (impr.) | `scan --iac` headline labelled; 39 Issues on `lab/terraform/aws`. |
| IC2 | SHORT | SHORT | = | CODEOWNERS only. |
| IC3 | ABSENT | ABSENT | = | — |
| IC4 | SHORT | SHORT | = | No release for the Action. |
| IC5 | SHORT | SHORT | = | — |

### 8. Remediation

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| RM1 | MATCHES | MATCHES | (impr.) | 20/20 plan steps typed (Qualys numbered steps, CrowdStrike permissions). K8s step headline and pod target wrong (R2). |
| RM2 | MATCHES | MATCHES | = | Per-hunk suggestions. |
| RM3 | MATCHES | MATCHES | = | "By target resource (21 target(s))". |
| RM4 | MATCHES (offline) | MATCHES (offline) | (impr.) | RDS, Lambda readers; RDS/Lambda from-file paths verified, forged/absent unverified. Never live (XM, Orca). |
| RM5 | ABSENT | ABSENT | = | — |
| RM6 | ABSENT | ABSENT | = | — |

### 9. Compliance & evidence

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| CO1 | MATCHES | MATCHES | (impr.) | 9 of 11 frameworks non-zero with PASS rows (Orca 185+). |
| CO2 | MATCHES | MATCHES | = | — |
| CO3 | SHORT | SHORT | = | — |
| CO4 | SHORT | SHORT | = | Evidence zip unsigned. |
| CO5 | ABSENT | **SHORT** | ↑ | Per-scan lifecycle trend and "% of closures verified". No cadence, no lookback window, no per-finding score journey (Vanta hourly, Upwind 13 months). |
| CO6 | ABSENT | ABSENT | = | No Vanta export. |
| CO7 | ABSENT | ABSENT | = | — |

### 10. Detection

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| DR1 | SHORT | SHORT | = | Polling, documented. |
| DR2 | SHORT | SHORT | = | — |
| DR3 | ABSENT | ABSENT | = | — |
| DR4 | ABSENT | ABSENT | = | — |

### 11. Integrations & workflow

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| IW1 | SHORT | SHORT | = | Routing by severity. |
| IW2 | MATCHES | MATCHES | = | No reverse sync (Datadog). |
| IW3 | **BEATS** | **BEATS** | = | — |
| IW4 | MATCHES | MATCHES | = | OCSF 1.6.0 / SARIF 2.1.0. |

### 12. Dashboard

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| UX1 | MATCHES | MATCHES | (impr.) | Titles match `issues`; risk panel "(2 toxic)" wording (R4). |
| UX2 | SHORT | **MATCHES** | ↑ | Trend panel: per-scan sparklines for new / resolved / reopened / verified / regressed / verified%; MTTR and on-time in owners (J1 trend widgets + time-to-remediate). Lab history is 3 scans. |
| UX3 | SHORT | SHORT | = | No executive report. |
| UX4 | SHORT | SHORT | = | "no cost data". |

### 13. AI & agent interfaces

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| AI1 | MATCHES (regr.) | MATCHES | (impr.) | Regression fixed; 2.8 KB answers; one-line dependency error (Upwind editable query still ahead). |
| AI2 | MATCHES | MATCHES | = | — |
| AI3 | MATCHES | MATCHES | (impr.) | `paths` query args; `verify` evaluates stored state. stdio only (Sysdig remote, token-filtered). |
| AI4 | MATCHES | MATCHES | = | Audit JSONL. |
| AI5 | ABSENT | ABSENT | = | Cut. |

### 14. Platform

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| PF1 | MATCHES | MATCHES | (impr.) | Errors once; casing mixed. |
| PF2 | SHORT | SHORT | = | — |
| PF3 | SHORT | SHORT | (impr.) | `min_owner_share`, comment-preserving `--write` (log). |
| PF4 | ABSENT | ABSENT | = | — |
| PF5 | ABSENT | ABSENT | = | No release; 155.9 MB stripped. |
| PF6 | SHORT | SHORT | = | — |

### 15. Trust & supply chain

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| TS1 | ABSENT | ABSENT | = | Never run on a tag. |
| TS2 | MATCHES | MATCHES | = | — |
| TS3 | MATCHES | MATCHES | (impr.) | No-network honoured by `onboard` and `doctor`. |
| TS4 | **BEATS** | **BEATS** | (impr.) | README transcript is now release-gated output of the binary. Precision double-counts P13 (new #3). |

### 16. Ecosystem interop

| ID | R4 | R5 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| EI1 | MATCHES | MATCHES | = | — |
| EI2 | SHORT | SHORT | (impr.) | 55 Prowler queries ported with id, licence and pathfinding.cloud upstream. |
| EI3 | SHORT | SHORT | = | — |
| EI4 | ABSENT | ABSENT | = | — |

**Totals (91 rows).**

| | BEATS | MATCHES | SHORT | ABSENT | IN-FLIGHT |
|---|---|---|---|---|---|
| Round 5 | 4 | 34 | 34 | 19 | 0 |
| Round 4 | 4 | 33 | 34 | 20 | 0 |
| Round 3 | 4 | 32 | 33 | 22 | 0 |
| Round 2 | 4 | 28 | 35 | 24 | 0 |
| Round 1 | 3 | 16 | 39 | 25 | 8 |

Since round 4: 2 rows moved up (UX2 SHORT → MATCHES, CO5 ABSENT → SHORT), none moved down, 24 narrowed their gap,
and 1 (AP3) kept its verdict with a new defect (the duplicate Issue). The remaining buyer-visible ABSENT set is
AP9 (probes), CO6 (Vanta export), PF5/TS1 (release).

---

## (5) New top 15 shortfalls, ranked by buyer impact

No CLOSED item is repeated; IMPROVED items appear only for what remains.

| # | Shortfall (observed) | Fix | Effort | Owner track | Plan v3 |
|---|---|---|---|---|---|
| 1 | **Never run against a live cloud.** `doctor` "no accounts configured"; `verify` has only ever re-read files; the RDS/Lambda/EKS/Azure readers have never touched an API. | Apply `lab/terraform/aws` to a sandbox account; scan with the built binary; publish a `live_cloud: true` column in `benchmark.json`; run `verify` on a real W01 + W12 fix and on the RDS path inside the eventual-consistency window. | M | P1-LAB / P2-LAB (O1) | 0-1, TS4 |
| 2 | **Nothing to install.** `0.1.0-dev`; 38.45 MB gz (1.55 MB headroom, no gate); the archive has no lab, so the README demo cannot run from an install. | Cut signed `v0.2.0` (O3, O4, O5). Add the lab estate and config to goreleaser `files:`; add a ≤ 40 MB gz budget step to `release.yml`. | M | P0-REL | 0-5; lab-in-archive and size gate NEW |
| 3 | **The only rule-derived Issue duplicates an existing Issue.** `issues` rows 6 and 11 are the same two hops (dev-sam → ec2-admin-role, 7.0). The headline went 19 → 20 path Issues because of it; `plan` step 1 "resolves 2 path(s)"; dashboard "removes 14.0"; groundtruth matches P13 twice, so 23/23 precision counts one chain twice. A buyer who spots it will distrust every count. | When a verified match's hop set equals an emitted traversal path, annotate that Issue (rule id, Prowler credit, "matches EC2-001") instead of emitting a new path; emit a separate rule Issue only for chains traversal did not find. Groundtruth: count distinct chains. Restore the 19 (22) headline and regenerate the transcript. | S | P1-ENGINE | AP4 follow-up NEW |
| 4 | **Customer-authored path rules never reach the product.** `risk list/test --rules-dir` loads them; traversal uses only the embedded library. Sysdig custom risks become Issues with "New" badges. | A config key (`path_rules.dirs`) and the same `--rules-dir` on `ingest`/`scan`/`paths`, validated with `risk test` semantics before use; matches tagged `custom`. Show inferred matches as "potential" rather than discarding them. | S/M | P1-ENGINE | AP4 |
| 5 | **Ownership is empty out of the box.** Honest now, but the lab is 62 of 84 (74%) unassigned after `governance init --write`; `doctor` keeps advising the command that just ran. | `governance init --owner <team>` / interactive prompt for the default; read owners from AWS Organizations account tags and Azure subscription tags; route IaC Issues via CODEOWNERS; make `doctor` say "set defaults.owner or governance.digest.unassigned_sink". | S | P2-EVIDENCE (governance) | RP8 |
| 6 | **Verification coverage beyond AWS/Azure core.** No GCP, Kubernetes, Azure SQL/VM/Key Vault, AWS Secrets/KMS readers; MCP `verify` evaluates stored state only. | Readers for GCP firewall/instance/bucket and Kubernetes Service/RBAC first (they carry lab paths); optional MCP `verify --from-file` within the read scope. | M | P2-VERIFY | RM4 |
| 7 | **Kubernetes fix step is wrong in two ways.** Plan step headline `cloud-posture fix --id lab-W49 --generate-terraform` prints a generic stub; the typed fix runs `kubectl patch … -- pod report-worker-0` with a Service patch. | Headline uses the step's own format (`--format kubernetes`); resolve the Service that selects the pod and patch `service/<name>`; add a plan test asserting each headline command produces the typed template. | S | P2-VERIFY (remediation) | RM1 |
| 8 | **Graph query has no UI and no saved queries.** CLI and MCP only. | Dashboard query box over `paths --from/--to/--through` with results drawn on the existing graph; `--save <name>` and a saved list; property predicates (`tag:env=prod`, `sensitivity:pii`). | S/M | P1-ENGINE / UX | IG6 |
| 9 | **Compliance evidence stops short.** CIS Kubernetes and CIS GCP 0% (no PASS rows); evidence zip unsigned; no Vanta resource-API export; 11 hand-written frameworks. | Lab PASS rows for K8s/GCP; sign the evidence zip with the release key; Vanta export; import Prowler compliance JSONs (Apache-2.0). | M | P2-EVIDENCE | CO1/CO4/CO6 |
| 10 | **Privesc library breadth and inferred matches.** 55 rules vs Prowler ~70; 7 inferred lab matches (SSM ×4, EC2 Instance Connect ×2, PutRolePolicy self) are invisible outside `risk list`. | Port the remaining Prowler queries with fixtures; surface inferred matches as "potential escalation" annotations on the principal's Issues. | M | P2-CIEM | ID2, EI2 |
| 11 | **Trend has no time window.** Per-scan lifecycle sparklines exist, but no lookback period, no per-Issue score journey, no cadence statement (Upwind Score Journey, Vanta hourly). | `issues trend --since 90d` over `issue_score_history`; per-Issue score line in `issues show` and the dashboard drawer. | S/M | P2-EVIDENCE / UX | CO5, UX2 |
| 12 | **Install-time Python advice is wrong.** `doctor`: `pip install "nimbus-cspm[ai]"` (not on PyPI); the copilot asks for `[ai]` although the offline copilot runs on the base package. | Until a PyPI release, print the from-source command; ask for `[ai]` only when an API key is configured. | S | P3-PACKAGE | NEW |
| 13 | **Small wording residuals a careful buyer will notice.** Dashboard "12 critical (2 toxic)" vs CLI "(2 path, 10 finding)"; `issues show` "Hop variants" uses the old title shape; verify outcome "is now PASS or absent"; `onboard` "Nothing detected. Log in first" after a no-network skip; "Error:" vs "error:". | Reuse the headline builder in the dashboard risk panel; `pathIssueView` for variant lines; "is now PASS (re-read)"; "credentials found; detection skipped (no-network)"; one error prefix. Extend the consistency test to the dashboard payload. | S | P1-ISSUES / CLI | NEW |
| 14 | **MCP is stdio only.** Sysdig ships a remote MCP that filters tools by token permissions. | Streamable HTTP transport behind `serve` auth, tool list filtered by scope; keep stdio default. | M | P1-MCP | AI3 |
| 15 | **Foreign-org trust stays partial** (log, verification 6 C1): no collector records `organization_id`, so a foreign `PrincipalOrgID` can delete a real path. | Collect the org id (AWS Organizations `DescribeOrganization`, account metadata) and evaluate `aws:PrincipalOrgID` against it; groundtruth case. | S/M | P1-ENGINE (collector) | ID1 |

---

## (6) Where nimbus now beats everyone (observed in this run only)

1. **Verification that names the surviving hop and cannot be forged by a file, now on RDS and Lambda too.**
   `pii_partial.json` → "✗ still open — path survives: Internet → nimbus-lab-export → nimbus-lab-export-lambda-role
   → nimbus-lab-customer-pii (score 10.0 CRITICAL → 7.0 HIGH)"; `rds_fixed.json` → "✓ verified-fixed … no surviving
   path from the internet to nimbus-lab-orders"; forged and absent files → "? unverified", exit 2. XM, Prowler
   partial scans and Orca confirm a finding is gone; none reports the surviving hop. Caveat: offline only.
2. **Closure quality as a trend.** `ingest --diff`: "1 verified fixed, 0 regressed after verify; … 33% of closures
   verified", then "1 regressed after verify" with the reopened Issue named; the dashboard charts the same per scan.
   J1 and ASH chart open/closed counts; none separates verified closures from resolved ones or counts regressions
   after verification.
3. **An exact, re-verified minimum fix set with typed steps for every fix.** "20 fix(es) — min_fix_exact=true …
   min_fix_verified=true … removes 95.7%", 0 of 20 generic stubs, a `cloud-posture verify <id>` per step. ASH plans
   lack a minimality proof; MDC and SCC stop at choke points.
4. **A plan-time attack-path diff with one-click fixes.** `closes.plan.json`: "opens 1 / escalates 0 / lowers 1 /
   closes 1" with two batched suggestion blocks.
5. **One reachability verdict with the blocking rule, carried into the score.** Ledger #45 "6.8 Medium … exposure
   ×0.50 not exposed (blocked: route table … has no route to an internet gateway)", the copilot says the same.
6. **`who-can` with the internet first and statement ids, identical in CLI, MCP and the copilot** (21 principals).
7. **Test-before-save path rules with upstream credit and statement evidence**, runnable by id: `risk test
   aws-ec2-privesc-passrole-iam` → "own tests: pass", dry run "(no writes)", four `because` lines down to
   `inline-policy#PassBuilderRole`, credit "Prowler (Apache-2.0) … upstream pathfinding.cloud - EC2-001".
8. **A README whose demo output is the binary's output, enforced by the release.** `readme-bench -transcript
   -check` plus strict groundtruth, mapping floors and the benchmark block in `release.yml`.
9. **MCP redaction that survives a hostile client, now with the graph query**: 0 raw ids over 15 calls including
   `from/to/through` queries.

## (7) Verdict

**Not yet, and for the same reason as round 4: nothing has touched a real cloud and there is nothing signed to
install. The code-side minute-one polish is done; one new credibility defect needs fixing before a demo.**

Wave 6 closed nine of the fifteen round-4 shortfalls and moved the other four code items. The README demo is now
the binary's own output and the release fails if it drifts; counts and titles agree on every CLI surface; the
copilot's first run is one actionable line; `governance init` no longer invents an owner; every plan step has a
typed fix; trend and compliance panels carry real numbers. Release readiness is 9 of 16, and the three not met are
all owner actions.

What a Wiz-trained CISO would still catch:

- **No live run, no signed binary** (owner actions O1, O3–O5).
- **The duplicate rule Issue.** The headline "20 attack path Issues" includes one chain counted twice, and the
  groundtruth precision counts it twice too. It is S effort and it is the kind of thing a buyer finds by reading
  the top ten.
- **Ownership is 74% empty**: honest now, but still empty.

**The single thing that would change the answer: one live AWS run with the signed `v0.2.0` binary** on the lab
twin, producing a `live_cloud: true` column and one RDS or S3 path closed by `verify` against the live API. Before
that run, land new #3 (de-duplicate rule matches, restore the 19 (22) headline) and #7 (Kubernetes fix target),
because both would appear in the live demo.

## (8) What to show in the first demo (observed commands and outputs only)

Run everything with `--config lab/local/cloud-posture.lab.yaml`.

1. `cloud-posture ingest lab/local/out/estate.findings.json --source native` → "84 open Issues: 20 attack path
   Issues (23 hop variants) + 64 finding Issues; 12 critical (2 path, 10 finding)" and the top Issue with its
   `issues show` command. (After new #3 lands this becomes 19 (22); the README transcript regenerates.)
2. `cloud-posture paths --limit 5` → #2 "Internet → nimbus-lab-customer-pii … readable by anyone on the internet",
   each row ending "Issue <id> · cloud-posture issues show <id>".
3. The Wiz Explorer question: `cloud-posture paths --from internet --to aws_s3_bucket --through aws_iam_role` →
   "3 path(s) …", every hop with `because`. Show the same query from Claude Desktop through MCP `paths` (`from`,
   `to`, `through`).
4. `cloud-posture who-can s3:GetObject nimbus-lab-customer-pii` → "21 principal(s)", anonymous (internet) first.
5. `cloud-posture plan` → "20 fix(es) — min_fix_exact=true … removes 95.7%"; open steps 3, 6 and 19 to show typed
   Terraform with permissions, breaks-function and a `cloud-posture verify <id>` line.
6. Close the loop: `cloud-posture verify <customer-pii id> --from-file partial.json --attempts 1` → "still open —
   path survives: Internet → nimbus-lab-export → nimbus-lab-export-lambda-role → nimbus-lab-customer-pii (10.0 →
   7.0)"; with both fixes → "verified-fixed". Then `cloud-posture ingest clean.json --diff` → "1 verified fixed …
   33% of closures verified", and re-ingest the original → "1 regressed after verify". Show the dashboard trend
   panel.
7. Shift left: `cloud-posture pr-comment --plan-json testdata/action-fixture/plans/closes.plan.json --live off
   --trusted-cidr 203.0.113.0/24 --iac <fixture copy>` → "opens 1 / escalates 0 / lowers 1 / closes 1" with two
   suggestion blocks.
8. End on `prioritize --explain` (ledger #45, "6.8 Medium … blocked: route table …") and `risk test
   aws-ec2-privesc-passrole-iam` (statement-level evidence, Prowler credit).

Do **not** show `issues` rows 6 and 11 side by side, step 11 of `plan --top 20` (Kubernetes), or
`governance init` on the lab until new #3, #7 and #5 land. `ask` is safe to show from a venv with the base package
(`python.enabled: true`).
