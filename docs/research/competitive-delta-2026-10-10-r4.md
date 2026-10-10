# Competitive delta review 4 (2026-10-10, round 4)

This is the fourth competitive review under the owner's standing rule: "constantly compare the code to the
competitors so we don't come up short". It re-checks round 3 (`docs/research/competitive-delta-2026-10-10-r3.md`)
after wave 5 landed: W5-ISSUES, W5-PR-MCP and W5-ENGINE (`docs/sessions/2026-10-10-wave5.md`). The reviewer was
read-only on code. A read-only verifier ran at the same time, and no code agents ran. Every verdict comes from
behaviour seen in this run unless it is marked "(log)", meaning it was taken from the session log and not
re-observed here.

**Verdict scale** (same as rounds 1–3). BEATS, MATCHES, SHORT, ABSENT, IN-FLIGHT. **Δ** is measured against
round 3: ↑ better, ↓ worse, = unchanged, "(impr.)" means the same verdict with a smaller gap, "(regr.)" the
same verdict with a new defect. **Effort:** S ≤ 2 agent-days, M ≤ 1 week, L ≤ 3 weeks. **Plan:** the plan v3
row or track (`.planning/IMPLEMENTATION_PLAN_v3.md`). "NEW" means plan v3 does not have it.

## Method and evidence

Scratch directory: `scratchpad/delta4/`. `CLOUD_POSTURE_NO_NETWORK=1` was set for every command.

- **Build** (02:04, 2026-10-10). `go build -o cp ./cmd/cloud-posture`. `cp version`: `0.1.0-dev`,
  `commit: unknown (dev build)`, `built: unknown`, `score: 2.4.0`. Unstripped 221 MB. With
  `-trimpath -ldflags "-s -w"`: **155.6 MB, 38.35 MB gzipped** (round 3: 155 MB / 38 MB).
- **Lab.** `go run ./lab/local/gen` is byte-identical to `lab/local/out/estate.findings.json`, which now holds
  **92 records** (round 3: 83). Ingested with `lab/local/cloud-posture.lab.yaml`.
- **Commands re-run as in rounds 1–3.** `ingest`, `paths`, `paths --exposures`, `plan` (default and `--top 20`),
  `prioritize --explain` / `--json --top 0`, `issues` / `--json` / `show`, `issues metrics`, `who-can`,
  `convert` (native → OCSF → SARIF), `scan --iac lab/terraform/aws`, `mcp`, `pr-comment` on the four fixture
  plans, `doctor`, `scan` and `onboard` in an empty `HOME`, `make readme-check`, `readme-bench -check`,
  `GROUNDTRUTH_STRICT=1 go test ./tests/groundtruth`, the dashboard, the copilot, and a first-30-minutes walk in a
  fresh copy of the repo (`scratchpad/delta4/clone`, no `node_modules`, `.venv`, `bin`, DBs or `.git`).
- **New surfaces in this round.**
  - `risk list`; `risk test` by rule id and by YAML path (a shipped privesc rule and `rules/paths/aws/example-ssm-prod-only.yaml`).
  - `paths --from internet --to aws_s3_bucket --through aws_iam_role`, `--through nimbus-lab-media-role`,
    `--through nosuchrole`, `--format json`.
  - `catalog unmapped --tool checkov|trivy` (from the scratch dir and from the repo root).
  - `verify --from-file` on five exports, each on its own DB copy, for the customer-pii path Issue `7cbb82bf…`
    and its S3 finding Issue `345d1409…`:
    `forged.json` (one unrelated bucket PASS), `w01only.json` (only W01, flipped to PASS), `partial.json` (full
    estate, W01 PASS), `absent.json` (full estate minus W01), `clean.json` (W01 and W12 PASS). Then
    `ingest clean.json --diff` (durability) and `ingest estate.findings.json --diff` (regression).
  - `governance init` and `governance init --write`, then `issues metrics` and `doctor`.
  - `doctor`, `scan` and `onboard` with no config, an empty `HOME`, `PATH=/usr/bin:/bin` and fake env credentials.
  - `ask` offline (4 questions incl. "who can access nimbus-lab-customer-pii?") with `PATH=/usr/bin:/bin`, no
    `CLOUD_POSTURE_BIN`, the repo venv, `NIMBUS_PYTHON_DIR`, and once from the clone with no Python deps.
  - `pr-comment --live off --trusted-cidr 203.0.113.0/24 --redact off --iac <dir>` on `closes`, `bad`, `create`,
    `revert`, against the committed fixture (`var.ssh_cidr`) and a literal-`0.0.0.0/0` copy (as `action-e2e.yml` does).
  - MCP smoke (default scope, hostile SQL): `tools/list`, `summary`, `paths`, `who_can` by bare name,
    `prioritize`, `issue`, `verify`, `draft_fix`, `hex(account)`, `LIKE '1111%'`, `store_meta`.
  - Dashboard rendered from the lab DB, captured with `shot.mjs` at `#overview`, `#paths`, `#issues`,
    `#compliance`: 0 page errors on all four.

---

## (1) Round-3 top 15, re-scored

| # | Round-3 shortfall | Status | Evidence seen in this run | What remains |
|---|---|---|---|---|
| 1 | Never run against a live cloud | **OPEN** | `doctor`: "warn credentials no accounts configured". No live column in `benchmark.json`. | Everything (owner action O1). |
| 2 | Nothing to install | **OPEN** | `0.1.0-dev`, `commit: unknown`; 155.6 MB stripped / 38.35 MB gz; `.goreleaser.yaml:43-47` `files:` is still LICENSE/README/SECURITY/CHANGELOG (no lab estate); `release.yml` has no size budget step. | Everything (O3, O4, O5), plus lab-in-archive and a size gate. |
| 3 | Verified closure not durable or wired | **CLOSED** | **Durable:** after `verify` on `clean.json`, `ingest clean.json --diff` prints "Verified fixed since the previous scan: 2" and `issues show` reads `state: verified_fixed`. **Regression:** re-ingesting the original estate prints "regressed 7cbb82bf… verified-fixed Issue observed again (reopened)" and the timeline row "regressed after verify". **Forge-resistant:** `forged.json` → "? unverified … the file mentions none of the path's 3 hop resource(s)", exit 2; `absent.json` → "unverified … the file never mentions arn:aws:s3:::nimbus-lab-customer-pii". `partial.json` → "✗ still open — path survives: Internet → nimbus-lab-export → nimbus-lab-export-lambda-role → nimbus-lab-customer-pii (score 10.0 CRITICAL → 7.0 HIGH)", exit 2; `clean.json` → verified-fixed, exit 0. `issues mark-pending` and `--state pending|verified` exist; `issues metrics` has "closure: verified fixed … verified share … regressions after verify". `plan` verify steps print `cloud-posture verify <issue-id>`; 0 "Until finding lifecycle" lines. MCP has a `verify` tool. | Targeted readers still AWS S3/EC2/SG/IAM role only (the MCP `verify` result says so). The MCP `verify` tool is a read-only report (`"mutates": false`, returns the command), not a verification. `verify --help` still says a finding Issue is fixed when the finding is "PASS **or absent**", while the behaviour (correctly) treats absence as unverified. Never run live. Moved to new #8. |
| 4 | Headline numbers disagree | **IMPROVED** (large) | `ingest`, `issues`, the dashboard risk panel, MCP `summary` and the copilot all say "83 open Issues: 19 attack path Issues (22 hop variants) + 64 finding Issues; 12 critical (2 path, 10 finding)". `issues` header "6 of 83 open Issues (path Issues by score, then finding Issues by severity)", path Issues first. Credential titles in `issues`: "external trust abuse of nimbus-lab-vendor-access → AdministratorAccess", "credential compromise of nimbus-lab-dev-sam → nimbus-lab-ec2-admin-role (AdministratorAccess)". | `plan` still opens "Plan: 22 attack path(s) (21 traversal, 1 rule-chain)". `paths`, `plan` and the dashboard path list still title the same Issue "nimbus-lab-vendor-access → nimbus-lab-vendor-access → Privilege escalation to nimbus-lab-vendor-access". `scan --iac` prints "0 critical (0 path, 0 finding)" and, five lines later, "Top risk: 9.8 Critical". Tie order differs: `ingest`/`issues` put hrexports first, `paths`/dashboard/copilot put customer-pii first. CLI `who-can s3:GetObject nimbus-lab-customer-pii` (bare name) returns **19** principals and omits anonymous (internet); the ARN form and MCP `who_can` by name return 21. The README quickstart block is now stale (new #3). |
| 5 | Ownership mostly empty out of the box | **IMPROVED** (outcome, but wrong owner) | `governance init` now proposes `defaults.owner` and `account_owners`; `--write` → "applied to 83 open Issues: 0 unassigned (0%)"; `doctor` "ok ownership 83 of 83 open Issues have an owner". | The proposal is a tie-break: "proposed defaults.owner "finance": the most common owner tag (2 of 14 tagged resources)"; "account owner aws/111111111111: … "finance" (2 of 11)". `issues metrics` after `--write`: **finance 63 of 83**, including the GCP, Kubernetes (cluster-admin), GitHub and Okta Issues. Before `init`, 64 of 83 are still "(unassigned)". |
| 6 | PR one-click fixes rarely appear | **CLOSED** | `closes.plan.json` with a literal-`0.0.0.0/0` copy: "opens 1 / escalates 0 / lowers 1 / closes 1", `nimbus-closes-paths: 1`, **2 ```` ```suggestion ```` blocks**, "part 1 of 2 of one fix: commit all 2 together (Add suggestion to batch)", the second hunk adds a validated `variable "allowed_cidrs"` with no default. `bad` and `create` on the literal copy: 2 blocks each. `action.yml:138` adds `--iac "${CP_TF_DIR:-$CP_IAC}"` when `suggestions` is true (default `"true"`). | The committed fixture (`var.ssh_cidr`) gets 0 blocks, which is correct (the fix is a variable value). Review-comment posting needs GitHub and was not exercised. |
| 7 | MCP surface lags the CLI | **CLOSED** | Default `tools/list`: coverage, explain, issue, paths, prioritize, schema, sql, summary, verify, who_can (10). `draft_fix` → "unknown tool or outside this session's scope". `who_can` by bare name → count 21, anonymous first. `paths` returns `issues` with `issue_id` and `variant_count`. 0 raw account / `rtb-`/`acl-`/`sg-` ids across all 11 calls. `hex(account)` returns the placeholder's hex; `LIKE '1111%'` → 0; `store_meta` → "not queryable". README `mcp` row now says "default scope `read`" and matches `mcp --help`. | stdio only. MCP `paths` has no `from/to/through` arguments. `verify` is a report only. Finding fingerprints / MCP `finding_id` still unkeyed (log). |
| 8 | No graph query | **CLOSED** | `paths --from internet --to aws_s3_bucket --through aws_iam_role` → "3 path(s) … (max 6 hops; 1 start node(s), 6 end node(s))": customer-pii via the export Lambda role, billing-exports via media-01/media-role, analytics-pii via report-worker IRSA, every hop with `because`. `--through nimbus-lab-media-role` → 1 path. `--through nosuchrole` → "selector "nosuchrole" matches no node in the graph (use internet, type:<type>, class:<class>, a node id or an exact name)", exit 1. `--format json` carries the query and per-hop steps. | Not on MCP or the dashboard; no saved queries (Wiz Explorer, Prowler query box). The error is printed twice ("Error:" and "error:"). Not in the README command table. |
| 9 | No path-rule authoring or privesc library | **IMPROVED** (large) | `risk list`: 21 path rules, each "[Prowler Apache-2.0: aws-…]". `risk test internal/attackpath/rules/aws/privesc/aws-ec2-privesc-passrole-iam.yaml` → "own tests: pass … dry run against the stored snapshot (no writes): 1 match(es) • nimbus-lab-dev-sam → nimbus-lab-ec2-admin-role [verified]" with four `because` lines down to `inline-policy#PassBuilderRole`. `risk test rules/paths/aws/example-ssm-prod-only.yaml` → own tests pass, 0 matches. | `risk test aws-ec2-privesc-passrole-iam` (the id `risk list` prints) → "open aws-ec2-privesc-passrole-iam: no such file or directory", printed twice; the shipped rules live under `internal/` and are not in the release archive. Matches are dry-run only: not wired into `paths`, Issues or scoring (log). 21 rules vs Prowler's ~70 attributed queries. |
| 10 | Fix content thins out past the top | **IMPROVED** | LAMBDA_PUBLIC is typed (log; not a stub in `plan --top 20`). `plan` ends "By target resource (6 target(s))" (21 with `--top 20`) with "resolves N / reduces M". Every verify phase names `cloud-posture verify <issue-id>` for the finding and the path Issue it resolves. | `plan --top 20`: **9 of 20 minimum-fix steps are "generic stub"**: 7 native `NIMBUS-LAB:*` checks (instance SSH/HTTPS exposure, LoadBalancer ×2, bedrock agent, GitHub OIDC trust, K8s secret RBAC, Okta MFA-exempt) and `GCP_INSTANCE_PUBLIC_IP`. |
| 11 | Copilot rough edges | **IMPROVED** (with a regression) | With `PATH=/usr/bin:/bin` and no `CLOUD_POSTURE_BIN`: "21 principal(s) can s3:GetObject on nimbus-lab-customer-pii: anonymous (internet) (inferred); …". SQL is folded: "Sources: 1 query (--show-sql to print)". Ledger: "Blocked … nimbus-lab-ledger (not exposed (blocked: route table …))". "top attack paths": "19 open attack-path Issue(s) (22 hop variant(s))". | **Regression:** from a clone after `make build` with no `pip install`, `ask` finds `python/` beside the binary, passes the `import nimbus` probe, then prints a Python traceback ending "ModuleNotFoundError: No module named 'typer'". With the README's lab config (`python: enabled: false`) `ask` says "pip install -e "python[ai]"", which is the wrong advice. Each answer is followed by a wrapped table: **40 KB** (who-can), **50 KB** (top attack paths) at non-TTY width. The ledger answer still opens "Nothing here is exposed to the internet." |
| 12 | Release gate and changelog lag | **CLOSED** | `release.yml` runs `GROUNDTRUTH_STRICT=1 make groundtruth`, `readme-bench -check`, `make readme-check` and "CHANGELOG has a section for this tag" before goreleaser. CHANGELOG `[Unreleased]` has score 2.2.0, 2.3.0 and 2.4.0 and waves 3–4. `readme-check` PASS (22 claims); `readme-bench -check` current. | No gate covers the README quickstart transcript, which is stale (new #3). |
| 13 | `onboard` needs the cloud CLIs | **CLOSED** | Empty `HOME`, `PATH=/usr/bin:/bin`, fake `AWS_ACCESS_KEY_ID`: "✗ aws sts:GetCallerIdentity: … InvalidClientTokenId" (SDK chain; round 3 said "aws not installed"). | `onboard` made that STS call although `CLOUD_POSTURE_NO_NETWORK=1` was set (new #14). |
| 14 | Reachability mostly "unknown" in the lab | **CLOSED** | `paths --exposures`: web-01, media-01, jump-01 (via `nimbus-lab-jump-nsg`), orders all carry a verdict; the "not known: route table and network ACL not evaluated" clause is gone. `prioritize` top 8 reasons are one short clause each. Log: reachable 8 → 12, unknown 15 → 10. | S3/RDS weakness exposure still reads "(no width data; treated as wide)". |
| 15 | Checkov normalisation below the bar | **CLOSED** | `catalog unmapped --tool checkov`: "80/95 FAIL findings mapped (84.2%), 15 unmapped across 14 distinct checks"; Trivy 54/60 (90.0%). `scan --iac lab/terraform/aws`: Trivy 42 of 44 mapped (round 3: 41), native 13/13. | Security-relevant ids still unmapped: `CKV_AWS_260` (SG ingress 0.0.0.0/0 to port 80), `AZU-0047` (unrestricted ingress). `catalog unmapped` fails outside the repo ("lab/golden/expectations.yaml not found … pass --from"). |

**Tally: 8 CLOSED (3, 6, 7, 8, 12, 13, 14, 15), 5 IMPROVED (4, 5, 9, 10, 11), 2 OPEN (1, 2).** Both OPEN items are
blocked on owner actions (O1; O3/O4/O5). Every code-side item from round 3 moved.

---

## (2) Release readiness for a signed v0.2.0, re-scored

✓ = met, ~ = partly met, ✗ = not met.

| # | Must be true at install time | R2 | R3 | R4 | Evidence seen in this run |
|---|---|---|---|---|---|
| 1 | `brew install`, `docker run …@sha256`, `install.sh --require-signature` on macOS arm64 / Linux amd64 / arm64; `cosign verify-blob` succeeds | ✗ | ✗ | ✗ | No tag; pipeline never run (O3, O4, O5). |
| 2 | `version` prints `0.2.0`, a real commit, a build date and the score version | ✗ | ✗ | ✗ | `0.1.0-dev` / `commit: unknown (dev build)` / `built: unknown` / `score: 2.4.0`. |
| 3 | Binary size stated and reasonable; archive ≤ 40 MB; SBOM attached | ~ | ~ | ~ | 155.6 MB stripped, 38.35 MB gz (1.6 MB headroom); no size gate in `release.yml`; SBOM configured, never produced. |
| 4 | `doctor` has no stale messages, exits non-zero on a hard failure, states the KEV/EPSS date | ~ | ✓ | ✓ | No config, empty `HOME`: "ok config (none: no config file found) valid, 0 account(s)", "ok intel snapshot embedded KEV/EPSS snapshot 2026-10-09", python row "optional; scanning, scoring and paths are Go-native", exit 0. |
| 5 | The first `scan` with no targets says nothing was scanned and exits non-zero | ✗ | ✓ | ✓ | "✗ nothing scanned: no accounts configured, no IaC root and no tool ran; run `cloud-posture onboard` or pass --iac <dir>". |
| 6 | First `onboard` → `scan` on one AWS account in under 10 minutes on the shipped read-only policy | ✗ | ✗ | ✗ | Never live (O1). Detection is now SDK-chain (a real STS round trip was observed with fake keys). |
| 7 | Offline quickstart demo works and matches the README | ~ | ~ | ~ (regr.) | It works from source, but the README's "real output" no longer matches: README "Scan complete! Found 62 open findings (83 total results): - 9 Critical (22 attack paths)"; binary "Ingest complete: 62 open findings in 92 results … 83 open Issues: 19 attack path Issues (22 hop variants) + 64 finding Issues; 12 critical". `paths` and `plan` lines still match. Not in the release archive. |
| 8 | One verdict everywhere | ✗ | ✓ | ✓ | Ledger #45 at 6.8 Medium with the route-table reason in `prioritize`, the copilot and the Issue; 12 critical Issues on every headline surface; copilot parity 27/27 verdicts and 19/19 path Issues (log). Residual wording in `plan`/`paths` titles is tracked as new #4. |
| 9 | README claims current; `make readme-check` runs in the release workflow | ✗ | ~ | **✓** | `release.yml:44-57` runs strict groundtruth, readme-bench, readme-check and the CHANGELOG gate. |
| 10 | Benchmark numbers come from `benchmark.json`; "synthetic, not live" on the first screen | ~ | ✓ | ✓ | Status line in the first screen; `readme-bench -check` current. |
| 11 | Every command in `--help` is documented; no help text overclaims | ✗ | ~ | ~ | MCP mismatch fixed. Not in the README command table: `risk`, `catalog unmapped`, `paths --from/--to/--through`, `issues mark-pending`. `verify --help` says "PASS or absent" although absence is now unverified. |
| 12 | Action, pinned by SHA to the v0.2.0 commit, passes e2e on GitHub | ~ | ~ | ~ | `action.yml` now passes `--iac`; `action-e2e.yml` asserts the closes fixture and 2 suggestion blocks, which reproduce locally. The GitHub run waits on a release. |
| 13 | MCP config for Claude Desktop and Cursor works against the installed binary | ✓ | ✓ | ✓ | 10 tools, default `read`, 0 raw-id leaks, oracle refused. |
| 14 | `convert` and `scan -o` outputs validate | ✓ | ✓ | ✓ | native → OCSF: 92 records, `class_uid 2004`, `1.6.0`; → SARIF `2.1.0`, 62 results. |
| 15 | SECURITY.md steps, O4 setting, CHANGELOG with the score changes | ~ | ~ | ~ | CHANGELOG fixed (2.2.0/2.3.0/2.4.0). O4 still undecided. |
| 16 | `go test ./...`, `pytest`, `make ui-test`, strict groundtruth, govulncheck green | ✓ | ✓ | ✓ | Strict groundtruth PASS here (precision 22/22, recall@7 19/20, finding-level 0 / 0 of 62, noise 4/4). W5-ENGINE end gate (log): `go test` 40/40, pytest 430, `groundtruth-golden` PASS. |

**Score: 8 of 16 met (round 3: 7; round 2: 3), 5 partly met, 3 not met.** The three not met (1, 2, 6) are owner
actions. Of the five partly met, #7, #11 and #15 (CHANGELOG half) close in S effort on the code side; #3 and #12
need the release itself.

---

## (3) The 21 round-3 rough edges, re-walked

Walk: fresh repo copy, `make build` (7.9 s wall with a warm cache; `bin/cloud-posture` 221 MB), then the README
quickstart, `issues`, `issues show`, dashboard, `ask`, `onboard`, `scan`, `doctor`, `governance init`, `mcp --help`.

| Edge | Round 3 | Round 4 | Observed |
|---|---|---|---|
| E1 | Two names (nimbus / cloud-posture) | remaining | Now explained in the README's first line, still two names (O3). |
| E2 | `go install …@latest` resolves a pseudo-version, unsaid | remaining | Unchanged text. |
| E3 | No size warning; 220 MB dev build | remaining | 221 MB. |
| E4 | `ingest` says "Scan complete!" | **fixed** | "Ingest complete: 62 open findings in 92 results (scanner evidence)." |
| E5 | DB location unsaid | **fixed** | "Database: …/clone/.cloud-posture/posture.db". |
| E6 | "22 attack paths" then "19 Issues" | partly fixed | `ingest` now says "19 attack path Issues (22 hop variants)"; `plan` still "22 attack path(s)"; the README block still shows the old "9 Critical (22 attack paths)". |
| E7 | "X → X → Privilege escalation to X" credential titles | partly fixed | Fixed in `issues`, MCP and the copilot; unchanged in `paths`, `plan` and the dashboard path list. |
| E8 | Stale "Until finding lifecycle lands" verify text | **fixed** | 0 occurrences; each step names `cloud-posture verify <id>`. |
| E9 | "3 Issue(s)" header | **fixed** | "6 of 83 open Issues (path Issues by score, then finding Issues by severity)". |
| E10 | Single Azure-blob finding above the 10.0 path Issue | **fixed** | Path Issues by score come first. |
| E11 | 64 of 83 owners "(unassigned)" | remaining (changed) | Still 64 before `governance init`; after `--write`, 63 go to "finance" by tie-break. |
| E12 | `paths` prints no Issue id | partly fixed | `ingest` prints "top Issue 0248… (cloud-posture issues show 0248…)"; `paths` text still prints none (JSON query output has path ids only). |
| E13 | LAMBDA_PUBLIC "generic stub" | **fixed** | Typed; 9 other stubs remain in the top 20 (new #9). |
| E14 | "12 critical" vs 19 vs 9 | mostly fixed | `ingest`/`issues`/dashboard/MCP: 12 critical Issues. `prioritize` still lists 19 Critical findings under "Top 50 risks", without saying they are findings. |
| E15 | Compliance 0% with no explanation | remaining | A legend now reads "PASS = only passing checks map to the control …", but nothing says the lab has no PASS rows. |
| E16 | `ask` error printed twice; `[ai]` vs `[all]` | remaining (changed) | Printed once now, but from a clone it is a Python traceback ("No module named 'typer'"); with the lab config it is the wrong "pip install" advice; the error names `python[ai]`, the README `python[all]`. |
| E17 | Copilot cannot find the binary | **fixed** | who-can answers with `PATH=/usr/bin:/bin` and no `CLOUD_POSTURE_BIN`. |
| E18 | 3 KB of SQL printed twice | **fixed** (new edge) | SQL folded behind `--show-sql`; replaced by 40–50 KB wrapped tables. |
| E19 | `onboard` needs the `aws` CLI | **fixed** | SDK chain, STS called. |
| E20 | `governance init` suggests no owner value | **fixed** (new edge) | Proposes `defaults.owner` and `account_owners`, but by a 2-of-11 tie-break. |
| E21 | README "read scope by default" vs help "every tool" | **fixed** | Both say `read`. |

**Fixed 11 (E4, E5, E8, E9, E10, E13, E17, E18, E19, E20, E21); partly 4 (E6, E7, E12, E14); remaining 6
(E1, E2, E3, E11, E15, E16).** New edges seen in this walk: **N1** the README quickstart output is stale;
**N2** copilot traceback from a clone; **N3** 40–50 KB copilot tables; **N4** `risk test <id>` fails, only a file
path works; **N5** `paths`, `risk test` and `catalog unmapped` print every error twice ("Error:" + "error:");
**N6** CLI `who-can` by name returns 19 and drops anonymous (MCP returns 21); **N7** `onboard` calls STS under
`CLOUD_POSTURE_NO_NETWORK=1`; **N8** `scan --iac` writes `.cloud-posture/runs/…` under the working directory even
when `--db` points elsewhere; **N9** `scan --iac` "0 critical" beside "Top risk: 9.8 Critical"; **N10**
`catalog unmapped` fails outside the repo. Nothing crashed in Go.

---

## (4) Full capability table, round 4 (91 rows)

Columns: round-3 → round-4 verdict, Δ against round 3, observed evidence or the remaining gap against the
best-in-class row with the same ID in `docs/research/competitive-feature-matrix.md`.

### 1. Inventory & graph

| ID | R3 | R4 | Δ | Observed / remaining gap (best-in-class) |
|---|---|---|---|---|
| IG1 | SHORT | SHORT | = | `doctor` 0 accounts; fakes only (Prowler: 23 providers). |
| IG2 | SHORT | SHORT | = | `federates_to` declared by the lab (Cartography emits it). |
| IG3 | SHORT | SHORT | = | No org fan-out run. |
| IG4 | MATCHES | MATCHES | = | Keyed per-DB Issue ids (HMAC; old ids still resolve) (log). |
| IG5 | SHORT | SHORT | = | No unified kinds (Fix Inventory). |
| IG6 | ABSENT | **SHORT** | ↑ | `paths --from/--to/--through/--max-hops` with type/class/name/id selectors, JSON out. No saved queries, no property predicates, not in MCP or the dashboard (Sysdig SysQL, Wiz Explorer). |
| IG7 | SHORT | SHORT | = | `issue_score_history` (`--diff` rescored); no per-resource versions. |
| IG8 | MATCHES (fakes) | MATCHES (fakes) | = | Coverage panel "1 API calls / tool runs recorded"; empty scan fails loudly. |
| IG9 | MATCHES | MATCHES | = | Bedrock agent hop p=0.70. |

### 2. Attack paths & toxic combinations

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| AP1 | SHORT | SHORT | (impr.) | Fold keeps the max score; order-independent merge (log). No `Truncated` flag, no 50k-node benchmark (SCC, Cortex). |
| AP2 | MATCHES | MATCHES | = | `because` per hop in `paths`, the query output and the dashboard. |
| AP3 | MATCHES | MATCHES | (impr.) | 83 Issues; states open / pending / verified_fixed / reopened. |
| AP4 | ABSENT | **SHORT** | ↑ | Rule YAML + `risk test` (own tests, dry run, no writes) + 21 attributed rules. Not wired into output; id form fails (Sysdig custom risks, Prowler library). |
| AP5 | MATCHES | MATCHES | = | Dashboard "Choke points (10) … closes 2". |
| AP6 | **BEATS** | **BEATS** | (impr.) | "20 fix(es) … min_fix_exact=true … min_fix_verified=true … 95.5%" plus "By target resource". |
| AP7 | MATCHES | MATCHES | = | Trusted 3 / private 2 with reasons; dead ends 17. |
| AP8 | MATCHES (AWS) | MATCHES (AWS) | (impr.) | Lab compute and RDS carry verdicts; jump-01 via NSG; short reasons. Never live (ASH). |
| AP9 | ABSENT | ABSENT | = | No probes. |
| AP10 | **BEATS** | **BEATS** | (impr.) | opens / escalates / lowers / closes all exercised ("opens 1 / lowers 1 / closes 1"), per-hunk suggestions. |

### 3. Risk prioritization

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| RP1 | MATCHES | MATCHES | = | `score_version 2.4.0` in every explanation (jump shape 3.6 → 5.0). |
| RP2 | MATCHES | MATCHES | = | KEV ×1.50 (Log4Shell on media-01). |
| RP3 | MATCHES | MATCHES | = | — |
| RP4 | SHORT | SHORT | = | `compensating_controls ×1.00 no compensating control recorded` everywhere (Zscaler UVM). |
| RP5 | MATCHES | MATCHES | (impr.) | `--diff`: "regressed … verified-fixed Issue observed again (reopened)"; "Verified fixed since the previous scan: 2". |
| RP6 | SHORT | SHORT | (impr.) | Checkov 84.2%, Trivy 90.0%, `catalog unmapped`; CKV_AWS_260 / AZU-0047 unmapped; no J1-style one row per CVE per asset. |
| RP7 | MATCHES | MATCHES | = | Verify keeps suppressions (log). |
| RP8 | MATCHES | MATCHES | (impr.) | Default/account/provider owners, `unassigned_sink`; heuristic picks "finance" for 63/83 (MDC defaults per subscription, set by a human). |

### 4. Identity / CIEM

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| ID1 | MATCHES (offline) | MATCHES (offline) | (impr.) | Trust conditions via the IAM evaluator; BPA-first, Deny honoured (log). |
| ID2 | SHORT | SHORT | (impr.) | 21 Prowler-credited techniques, upstream-correct targets (log); dry-run only (Prowler ~70). |
| ID3 | MATCHES | MATCHES | (impr.) | MCP `who_can` (21 by name). CLI by bare name returns 19 without anonymous (N6). |
| ID4 | SHORT | SHORT | = | PassRole scoping only (Datadog suggested policy, Cortex). |
| ID5 | SHORT | SHORT | = | No Azure RBAC. |
| ID6 | SHORT | SHORT | = | — |
| ID7 | ABSENT | ABSENT | = | Cut. |

### 5–6. Data, vulnerabilities

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| DS1 | ABSENT | ABSENT | = | Cut. |
| DS2 | ABSENT | ABSENT | = | — |
| DS3 | SHORT | SHORT | = | Sensitivity from labels only. |
| VS1 | SHORT | SHORT | (impr.) | Trivy 42/44 mapped on lab IaC. |
| VS2 | ABSENT | ABSENT | = | Cut. |
| VS3 | ABSENT | ABSENT | = | — |
| VS4 | SHORT | SHORT | = | — |
| VS5 | ABSENT | ABSENT | = | — |

### 7. IaC & code-to-cloud

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| IC1 | SHORT | SHORT | (impr.) | 13 native + 44 Trivy on `lab/terraform/aws`; summary says "0 critical" beside "9.8 Critical" (N9). |
| IC2 | SHORT | SHORT | = | CODEOWNERS only. |
| IC3 | ABSENT | ABSENT | = | — |
| IC4 | SHORT | SHORT | (impr.) | `action.yml` passes `--iac`; e2e asserts closes + 2 suggestions. No release. |
| IC5 | SHORT | SHORT | = | — |

### 8. Remediation

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| RM1 | MATCHES | MATCHES | (impr.) | LAMBDA_PUBLIC, EKS, RDS, cross-account trust typed (log); 9/20 stubs remain. |
| RM2 | SHORT | **MATCHES** | ↑ | Per-hunk ```` ```suggestion ```` blocks with confidence and "commit all together"; Action wired (Checkov, Cortex one-click). |
| RM3 | MATCHES | MATCHES | (impr.) | "By target resource (21 target(s))" with resolves/reduces (ASH remediation plans). |
| RM4 | MATCHES (offline) | MATCHES (offline) | (impr.) | Durable, regression-aware, forge-resistant `verify`; AWS 4 types; never live (XM, Orca). |
| RM5 | ABSENT | ABSENT | = | — |
| RM6 | ABSENT | ABSENT | = | — |

### 9. Compliance & evidence

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| CO1 | MATCHES | MATCHES | = | 11 frameworks; all 0% in the lab, unexplained (E15). |
| CO2 | MATCHES | MATCHES | = | — |
| CO3 | SHORT | SHORT | = | — |
| CO4 | SHORT | SHORT | = | Evidence zip unsigned. |
| CO5 | ABSENT | ABSENT | = | Trend "scan history carries totals only". |
| CO6 | ABSENT | ABSENT | = | No Vanta resource-API export. |
| CO7 | ABSENT | ABSENT | = | — |

### 10. Detection

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| DR1 | SHORT | SHORT | = | Polling, documented as such. |
| DR2 | SHORT | SHORT | = | — |
| DR3 | ABSENT | ABSENT | = | — |
| DR4 | ABSENT | ABSENT | = | — |

### 11. Integrations & workflow

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| IW1 | SHORT | SHORT | (impr.) | IPv6 zones, metadata always refused incl. NAT64/6to4/Teredo, no cross-origin body replay (log). Routing still by severity. |
| IW2 | MATCHES | MATCHES | (impr.) | `pending_verification` + `mark-pending`; ticket closes only on verified (log). No reverse sync (Datadog). |
| IW3 | **BEATS** | **BEATS** | = | — |
| IW4 | MATCHES | MATCHES | = | OCSF 1.6.0 / SARIF 2.1.0. |

### 12. Dashboard

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| UX1 | MATCHES | MATCHES | (impr.) | Risk panel "83 open issues: 19 attack path (22 hop variants) + 64 finding; 12 critical". Path list still uses old credential titles. |
| UX2 | SHORT | SHORT | (impr.) | `issues metrics` closure block (verified share, regressions after verify); trend still totals only (J1). |
| UX3 | SHORT | SHORT | = | No executive report. |
| UX4 | SHORT | SHORT | = | "no cost data". |

### 13. AI & agent interfaces

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| AI1 | MATCHES | MATCHES | (regr.) | Binary discovery and folded SQL fixed; first run from a clone is a traceback, tables 40–50 KB (Upwind editable query). |
| AI2 | MATCHES | MATCHES | = | — |
| AI3 | MATCHES | MATCHES | (impr.) | 10 tools, default read, grouped Issues, verdict-text redaction, `store_meta` refused. stdio only (Sysdig MCP). |
| AI4 | MATCHES | MATCHES | = | Audit JSONL per call. |
| AI5 | ABSENT | ABSENT | = | Cut. |

### 14. Platform

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| PF1 | MATCHES | MATCHES | = | Errors printed twice on several commands (N5); `ask` once. |
| PF2 | SHORT | SHORT | = | — |
| PF3 | SHORT | SHORT | (impr.) | New governance keys validated (log). |
| PF4 | ABSENT | ABSENT | = | — |
| PF5 | ABSENT | ABSENT | = | No release; 155.6 MB stripped. |
| PF6 | SHORT | SHORT | = | — |

### 15. Trust & supply chain

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| TS1 | ABSENT | ABSENT | = | Never run on a tag. |
| TS2 | MATCHES | MATCHES | = | — |
| TS3 | MATCHES | MATCHES | (impr.) | SDK-chain detection; but STS called under no-network (N7). |
| TS4 | **BEATS** | **BEATS** | = | Strict groundtruth and mapping floors in `release.yml`; README quickstart transcript stale (N1). |

### 16. Ecosystem interop

| ID | R3 | R4 | Δ | Observed / remaining gap |
|---|---|---|---|---|
| EI1 | MATCHES | MATCHES | = | — |
| EI2 | SHORT | SHORT | (impr.) | 21 Prowler privesc queries ported with upstream id and licence. |
| EI3 | SHORT | SHORT | = | — |
| EI4 | ABSENT | ABSENT | = | — |

**Totals (91 rows).**

| | BEATS | MATCHES | SHORT | ABSENT | IN-FLIGHT |
|---|---|---|---|---|---|
| Round 4 | 4 | 33 | 34 | 20 | 0 |
| Round 3 | 4 | 32 | 33 | 22 | 0 |
| Round 2 | 4 | 28 | 35 | 24 | 0 |
| Round 1 | 3 | 16 | 39 | 25 | 8 |

Since round 3: 3 rows moved up (IG6 and AP4 ABSENT → SHORT, RM2 SHORT → MATCHES), none moved down, 25 narrowed
their gap, and 1 (AI1) kept its verdict with a new defect. The two ABSENT rows a Wiz-trained buyer asks about first,
graph query and custom rules, are now SHORT. The rest of the buyer-visible ABSENT set is unchanged: AP9 (probes),
CO5/CO6 (continuous evidence), PF5/TS1 (release).

---

## (5) New top 15 shortfalls, ranked by buyer impact

No CLOSED item is repeated; IMPROVED items appear only for what remains.

| # | Shortfall (observed) | Fix | Effort | Owner track | Plan v3 |
|---|---|---|---|---|---|
| 1 | **Never run against a live cloud.** `doctor` "no accounts configured"; `live_cloud: false`; `verify` has only re-read JSON files. | Apply `lab/terraform/aws` to a sandbox account; scan with the built binary; publish a live column in `benchmark.json`; run `verify` on a real W01 + W12 fix inside the eventual-consistency window. | M | P1-LAB / P2-LAB (O1) | 0-1, TS4 |
| 2 | **Nothing to install.** `0.1.0-dev`, `commit: unknown`; 38.35 MB gz with 1.6 MB headroom and no size gate; archive lacks the lab, so the offline demo cannot run from an install. | Cut signed `v0.2.0` (O3, O4, O5). Add `lab/local/out/estate.findings.json` and the lab config to goreleaser `files:`. Add a ≤ 40 MB gz budget step to `release.yml`. | M | P0-REL | 0-5 (PF5/TS1); lab-in-archive and size gate NEW |
| 3 | **The README's "real output" is stale, and nothing gates it.** README: "Scan complete! Found 62 open findings (83 total results): - 9 Critical (22 attack paths)". Binary: "Ingest complete: 62 open findings in 92 results … 83 open Issues … 12 critical". `risk`, `catalog unmapped`, `paths --from/--to/--through` and `issues mark-pending` are not in the command table; `verify --help` says "PASS or absent". | Generate the quickstart transcript (ingest, `paths --limit 5`, `plan` heads) with `readme-bench` between markers, and gate it in `release.yml` like the benchmark block. Add the four commands to the table. Fix the `verify` help line. | S | Docs / P0-GOV | 0-6 (README claims match evidence); transcript gate NEW |
| 4 | **Residual count and title disagreements.** `plan` "22 attack path(s)"; `paths`/`plan`/dashboard "nimbus-lab-vendor-access → nimbus-lab-vendor-access → Privilege escalation to …" vs `issues` "external trust abuse of nimbus-lab-vendor-access → AdministratorAccess"; `scan --iac` "0 critical" beside "Top risk: 9.8 Critical"; tie order hrexports-first vs customer-pii-first; CLI `who-can` by name 19 (no anonymous) vs 21. | Use `model.PathIssueTitle` in `paths`, `plan` and the dashboard; `plan` headline "19 attack path Issues (22 hop variants)"; label `prioritize` and the scan "Top risk" as findings; one tie-break (score, then Issue id) everywhere; route CLI `who-can` names through MCP's `resolveNodeName`. Extend `TestHeadlineConsistentAcrossSurfacesOnLab` to `plan`, `paths` and `who-can`. | S | P1-ISSUES + P1-ENGINE | NEW (extends W5 consistency test) |
| 5 | **The default owner is a tie-break, so "100% assigned" is misleading.** "finance" is proposed from 2 of 11 tagged AWS resources and receives 63 of 83 Issues, including GCP, Kubernetes cluster-admin, GitHub and Okta; `doctor` then says "ok ownership 83 of 83". | No default on a tie or a weak plurality: emit `defaults.owner: <set-me>` and keep `doctor` at warn. Propose per-provider owners only where that provider has tags. Report "assigned by default" separately in `doctor` and `issues metrics`. | S | P2-EVIDENCE (governance) | RP8 |
| 6 | **The copilot's first run breaks.** From a clone without `pip install`: Python traceback "No module named 'typer'". With the README lab config (`python.enabled: false`): "pip install -e "python[ai]"" (wrong advice; README says `python[all]`). Answers carry 40–50 KB wrapped tables. | Probe the copilot's imports (typer, rich) and print one actionable line; when config disables Python, say so and name the key; one extras name in both places; tables only on a TTY or `--table`, capped at 20 rows. | S | P1-MCP follow-up | AI1 partly; rest NEW |
| 7 | **Path rules do not reach the product.** `risk test` matches are dry-run only; `risk test <id>` (the form `risk list` prints) fails "no such file"; shipped rules live under `internal/` and are not in the archive; 21 rules vs Prowler's ~70. | `risk test <id|file>`; embed shipped rules and print their path; wire verified matches into traversal as escalation edges behind a groundtruth gate; port the next Prowler tranche with fixtures. | M | P1-ENGINE + P2-CIEM | AP4, ID2 |
| 8 | **Verification coverage is narrow and the MCP tool does not verify.** Targeted readers: AWS S3/EC2/SG/IAM role only; MCP `verify` returns the command (`"mutates": false`). | Readers for RDS, Lambda, EKS, IAM user, Azure storage and NSG; MCP `verify` runs a read-only evaluation (from-file or targeted read) and reports the outcome without recording state unless a write scope exists. | M | P2-VERIFY | RM4; MCP execution NEW |
| 9 | **Fix content still thins out.** 9 of the 20 minimum-fix steps are "generic stub": seven native `NIMBUS-LAB:*` checks and `GCP_INSTANCE_PUBLIC_IP`. | Catalog aliases for the native ids (instance SSH/HTTPS → SG ingress template, LB service, GitHub OIDC `sub`, K8s secret RBAC, Okta MFA), with a re-label of the lab. Target ≥ 18/20 typed. | M | P2-VERIFY (remediation) | RM1/RM3; templates NEW |
| 10 | **The graph query stays in the CLI.** No MCP `paths` filter, no dashboard query box, no saved queries; errors printed twice. | MCP `paths` `from`/`to`/`through`/`max_hops` arguments; a dashboard query box (Prowler, Wiz Explorer); `--save <name>`. Silence cobra's duplicate error print globally. | S | P1-ENGINE / P1-MCP | IG6 follow-up |
| 11 | **Security-relevant scanner ids unmapped; `catalog unmapped` repo-bound.** `CKV_AWS_260` (port 80 from 0.0.0.0/0), `AZU-0047` (unrestricted ingress); `catalog unmapped` fails outside the repo. | Map both to the SG/NSG open-ingress canonical ids; default `catalog unmapped` to the stored DB's findings (`--from-db`). | S | P1-INTEROP | RP6 |
| 12 | **Trend is totals only.** "scan history carries totals only"; `issue_score_history` and the closure metrics are not charted. | Per-scan new/resolved/regressed counts; chart score history and verified share on the overview. | S/M | P2-EVIDENCE / UX | UX2, CO5 |
| 13 | **Compliance reads 0% everywhere with no explanation.** All 11 frameworks 0% in the lab; evidence zip unsigned; no Vanta export. | Overview note when a framework has 0 PASS rows; add PASS rows to the lab estate; then signed evidence and a Vanta resource-API export. | S → M | P2-EVIDENCE | CO1/CO4/CO6 |
| 14 | **`onboard` ignores no-network; `scan --iac` writes beside the cwd.** A real STS call ran under `CLOUD_POSTURE_NO_NETWORK=1`; runs land in `./.cloud-posture/runs` even with `--db` elsewhere. | `onboard` reports "skipped (no-network)" for STS; run artefacts beside the DB. | S | P3-PACKAGE / CLI | NEW |
| 15 | **Identifier residuals** (log): finding fingerprints / MCP `finding_id` still unkeyed digests; DB-less outputs (pathdiff, PR SARIF) print old ids; Go commands migrate Python-built DBs. | Per-session HMAC for MCP `finding_id`; refuse to migrate a Python-built DB outside `ingest`. | S/M | P1-MCP / P1-ISSUES | NEW |

---

## (6) Where nimbus now beats everyone (observed in this run only)

1. **Verification that knows which path survived, and that cannot be forged by a file.**
   `partial.json` → "✗ still open — path survives: Internet → nimbus-lab-export → nimbus-lab-export-lambda-role →
   nimbus-lab-customer-pii (score 10.0 CRITICAL → 7.0 HIGH)", exit 2. `forged.json` → "? unverified … no evidence
   about this Issue", exit 2. `clean.json` → verified-fixed; the state survives the next ingest, and a returning
   problem prints "regressed … verified-fixed Issue observed again (reopened)". XM Remediation Confirmation, Prowler
   partial scans and Orca close-then-rescan confirm that a finding is gone; none reports the surviving hop.
   Caveat: offline only.
2. **An exact, re-verified minimum fix set, grouped by target.** "20 fix(es) — min_fix_exact=true …
   min_fix_verified=true … removes 95.5%", then "By target resource" and a `cloud-posture verify <id>` per step.
   ASH plans have phases without a minimality proof; MDC and SCC stop at choke points.
3. **A plan-time attack-path diff with credit and one-click fixes.** `closes.plan.json`: "opens 1 / escalates 0 /
   lowers 1 / closes 1", plus two batched ```` ```suggestion ```` blocks that add a validated, default-less
   `allowed_cidrs` variable. Checkov and Cortex suggest per-resource fixes; none diffs attack paths at plan time.
4. **One reachability verdict with the blocking rule, carried into the score.** `prioritize` #45: "6.8 Medium …
   exposure ×0.50 not exposed (blocked: route table rtb-0a1b2c3d4e5f60001 has no route to an internet gateway)";
   the copilot answers the same.
5. **`who-can` with the internet first and statement ids, in the CLI and in MCP.** "21 principal(s) … anonymous
   (internet) inferred allow — bucket policy Principal *", then principals with `policy#index` and a confidence
   grade; MCP `who_can` by bare name returns the same 21.
6. **Test-before-save path rules with upstream credit and statement-level evidence.** `risk test` prints "own tests:
   pass", then a dry run "(no writes)" with "nimbus-lab-dev-sam → nimbus-lab-ec2-admin-role [verified]" and the
   granting statements. Sysdig has test-before-save for custom risks but a closed library; Prowler ships the
   queries but the cluster docs record no dry-run with statement evidence.
7. **An open benchmark that gates the release.** Strict groundtruth (22/22, recall@7 19/20, finding-level 0 / 0 of
   62) and mapping floors (Checkov 84.2%, Trivy 90.0%, `catalog unmapped` lists the rest) run in `release.yml`.
8. **MCP redaction that survives a hostile client**, now with grouped Issues and `who_can`: 0 raw ids over 11
   calls, `hex()` returns the placeholder's hex, the LIKE oracle returns 0, internal tables refused.

## (7) Verdict

**Not yet. The code has caught up with what a Wiz-trained buyer checks in a demo; the product has not caught up with
what that buyer checks before signing.**

Wave 5 closed eight of the fifteen round-3 shortfalls and moved the other five. The round-3 demo breakers are gone:
a verified fix now stays verified and reopens if the problem returns, a forged export cannot close anything, the
PR comment offers one-click fixes on the common case, MCP is read-only by default with `who_can`, and there is a
graph query and a rule test. On the wedge (minimum fix set, plan-time diff, path-aware verification, explainable
reachability, open benchmark) nimbus is ahead of every named competitor in substance.

The CISO would still not say "best-in-class", for three reasons:

- **Nothing has touched a real cloud**, and there is nothing signed to install. Both are owner actions.
- **The first screen is out of date.** The README's quickstart output no longer matches the binary, and it is the
  first thing a buyer compares.
- **Polish at the edges a buyer meets in minute one:** "100% owned" by a tie-break owner, a Python traceback from
  `ask`, and `plan`/`paths` still using the counts and titles the rest of the product dropped.

**The single thing that would change the answer: one live AWS run with the signed `v0.2.0` binary**, applied to the
lab twin, producing a `live_cloud: true` column and one fix closed by `verify` against the live API. Before that
run, land the three S items that would otherwise show up in it: new #3 (README transcript gate), #4 (titles and
counts) and #5 (no tie-break default owner).

## (8) What to show in the first demo (observed commands and outputs only)

Run everything with `--config lab/local/cloud-posture.lab.yaml`. Start with
`cloud-posture ingest lab/local/out/estate.findings.json --source native`: "83 open Issues: 19 attack path Issues
(22 hop variants) + 64 finding Issues; 12 critical (2 path, 10 finding)". Then `cloud-posture paths --limit 5`: the
#1 Issue is "Internet → nimbus-lab-customer-pii … readable by anyone on the internet". Ask the Wiz Explorer
question, `cloud-posture paths --from internet --to aws_s3_bucket --through aws_iam_role`: three paths to PII
buckets through roles, every hop with `because`. Ask who can read it, `cloud-posture who-can s3:GetObject
arn:aws:s3:::nimbus-lab-customer-pii`: "21 principal(s)", anonymous (internet) first, with statement ids. Show the
fix, `cloud-posture plan`: "20 fix(es) — min_fix_exact=true … removes 95.5%", with a `cloud-posture verify <id>`
line in each step. Close the loop: fix only the bucket and run `cloud-posture verify 7cbb82bf… --from-file
partial.json` → "still open — path survives: Internet → nimbus-lab-export → nimbus-lab-export-lambda-role →
nimbus-lab-customer-pii (10.0 → 7.0)"; fix the Lambda too and `clean.json` → "verified-fixed". Shift left:
`cloud-posture pr-comment --plan-json testdata/action-fixture/plans/closes.plan.json --live off --trusted-cidr
203.0.113.0/24 --iac <fixture copy>` → "opens 1 / escalates 0 / lowers 1 / closes 1" with two one-click
suggestion blocks. End on the prioritised list (`prioritize --explain`, ledger at #45, "6.8 Medium … blocked: route
table … has no route to an internet gateway") and the dashboard's attack-paths view. Do **not** show `ask` from a
fresh clone, `governance init`, or `plan`'s first line until new #3–#6 land.
