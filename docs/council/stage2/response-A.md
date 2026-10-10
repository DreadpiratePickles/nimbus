# Council stage 1 — council member / distribution strategist

_council member: what gets a tool into 1,000 CI pipelines and named in ADOPTERS files. Written 2026-10-09 against the live tree. Shorthand: STRAT = `docs/research/strategy-how-to-win.md`, GAP = `docs/research/nimbus-gap-analysis.md`, MATRIX = `docs/research/competitive-feature-matrix.md`, OS = `docs/research/competitors/open-source.md`, CL = `docs/research/competitors/cnapp-leaders.md`, PL = `docs/research/competitors/platforms.md`, CA = `docs/research/competitors/compliance-and-adjacent.md`, INV = `docs/research/nimbus-capability-inventory.md`, BENCH = `docs/benchmark.md`, PLAN = `.planning/IMPLEMENTATION_PLAN_v2.md`, SESSION = `docs/sessions/2026-10-09-cwm-ui.md`. Every number below comes from one of those files._

## 1. Verdict on IMPLEMENTATION_PLAN_v2

**Right.** The positioning survives contact with Prowler: ingest their content, do not race their 1,616 check files (OS §1 tree count), compete on graph, fix and trust (PLAN §1, STRAT §4i). "Trust and truth first" is the correct order; Checkov's 38× download multiple over Prowler (STRAT §2.1) only pays if the thing in the pipeline does not lie, and INV's top-20 would have made every demo lie. Track E already produced a release surface most 10k-star projects lack: cosign keyless signing, SPDX SBOMs, SLSA attestation, distroless non-root image, an `install.sh` that refuses branches and verifies signatures, an Action pinned by SHA that installs from its own checkout (`.goreleaser.yaml`, `install.sh`, `action.yml`). The local ground-truth lab (BENCH: recall 12/12, recall@7 10/12, precision 95.2%, zero unlabelled paths ≥ 7) is the most differentiating asset in the repo; nobody publishes path-level ground truth (MATRIX TS4). Issues/lifecycle and a tested `docs/scoring.md` answer the loudest Wiz complaint ("tickets appear and disappear magically", STRAT §1.3).

**Wrong, from the distribution seat.**

1. **Distribution is Phase 3, about 27 days (GAP §e), after roughly 260 days of features.** Backwards. The research's strongest finding is that placement, not features, made Checkov (3.97M PyPI/month), c7n (1.38M) and Trivy (128M pulls) while ScoutSuite (7.8k stars, 0 commits in 12 months) died (STRAT §2.1, §2.4). Action, OCSF/ASFF, packaging and the interop spec are Phase 1 engineering tracks with acceptance tests.
2. **No community or governance scaffolding exists.** SECURITY.md, CONTRIBUTING.md, CODEOWNERS and a Code of Conduct, yes; ADOPTERS.md, GOVERNANCE.md, MAINTAINERS.md, ROADMAP.md, OPEN_SOURCE_PROMISE.md, no. The repo sits under a personal handle. STRAT §2.3 ranks "no business behind the project" as stall cause #1; §5.2 says MAINTAINERS with companies is a CNCF prerequisite. PLAN mentions ADOPTERS.md once, in Phase 3.
3. **Three names.** "nimbus" the project, `cloud-posture` the binary and cask, `ghcr.io/dreadpiratepickles/cloud-posture` the image. Trivy, Checkov, Prowler, Kubescape: one word, one binary, one formula. `v0.2.0` has not shipped; this is the last cheap moment.
4. **The north star ("paths closed through merged nimbus PRs per week") has no measurement.** STRAT §7.4 proposes a PR-body signature findable by public GitHub search; PLAN drops it. Zero telemetry is right; a searchable marker is one line.
5. **Prowler's repo is more agent-friendly than ours** (`AGENTS.md`, `.claude-plugin/marketplace.json`, OS §1). For a project built by agents, that is also the contributor on-ramp.
6. **The Python layer is still a second install** (STRAT §7.5 risk 10; PLAN §7) with no acceptance test for "the wedge loop needs only the Go binary".
7. **The cheapest content win is ignored.** Prowler ships 105 compliance framework JSONs under Apache-2.0 (OS interop table); importing them with attribution converts INV §8's "11 hand-written frameworks with known errors" into parity in a week.

Net: the engineering spine is right; the sequencing treats adoption as what happens after the product is finished. Adoption is a track.

## 2. Still missing for "complete package" in a 2026 RFP

Against CA's 24-row analyst/RFP checklist and GAP §b:

- **A live-cloud run.** BENCH: the Terraform lab was "never planned or applied". Every INV "real" is real against fakes. Reference calls end here.
- **CIEM depth.** `IsAdmin` ignores NotAction, `DataAccess` ignores Deny and conditions, no Azure RBAC or GCP project IAM (MATRIX ID1, ID5); GigaOm and rfp.wiki criterion (GAP §b rank 5).
- **Code-to-cloud in the PR.** No plan-time diff; the patcher is module-blind and a crafted `.tf` crashes the scanner (SESSION "Verification 2" defects 1–2). Latio: "CNAPP is defined… by code-to-cloud and runtime".
- **Runtime-to-posture correlation** by ingesting Falco/GuardDuty/Defender alerts onto nodes, so the RFP row reads "Partial" not "No" (GAP §f).
- **Standard outputs.** No OCSF or ASFF (MATRIX IW4); Security Hub speaks OCSF 1.6 (STRAT §5.1), and that bridge was Prowler's breakthrough channel.
- **Trend, MTTR, SLA, executive PDF** (MATRIX UX2–3); "weak executive reporting" is a cross-cluster complaint (CL).
- **GRC export** to Vanta/Drata, the buyer's system of record (CA steal #1).
- **MCP server.** Prowler, Steampipe, Kubescape, Sysdig, Datadog, AWS, JupiterOne all ship one (MATRIX AI3).
- **Vendor criteria** (SLA, SOC 2 Type II): "No" for OSS (CA rows 23–24). Substitute: signed releases, Scorecard, SECURITY.md, a named sponsor or services entity.
- **Named adopters.** Cartography: "70+ companies", 233 contributing orgs (STRAT §2.2). nimbus: zero.

## 3. Twelve-month roadmap, five bets, five cuts

**Q4 2026: make it true, make it installable.** Close Phase 0 (hardening re-probed, verifier-2 defects fixed, strict ground truth green except labelled gaps). Ship signed `v0.2.0`. One name, one org. Action e2e, OCSF/ASFF/`convert`, finding-contract spec, Prowler framework import, MCP server, governance files. First live AWS lab run the day credentials exist, published as unverified until then.
**Q1 2027: the wedge loop in public.** Plan-time path diff, verified fix, root-cause plans, EPSS/KEV, dead-end filter. Benchmark v1 with Checkov and Trivy run on `lab/terraform` (no cloud needed), Prowler after the cloud run. Show HN titled with the benchmark result; tl;dr sec and CloudSecList; comparison pages; 90-second GIF. Homebrew tap now, homebrew-core at 225 stars (STRAT §5.1). Ten design partners; first ADOPTERS entries.
**Q2 2027: depth buyers probe.** Effective IAM evaluator with corpus, `who-can`, right-sized policy PRs, Prowler path-library port, inbound adapters, Falco/GuardDuty ingest, Vanta export, evidence v2, governance/MTTR. fwd:cloudsec 2027 CFP; AWS Security Blog pitch on OCSF → Security Hub.
**Q3 2027: ecosystem and sustainability.** Helm in-cluster scans, Claude Code/Cursor skills, Cartography-label export so Prowler's queries run on nimbus, CNCF sandbox application once two maintainers from two orgs exist, services revenue from design partners (STRAT §6.3), Arsenal/Demo Labs submissions.

**Five bets.** (1) Plan-time path diff as the distribution engine; no vendor has it (MATRIX AP10). (2) The open benchmark re-run per release with Prowler/Checkov/Trivy on the same estate (TS4). (3) The finding contract as a public spec on OCSF, adapters as reference implementation: "OpenTelemetry for cloud findings" (STRAT §7.3). (4) Supply-chain trust as a marketed feature after Trivy 2026-03-19 and KICS 2026-04-22 (OS headline 3). (5) Agent-native distribution: free read-only MCP plus skills plus an agent-friendly repo, while Prowler's pricing page gates MCP and its README disagrees (MATRIX disagreements).

**Five cuts.** (1) cwm UI as primary surface; CLI printout plus static HTML first (STRAT §7.2). (2) Native check breadth; ingest Prowler (GAP §f). (3) Cost/ROI as positioning; one card (INV §11). (4) Team mode/SSO/RBAC/Postgres until adopters ask (GAP O60 ranks last). (5) Snapshot scanning, DSPM classification, JIT brokering (GAP §f); ingest labels instead.

## 4. First 10 engineering items (two weeks, parallel Opus tracks)

| # | Item | Lands in | Acceptance test |
|---|---|---|---|
| 1 | **One name, one org, before `v0.2.0`.** Binary = formula = image = repo. | `.goreleaser.yaml`, `install.sh`, `action.yml`, `Dockerfile`, README, SECURITY.md, `cmd/` | `grep -rn` for the retired name and the personal handle over user-facing files returns 0; `make release-snapshot` green; item 2 green under the new name |
| 2 | **Release rehearsal `v0.2.0-rc.1`**, Windows included. | `release.yml`, new `release-smoke.yml` | Fresh ubuntu/macos/windows runners: `install.sh --require-signature` (zip + `checksums.txt` on Windows) installs; `cosign verify-blob` and `gh attestation verify` pass; `version` prints the tag; Scorecard publishes ≥ 7 |
| 3 | **Action e2e on a fixture repo.** | `action-e2e.yml`, `testdata/action-fixture/` | Runs `action.yml` on every PR; a second commit edits the sticky comment (one comment, asserted via API); SARIF under the 25,000-result cap (STRAT §5.1); `fail-on` exit asserted both ways |
| 4 | **Fix verifier-2 D1 and D3** (module-blind tfstate mapping; stack overflow on nested brackets). | `internal/iac/iac.go`, `internal/cli/fix.go` | SESSION repros `scratchpad/verify-2/d/modrepro` and `so/deep.tf` become tests: module A patches module A's file; a 140 KB hostile `.tf` exits 1, never 2 |
| 5 | **OCSF 1.6 + ASFF writers, `convert`.** | `internal/output/{ocsf,asff}.go`, `internal/cli/convert.go` | Validates against the OCSF 1.6 Detection Finding schema in CI; `ingest` of our own OCSF reproduces identical fingerprints; Prowler OCSF golden → ASFF with no dropped required fields |
| 6 | **Finding contract as a published spec.** | `docs/spec/finding-contract.md`, `finding.schema.json`, `internal/model` | Every adapter golden validates against the schema in `go test`; `spec_version` field; spec documents `related`/`relations` exactly as BENCH's contract |
| 7 | **Prowler framework import.** | `internal/compliance/import/prowler.go` | All 105 JSONs load with attribution; integrity test fails on duplicate requirement ids or dangling refs (Prowler 5.42 pattern, OS §1); Go and Python counts equal per framework |
| 8 | **Governance files, DCO, scaffolds.** | `ADOPTERS.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, `ROADMAP.md`, `OPEN_SOURCE_PROMISE.md`, `AGENTS.md`, `dco.yml`, `make new-adapter` | DCO blocks an unsigned commit; `make new-adapter name=foo` generates adapter + passing golden test; PROMISE states the GitLab buyer-based rule and "DCO, no CLA" (STRAT §6.2–6.3) |
| 9 | **Benchmark job with Checkov and Trivy on `lab/terraform`.** | `lab/golden/{checkov,trivy}/<ver>/`, `make benchmark`, `benchmark.yml`, `docs/benchmark.md` | Pinned images run on the lab Terraform; both ingested and scored against `lab/ground_truth.yaml`; per-tool table written to BENCH and `benchmark.json` attached to the release; `cmd.txt` + `sha256.txt` per golden |
| 10 | **Read-only MCP server** (PLAN Phase 1 #5, pulled forward). | `internal/mcp/`, `internal/cli/mcp.go` | Tools `sql`, `paths`, `issue`, `explain`, `draft_fix` (diff only); the 14-payload corpus from `internal/query/security_test.go` is refused via MCP; scoped token hides write-shaped tools; scripted client lists the lab's 12 paths |

## 5. Biggest risk and de-risking

Not technical: the **single-maintainer, no-business, personal-handle pattern that killed ScoutSuite, CloudMapper and Magpie** (STRAT §2.3), compounded by a product that holds read credentials to other people's clouds. A buyer who checks the repo sees one person, no governance, no adopters, and remembers that Trivy's sponsor could recover from a compromise within days (OS §10).

De-risk, in order: (a) org ownership and governance files this week (item 8); (b) the open-source promise written before the first release so it never reads as a reaction; (c) two committers from two organisations by Q2 via "good first adapter / fix template / path rule" issues, crediting Prowler and Cartography upstream (STRAT §4i); (d) design partners on a services footing, services before paid features (STRAT §6.3), which also fills ADOPTERS.md; (e) CNCF sandbox in Q3 once (c) holds, accepting Cartography's 12-month precedent (STRAT §2.2); (f) an agent-executable repo so team size is not the ceiling.

## 6. Implementation plan

### 6.1 Scoring rule

"Best-in-class" is the concrete bar in MATRIX's best-in-class column, cited per row. **D** = differentiation if nimbus is best-in-class, 1–5 [inferred]: 5 no tool has it; 4 only paid/closed tools; 3 OSS parity exists but nimbus can lead; 2 parity needed, little upside; 1 ingest or skip. Effort uses GAP's scale (S ≤ 2 d, M ≤ 1 wk, L ≤ 3 wk, XL > 3 wk). Distribution, community and interop are capabilities with acceptance tests like any other.

### 6.2 Capability map (ranked by D within each group)

#### A. Attack paths, scoring, explainability

| ID | Capability | Best-in-class means | Today | Design | Eff | Deps | Acceptance | D |
|---|---|---|---|---|---|---|---|---|
| AP10 | Plan-time path diff | No vendor combines plan + live graph in a PR (MATRIX AP10) | `pr-comment` posts findings only | `internal/iac/planjson.go` ingests `terraform show -json`; `attackpath/diff.go` overlays and diffs path sets; `pr-comment --paths`; Action input `plan-json` | L | lifecycle | Lab PR adding 0.0.0.0/0 → "opens 1 path"; revert → "closes 1"; comment edited not duplicated; path ids stable | 5 |
| AP6 | Minimum fix set | No vendor computes min-cost cut (MATRIX AP6) | Greedy, re-verified (SESSION B) | Exact max-flow min-cut for small graphs in `attackpath/mincut.go`; greedy fallback flagged `approximate` | M | — | "breaks N" equals re-traversal delta; exact and greedy agree on the lab | 5 |
| AP2 | Published score, per-hop why | SCC formula; ASH per-hop permission; FortiCNAPP top-3 paths, "no data ≠ 0" (MATRIX AP2, CL) | `docs/scoring.md` v2.0.0 tested; `because` per hop (BENCH) | Keep; `explain --json` reproduces score within 0.01; version-bump banner (PL #8) | S | — | `doc_test.go` guards weights; every lab edge has `because`; banner names the delta | 4 |
| AP7 | Exposure accuracy | MDC wide/narrow + trusted IPs; XM dead ends (MATRIX AP7) | wide/narrow/trusted wired; F01 suppressed (BENCH) | Dead-end header + toggle; `reaches_crown_jewel` on every exposure | S | — | Header equals exposures with zero jewel paths | 4 |
| AP4 | User rules, preview, attributed library | Sysdig anchor + badges + auto-close; Prowler ~100 attributed ids (MATRIX AP4) | 11 chains | `rules/risks/*.yaml` (anchor, id, attribution); `risk test` dry-run; Prowler id port in Phase 2 | M→L | lifecycle | `risk test` leaves DB hash unchanged; every rule has id, attribution, true-positive and near-miss fixture | 4 |
| AP9 | Validated exploitability | S1 Exploit Evidence; ASH network scanning (MATRIX AP9) | none | `internal/verify/probes.go`, opt-in `--consent --allow`, read-only probes, evidence on the Issue | L | ID1 | No probe without allowlist; lab bucket gets anonymous-list evidence; NACL-deny case "not reachable" | 4 |
| AP1 | Engine AND/OR semantics | SCC AND/OR (MATRIX AP1) | 6-hop DFS, typed, toxic floor | Implement OR-nodes or drop the claim (PLAN B) | M | — | Strict ground truth green; README matches | 3 |

#### B. Remediation and verified closure

| ID | Capability | Best-in-class means | Today | Design | Eff | Deps | Acceptance | D |
|---|---|---|---|---|---|---|---|---|
| RM4 | Verified fix | XM confirmation; Prowler 5.44 partial scans (MATRIX RM4) | none | `verify <issue>`: targeted re-collect of one resource and edges, re-traverse, `verified-fixed` only if the path is gone; ticket close/reopen | M | lifecycle | Lab fix verified < 60 s on the fake; failing recheck reopens with evidence | 4 |
| RM3 | Root-cause plans | ASH "resolves N / reduces M", phases, rollback (PL #1); Upwind hotspots (CL #4) | `plan.go` exists, unverified | Group by the one change; phases prerequisite→snapshot→fix→verify; N from re-traversal | L | AP6 | N equals delta on the lab; one PR per plan | 4 |
| RM2 | IaC patch + PR | Prisma suggestion; Datadog TF PR (MATRIX RM2) | D1 module bug, D3 overflow | Full-address `byAddr`; nesting cap; PR footer `nimbus-closes-paths: N` for the north star | M | — | D1/D3 tests; `terraform validate` in patch test; footer in every PR | 4 |
| RM1 | Structured fix content | CrowdStrike permissions/validation/compensating; Qualys verify (MATRIX RM1) | 42 templates, schema in progress | Fields: actions-required, validation query, mitigation, effort, confidence, rollback | M | — | Schema test; validation query passes after fix; no `-auto-approve` anywhere | 3 |
| RM6 | Preventive guardrails | Kubescape CEL VAP (MATRIX RM6) | Rego stub | `prevent --format vap|scp` from the same rules | M | AP4 | VAP admits lab-good, rejects lab-bad in kind | 2 |
| RM5 | Simulate/approve automation | Wiz gating; C7N dry-run; Flowpipe `input` (MATRIX RM5) | none | Design only; not in 12 months | XL | RM4 | — | 2 |

#### C. Identity / CIEM

| ID | Capability | Best-in-class means | Today | Design | Eff | Deps | Acceptance | D |
|---|---|---|---|---|---|---|---|---|
| ID1 | Effective-permission evaluator | ASH Impact: identity + resource policies + SCP/RCP, per-hop (MATRIX ID1) | Ignores NotAction, Deny, conditions (INV §1) | New `internal/iam`, ≥ 200-case corpus; reads `get-account-authorization-details` (OS interop) | XL | — | Corpus 100%; lab S01 closes; sampled agreement with `SimulatePrincipalPolicy` in e2e | 4 |
| ID3 | Who can reach X | Fix Inventory weighted edges; Datadog Access Insights (MATRIX ID3) | ignores Deny | `who-can` over `can_perform{actions}` edges, direct + transitive with statement | M | ID1 | Lab `who-can write s3://pii` matches labels; PMapper fixture parity | 4 |
| ID4 | Right-sized policy PR, lint, taxonomy | Cortex Adjust Policy; Datadog TF PR; Parliament; Cloudsplaining (MATRIX ID4, OS #7–8) | none | CloudTrail + last-accessed; `iam/rightsize.go`; narrowing-only PR; 5-category badges; lint in PRs | L | ID1, RM2 | Plan shows only narrowing; lint flags `s3:GetObject` without `/*` | 4 |
| ID2 | Privilege-escalation paths | Prowler ~70 pathfinding.cloud queries (MATRIX ID2) | none | Port with ids + attribution; `can_escalate_to` edges | L | ID1 | Seeded PassRole found; ids match Prowler's | 3 |
| ID5 | Azure RBAC, GCP IAM | Tenable cross-cloud (MATRIX ID5) | absent | Collect into `internal/iam` | L | ID1 | P09/P11 fire from collected bindings, not hints | 3 |
| ID7 | Org guardrails, zombies | Sonrai (MATRIX ID7) | absent | SCP/RCP IaC PR with size budget; reversible quarantine; no broker (GAP §f) | L | ID4 | SCP within budget; quarantine reversible | 2 |
| ID6 | K8s RBAC | Kubescape 290 controls (MATRIX ID6) | 7 checks | Ingest Kubescape/kube-bench JSON | M | EI | Goldens ingest | 2 |

#### D. Inventory, graph, lifecycle, data

| ID | Capability | Best-in-class means | Today | Design | Eff | Deps | Acceptance | D |
|---|---|---|---|---|---|---|---|---|
| RP5 | Issues + lifecycle | Wiz Issues; Cartography stable identity (MATRIX RP5, OS #3) | Landed; scope gap (SESSION verifier-2 #3) | Scopes from the scan plan, not observed findings; backfill on migration | S | — | Deleting a scope's last resource resolves it; `ingest []` valid | 3 |
| RP2 | EPSS/KEV | Cortex CVRS; Cartography data (MATRIX RP2) | `internal/intel` snapshot | Daily cached feeds, offline fallback; unexploited CVEs excluded with a note | S | — | KEV raises score; feed absent → `not scored` | 3 |
| IG7 | History, diff, source data | Fix Inventory hourly diff; Rapid7 raw JSON (MATRIX IG7) | none | Config table per scan; `diff`; raw provider JSON with call + timestamp | L | RP5 | Making the lab bucket public shows a diff and the event | 3 |
| IG8 | Coverage honesty, rollback | FortiCNAPP reasons + rollback (MATRIX IG8) | Landed; rollback lacks account check (verifier-2 #4) | STS account must equal manifest; name/tag allowlist | S | — | Cross-account replay refused before any API call | 3 |
| IG9 | AI assets as nodes | SCC agents in paths; ASH AI inventory (MATRIX IG9) | absent | Node types for agents, endpoints, MCP servers; "agent role can modify IAM" | L | ID1 | Lab agent with admin produces an Issue | 3 |
| IG5 | SQL + cross-cloud kinds | Steampipe tables; Fix Inventory base kinds (MATRIX IG5) | hardened read-only path | `nimbus.database/bucket/identity` views | M | — | One query returns RDS + Cloud SQL + Azure SQL | 2 |
| DS2 | DSPM label ingest | Proofpoint↔Wiz; Sysdig data in paths (MATRIX DS2–3) | name heuristics | Macie/Purview/DLP/Cyera/Sentra adapters → sourced `data_sensitivity`; heuristics marked `inferred` | M | — | Label marks lab bucket sensitive; score rises | 2 |
| IG1 | Collection breadth | Prowler 23 providers (MATRIX IG1) | 48 checks | Do not chase; ingest Prowler | — | — | Benchmark: nimbus+Prowler recall ≥ nimbus alone | 1 |

#### E. Trust and supply chain

| ID | Capability | Best-in-class means | Today | Design | Eff | Deps | Acceptance | D |
|---|---|---|---|---|---|---|---|---|
| TS4 | Public benchmark | Nobody publishes path ground truth (MATRIX TS4) | Local lab, 12 paths (BENCH) | Item 9; cloud lab on credentials; per-release re-run; `benchmark.json` asset | M→L | creds | CI publishes table; strict gate for release; Prowler golden after first cloud run | 5 |
| TS1/2 | Signed, attested, immutable, pinned | c7n-left cosign; Trivy GHSA-69fq lessons (MATRIX TS1–2) | Configured, never run on a tag | Items 1–2; Scorecard badge; `security.txt` when a domain exists | S | — | Three-OS rehearsal; Scorecard ≥ 7 now, ≥ 8 by Q2 | 4 |
| TS3 | Least-privilege onboarding | MDC scoped roles; Prowler External ID (MATRIX TS3) | AST-derived policies (`docs/iam/README.md`) | Publish as trust artefact | S | — | `TestReadOnlyPolicies` green; embedded copy equals docs | 3 |

#### F. Distribution and packaging

| ID | Capability | Best-in-class means | Today | Design | Eff | Deps | Acceptance | D |
|---|---|---|---|---|---|---|---|---|
| IC4 | Action with SARIF, gating, baseline | trivy-action 55,417 repos, checkov-action 7,654 (STRAT §5.1); Powerpipe `--where` (OS #12) | Rewritten, untested e2e | Item 3; `--baseline`; `--where`; Marketplace listing | M | item 2 | e2e green; same findings twice → 0, one new HIGH → 1 | 4 |
| PF5 | Packaging ubiquity | Trivy everywhere (MATRIX PF5); homebrew-core 75/225-star gates (STRAT §5.1) | archives, cask, GHCR | Docker Hub mirror, `.deb/.rpm`, scoop/winget, signed Helm CronJob chart, PyPI extra; homebrew-core at 225 stars | M | item 1 | `release-snapshot` emits all; `helm lint/template` pass; Windows runs the zip; clean-venv pip install | 3 |
| IC5 | Pre-commit, IDE, agent hand-off | FortiCNAPP changed-files; Datadog hand-off (MATRIX IC5); Prowler `.claude-plugin` (OS §1) | hook exists; unsafe VS Code setting (INV #16) | `hook --changed-only`; workspace-trust gating; `skills/` calling MCP; "copy prompt" | S–M | item 10 | Hook scans only changed files; extension refuses untrusted `binaryPath`; skill lists lab paths | 3 |
| NS | North-star measurement | STRAT §7.4 PR signature; zero telemetry | none | PR footer (RM2); `docs/metrics.md` with the search query | S | RM2 | Footer asserted | 3 |

#### G. Interop

| ID | Capability | Best-in-class means | Today | Design | Eff | Deps | Acceptance | D |
|---|---|---|---|---|---|---|---|---|
| IW3 | Cross-scanner graph | No OSS tool (MATRIX IW3); nimbus's most distinctive asset (GAP §a) | 6 adapters; runner 0% (INV §2) | Item 6 spec; runner tests; `make new-adapter` | M | — | Goldens validate; runner keeps output despite stderr "error" | 5 |
| EI1 | Cartography import/export | Prowler runs paths on Cartography (OS headline 2) | export-only labels | Import a Cartography graph; export labels so Prowler's queries run | L | — | Sample Prowler queries return equal rows on nimbus's export | 4 |
| IW4 | Outbound formats | KICS 11 formats; Prowler OCSF; Trivy `convert` (MATRIX IW4) | SARIF only | Item 5 + GitLab SAST, JUnit, Powerpipe control shape | M | — | Schema validation per format | 3 |
| EI2 | Prowler content reuse | 105 frameworks, ~100 queries, OCSF history (OS interop) | OCSF/v3 adapter | Items 7, ID2; `--source prowler-history` | M | — | Integrity test; history round-trip | 3 |
| CO6 | GRC export | Vanta full-state PUT (MATRIX CO6) | none | `export vanta`; explicit "omitted = deleted" handling | M | RP5 | Mock PUT; deletion-semantics test | 3 |
| DR4 | Runtime-to-posture | SCC Correlated Threats; GuardDuty sequences (MATRIX DR4) | none | Falco/GuardDuty/Defender alerts as node evidence; stable-id combo Issues | L | AP4 | VM + KEV + brute-force fixture → one Issue | 3 |
| EI3/4 | Steampipe, Custodian, warehouse | Table names; Custodian YAML; Parquet (OS interop) | passthrough | Compatibility views; Custodian filters → detections; Parquet export | L | IG5 | Saved Steampipe SQL runs unchanged; Custodian fixture → Issues | 2 |

#### H. Compliance, reporting, AI, platform

| ID | Capability | Best-in-class means | Today | Design | Eff | Deps | Acceptance | D |
|---|---|---|---|---|---|---|---|---|
| AI3/2/4 | MCP, BYO-LLM, guardrails | Sysdig token-filtered MCP; Lighthouse incl. Ollama; Cortex AgentiX (MATRIX AI2–4) | Anthropic-only | Item 10; provider abstraction in `python/nimbus/ai/llm.py`; allowlisted tools, `agent_audit`, timeouts | M | — | Eval suite on two providers; tag injection cannot trigger tools | 3 |
| CO4/5 | Evidence, period coverage | Audit Manager layout, closed 2026-04-30; Vanta hourly (MATRIX CO4–5) | unsigned ZIP | Signed manifest; by-control/source/date; "effective X of Y days"; manual controls never auto-pass | L | IG7 | Signature verifies; days equal stored scans | 3 |
| CO1/2 | Breadth and integrity | Orca 185+; Prowler integrity + universal frameworks (MATRIX CO1–2) | 11 with errors (INV §8) | Item 7; "7 of 212" denominators (OS #3) | M | — | Integrity CI; ratios equal hand counts | 2 |
| UX2/3 | Trends, MTTR, exec PDF | JupiterOne trends; MDC PDF (MATRIX UX2–3) | none | Daily snapshots → sparklines; one-page PDF "computed at" | M | IG7 | PDF snapshot test; MTTR equals lifecycle stamps | 2 |
| RP8 | Governance, SLA | MDC rules (MATRIX RP8) | dead `owner` | `governance:` YAML; owner from tag/CODEOWNERS; digest | M | RP5 | Overdue list correct | 2 |
| AI1 | NL that shows its logic, offline | Upwind editable queries; FortiCNAPP identifier-paste (MATRIX AI1) | regex intents | ARN/CVE/CIDR paste → canned query; always show SQL | S | — | Lab ARN opens the resource without an LLM | 2 |
| PF3 | Validated config | Orca provider (MATRIX PF3) | unvalidated | Strict schema; `*_env` resolvers; literal secrets refused | M | — | Literal token fails to load with env-var pointer | 2 |
| PF4 | RBAC/SSO/tenants | Wiz Tenant Manager (MATRIX PF4) | absent | Not in 12 months; future paid tier per PROMISE | XL | — | — | 1 |
| DR3/VS2/DS1 | Runtime, snapshots, classification | Sysdig, Orca, Cortex | absent | Not doing (GAP §f); ingest | — | — | — | 0 |

### 6.3 Phases, tracks, exit criteria, claims

**Phase 0 — Trust, truth, name (now → `v0.2.0`, ~3 weeks).** Parallel tracks on disjoint packages: **A2** hardening re-probe + verifier-2 defects 1–6 (`internal/iac`, `offboard.go`, `remediation`); **E2** release rehearsal + naming (items 1–2); **H2** benchmark CI (item 9); **COMM-1** governance, DCO, scaffolds, `AGENTS.md` (item 8); **DIST-1** Action e2e (item 3); **INT-1** OCSF/ASFF/`convert` + spec (items 5–6); **CONTENT-1** Prowler frameworks (item 7); **MCP-1** (item 10). Exit: `make verify` green; strict ground truth fails only on labelled gaps; `v0.2.0` installed on three OSes with signature verification; README matches behaviour; governance files merged; one name everywhere. **Claim:** "the only open-source CSPM whose every release is signed, attested, immutable and benchmarked against published path-level ground truth."

**Phase 1 — The wedge loop in the PR (Q1 2027, ~8 weeks).** **W1** plan-time diff (AP10); **W2** verified fix (RM4); **W3** plans + exact min-cut (RM3, AP6); **W4** EPSS/KEV, dead ends, banner (RP2, AP7, AP2); **W5** user rules (AP4); **DIST-2** packaging matrix + hook/skills (PF5, IC5); **LAUNCH-1** comparison pages, `make demo` GIF reproducible from the lab, Show HN, newsletters, first ADOPTERS. Exit: the 90-second demo runs on the lab with zero egress except cloud APIs and the chosen LLM; Action dependents tracked; benchmark v1 with Checkov and Trivy columns; ten design partners (STRAT §7.4 makes companies, not stars, the gate). **Claim:** "the only tool, open or closed, that tells a pull request how many attack paths it opens or closes, then proves the fix closed them."

**Phase 2 — Depth buyers probe (Q2 2027, ~10 weeks).** **I1** `internal/iam` + corpus (ID1); **I2** `who-can`, right-sizing, lint (ID3–4); **I3** Prowler path port, Azure/GCP IAM (ID2, ID5); **D1** history/diff/source pane (IG7); **C1** evidence v2, governance, trends, PDF (CO4, RP8, UX2–3); **INT-2** inbound adapters, Falco/GuardDuty evidence, Vanta (EI, DR4, CO6); **LAUNCH-2** fwd:cloudsec CFP, AWS Security Blog pitch, Prowler golden after the first cloud run. Exit: corpus 100%; S01 and P12 closed; first live benchmark published; OCSF accepted by Security Hub in e2e; one GRC tool receiving nimbus data at a design partner. **Claim:** "the only open-source tool with a published effective-permission evaluator benchmarked against the cloud's own simulator."

**Phase 3 — Ecosystem and sustainability (Q3 2027, ~8 weeks).** **ECO-1** Cartography import/export (EI1); **ECO-2** Steampipe views, Custodian, Parquet (EI3–4); **ECO-3** Helm scheduled scans, Trivy Operator CRDs; **AI-2** AI assets (IG9), VAP export (RM6); **GOV-1** second and third maintainers from other orgs, CNCF sandbox filed, services offering published. Exit: two maintainers from two organisations in MAINTAINERS.md; sandbox application filed; ≥ 25 named adopters; homebrew-core accepted. **Claim:** "the neutral graph that Prowler, Checkov, Trivy, Cartography and Steampipe users adopt without switching anything."

### 6.4 Lines I would not let the plan cross

No launch before the first live run, lab or not (STRAT §7.5 risk 1). Paths, fixes, adapters and MCP never move behind a paid tier; write it into OPEN_SOURCE_PROMISE now (STRAT §6.2 principle 3). DCO, no CLA. No check added because Prowler has it. No KubeCon EU 2027 talk (CFP closes in two days) with nothing live: "don't present vapor" (STRAT §5.2 step 12).
