# nimbus implementation plan v2 — "Fix the path, not the finding"

_Written 2026-10-09 by the planning session after the competitive research sweep. Supersedes `IMPLEMENTATION_PLAN.md` (v0.2→v1.0, 2026-10-08), whose Phase 1 survives here as Phase 0. Inputs: `docs/research/strategy-how-to-win.md`, `docs/research/nimbus-gap-analysis.md` (67 scored opportunities, phase draft), `docs/research/competitive-feature-matrix.md` (91 capabilities × vendors), `docs/research/competitors/*.md` (66 vendors/projects, sourced), `docs/research/nimbus-capability-inventory.md` (what actually works, top-20 defects). Execution evidence lives in `docs/sessions/`._

## 1. Positioning (decided)

**nimbus is the open, local-first security graph.** It ingests the findings teams already have (Prowler, Checkov, Trivy, Steampipe, its own collectors), reduces them to the few attack paths that reach crown jewels, and opens the pull request that closes them. Published scoring, no SaaS, bring-your-own model, signed releases.

Three wedges, in order of investment:
1. **Paths from everything** — one graph over every scanner's output; free, explainable, cross-cloud attack paths with a cheapest fix set. Prowler/Checkov are content suppliers, not rivals on check count.
2. **Fix the path, in the PR** — plan-time path diff in PR comments, deterministic IaC fixes, verified closure. This is the distribution engine (Checkov's 3.9M monthly downloads vs Prowler's 104k shows placement beats stars).
3. **Local-first and verifiable** — offline, BYO-LLM, read-only roles, signed + provenance-attested immutable releases (the Trivy/KICS 2026 compromises make this a buying criterion).

Supporting: compliance evidence (AWS Audit Manager closed to new customers 2026-04-30; Vanta's resource API is a channel), SQL/plain-English via a read-only MCP server, cost+security. **Not doing** (see gap analysis §f): host agents, runtime EDR, JIT brokering, hosted SaaS, snapshot workload scanning, exploits against production, auto-merge remediation, check-count races, Cyera-grade classification, GRC workflows, SAST/SCA, team/MSP mode near-term.

North-star metric: attack paths closed through merged nimbus PRs per week. Near-term target: 100 named adopter organisations before 10k stars.

## 2. Principles (unchanged, enforced)
Nothing ships unverified (executable evidence per item); one implementation per number (Go scores, Python consumes); precision over volume; secure by default; agentless/open/reproducible; research before feature; failing test first; implemented ≠ deployed ≠ verified; Opus agents execute tracks, the planning session reviews and integrates; no push/merge/release without Bobby.

## 3. Phase 0 — Trust & truth (now → first signed release)

**Why first:** three network-reachable critical flaws, service-account paths that never fire, a patcher that edits the wrong resource, findings that never resolve, and zero live-cloud runs. A security product with these is dead on arrival; every demo would lie.

**Exit criteria:** (a) all inventory top-20 defects closed with tests and re-probed by an independent verifier; (b) `make verify` (vet, tests, pytest, ui-smoke, govulncheck, gosec high, local ground-truth suite) green; (c) `v0.2.0` built by goreleaser with cosign signatures, SBOM, SLSA provenance, non-root image, SHA-pinned Action, install.sh that verifies; (d) README claims match verified behaviour; (e) local ground-truth lab passes: every labelled path found with score ≥ 7, zero unlabelled paths ≥ 7, seeded false positive not reported; (f) cloud lab code merged and gated by `NIMBUS_E2E=1` (live run blocked until credentials exist — recorded as unverified).

### Tracks (disjoint packages; run in parallel)
| Track | Scope | Packages | Inventory defects / opportunities |
|---|---|---|---|
| **A** Security hardening (running) | read-only SQL enforcement (Go+Python), view-identifier injection, Python alerts SSRF, server bind/auth/Host/CSRF/timeouts/body limits, auto-PR path traversal + wrong file, secret leaks, Python auto-exec from CWD, x/net CVEs, scan-scope gates | internal/query, internal/store (query path), internal/server, internal/cli (serve/fix/root/scan), internal/gitops, python/nimbus/server.py, store.py | 1, 2, 3, 4, 5, 8, 11, 12, 14 |
| **B** Attack-path correctness + "why" | service-account class fix so K8s/GCP SA paths fire; fix attribution to the right node; stop counting partial paths; real AND/OR semantics or remove the claim; per-hop `because` on every edge; dead-end classification (`reaches_crown_jewel`); choke-point drill-in (paths through node, "closes N" by re-traversal); exact min-cut on small graphs with greedy fallback flagged | internal/graph, internal/attackpath, internal/model (edge attrs) | 9, 18; O4, O11, O9, O7 (plan math) |
| **C** Collector truth + exposure width | AWS NotAction, account-level S3 BPA, Azure NSG AND-of-NIC-and-subnet, GCP firewall deny+priority and project IAM collection, M365 CA exclusions, Okta sign-on; exposure labelled wide/narrow/trusted via `trusted_cidrs`; `crown_jewels` config block into the Config struct; per-account timeouts; GitHub rate-limit surfaced as coverage error not silent skip | internal/collector/*, internal/config | 15, 20 (collector part); O10, O62 (config) |
| **D** Remediation truth | patcher targets the right block (resource type+name match, not first match); fixes declare the variables they reference; destructive templates rewritten to least-change fixes; never emit `-auto-approve`; HCL scanner no longer panics on unary expressions; template metadata schema (actions-required, validation query, mitigation, effort, confidence, rollback) with a schema test | internal/iac, internal/remediation | 6, 7, 17; O26 |
| **E** Release trust kit | goreleaser (linux/darwin/windows × amd64/arm64), cosign keyless signing, syft SBOM, SLSA provenance workflow, immutable releases, Docker non-root + digest pinning, `install.sh` verifies checksum+signature and refuses `main`, `action.yml` pins by SHA and downloads a verified release, SECURITY.md/CONTRIBUTING/CODE_OF_CONDUCT/CHANGELOG/CODEOWNERS/Dependabot, OpenSSF Scorecard workflow, version from ldflags | .goreleaser.yaml, .github/workflows/*, install.sh, action.yml, Dockerfile, root docs, cmd/cloud-posture (version) | 13; O2 |
| **F** One score, published | single Go risk implementation with `score_version`; Python consumes Go output; `docs/scoring.md` with the formula, bands, multipliers, changelog; golden calibration set; `explain` output (factors, top 3 paths, "not scored" when inputs missing); EPSS/KEV daily feeds with offline cache; crown-jewel levels from config | internal/risk, new internal/intel, python/nimbus/risk.py, docs/scoring.md | O6, O5, O21, O62 (consumer) |
| **G** Lifecycle + coverage honesty (after A) | versioned migrations; findings `state` (open/resolved/reopened) with `resolved_at`; Issue object (one per canonical_id × resource, findings as evidence, toxic-combination Issues); Trivy fingerprint includes package; `scan --diff`; coverage table recording denied/skipped API calls per account with reasons; `onboard` manifest + `offboard --rollback`; generated read-only IAM policy | internal/store, internal/model, internal/cli (scan/onboard), internal/collector/core (denial recording) | 19, 20 (rest); O3, O46 |
| **H** Local ground-truth lab | `lab/local/estate.yaml` → synthetic multi-cloud estate generator producing native findings + graph for every seeded weakness (public S3 w/ PII, IMDSv1 EC2 behind 0.0.0.0/0 with admin profile, public RDS, cross-account trust, no-MFA user + stale key, Lambda URL, EKS public endpoint + cluster-admin SA, K8s SA chain, GCP SA chain, Azure public blob + open RDP, GitHub repo w/o protection, one seeded false positive behind trusted CIDR, one path behind an SCP deny); `lab/ground_truth.yaml` labelling expected paths + scores; `tests/groundtruth` Go test asserting precision/recall; `lab/terraform/` real-cloud equivalent gated by `NIMBUS_E2E=1`; `docs/benchmark.md` | lab/, tests/, docs/benchmark.md | O1 |
| **I** Dashboard follow-through | re-layout on resize; Issues instead of findings in counts; per-hop "why" and explain factors in the detail pane; dead-end toggle; choke-point drill-in; coverage panel from the coverage table | internal/dashboard (after B/F/G land) | UI nits |

Independent verification after each track: an Opus reviewer re-runs the inventory's original probes and the track's tests, and tries to break the fix; findings go back to the track before it is accepted.

## 4. Phase 1 — The wedge loop
**Exit:** the 90-second demo runs on the local lab, then on the cloud lab: ingest → 5 paths with "why" → `plan` → PR with path diff comment → merge → `verify` → paths 5→2, verified; zero network egress except cloud APIs and the chosen LLM.

| # | Item | Lands in | Acceptance |
|---|---|---|---|
| 1 | **Verified fix** `cloud-posture verify <issue>`: targeted re-collect of one resource (<60 s), re-traverse, mark `verified-fixed` only if path count drops; ticket close/reopen (GitHub, Jira) | internal/cli, internal/collector/core (targeted), internal/integrations, internal/store | lab fix → verified; failing recheck reopens with evidence |
| 2 | **Plan-time path diff** in PR comments: ingest `terraform show -json`, overlay on live graph, diff paths; sticky comment "opens N / closes M paths to <crown jewel>", edited not duplicated; Action wiring | internal/iac, internal/attackpath, internal/cli/pr-comment, action.yml | lab PR opening 0.0.0.0/0 → "opens 1 path"; revert → "closes 1" |
| 3 | **User-authored combination rules** `rules/risks/*.yaml` with anchor resource, auto-close, New/Live badges; `risk test` dry-run | internal/attackpath | rule → Issues; preview writes nothing; every shipped rule has id + attribution |
| 4 | **Root-cause plans** `cloud-posture plan`: group fixes by the one change (SG, policy, module, base image); "resolves N / reduces M" from in-graph re-traversal; phases prerequisite→snapshot→fix→verify with rollback; sortable | new internal/remediate/plan.go, internal/cli | resolves N equals re-traversal delta on lab |
| 5 | **Read-only MCP server** `cloud-posture mcp`: tools `sql` (hardened path), `paths`, `issue`, `explain`, `draft_fix` (returns diff, never applies), `who_can` (later); token-scoped tool list | new internal/mcp, internal/cli | injection corpus refused; Claude Desktop smoke lists lab paths |
| 6 | **Offline collect/evaluate** `collect` → snapshot, `evaluate` → findings; air-gapped equality test; single-file report escapes everything | internal/cli, internal/store (snapshot export) | identical results online vs offline; XSS corpus escaped |
| 7 | **Copilot guardrails + BYO-LLM**: allowlisted read-only tools, approvals for writes, per-turn cost cap, audit table, timeouts; provider abstraction (Anthropic, OpenAI-compatible local, Bedrock); recorded eval suite | python/nimbus/ai, python/nimbus/store.py, internal/server proxy | injection in tags cannot trigger tools; eval passes on two providers |
| 8 | **Exposure width + compensating controls (v1)**: WAF/private endpoint/NetworkPolicy/SCP-deny nodes lower scores with a visible chip | internal/graph, internal/risk | lab path behind WAF scores lower; removing it raises |
| 9 | **Governance rules**: owner from tag/CODEOWNERS, due dates by severity, grace, weekly digest, MTTR/SLA tiles | internal/integrations, internal/config | overdue list correct; digest to test sink |
| 10 | **Dashboard**: Issues, plans, verify button (live mode), path diff view, MTTR/SLA, coverage honesty — all in the cwm look | internal/dashboard | ui-smoke extended |

## 5. Phase 2 — Depth
Effective IAM evaluator (`internal/iam`, ≥200-case corpus incl. Deny/NotAction/conditions/SCP/RCP/boundaries/resource policies; cross-checked with `iam:SimulatePrincipalPolicy` in e2e) → `who-can` → right-sized policy PRs from CloudTrail/service-last-accessed → org-guardrail (SCP/RCP) generator with size budget + reversible zombie quarantine → Prowler AWS path library port with attribution + privilege-escalation edges → opt-in read-only exposure probes with evidence → validated secrets (opt-in, never stored) → risk timeline (event + commit that created the Issue) → DSPM label ingest (Macie, Purview, DLP, Cyera/Sentra fixtures) → evidence bundle v2 (signed manifest, period coverage, no manual-control passes) → compliance integrity CI + progress ratios → code-to-cloud coverage % + drift Issues with import blocks → executive PDF.

## 6. Phase 3 — Ecosystem & distribution
Vanta/Drata export (full-state semantics), inbound adapters (Cartography Neo4j, Prowler history, Trivy Operator, Kubescape, kube-bench, Custodian), outbound formats (OCSF 1.6 validated, ASFF, GitLab SAST, JUnit, `convert`), Claude Code/Cursor skills + changed-files pre-commit, Homebrew tap, Docker/Helm, Action marketplace listing, CNCF sandbox application (Apache-2.0 eligible), public benchmark page re-run per release, ADOPTERS.md, talk CFPs (KubeCon EU 2027 CFP closes 2026-10-11).

## 7. Risks and mitigations
| Risk | Mitigation |
|---|---|
| No live-cloud run yet | Local ground-truth lab now; cloud lab code ready; first live run is the top item once Bobby provides lab credentials (recorded as a blocker, not hidden) |
| Prowler absorbs the wedges | Speed on plan-time path diff + verified fix (nobody has both); interop with Prowler output so its users can adopt without switching |
| Wrong IAM/path results | Corpus-driven evaluator, benchmark precision/recall published, per-hop evidence |
| Bad auto-PRs | Never auto-merge; plans show rollback; verify step; structured template metadata |
| Supply-chain compromise | Track E; all-at-once credential rotation policy in SECURITY.md |
| Scope sprawl | This document is the gate; items below rank 40 are deferred until benchmark + adopter evidence |
| Two languages, install friction | Single Go binary does everything in the wedge loop; Python optional for reports/AI |

## 8. Execution log
See `docs/sessions/2026-10-09-cwm-ui.md` (this session) and subsequent `docs/sessions/*.md`. Status table maintained in `.planning/STATE.md`.
