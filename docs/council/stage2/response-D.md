# Council stage 1 — the CNAPP product council member

_council member: I built the security graph, the Issue/toxic-combination model, CIEM and remediation workflows at a market-leading CNAPP. I judge by data model, correctness, scalability and the depth leaders actually ship. Written 2026-10-09 against the tree as verified in `docs/sessions/2026-10-09-cwm-ui.md` ("Phase 0 gate", "Verification 2") and `docs/benchmark.md` (recall 12/12, recall@7 10/12, precision 95.2%). Every competitive claim cites the research by path; no market number here is new._

## 1. Verdict on IMPLEMENTATION_PLAN_v2

**What it gets right.** The positioning ("the open, local-first security graph … the PR that closes them", `.planning/IMPLEMENTATION_PLAN_v2.md` §1) matches what the research says incumbents structurally cannot copy: published math, cross-scanner ingestion, local-first (`docs/research/strategy-how-to-win.md` §4 scorecard, §7.3). Phase 0 "trust & truth" before features is correct and has mostly landed with executable evidence. Track B's per-hop `because`, prefix de-duplication, re-traversal-verified fixes and exact-when-small min-fix set are how a serious path engine should be built (`internal/attackpath/traversal.go`, `fix.go`). Track F's single multiplicative score with `not scored` factors and a drift test against `docs/scoring.md` beats the explainability the matrix credits to FortiCNAPP (`docs/research/competitive-feature-matrix.md` RP1). Track G's Issue table keyed `(kind, canonical_id, resource_id)` with multi-source confidence is the right primitive (`internal/store/issues.go`).

**What it gets wrong, from the data-model seat.**

1. **The graph is still finding-derived, not inventory-derived.** `graph.AttachFindings` creates nodes from findings and classifies them by substring (`internal/graph/graph.go` `ClassFor`, `GuessType`, `looksSensitive`). Leaders build the graph from inventory first and attach findings second (Wiz Security Graph, IG4 in the matrix). Substring classification is how defect 9 happened and will happen again on the first live estate with types nobody anticipated. Plan v2 never names this.
2. **Permission edges carry no semantics.** `has_policy` and `grants_access_to` say that an edge exists, not which actions, effect, resources or conditions (`graph.go` edge kinds; `traversal.go evaluate` uses only weakness flags). Every Phase 2 item (who-can, right-sizing, SCP generator, privesc edges) needs action sets on edges. Plan v2 schedules the evaluator in Phase 2 but puts nothing in Phase 0/1 to make edges carry statements, so Phase 1 features (plan-time diff, verify) will be built on edges that must then be redefined.
3. **Attack paths are not Issues.** Issues exist only for `single` and `combination` kinds; traversal paths live in `attack_paths`, replaced wholesale per scan (`store.ReplaceAttackPaths`), with IDs hashed over the full hop list. That is the "tickets appear and disappear in hundreds" failure mode the research quotes against Wiz (`strategy-how-to-win.md` §1.3). A path whose plumbing hop changes gets a new ID; nothing is `resolved`, `reopened` or `verified_fixed` at path level. Verified fix (Phase 1 item 1) has no object to verify.
4. **Scale is not designed.** The DFS caps at 20,000 frames and 25 branches per node and truncates silently (`traversal.go traverse`); `analyzeFixes` clones and re-traverses the graph once per choke point; `g.Edges()` sorts every edge on each call. AWSHound processed ~160k nodes and 10.5M edges in 15 minutes (`strategy-how-to-win.md` §3.1C); a 50-account estate will be in that range. Plan v2 lists "traversal caps … silent truncation" in the matrix (PF6) and never schedules it.
5. **Two engines for one concept.** `rules.yaml` chains joined by `same_account` with justifications (`internal/attackpath/rules.yaml`) and graph traversal are both called attack paths and merged by score. The benchmark shows what removed the noise was requiring real links (`docs/benchmark.md` "What removed the noise"). Rule chains should become anchored graph queries (Sysdig-style, AP4), not a parallel engine.
6. **No history.** No per-resource configuration versions, so no timeline, no trend, no MTTR, no "what changed" (IG7 absent). Plan v2 defers this to Phase 2 "risk timeline" but Phase 1 governance/MTTR tiles depend on it.
7. **Python duplication.** Prowler-style boto3 checks, a drifted catalog copy and `ensure_views` that reverts Go's lifecycle views (Verification 2 defect 7). "Go scores, Python consumes" must extend to views, catalog and checks.

The phase order (truth → wedge loop → depth → ecosystem) survives. What changes is that the **model** work (typed inventory graph, permission edges, path Issues, history, scale) moves into the next six weeks, because every wedge feature is cheap to build once on it and expensive to rebuild.

## 2. What is still missing for "complete package" in a 2026 RFP

Against the rfp.wiki and Gartner criteria synthesised in `docs/research/competitors/compliance-and-adjacent.md` ("Analyst/RFP checklist") and the table-stakes ranking in `docs/research/nimbus-gap-analysis.md` §b, a buyer shortlisting nimbus today would score it red on:

- **Identity posture / CIEM** (checklist row 6; matrix ID1–ID5 all partial/absent): no effective-permission evaluation (`IsAdmin` fails 8 of 14 adversarial cases per Verification 2), no Azure RBAC or GCP IAM bindings, no usage-based right-sizing, no privilege-escalation edges. Datadog's data says identity, not public buckets, is where the problems now are (`strategy-how-to-win.md` §3.1A: 59% of IAM users with keys >1 year, 19.4% over-privileged EC2).
- **Finding/Issue lifecycle at path level and verified remediation** (RM4 absent, RP5 partial): nothing proves a path closed.
- **Change history, trends, MTTR/SLA, executive reporting** (IG7, UX2 absent): no history tables.
- **Runtime-to-posture correlation** (DR4 absent): no ingestion of GuardDuty/Defender/Falco alerts as evidence on graph nodes. Only the correlation half is in scope, but it is a named criterion three times (gap analysis §b rank 1).
- **Data context** (DS1–DS3): sensitivity is name guessing; no DSPM label ingest.
- **Standard outputs** (IW4): no OCSF/ASFF writer, so no Security Hub or Prowler interop.
- **Agent interface** (AI3 absent): no MCP server while Prowler, Sysdig, Datadog, AWS, JupiterOne all ship one.
- **Vendor criteria** (checklist rows 23–24): no commercial entity; the research says to answer with signed releases, SBOM, Scorecard (Track E).

Everything in that list is reachable by an agentless, local-first tool; nothing requires a sensor.

## 3. Twelve-month roadmap, five bets, five cuts

| Quarter | Theme | Lands | Claim unlocked |
|---|---|---|---|
| **Q1** (months 1–3) | Model + loop | Phases 1–2 below: typed inventory graph, permission edges, IAM evaluator v1, path Issues with lifecycle, history, scale; then verify, plan-time diff, root-cause plans, user rules, MCP, offline; **first live-cloud run** | "The only open-source tool whose attack paths carry statement-level evidence on every hop, keep a stable Issue ID across scans, and are proven closed by a targeted re-scan" |
| **Q2** (4–6) | CIEM depth | who-can, right-sized policy PRs from usage, privesc library (pathfinding.cloud), Azure RBAC + GCP IAM, SCP/RCP generator, validated secrets, compensating controls, exposure probes, DSPM ingest, timeline | "The only open-source CIEM that answers 'who can write to this bucket' transitively with the granting statement, and opens the PR that narrows it" |
| **Q3** (7–9) | Ecosystem + compliance | OCSF 1.6/ASFF/GitLab/JUnit, Cartography import/export, Prowler history import, Vanta export, evidence v2, compliance integrity + progress, governance rules, executive report, correlated threat Issues (GuardDuty/Falco ingest), AI-asset nodes | "Bring any scanner, any GRC tool, any graph: nimbus is the open bridge" |
| **Q4** (10–12) | Team + automation | Postgres backend option, OIDC, approvals queue with `simulate → approve → auto`, missions, benchmark v2 (Prowler/Checkov/Trivy goldens on the cloud lab), CNCF sandbox application | "Published precision/recall per release, on a lab anyone can run" |

**Five bets.** (1) An inventory-first typed graph with permission-bearing edges published as a small open spec on OCSF (the research's "OpenTelemetry for cloud findings", `strategy-how-to-win.md` §7.3). (2) Effective-IAM evaluation plus who-can plus right-sizing PRs: the identity plane is where the market moved and where leaders charge. (3) Path Issues with lifecycle and verified fix: the closed loop nobody in OSS has (gap analysis O8 rank 1, O3 rank 4). (4) The open benchmark with published math, re-run per release (O1). (5) Read-only MCP server and agent skills as the primary non-CLI surface (AI3; `open-source.md` "Features nimbus should steal" #18).

**Five cuts.** (1) The `rules.yaml` chain engine with `same_account` joins: migrate the eleven rules to anchored graph queries and delete the co-tenancy machinery. (2) The cost module beyond one "security-driven savings" card (`strategy-how-to-win.md` §4f). (3) Python re-implementations: Prowler-style boto3 checks, the drifted catalog copy, Python `ensure_views`; Python keeps reports and the copilot and reads Go output. (4) Neo4j/Neptune as maintained sinks and the Steampipe passthrough: keep a Cartography-compatible export file only (EI1). (5) Further investment in the cwm desktop UI as the primary surface (`strategy-how-to-win.md` §7.2); the default is CLI + static report + MCP. The gap analysis's §f list (agents, runtime EDR, JIT broker, SaaS, snapshot scanning, exploit execution, auto-merge, DSPM sampler) stays cut.

## 4. First ten engineering items (next two weeks)

Each is a disjoint package so Opus agents run them in parallel; each has a failing test first.

| # | Item | Packages | Acceptance test |
|---|---|---|---|
| 1 | **Node type registry** replacing substring classification: `graph/schema.go` with a closed table `TypeSpec{Type, Class, Provider, IDFormat, Crown bool}`; `ClassFor` consults it first and marks unknown types `guessed=true` with a coverage row | `internal/graph`, `internal/collector/core` | Every type emitted by the seven collectors and `lab/local/estate.yaml` resolves without the substring fallback; `make groundtruth` numbers unchanged; a test fails when a collector emits a type absent from the registry |
| 2 | **Permission-bearing edges**: `has_policy`, `grants_access_to`, `can_assume` carry `attr{actions[], effect, resources[], conditions{}, statement: "<policy-arn>#<sid|index>"}`; `DescribeEdge` renders the statement | `internal/graph`, `internal/collector/aws` (policy → edges), `k8s`, `gcp` | Lab P06 step 3 `because` reads `s3:GetObject on arn:aws:s3:::…pii via <policy>#ExportRead`; `paths --format json` schema test asserts non-empty `actions` on every permission edge of every lab path |
| 3 | **`internal/iam` evaluator v1** (pure, no SDK): `Evaluate(req Request, ctx PolicySet) Decision` honouring explicit Deny, NotAction/NotResource, wildcard resources, conditions as `conditional`, permission boundaries, SCP/RCP; `IsAdmin` and `DataAccess` re-implemented on it | new `internal/iam`, `internal/collector/aws/policy.go` | Corpus `internal/iam/testdata/corpus.yaml` ≥ 80 cases 100% green including the 8 failing Verification-2 cases; lab S01 (SCP deny) no longer reported, `scp_denied` chip appears, `lab/known_gaps.yaml` entry removed |
| 4 | **Path Issues**: migration 5 adds `kind IN ('single','combination','path','chokepoint')`, `anchor_id`, `entry_id`, `rule_id`, `score`, `verified_at`, `verified_by`; path Issue ID = `sha(kind|entry|anchor|rule)`; hop lists are evidence, not identity | `internal/store` (`migrate.go`, `issues.go`), `internal/model/issue.go`, `internal/cli/scan.go` | Ingest the lab twice → identical path Issue IDs; resolve W02 (IMDSv1) → P02 Issue `resolved`; restore → `reopened` with `first_seen` kept; `/api/summary` counts path Issues |
| 5 | **Resource history**: `resource_versions(resource_id, scan_id, config_hash, config_json, first_seen, last_seen)`; write only on hash change; `cloud-posture diff <resource-id>` prints JSON diff between the last two versions | `internal/store/history.go`, `internal/cli/diff.go` | Two ingests with one attribute changed → exactly one new version and a diff naming that attribute; unchanged resources add no rows; 10k resources × 10 scans stays under 50 MB |
| 6 | **Patcher correctness** (Verification 2 D1–D3): module-aware address map keyed by full `module.a.aws_instance.x`; `merge()`-tag `yor_trace` detection; nesting/size cap before `hclsyntax` | `internal/iac/iac.go`, `patch.go`, `scan.go` | `scratchpad/verify-2/d/modrepro` patches `modules/a/main.tf`; duplicate trace under `merge()` is refused with `TargetError`; 70k-nested `.tf` exits 1 with a message, no stack overflow |
| 7 | **`verify <issue>` v1**: collector interface gains `Target(ctx, ids []string) (*Result, error)`; verify re-collects the Issue's anchor plus one-hop neighbours, re-traverses, sets `verified_fixed` only if the path is gone, otherwise `reopened` with the surviving hop as evidence | `internal/collector/core/types.go`, `internal/cli/verify.go`, `internal/store` | Fake collector: verify on an unchanged public bucket leaves P01 open with evidence; after the flag flips, verify marks `verified_fixed` in < 60 s and writes `verified_by=rescan`; `attack_paths` row for other paths untouched |
| 8 | **Traversal scale**: adjacency built once per analysis; backward reachability from crown jewels prunes nodes that cannot reach one; `Analysis.Truncated bool` set whenever a cap is hit; choke-point "closes N" computed on the pruned graph | `internal/attackpath/reach.go`, `traversal.go` | Synthetic generator 50k nodes / 500k edges completes `Traverse` in < 30 s on the CI runner; lab results byte-identical; a test asserts `Truncated=true` when `MaxPaths` is exceeded and that the CLI prints it |
| 9 | **Rules as attributed content**: `rules/paths/*.yaml` with `id`, `name`, `attribution`, `anchor_type`, `match` (edge pattern), `score_hint`; `cloud-posture risk test <file>` dry-run; first ten pathfinding.cloud privesc techniques emitted as `can_escalate_to{technique}` edges by the AWS collector | `internal/attackpath/rules/`, `internal/collector/aws`, `internal/cli` | Seeded `iam:PassRole + ec2:RunInstances` lab scenario (new S15) yields a path whose hop cites the technique id; `risk test` exits 0, writes zero rows (asserted by row count) |
| 10 | **Collector truth v2** (Verification 2 Track C): M365 grant `OR` operator and ignored conditions, Okta `riskScore`/`identityProvider` rules, GCP explicit priority 0, port ranges judged over the full range, cross-host `Authorization` leak | `internal/collector/saas`, `gcp`, `azure/nsg.go`, `core/rest.go` | One negative fixture per item flips from PASS to FAIL (or FAIL to PASS); `TestZZVerifyRESTCrossHostLinkLeaksAuth` passes; the eight `ZZVerify*` probes from `scratchpad/verify-2` are promoted into the packages |

## 5. The biggest risk and how to de-risk it

**The identity and graph layer is heuristic and has never met a live estate.** Classes come from substrings, permissions from flags, relationships partly from scanner "hints" (`graph.go AttachFindings`), and the benchmark that says precision 95.2% is a 28-resource lab (`docs/benchmark.md`). A real 50-account estate will produce either silence (unclassified types, no admin edges) or noise (every "account"-ish type a crown jewel, every hint an edge). The research is blunt that one false "critical path" in public is unrecoverable (`strategy-how-to-win.md` §4b risks; §7.5 risk 1 and 6).

De-risking, in order: (a) items 1–3 above make classification and permissions deterministic and corpus-tested; (b) every path carries a confidence label derived from its weakest edge, `verified` (typed inventory edge) / `inferred` (policy evaluation with conditions) / `hint` (scanner hint), and the CLI defaults to hiding `hint`-only paths; (c) the first live run happens on the cloud lab plus **three design-partner accounts under NDA** before any launch, with `iam:SimulatePrincipalPolicy` sampling as the oracle for the evaluator; (d) `GROUNDTRUTH_STRICT=1` becomes a required CI check and the known-gaps file may only shrink; (e) path Issues with stable IDs (item 4) so churn is measured as reopen/resolve counts, published per release.

---

## 6. Implementation plan — the complete package, best-in-class per capability

**How to read it.** The capability map follows the groups of `docs/research/competitive-feature-matrix.md` (IDs such as `AP3` are its rows; "today" is its status column plus Phase 0 results). "Best-in-class means" is what the research says the leader does, cited to the cluster docs under `docs/research/competitors/` (`cnapp-leaders.md`, `platforms.md`, `open-source.md`, `compliance-and-adjacent.md`). Effort uses the gap-analysis scale (S ≤ 2 d, M ≤ 1 wk, L ≤ 3 wk, XL more). The owner's clarification is answered twice: §6.1 ranks how much being best differentiates nimbus; each row says what best concretely means.

### 6.1 Ranking: where best-in-class differentiates most

| Rank | Capability | What best-in-class concretely means for nimbus | Why it differentiates |
|---|---|---|---|
| 1 | Attack paths with statement-level evidence, stable Issue IDs and verified closure (AP1–AP3, RM4) | Every hop names the rule/statement; the path is an Issue with lifecycle; `verify` proves closure by re-scan; math published | No vendor publishes the math (`platforms.md` best-in-class "Attack-path scoring transparency" credits only SCC/AWS); no OSS has lifecycle + verify (`open-source.md` steal #4) |
| 2 | Effective IAM + who-can + right-sized PR (ID1, ID3, ID4) | Deny/NotAction/conditions/SCP/RCP/boundaries honoured; transitive answer with the granting statement; PR only narrows | Only dormant OSS (PMapper) does any of it (`open-source.md` §19); leaders charge for it (`cnapp-leaders.md` best-in-class "Least-privilege generation") |
| 3 | Plan-time path diff in PRs (AP10) | Sticky comment "opens N / closes M paths", computed on live graph + plan | "No vendor" (`competitive-feature-matrix.md` AP10); CI placement is the distribution engine (`strategy-how-to-win.md` §5.1) |
| 4 | Open benchmark with precision/recall per release (TS4) | Lab + goldens for Prowler/Checkov/Trivy; strict gate in CI | "No vendor or OSS project publishes path-level ground truth" (matrix TS4) |
| 5 | Min-fix set and root-cause plans (AP6, RM3) | Exact when small, verified by re-traversal; plans with phases and rollback; "resolves N" equals re-simulation | "No vendor computes the minimum-cost set" (matrix AP6); AWS plans are the bar (`platforms.md` steal #1) |
| 6 | Cross-scanner Issue model with confidence (RP6, IW3) | One Issue per problem per resource across Prowler/Checkov/Trivy/native, confidence rising with agreeing sources | "In OSS, no tool puts Prowler, Checkov, Trivy and Steampipe output into one graph" (matrix IW3) |
| 7 | Exposure accuracy: width, trusted CIDRs, dead ends, compensating controls (AP7, RP4) | Every exposure labelled; trusted-only suppressed with reason; WAF/SCP/private endpoint lower the score with a chip | Microsoft and XM Cyber set the bar (`platforms.md` best-in-class "Exposure accuracy"; `compliance-and-adjacent.md` steal #6) |
| 8 | Read-only MCP + skills (AI3, IC5) | Token-scoped tools, every answer cites query + Issue IDs, `draft_fix` returns a diff and never applies | Table stakes for 2027 (`strategy-how-to-win.md` §3.1H); free where Prowler's is paid |
| 9 | Coverage honesty + clean onboarding (IG8, TS3) | Per-call denied/skipped with reason; manifest + rollback; generated read-only policy | FortiCNAPP bar (`cnapp-leaders.md` best-in-class "Coverage honesty") |
| 10 | History, timeline, MTTR (IG7, UX2) | Per-resource versions and diffs; Issue timeline merges change events and IaC commits | Fix Inventory (dormant) and CrowdStrike beta (`open-source.md` steal #9; `cnapp-leaders.md` steal #10) |
| 11 | Trust kit (TS1, TS2) | cosign, SLSA, SBOM, immutable releases, pinned Actions | Buying criterion after Trivy/KICS 2026 (`strategy-how-to-win.md` §3.1G) |
| 12 | User-authored anchored rules with test-before-save (AP4) | YAML rule → Issues; preview; attribution | Sysdig/Cortex bar (`cnapp-leaders.md` best-in-class "User-defined toxic combinations") |
| 13 | DSPM label ingest and data-aware paths (DS2, DS3) | Sourced labels override name guesses; labels raise path score | Proofpoint↔Wiz spec (`compliance-and-adjacent.md` best-in-class "DSPM↔CSPM interop spec") |
| 14 | Compliance evidence v2 and GRC export (CO4–CO6) | Signed manifest, period coverage, Vanta full-state PUT | Audit Manager closed 2026-04-30 (matrix CO4) |
| 15 | Standard outputs and inbound interop (IW4, EI1–EI4) | OCSF 1.6, ASFF, SARIF, Cartography schema both ways | Prowler got AWS's blessing by bridging into Security Hub (`strategy-how-to-win.md` §5.1) |

Below rank 15: executive reporting, governance rules, framework breadth, correlated threat Issues, AI-asset nodes, team mode. They are needed for the RFP but do not differentiate; they are built to the bar, not above it.

### 6.2 Capability map with designs

**Group A — Inventory and graph**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| IG4 typed persisted graph | Wiz: typed nodes and relationships with properties, findings attached (`cnapp-leaders.md` Wiz "Inventory & graph") | partial; finding-derived, substring classes | `internal/graph/schema.go` type registry (item 1); collectors emit `core.Res` for every resource, not only failing ones; `graph_nodes` gains `type_known BOOL`, `confidence TEXT` | M | — | Registry covers 100% of collector types; unknown types counted in coverage |
| Permission edges | AWS Impact tab labels each hop with the permission used (`platforms.md` best-in-class "Attack-path scoring transparency"); Fix Inventory permission-weighted edges (`open-source.md` steal #6) | edges carry kind only | item 2; `graph.Edge.Attr` schema documented in `docs/graph-schema.md`; `DescribeEdge` renders statements | M | registry | every lab permission hop has `actions` |
| IG3 org enumeration | Prowler StackSet per member account (matrix IG3) | no Organizations enumeration | `internal/collector/aws/org.go`: `organizations:ListAccounts` → `AccountSpec` fan-out with per-account role; Azure management groups, GCP folders analogous | M | coverage table | fake org with 3 accounts → 3 coverage rows, 3 account nodes |
| IG5 SQL + base kinds | Fix Inventory 40+ base kinds (`open-source.md` best-in-class "Cross-cloud normalised model") | per-type views only | `internal/store/kinds.go`: views `nimbus_database`, `nimbus_bucket`, `nimbus_identity`, `nimbus_workload`, `nimbus_network_control` unioning provider types from the registry | S | registry | `SELECT * FROM nimbus_database WHERE public=1` returns RDS + Cloud SQL + Azure SQL from the lab |
| IG7 history | Fix Inventory hourly snapshots and diffs (`open-source.md` steal #9) | absent | item 5; `cloud-posture diff`; `/api/resource/{id}/history` | M | — | item 5 test |
| IG8 coverage honesty | FortiCNAPP per-account status with failure reason (`cnapp-leaders.md` steal #14) | coverage table exists (Track G) | Fix Verification-2 gaps: ctx-honouring partial collector reported `ok`; add `coverage_summary` view; dashboard panel reads it | S | — | partial-after-deadline collector gets `timeout`, not `ok` |
| IG9 AI assets | SCC agents as path nodes; AWS three-source inventory (`platforms.md` steal #17) | absent | registry types `aws_bedrock_agent`, `gcp_vertex_agent`, `mcp_server`; collector reads Bedrock/Vertex agent execution roles → `runs_as` edges; rule "agent role can modify IAM" | M | registry, iam | seeded agent with `iam:*` role → path Issue |

**Group B — Attack paths and toxic combinations**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| AP1 engine | SCC simulated attacker, AND/OR edges (matrix AP1) | DFS 6 hops, caps, two engines | item 8 (`reach.go`); retire `rules.yaml` chains into anchored queries (AP4); per-path `confidence` from weakest edge | L | registry | scale test; lab identical; `confidence` present on every path |
| AP2 published scoring | SCC formula, AWS matrix (`platforms.md` best-in-class) | published in `docs/scoring.md`; toxic floor | keep; add 5×5 likelihood × impact lens in `internal/risk/matrix.go` (`platforms.md` steal #6) | S | — | doc test covers matrix; every path has a cell |
| AP3 path Issues | Wiz Issue = correlated toxic combination with anchor (matrix AP3) | paths not Issues | item 4; Issue score = max over its paths; `issues.anchor_id` is the crown jewel | M | — | item 4 test |
| AP4 user rules | Sysdig anchor + Managed/Custom + New/Live badges; Cortex search-before-save (`cnapp-leaders.md` best-in-class) | 11 built-in chains | item 9; `rules/paths/*.yaml` schema: `id, name, attribution, anchor_type, pattern: [{edge, to_class, where}], severity`; loader compiles to a traversal filter; badges from Issue `first_seen` | M | Issues | `risk test` dry-run; shipped rules all have attribution |
| AP5 choke drill-in | MDC blast radius; SCC "fix one closes many" (`platforms.md` steal #5) | `--choke` exists; counts traversal paths only | count path Issues of all kinds; `/api/choke/{id}` subgraph | S | Issues | choke count equals Issues removed on re-traversal |
| AP7 exposure accuracy | MDC wide/narrow + trusted; XM dead ends (matrix AP7) | done in Track C/B3 | fix dead-end SG id mismatch (Verification 2 `paths --dead-ends` (b)); registry-based ID canonicalisation | S | registry | `sg-0abc123` resolves to its ARN node |
| AP8 network reachability | AWS reachability trait (matrix AP8) | SG/NSG/firewall edges | `internal/collector/aws/netpath.go`: route tables, NACLs, IGW/NAT presence → `allows_traffic_to` edges carry `ports`, `via_nacl`, `via_route`; "reachable" requires all three | L | registry | lab S13 plus a seeded NACL deny → path suppressed with reason |
| AP9 validated exploitability | S1 Exploit Evidence tab (`cnapp-leaders.md` best-in-class "Attack-path proof") | absent | `internal/verify/probe.go`: opt-in `--probe --allow <cidr|id>`; anonymous bucket list, TCP connect, unauthenticated K8s API, `SimulatePrincipalPolicy`; evidence stored in `issue_evidence(issue_id, kind, request, response_hash, at)`; Issue `validated=true` | L | Issues, iam | no probe without allowlist (test); lab public bucket gets listing evidence |
| AP10 plan-time diff | nobody (matrix AP10) | absent | `internal/iac/plan.go` parses `terraform show -json` → planned resources with predicted IDs (tfstate map or address-derived); `attackpath.Diff(live, overlay)` keyed by path Issue ID; `pr-comment` writes a sticky marker comment | L | Issues, registry | lab PR opening 0.0.0.0/0 → "opens 1 path to <jewel>"; revert → "closes 1"; comment edited not duplicated |

**Group C — Risk prioritisation**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| RP1 explainable score | FortiCNAPP factors + top-3 paths, "no data ≠ 0" (`cnapp-leaders.md` steal #1) | done (score 2.0.0) | Issue-level score = finding score with `attack_path` factor from path Issues; `explain <issue>` | S | Issues | factors multiply to score for every Issue |
| RP3 crown jewels | MDC critical-asset rules (matrix RP3) | config levels done | drop `defaultJewels` name globs from `traversal.go` once registry `Crown` and DSPM labels exist; built-in catalog becomes typed (secrets, KMS, IdP tenants) | S | registry, DS2 | lab PII bucket is a jewel from config/label, not name |
| RP4 compensating controls | Zscaler/Check Point (`platforms.md` steal #18) | hook weights exist | WAF, private endpoint, NetworkPolicy, SCP deny become nodes/attrs set by collectors; path step `evidence.compensating` and score chip | M | iam (SCP) | lab path behind WAF scores lower; removing raises |
| RP7 mutes | DD suppressions with expiry (matrix RP7) | JSON globs with expiry | mandatory `reason`, `expires_at`, `author`; muted Issues kept as `suppressed` state | S | Issues | mute without reason rejected |
| RP8 governance | MDC owner from tag, SLA 7/14/30/90, digest (`platforms.md` steal #3) | SLA/DueAt on risk | `internal/governance`: YAML rules first-match; owner from tag/CODEOWNERS; `issues.owner, due_at`; weekly digest sink; MTTR from history | M | Issues, history | overdue list equals hand count on lab |

**Group D — Identity / CIEM**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| ID1 effective permissions | AWS Impact trait: identity + resource + SCP + RCP (matrix ID1) | flags; 8/14 wrong | item 3 (`internal/iam`): `type Request{Principal, Action, Resource, Context map}`; `type PolicySet{Identity, Boundary, SCPs, RCPs, Resource, Session []Policy}`; `Decision{Effect allow|deny|conditional, Chain []StepRef}` following AWS order (explicit deny → SCP → RCP → resource → boundary → identity); materialise `can_perform{actions}` edges for the privesc/data action catalogue | XL (v1 M) | — | corpus 100%; sampled agreement with `SimulatePrincipalPolicy` in e2e |
| ID2 privesc paths | Prowler ~70 pathfinding.cloud queries (matrix ID2) | absent | item 9; full port in Q2 with ids kept for comparability (`open-source.md` interop table) | L | iam | each ported technique has a fixture that fires and a negative that does not |
| ID3 who-can | Fix Inventory, DD Access Insights (matrix ID3) | ignores Deny | `cloud-posture who-can <action> <resource>`: reverse walk over `can_perform` + `can_assume` + `member_of`, each row with statement | M | iam, item 2 | lab `who-can s3:GetObject pii` lists Lambda role, admin user, external role with statements |
| ID4 right-sizing | Cortex Adjust Policy; DD Terraform PR (`cnapp-leaders.md` best-in-class "Least-privilege generation") | absent | `internal/collector/aws/usage.go` (service-last-accessed + CloudTrail 90/180 d) → `identity_usage` table; `internal/iam/rightsize.go` emits policy JSON that only narrows; `fix --rightsize` opens the PR | L | iam, history | plan shows only removals; lab workload smoke still passes; "% entitlements removed" printed |
| ID5 Azure RBAC, GCP IAM | Tenable cross-cloud effective permissions (matrix ID5) | absent | `azure/rbac.go` role assignments → `can_perform` with scope; `gcp/iam.go` project/folder/org bindings incl. conditions; same `Decision` type | L | iam | lab S09/S11 paths cite the binding, not a name match |
| ID6 K8s RBAC | Kubescape 290 controls (matrix ID6) | 7 checks | RoleBinding/ClusterRoleBinding → `bound_to{verbs, resources}`; wildcard and `escalate`/`bind`/`impersonate` verbs as `can_escalate_to` | M | registry | P08 hop cites the binding and verbs |
| ID7 guardrails | Sonrai SCP/RCP firewall, quarantine (matrix ID7) | absent | `internal/remediate/guardrails.go`: SCP/RCP deny from unused privileged actions with exemptions; size-budget meter; reversible deny-all quarantine PR | L | ID4 | generated SCP under size limit; quarantine reversible (test re-enables) |

**Group E — Data / DSPM**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| DS2 label ingest | Proofpoint↔Wiz daily pull/push (`compliance-and-adjacent.md` best-in-class) | absent | `internal/adapters/dspm/{macie,purview,gcpdlp,cyera,sentra}.go` → `data_labels` attr with `source`; `looksSensitive` demoted to `inferred` | M | — | golden fixtures; lab bucket sensitive from label raises path score |
| DS3 data-aware paths | Sysdig data in paths (matrix DS3) | `stores_data_in` never emitted | emit from Lambda env/role grants and app→DB edges in collectors; registry marks data stores | S | item 2 | at least one lab path ends on a labelled store via `stores_data_in` |

**Group F — Vulnerabilities, secrets, SBOM**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| VS1 CVE ingest | Trivy one JSON many renderings (matrix VS1) | adapter drops CVSS; PkgPath collapse | fingerprint includes `PkgPath`; keep CVSS/PrimaryURL; version bump keeps `first_seen` by matching `(cve, pkg, path)` | S | — | Verification-2 Trivy defects (a)(b) fixed with fixtures |
| VS3 reachability tiers | Orca three tiers (`cnapp-leaders.md` steal #5) | absent | field `reachability: installed|potentially_loaded|executed|function_called`; `potentially_loaded` from image entrypoint/service units in Trivy SBOM; higher tiers from SARIF/Falco ingest | M | VS5 | queue sorts tier → KEV → EPSS |
| VS4 validated secrets | S1 validated for active use (`cnapp-leaders.md` steal #6) | detect only | `internal/secrets/validate.go`: opt-in harmless calls; store hash only; `Active|Revoked|Unverifiable`; active secret = path entry 0.9 | M | — | secret value absent from DB (grep test); seeded revoked key classified |
| VS5 SBOM re-evaluation | Aqua smart rescan (`cnapp-leaders.md` best-in-class "Vuln freshness") | absent | `sboms(digest, cyclonedx)` table; nightly re-match on intel refresh | M | intel | new KEV entry creates Issue without re-scan |

**Group G — IaC and code-to-cloud**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| IC1 IaC scanning | Checkov plan scanning (matrix IC1) | native HCL 20 rules | ingest Checkov/KICS/Trivy JSON as first-class (`open-source.md` interop); native scanner stays for patch targeting; plan JSON (AP10) | M | — | Checkov results on `testdata/iac` dedupe with native findings into one Issue each |
| IC2 cloud-to-code | Wiz Code file/line/module/owner via state (matrix IC2) | module-blind | item 6; `trace` table `(resource_id, repo, file, line, module, commit, author)` from tfstate + git blame | M | history | D1 repro fixed; lab IaC resource shows commit |
| IC3 coverage/drift | Cortex coverage dashboard (`cnapp-leaders.md` steal #11) | absent | `% traced` tile; `DRIFT_UNTRACED` Issue with `import` block suggestion | M | IC2, Issues | one ClickOps lab resource → drift Issue with import block |
| IC5 agent hooks | FortiCNAPP changed-files plugin; DD hand-off (matrix IC5) | hook fixed | `skills/` for Claude Code/Cursor calling MCP; "copy prompt for coding agent" on IaC Issues | S | MCP | pre-commit scans only changed files and blocks on critical |

**Group H — Remediation**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| RM1 structured fixes | CrowdStrike permissions/validation/compensating (`cnapp-leaders.md` steal #7) | 42 sidecars done | render metadata in PR body; validation SQL run by `verify` | S | verify | PR body shows all metadata fields |
| RM2 patch + PR | Cortex one-click, Wiz 2.0 (matrix RM2) | works; D1–D6 defects | item 6; D4 `--` before positional args; D5 diff algorithm bounded | M | — | Verification-2 D-list closed with fixtures |
| RM3 root-cause plans | AWS plans: one per resource change, phases, rollback (`platforms.md` steal #1) | `plan` stub (min-fix set + resolves) | `internal/remediate/plan.go`: group fixes by `root key` (SG id, policy ARN, module path, image digest); phases prerequisite→snapshot→fix→verify with `rollback` from sidecar; sortable; one PR per plan | L | Issues, RM1 | "resolves N" equals re-simulation (already verified) for grouped plans; hotspot of 3 findings yields one PR |
| RM4 verified fix | XM confirmation, Prowler partial scans (matrix RM4) | absent | item 7; Jira/GitHub close only after `verified_fixed`; reopen with evidence | M | item 7 | ticket close test |
| RM5 automation modes | Wiz Workflows simulate→block; Flowpipe approvals (`cnapp-leaders.md` steal #9) | absent | Q4: `remediate:` block per rule `mode: simulate|approve|auto`, Pending Changes table, Slack buttons, audit log; never default-on | XL | RM3, verify | simulate writes nothing (test); approve requires token |
| RM6 preventive | Kubescape VAP export (matrix RM6) | Rego stub | `prevent --format vap|scp|azure-policy` from the same rules; delete Rego stub | M | AP4 | generated VAP rejects the lab privileged pod in a kind cluster test |

**Group I — Compliance and evidence**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| CO1/CO2 breadth + integrity | Prowler 105 framework files, integrity test, universal frameworks (`open-source.md` best-in-class) | 11 hand-written; errors | import Prowler compliance JSON (Apache-2.0, credited) via `internal/compliance/import_prowler.go`; CI integrity test (duplicate IDs, dangling refs, Go/Python parity) | M | — | PCI 4.0 IDs correct; CI fails on a dangling ref |
| CO4/CO5 evidence v2 | Audit Manager layout; Upwind Score Journey (matrix CO4, CO5) | unsigned ZIP | signed manifest (cosign or minisign), by-control/by-source/by-date, "effective X of Y days" from history, manual controls never auto-pass | L | history, trust kit | signature verifies; coverage days equal history |
| CO6 GRC export | Vanta full-state PUT (`compliance-and-adjacent.md` steal #1) | absent | `internal/integrations/vanta.go`; omitted-equals-deleted handled explicitly; Drata if API allows | M | Issues | mock full-state PUT test |
| CO3 custom frameworks | S1 tree builder; Drata editor (matrix CO3) | lose inventory | fix `cli/report.go:56`; YAML clone/blend with line-level validation | M | CO2 | custom framework keeps inventory |

**Group J — Detection and correlation (agentless only)**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| DR1 event-driven | C7N serverless policies (matrix DR1) | polling, defects | fix monitor (overlap window, dedup by event id); optional EventBridge/Event Grid subscriber → `verify`-style targeted re-collect | L | item 7 | late event not lost (test); touched resource re-collected within one poll |
| DR4 runtime↔posture | SCC Correlated Threats; Qualys numbered insights (`platforms.md` steal #16) | absent | ingest GuardDuty/Defender/Falco alerts as `detections(resource_id, type, at)`; rule `NIM-TC-*` joins detection + path Issue into a `correlated` Issue with stable ID | M | Issues, AP4 | fixture alert on lab web-1 produces `NIM-TC-0001` |

**Group K — Integrations, outputs, interop**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| IW4/EI outputs | KICS 11 formats; Prowler OCSF; Trivy convert (`open-source.md` steal #14, #15) | SARIF only | `internal/output/{ocsf,asff,gitlab,junit}.go`; `cloud-posture convert` | M | — | OCSF validates against 1.6 schema; imports into Prowler "Import Findings" fixture |
| EI1 Cartography | published schema; Prowler runs on it (matrix EI1) | export-ish | import Neo4j dump → registry types; export with Cartography labels so Prowler queries run (`open-source.md` interop) | L | registry | a sample Prowler query returns the same rows on nimbus export |
| IW1/IW2 sinks, tickets | DD two-way Jira, auto-close on fix (matrix IW2) | one-way; GitHub close | close/reopen driven by Issue state transitions; retries with backoff; routing by `verdict`/owner | M | Issues, verify | Jira mock closes on `verified_fixed`, reopens on `reopened` |

**Group L — AI, platform, trust**

| Capability | Best-in-class means | Today | Design | Effort | Deps | Acceptance |
|---|---|---|---|---|---|---|
| AI3 MCP | Sysdig token-filtered Go MCP server (`cnapp-leaders.md` best-in-class "Security inside AI coding agents") | absent | `internal/mcp`: tools `sql` (via `store.QueryReadOnly`), `issues`, `paths`, `explain`, `who_can`, `draft_fix` (diff only), `verify` (opt-in); tool list filtered by token scope; same server backs the Python copilot | M | Issues, iam | injection corpus refused; Claude Desktop smoke lists lab paths |
| AI2/AI4 BYO-LLM, guardrails | Prowler Lighthouse providers; Cortex AgentiX (matrix AI2, AI4) | Anthropic only | provider abstraction; `agent_audit` table; untrusted-data wrapping; timeouts | M | MCP | eval suite passes on two providers; injected tag cannot call a tool |
| PF4/PF6 team + backend | Wiz Tenant Manager (matrix PF4) | SQLite, one token | Q4: `store` behind an interface with a Postgres implementation; OIDC; RBAC read/write/admin | XL | — | same test suite green on both backends |

### 6.3 Sequenced plan: phases, parallel tracks, exit criteria, claims

**Phase 1 — Model (weeks 1–6).** Tracks run in parallel on disjoint packages: **M1** registry + permission edges (items 1, 2; `internal/graph`, `collector/*`), **M2** IAM evaluator v1 (item 3; `internal/iam`), **M3** path Issues + history (items 4, 5; `internal/store`, `model`), **M4** patcher + verify v1 (items 6, 7; `internal/iac`, `cli/verify.go`), **M5** traversal scale + rules content (items 8, 9; `internal/attackpath`), **M6** collector truth v2 + org enumeration + first live run on the cloud lab (item 10; blocked on credentials, recorded as a blocker). An Opus verifier re-probes each track.
*Exit:* all ten acceptance tests green; `GROUNDTRUTH_STRICT=1` green with `lab/known_gaps.yaml` empty (S01 closed by M2, P12 by the OIDC rule in M5); synthetic 50k-node scale test under 30 s; path Issue IDs stable across two lab ingests; live-cloud run executed or recorded as blocked.
*Claim:* "The only open-source tool whose attack paths name the IAM statement on every hop, honour SCP/RCP denies, and keep one stable Issue ID per path across scans."

**Phase 2 — Loop (weeks 6–14).** **L1** plan-time path diff (AP10), **L2** root-cause plans (RM3) + PR body metadata (RM1), **L3** MCP server + skills + BYO-LLM (AI3, AI2, IC5), **L4** offline collect/evaluate + escaped report (gap analysis O55), **L5** who-can + K8s RBAC edges (ID3, ID6), **L6** exposure probes v1 (AP9) + compensating controls (RP4), **L7** Action with `--baseline` (fails only on new Issues) + OCSF/ASFF writers (IC4, IW4) + OpenSSF Scorecard ≥ 8 gate (TS1).
*Exit:* the 90-second demo runs on the local lab and the cloud lab: ingest → paths with statement-level why → plan → PR with path-diff comment → merge → `verify` → path Issues `verified_fixed`; zero egress except cloud APIs and the chosen LLM; MCP smoke in Claude Desktop.
*Claim:* "The only tool, open or closed, that tells a pull request how many attack paths it opens or closes, and then proves the merge closed them."

**Phase 3 — Depth (weeks 14–26).** **D1** right-sizing PRs from usage (ID4), **D2** privesc library port (ID2), **D3** Azure RBAC + GCP IAM (ID5), **D4** SCP/RCP guardrail generator + quarantine (ID7), **D5** validated secrets + SBOM re-evaluation + reachability tiers (VS3–VS5), **D6** DSPM label ingest + data-aware paths (DS2, DS3), **D7** timeline + cloud-to-code trace + drift (IG7, IC2, IC3), **D8** AI-asset nodes (IG9).
*Exit:* lab IAM corpus ≥ 200 cases green; sampled `SimulatePrincipalPolicy` agreement reported in `docs/benchmark.md`; lab role with unused `s3:*` receives a PR whose plan only narrows; three design-partner estates scanned with no false "critical" path reported after review.
*Claim:* "The only open-source CIEM that answers who can reach your data transitively and opens the PR that narrows it."

**Phase 4 — Ecosystem and compliance (weeks 26–40).** **E1** Cartography import/export + Prowler history import (EI1, EI2), **E2** Vanta export + evidence v2 + compliance import/integrity (CO1–CO6), **E3** governance rules + MTTR/SLA + executive PDF (RP8, UX2, UX3), **E4** correlated threat Issues from GuardDuty/Defender/Falco (DR4) + monitor fixes (DR1), **E5** two-way Jira/GitHub on Issue state (IW2), **E6** preventive exports (RM6).
*Exit:* OCSF output accepted by Security Hub and Prowler import in e2e; evidence bundle signature verifies and period coverage is computed from history; at least one design partner receiving nimbus data in a GRC tool.
*Claim:* "Bring any scanner, any GRC tool, any graph: the open bridge between them."

**Phase 5 — Team and automation (weeks 40–52).** **T1** Postgres backend + OIDC + RBAC (PF4, PF6), **T2** automation modes with Pending Changes and audit (RM5), **T3** missions (gap analysis O38), **T4** benchmark v2 with Prowler/Checkov/Trivy goldens on the cloud lab, published per release (TS4), **T5** CNCF sandbox application and `OPEN_SOURCE_PROMISE.md`.
*Exit:* same test suite green on SQLite and Postgres; simulate mode provably writes nothing; benchmark page published with raw outputs and methodology.
*Claim:* "The only CNAPP that publishes its precision and recall on a lab anyone can run, every release."

### 6.4 Cross-cutting rules for every track

Failing test first; every Issue-visible number derived from Issues, never raw findings; every edge and path carries `because`, `evidence` and `confidence`; nothing writes to a cloud without `--apply` plus a token; Python reads Go output and never re-implements a number; every new capability lands with a lab scenario, a ground-truth label and, where it changes scores, a `score_version` bump and changelog entry in `docs/scoring.md`.
