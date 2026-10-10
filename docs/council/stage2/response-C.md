# Council stage 1 — the council member / attack-path engineer's answer

_2026-10-09. council member: BloodHound / pathfinding.cloud / PMapper school. I judge nimbus by one question: would its output survive contact with a real 50,000-resource estate and a real attacker? Evidence: I read the engine (`internal/attackpath/*`, `internal/graph/graph.go`, `internal/collector/aws/policy.go`, `internal/collector/core/exposure.go`, `internal/risk/risk.go`), the research under `docs/research/`, and I built and ran `make groundtruth` read-only (result reproduced: 12/12 recall, 10/12 recall@7, 20/21 precision, 1 unlabelled path `internet > nimbus-lab-eks` at 4.00, two known gaps P12 and S01)._

## 1. Verdict on IMPLEMENTATION_PLAN_v2

**Right.** Phase 0 "trust and truth" before features is the only defensible order for a security tool; the Remediated table in `docs/research/nimbus-capability-inventory.md` shows the hardening track actually closed defects 1–5, 8, 11, 12, 14 with failing-test-first evidence. The ground-truth lab with a seeded false positive (F01) and a seeded "should not report" (S01) is the single best artefact in the repo: no vendor publishes path-level ground truth (`docs/research/competitive-feature-matrix.md` TS4). Positioning as the graph over other scanners' output rather than a check-count race is correct (`docs/research/nimbus-gap-analysis.md` §f). The per-hop `because`, `WeaknessOn` attribution, re-verified break fixes and `MinFixVerified` in `traversal.go`/`fix.go` are real engineering, not slides.

**Wrong, in order of how much it would embarrass nimbus in front of an attacker:**

1. **The effective IAM evaluator is in Phase 2, behind the MCP server, governance rules and dashboard work.** Every path that ends at an identity or a data store today rests on `policy.go`: `IsAdmin()` and `DataAccess()` ignore Deny, Conditions, permission boundaries, resource policies, KMS key policies, SCPs and RCPs. `can_assume` edges come from trust policies alone (`analyze.go` `role()`), never checking that the caller holds `sts:AssumeRole` in its own identity policy, which cross-account assumption requires. Plan v2 proposes to ship plan-time path diffs (Phase 1 item 2) and PR-opening fixes on top of these edges. Diffing wrong paths produces wrong PRs faster. The evaluator must move to Phase 1 track 1.
2. **Likelihood is hand-tuned to the lab and then floored by policy.** `docs/benchmark.md` shows P02 going 5.69 → 7.60 and P08/P09/P11 landing at exactly 7.00 via the toxic-combination floor (`toxic.go`, `ToxicFloor = 0.7`). The floor is an impact policy dressed as a probability; it is defensible, but `docs/scoring.md` should say "policy" not "likelihood", and the per-hop table should not be read as calibrated. In a real estate `exposesEval` gives 0.95 to any exposed node with `CVECount > 0` and `credentialHop` gives 0.6 for the same, with no KEV/EPSS gate and no check that the vulnerable service is the exposed one (`traversal.go:302-306`, `credhop.go` `exploitable()`). That is a false-positive generator: every internet-facing EC2 with an Inspector finding becomes a 0.95 entry.
3. **Precision 95% is measured on a 28-resource estate written by the people who wrote the heuristics.** The default crown-jewel catalog (`traversal.go` `defaultJewels`: `*admin*`, `*prod*`, `*customer*`, `*pii*`) and `looksSensitive` (`graph.go`) are name-substring rules; the lab names resources `nimbus-lab-customer-pii`. There is no noise in the estate: no 300 benign resources named `prod-*`, no load balancer open on 443 that is supposed to be open, no admin role nobody can reach. The benchmark proves recall on seeded paths; it proves nothing about precision at scale.
4. **Three correctness-critical capability areas are absent from every phase:** network reachability beyond SG/NSG source CIDRs (no NACL, route table, IGW, ENI public-IP or load-balancer listener model; `AP8` is `partial†` in the matrix and never appears in plan v2 tracks), Kubernetes RBAC beyond "cluster-admin or wildcard" (`k8s.go:370-412` records `wildcard`/`admin` flags only; no verb analysis), and cross-plane identity federation (IRSA/EKS Pod Identity, GKE Workload Identity, Azure federated credentials, Okta/Entra → AWS SAML, GitHub OIDC `sub` conditions). These are where real attackers move between planes; nimbus's graph has no edges there.
5. **P12 was left as a "planning decision"** (`lab/known_gaps.yaml`). It is not a scoring decision; it is a modelling gap. Whether an unprotected repo reaches cloud admin depends on the OIDC trust's `sub` condition and on the workflow triggers (`pull_request_target`, fork PRs), none of which nimbus collects.
6. **Exploitability evidence has no home in the data model.** Phase 2 adds probes (O25) but `model.AttackPath` has no `validation` state. Without a `theoretical | validated | refuted` field, probes become a side report nobody trusts.

## 2. What is still missing for "complete package" in a 2026 CSPM/CNAPP RFP

From the rfp.wiki and analyst criteria in `docs/research/competitors/compliance-and-adjacent.md` Part F and `docs/research/nimbus-gap-analysis.md` §b, through my lens:

- **Identity posture that is correct** (RFP "Identity Posture Analysis", GigaOm CIEM): effective permissions across AWS, Azure RBAC, GCP IAM and Kubernetes RBAC, with "who can reach X" and unused-privilege right-sizing (`ID1`, `ID3`, `ID4`, `ID5`, `ID6` all `partial†`/`absent†`).
- **Reachability truth** (ASH reachability trait, MDC width): a path must know whether the packet arrives, not whether a rule exists (`AP8`).
- **Exploitability evidence**: S1's Exploit Evidence tab and ASH Network Scanning set the bar (`AP9` absent). A buyer will ask "how many of these paths did you prove?"; the honest answer must be a number.
- **Data context** (`DS1–DS3` absent/partial): ingest Macie/Purview/DLP/Cyera labels; stop guessing from names.
- **Code-to-cloud and pipeline paths** (Gartner, Latio): plan-time diff is planned; pipeline-poisoning paths (workflow triggers, OIDC subjects, secrets) are not.
- **Lifecycle, history, trend, MTTR** (`RP5`, `IG7`, `UX2`): planned in Track G; a buyer cannot evaluate a tool whose counts never go down.
- **Runtime-to-posture correlation** by ingest only (Falco/GuardDuty/Defender alerts as node evidence), never agents.
- **Org-wide onboarding** (`IG3`): Organizations/management-group/folder enumeration, or the demo dies at account 2.

## 3. Implementation plan

### 3.1 Capability map, ranked by how much best-in-class would differentiate nimbus

Rank = how far ahead nimbus would be if it were best-in-class, weighted by whether a real attacker would notice the difference. "Best" cites the matrix row (`docs/research/competitive-feature-matrix.md`) or cluster doc. Effort S ≤ 2 d, M ≤ 1 w, L ≤ 3 w, XL > 3 w (same scale as the gap analysis).

| # | Capability (group) | Best-in-class means concretely | nimbus today | Effort | Differentiation |
|---|---|---|---|---|---|
| 1 | Effective IAM evaluation (Identity) | ASH Impact trait + Wiz CIEM: identity + resource + KMS policies, boundaries, session policies, SCP/RCP, conditions, per-hop permission label (`ID1`); PMapper's transitive simulation (`docs/research/competitors/open-source.md` best-in-class table) | `policy.go` Allow-only wildcard matcher | XL | Highest: no OSS tool has a maintained, corpus-verified evaluator; every path depends on it |
| 2 | Cross-plane identity federation (Identity) | Cartography federation edges Okta/Entra → AWS roles (`IG2`); nobody models IRSA/WIF/GitHub OIDC `sub` classes as path hops | none | L | Very high: the bridges attackers actually use; Cartography has facts, no scoring |
| 3 | Network reachability (Exposure) | ASH reachability trait, MDC wide/narrow + trusted (`AP7`, `AP8`); ASH Network Scanning probes from outside | SG/NSG/firewall source CIDRs only; GCP priority/deny now in `gcp.go` `decide()` | L | Very high: reachability is the #1 FP source in every CSPM |
| 4 | Exploitability evidence (Paths) | S1 Exploit Evidence tab; Pentera read-only check (`AP9`, CA #17) | none; no `validation` field | M+L | Very high: "proved N of M" beats every vendor's "possible" |
| 5 | Privilege-escalation edges + attributed path library (Identity/Paths) | Prowler ~100 AWS queries, ~70 pathfinding.cloud techniques with stable ids (`ID2`, `AP4`) | none (`privEscActions` list used only for admin detection) | L | High: port is Apache-2.0; nimbus runs it cross-cloud and scores it |
| 6 | Kubernetes RBAC depth (Identity) | Kubescape 290 controls incl. access-control risks (`ID6`); KubeHound-style verb escalation | cluster-admin/wildcard flag only | M | High: K8s is where OSS buyers live |
| 7 | CI/CD pipeline paths (Code-to-cloud) | Wiz Code / Cortex pipeline onboarding (`IC3`); nobody models workflow triggers + OIDC subject as a path | BRANCH_UNPROTECTED entry 0.4 | M | High: P12 becomes a real, explainable path |
| 8 | Plan-time path diff + verified fix (Remediation) | No vendor (`AP10`); XM Remediation Confirmation, Prowler partial scans (`RM4`) | planned Phase 1 | L+M | High, but only after 1–3 are right |
| 9 | Toxic rules, dead ends, choke points, min fix set (Paths) | Sysdig anchor rules + test-before-save (`AP4`); MDC blast radius (`AP5`); nobody computes min fix set (`AP6`) | real, exact on small graphs, verified | M | Medium-high: already ahead; keep honest labelling |
| 10 | DSPM-lite label ingest (Data) | Proofpoint↔Wiz interop (`DS2`); Sysdig data inside paths (`DS3`) | name heuristics | M | Medium-high: "sourced vs inferred" sensitivity is cheap credibility |
| 11 | Scoring explainability + KEV/EPSS (Prioritisation) | FCN explainability, Cortex CVRS (`RP1`, `RP2`) | shipped: `risk.go` factors, `not scored`, snapshot intel | S | Medium: done; extend to path hops |
| 12 | Right-sizing + org guardrails (Identity) | Cortex Adjust Policy, DD Suggested Policy PR, Sonrai SCP budget (`ID4`, `ID7`) | none | L | Medium-high; depends on 1 |
| 13 | Lifecycle/Issues/history/coverage honesty (Graph) | Sysdig auto-close, FixInv timeline, FCN failure reasons (`RP5`, `IG7`, `IG8`) | Track G planned | M | Medium: table stakes |
| 14 | Org enumeration + collectors breadth (Graph) | Prowler StackSets (`IG3`) | per-account specs | M | Medium: table stakes |
| 15 | Compliance evidence v2, GRC export (Compliance) | Audit Manager layout, Vanta resources API (`CO4`, `CO6`) | evidence ZIP | L | Medium: channel, not correctness |
| 16 | MCP server, BYO-LLM, guardrails (AI) | Sysdig token-scoped MCP, Cortex AgentiX (`AI3`, `AI4`) | partial | M | Medium: distribution |
| 17 | Outputs/interop OCSF/ASFF/Cartography (Integrations) | Prowler OCSF, Cartography schema (`IW4`, `EI1`) | SARIF only | M | Medium |
| 18 | Release trust kit (Platform) | c7n-left cosign, Trivy lesson (`TS1`, `TS2`) | Track E | M | Medium: necessary, not differentiating |
| 19 | Dashboards, exec PDF, trends (UX) | Cortex Command Center, J1 trends (`UX1–UX3`) | cwm UI | M | Low for my lens; needed for RFP |
| 20 | Runtime/CDR, DSPM classification, JIT, team mode | `DR3`, `DS1`, `ID7`, `PF4` | absent | XL | Skip (see §7) |

### 3.2 Correctness-critical designs (what an engineering agent builds)

#### 3.2.1 Effective IAM evaluator — `internal/iam`

**Design.** A pure package, no SDK imports. `type Request {Principal, Action, Resource, Context map[string]ConditionValue}`. `Evaluate(req, PolicySet) Decision` where `PolicySet{Identity []Policy, Boundary *Policy, Resource *Policy, SCPs [][]Policy (one slice per OU level), RCPs [][]Policy, Session *Policy}` and `Decision{Effect allow|implicit_deny|explicit_deny, Matched []StatementRef, DeniedBy *StatementRef, Unknown []string}`. Evaluation order follows AWS: explicit Deny anywhere wins; SCP and RCP must each allow at every level; boundary and identity (or resource policy for same-account) must allow; cross-account requires identity allow AND resource-policy allow. Condition operators implemented: `String*`, `Arn*`, `Bool`, `IpAddress`, `Null`, `*IfExists`, `ForAnyValue/ForAllValues`, with `aws:PrincipalArn`, `aws:PrincipalOrgID`, `aws:SourceIp`, `aws:SourceVpce`, `aws:MultiFactorAuthPresent`, `sts:ExternalId`, `token.actions.githubusercontent.com:sub/aud`. Unknown condition keys resolve to `Unknown`, never silently to allow; the edge carries `evidence.unknown_conditions`. Policy variables `${aws:username}` substituted from context. Action matching case-insensitive glob; resource matching ARN-segment-aware (S3 object patterns cover buckets as `MatchesResource` does today).

**Graph contract.** `grants_access_to`, `can_assume`, `has_policy` edges carry `evidence.statements: [{policy_arn, sid|index, effect}]`, `evidence.denied_by`, `evidence.requires_conditions`. `can_assume` is emitted only when `Evaluate(sts:AssumeRole)` allows for both trust and caller identity (same-account trust naming the exact role ARN is the one exception, per AWS docs). SSE-KMS data stores need `kms:Decrypt` on the key policy; otherwise the edge is suppressed with `blocked_by: kms key policy` (today's `policyNode()` would draw it).

**Collectors.** `organizations:ListPoliciesForTarget/DescribePolicy` for SCPs and RCPs up the OU chain; `iam:GetAccountAuthorizationDetails` already fetched; S3/KMS/Secrets/SQS/Lambda resource policies; `sts:GetCallerIdentity` for org id. Lab: `governing_scps` attribute already exists on `nimbus-lab-batch-role` (`lab/local/estate.yaml` S14).

**Test corpus.** `internal/iam/testdata/corpus/*.yaml`, ≥ 200 cases, each `{policies, request, expect, source}`; sources: AWS policy-evaluation-logic documentation examples, PMapper's test suite patterns, pathfinding.cloud techniques, and 50 cases recorded from `iam:SimulatePrincipalPolicy` (`tests/e2e`, gated by `NIMBUS_E2E=1`, stored as fixtures so they run offline). Categories with minimum counts: Deny precedence 20, NotAction/NotResource 20, conditions 50 (incl. IfExists and set operators), SCP/RCP 25, boundary 15, resource policy and cross-account 30, KMS 10, policy variables 10, session policy 10, unknown keys 10.

**Acceptance.** Corpus 100%; `make groundtruth` strict: S01 no longer reported, `known_gaps.yaml` entry deleted; property test: for every lab principal and every (action, resource) pair in the lab, nimbus's decision equals the recorded simulator decision; a new seeded false positive F02 (`Allow s3:*` plus `Deny s3:GetObject` on the PII bucket) produces no `grants_access_to` edge; benchmark precision does not drop.

#### 3.2.2 Network reachability — `internal/reach`

**Design.** `Reachable(src Endpoint, dst Node, port, proto) Verdict{reachable bool, width wide|narrow|trusted|private, evidence []Hop, blocked_by *Control}`. Model, per cloud: AWS public IP / EIP / ENI → subnet route table has `0.0.0.0/0 → igw-` → NACL inbound allow and no earlier deny → SG allow → instance; ALB/NLB listener → target group → target; Lambda URL AuthType; RDS `PubliclyAccessible` AND subnet route AND SG. Azure: public IP → NSG on NIC AND NSG on subnet (fix the OR at `build.go:236-255`) → VM; Front Door/App Gateway listener. GCP: external IP → firewall rules by priority with deny (`gcp.go` `decide()` already orders rules; reuse) → instance network tags/SAs. Kubernetes: Service type LoadBalancer with `loadBalancerSourceRanges`, Ingress hosts, NetworkPolicy ingress. Every `exposes`/`allows_traffic_to` edge gets `evidence.hops` (rule ids, route ids, listener arns) and `blocked_by` when any control denies, replacing the existing `because` prose.

**Corpus.** `internal/reach/testdata/*.yaml`, ≥ 60 topologies: SG open + NACL deny; SG open + private subnet no IGW; ALB public + instance private (reachable via ALB only on 443, not 22); NLB preserving client IP; RDS public flag but no route; Azure NIC-NSG allow + subnet-NSG deny; GCP lower-priority allow shadowed by deny; LB with `loadBalancerSourceRanges` trusted.

**Acceptance.** Lab gains F03 (SG 0.0.0.0/0 on 22, NACL denies 22) and F04 (public RDS flag, isolated subnet) that must not produce paths; P02/P03 still found with `evidence.hops` non-empty; JSON schema test asserts every internet edge has `hops` or `blocked_by`.

#### 3.2.3 Exploitability evidence — `model.AttackPath.Validation` + `internal/verify`

**Design.** Add `Validation{Status theoretical|validated|refuted|unverifiable, Probes []ProbeResult{kind, target, request_summary, response_summary, at, consent_scope}}` to `model.AttackPath` and `model.Step`. Probes, all opt-in behind `verify --exposure --allow <cidr|arn list>` and a consent file, all read-only and rate-limited: anonymous `s3:ListBucket`/`GetBucketAcl` with no credentials; TCP connect + banner on the exposed port from the operator's host; `GET /version`, `/api` on a public EKS/GKE/AKS endpoint without a token (anonymous auth check); Lambda URL `GET` without auth; `iam:SimulatePrincipalPolicy` and GCP `projects.testIamPermissions` / Azure `checkAccess` for identity hops; S3 Access Analyzer external-access findings as corroboration. Never: exploitation, credential use beyond the operator's own, IMDS (unreachable externally; it stays `theoretical` with the reason stated). Secret values never stored (hash only), per `O24`.

**Scoring.** `validated` multiplies nothing; it is a status and a filter. `refuted` demotes the path to `Incomplete` with the probe as evidence. The dashboard header reads "N of M paths validated".

**Acceptance.** Lab-local HTTP/TCP fixtures: a fake bucket endpoint returning a listing → P01 `validated`; a fake closed port → F03 `refuted`; without `--allow` zero network calls (asserted by a recording transport); `grep` test proves no secret value in the DB.

#### 3.2.4 DSPM-lite — `internal/adapters/{macie,purview,gcpdlp,cyera,sentra}.go`

**Design.** Each adapter maps vendor labels to `data_sensitivity: {labels[], source, confidence, observed_at}` on the resource node. `looksSensitive` is kept but tagged `source: inferred`, and the risk factor says so (`risk.go` `labelsOf` already reads `dspm_labels`). Toxic rule `exposed+sensitive` requires `source != inferred` or a configured crown jewel to fire at the floor; inferred-only sensitivity scores ×1.2 not ×1.5.

**Acceptance.** Golden fixtures per vendor; lab bucket labelled by a Macie fixture raises P01 explanation to `label pii (source macie)`; the same bucket with only name evidence shows `inferred`; a decoy `three-prod-db` (matches `hr`, `prod`, `db`) with a `public` label scores non-sensitive.

#### 3.2.5 CI/CD pipeline paths — `internal/collector/saas/github.go` + `internal/attackpath/pipeline.go`

**Design.** Collect per repo: branch protection and rulesets (fix the 404-means-unprotected defect), workflow files (`.github/workflows/*.yml`) parsed for triggers (`pull_request_target`, `workflow_run`, `issue_comment`), `permissions`, `id-token: write`, secrets referenced, third-party actions pinned by tag vs SHA, environments with required reviewers, and the OIDC trust's `sub` condition from the AWS/GCP/Azure side. Entry likelihood becomes a function of who can reach the role: no `sub` condition → 1.0 from the internet node ("any GitHub repo in the world"); `repo:org/*` → 0.9 from any org member; `repo:org/repo:*` with `pull_request_target` and secrets → 0.8 from the internet; `ref:refs/heads/main` → BRANCH_UNPROTECTED 0.5, protected 0.15 (below floor). Edges: `repo -[can_assume {sub_condition, trigger}]-> role`; `action@tag -[runs_in]-> workflow` for unpinned third-party actions (the Trivy/KICS 2026 lesson in `docs/research/competitors/open-source.md` headline 3).

**Acceptance.** P12 reaches ≥ 7 with `evidence.sub_condition` present and the known gap deleted; a sibling scenario S15 with `sub: repo:nimbus-lab/infra-live:ref:refs/heads/main` and branch protection on scores < 5; S16 with no `sub` condition scores 10 from `internet`.

#### 3.2.6 Kubernetes RBAC — `internal/collector/k8s/rbac.go`

**Design.** Resolve every (Cluster)RoleBinding to effective verbs per subject per namespace. Emit `can_escalate_to` edges with `technique`: `escalate`/`bind` on roles; `impersonate` users/groups/SAs; `create pods` in a namespace holding a privileged SA (SA token theft); `pods/exec`, `pods/attach`, `pods/portforward` create; `secrets get|list|watch` (token theft, namespace- or cluster-wide); `nodes/proxy`; `serviceaccounts/token create`; `create` on `clusterrolebindings`; webhooks/CSR approval. Subjects `system:unauthenticated` and `system:authenticated` become edges from `internet` (with the API endpoint's exposure) — this is what makes P07 critical when it really is. Add cross-plane edges: SA annotation `eks.amazonaws.com/role-arn` or Pod Identity association → `can_assume` AWS role; GKE `iam.gke.io/gcp-service-account` → GCP SA; AKS federated credential → Azure identity; these feed 3.2.1.

**Acceptance.** Lab S17 (SA with cluster-wide `secrets list`, exposed pod) found ≥ 7 with technique `secrets-list-token-theft`; S18 (`system:unauthenticated` bound to a view role on a public endpoint) found; S19 (pod → SA → IRSA role → PII bucket) found with the AWS hop evaluated by 3.2.1; P07 as labelled stays medium (no credential route) unless anonymous auth is on.

#### 3.2.7 Cross-cloud identity federation — `internal/collector/saas/{okta,m365}.go` + `internal/iam/federation.go`

**Design.** Okta/Entra apps of type SAML/OIDC to AWS IAM Identity Center, AWS SAML providers, GCP workforce identity, Azure enterprise apps: emit `idp_group -[federates_to {app, attribute_mapping}]-> permission_set|role`. Entry weaknesses on the IdP side (no MFA, legacy auth, weak sign-on policy from `WEAK_AUTH`) flow through to cloud admin. Same for GCP Workload Identity Federation pools (`attribute.repository` conditions) and Azure federated identity credentials (`subject` claims), evaluated by the same `sub`-class logic as 3.2.5.

**Acceptance.** Lab S20: Okta group with MFA-exempt sign-on rule → Identity Center permission set `AdministratorAccess` scores ≥ 7 with entry `okta:group/...`; the same with MFA enforced scores < 5. Cartography's published schema (`EI1`) is the import fixture for the federation edges so a Cartography user gets the paths on day one.

### 3.3 Sequenced plan

**Phase 0 (finish, 2 weeks).** As plan v2, plus the adversarial lab in §5. Exit as written, with `GROUNDTRUTH_STRICT=1` green **and** the noise estate reporting 0 unlabelled paths ≥ 5. Claim: "the only CSPM that publishes its path-level precision and recall, including on a noisy estate".

**Phase 1 — Identity, reachability, evidence (Q4 2026 → Q1 2027), tracks in parallel:** T1 `internal/iam` AWS (3.2.1); T2 `internal/reach` AWS + Azure NSG AND fix (3.2.2); T3 Validation model + probes (3.2.3); T4 K8s RBAC verbs + cross-plane SA edges (3.2.6); T5 pipeline paths (3.2.5); T6 Prowler/pathfinding.cloud privesc port onto the evaluator (`O15`, keeping ids); T7 lifecycle/Issues/coverage (plan v2 Track G, unchanged). Exit: corpus 100%; S01, P12 gaps deleted; "N of M validated" on the lab; `who-can <action> <resource>` lists direct and transitive principals with statements and matches simulator fixtures. Claim: "the only open-source tool whose attack paths honour Deny, SCPs, conditions and KMS, and that tells you which paths it proved".

**Phase 2 — The loop on truthful paths (Q2 2027):** plan-time path diff, verified fix, root-cause plans, user rules with `risk test`, MCP server, right-sizing PRs from CloudTrail/Access Advisor, DSPM-lite, Okta/Entra federation (3.2.7), GCP IAM and Azure RBAC evaluators behind the same `internal/iam` interface. Exit: the 90-second demo (plan v2 §4) on the cloud lab with every path validated or labelled theoretical. Claim: "the only tool that shows in the PR which proven paths it opens or closes".

**Phase 3 — Distribution (Q3 2027):** OCSF/ASFF/Cartography interop, Vanta export, Action listing, Homebrew/Helm, CNCF application, public benchmark page re-run per release with Prowler, Cartography and Checkov on the same estate.

## 4. Twelve-month roadmap, five bets, five cuts

| Quarter | Focus | Exit evidence |
|---|---|---|
| Q4 2026 | Phase 0 close; first live-cloud run; adversarial lab; `internal/iam` AWS + `internal/reach` AWS | strict lab green; noise estate FP = 0 at ≥ 5; corpus ≥ 200 at 100%; live run report in `docs/sessions/` |
| Q1 2027 | K8s RBAC verbs, cross-plane SA edges, pipeline paths, privesc port, Validation + probes, Issues/lifecycle | S15–S20 found; "validated N of M" shipped; Prowler query ids runnable on nimbus's graph |
| Q2 2027 | Plan-time diff, verified fix, plans, right-sizing PRs, DSPM-lite, GCP/Azure evaluators, Okta/Entra federation | 90-second demo on the cloud lab; evaluator parity tests against `testIamPermissions`/`checkAccess` fixtures |
| Q3 2027 | Interop, GRC export, release trust kit polish, public benchmark vs peers, CNCF sandbox | benchmark page; three named adopters running the lab against their own estate |

**Five bets:** (1) corpus-verified effective IAM across four planes, (2) the cross-plane identity graph (K8s ↔ cloud ↔ IdP ↔ CI) as the thing no OSS tool has, (3) evidence-backed paths with a published validated ratio, (4) an adversarial, noisy, independently authored benchmark run against competitors, (5) the plan-time diff + verified-fix loop once 1–3 hold.

**Five cuts:** (1) FAIR/dollar risk (`O67`), (2) JIT access brokering (`ID7`), (3) agentic routines and "agent fleets" (`AI5`), (4) in-account DSPM sampler and classification (`O51`, `DS1`), (5) team mode/SSO/RBAC (`O60`). Also defer the graph DSL/no-code builder (`O14`), TV mode, executive PDF and the Vanta connector until the paths are right.

## 5. First ten engineering items (next two weeks), each with an acceptance test

1. **Noise estate** `lab/local/noise.yaml`: 300 benign resources with decoy names (`prod-admin-api`, `customer-portal-lb` open on 443 by design, unreachable admin roles, SGs open to 0.0.0.0/0 on 443 behind an ALB). Test: `make groundtruth` reports 0 unlabelled paths ≥ 5 and prints FP rate per hop kind.
2. **`internal/iam` core** (statement matching, Deny precedence, NotAction/NotResource, wildcards, variables): 60-case corpus from AWS documentation examples at 100%.
3. **SCP/RCP evaluation** from `governing_scps` (lab) and `organizations` (collector): S01 suppressed with `denied_by: p-lab0quarantine`; delete the known gap.
4. **Replace `IsAdmin`/`DataAccess`** with the evaluator; `grants_access_to` carries `statements`; new F02 (Allow `s3:*` + Deny on PII) draws no edge; lab recall unchanged.
5. **`can_assume` requires caller permission**: cross-account edges need identity-policy `sts:AssumeRole`; ExternalId condition evaluated, not just `HasCondition`. Test: a lab role trusting `999999999999:root` with no caller policy on record gets `evidence.caller_permission: unknown` and likelihood 0.4, not 0.7.
6. **KMS gate**: SSE-KMS buckets require `kms:Decrypt`; test fixture bucket + key policy denying the role → edge suppressed with `blocked_by`.
7. **CVE gating**: `exploitable()` and `exposesEval` require KEV, EPSS ≥ 0.5, or a reachable vulnerable service; bare `CVECount > 0` yields 0.3 and `validation: theoretical`. Test: W16 `CVE-2025-1974` keeps P08 ≥ 7 only if the snapshot has it in KEV/EPSS; a decoy pod with an EPSS-low CVE scores < 5.
8. **`internal/reach` AWS v1**: public IP + route table + NACL + SG; F03/F04 added and suppressed; P02 edge has `evidence.hops`.
9. **K8s RBAC verbs**: `can_escalate_to` with techniques for `secrets list`, `pods/exec`, `escalate`, `bind`, `impersonate`, `system:unauthenticated`; S17/S18 found.
10. **Validation field + JSON schema**: `model.AttackPath.Validation` with `theoretical` default; `paths --format json` validated by a schema test; dashboard header "0 of 21 validated" until probes land (honest zero).

## 6. The biggest risk and how to de-risk it

**The benchmark is self-referential.** The estate, the labels, the hop likelihoods and the floor were all written by the same session; the per-hop table in `docs/benchmark.md` was tuned until the labels passed (P02 5.69 → 7.60; four paths landing at exactly 7.00). Nothing has run against a live cloud. The first real estate will produce hundreds of `*admin*`/`*prod*` crown jewels, 0.95-likelihood paths from every exposed host with any CVE, and `grants_access_to` edges that a Deny or a key policy would have blocked. One public screenshot of that ends the "precision over volume" positioning (`docs/research/nimbus-gap-analysis.md` §d, defect 15 rationale).

**De-risk:** (a) the noise estate (item 1) written by a different agent from the one that tunes the engine, with a rule that `known_gaps.yaml` may list misses but never unlabelled paths ≥ 5; (b) the live-cloud run on `lab/terraform/` as the top item the moment credentials exist, with the diff between local and live results recorded in `docs/sessions/`; (c) every IAM decision cross-checked against recorded `SimulatePrincipalPolicy` fixtures, every reachability verdict against recorded VPC Reachability Analyzer results; (d) publish the validated ratio and the FP rate next to recall, so the number nimbus is judged on is the one an attacker would check; (e) freeze the hop table under `score_version` and require a corpus change, not a lab change, to move a weight.

## 7. Competitor features that are marketing for nimbus's purposes — skip

- **Dollar-denominated risk / FAIR dashboards** (Aqua, `docs/research/competitors/cnapp-leaders.md` best-in-class table): editable inputs produce whatever number the slide needs; nimbus's own ROI formula is already flagged heuristic (`nimbus-capability-inventory.md` §11).
- **"Attack paths" counted in the thousands and framework counts (185+, 2,500+ controls)** (Orca, `CO1`): volume is the opposite of what an attacker-grade tool should advertise.
- **Adversary-group tags on posture findings** (CrowdStrike): threat intel mapped onto misconfigurations adds colour, not reachability.
- **Agentic fleets, scheduled AI routines, "Red/Blue/Green agents"** (Tenable Hexa, Wiz agents, `AI5`): the 2026 bar is a read-only MCP server with guardrails; the fleets are a UI over the same queries.
- **Exploit execution in production** (Sweet Attack, Pentera): a credentialed security tool running attacks is a liability; read-only probes give the evidence without the risk (`docs/research/nimbus-gap-analysis.md` §f).
- **JIT brokering and runtime blocking** (`ID7`, `DR3`): write paths into IAM and hosts; out of scope by design, and every vendor selling it has a support organisation behind it.
- **Three-bucket verdicts and "0.04% noise" claims** (Sweet): require runtime telemetry nimbus does not have.
- **No-code graph builders and English-like DSLs** (SCC, J1QL, `IG6`): pleasant, but they do not change a single edge's truth; SQL plus a documented `paths` JSON is enough until the edges are right.
- **A 5×5 likelihood × impact matrix as a second lens** (ASH, PL steal #6): a coarser rendering of the same score; one published formula with `not scored` is more honest.

The capabilities that are not marketing, and that nimbus should be measured on, are the seven in §3.2. They are also the ones no open-source tool has and the ones a buyer's red team will test first.
