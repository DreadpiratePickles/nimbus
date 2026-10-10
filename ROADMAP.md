# Roadmap

This is the public summary of the working plan,
[`.planning/IMPLEMENTATION_PLAN_v3.md`](.planning/IMPLEMENTATION_PLAN_v3.md) ("plan v3", assembled
2026-10-09). It follows the binding decisions in [`docs/council/decision.md`](docs/council/decision.md).
Where this summary and the plan disagree, the plan wins. Dates are targets, not promises.
Calendar: week 1 is the week of 2026-10-12.

**Rules the roadmap follows**
- **Truth before reach.** A capability counts as shipped only when it passes its acceptance test on
  the lab. Until then it is labelled `experimental`. Implemented ≠ deployed ≠ verified.
- **Claims are gated.** Each phase unlocks one public claim, and only when its exit criteria have
  executable evidence. Launch events (Show HN, newsletters, conference talks, Marketplace listing)
  wait until Phase 0 is closed. The plan-time path diff is marketed only after Phase 1.
- **The open-source promise holds throughout** ([OPEN_SOURCE_PROMISE.md](OPEN_SOURCE_PROMISE.md)).

## Where we are (2026-10-09)

**Phase 0 is not closed.** What it delivered is listed with evidence in plan v3 §0.1, and the full
record is in [`docs/sessions/2026-10-09-cwm-ui.md`](docs/sessions/2026-10-09-cwm-ui.md). In short:

- security hardening of the server, the SQL guard, PR writes and the Python layer, independently
  re-verified ([`docs/research/nimbus-capability-inventory.md`](docs/research/nimbus-capability-inventory.md), "Remediated 2026-10-09");
- attack-path correctness work and a hand-labelled synthetic lab, with published recall and precision
  ([`docs/benchmark.md`](docs/benchmark.md));
- one published risk score ([`docs/scoring.md`](docs/scoring.md));
- a release pipeline that signs, checksums, attests and builds an SBOM. **No release has been
  published yet.**

**Still open before Phase 0 can close** (plan v3 §0.2):

| # | Item | Blocked on |
|---|---|---|
| 0-1 | **First run against a live cloud account** (lab AWS account: apply, scan, score against ground truth, destroy) | owner: a lab AWS account and credentials |
| 0-2 | Independent re-verification of the last round of fixes | in progress |
| 0-3 | Remaining correctness leftovers (IaC edge cases, collector cancellation status, API filters) | in progress |
| 0-4 | A noise estate written by someone who has not seen the engine's tuning, and honest precision on it | in progress |
| 0-5 | `v0.2.0` signed and installable under one name | owner: name/org decision, repo settings, authorisation to tag |
| 0-6 | README claims match evidence (`make readme-check`) | this change |
| 0-7 | Repository hygiene (a credential rotation) | owner |
| 0-8 | Commit the Phase 0 tree | owner authorisation |

**Claim unlocked at Phase 0 exit:** "the only CSPM, open or closed, with a public ground-truth
benchmark (recall, precision, false-positive rate) re-run on every release, and signed,
provenance-attested releases."

## Phase 1: the data model, IAM v1, path Issues (weeks 1–6, to 2026-11-20)

- **Typed inventory graph** replacing name-based type guessing. Every edge carries `because`,
  confidence (`verified | inferred | hint`) and, for permissions, the granting statement.
- **Effective IAM evaluator v1** for AWS: Deny precedence, NotAction/NotResource, conditions
  (unknown → not allowed), permission boundaries, SCP/RCP, resource and KMS policies. At least a
  200-case corpus, cross-checked against recorded `SimulatePrincipalPolicy` results.
- **Path Issues with stable ids**, so a path keeps its identity across scans and can be resolved,
  reopened and verified. Resource history.
- **One rule engine** (the old chain rules migrate into attributed traversal rules), plus traversal
  scale work with explicit truncation.
- Built in parallel, launched later: the **plan-time path diff** on pull requests (a sticky comment
  saying which paths a change opens or closes, with a PR footer for the north-star metric), and a
  **read-only MCP server**.
- Distribution plumbing: OCSF 1.6, ASFF, GitLab SAST and JUnit outputs, `convert`, and the Prowler
  framework import (after the CIS-content licence decision).

**Claim unlocked at exit:** "the only open-source tool that evaluates effective IAM like AWS does,
turns every scanner's output into path-level Issues with stable ids, and tells a pull request which
attack paths it opens or closes."

## Phase 2: verify, right-size, evidence (Q1 2027)

- `verify`: a fix is "fixed" only after a targeted re-collect shows the path gone, with a window for
  eventual consistency. Tickets close only then.
- Right-sized IAM policies, proposed as pull requests that only remove permissions; `who-can`.
- **Azure RBAC, GCP IAM and Kubernetes RBAC as real permission edges**, plus Azure and GCP live labs.
  This is when the "AWS depth, Azure/GCP breadth" caveat can be retired.
- Reachability with compensating controls, and opt-in read-only probes ("N of M paths validated").
- Signed evidence v2 with GRC export, a detection timeline, and DSPM label ingest.

**Claim unlocked at exit:** "the only open-source tool that verifies a fix closed the path,
right-sizes policies into PRs, and ships auditor-grade signed evidence with GRC export."

## Phase 3: ecosystem (Q2 2027 onward)

- Cartography, Prowler history, Trivy Operator, Kubescape, kube-bench and Custodian adapters; SBOM ingest.
- Helm chart, more packages (homebrew-core once eligible, `.deb`/`.rpm`, scoop/winget).
- Benchmark v2: Prowler/Checkov/Trivy goldens on the live lab, and independent estates (CloudGoat,
  TerraGoat).
- A second and third maintainer from other organisations, then a CNCF sandbox application
  ([GOVERNANCE.md](GOVERNANCE.md)).

**Claim unlocked at exit:** "the open security graph: Cartography, Prowler, Trivy, Kubescape,
Custodian and Vanta plug in; agents reach it through a read-only MCP server."

## What we are deliberately not doing

From plan v3 §6. Each cut has a one-line reason there.

- No investment in the dashboard beyond maintenance. The CLI, static reports and MCP are the
  primary surfaces.
- Cost and ROI are reduced to one card. No dollar-denominated risk (FAIR).
- No Python re-implementations of Go logic: Python consumes Go output only.
- No JIT access brokering, no agentless snapshot scanning, no in-account data classifier.
- No team/MSP mode, SAML or SCIM in the near term (OIDC-lite no earlier than Q2 2027).
- No race for native check counts. We ingest Prowler and others instead.
- No launch events, and no KubeCon EU 2027 talk, before Phase 0 closes.

## Research behind the plan

- Strategy and distribution: [`docs/research/strategy-how-to-win.md`](docs/research/strategy-how-to-win.md)
- Competitors: [`docs/research/competitors.md`](docs/research/competitors.md) and [`docs/research/competitors/`](docs/research/competitors)
- Capability inventory and gaps: [`docs/research/nimbus-capability-inventory.md`](docs/research/nimbus-capability-inventory.md), [`docs/research/nimbus-gap-analysis.md`](docs/research/nimbus-gap-analysis.md)
- Feature matrix: [`docs/research/competitive-feature-matrix.md`](docs/research/competitive-feature-matrix.md)
- Council: [`docs/council/`](docs/council) (four independent reviews, cross-ranked; [decision](docs/council/decision.md))
- Metrics: [`docs/metrics.md`](docs/metrics.md)

Want to influence the roadmap? Open an issue. For anything in the RFC list in
[GOVERNANCE.md](GOVERNANCE.md#rfcs), open an RFC.
