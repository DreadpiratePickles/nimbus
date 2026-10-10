# The nimbus open-source promise

nimbus (binary `cloud-posture`) holds read access to other people's clouds. People will only build on
it if they can trust that the project will not change the deal later. This file is that deal. It is
written before the first release so that it is a commitment, not a reaction.

The project name is not final: the single-name decision is pending (owner action O3 in
[`.planning/IMPLEMENTATION_PLAN_v3.md`](.planning/IMPLEMENTATION_PLAN_v3.md)). The promise follows the
project under whatever name it takes.

## 1. The licence

- **The core is Apache-2.0, forever.** "The core" is everything in this repository: the Go binary, the
  optional Python layer, the GitHub Action, the VS Code extension, the dashboard, the lab and the docs.
  It also covers every future contribution to this repository.
- **No relicensing without a public RFC.** A licence change for the core, including a move to a
  source-available licence (BSL, SSPL, Elastic, "fair source" or anything similar), may only be
  proposed as a public RFC under [GOVERNANCE.md](GOVERNANCE.md#rfcs). The RFC stays open for comments for
  at least 30 days. This promise forbids any change that takes away a freedom users already have.
- **Releases are never retracted from the licence.** Every release published under Apache-2.0 stays
  under Apache-2.0. The Apache licence already guarantees this; we repeat it here so nobody has to look
  it up.

## 2. DCO, never a CLA

- Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/):
  every commit carries `Signed-off-by:` (`git commit -s`), and
  [`.github/workflows/dco.yml`](.github/workflows/dco.yml) checks it on every pull request.
- **There is no Contributor Licence Agreement and no copyright assignment.** Contributors keep their
  copyright. Because nobody holds every contributor's rights, nobody can quietly relicense the code.
  That is the point.
- A commit written with an AI agent is signed off by the human who submits it. That human certifies
  the DCO for it (see [AGENTS.md](AGENTS.md)).

## 3. What may ever be paid: the buyer-based rule

We adopt GitLab's stewardship rule
([handbook](https://handbook.gitlab.com/handbook/company/stewardship/)):

> **If the likely buyer is an individual contributor, the feature is open source.**

Anything an individual engineer needs to find an attack path, understand it and fix it stays in the
open-source core. Paid offerings, if they ever exist, are limited to what a buyer who manages people,
tenants or audits needs. Examples:

- SAML/OIDC single sign-on, SCIM, role-based access control and an audit log for a shared server;
- multi-tenant / MSP mode;
- long retention and period reporting beyond what a single team needs;
- approval workflows for fix pull requests across teams;
- two-way ticketing sync with SLAs;
- high-availability deployment;
- a hosted service, support contracts, training and custom content (services).

**Today none of these exist and nothing is for sale.** There is no company behind nimbus yet. The
strategy research ([`docs/research/strategy-how-to-win.md`](docs/research/strategy-how-to-win.md) §6)
sets the order: no paid features before the placement milestones, and services before any paid
software.

## 4. Never paid: the explicit list

The following stay in the Apache-2.0 core, fully maintained, for every user, forever:

1. **Attack paths**: path detection on every supported cloud, scoring (the published formula in
   [`docs/scoring.md`](docs/scoring.md)), choke points, break-the-path, the minimum fix set, path
   Issues, and, as they land, the plan-time path diff on pull requests, `who-can` and the effective IAM
   evaluator.
2. **Fixes**: every fix template, in-place IaC patches, fix pull requests and the PR footer, `plan`,
   and verification that a fix closed the path.
3. **Adapters and collectors**: every scanner adapter (Prowler, ScoutSuite, Checkov, Trivy, Steampipe,
   native JSON, and any added later), every cloud and SaaS collector, and every input/output format
   (SARIF, OCSF, ASFF, JSON, CSV, Cypher).
4. **The MCP server** over the local graph, with its read-only guardrails, and bring-your-own-model AI.
5. **The benchmark**: the lab, the ground truth, the noise estate, the scanner golden outputs, the
   harness and every published number ([`docs/benchmark.md`](docs/benchmark.md)).
6. Also never paid: the CLI, the GitHub Action, the local dashboard and static reports, SQL over the
   local database, compliance mappings and evidence bundles, signed releases with SBOM and provenance,
   and security fixes for every supported release.

## 5. Things we will not do

- **Move a feature from open source to paid.** An open-source feature is never removed in favour of a
  paid one, and it is never left unmaintained while a paid version improves (the CloudQuery plugin
  pattern).
- **Restrict content.** Rules, path definitions, fix templates and framework mappings are never put
  under a more restrictive licence than the code (the Semgrep rules pattern).
- **Decline a pull request because it competes with a paid feature.** If a contribution fits the open
  core under rule 3, it is reviewed on its merits.
- **Phone home.** nimbus sends no telemetry. The project measures adoption only from public signals
  ([`docs/metrics.md`](docs/metrics.md)).

## 6. Changing this promise

This file can only be changed through a public RFC ([GOVERNANCE.md](GOVERNANCE.md#rfcs)). A change may add
commitments. It may not weaken one for code, content or features that already shipped. Why this
matters: the HashiCorp (BSL → OpenTofu), Semgrep (rules → Opengrep) and CloudQuery (plugins → paid)
precedents are summarised in [`docs/research/strategy-how-to-win.md`](docs/research/strategy-how-to-win.md) §6.2.
