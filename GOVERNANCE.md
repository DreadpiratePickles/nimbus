# Governance

This file describes how nimbus (binary `cloud-posture`) is run today, how decisions are made, and how
the project moves from one maintainer to several. It is honest about where we are: **nimbus currently
has a single maintainer.** The strategy research lists that as the main reason open-source security
tools stall ([`docs/research/strategy-how-to-win.md`](docs/research/strategy-how-to-win.md) §2.3).
This file exists to change that.

Related: [MAINTAINERS.md](MAINTAINERS.md) (who), [OPEN_SOURCE_PROMISE.md](OPEN_SOURCE_PROMISE.md) (what
never changes), [CONTRIBUTING.md](CONTRIBUTING.md) (how to contribute), [SECURITY.md](SECURITY.md)
(vulnerabilities), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [ROADMAP.md](ROADMAP.md).

## Stage 1 (today): benevolent dictator, in the open

- The founding maintainer (see [MAINTAINERS.md](MAINTAINERS.md)) has the final say on technical and
  project decisions.
- They must exercise that say in public. Decisions are made in issues, pull requests or RFCs, with the
  reasons written down. Planning documents are in the repository: [`.planning/`](.planning) and the
  decision record [`docs/council/decision.md`](docs/council/decision.md).
- The BDFL cannot override [OPEN_SOURCE_PROMISE.md](OPEN_SOURCE_PROMISE.md). Changing it takes an RFC.

## Stage 2: maintainers from more than one organisation

The project moves to stage 2 when [MAINTAINERS.md](MAINTAINERS.md) lists at least two maintainers from
at least two organisations. From then on:

- Decisions use **lazy consensus** among maintainers. A decision stands if no maintainer objects
  within the review window (below).
- If consensus fails, maintainers vote. A simple majority of maintainers decides, and each
  organisation's votes together count as at most half of the total.
- The founding maintainer has no veto. Changes to the licence, to OPEN_SOURCE_PROMISE.md or to this
  file need a two-thirds majority after an RFC.
- The project applies to the CNCF sandbox (plan v3 Phase 3, track P3-COMMUNITY). If accepted, CNCF
  governance requirements take precedence over this file where they conflict.

## Roles

| Role | What they do | How you get it |
|---|---|---|
| Contributor | Opens issues and pull requests (DCO sign-off on every commit). | Anyone, under the [Code of Conduct](CODE_OF_CONDUCT.md). |
| Reviewer | Reviews pull requests in an area they know, for example adapters, IaC fixes or the lab. Their approval counts toward merging in that area. | Several merged, non-trivial contributions in the area; a maintainer proposes it in an issue, and lazy consensus applies. |
| Maintainer | Merges, cuts releases, triages security reports and owns parts of the roadmap. Listed in [MAINTAINERS.md](MAINTAINERS.md). | Sustained reviewing and contribution over at least three months; nominated by a maintainer in a public issue; lazy consensus of the existing maintainers (in stage 1, the BDFL's approval). |
| Emeritus | A former maintainer, credited but with no merge rights. | On request, or after six months of inactivity, with notice. |

Maintainers must keep 2FA on and follow the credential rules in [SECURITY.md](SECURITY.md).
Release-signing and repository-admin rights are limited to maintainers who need them.

## How decisions are made

1. **Everyday changes** go through pull requests. Each PR needs one maintainer approval (or reviewer
   approval in the reviewer's area), a green CI and DCO sign-off. PRs must carry evidence: a test that
   failed first, then the output of `make verify` ([CONTRIBUTING.md](CONTRIBUTING.md)).
2. **Claims need evidence.** A sentence in the README with a number or a superlative must link to a
   test or a benchmark section, and `make readme-check` enforces this. "Implemented" is not "verified".
   No phase's public claim is used before its exit criteria have executable evidence
   ([ROADMAP.md](ROADMAP.md)).
3. <a id="rfcs"></a>**RFCs** are needed for changes that are hard to undo, or that users rely on:
   - the licence, OPEN_SOURCE_PROMISE.md or this file;
   - a new `score_version` of the published risk or path formula ([`docs/scoring.md`](docs/scoring.md));
   - breaking changes to the CLI, the database schema or the output schemas;
   - removing a capability or a supported cloud;
   - adding a new class of runtime dependency, or anything that sends data off the machine.

   An RFC is a GitHub issue labelled `rfc`. It states the problem, the proposal, the alternatives, and
   how it will be verified. It stays open for at least 14 days (30 days for licence or promise
   changes). The outcome and its reasons are recorded in the issue and in `docs/`.
4. **Review window** for lazy consensus: 7 days. Security fixes are exempt (see below).

## Security response

The full policy is in [SECURITY.md](SECURITY.md). In summary:

- Report privately via GitHub private vulnerability reporting. We acknowledge within 3 working days.
  The default embargo is 90 days or the release of a fix, whichever comes first.
- Maintainers triage in a private advisory. A fix can merge without the lazy-consensus window. It
  still needs a test that failed first.
- If a credential is suspected compromised, **every** project credential is rotated in one window
  (SECURITY.md "Credential rotation policy").
- A wrong result (a false critical path, or a fix that does not close what it claims) is handled as
  a correctness incident: we publish the rule, the fix, the affected ids and the release (SECURITY.md
  "Correcting a wrong result").

## Code of conduct

The [Code of Conduct](CODE_OF_CONDUCT.md) applies everywhere the project operates. The maintainers
enforce it. Reports go to the private address in SECURITY.md until a dedicated conduct contact exists.

## Changing this file

Changes go through an RFC. In stage 1, the BDFL approves. In stage 2, a two-thirds majority of
maintainers is needed.
