# Contributing to nimbus

Thanks for helping. The project follows `docs/development_methodology_and_coding_rulebook.md`; the
short version for contributors:

## Ground rules

1. **Failing test first.** Every behaviour change starts with a test that fails for the right reason,
   then the smallest change that makes it pass. Bug fixes include a regression test.
2. **Evidence, not claims.** A PR says what it changed and pastes the command output that proves it
   (`make verify` tail, a reproduction, a screenshot for UI changes). "Implemented" is not
   "verified".
3. **Precision over volume.** New checks or attack-path rules need fixtures showing a true positive
   and a near-miss that must *not* fire.
4. **No secrets anywhere.** Credentials come from the environment only. Never commit tokens, real
   account IDs or customer data; use `testdata/` fixtures.
5. **Small PRs**, one concern each, conventional-commit titles (`feat:`, `fix:`, `sec:`, `docs:`,
   `test:`, `ci:`, `chore:`). The release changelog is generated from them.

## Sign your commits (DCO)

nimbus uses the [Developer Certificate of Origin](https://developercertificate.org/), not a CLA
([OPEN_SOURCE_PROMISE.md](OPEN_SOURCE_PROMISE.md)). Every commit needs a `Signed-off-by:` trailer
whose email matches the commit author:

```sh
git commit -s -m "fix: ..."           # adds Signed-off-by: Your Name <you@example.com>
git rebase --signoff origin/main       # fix a branch that is missing sign-offs
```

`.github/workflows/dco.yml` checks every commit in a pull request. If you used an AI agent, you,
the human submitting the work, sign off and certify the DCO for it ([AGENTS.md](AGENTS.md)).

## Setup

```sh
go version            # Go >= the version in go.mod
make build            # bin/cloud-posture
python3 -m venv python/.venv && . python/.venv/bin/activate && pip install -e "python[dev]"   # optional layer
make ui-deps          # Playwright for the dashboard smoke test
```

## Before you open a PR

```sh
make verify
```

`make verify` runs `go vet`, `go test ./...`, the Python tests, the dashboard Playwright smoke test,
`govulncheck ./...` (installed if missing), `gosec -severity high -confidence high ./...` when gosec
is installed, and `make readme-check`. That last check fails when a README sentence with a number or a
superlative has no `<!-- claim: … -->` marker resolving to a Go test, a pytest node id or a docs
section. It must be green. If something cannot be verified locally (e.g. a live cloud), say so
explicitly in the PR.

Release tooling: `make release-snapshot` builds every platform archive, checksums and the container
image locally without publishing or signing.

## Don'ts

- Don't run `go mod tidy` in a PR that isn't about dependencies.
- Don't add GitHub Actions referenced by tag or branch; pin a full commit SHA with a `# vX.Y.Z`
  comment.
- Don't add `curl | sh` installs anywhere (Dockerfile, CI, docs).

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.

## Governance

How decisions are made and how to become a reviewer or maintainer: [GOVERNANCE.md](GOVERNANCE.md).
The plan you are contributing to: [ROADMAP.md](ROADMAP.md). If your organisation uses nimbus, add it to
[ADOPTERS.md](ADOPTERS.md). Imported third-party content must be listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) in the same pull request.

By contributing you certify the DCO for each commit, agree that your work is licensed under the Apache
License 2.0 ([LICENSE](LICENSE)), and agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
