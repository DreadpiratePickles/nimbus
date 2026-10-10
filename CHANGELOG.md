# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). GitHub release notes are generated from conventional
commits by goreleaser; this file is the curated summary.

## [Unreleased]

### Changed
- Risk score version 2.4.0: a resource reachable only through an exposed network control (security group or NSG) now scores Medium (5.0) instead of Low; no other weight changed (see docs/scoring.md changelog).

### Score changes (`score_version`, contract in `docs/scoring.md` § Changelog)
- **2.4.0** (wave 5): a resource reachable from the internet only through an exposed network control (a
  security group or NSG "jump" shape) scores like direct exposure: the lab's jump-01 3.6 Low → 5.0 Medium.
  No weight changed.
- **2.3.0** (wave 4): the internet-reachability verdict (`graph.Verdict`) feeds the `exposure` factor; a
  REACH-blocked resource is `not exposed (blocked: <reason>)` whatever its `PUBLIC_*` weakness says, and an
  unknown verdict keeps the width labelled `inferred`. Trusts limited by `aws:PrincipalOrgID` /
  `PrincipalOrgPaths` / `PrincipalAccount` are not external entries; `sts:ExternalId` / `SourceIdentity`
  trusts are entry likelihood 0.3 (was 0.4) with no identity floor. Lab: Critical findings on non-exposed
  resources 1 → 0 (`risk.CriticalOnNonExposed`).
- **2.2.0** (wave 3): a bounded combination replaces the flat cap at 10 (`7.0 + 3.0 × (1 − e^(−(raw − 7.0) / 4.5))`
  above the 7.0 knee); lab findings at 10.0 41/62 → 5/62; Critical needs raw ≥ ≈ 11.9. Stored scores and Issue
  severities move at the next ingest.
- **2.1.0** (the previous entry): `off_path` ×0.5 with a 6.9 ceiling, `attack_path` 0.12 / max 2.0,
  `identity.admin` 1.25.

### Added (waves 3–4, `docs/sessions/2026-10-09-cwm-ui.md`, `docs/sessions/2026-10-10-wave5.md`)
- Plan-time attack-path diff (`pr-comment --plan-json`): opens / escalates / lowers / closes headline and
  footer counters, sticky comment redacted by default on public repositories, `--fail-on-opened` /
  `--opened-only` gate, one-click GitHub suggestions (one block per hunk, posted as review comments with a
  confidence label) when `--iac` is given; the Action passes `--iac` by default (`suggestions` input).
- `verify <issue>`: targeted re-collect of the resources an Issue rests on, with backoff for eventual
  consistency; the ticket closes only when the Issue is verified fixed.
- MCP server (`cloud-posture mcp`): tools sql, schema, paths (attack-path Issues with their variants), issue,
  explain, coverage, who_can, prioritize, verify (read-only report), summary; simulate_fix / draft_fix with
  `--scope fix`. Default scope `read`; redaction on by default (account ids, ARN accounts, GCP projects, AWS
  resource ids, IPs, tag values, also inside verdict text); JSONL audit log.
- Reachability model (P2-REACH): route tables, IGW/NAT, NACLs, ELBv2; `paths --exposures` with a verdict and the
  blocking rule; `who-can` lists the internet and the organisation first.
- Governance: owner rules, SLA / grace, MTTR metrics, per-owner digests (Slack / stdout), `governance init`.
- One row per attack-path Issue everywhere (CLI, API, dashboard, copilot); rule chains fold into traversal
  paths (lab path Issues 25 → 19, recall unchanged); PassRole fix template (minimum fix set 95.5 %).
- Scanner normalisation: Checkov 72.6 %, Trivy 88.3 % of golden findings mapped; 20 new canonical entries.
- Benchmark: real-world precision column, finding-level row, `make readme-bench` / `make readme-check`.
- Copilot: engine verdicts (exposure, path Issues, who-can through the Go evaluator), `--show-sql`, binary
  discovery (`CLOUD_POSTURE_BIN`, PATH, beside the package, `./bin`).

### Security (waves 4–5)
- MCP SQL runs over redacted views (no raw id reaches an SQLite function; LIKE oracle blind; errors redacted).
- Python copilot: every SQL statement goes through one guarded entry point; model-chosen SQL is refused when it
  transforms or aliases identifiers; the redactor is seeded from every account-like column.
- Sink URL policy: https only, link-local / metadata / private ranges refused (metadata always, IPv6 zones
  refused, NAT64 / 6to4 / Teredo forms decoded), credentials and request bodies never follow a cross-origin
  redirect; sticky comment edits only the bot's own comment; `action.yml` event allowlist.

### Changed
- Release workflow runs the strict ground truth, `readme-bench -check` and `make readme-check` before
  goreleaser, and refuses a tag without a `## [<version>]` section in this file.

**Earlier in this cycle:** summary of the 2026-10-09 session (`docs/sessions/2026-10-09-cwm-ui.md`).

### Added
- Dashboard redesigned with the general look of the cwm window manager (not a window manager):
  menu-style navigation, white panels, right-hand detail pane, hash routing, keyboard navigation;
  Playwright smoke test (`make ui-test`, 16 checks).
- Research and planning: competitor sweep, capability inventory, gap analysis and
  `.planning/IMPLEMENTATION_PLAN_v2.md` ("fix the path, not the finding").
- Release trust kit (Track E): goreleaser config for linux/darwin/windows × amd64/arm64 with
  `-trimpath` and ldflags-injected version/commit/date; cosign keyless signatures (Sigstore bundles) on
  checksums and archives; SPDX SBOMs; multi-arch distroless non-root image with BuildKit SBOM and
  provenance; SLSA build provenance via `actions/attest-build-provenance`; draft-then-publish flow
  for immutable releases; Homebrew cask in `DreadpiratePickles/homebrew-tap`.
- OpenSSF Scorecard and CodeQL workflows; Dependabot (gomod, pip, github-actions, npm, docker).
- `make verify` (vet, tests, pytest, ui smoke, govulncheck, gosec high) and `make release-snapshot`.
- SECURITY.md (disclosure, supported versions, signing/verification, all-at-once credential
  rotation), CONTRIBUTING.md, CODE_OF_CONDUCT.md (Contributor Covenant 2.1), CODEOWNERS, issue and PR
  templates, LICENSE (Apache-2.0 text; the project was already declared Apache-2.0).

### Changed
- `cloud-posture version` reports `0.1.0-dev (…)` for source builds and the tag, commit and build date
  for releases.
- `install.sh` installs only tagged releases, verifies `checksums.txt` and (when cosign is present,
  or mandatory with `--require-signature`) the cosign signature, refuses on mismatch, supports
  `VERSION=` / `INSTALL_DIR=`, never uses sudo or pipes further scripts into a shell.
- GitHub Action installs a pinned, verified release with the `install.sh` from its own commit
  instead of `curl | bash` from `main`; inputs reach shell steps via env vars only.
- Dockerfile: static Go binary on `gcr.io/distroless/static:nonroot` (uid 65532), base images pinned
  by digest, `.dockerignore` keeps `.venv`, local state and reports out of the context. The Python
  layer and third-party scanners are no longer baked into the image.
- All GitHub Actions in workflows and `action.yml` pinned by full commit SHA.
- README: install/verify section rewritten; overstated claims corrected (IaC coverage beyond
  Terraform needs checkov or trivy; auto-close is GitHub Issues only; no Windows installer;
  credentials can be persisted by `onboard`/config).

### Security
- Hardening track (inventory defects 1, 2, 3, 4, 5, 8, 11, 12, 14): read-only SQL enforced in Go and
  Python; view-identifier injection closed; `/api/alerts` SSRF/credential exfiltration closed;
  server binds loopback by default with token auth, Host check, CSRF guard, timeouts and body limits;
  auto-PR path containment and same-file read/write; secrets redacted from errors and help; Python
  layer no longer auto-executed from the working directory; CI gates use only the current scan's
  findings.
- Supply chain (inventory defect 13): no `curl | sh` from `main` in the Action, installer or image.

## [0.1.0] - 2026-10-08

### Added
- Initial release of the unified multi-cloud CSPM: Go core (collectors, scanner adapters, canonical
  catalog, SQLite store, attack-path graph, risk scoring, remediation, compliance, integrations,
  dashboard) and Python intelligence layer. Never validated against a live cloud account.

[Unreleased]: https://github.com/DreadpiratePickles/nimbus/compare/6db17c4...HEAD
[0.1.0]: https://github.com/DreadpiratePickles/nimbus/commit/6db17c4
