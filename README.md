# nimbus · `cloud-posture`

> **Name:** the project is called `nimbus` and the binary `cloud-posture` until the single-name decision (O3 in [ROADMAP.md](ROADMAP.md)) lands; both will then change together.

**An open-source, local-first security graph for cloud posture.** nimbus ingests the findings you
already have (Prowler, ScoutSuite, Checkov, Trivy, Steampipe) plus its own agentless collectors,
builds one graph, and reduces it to the attack paths that reach your crown jewels. For each path it
shows the fix that breaks it, the Terraform patch or pull request that applies the fix, and the SQL to
check it. It is a single Go binary with a published scoring formula and no SaaS. You can bring your
own AI model.

> **Status: pre-release (`0.1.0-dev`). nimbus has not yet been run against a live cloud account.**
> Every collector is tested against fake SDK clients, and every attack-path number below comes from a
> synthetic, hand-labelled lab. No signed release has been published yet, so build from source.
> What is verified and what is not is listed below, with links to the tests. <!-- claim: docs/benchmark.md#cloud-lab-validated-never-applied, internal/collector/aws/TestCollectGraph, internal/collector/azure/TestCollectGraph, internal/collector/gcp/TestGraph, internal/collector/k8s/TestGraph, TestGitHubCollect, TestOktaCollect, TestM365Collect -->

## What it does today, and the evidence

"Lab-tested" means it passes on the synthetic lab ([`docs/benchmark.md`](docs/benchmark.md)).
"Unit-tested" means it is covered by tests with fixtures or fakes. "Experimental" means it works in tests but
sits outside the current plan's core, and no quality claim is made for it
([ROADMAP.md](ROADMAP.md#what-we-are-deliberately-not-doing)).

| Capability | State | Evidence |
|---|---|---|
| Ingest Prowler (OCSF), ScoutSuite, Checkov, Trivy, Steampipe and native JSON into one model | unit-tested | `TestProwlerOCSF`, `TestScoutSuite`, `TestCheckov`, `TestTrivy`, `TestSteampipe`, `TestNativeTypedRelations` <!-- claim: TestProwlerOCSF, TestScoutSuite, TestCheckov, TestTrivy, TestSteampipe, TestNativeTypedRelations --> |
| Multi-hop attack paths from internet, identity and repository entry points to crown jewels; every hop explains itself (`because`) | lab-tested | `TestTraverseFindsMultiHopPaths`, `TestEveryStepHasBecause`, `TestGroundTruth` <!-- claim: TestTraverseFindsMultiHopPaths, TestEveryStepHasBecause, tests/groundtruth/TestGroundTruth --> |
| Path score = likelihood × priority with a published per-hop table and a documented toxic-combination floor | lab-tested | [`docs/benchmark.md`](docs/benchmark.md#path-likelihood-table-traversal-b2), `TestLabCalibration`, `TestToxicFloorScope` <!-- claim: docs/benchmark.md#path-likelihood-table-traversal-b2, TestLabCalibration, TestToxicFloorScope --> |
| Trusted-CIDR suppression of the seeded false positive | lab-tested | `TestTrustedExposureSuppressesF01`, `TestTrustedCIDRSuppressedThroughCLI` <!-- claim: TestTrustedExposureSuppressesF01, TestTrustedCIDRSuppressedThroughCLI --> |
| Choke points and an exact, re-verified minimum fix set (`paths --fixes`, `plan`) | unit-tested | `TestMinFixSetIsExactAndVerified`, `TestExactCoverBeatsGreedy`, `TestSimulateMatchesRetraversal` <!-- claim: TestMinFixSetIsExactAndVerified, TestExactCoverBeatsGreedy, TestSimulateMatchesRetraversal --> |
| Finding risk score on a 1–10 scale with published weights, an explanation that reproduces the number, and KEV/EPSS from an embedded offline snapshot | unit-tested | [`docs/scoring.md`](docs/scoring.md), `TestExplainReproducesScore`, `TestWeightsDocumented`, `TestNoNetworkUsesSnapshot` <!-- claim: docs/scoring.md#formula, TestExplainReproducesScore, TestWeightsDocumented, TestNoNetworkUsesSnapshot --> |
| Terraform: native scan, and an in-place patch that refuses ambiguous targets and must not widen access | unit-tested | `TestScanAndPatch`, `TestPatchRefusesDuplicateYorTrace`, `TestMapCloudToCodeRefusesNonUniqueAddress` <!-- claim: TestScanAndPatch, TestPatchRefusesDuplicateYorTrace, TestMapCloudToCodeRefusesNonUniqueAddress --> |
| Fix templates (Terraform, CloudFormation, Bicep, Kubernetes) with metadata and validation SQL; generated commands never auto-approve | unit-tested | `TestEveryTemplateHasCompleteMetadata`, `TestValidationSQLRunsOnStore`, `TestNoGeneratedCommandAutoApproves` <!-- claim: TestEveryTemplateHasCompleteMetadata, TestValidationSQLRunsOnStore, TestNoGeneratedCommandAutoApproves --> |
| Fix pull requests (`fix --auto-pr`) that write only inside the repository | unit-tested (local git, not GitHub) | `TestOpenFixPRWritesTheFileItRead`, `TestOpenFixPRRejectsEscapingPaths` <!-- claim: TestOpenFixPRWritesTheFileItRead, TestOpenFixPRRejectsEscapingPaths --> |
| SQL over the local database, behind a read-only guard | unit-tested | `TestReadOnlyGuardBlocksBypasses`, `TestReadOnlyEngineLayers` <!-- claim: TestReadOnlyGuardBlocksBypasses, TestReadOnlyEngineLayers --> |
| Collectors: AWS, Azure, GCP, Kubernetes, GitHub, Okta, M365 | unit-tested against fake SDK clients; **never run live** | `internal/collector/aws/TestCollectGraph`, `internal/collector/azure/TestCollectGraph`, `internal/collector/gcp/TestGraph`, `internal/collector/k8s/TestGraph`, `TestGitHubCollect` <!-- claim: internal/collector/aws/TestCollectGraph, internal/collector/azure/TestCollectGraph, internal/collector/gcp/TestGraph, internal/collector/k8s/TestGraph, TestGitHubCollect, docs/benchmark.md#cloud-lab-validated-never-applied --> |
| SARIF output, pre-commit hook, GitHub Action | unit-tested; the Action has no end-to-end run yet | `TestSARIFCleanScanHasEmptyResultsArray`, `TestPreCommitHookDoesNotStore` <!-- claim: TestSARIFCleanScanHasEmptyResultsArray, TestPreCommitHookDoesNotStore --> |
| Compliance reports from control mappings (CIS, NIST SP 800-53, PCI DSS, HIPAA, GDPR, ISO/IEC 27001, SOC 2), evidence ZIP | unit-tested; mappings, not certifications; CIS text licence pending ([notices](THIRD_PARTY_NOTICES.md)) | `TestReportAndDerivation` <!-- claim: TestReportAndDerivation --> |
| Alerts (Slack, Teams, PagerDuty, Jira, GitHub Issues, Datadog, Splunk, Sentinel, Elastic, webhook, syslog) | experimental | `TestDispatchRulesSuppressionsAutoClose`, `TestAlertExitsNonZeroWhenAnySinkFails` <!-- claim: TestDispatchRulesSuppressionsAutoClose, TestAlertExitsNonZeroWhenAnySinkFails --> |
| Change detection by polling CloudTrail, Azure Activity Log and GCP audit logs (`monitor`); this is polling, not real time | experimental | `TestPollCheckpointsAndDedup`, `TestMapCloudTrail` <!-- claim: TestPollCheckpointsAndDedup, TestMapCloudTrail --> |
| Optional Python layer: AI copilot with offline fallback, HTML/PDF reports, FastAPI server | experimental; being reduced to consume Go output only | `python/tests/test_ai.py::test_explain_offline`, `python/tests/test_copilot.py::test_policy_generation_offline` <!-- claim: python/tests/test_ai.py::test_explain_offline, python/tests/test_copilot.py::test_policy_generation_offline --> |
| Static and live dashboard, Neo4j/Cypher export, cost card | maintenance only | `TestRenderNoExternalSources`, `internal/neo4j/TestStatements`, `TestROIMath` <!-- claim: TestRenderNoExternalSources, internal/neo4j/TestStatements, TestROIMath --> |

## Coverage, stated plainly

- **Live clouds:** not yet run against a live cloud account. The Terraform twin of the lab exists but has been validated with OpenTofu but never applied. That first live run is item 1 of the plan, and it is blocked on a lab AWS account. <!-- claim: docs/benchmark.md#cloud-lab-validated-never-applied -->
- **AWS depth, Azure/GCP breadth.** AWS has the deepest collector: policy analysis that classifies admin as none, conditional or full, account-level S3 Block Public Access, and trust analysis. Azure and GCP collectors cover exposure and configuration (NSG/firewall evaluation, public storage, default service accounts), but identity is not yet modelled as permission edges (Azure RBAC, GCP IAM). That is Phase 2 work. <!-- claim: TestAdminLevel, TestS3AccountLevelBlockPublicAccess, TestNICAndSubnetNSGAreANDed, TestEvaluateIngressPriorityZeroAndRanges -->
- **Effective IAM:** policies are evaluated by a pure-Go evaluator (`internal/iam`: identity, resource, boundary, SCP/RCP and session policies, conditions; an unknown condition key never grants). It is tested against an adversarial corpus and recorded simulator fixtures, not yet against a live account's `SimulatePrincipalPolicy`. <!-- claim: internal/iam/TestCorpus, internal/iam/TestSimulatorParity -->
- **IaC: Terraform first.** Native scanning, cloud-to-code mapping (`--tfstate`) and in-place patches support Terraform. CloudFormation, Bicep, Kubernetes, Helm, CDK, Pulumi and Ansible are scanned when Checkov or Trivy is installed, and their output is ingested. Fix templates exist for CloudFormation, Bicep and Kubernetes, but there is no in-place patching for them. <!-- claim: TestScanAndPatch, TestMapCloudToCodeResolvesModuleAddress, TestYAMLTemplatesParse -->

## Benchmark (synthetic lab)

<!-- BEGIN readme-bench: generated by `make readme-bench` from lab/local/out/benchmark.json; edit tools/readme-bench, not this block -->
Both estates are scored on every `make groundtruth`. The labelled lab is a seeded, deliberately vulnerable estate across seven accounts (AWS, Azure, GCP, EKS and GitHub) with 21 expected attack paths plus false-positive and pending-feature labels; the noise estate was written by an independent author. Numbers from `benchmark.json`, measured **2026-10-10**, synthetic estates only (`live_cloud: false`): <!-- claim: docs/benchmark.md#honest-numbers-2026-10-09-labelled-and-real-world, tests/groundtruth/TestGroundTruth, tests/groundtruth/TestNoiseEstate -->

<!-- claim-table: docs/benchmark.md#honest-numbers-2026-10-09-labelled-and-real-world tests/groundtruth/TestGroundTruth tests/groundtruth/TestNoiseEstate -->
| metric | labelled lab (project-authored) | noise estate (independent author) |
|---|---|---|
| expected paths (labels) | 21 | 3 |
| reported paths (all / score ≥ 7) | 23 / 22 | 4 / 4 |
| precision, labelled | 100.0% (23/23) | 100.0% (4/4) |
| precision, real-world | 100.0% (23/23) | 100.0% (4/4) |
| precision@7, real-world | 100.0% (22/22) | 100.0% (4/4) |
| recall (any score), real-world | 100.0% (21/21) | 100.0% (3/3) |
| recall@7, labelled / real-world | 95.2% (20/21) / 95.2% (20/21) | 100.0% (3/3) / 100.0% (3/3) |
| recall in band, real-world | 100.0% (21/21) | — |
| unlabelled paths | 0 | 0 |
| real-world false positives | 0 | 0 |
| finding level: Critical findings on a blocked, false-positive or pending-feature resource (target 0) | 0 of 66 ranked | — |
| finding level: such resources in the `prioritize` top 10 (target 0) | 0 | — |

**Read these numbers with care.** The labelled lab and its labels were written by the project that tuned the engine. The noise estate was written independently, but the engine's noise round was tuned on its false positives, so its precision is in-sample, not held-out. Checkov and Trivy golden outputs of the lab Terraform are scored separately (`make groundtruth-golden`). No live cloud has been scanned yet. This is a regression benchmark, not a comparison with other tools. <!-- claim: docs/benchmark.md#noise-estate-independently-authored, docs/benchmark.md#scanner-interop-checkov--trivy-goldens, tests/groundtruth/TestGoldenScannerInterop -->
<!-- END readme-bench -->

Reproduce: `make groundtruth` (known gaps tolerated) or `GROUNDTRUTH_STRICT=1 make groundtruth`.

## Try it on the lab

This is real output of the binary built from this tree, regenerated by `go run ./tools/readme-bench -transcript`; the release workflow fails when it no longer matches (`-check`). Issue ids are per database, so they appear as `<issue-id-N>`.

<!-- BEGIN readme-transcript: generated by `go run ./tools/readme-bench -transcript` from a source build on the lab with CLOUD_POSTURE_NO_NETWORK=1 (Issue ids are per database, shown as <issue-id-N>); release.yml fails when it is stale -->
```text
$ make build
$ ./bin/cloud-posture ingest lab/local/out/estate.findings.json --source native --config lab/local/cloud-posture.lab.yaml
Ingest complete: 66 open findings in 99 results (scanner evidence).
88 open Issues: 20 attack path Issues (23 hop variants) + 68 finding Issues; 12 critical (2 path, 10 finding)
Findings by provider: aws=45  azure=3  gcp=7  github=1  kubernetes=9  okta=1
Attack paths: top Issue <issue-id-1> 10.0 Critical — Internet → nimbuslabhrexports (cloud-posture issues show <issue-id-1>)
Database: .cloud-posture/posture.db

$ ./bin/cloud-posture paths --config lab/local/cloud-posture.lab.yaml --limit 3
20 attack path Issue(s) from 23 hop variant(s) (9 entry points, 29 crown jewels); --all-variants lists every variant

 1. [CRITICAL 10.0] Internet → nimbuslabhrexports — sensitive data exfiltration
      1. nimbuslabhrexports (azure_storage_account): readable by anyone on the internet [p=1.00]
      MITRE: T1190
      Issue <issue-id-1> · cloud-posture issues show <issue-id-1>
 2. [CRITICAL 10.0] Internet → nimbus-lab-customer-pii — sensitive data exfiltration  (+1 more hop variant(s))
      1. nimbus-lab-customer-pii (aws_s3_bucket): readable by anyone on the internet [p=1.00]
      MITRE: T1190
      Issue <issue-id-2> · cloud-posture issues show <issue-id-2>
 3. [HIGH 8.0] external trust abuse of nimbus-lab-partner-sync → AdministratorAccess — privilege escalation
      1. nimbus-lab-partner-sync (aws_iam_role): CROSS_ACCOUNT_TRUST: assumable by every principal of external account 777777777777 (account root trust arn:aws:iam::777777777777:root) without an ExternalId condition (trust names organisation o-partner00001, not the role's own o-lab0000001) [p=0.80]
      MITRE: T1098.003
      Issue <issue-id-3> · cloud-posture issues show <issue-id-3>

suppressed (trusted): 3, suppressed (private): 2
  - nimbus-lab-allow-ssh-corp [trusted 203.0.113.0/24]: every source (203.0.113.0/24) is inside trusted_cidrs
  - nimbus-lab-gce-bastion [trusted 203.0.113.0/24]: every source (203.0.113.0/24) is inside trusted_cidrs
  - nimbus-lab-corp-tools-01 [trusted 203.0.113.0/24]: every source (203.0.113.0/24) is inside trusted_cidrs
  - nimbus-lab-partner-export [private ]: auth required (function_url_auth_type AWS_IAM)
  - nimbus-lab-shared-reports [private ]: org-conditioned (Principal * limited by aws:PrincipalOrgID)

Exposures (not attack paths): 16 (--exposures lists them)

Dead ends: 18 finding-bearing resource(s) reach no crown jewel (--dead-ends lists them, --no-dead-ends hides this)

$ ./bin/cloud-posture plan --config lab/local/cloud-posture.lab.yaml
Plan: 20 attack path Issues (23 hop variants: 22 traversal, 1 rule-chain), total score 169.3
Minimum fix set: 21 fix(es) — min_fix_exact=true (provably minimal), min_fix_verified=true (re-traversal confirmed), removes 95.7% of traversal path score

1. public data store on nimbuslabhrexports
   resolves 1 path(s) alone, reduces 0, remaining score 154.2 · steps 1–1 together: resolves 1, remaining score 154.2
 …

$ ./bin/cloud-posture prioritize --explain --no-network --config lab/local/cloud-posture.lab.yaml
Top 50 findings by risk score (score 0–10, score_version 2.4.0; bands Critical ≥9, High ≥7, Medium ≥5, Low <5 — docs/scoring.md; `issues` lists Issues)

 1. 10.0 Critical S3_PUBLIC_BUCKET             nimbus-lab-customer-pii
      aws/111111111111 · owner: data-platform · due <date> · paths: 2
      why: CRITICAL severity; internet exposed (wide); sensitive data (PII); production workload; on 2 attack path(s), max score 10.0
      factor                 ×mult    status      reason
      base                   7.00     scored      CRITICAL severity
      exposure               ×1.40    scored      internet exposed (wide) [weakness PUBLIC_DATA_STORE (no width data; treated as wide)]
      identity               ×1.00    scored      no identity weakness or privileged identity found
      data_sensitivity       ×1.50    scored      sensitive data (PII) [label pii]
      criticality            ×1.30    scored      production workload [node criticality=production]
      exploitability         ×1.00    not scored  not scored: no CVE data on this finding
 …
```
<!-- END readme-transcript -->

## Install

**Today: build from source.** You need the Go version in `go.mod`. The build reports `0.1.0-dev`. With no tag
published, `go install …@latest` resolves a pseudo-version of the default branch (`v0.0.0-<date>-<commit>`), not a
release. A source build keeps debug information and is large; build with `-trimpath -ldflags "-s -w"` for a
stripped binary.

```bash
go install github.com/DreadpiratePickles/nimbus/cmd/cloud-posture@latest
# or, in a clone:
make build && ./bin/cloud-posture --help
# optional Python layer: the AI copilot (`ask`) needs only [ai]; [all] adds reports and FastAPI
pip install -e "python[ai]"
```

**After the first tagged release (`v0.2.0`, not yet published).** The release pipeline is set up but
has not yet produced a release. It runs on CI when a `v*` tag is pushed, signs with cosign (keyless),
publishes SHA-256 checksums, an SPDX SBOM and SLSA provenance, and builds a distroless, non-root
container image. Once it exists:

```bash
# Linux / macOS: fetch the installer at the tag, read it, then run it. It verifies the cosign
# signature and the checksum, and refuses to install on any mismatch.
curl -fsSLO https://raw.githubusercontent.com/DreadpiratePickles/nimbus/v0.2.0/install.sh
less install.sh
VERSION=v0.2.0 INSTALL_DIR="$HOME/.local/bin" sh install.sh --require-signature   # needs cosign

brew install --cask DreadpiratePickles/tap/cloud-posture                          # own tap
docker run --rm -v "$PWD:/work" ghcr.io/dreadpiratepickles/cloud-posture@sha256:<digest> ingest /work/scanner-output
```

Windows: there is no installer. The release archives will include Windows zips that are built but
not tested on Windows. Verify them by hand.

### Verifying a release

Do not run a release you have not verified. The full commands are in
[SECURITY.md](SECURITY.md#verifying-a-release). In short:

1. `cosign verify-blob` the `checksums.txt` bundle against the identity
   `https://github.com/DreadpiratePickles/nimbus/.github/workflows/release.yml@refs/tags/<tag>`
   and the issuer `https://token.actions.githubusercontent.com`.
2. `sha256sum --ignore-missing -c checksums.txt` for the archive you downloaded.
3. `gh attestation verify <archive> --repo DreadpiratePickles/nimbus` for SLSA provenance.
4. Container: pin by digest and `cosign verify` it with the same identity.

`install.sh` does the signature and checksum steps for you. Never pipe a script from `main` into a shell.

### GitHub Action

Reference the action by **full commit SHA**, never by tag. Tags can be force-pushed, as the 2026
trivy-action compromise showed. The action installs the release named by `version` with checksum and
cosign verification. No end-to-end run exists yet (plan v3 Phase 1). <!-- claim: docs/research/strategy-how-to-win.md#51-evidence-base-what-distribution-looks-like-for-the-winners -->

```yaml
- uses: DreadpiratePickles/nimbus@<40-hex-commit-sha> # v0.2.0
  with:
    version: v0.2.0
    iac-path: infra
    fail-on: HIGH
```

### Credentials

nimbus uses your existing AWS/Azure/GCP/kubectl sessions, or environment variables (`GITHUB_TOKEN`,
`OKTA_API_TOKEN`, `M365_*`, `SLACK_WEBHOOK_URL`, `ANTHROPIC_API_KEY`). A `.env` or `nimbus.env` in the
working directory is loaded automatically and is git-ignored. **Caveat:** `cloud-posture.yaml` accepts
literal tokens, and `onboard` can write them into it. Keep secrets in environment variables, and keep
`cloud-posture.yaml` out of version control. The scan needs read-only access; `onboard --aws-org`
prints a StackSet that creates a read-only role with an External ID. <!-- claim: TestReadOnlyPolicies, TestOnboardManifestAndOffboardRollback -->

## Threat model (summary)

nimbus reads cloud configuration with your credentials. Its database is a map of your estate. The
design assumptions, and what defends each:

- **The scan path is read-only.** The generated AWS policy contains no write actions. Commands that change anything (`onboard --deploy`, `offboard --rollback`, `fix --apply`) are explicit and separate, and the rollback refuses to touch anything outside its manifest. <!-- claim: TestReadOnlyPolicies, TestRollbackRefusesNonAllowlistedResources, TestRollbackRefusesOtherAccountsManifest -->
- **Local server:** `serve` binds to loopback by default. Binding anywhere else requires a token. Host-header allowlist, CSRF checks, timeouts and body limits are enforced. <!-- claim: TestBindRequiresTokenOffLoopback, TestHostHeaderAllowlist, TestCrossSitePostRejected, TestServerTimeoutsAndBodyLimit -->
- **SQL** from the API or CLI runs through a layered read-only guard with a timeout. <!-- claim: TestReadOnlyGuardBlocksBypasses, TestQueryTimeoutInterruptsRunawaySQL, python/tests/test_security.py::test_query_readonly_rejects_bypasses -->
- **Untrusted input:** crafted scanner output cannot inject SQL views. Pathological HCL is refused, not crashed on. PR writes are confined to the repository, and Python is never loaded from the working directory. <!-- claim: TestIngestCraftedResourceTypeCannotDropTables, TestScanHCLPathologicalNestingIsAnErrorFinding, TestOpenFixPRRejectsEscapingPaths, TestPythonNotLoadedFromWorkingDirectory -->
- **Egress:** with `--no-network` / `CLOUD_POSTURE_NO_NETWORK=1`, nimbus makes zero outbound connections and uses the embedded KEV/EPSS snapshot. Webhook URLs are redacted from errors. <!-- claim: TestNoNetworkMakesZeroOutboundConnections, TestDeliveryErrorsRedactWebhookURLs -->
- **Open risks we know about** (plan v3 §5): the scan database is not encrypted at rest and has no `purge` yet. What is sent to an LLM is not yet minimised or documented field by field. The scan and operator roles are not yet separate policies. Treat the database file as sensitive, and use a local model for sensitive estates.

How issues are fixed and found: [Verification evidence](#verification-evidence) below. Report vulnerabilities privately: [SECURITY.md](SECURITY.md).

## Verification evidence

- **The gate:** `make verify` runs `go vet`, the Go tests, the Python tests, the dashboard smoke test, `govulncheck`, `gosec` (high severity) and `make readme-check`. The last gate results are recorded in the session log.
- **Hardening record:** each security fix with its failing-first test, in [`docs/research/nimbus-capability-inventory.md`](docs/research/nimbus-capability-inventory.md#remediated-2026-10-09).
- **Session logs:** [`docs/sessions/`](docs/sessions) hold red → green evidence per track and the independent verifier reports.
- **README claims:** every sentence here with a number or a superlative carries a hidden `<!-- claim: … -->` marker, and `make readme-check` fails if a marker is missing or does not resolve to a Go test, a pytest node id or a docs section. `python3 tools/readme-claims/check.py --list` prints them all. <!-- claim: tools/readme-claims/test_check.py::RepoReadmeTest::test_repo_readme_passes -->

## Commands

| Command | What it does |
|---|---|
| `ingest` | Import scanner output files or directories (format auto-detected) |
| `scan` | Run native collectors and installed scanners per account; `--iac` for Terraform; `--output table\|json\|sarif\|dashboard\|markdown`; `--fail-on` |
| `paths` | One row per attack path Issue (titled like `issues`) with scores, MITRE tags, `--fixes` (choke points, minimum fix set), `--blast-radius`, `--format mermaid\|dot\|json` (`--grouped`: one JSON object per path Issue); graph query `--from internet --to type:aws_s3_bucket --through type:aws_iam_role [--max-hops N]` with a `because` per hop |
| `plan` | The minimum fix set and what each fix resolves, by re-traversal; counts path Issues and their hop variants; each step ends with `cloud-posture verify <issue-id>` |
| `prioritize` | Findings ranked by risk score with reasons, owner and SLA; `--explain` prints the factors behind the number |
| `fix` | Generate IaC remediation; `--patch` rewrites a Terraform block in place; `--auto-pr`; `--tfstate` maps cloud findings to code |
| `query` | SQL over `findings`, inventory views, `attack_path_summary` and compliance views; `--engine steampipe` passthrough |
| `report` | Framework reports, `--format md\|json\|html\|pdf`, `--evidence-zip` |
| `onboard` / `offboard` / `doctor` | Credential detection and config; manifest-based rollback; health checks (both make no network call under `--no-network`) |
| `serve` / `dashboard` | Local dashboard and JSON API; static HTML report |
| `issues` | Issues (one per path or finding group) with owner, due date and state; `issues show <id>`, `issues history <id>`, `issues metrics` (incl. "assigned by default"), `--overdue`, `--state pending\|verified`; `issues mark-pending <id> --by <PR>` when a fix is merged |
| `verify <issue>` | Re-collect just the Issue's resources, re-traverse, and mark it verified-fixed when its path or finding is gone in repeated checks with backoff; `--from-file <export>` verifies offline from a scanner export (a file that never evaluates the Issue's check is "unverified", not fixed) |
| `who-can <action> <resource>` | Principals that can perform an action on a resource (an ARN, node id or unique name), anonymous (internet) first, with the granting and denying statements |
| `governance init` | Starter owner rules from owner/team tags and CODEOWNERS; proposes default / account / provider owners only from a clear majority (`governance.defaults.min_owner_share`, default 50%); `--write` merges them into the config atomically <!-- claim: TestGovernanceInitMajorityDefaultReportedAsDefault, TestGovernanceInitProposesDefaultAndAccountOwners, TestGovernanceInitWriteMergesAnEmptyBlock --> |
| `convert <file>` | Convert nimbus or scanner JSON to `sarif\|ocsf\|asff\|csv\|junit\|gitlab\|html` |
| `mcp` | MCP server over stdio for Claude Desktop, Cursor and other agents (default scope `read`: sql, schema, paths, issue, explain, coverage, who_can, prioritize, verify, summary; `--scope fix` adds simulate_fix / draft_fix; nothing writes; redaction on, audit log) |
| `pr-comment` | Plan-time attack-path diff for a Terraform plan: opens / escalates / lowers / closes, with a gate (`--fail-on-opened`, `--opened-only`) |
| `risk` | Path-rule library: `risk list`; `risk test <rule-id\|file.yaml>` validates a rule, runs its own tests and dry-runs it on the stored snapshot (no writes) |
| `catalog unmapped --tool checkov\|trivy` | Scanner check ids with no canonical mapping, with counts and the mapped share |
| `ask "<question>"` | AI copilot over the database (Python layer, `pip install -e "python[ai]"`); offline rule-based fallback; tables capped at 20 rows unless `--full`; `--show-sql`; `--no-python` (or `python.enabled: false`) turns the Python layer off <!-- claim: python/tests/test_w6_copilot_first_run.py::test_ask_table_capped_unless_full, TestAskNamesTheSettingThatDisablesPython --> |
| `alert`, `monitor`, `cost`, `graph`, `learn`, `hook`, `action`, `catalog`, `version` | See `cloud-posture <cmd> --help` (several are experimental, see above; `monitor` polls audit logs, it is not real time) |

Example config: [`cloud-posture.example.yaml`](cloud-posture.example.yaml). Canonical checks: [`docs/checks.md`](docs/checks.md). Score contract: [`docs/scoring.md`](docs/scoring.md).

## Development

```bash
make build && make test          # go vet + go test ./...
make python-test                 # cd python && pytest
make groundtruth                 # attack-path benchmark on the synthetic lab
make readme-check                # README claims link to evidence
make verify                      # the full gate before any PR
```

Contributor guide: [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off, tests first). AI agents: [AGENTS.md](AGENTS.md). Design notes: [`CLAUDE_CONTEXT.md`](CLAUDE_CONTEXT.md), [`.planning/`](.planning).

## Project

[ROADMAP.md](ROADMAP.md) · [GOVERNANCE.md](GOVERNANCE.md) · [MAINTAINERS.md](MAINTAINERS.md) · [ADOPTERS.md](ADOPTERS.md) · [OPEN_SOURCE_PROMISE.md](OPEN_SOURCE_PROMISE.md) · [SECURITY.md](SECURITY.md) · [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) · [Metrics](docs/metrics.md) · [Code of Conduct](CODE_OF_CONDUCT.md)

## Status

Pre-release `0.1.0-dev`. Phase 0 is not yet closed ([ROADMAP.md](ROADMAP.md#where-we-are-2026-10-09)). In particular, nimbus has not yet been run against a live cloud account. Treat collector output as beta until it has.

Licensed under Apache-2.0. Paths, fixes, adapters, the MCP server and the benchmark are never moved behind a paid tier ([OPEN_SOURCE_PROMISE.md](OPEN_SOURCE_PROMISE.md)).
