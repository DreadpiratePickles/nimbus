# nimbus attack-path benchmark

The lab is the acceptance harness for attack-path detection. It is a seeded, deliberately
vulnerable multi-cloud estate, with every attack path labelled by hand. The test checks what
the engine reports against those labels. It covers plan v2 Track H and gap-analysis item O1.

## What the lab contains

| file | role |
|---|---|
| `lab/local/estate.yaml` | the estate: 9 accounts (AWS ×4 incl. two external ones, Azure, GCP, EKS/Kubernetes, GitHub, Okta), 69 resources, 62 seeded weaknesses `W01–W62`, 30 scenarios `S01–S30` (S15–S30 added by P1-LAB L1) |
| `lab/local/estate/` + `lab/local/gen/` | the generator. Writes `lab/local/out/estate.findings.json` (native findings JSON: one FAIL finding `lab-Wxx` per weakness and one PASS `lab_inventory` record per resource that has no weakness) |
| `lab/local/cloud-posture.lab.yaml` | the lab config. Holds `trusted_cidrs: [203.0.113.0/24]` for the seeded false positive |
| `lab/ground_truth.yaml` | the hand labels: 20 expected paths `P01–P20`, 5 must-not-report labels `F01`, `F05–F08` (`false_positive`), 5 `pending-feature` labels `S01`, `F02–F04`, `F09` (reported until a named feature lands), and the expected finding counts per severity |
| `lab/known_gaps.yaml` | engine gaps that are measured and owned (see below) |
| `tests/groundtruth/` | the black-box test. It builds the CLI with `go build`, then runs `ingest --source native -o json`, `paths --format json --limit 0` and `prioritize --json --top 0` |
| `lab/terraform/` | the real-cloud twin of S01–S14: `aws/` (S01–S07, S12, S13; S14 is a sketch), plus `azure/` and `gcp/` stubs. `fmt -check` + `validate` pass (OpenTofu 1.13.1); **never planned or applied** (see below). S15–S30 have no Terraform twin yet |
| `lab/golden/` | raw Checkov 3.3.26 and Trivy 0.75.0 outputs for `lab/terraform` (`<tool>/<version>/`), `expectations.yaml`, `regen.sh`; scored by `tests/groundtruth/golden_test.go` (see "Scanner interop") |

Seeded scenarios:

| id | scenario | weaknesses |
|---|---|---|
| S01 | Public S3 bucket tagged PII (crown jewel) | W01 |
| S02 | EC2 with IMDSv1 behind a 0.0.0.0/0 SG, instance profile with AdministratorAccess | W02–W05 |
| S03 | Publicly accessible production RDS | W06 |
| S04 | Role trusting external account 999999999999 (no ExternalId), with admin | W07, W08 |
| S05 | IAM user: no MFA, 400-day access key, AdministratorAccess | W09–W11 |
| S06 | Public Lambda function URL; its execution role reads the PII bucket | W12 |
| S07 | Public EKS endpoint; SA `ci/deployer` bound to cluster-admin | W13, W14 |
| S08 | Exposed pod with a CVE → auto-mounted SA token → ClusterRoleBinding(cluster-admin) | W15–W17 (+W14) |
| S09 | Public GCE instance running as the default compute SA, which has roles/editor | W18–W21 |
| S10 | Azure storage account with anonymous blob access, classified confidential | W22 |
| S11 | Azure NSG with RDP open → jump VM → managed identity that is Contributor on the subscription | W23, W24 |
| S12 | GitHub repo with no branch protection → OIDC deploy role with AdministratorAccess | W25, W26 |
| S13 | **Seeded false positive.** SSH is open only to the trusted corporate CIDR. The instance still has IMDSv1 and a PowerUser role | W27–W29 |
| S14 | **Path behind an SCP deny.** IMDSv1 EC2 → admin role, but an SCP on the role denies `*` | W30–W32 |
| S15 | (F02) Public Lambda URL → role with `Allow s3:*` + explicit `Deny s3:GetObject` → claims PII bucket | W33 |
| S16 | (F03) EC2 with SG 0.0.0.0/0:22 whose subnet NACL denies 22 → admin role | W34–W36 |
| S17 | (F04) RDS `publicly_accessible` in an isolated subnet with no IGW route | W37 |
| S18 | (F05) Protected repo → GitHub OIDC trust pinned to `ref:refs/heads/main` → admin deploy role | W38 |
| S19 | (P13) No-MFA user with `iam:PassRole` + `ec2:RunInstances` → EC2 admin role (no declared edge) | W39–W41 |
| S20 | (P14) GitHub OIDC trust with no `sub` condition → admin deploy role | W42, W43 |
| S21 | (P15) Okta user under an MFA-exempt sign-on rule → `aws-admins` group → Identity Center `AdministratorAccess` | W44, W45 |
| S22 | (P16) Exposed pod → SA → ClusterRoleBinding granting get/list secrets cluster-wide | W46–W48 |
| S23 | (P17) Exposed pod with a KEV CVE → IRSA service account → role → analytics PII bucket | W49, W50 |
| S24 | (P18) Publicly invocable Bedrock agent → agent role with `iam:PutRolePolicy` | W51, W52 |
| S25 | (F06) GCP twin of S13: SSH firewall open only to the trusted CIDR → bastion → SA with roles/editor | W53–W55 |
| S26 | (F07) Lambda function URL with `AuthType AWS_IAM` → role → claims PII bucket | W56 |
| S27 | (F08) Bucket policy `Principal *` conditioned on `aws:PrincipalOrgID` | W57 |
| S28 | (P19) EC2 with Log4Shell (CISA KEV), IMDSv2, 443 open → role → billing PII bucket | W58, W59 |
| S29 | (P20) External account → auditor role (no ExternalId) → chained AssumeRole into break-glass admin | W60, W61 |
| S30 | (F09) Public records API (member account) → role whose `s3:GetObject` is denied by SCP `p-lab0nodataread` | W62 |

S11 adds a managed identity to the brief's "public blob + NSG open RDP" so that the RDP exposure leads to a crown jewel. S12 adds the OIDC deploy role for the same reason.

## How matching works

- A reported path matches a labelled path when three things hold:
  - its **entry** is the same (`internet`, or the foothold resource);
  - its **target** is the same: the last step, or the last step before trailing optional hops (for example the ClusterRole after a binding; B2 item 7);
  - its hop set contains every labelled hop and nothing outside `hops ∪ optional_hops`. Hop order is ignored.
- `optional_hops` covers plumbing that an engine may render or skip: security groups, firewalls, NSGs, the ClusterRole behind a binding.
- Entry derivation:
  - A traversal path with no `entry` step starts at the internet.
  - A rule chain whose first stage is `PUBLIC_*` also starts at the internet.
  - In any other case, the first resource is the foothold.
- A `false_positive` label counts as reported when either:
  - a path matches it, or
  - an internet path passes through its first hop (for F01, the corporate-only instance).

The test asserts all of the following:
- Every `expected` path is found.
- Its best match scores ≥ `min_score` (7), or lies in its labelled band. A label below the threshold
  needs `band`, `band_reason` and `max_score` (P07: `medium`, 5 ≤ score < 7); scoring at or above
  `max_score` is an `above_band` failure.
- No unlabelled path scores ≥ 7.
- No `false_positive` label (F01, F05–F08) produces a path.
- Every `pending-feature` path is tracked (reported today, listed in `lab/known_gaps.yaml`).
- The ingest counts match `expected_findings`: 62 FAIL (9 CRITICAL, 47 HIGH, 6 MEDIUM) and 30 inventory records.
- Every seeded finding appears in `prioritize`.

`TestGroundTruthIntegrity` checks that the files agree with each other:
- the committed generated JSON matches the estate;
- every ground-truth id resolves to a resource in the estate;
- the severity counts match.

## Running it

```sh
make groundtruth                                  # go test ./tests/groundtruth -count=1 -v (known gaps tolerated)
GROUNDTRUTH_STRICT=1 make groundtruth             # Phase 0 exit criterion (e): no gaps allowed
go test ./tests/groundtruth -v -args -strict      # same as above
GROUNDTRUTH_REPORT=/tmp/bench.md make groundtruth # also write the benchmark table as Markdown
GROUNDTRUTH_JSON=/tmp/benchmark.json make groundtruth # benchmark.json elsewhere (default lab/local/out/benchmark.json, git-ignored)
make lab-local                                    # regenerate lab/local/out/estate.findings.json after editing estate.yaml
make groundtruth-golden                           # Checkov/Trivy goldens through the real adapters (GOLDEN_REPORT=/tmp/interop.md for the table)
make lab-golden                                   # regenerate the goldens (needs checkov + trivy; lab/golden/README.md)
make lab-validate                                 # tofu/terraform fmt -check + validate on lab/terraform (no credentials)
cloud-posture ingest lab/local/out/estate.findings.json --source native && cloud-posture paths   # by hand
```

How the known-gaps gate behaves:
- **The default run fails when a new failure appears.** That is either a regression or a gap nobody has labelled.
- **It also fails when a gap listed in `lab/known_gaps.yaml` stops reproducing.** Delete that entry in the same change that fixes the gap.
- **The strict run ignores the list.**

CI runs the test in the `test` job of `.github/workflows/cloud-posture.yml`. It runs as part of `go test ./...` and again as its own named step.

## Honest numbers (2026-10-09, labelled and real-world)

The harness reports two views of every precision and recall figure (competitive delta
2026-10-09, shortfall #2):

- **labelled**: a reported path that matches a `pending-feature` label counts as a hit, because it is
  what today's engine is expected to do. This is the column published before 2026-10-09.
- **real-world**: every reported path that matches a `false_positive` or a `pending-feature` label
  (S01, F02–F04, F09: all "should NOT be reported" once their feature lands) is a false positive,
  as it would be in a real estate. An expected label met only through such a path is not found.

Verbatim `make groundtruth` output on the working tree, 2026-10-09 (labelled lab; the engine at this
point includes the P1-IAM evaluator wiring, so F02 and F09 are suppressed):

| metric | labelled | real-world |
|---|---|---|
| expected paths | 20 | 20 |
| reported paths (all / score >= 7) | 31 / 20 | 31 / 20 |
| recall (found at any score) | 95.0% (19/20) | 95.0% (19/20) |
| recall@7 (best score >= 7) | 75.0% (15/20) | 75.0% (15/20) |
| recall in band (min_score <= best < max_score) | 80.0% (16/20) | 80.0% (16/20) |
| precision (all reported) | 100.0% (31/31) | 87.1% (27/31) |
| precision@7 (reported >= 7) | 100.0% (20/20) | 85.0% (17/20) |

Real-world false positives: 4

| score | label | rule | chain |
|---|---|---|---|
| 8.00 | F04 | GRAPH_TRAVERSAL | internet > nimbus-lab-ledger |
| 7.00 | F03 | GRAPH_TRAVERSAL | internet > sg-0a1b2c3d4e5f60004 > i-0a1b2c3d4e5f60004 > nimbus-lab-sftp-role |
| 7.00 | F03 | GRAPH_TRAVERSAL | internet > i-0a1b2c3d4e5f60004 > nimbus-lab-sftp-role |
| 5.70 | S01 | INTERNET_TO_ACCOUNT_ADMIN | internet > i-0a1b2c3d4e5f60003 > i-0a1b2c3d4e5f60003 > nimbus-lab-batch-role |

Noise estate, same run: precision 100.0% (4/4) labelled and real-world, precision@7 100.0% (4/4),
recall 100.0% (3/3), recall@7 100.0% (3/3). The two views are identical there by construction:
`lab/noise_truth.yaml` has no pending-feature labels, so every reported path that is not a TP chain
already counts as a false positive.

History (labelled lab; real-world columns before today are derived from the published per-label
tables: the only pending-feature label before P1-LAB L1 was S01, reported as 2 paths in B2 and later,
and no S01 path can match an expected label, so real-world recall equals labelled recall in every
column):

| metric | baseline (Track H) | B2 | B3 | noise round | now (2026-10-09) |
|---|---|---|---|---|---|
| expected labels | 12 | 12 | 12 | 12 | 20 |
| reported paths (all / ≥ 7) | 45 / 2 | 19 / 7 | 21 / 13 | 20 / 13 | 31 / 20 |
| recall@7 (both views) | 16.7% (2/12) | 50.0% (6/12) | 83.3% (10/12) | 83.3% (10/12) | 75.0% (15/20) |
| precision, labelled | 26.7% (12/45) | 89.5% (17/19) | 95.2% (20/21) | 100% (20/20) | 100% (31/31) |
| precision, real-world | 22.2% (10/45) | 78.9% (15/19) | 85.7% (18/21) | 90.0% (18/20) | 87.1% (27/31) |
| precision@7, labelled | 100% (2/2) | 100% (7/7) | 100% (13/13) | 100% (13/13) | 100% (20/20) |
| precision@7, real-world | 100% (2/2) | 71.4% (5/7) | 84.6% (11/13) | 84.6% (11/13) | 85.0% (17/20) |
| noise estate precision (both views) | — | — | — | 100% (4/4) | 100% (4/4) |

(The P1-LAB L1 run, between "noise round" and "now", is left out: its F02/F09 match counts were not
recorded, so its real-world precision cannot be derived exactly.)

`make groundtruth` prints both views at the end of the run and writes them to
`lab/local/out/benchmark.json` (schema `nimbus.benchmark/v1`, git-ignored; `GROUNDTRUTH_JSON`
overrides the path) with the real-world false positives listed per estate, for the release
pipeline to attach. `GROUNDTRUTH_STRICT=1` semantics are unchanged: the gate still fails on every
`pending_feature_reported:` entry, independent of which precision view is printed.

### How to read these numbers

The **labelled lab** (`lab/local/estate.yaml`, `lab/ground_truth.yaml`) measures whether the engine
finds 20 hand-labelled attack paths at the right score and stays silent on 10 must-not-report
cases, on a 69-resource multi-cloud estate. It was authored by this project, by the same people
who build the engine, so it is self-referential: it shows the engine does what its authors
intended, and it can share their blind spots. The **noise estate** (`lab/local/noise/estate.yaml`,
`lab/noise_truth.yaml`) measures false positives: 300 resources (291 benign decoys, many of them
near misses) and 3 true-positive chains, written by an independent author, a separate agent that
was forbidden to read the attack-path engine, the scoring docs and the lab labels and logged every
file it did read (`lab/local/noise/AUTHOR_LOG.md`; it did see the main lab estate and the check
catalog). It is small (3 chains), it was authored inside the same project rather than by an outside
party, and it has no pending-feature labels. **Its 100% precision is in-sample:** the engine noise
round was tuned directly on this estate's false positives after its first measurement (23 FPs → 0),
so it is no longer held-out evidence. The next independent estate (a new author, measured before
any tuning on it) — and a live-cloud run — is the real test of precision. Quote the **real-world** column when comparing against
another product; the labelled column is a regression gate for today's engine. Both estates are
synthetic findings ingested through the real CLI: **no live-cloud run exists yet** (gap analysis
O1), so none of these numbers has been measured against a real cloud account.

## Current numbers (2026-10-09, after Track B3)

Measured with `make groundtruth` (`GROUNDTRUTH_REPORT` table) on the working tree. Columns:
**baseline** is Track H's first measurement, **B2** is the tree after Track B2 (before the
generator emitted typed relationships and before the CLI passed `trusted_cidrs`), **now** is the
tree after Track B3 (typed lab, CLI wiring, toxic-combination floor, P07 relabelled medium).

| id | path | band | baseline | B2 | now |
|---|---|---|---|---|---|
| P01 | Public S3 bucket exposes customer PII | ≥ 7 | 9.50 | 10.00 FOUND | 10.00 FOUND |
| P02 | Internet → IMDSv1 EC2 → admin instance role | ≥ 7 | 5.69 | 7.60 FOUND | 7.60 FOUND |
| P03 | Publicly accessible production RDS | ≥ 7 | 6.65 | 8.00 FOUND | 8.00 FOUND |
| P04 | External account → admin vendor role | ≥ 7 | 4.62 | 7.00 FOUND | 7.00 FOUND |
| P05 | No-MFA / stale-key admin user | ≥ 7 | 3.37 | 7.00 FOUND | 7.00 FOUND |
| P06 | Lambda URL → execution role → PII bucket | ≥ 7 | missed | missed | 7.00 FOUND (exposed+sensitive) |
| P07 | Public EKS endpoint → cluster-admin binding | medium 5–7 (was ≥ 7) | missed | 5.15 low | 5.15 FOUND (in band) |
| P08 | Pod → SA → ClusterRoleBinding(cluster-admin) | ≥ 7 | missed | 3.43 low | 7.00 FOUND (6.86 → floor, exposed+admin) |
| P09 | Public GCE → default SA (editor) | ≥ 7 | 3.16 | 3.80 low | 7.00 FOUND (exposed+admin) |
| P10 | Anonymous Azure blob, confidential | ≥ 7 | 9.50 | 10.00 FOUND | 10.00 FOUND |
| P11 | RDP NSG → jump VM → Contributor managed identity | ≥ 7 | missed | missed | 7.00 FOUND (exposed+admin) |
| P12 | Unprotected repo → OIDC admin deploy role | ≥ 7 | 1.90 | 1.90 low | 3.80 low (known gap) |
| F01 | Seeded false positive (trusted CIDR) | must not report | 13 paths | 2 paths (best 5.20) | 0 paths, 1 suppressed |
| S01 | SCP-denied path (pending-feature) | until SCP lands | 2 paths (5.69) | 2 paths (7.60) | 2 paths (7.60, known gap) |

| metric | baseline | B2 | B3 | now (P1-ENGINE noise round, 2026-10-09) |
|---|---|---|---|---|
| reported paths (all / score ≥ 7) | 45 / 2 | 19 / 7 | 21 / 13 | 20 / 13 |
| recall (found at any score) | 66.7% (8/12) | 83.3% (10/12) | 100% (12/12) | 100% (12/12) |
| recall@7 (best ≥ 7) | 16.7% (2/12) | 50.0% (6/12) | 83.3% (10/12) | 83.3% (10/12) |
| recall in band | — | — | 91.7% (11/12) | 91.7% (11/12) |
| precision (labelled / all reported) | 26.7% (12/45) | 89.5% (17/19) | 95.2% (20/21) | 100% (20/20) |
| precision@7 | 100% (2/2) | 100% (7/7) | 100% (13/13) | 100% (13/13) |
| unlabelled paths ≥ 7 | 0 | 0 | 0 | 0 |
| known gaps (strict failures) | 12 | 8 | 2 (P12, S01) | 2 (P12, S01) |

recall@7 counts every expected label, so P07 (relabelled medium) cannot count towards it; "recall
in band" is the share of labels whose best match lies in their own band. Every per-path score in
the table above is unchanged by the noise round. The one unlabelled path after B3,
`internet > nimbus-lab-eks` (4.00, the public EKS endpoint with the cluster itself as the target),
is gone: since the P1-ENGINE noise round a path must end at an impact target (a sensitive or crown
data store, an admin-level identity or a configured crown jewel; `docs/scoring.md` "Path score"),
and a cluster is none of these, so the endpoint is listed in `Analysis.Exposures` instead.

What remains:
- **P12** (3.80): the entry is an unprotected branch (0.4), not internet exposure, so the
  toxic-combination rule does not cover it. B3 did not widen the rule; this is a planning decision
  (see `lab/known_gaps.yaml`).
- **S01**: reported until SCP/RCP deny evaluation lands (Phase 2).

What removed the noise (B2 item 2): rule chains now need a real link between consecutive steps.
That link is the same resource, or a declared or contained relationship. Before B2, 34 of 45
reported paths were `INTERNET_TO_ACCOUNT_ADMIN` / `PUBLIC_K8S_API_TAKEOVER` / `STALE_KEY_ABUSE`
chains joined only by "same account".

## P1-LAB L1 labels (2026-10-09)

Plan v3 §0 ("Lab id convention") published F02–F05 and P13–P18 with fixed meanings; they keep those
meanings here. The P1-LAB brief also asked for scenarios the plan had not numbered; they take fresh ids
(F06–F09, P19, P20) so that no published id changes meaning:

| brief asked for | label |
|---|---|
| Allow `s3:*` + Deny `s3:GetObject` is not a path | F02 (plan) |
| trusted-CIDR-only SSH | F01 already covers AWS; F06 is the GCP twin |
| IAM-auth Lambda URL | F07 (plan F04 is the isolated-subnet RDS) |
| org-conditioned `Principal *` bucket | F08 (plan F05 is the branch-pinned OIDC trust) |
| OIDC wildcard-subject pipeline → admin | P14 (plan; no `sub` condition) |
| IRSA pod → role → sensitive bucket | P17 (plan) |
| Okta/Entra user without MFA → AWS admin via federation | P15 (plan) |
| KEV CVE on exposed host → role → data | P19 |
| cross-account trust from an external account → admin | P04 already covers one hop; P20 is the chained (role-chaining) version |
| SCP-denied path not reported once IAM v1 is wired | S01 covers the admin edge; F09 is the data-edge (`grants_access_to`) version |

Plan labels not in the brief, added with the rest: F03 (SG open, NACL deny), F04 (public RDS without an
IGW route), F05 (OIDC pinned to a protected branch), P13 (PassRole + RunInstances), P16 (SA lists
secrets cluster-wide), P18 (Bedrock agent role with `iam:PutRolePolicy`).

Measured with `make groundtruth` on the first run after the labels landed; nothing in the engine was
changed. Every miss is in `lab/known_gaps.yaml` with its observed cause and owner.

| id | status | label | today | gap / owner |
|---|---|---|---|---|
| F02 | pending-feature | Allow `s3:*` + Deny `s3:GetObject` → no read edge | reported 7.00 | `pending_feature_reported:F02`, P1-IAM wiring |
| F03 | pending-feature | SG 0.0.0.0/0:22 + NACL deny 22 | reported 7.00 | `pending_feature_reported:F03`, P2-REACH |
| F04 | pending-feature | public RDS in an isolated subnet | reported 8.00 | `pending_feature_reported:F04`, P2-REACH |
| F05 | false_positive | OIDC trust pinned to protected `main` | SUPPRESSED | — |
| F06 | false_positive | GCP SSH open only to trusted CIDR | SUPPRESSED (trusted) | — |
| F07 | false_positive | Lambda URL `AuthType AWS_IAM` | SUPPRESSED (private: auth required) | — |
| F08 | false_positive | `Principal *` + `aws:PrincipalOrgID` | SUPPRESSED (private: org-conditioned) | — |
| F09 | pending-feature | SCP denies the role's `s3:GetObject` | reported 7.00 | `pending_feature_reported:F09`, P1-IAM wiring |
| P13 | expected | PassRole + RunInstances → admin | MISSED | `missed:P13`, P1-IAM (`can_escalate_to`) |
| P14 | expected | OIDC trust without `sub` → admin | FOUND 7.00 | — |
| P15 | expected | Okta MFA-exempt user → Identity Center admin | 1.44 (low) | `low_score:P15`, P1-ENGINE + P2-MULTICLOUD X3 |
| P16 | expected | exposed pod → SA reads all secrets | FOUND 7.00 | — |
| P17 | expected | exposed pod → IRSA → role → PII bucket | FOUND 7.00 | — |
| P18 | expected | public Bedrock agent → role with `iam:PutRolePolicy` | MISSED | `missed:P18`, P1-ENGINE + P3-CONTENT IG9 |
| P19 | expected | KEV host → role → billing PII | FOUND 7.00 | — |
| P20 | expected | external account → auditor → break-glass admin | 5.99 (low) | `low_score:P20`, P1-ENGINE |

| metric | before L1 (12 expected) | after L1 (20 expected) |
|---|---|---|
| reported paths (all / score ≥ 7) | 20 / 13 | 33 / 22 |
| recall (found at any score) | 100% (12/12) | 90.0% (18/20) |
| recall@7 | 83.3% (10/12) | 70.0% (14/20) |
| recall in band | 91.7% (11/12) | 75.0% (15/20) |
| precision (labelled / all reported) | 100% (20/20) | 100% (33/33) |
| precision@7 | 100% (13/13) | 100% (22/22) |
| unlabelled paths ≥ 7 | 0 | 0 |
| known gaps (strict failures, `gaps:`) | 2 (P12, S01) | 10 (P12, P13, P15, P18, P20, S01, F02, F03, F04, F09) |

Precision counts a reported `pending-feature` path as labelled (it is correct today), so the five
pending-feature labels show up as gaps, not as precision loss. P01–P12 and F01 scores are unchanged.

## Noise estate (independently authored)

The labelled lab above was written by the same sessions that wrote the engine and its hop weights
(plan v3 §8 risk 2: the benchmark is self-referential). The noise estate is the first counterweight:
`lab/local/noise/estate.yaml` (fictional org "halyard", 12 accounts across AWS, Azure, GCP, EKS and
GitHub) and its labels `lab/noise_truth.yaml` were written by an agent that did not read
`internal/attackpath`, `internal/risk`, `docs/scoring.md`, this file or the main lab's ground truth
(file-read log: `lab/local/noise/AUTHOR_LOG.md`). It is ~300 realistic, benign-but-noisy resources
whose scanner findings are individually true but form no attack path, plus exactly **3 labelled
true-positive chains**. A precise engine reports those 3 and nothing else.

| file | role |
|---|---|
| `lab/local/noise/estate.yaml` | the estate (300 resources, 103 seeded findings `N001–N103`), generated by the unchanged `lab/local/gen` |
| `lab/noise_truth.yaml` | per-resource labels (`class`, `expected_paths`, `near_miss`, `why`) and the 3 true-positive chains `TP1–TP3` |
| `tests/groundtruth/noise_test.go` | `TestNoiseTruthIntegrity` (labels ↔ estate) and `TestNoiseEstate` (generate → ingest into its own DB → `paths --format json --limit 0` → `prioritize --json --top 0` → Issues → score) |
| `lab/known_gaps.yaml` `noise:` | the measured noise gaps, one per false-positive path and one per missed chain, each with an owner |

Composition (from `lab/noise_truth.yaml` `classes`):

| class | slug | resources | seeded findings | what it is |
|---|---|---|---|---|
| NZ01 | `public_website_bucket` | 12 | 11 | Public buckets that only serve public website assets (no sensitive tag), mostly behind CloudFront |
| NZ02 | `alb_private_imdsv2` | 35 | 10 | Internet-facing ALBs in front of private instances (no public IP, IMDSv2 required, scoped roles, no exploitable CVE) |
| NZ03 | `sg_443_alb_only` | 16 | 3 | Security groups open to 0.0.0.0/0 on 443 only, attached only to load balancers fronting ECS services |
| NZ04 | `scoped_readonly_role` | 12 | 1 | Roles with broad-but-scoped read-only policies, trusted only by SSO or AWS services |
| NZ05 | `unreachable_admin_role` | 5 | 4 | Admin roles only assumable via SSO SAML with MFA condition; no workload or external trust |
| NZ06 | `org_cross_account_trust` | 12 | 4 | Cross-account trusts to the org's own accounts (PrincipalOrgID / ExternalId conditions) |
| NZ07 | `lambda_url_iam_auth` | 16 | 3 | Lambda function URLs with AuthType AWS_IAM (some with org-scoped resource policies scanners call public) |
| NZ08 | `eks_private_endpoint` | 2 | 0 | EKS clusters with private-only API endpoints |
| NZ09 | `k8s_namespaced_read_sa` | 30 | 5 | K8s service accounts bound to namespaced read-only roles |
| NZ10 | `gcp_custom_least_priv_sa` | 19 | 5 | GCP instances running as custom least-privilege service accounts |
| NZ11 | `azure_private_storage` | 26 | 2 | Azure storage with private endpoints and no public blob; VMs with scoped managed identities |
| NZ12 | `github_protected_repo` | 20 | 5 | GitHub repos with branch protection; OIDC deploy roles pinned to protected environments |
| NZ13 | `iam_user_mfa_rotated` | 17 | 5 | IAM users with MFA and rotated keys |
| NZ14 | `cve_nonkev_private_host` | 16 | 16 | CVEs not in CISA KEV with low EPSS on private, non-internet-reachable hosts |
| NZ15 | `dev_sandbox_tagged` | 19 | 17 | Dev/sandbox accounts and projects, tagged as such, holding only synthetic data and no trust into prod |
| NZ16 | `private_data_store` | 8 | 2 | Sensitive data stores that are private and only reachable from unexposed principals |
| NZ90 | `near_miss` | 26 | 4 | Alarming names (admin/prod/pii/customer/root/secret) but benign attributes |
| NZT1 | `true_positive` | 9 | 6 | Deliberate, labelled true positives (3 chains) |
| **total** | | **300** | **103** | 291 benign (26 of them near misses), 9 on the 3 true-positive chains |

True-positive chains:

| TP | chain | rationale (from the truth file) |
|---|---|---|
| TP1 | SG `legacy-reports-ssh` (SSH 0.0.0.0/0) → instance `legacy-reports-01` (public IP, IMDSv1) → `legacy-reports-role` → S3 `halyard-finance-ledger` (confidential) | SSH open to the internet on an IMDSv1 host whose role reads the finance ledger |
| TP2 | repo `halyard/release-tools` (no branch protection, outside collaborators) → OIDC role `gha-release-tools` (AdministratorAccess, `sub=repo:halyard/release-tools:*`) | any push to any branch mints a token for a prod admin role |
| TP3 | Lambda `partner-webhook-debug` (function URL AuthType NONE) → `partner-webhook-debug-role` → DynamoDB `halyard-customer-contacts` (PII) | unauthenticated URL whose role can Scan the PII table |

How it is scored:
- Every reported path is matched to a TP or counted as a false positive. A path matches a TP when
  its last step is the TP's target, every resource on it is on the TP chain (sub-chains count as the
  same TP), and its first step is the TP's entry. A TP whose entry is a network control (TP1's
  security group) also matches an internet path that starts at the next chain member, the same
  plumbing allowance as `optional_hops` in the labelled lab (`TestMatchNoiseTP`).
- FP rate = false-positive paths / reported paths; precision = TP-matching paths / reported paths.
- "Entry-hop kind" is step 1's relation, weakness and resource type.
- The run uses a neutral config (`python.enabled: false`, **no `trusted_cidrs`**): the noise
  author supplied no config, and the main lab's `trusted_cidrs` exist for its seeded false positive.
  With the main lab's `trusted_cidrs: [203.0.113.0/24]` one path less is reported (`halyard-eks-dev`,
  2.00; 25 paths). That variant was measured by hand and is not part of the test.
- The ingest uses its own temp DB: the noise estate's `lab-inv-NN` ids collide with the main lab's.
- Gate: same as the labelled lab. The default run fails on a new failure and on a listed `noise:` gap
  that no longer reproduces; `GROUNDTRUTH_STRICT=1` ignores the list. Every false-positive path is a
  gap (`fp:<first resource> -> <target>`), whatever its score. Plan v3 §4 makes 0 unlabelled paths
  ≥ 5 a Phase 1 exit gate; Phase 0 only requires these numbers to be published.

```sh
make groundtruth                                  # labelled lab + noise estate, both tables
make groundtruth-noise                            # noise estate only
GROUNDTRUTH_STRICT=1 make groundtruth             # no gaps tolerated (fails today: 2 lab (P12, S01) + 0 noise)
GROUNDTRUTH_NOISE_REPORT=/tmp/noise.md make groundtruth-noise   # write the table below as Markdown
make lab-noise                                    # regenerate lab/local/out/noise.findings.json
```

### Measured numbers after the P1-ENGINE noise round (2026-10-09)

The engine changes are planning decisions 1–6 of the noise round (rules in `docs/scoring.md`
"Path score"): a path must end at an impact target (exposures go to `Analysis.Exposures`);
exposure needs anonymous reach (AWS_IAM / org-conditioned / anonymous-access-disabled targets are
`private` with the reason); an authenticating load balancer on the entry is `auth-lb ×0.3` with
no toxic floor; a user with no usable credential is no entry (unknown: hint ×0.5); the catalog no
longer maps TLS / network-rule / uniform-access storage checks to `PUBLIC_DATA_STORE`; and the
internet node's out-edges are no longer capped by `MaxBranching`. Verbatim
`GROUNDTRUTH_NOISE_REPORT` output of `make groundtruth` (labelled lab in the same run: recall 100%,
recall@7 83.3%, precision 100% (20/20), precision@7 100% (13/13), 0 unlabelled paths):

Noise estate run 2026-10-09 (lab/local/noise/estate.yaml vs lab/noise_truth.yaml)

| TP | kind | matching paths | best score | outcome |
|---|---|---|---|---|
| TP1 | internet -> host (SSH, IMDSv1) -> instance role -> confidential data | 2 | 7.00 | FOUND |
| TP2 | unprotected repo -> OIDC wildcard sub -> prod admin role | 1 | 3.80 | FOUND |
| TP3 | unauthenticated function URL -> execution role -> PII table | 1 | 7.00 | FOUND |

| metric | value |
|---|---|
| TP chains found / expected | 3 / 3 |
| reported paths | 4 |
| paths matching a TP chain | 4 |
| false-positive paths | 0 |
| FP rate (FP / reported) | 0.0% (0/4) |
| precision (TP paths / reported) | 100.0% (4/4) |
| unlabelled paths score >= 5 | 0 |
| unlabelled paths score >= 7 | 0 |
| reported paths by severity | CRITICAL 3, MEDIUM 1 |
| near-miss resources on a reported path | 0 |

False positives per entry-hop kind (step 1: relation weakness (resource type))

| entry hop | FP paths |
|---|---|

False positives per target type

| target type | FP paths |
|---|---|

False positives per decoy class of the first resource

| class | FP paths |
|---|---|

Unlabelled paths score >= 7: 0

Unlabelled paths score >= 5: 0

All false-positive paths: 0

| score | entry hop | hops |
|---|---|---|

Near-miss resources that produced paths: 0

Findings and Issues (alert-fatigue proxy)

| measure | value |
|---|---|
| ingested records / FAIL findings | 311 / 103 |
| FAIL findings by severity | CRITICAL 8, HIGH 26, MEDIUM 41, LOW 28 |
| open Issues | 99 |
| open Issues by severity | CRITICAL 8, HIGH 26, MEDIUM 41, LOW 24 |
| open Issues by kind | single 99 |
| CRITICAL + HIGH open Issues | 34 (on a TP-chain resource: 6; on benign resources: 28) |
| prioritize: ranked findings | 103 |
| prioritize: TP-chain findings in top 10 | 2 of 6 TP findings |
| prioritize: TP-chain findings in top 20 | 6 of 6 TP findings |
| prioritize: best rank of each TP's findings | TP1 #2, TP2 #15, TP3 #13 |

Reading the numbers (before → after):
- **TP chains 2/3 → 3/3.** TP3 was never a scoring problem: the internet node had 45 exploitable
  out-edges and the traversal's per-node `MaxBranching` (25) also capped the internet, so every
  exposure after the 25th in store order was silently dropped. TP3 now scores 7.00
  (exposed+sensitive). TP1 7.00 unchanged; **TP2 stays at 3.80** — the labelled lab's
  `low_score:P12` shape (CI entry 0.4, no toxic floor for a non-internet entry), still a planning
  decision; the noise harness has no per-TP score band, so it is tracked under P12.
- **Reported paths 26 → 4; false positives 23 → 0** (FP rate 88.5% → 0%, precision 11.5% → 100%;
  unlabelled ≥ 5: 5 → 0; ≥ 7: 4 → 0; near misses on a path: 4 → 0). Per FP class: 17 one-step /
  plumbing exposure paths (NZ01 website buckets, NZ10 GCE 443 hosts and the GCS web bucket, NZ03
  SG → ALB → ECS, the NZ15 narrow EKS endpoint) and the NZ90 `customer-portal` chain are now
  exposures (decision 1: no impact target; names no longer give priority); the NZ07 Lambda URLs
  `invoice-pdf` / `feature-flag-reader` are `private: auth required` (decision 2); the NZ11 Azure
  storage accounts are `private: anonymous access disabled` (decision 2 — the estate's findings
  carry `PUBLIC_DATA_STORE` themselves, so the catalog fix alone would not have removed them);
  `svc-prod-admin-legacy` has no usable credential (decision 4). Two FPs that the fan-out cap had
  been hiding (`public-pii-redacted-reports` 10.00, `halyard-sandbox-public-fixtures` 5.00) were
  removed by the explicit-classification rule before they were ever reported.
- **prioritize** improved as a side effect: TP-chain findings in the top 20 5/6 → 6/6; best ranks
  TP1 #4 → #2, TP2 #17 → #15, TP3 #33 → #13.
- **Alert fatigue is unchanged: 34 open CRITICAL/HIGH Issues, 28 on benign resources** (target
  ≤ 5 missed). Issue severity is the scanner finding's severity (`internal/store` RebuildIssues);
  no Issue is of kind path, so the engine changes cannot move this number. It needs Issue
  severity to take the path / exposure verdict into account (owner: store / CLI track).

`lab/known_gaps.yaml` `noise:` is empty (all 24 entries pruned; the harness fails on a listed gap
that no longer reproduces). `GROUNDTRUTH_STRICT=1 make groundtruth` now fails only on the two
labelled-lab gaps (P12, S01).

### Baseline (2026-10-09, P0-NOISE wiring, engine untouched)

Verbatim `GROUNDTRUTH_NOISE_REPORT` output of `make groundtruth` on the working tree (engine
untouched by this item; labelled-lab numbers in the same run were unchanged: recall 100%, recall@7
83.3%, precision 95.2% (20/21), precision@7 100% (13/13)). Hop lists show the short resource name
and its truth class; "Findings and Issues" is the alert-fatigue proxy (current open Issues, and
where `prioritize` ranks the true-positive findings among all 103).

Noise estate run 2026-10-09 (lab/local/noise/estate.yaml vs lab/noise_truth.yaml)

| TP | kind | matching paths | best score | outcome |
|---|---|---|---|---|
| TP1 | internet -> host (SSH, IMDSv1) -> instance role -> confidential data | 2 | 7.00 | FOUND |
| TP2 | unprotected repo -> OIDC wildcard sub -> prod admin role | 1 | 3.80 | FOUND |
| TP3 | unauthenticated function URL -> execution role -> PII table | 0 | - | MISSED |

| metric | value |
|---|---|
| TP chains found / expected | 2 / 3 |
| reported paths | 26 |
| paths matching a TP chain | 3 |
| false-positive paths | 23 |
| FP rate (FP / reported) | 88.5% (23/26) |
| precision (TP paths / reported) | 11.5% (3/26) |
| unlabelled paths score >= 5 | 5 |
| unlabelled paths score >= 7 | 4 |
| reported paths by severity | CRITICAL 6, HIGH 8, MEDIUM 11, LOW 1 |
| near-miss resources on a reported path | 4 |

False positives per entry-hop kind (step 1: relation weakness (resource type))

| entry hop | FP paths |
|---|---|
| exposes PUBLIC_DATA_STORE (aws_s3_bucket) | 8 |
| exposes PUBLIC_NETWORK_EXPOSURE (aws_security_group) | 4 |
| exposes PUBLIC_NETWORK_EXPOSURE (gcp_compute_instance) | 4 |
| exposes PUBLIC_DATA_STORE (azure_storage_account) | 2 |
| exposes PUBLIC_NETWORK_EXPOSURE (aws_lambda_function) | 2 |
| entry NO_MFA (aws_iam_user) | 1 |
| exposes PUBLIC_DATA_STORE (gcp_storage_bucket) | 1 |
| exposes PUBLIC_NETWORK_EXPOSURE (aws_eks_cluster) | 1 |

False positives per target type

| target type | FP paths |
|---|---|
| aws_s3_bucket | 9 |
| aws_ecs_service | 4 |
| gcp_compute_instance | 4 |
| azure_storage_account | 2 |
| aws_dynamodb_table | 1 |
| aws_eks_cluster | 1 |
| aws_iam_user | 1 |
| gcp_storage_bucket | 1 |

False positives per decoy class of the first resource

| class | FP paths |
|---|---|
| NZ01 | 8 |
| NZ10 | 5 |
| NZ03 | 3 |
| NZ07 | 2 |
| NZ11 | 2 |
| NZ90 | 2 |
| NZ15 | 1 |

Unlabelled paths score >= 7: 4

| score | severity | hops |
|---|---|---|
| 10.00 | CRITICAL | internet > halyardbackups[NZ11] |
| 10.00 | CRITICAL | internet > halyardcrmexports[NZ11] |
| 8.00 | CRITICAL | internet > sg-03c45372568aef802[NZ90] > abfc0863b14abbb3[NZ90] > customer-portal[NZ90] |
| 7.00 | CRITICAL | internet > invoice-pdf[NZ07] > invoice-pdf-fn-role[NZ07] > halyard-billing-exports[NZ16] |

Unlabelled paths score >= 5: 5

| score | severity | hops |
|---|---|---|
| 10.00 | CRITICAL | internet > halyardbackups[NZ11] |
| 10.00 | CRITICAL | internet > halyardcrmexports[NZ11] |
| 8.00 | CRITICAL | internet > sg-03c45372568aef802[NZ90] > abfc0863b14abbb3[NZ90] > customer-portal[NZ90] |
| 7.00 | CRITICAL | internet > invoice-pdf[NZ07] > invoice-pdf-fn-role[NZ07] > halyard-billing-exports[NZ16] |
| 5.00 | HIGH | svc-prod-admin-legacy[NZ90] |

All false-positive paths: 23

| score | entry hop | hops |
|---|---|---|
| 10.00 | exposes PUBLIC_DATA_STORE (azure_storage_account) | internet > halyardbackups[NZ11] |
| 10.00 | exposes PUBLIC_DATA_STORE (azure_storage_account) | internet > halyardcrmexports[NZ11] |
| 8.00 | exposes PUBLIC_NETWORK_EXPOSURE (aws_security_group) | internet > sg-03c45372568aef802[NZ90] > abfc0863b14abbb3[NZ90] > customer-portal[NZ90] |
| 7.00 | exposes PUBLIC_NETWORK_EXPOSURE (aws_lambda_function) | internet > invoice-pdf[NZ07] > invoice-pdf-fn-role[NZ07] > halyard-billing-exports[NZ16] |
| 5.00 | entry NO_MFA (aws_iam_user) | svc-prod-admin-legacy[NZ90] |
| 4.00 | exposes PUBLIC_NETWORK_EXPOSURE (gcp_compute_instance) | internet > web-fe-2[NZ10] |
| 4.00 | exposes PUBLIC_NETWORK_EXPOSURE (gcp_compute_instance) | internet > api-1[NZ10] |
| 4.00 | exposes PUBLIC_NETWORK_EXPOSURE (gcp_compute_instance) | internet > api-2[NZ10] |
| 4.00 | exposes PUBLIC_NETWORK_EXPOSURE (aws_security_group) | internet > sg-02594332f6ea5f987[NZ03] > 48a340fa450f90fc[NZ03] > pricing-api[NZ03] |
| 4.00 | exposes PUBLIC_NETWORK_EXPOSURE (aws_security_group) | internet > sg-0ebc08638c58e809e[NZ03] > 47f55f7d1a95d4a3[NZ03] > notifications-api[NZ03] |
| 4.00 | exposes PUBLIC_NETWORK_EXPOSURE (aws_security_group) | internet > sg-0a35e5b101ebe8356[NZ03] > 63b669584672086a[NZ03] > webhooks-ingest[NZ03] |
| 4.00 | exposes PUBLIC_NETWORK_EXPOSURE (gcp_compute_instance) | internet > web-fe-1[NZ10] |
| 2.00 | exposes PUBLIC_DATA_STORE (gcp_storage_bucket) | internet > halyard-gcp-web-assets[NZ10] |
| 2.00 | exposes PUBLIC_NETWORK_EXPOSURE (aws_eks_cluster) | internet > halyard-eks-dev[NZ15] |
| 2.00 | exposes PUBLIC_DATA_STORE (aws_s3_bucket) | internet > halyard-docs-site[NZ01] |
| 2.00 | exposes PUBLIC_DATA_STORE (aws_s3_bucket) | internet > halyard-www-static[NZ01] |
| 2.00 | exposes PUBLIC_DATA_STORE (aws_s3_bucket) | internet > halyard-marketing-assets[NZ01] |
| 2.00 | exposes PUBLIC_DATA_STORE (aws_s3_bucket) | internet > halyard-status-page[NZ01] |
| 2.00 | exposes PUBLIC_DATA_STORE (aws_s3_bucket) | internet > halyard-careers-site[NZ01] |
| 2.00 | exposes PUBLIC_DATA_STORE (aws_s3_bucket) | internet > halyard-press-images[NZ01] |
| … | | 3 more |

Near-miss resources that produced paths: 4

| near-miss resource | paths | best score |
|---|---|---|
| sg-03c45372568aef802 | 1 | 8.00 |
| customer-portal | 1 | 8.00 |
| abfc0863b14abbb3 | 1 | 8.00 |
| svc-prod-admin-legacy | 1 | 5.00 |

Findings and Issues (alert-fatigue proxy)

| measure | value |
|---|---|
| ingested records / FAIL findings | 311 / 103 |
| FAIL findings by severity | CRITICAL 8, HIGH 26, MEDIUM 41, LOW 28 |
| open Issues | 99 |
| open Issues by severity | CRITICAL 8, HIGH 26, MEDIUM 41, LOW 24 |
| open Issues by kind | single 99 |
| CRITICAL + HIGH open Issues | 34 (on a TP-chain resource: 6; on benign resources: 28) |
| prioritize: ranked findings | 103 |
| prioritize: TP-chain findings in top 10 | 2 of 6 TP findings |
| prioritize: TP-chain findings in top 20 | 5 of 6 TP findings |
| prioritize: best rank of each TP's findings | TP1 #4, TP2 #17, TP3 #33 |

Reading the numbers:
- **2 of 3 chains found; TP2 at 3.80** (the same pipeline-poisoning score gap as P12 in the labelled
  lab). **TP3 is missed outright**: `graph export` holds every edge of the chain (internet `exposes`
  the function with `exposure: wide`, `runs_as` the role, `grants_access_to` the table marked
  `sensitive: true`), yet no path is reported.
- **4 false positives score ≥ 7** and would be raised as CRITICAL: two Azure storage accounts from a
  catalog alias that maps a TLS-1.1 check to "public blob" (`storage_ensure_minimum_tls_version_12`
  → `AZ_STORAGE_PUBLIC_BLOB`), the near-miss `customer-portal` SG → ALB → Fargate chain (8.00), and
  `invoice-pdf` (AWS_IAM function URL with an org-conditioned `Principal *` policy, 7.00 via the
  toxic floor).
- **The bulk (17 of 23) are one-step or plumbing-only exposure paths** that end on the exposed
  resource itself: 9 public-by-design website buckets, 4 GCE web hosts open on 443 only, 3 443-only
  SG → ALB → private ECS chains, 1 narrow-CIDR dev EKS endpoint. The other two: a NO_MFA user with
  no credentials and no policies reported as a one-step identity path (5.00), and the second
  org-conditioned Lambda URL (`feature-flag-reader`, 0.61).
- **Alert fatigue**: 34 open CRITICAL/HIGH Issues, 28 of them on benign resources.

Owners for each gap were in `lab/known_gaps.yaml` under `noise:` (pruned by the P1-ENGINE noise
round above). Nothing in the engine was changed to produce these baseline numbers.

## Path likelihood table (traversal, B2)

`score = min(10, likelihood × priority)`, priority 10 / 5 / 2 / 1 for crown-jewel tier 4 / 3 / 2 / 1.
`likelihood = entry × Π(hop × decay)`. The decay is 0.95 per lateral hop. It is not applied to the
initial access hop from the internet, nor to plumbing hops through an exposed network control.
Paths with likelihood < 0.1 (`MinLikelihood`) are not reported. A complete path never scores below
the best crown jewel it passes. Each step records its hop value in `evidence.likelihood`.
Since the P1-ENGINE noise round the tier comes only from typed facts (configured crown jewel,
sensitive / crown data store, admin-level identity); a path must end at such an impact target, and
an exposed resource that is not one is listed in `Analysis.Exposures` (`docs/scoring.md` "Path score").

| edge / entry | condition | value |
|---|---|---|
| internet → node (`exposes`) | public data store (anonymous read) | 1.0 |
| | exposed with a CVE: reachability 0.8, raised to 0.9 only when a CVE is in CISA KEV (a CVE count alone no longer prices 0.95) | 0.8 / KEV 0.9 |
| | exposed with weak authentication | 0.8 |
| | exposed (plain) | 0.8 |
| | width factor: wide ×1.0, narrow ×0.5, trusted / private → no edge, listed in `suppressed` | |
| | target requires authentication (AWS_IAM / authorizer), org-conditioned `Principal *`, or anonymous access disabled → private, listed in `suppressed` with the reason; serverless URL / object storage with no deciding attribute → `confidence: hint` | |
| exposed SG / NSG / firewall → workload (`allows_traffic_to`) | plumbing: the internet hop priced the exposure | 1.0, no decay |
| | through an authenticating load balancer / API gateway (OIDC, Cognito, IAM authorizer, WAF): `auth-lb ×0.3` chip, no toxic floor | 0.3, no decay |
| other `allows_traffic_to` | from an exposed non-network node: 0.55 (to a CVE-bearing target: max(0.55, CVE gate)); lateral 0.5 | |
| workload → its identity (`runs_as`, `attached_to`) | IMDSv1 and internet-exposed (SSRF) | 1.0 |
| | mounted service-account token on an exposed pod (file read suffices) | 0.8 |
| | exposed with CVEs: the CVE gate (engine round 2, `internal/attackpath/cvegate.go`): KEV 0.9 · EPSS ≥ 0.5 → 0.6 · EPSS ≥ 0.1 → 0.3 · EPSS < 0.1 → 0.1 · CVE ids without a KEV/EPSS row or a bare UNPATCHED/CVE count → 0.3 (hint) | 0.9 / 0.6 / 0.3 / 0.1 |
| | remote-login port (SSH / RDP / WinRM) open to the internet | 0.5 |
| | publicly invocable serverless function without auth | 0.5 |
| | anything else, or not internet-exposed | 0.1 (below the reporting floor) |
| non-workload → identity hint (`attached_to`, `runs_as`) | scanner hint, attachment not verified | 0.5 |
| `has_policy` | to an admin / wildcard policy | 1.0 (else 0.9) |
| `grants_access_to`, `stores_data_in` | from an over-privileged identity | 1.0 (else 0.85) |
| `can_assume` | from a repository / CI identity (federated OIDC trust) | 1.0 |
| | into a role with CROSS_ACCOUNT_TRUST | 0.9 |
| | into an admin role | 0.8 (else 0.6) |
| `bound_to` | to cluster-admin / via a CLUSTER_ADMIN binding | 1.0 (else 0.6) |
| `member_of` | into an identity | 0.8 |
| entry: identity / repo (no network path) | NO_MFA 0.5, STALE_CREDENTIALS 0.4, WEAK_AUTH 0.45, SECRET_EXPOSURE 0.6, BRANCH_UNPROTECTED 0.4 | combined as noisy-OR 1 − Π(1 − p) |
| | user credential weaknesses need a usable credential: `console_access=false` and no active key → no entry; usability unknown → ×0.5, `confidence: hint` | |
| entry: role assumable from outside the account | wildcard principal 1.0, foreign account without ExternalId 0.7, with ExternalId 0.4 | |

### Toxic-combination floor (B3, planning decision)

A graph-traversal path gets a **likelihood floor of 0.7** before priority is applied when both hold:

1. its entry hop is **wide** internet exposure (`exposure = wide`: a 0.0.0.0/0 or ::/0 source, or no
   source restriction known), and
2. its target is **admin-level** or a **sensitive data store**:
   - admin-level: an identity or RBAC binding with `OVERPRIVILEGED_IDENTITY` or `CLUSTER_ADMIN`; the
     `cluster-admin` ClusterRole; a project / subscription / account admin role (`AdministratorAccess`,
     `roles/owner`, `roles/editor`, Owner / Contributor / User Access Administrator at subscription or
     management-group scope); or a configured crown jewel at level `very_high` / `high`;
   - sensitive: a data store marked sensitive (or a configured `very_high` / `high` data store).

The path's last step is tagged `evidence.toxic_combination` = `exposed+admin` or `exposed+sensitive`
(with `evidence.toxic_reason`), and its `because` ends with a one-line reason, e.g.
`; toxic combination exposed+admin: wide internet exposure reaches nimbus-lab-jump-mi
(admin / over-privileged identity); likelihood floored 0.38 → 0.70`. With priority 10 such a chain
scores ≥ 7. The rule mirrors Wiz "toxic combinations" and Tenable's "toxic cloud trilogy" (public
exposure + critical vulnerability or excessive privilege + sensitive data): exposure that leads to
admin rights or sensitive data is critical even when the per-hop table multiplies to a modest number.

It does **not** apply to narrow, trusted or private exposure; to non-internet entries (identities,
repositories, external accounts); to rule chains (they have no likelihood, so `weak_link` chains are
never floored); or to targets that are neither admin-level nor sensitive. It only lifts a path
that is already reported: a path below `MinLikelihood` (0.1) is not created by the floor, so removing
the weakness that enabled a hop, or the exposure itself, still breaks the path (`Simulate` and the
fix re-evaluation apply the same floor). A path that ends past a floored jewel keeps that jewel's
score and tag. The per-hop table above is unchanged. Code: `internal/attackpath/toxic.go`; tests:
`internal/attackpath/toxic_test.go`.

An identity that is both the entry and a tier ≥ 3 crown jewel is reported as a one-step path. P05
is an example: an admin user with no MFA and a 400-day key has likelihood 1 − 0.5·0.6 = 0.7, which
scores 7.0. The credential-hop rows come from the planning-session decision: IMDSv1 + exposed is
1.0, CVE + exposed takes the CVE gate value (KEV 0.9, EPSS ≥ 0.5 0.6, EPSS ≥ 0.1 0.3, EPSS < 0.1 0.1, unknown 0.3 hint; engine round 2), anything else is 0.1. B2 added the SA-token, remote-login and serverless
rows; these are judgment calls flagged for review.

## Native relationship contract

`resource.related` entries may be strings or typed objects. Both forms can appear in one record.
Strings are the legacy form, and they become unverified `attached_to` hints.

```json
"related": [
  "arn:aws:ec2:us-east-1:111111111111:security-group/sg-1",
  {"id": "arn:aws:iam::111111111111:role/app", "kind": "runs_as", "attr": {"via": "instance profile app"}},
  {"id": "arn:aws:s3:::pii", "kind": "grants_access_to", "attr": {"actions": "s3:GetObject", "because": "inline policy ExportRead"}}
]
```

- `kind` is any graph edge kind. The canonical kinds are `attached_to`, `runs_as`, `bound_to`, `member_of`, `trusts`,
  `has_policy`, `grants_access_to`, `runs_on`, `allows_traffic_to`, `can_assume`, `exposes`, `contains` and `stores_data_in`.
  The aliases are:
  - `policy` → `has_policy`
  - `resource` → `grants_access_to`
  - `sts_assume_role_allows` → `can_assume`, pointing **from** the listed principal to this resource
  - `exposed_to_internet` → internet `exposes` this resource
- An unknown kind is kept as an `attached_to` hint, with `declared_kind` recorded on the edge.
- `trusts` (role → principal) also adds `principal -can_assume-> role`.
- `attr` is copied onto the edge. `attr.because` becomes the hop's explanation. Without it, the explanation is
  derived from attributes such as `ports`, `principal`, `actions` and `via`. In both cases it ends with the
  declaring finding.
- The Go model keeps every ID in `Resource.Related`, so string consumers keep working. It keeps the typed entries
  in `Resource.Relations`. On output, `related` stays a string list and typed entries are written as `relations`
  (`internal/model/relation.go`). The Python SDK ignores the extra key.
- `attributes.exposure_cidrs` is a list of the public sources the scanner saw. Analysis classifies it as
  wide / narrow / trusted against `trusted_cidrs` (`core.ExposureWidth`).

**What the lab generator emits (done in B3).** `lab/local/estate/estate.go` `findingResource` writes
each estate relationship as `{"id": rel.To, "kind": rel.Kind, "attr": {"via": rel.Via}}`, leaving
out `attr` when `via` is empty (`FindingResource.Related []any`). `attributes.lab_relationships` is
gone. The estate's kinds (`attached_to`, `runs_as`, `allows_traffic_to`, `trusts`,
`grants_access_to`, `contains`, `bound_to`, `can_assume`) are all accepted as written.
`lab/local/out/estate.findings.json` (`make lab-local`) was JSON-identical to
`internal/attackpath/testdata/lab_typed.findings.json` at B3; that fixture is the B3 (S01–S14) snapshot
and does not carry S15–S30. `TestLabEmitsTypedRelationships` guards the typed form of the lab output.
The CLI passes `trusted_cidrs` to traversal (`TraversalOptions.TrustedCIDRs`), the rule engine
(`EvaluateWith`) and `AnnotateExposure` before the graph is stored; `cloud-posture paths` prints
`suppressed (trusted): N` with one reason per node.

## Cloud lab: validated, never applied

`lab/terraform/` produces the same scenarios with the same names. Every resource is tagged:
- `nimbus_lab_id = <estate resource id>`;
- a `cost_ceiling_usd` tag;
- an `expires_at` tag.

The AWS output `lab_id_map` maps real ARNs to lab ids, so the same ground truth can score a cloud run.

Guard rails:
- Every target requires `NIMBUS_E2E=1`, and every root module has a `nimbus_e2e` variable validation.
- To bring the lab up or down: `NIMBUS_E2E=1 make -C lab/terraform lab-up` / `lab-down`. These targets live in `lab/terraform/Makefile` because Track H may only add `lab-local` and `groundtruth` to the root Makefile.
- `lab/terraform/nightly-destroy.workflow.yml.example` sketches the nightly run: OIDC credentials, apply, scan, score, then always destroy, plus a tag-based reaper.

Status (plan v3 §9 item 1, step 0, 2026-10-09): **validated, never planned or applied.** `make lab-validate`
(`lab/terraform/validate.sh`) runs `tofu fmt -check -recursive` on `lab/terraform` and `tofu init -backend=false`
+ `tofu validate` on temporary copies of `aws/`, `azure/` and `gcp/`. All three pass with OpenTofu 1.13.1 (providers
resolved: hashicorp/aws 5.100.0, archive 2.8.1, azurerm 4.81.0, google 6.50.0); no HCL change was needed. Apply →
scan → score → destroy is **blocked on O1** (no lab credentials exist): no plan has been run, no resource has
been created, and the live numbers do not exist. S15–S30 (P1-LAB L1) have no Terraform twin yet.
What the cloud lab cannot do:
- It cannot seed a 400-day-old key. Creating any key would also put a secret in state.
- It cannot seed a CVE image.
- S14 needs an AWS Organization.
- EKS (S07/S08) is off by default because of cost.

## Scanner interop (Checkov / Trivy goldens)

Plan v3 §4 P1-LAB L2. The two IaC scanners were run against `lab/terraform/{aws,azure,gcp}` (no cloud
needed) and their raw JSON is committed under `lab/golden/<tool>/<version>/` with `cmd.txt` (command,
version, date, lab commit) and `sha256.txt`. `tests/groundtruth/golden_test.go` ingests each golden through
the real adapter (`cloud-posture ingest --source checkov|trivy`) into a temp DB and checks it against
`lab/golden/expectations.yaml`, which lists, per tool, every lab weakness the tool detects (native check +
resource) and the canonical id nimbus must map it to. A listed detection missing from the raw golden fails
the test outright; a detection that nimbus maps wrongly or not at all is a gap in `lab/known_gaps.yaml`
`golden:` (same gate as `gaps:`; `GROUNDTRUTH_STRICT=1` ignores it).

| tool (pinned) | how it ran | lab weaknesses detected | detections mapped to the expected canonical id | FAIL findings | catalog coverage (mapped / FAIL) | unmapped FAIL findings (distinct checks) |
|---|---|---|---|---|---|---|
| Checkov 3.3.26 (`pip install checkov==3.3.26`) | `checkov -d lab/terraform/<cloud> -o json --skip-download` | 17 (21 detections) | 21 / 21 (100.0%) | 95 | 85.3% (81/95) | 14 (13) |
| Trivy 0.75.0 (Homebrew; embedded checks, `--skip-check-update`) | `trivy config -f json lab/terraform/<cloud>` | 10 (11 detections) | 11 / 11 (100.0%) | 60 | 91.7% (55/60) | 5 (5) |

Measured 2026-10-10 (`make groundtruth-golden`, after catalog alias batch 3 and the W6 open-ingress canonicals `EC2_SG_OPEN_HTTP` ← `CKV_AWS_260`, `AZ_NSG_UNRESTRICTED_SOURCE` ← `AVD-AZU-0047`, renamed by W7 from the wrong "any port" `AZ_NSG_OPEN_ALL`). The table is checked
against the measured numbers by `TestGoldenScannerInterop` (a stale row fails the test), and the
coverage floors are 80% for Checkov and 85% for Trivy (`tests/groundtruth/golden_mapping_test.go`).
`cloud-posture catalog unmapped --tool checkov|trivy [--from <scanner json>] [--format json]` prints the
same coverage and lists each unmapped check id with its count, for the golden or for any scanner output.
What the numbers say:
- **Every lab weakness either tool detects maps to the expected canonical id** (21/21 Checkov, 11/11
  Trivy). The earlier gaps (Trivy 0.6x+ ids `AWS-0028` / `KSV-0111` not matching `AVD-` aliases, empty
  Trivy Kubernetes resource ids, missing `CKV_AWS_274` / `CKV_AWS_258` / `CKV_AWS_70` / `CKV_GCP_117` /
  `CKV_AZURE_34` aliases, no `GCP_INSTANCE_PUBLIC_IP`) are fixed; the wrong `CKV_GCP_32`, `CKV_GCP_49` and
  `CKV_AWS_260` aliases were removed (`CKV_GCP_49` now maps to its own `GCP_SA_IMPERSONATION_ROLE`;
  `CKV_AWS_260` to its own `EC2_SG_OPEN_HTTP`, Trivy `AZU-0047` to `AZ_NSG_UNRESTRICTED_SOURCE` (an inbound rule from any source address on the port that rule opens; HIGH, no RDP/SSH control), both PUBLIC_NETWORK_EXPOSURE).
- **What stays unmapped is mostly operational or reliability hygiene** with no security meaning in the
  catalog: Checkov EBS-optimised instances, RDS enhanced monitoring and copy-tags-to-snapshots, S3
  lifecycle / event notifications / cross-region replication, Lambda concurrency and DLQ, Kubernetes
  liveness / readiness probes, Azure storage soft-delete and replication, a security group not attached to
  anything. Trivy: geo-redundant replication, infrastructure encryption, GCP default firewall rules, privileged
  container ports and trusted registries. Each would need a new canonical entry, not a looser alias.
- Not detectable from `lab/terraform` by either tool: the 400-day key, MFA, CVE image, branch protection,
  SCP (local-only or outside the HCL), the EKS endpoint (`enable_eks = false`), the cross-account
  ExternalId, Azure role assignments, and every S15–S30 scenario (no Terraform twin yet). Both tools
  correctly leave the corporate-only SSH rule (W27) alone. Per-tool lists: `lab/golden/expectations.yaml`.

Regenerate with `CHECKOV=… TRIVY=… make lab-golden` (writes a new `<version>/` directory; update
`expectations.yaml` `version:` and re-run). `.github/workflows/benchmark.yml` runs `make groundtruth` and
`make groundtruth-golden` on push and pull request and publishes the lab, noise and interop tables as the
job summary. These are finding-level (mapping) numbers; per-tool *path* recall needs a cloud run (Prowler) and
stays blocked on O1.

## Adding Prowler, Checkov and Trivy

Golden outputs live in `lab/golden/<tool>/<version>/` (not `testdata/golden/`, which holds the output
formatters' goldens). Each version directory holds:
- `cmd.txt`: the command, tool version, date and lab commit;
- the raw outputs (`aws.json`, `azure.json`, `gcp.json` for the IaC tools);
- `sha256.txt`.

Checkov and Trivy are done (section above). Prowler needs the cloud lab (`prowler aws --output-formats
json-ocsf`), so it waits for credentials (O1); per-tool path recall and precision on one estate (STRAT §7.3,
gap analysis O1) come with it.
