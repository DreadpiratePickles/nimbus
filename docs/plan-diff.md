# Plan-time attack-path diff

"This PR opens N / escalates E / lowers L / closes M attack paths." `cloud-posture pr-comment --plan-json` reads a saved
Terraform / OpenTofu plan, predicts the attack paths before and after it, and posts the difference
as one sticky pull-request comment (plan v3 AP10, P1-PLANDIFF). Public launch is gated on the
Phase 1 exit (council decision 3).

```sh
terraform plan -out tf.plan && terraform show -json tf.plan > plan.json   # or: tofu …
cloud-posture pr-comment --plan-json plan.json                             # print the comment
cloud-posture pr-comment --plan-json plan.json --repo owner/name --pr 12 \
  --sarif paths.sarif --fail-on-opened                                     # post it, gate on it
```

## How it works

1. **Plan ingest** (`internal/iac/plan.go`). `ParsePlanJSON` keeps managed resources only and
   normalises each change to `create | update | delete | replace | no-op`. `Plan.Resources(side)`
   maps the before or after values to graph resources with the same rules as the HCL scanner:

   | plan resource | graph effect |
   |---|---|
   | `aws_security_group` (+ `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`) | ingress rules; world-open → `EC2_SG_OPEN_SSH/RDP/ALL` |
   | `aws_instance` | `attached_to` its security groups; `runs_as` the role of its instance profile; IMDSv1 when `http_tokens` ≠ `required`; public reachability from `public_ip` / `associate_public_ip_address` |
   | `aws_iam_role` (+ `_policy_attachment`, `_role_policy`, `aws_iam_policy`) | admin (`AdministratorAccess`, `*:*`) → `OVERPRIVILEGED_IDENTITY`; foreign-account principals → `CROSS_ACCOUNT_TRUST`; GitHub OIDC subjects (`oidc_subjects`, `oidc_subject_class`) |
   | `aws_s3_bucket` (+ `_acl`, `_policy`, `_public_access_block`) | public ACL or unconditioned `Principal *` → `PUBLIC_DATA_STORE`; org/account/VPC conditions and a full public access block keep it private |
   | `aws_lambda_function` (+ `_url`) | `runs_as` its role; URL `authorization_type = NONE` → `LAMBDA_PUBLIC` |
   | `aws_eks_cluster` | public endpoint with `public_access_cidrs` |
   | `aws_db_instance` | `publicly_accessible`, security groups, `storage_encrypted = false` |

   Node ids: the ARN when known (the before ARN wins, so a replace keeps its id), a natural id
   (`sg-…`, `arn:aws:s3:::bucket`), else `tf:<address>`. Values unknown until apply (a new
   instance's security group ids) are linked through the configuration's `references` lists;
   expressions are never evaluated.
2. **Overlay** (`internal/pathdiff`). Live mode clones the live graph, applies every resource
   whose before and after differ (retract what only the before side contributed, attach the after
   side), recomputes the internet exposure of every workload behind a changed security group (the
   union of its groups' public ingress sources, gated by public reachability), and derives
   repository → role `can_assume` edges from planned GitHub OIDC trusts. Plan-only mode builds the
   before and after graphs from the plan alone.
3. **Diff**. `attackpath.Traverse` runs on both graphs; paths are compared by path Issue id
   (`model.PathIssueID(kind, entry, anchor, rule)`) refined by the entry they enter at
   (`attackpath.EntryKey`: an internet path's entry is `internet:<exposed node>`; PathRef
   `entry_key`). A path rerouted through a new middle hop keeps its key and is not "opened" (it is
   counted as rerouted); a **second public host** put in front of an anchor that is already
   reachable is a new entry and is **opened** (it trips `--fail-on-opened`, also with
   `--opened-only`), and removing one closes that entry only. The Issue id itself is unchanged, so
   two opened entries can share one Issue. Score changes of surviving Issues are listed apart,
   and two kinds get headline counts: an **escalation** is a surviving Issue whose band rises into
   High or Critical (`pathdiff.Escalates`: Low/Medium → High/Critical, High → Critical;
   `bad.plan.json` without the trusted range: 1.9 → 7.0, Low → High); a **lowering** (de-escalation
   credit, `pathdiff.Lowers`) is a surviving Issue whose band drops (`revert.plan.json` without the
   trusted range: 7.0 → 1.9, High → Low). Moves inside one band are score changes only.
   Each opened / closed path carries the hop the plan changed, that hop's `because`, the plan
   address that changed it, the score, toxic tag, confidence and a fix template id
   (`catalog` remediation, e.g. `sg_open_port`).

## Confidence modes

| mode | when | confidence | what it misses |
|---|---|---|---|
| `live` | a scan DB exists (`--live auto`, default) | `inferred` on changed hops; unchanged hops keep their edge confidence | values unknown until apply |
| `plan-only` | no DB (CI), or `--live off` | `hint` for everything (the comment says so) | anything outside the plan: live roles, branch protection, other security groups |

Set trusted ranges with config `trusted_cidrs` or `--trusted-cidr` (Action input
`trusted-cidrs`): exposure from them is never an entry.

## CI-entry floor (planning decision on P12)

A repository whose default branch is unprotected (`BRANCH_UNPROTECTED`, or attribute
`any_contributor_write`) plus a role trust for that repository's GitHub OIDC tokens whose subject
is **wildcard** (no `sub` condition, `repo:org/*`) or **unpinned** (`repo:o/r:*`,
`ref:refs/heads/*`, `pull_request`) is pipeline poisoning: anyone who can push gets the role. A
traversal path entering at such a repository whose trust hop has a matching wildcard / unpinned
subject and whose target is admin-level gets likelihood ≥ 0.7, tag
`toxic_combination: ci-entry`, and the hop attributes `oidc_subject` / `oidc_subject_class`
(`internal/attackpath/toxic.go`, classifier `saas.ClassifyOIDCSubject`). A pinned subject (one
branch, tag or environment), a protected repository, an unstated subject or a non-admin target
gets no floor. In the overlay, planned trusts become repository → role edges carrying the same
attributes. Lab P12 moved 3.80 → 7.00; F05 (pinned, protected) stays suppressed.

## Redaction and untrusted input

* `--redact auto` (default; Action input `redact`) is on unless the GitHub event says the
  repository is private (unknown visibility redacts). Redacted comments and SARIF carry counts,
  hop relations and types with a 4-hex hash (`aws_iam_role [a663]`), scores, toxic tags and fix
  template ids; no names, ids, ARNs, accounts or IPs. `--max-paths` caps the list (counts and
  footers always cover everything).
* Every cloud- or plan-controlled string in the comment passes `md()`: Markdown and HTML control
  characters, `:` and `@` become HTML entities, control characters become spaces, length is
  capped; a resource named `<!-- nimbus-plan-diff -->` cannot spoof the sticky marker. Fix
  template ids and commands are allow-listed.
* The plan JSON is untrusted: 20 MiB size cap (`--plan-max-bytes`), nesting depth 128 checked by
  an iterative byte scan before decoding, 50,000 resource changes; plan ingest reads no file named
  inside the plan and runs nothing (`TestPlanIngestReadsNoFilesAndRunsNothing`); `FuzzPlanJSON`.
* The Action refuses plan diff under `pull_request_target`; the plan and its JSON stay in
  `$RUNNER_TEMP` and are never uploaded; a fork PR's read-only token cannot comment, which is a
  warning, not a pass of the gate. Never upload the scan DB, `--diff-json` output or `risk.json`
  from a public repository.

## Output

* Sticky comment: found by the marker `<!-- nimbus-plan-diff -->` (only comments by
  `--bot-login` when given), edited with PATCH, never posted twice (`gitops.StickyComment`).
* Headline: `this PR opens O / escalates E / lowers L / closes C attack paths`, then sections
  Opened, Escalated to High/Critical, Lowered, Closed, Score changes.
* Footer, each on its own line: `nimbus-opens-paths: N`, `nimbus-escalates-paths: N`,
  `nimbus-lowers-paths: N`, `nimbus-closes-paths: N`; fix PRs end with `nimbus-closes-paths: N`.
  `tools/northstar` sums all four (tools/northstar/README.md); lowers is credit, never added to
  closes.
* `--sarif FILE`: one `NIMBUS_PATH_OPENED` result per opened path (error at score ≥ 7), capped at
  GitHub's 25,000 results.
* Ids: with redaction on, the SARIF `issue_id` / `nimbusPathIssue/v1` and the `--diff-json` `issue_id`s
  are run-keyed (`run-…`, HMAC with a random per-run key, or `NIMBUS_ID_KEY` (≥ 16 bytes, a CI secret)
  when they must stay stable for alert continuity), so no digest of a redacted name is published.
  Unredacted outputs keep the raw path Issue digest and say so: SARIF run property
  `nimbus_id_scheme: "unkeyed"`, `--diff-json` `"id_scheme": "unkeyed"`.

## Gate (`--fail-on-opened`)

| the plan… | exit with `--fail-on-opened` | with `--fail-on-opened --opened-only` |
|---|---|---|
| opens a path | 3 | 3 |
| escalates a path into High/Critical | 3 | 0 (still reported) |
| lowers a path's band | 0 | 0 |
| closes a path / only changes scores inside a band | 0 | 0 |

The scan gate uses exit 2, so the two stay distinguishable in CI logs. A comment that cannot be
posted (fork token) is a warning and never hides the gate result.

## Suggested changes (`--iac DIR`)

With `--iac` (the Terraform root, repository-relative; empty = off) each opened or escalated path
whose fix has a deterministic patcher is matched to the native Terraform scan of that root: same
canonical id (`EC2_SG_OPEN_SSH`, …), same resource address as the plan address that changed the
path (`module.web.aws_security_group.ssh`; the module address makes the patcher refuse a
same-named block in another module). `iac.PatchTerraformWith` patches it, and the patch becomes a
GitHub ```` ```suggestion ```` block only when all hold:

* it is **one hunk** of at most 40 lines (`pathdiff.SingleHunk`: no run of more than 3 unchanged
  lines inside the region; a pure insertion is anchored to the line above);
* it appends **no variable block** (that is a second hunk) and changes no **shared module**
  source (`Callers` > 1);
* it does not widen access, and the re-scan (`verifyPatchResult`) does not say "not fixed". A
  patch the re-scan cannot prove (a source moved to a variable) is shown as "re-scan unverified:
  review the values" with the patch confidence.

Otherwise the path keeps the CLI hint (`fix: template … — cloud-posture fix --finding …`), as do
fixes without a deterministic patcher (e.g. the committed fixture, whose SSH source is
`var.ssh_cidr`). The sticky comment lists the blocks under "Suggested changes" with
`file line N` / `lines N–M` (relative to the `--iac` root). GitHub offers **Commit suggestion**
only on review comments, so with `--repo`/`--pr` (and `--review-suggestions`, default true) each
block is also posted once as a pull-request review comment on `start_line..line`, side RIGHT, on
the PR head commit (`pull_request.head.sha` from `$GITHUB_EVENT_PATH`, else the API). A hidden
`<!-- nimbus-suggestion:<hash> -->` marker keeps re-runs from posting it twice; lines outside the
PR diff (GitHub 422) are a warning. `$GITHUB_API_URL` is honoured (GHES).

Escaping: the suggestion content is the replacement code, verbatim (escaping it would commit
entities). Its fence is one backtick longer than the longest backtick run in the content
(`pathdiff.Fence`, at least three), so repository-controlled text cannot close the block and inject
Markdown; the file path and explanation go through `md()` like every other string.

## Limits

AWS resource types only; NACLs, route tables and SCPs are not evaluated on the plan (as in the
live engine); `count` / `for_each` instances that reference each other by index link by base
address; a live security group without an `ingress` attribute never removes exposure; GitHub
branch protection is read from the live graph only, so the CI-entry rule needs a scan DB.

## Verify locally

```sh
go test ./internal/iac/ -run Plan ./internal/pathdiff/ ./internal/cli/ -run 'PRComment|PlanComment|Suggestion' -count=1
go test ./internal/iac/ -run '^$' -fuzz FuzzPlanJSON -fuzztime 60s
NIMBUS_E2E_NETWORK=1 go test ./internal/cli -run TestActionFixtureE2E -v   # needs tofu or terraform
```

The fixture (`testdata/action-fixture`) is a module with an EC2 instance whose instance profile
holds AdministratorAccess behind an SSH security group. Plans are made against the committed
`fixture.tfstate` with `plan -refresh=false` and mock credentials (no AWS call): `-var
ssh_cidr=0.0.0.0/0` opens 1 path, the revert closes 1. `testdata/action-fixture/plans/*.json` are
the committed OpenTofu 1.13.1 outputs the unit tests use. CI: `.github/workflows/action-e2e.yml`.
