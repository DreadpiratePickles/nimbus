# nimbus capability inventory (as built, 2026-10-09)

Read-only audit of `/Users/bobbymeher/Documents/nimbus`, written to support a competitive gap analysis. The facts come from the code, not from ROADMAP or README claims. Where those claims differ from the code, this document says so.

`internal/dashboard/*` was being rewritten by another agent during the audit, so it is excluded.

Unless noted, all paths are relative to the repo root.

**Status legend**

| Status | Meaning |
|---|---|
| `real` | Implemented, wired end to end into the CLI, and tested against fakes or golden files |
| `partial` | Implemented, with the gaps named in that section |
| `stub` | Exists in name only |
| `absent` | Not there |

**Nothing in this repo has ever run against a live AWS, Azure or GCP account** (`.planning/STATE.md:4`). Every "real" below means *real against fakes*.

## Summary

| # | Area | Status | One-line evidence |
|---|---|---|---|
| 1 | Collectors (AWS/Azure/GCP/K8s/GitHub/Okta/M365) | partial | 48 native checks (AWS 21, Azure 7, GCP 6, K8s 7, GitHub 3, Okta 2, M365 2). Fakes only. GCP project IAM is never collected. False-pass logic in M365, AWS IAM and Azure NSG. `internal/collector/**` |
| 2 | Scanner adapters | partial | 6 parsers with golden tests (`internal/adapters/*`). No Prowler v3 fixture. `scanner/runner.go` has 0% coverage and discards output when stderr contains "error" (`runner.go:317`) |
| 3 | Canonical catalog | real | 75 checks. Aliases: prowler 58, checkov 58, trivy 46, scoutsuite 38, steampipe 73. Hand curated, some aliases wrong. Python copy has drifted to 66 entries |
| 4 | Store / SQL | partial (critical defects) | SQLite views work. Read-only guard is a substring denylist on a read-write connection, bypassed by probe (`query.go:35-58`). SQL injection in view DDL (`store.go:404-408`). No migrations |
| 5 | Graph + attack paths | partial | 13 edge kinds, 9 classes, 11 rules, DFS of up to 6 hops. Min-cut is greedy set cover. K8s and GCP service-account chains never fire (`graph.go:365`) |
| 6 | Risk scoring | partial | Go sigmoid (`risk.go:204`) and Python logistic (`risk.py:218`) are different formulas. Score is swapped but the band is kept (`scan.go:444-450`). Most context inputs are name heuristics |
| 7 | Remediation | partial | 42 templates covering 36 of 75 IDs. Native HCL scanner has 20 rules and patches 19 IDs. Patcher can hit the wrong resource (`iac.go:556`). Auto-PR writes the wrong file (`fix.go:230` vs `gitops.go:121`). gitops has 0% coverage |
| 8 | Compliance | partial | 11 frameworks. Mappings are hand written. PCI labelled 4.0 uses 3.2.1 IDs. Go/Python control counts differ (cis_aws 42 vs 19). Custom frameworks lose their inventory (`cli/report.go:56`) |
| 9 | Integrations / alerting | partial | 11 delivery targets from 7 sink implementations. No retries. Auto-close works only for GitHub. Slack/Teams/SIEM have no tests. Python `/api/alerts` exfiltrates tokens |
| 10 | Monitor | partial | Polling only (2 min). 20 CloudTrail / 5 Azure / 5 GCP events. Errors swallowed, late events lost, alert storms (`monitor.go:343-348`) |
| 11 | Cost | partial | Hard-coded single-region price table (113 SKUs). Utilisation data is AWS only. ROI is `$4.88M × (1−e^(−Σscore/50))`. Savings are double counted |
| 12 | Copilot / AI | partial | Anthropic only, with offline regex/template fallback. SQL safety runs on a read-only connection but there is no timeout. Rego is a stub: 8 files, never evaluated |
| 13 | Server / API | partial (insecure) | 15 Go routes + 19 Python routes. No auth on reads or query. Go binds `:8080` on all interfaces. No Host check. CSRF via simple POST |
| 14 | CLI UX | real | 22 top-level commands, 25 leaf commands. `onboard` exists. No `init`/`doctor`/`validate`. CLI test coverage is 30.5% |
| 15 | DevX (VS Code, Action, pre-commit, SARIF) | partial | SARIF 2.1.0 is real. Action and hook are broken by the stored-findings bug. VS Code quick fix fails on a fresh workspace. 0 extension tests |
| 16 | Release / distribution | stub | No goreleaser, tap, signing, SBOM or published image. Version hard-coded `0.1.0`. 212 MB binary. `curl \| sh` from `main` |
| 17 | Docs | partial | README, checks.md (75 entries, accurate) and planning docs exist. README overstates IaC coverage, auto-close, Windows support and credential handling |
| 18 | Tests | partial | 122 Go `Test*` functions, 157 Python test cases (all passing). 0 live-cloud e2e. Several packages have 0% coverage |
| 19 | Config | partial | YAML loads but nothing is validated. Plain-text secrets are allowed. `neo4j.*_env` keys silently ignored (`config.go:68-70`) |
| 20 | Multi-tenant / RBAC / SSO / Postgres | absent | SQLite only. One optional shared token on `POST /api/scan` |

## Tooling results (run during this audit)

- **`go vet ./...`:** clean (exit 0).
- **`go test -cover ./...`:** all packages pass. Per-package coverage:

| Package | Coverage | Package | Coverage |
|---|---|---|---|
| adapters | 70.7% | iac | 54.9% |
| attackpath | 78.8% | integrations | 53.1% |
| catalog | 0% (no tests; 75.9% via adapters) | model | 0% (no tests; 73.2% cross-package) |
| cli | 30.5% | monitor | 81.5% |
| collector | 97.2% | neo4j | 81.9% |
| collector/aws | 85.5% | output | **0%** |
| collector/azure | 82.2% | query | 58.2% |
| collector/core | 73.9% | remediation | 85.8% |
| collector/gcp | 72.6% | risk | 70.5% |
| collector/k8s | 87.7% | scanner | **0%** |
| collector/saas | 84.7% | server | 62.6% |
| compliance | 60.9% | store | 66.5% |
| config | **0%** | devx | **0%** |
| cost | 89.1% | gitops | **0%** |
| graph | **0%** (exercised indirectly) | cmd/cloud-posture | 0% |
| dashboard | 88.2% (excluded) | | |

- **`pytest -q` (python/.venv):** 157 passed, 0 failed. pytest-cov is not installed, so Python coverage was skipped. I did not install it, to avoid modifying the venv.
- **govulncheck (installed in 3 s):** 5 *reachable* vulnerabilities, all in `golang.org/x/net@v0.59.0` and all HTTP/2: GO-2026-6617, -6612, -6611, -6610, -6603. They are fixed in v0.60.0. One more vulnerability exists in a required module but is not reachable.
- **gosec (installed in 20 s, run excluding `internal/dashboard`):** 47 issues.

| Rule | Count | Meaning |
|---|---|---|
| G301 | 14 | directory permissions |
| G306 | 13 | file permissions |
| G304 | 11 | file inclusion via variable |
| G204 | 6 | subprocess with a variable: `scanner/runner.go:298`, `query/query.go:91`, `gitops/gitops.go:46`, `devx/devx.go:36`, `cli/scan.go:324`, `cli/root.go:262`. All use argv; none use a shell |
| G101 | 3 | possible hard-coded credentials; all false positives on constants (`devx.go:141,153`, `traversal.go:568`) |

---

## 1. Collectors per provider: partial

**Shared plumbing**
- **Concurrency.** `collector.RunAll` (`internal/collector/collector.go:91-121`) uses an errgroup and recovers from panics (`:140-147`). `core.RunTasks` (`core/parallel.go:19-41`) is partial-failure tolerant.
- **Auth** (`core/auth.go`):
  - AWS: profile plus optional STS AssumeRole (session name `nimbus-cloud-posture`), adaptive retry with 8 attempts (`:21-44`).
  - Azure: `DefaultAzureCredential` (`:47`).
  - GCP: ADC or a key file (`:53-61`).
  - SaaS: token from an env var (`:64`).
- **SaaS REST client** (`core/rest.go`): 30 s timeout, 4 retries on 429/5xx only (`:97`), honours `Retry-After`, follows `Link` / `@odata.nextLink` pagination up to 10,000 pages, caps responses at 32 MiB.
- **CLI wiring** (`internal/cli/scan.go:118-141`):
  - `scan.parallel` has no default (`config.go:75`), so accounts run **sequentially**.
  - **`AccountTimeout` is never set**, so native collectors have no timeout. `--timeout` applies only to external tools.
  - A collector error becomes a failed ToolRun; it is not swallowed.
- **Tests:** `TestRunAll`, `TestRunAllBoundedConcurrency`, `TestRunAllAccountTimeout`, `TestForProvider`, `TestCheckFinding`, `TestAttachFindingKeepsNodeShape`, `TestResNodeContext`, `TestAddResourceContainsEdge`, `TestPortsHelpers`, `TestRunTasks`, `TestRESTPagination`, `TestNextLink`, `TestSpecLabelAndToken`. All against hand-written fakes. There are no golden files.

**Native checks per provider**

| Provider | API calls | Resource types | Native checks |
|---|---|---|---|
| AWS | 31 | 15 | **21** |
| Azure | 11 ops | 7 | **7** |
| GCP | 9 | 7 | **6** |
| Kubernetes | 11 List | 11 kinds | **7** |
| GitHub | 4 endpoints | org, repo | **3** |
| Okta | 4 endpoints | users, policies | **2** |
| M365 / Entra | 5 endpoints | users, roles, CA | **2** |
| **Total** | | | **48** (all resolve in catalog.yaml) |

### AWS
- **API calls** (`internal/collector/aws/inventory.go:152-662`, `collector.go:76-150`):
  - sts: GetCallerIdentity
  - ec2: DescribeRegions, DescribeInstances, DescribeSecurityGroups, DescribeVolumes, DescribeAddresses
  - s3: ListBuckets, GetPublicAccessBlock, GetBucketPolicyStatus, GetBucketAcl, GetBucketEncryption, GetBucketTagging
  - iam: GetAccountAuthorizationDetails, GetPolicy, GetPolicyVersion, GetAccountSummary, GenerateCredentialReport, GetCredentialReport
  - rds: DescribeDBInstances
  - lambda: ListFunctions, ListFunctionUrlConfigs
  - eks: ListClusters, DescribeCluster
  - secretsmanager: ListSecrets
  - kms: ListKeys, DescribeKey, GetKeyRotationStatus
  - cloudtrail: DescribeTrails, GetTrailStatus
  - cloudwatch: GetMetricStatistics
  - ce: GetCostAndUsage
- **Resource types:** s3_bucket, db_instance, secretsmanager_secret, security_group, iam_policy, iam_group, iam_user, iam_role, iam_root, instance, ebs_volume, lambda_function, eks_cluster, kms_key, cloudtrail.
- **Checks:**
  - S3: `s3_bucket_public_access`, `s3_bucket_default_encryption`
  - RDS: `rds_instance_no_public_access`, `rds_instance_storage_encrypted`
  - Security groups, internet ingress: `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`, `…_3389`, `…_any_port`
  - IAM admin policies: `iam_inline_policy_no_administrative_privileges`, `iam_customer_attached_policy_no_administrative_privileges`, `iam_aws_attached_policy_no_administrative_privileges`
  - IAM other: `iam_role_cross_account_readonlyaccess_policy`, `iam_root_mfa_enabled`, `iam_user_mfa_enabled_console_access`, `iam_user_accesskey_unused`
  - EC2: `ec2_instance_imdsv2_enabled`, `ec2_instance_public_ip`, `ec2_ebs_volume_encryption`
  - Lambda, EKS, KMS, CloudTrail: `awslambda_function_url_public`, `eks_control_plane_endpoint_access_publicly_accessible`, `kms_cmk_rotation_enabled`, `cloudtrail_multi_region_enabled`
  - Secrets are collected but no check runs on them.
- **Scope:**
  - Multi-region: enabled regions, 8 in parallel.
  - Multi-account: one spec per account. **No Organizations enumeration.**
  - Pagination: SDK paginators.
- **Graph edges:** contains, exposes, allows_traffic_to, attached_to, has_policy, grants_access_to, member_of, runs_as, can_assume, trusts.
- **Tests:** `TestCollectFindings`, `TestCollectGraph`, `TestCollectCostSignals`, `TestCollectPartialFailure`, `TestCollectFatal`, `TestCollectCloudTrailPass`, `TestSGOpenInfo`, `TestIsLargeType`, `TestParseCredentialReport`, `TestParsePolicyShapes`, `TestDataAccess`, `TestMatchesResource`, `TestTrustedPrincipals`.
- **Defects:**
  - Account-level S3 Block Public Access is ignored, which causes false positives (`analyze.go:93`, `inventory.go:565`).
  - `IsAdmin` ignores NotAction/NotResource (`policy.go:132-153`).
  - `DataAccess` ignores Deny statements and Conditions (`policy.go:176-201`).
  - A `Principal:*` trust fails even when it is conditioned (`analyze.go:440-471`).
  - The cross-account check ID is reused for "any external trust" (`analyze.go:480`).
  - CloudWatch is called serially per instance, and one error aborts the loop (`inventory.go:343-383`).

### Azure
- **API calls:**
  - Resource Graph: 2 KQL queries, paged with `$skipToken` up to 1000 pages (`collector.go:213-255`)
  - Compute and network: VirtualMachines ListAll (called twice), Disks, NSGs, NICs, PublicIPs
  - Data and secrets: StorageAccounts, SQL Servers plus FirewallRules, Key Vaults
  - Subscriptions List
- **Resource types:** NSG, VM, managed disk, storage account, SQL server, key vault, AKS.
- **Checks:** `network_ssh_internet_access_restricted`, `network_rdp_internet_access_restricted`, `storage_blob_public_access_level_is_disabled`, `storage_secure_transfer_required_is_enabled`, `sqlserver_firewall_rules_no_ingress_from_internet`, `keyvault_recoverable`, `aks_cluster_rbac_enabled`.
- **Not covered:** no VM, disk-encryption or identity/RBAC checks, and no identity edges.
- **Scope:** all enabled subscriptions are enumerated, but collected **sequentially**. `spec.Regions` is ignored.
- **Tests:** `TestInternetAllowsPort`, `TestSpecCoversAndHelpers`, `TestCollectFindings`, `TestCollectGraph`, `TestCollectCostSignals`, `TestPartialFailure`, `TestSubscriptionEnumeration`, `TestInterfaceConformance`.
- **Defects:**
  - NIC and subnet NSG results are combined with OR. Azure requires both to allow, so this produces false exposure (`build.go:236-255`).
  - The SQL "internet" rule only matches exactly `0.0.0.0–255.255.255.255` (`build.go:360-366`).
  - If the type-count query fails, the AKS query is skipped (`collector.go:225`).

### GCP
- **API calls:**
  - compute: Instances.AggregatedList, Firewalls.List, Disks.AggregatedList, Addresses.AggregatedList
  - storage: bucket iterator plus per-bucket IAM policy
  - Others: sqladmin Instances.List, cloudresourcemanager v1 Projects.Get, iam ServiceAccounts.List (`clients.go:122-229`)
- **Checks:** `compute_firewall_ssh_access_from_the_internet_allowed`, `compute_firewall_rdp_access_from_the_internet_allowed`, `compute_instance_default_service_account_in_use_with_full_api_access`, `cloudstorage_bucket_public_access`, `cloudsql_instance_public_ip`, `cloudsql_instance_ssl_connections`.
- **Scope:** one project per spec. No org or folder enumeration.
- **Tests:** `TestFindings`, `TestGraph`, `TestCostSignals`, `TestPartialFailure`, `TestCollectErrors`, `TestHelpers`.
- **Defects:**
  - **Project IAM policy is never collected.**
  - Firewall priority and deny rules are ignored (`gcp.go:242-263`, `:366-378`).
  - Bucket IAM is fetched serially (`clients.go:186`).

### Kubernetes
- **API calls:** List for namespaces, pods, deployments, serviceaccounts, services, clusterrolebindings, rolebindings, clusterroles, roles, networkpolicies, nodes (`k8s.go:149-293`). Paged with Limit 500 and Continue.
- **Checks:** `namespace_network_policy_defined`, `cluster_role_binding_cluster_admin_disabled`, `core_pod_privileged`, `pod_host_network_access_disabled`, `pod_volume_host_path`, `pod_container_privilege_escalation_disabled`, `pod_service_account_token_disabled`.
- **Tests:** `TestFindings`, `TestGraph`, `TestPartialFailure`, `TestClientError`, `TestPagination`, `TestHelpers`.
- **Defects:**
  - Every LoadBalancer or NodePort service counts as internet-exposed (`k8s.go:451-468`).
  - kube-system is not excluded (`:442`).
  - RoleBindings to admin or wildcard roles are not checked (`:408-415`).
  - No `rest.Config.Timeout`.

### GitHub, Okta, M365
- **GitHub** (`saas/github.go`):
  - Calls: org, repos (paged), branch protection, repo.
  - Checks: `organization_members_mfa_required`, `repository_default_branch_protection_enabled`, `repository_secret_scanning_enabled`. Push protection is parsed but not checked (`:45`).
  - Tests: `TestGitHubCollect`, `TestGitHubMissingConfig`, `TestGitHubRetriesServerErrors`.
  - Defects:
    - A rate-limit 403 is not retried and the check is silently skipped (`rest.go:97`, `github.go:170`).
    - A 404 is treated as "unprotected" even when rulesets protect the branch.
- **Okta** (`saas/okta.go`):
  - Calls: users, then one roles call per user (N+1), factors, sign-on policies and rules.
  - Checks: `okta_admin_user_mfa_enrolled`, `okta_sign_on_policy_require_mfa`.
  - Tests: `TestOktaCollect`, `TestOktaSignOnRule`, `TestOktaMissingConfig`.
  - Defects:
    - Passes if *any* rule requires MFA (`:233-239`).
    - Identity Engine ACCESS_POLICY is not covered.
- **M365** (`saas/m365.go`):
  - Calls: client-credentials token, users, directoryRoles with expanded members, authentication-method registration report, Conditional Access policies.
  - Checks: `entra_admin_users_mfa_enabled`, `entra_legacy_authentication_blocked`.
  - Tests: `TestM365Collect`, `TestM365MissingConfig`, `TestM365TokenFailure`.
  - Defects:
    - Admin MFA passes on *any* IncludeRoles and ignores exclusions (`:90-103`).
    - The `$expand` member list is likely truncated at 20 (`:209`).
    - The token is never refreshed (`:183`).
    - PIM-eligible admins are missed.

## 2. Scanner adapters: partial

| Adapter | Input accepted | Fields mapped | Dropped / bugs |
|---|---|---|---|
| Prowler v4/v5 OCSF (`adapters/prowler.go:50`) | JSON array with `finding_info` | event_code → CheckID, title, risk_details/desc, severity, status_code, provider, account, region, remediation, resources[0], unmapped.compliance, categories | `status_detail` (per-resource reason), resources[1:], time, refs, tags |
| Prowler v3 (`prowler.go:114`) | flat array with `CheckID` | equivalent fields | **No test fixture** |
| ScoutSuite (`scoutsuite.go`) | `scoutsuite_results = {…}` or JSON | key, description, rationale, level (danger → CRITICAL), compliance, items resolved through the service tree | counts, references, compliance version |
| Checkov (`checkov.go`) | report object or list | failed/passed/skipped, file+lines, guideline, bc_check_id, provider from `CKV_*` prefix | null OSS severity falls back to catalog; every secret forced to CRITICAL |
| Trivy (`trivy.go`) | config/fs/image/k8s | misconfigs (AVDID), CVEs, secrets | CVSS, PrimaryURL, k8s ns/kind/name. CVEs labelled provider=kubernetes (`:120`). **Package missing from fingerprint** (`model.go:140`), so findings collapse |
| Steampipe/Powerpipe (`steampipe.go`) | grouped controls export | control, reason, dimensions | CIS tag mapping is dead: `HasPrefix(k,"cis_")` never matches `"cis":"true"` (`:119`) |
| Native (`adapter.go:112`) | `model.Finding` array or JSONL | everything | — |

**How check IDs are canonicalised** (`catalog/catalog.go:74-101`):
1. Exact `(source, lower(id))` alias lookup.
2. Wildcard prefix match. This iterates a map, so it is nondeterministic, but latent because no wildcards exist yet.
3. Fallback chain: prowler → steampipe → checkov → trivy.
4. `cve-`/`ghsa-` → `CVE_VULNERABILITY`.
5. Otherwise `SOURCE:id`.

Other mapping behaviour:
- Catalog severity overrides INFO (`catalog.go:127`).
- Numeric CVSS becomes INFO, contrary to the comment at `model.go:28`.

**Runner** (`internal/scanner/runner.go`):
- Uses argv, with no shell injection.
- 30-minute per-tool timeout (`:292`).
- **Discards valid output if stderr contains "error"** (`:317`).
- Unbounded stdout buffer (`:311`).
- Passes `--kubeconfig ""` when unset (`:229`).
- **0% test coverage.**

**Tests:** `TestProwlerOCSF`, `TestCheckov`, `TestTrivy`, `TestSteampipe`, `TestScoutSuite`, `TestNativeAndOverrides`, `TestDetectUnknown`, against `testdata/*.json` golden files. Supported tool versions are implicit; none are declared or pinned. Steampipe export and Trivy k8s flag syntax were not verified against current releases.

## 3. Canonical catalog: real (hand curated)

`internal/catalog/catalog.yaml`. Each entry is keyed by an upper-case ID and carries title, provider, severity, resource_type, weaknesses, `aliases{tool:[ids]}`, compliance and remediation.

| Dimension | Breakdown |
|---|---|
| Canonical checks | **75** (matches `docs/checks.md` and the roadmap) |
| Entries with aliases, per tool (alias strings) | prowler 58 (129), checkov 58 (114), trivy 46 (90), scoutsuite 38 (61), steampipe 73 (121). No `native` alias key |
| By provider | aws 31, kubernetes 11, azure 10, gcp 9, github 4, oci 3, m365 3, okta 3, iac 1 |
| By severity | CRITICAL 13, HIGH 31, MEDIUM 19, LOW 10, INFO 2 |
| Weakness taxonomy (26 values) | PUBLIC_NETWORK_EXPOSURE 15, OVERPRIVILEGED_IDENTITY 9, DATABASE 8, NO_MFA 7, WEAK_AUTH 7, PUBLIC_DATA_STORE 6, UNENCRYPTED_AT_REST 6, NO_LOGGING 6, plus 18 more |
| Compliance mappings (all 75 have one) | nist_800_53 75, pci_dss 53, cis_aws 25, hipaa 24, gdpr 12, cis_azure 10, cis_gcp 9, cis_k8s 9, cis_github 3, iso_27001 1 |
| Remediation templates | 36 entries reference 42 templates, all present |

- **Integrity:** no alias collisions.
- **Semantically wrong aliases exist.** Examples: `AZ_AKS_RBAC_DISABLED` ← `aks_clusters_public_access_disabled`; `S3_PUBLIC_BUCKET` ← `cloudtrail_logs_s3_bucket_is_not_publicly_accessible`.
- **Python drift:** `python/nimbus/frameworks/catalog.yaml` has 66 entries. It is missing 9 Go entries, and aliases differ on 8 shared entries.
- **Tests:** no in-package tests (0%). Coverage is 75.9% via the adapter tests.

## 4. Store / SQL: partial (critical security defects)

**Schema** (`internal/store/store.go`)
- Driver: `modernc.org/sqlite` v1.39.0, WAL mode, busy_timeout 5000 (`:107`).
- Tables: findings, resources, attack_paths, scans, alerts, graph_nodes, graph_edges.
- Views:
  - One `<type>s` view per resource type, with 15 weakness booleans.
  - `findings_summary`, `attack_path_summary`, `finding_compliance`, `compliance_controls`.
  - Per framework: 5 `cis_*_benchmark` views plus nist_800_53, pci_dss, hipaa, gdpr, soc2, iso_27001.
- **No migrations or versioning:** setup is `CREATE … IF NOT EXISTS` only.
- **Findings are never resolved:** writes are upsert only (`:130`), so a fixed resource stays FAIL.

**Query safety**
- `internal/query/query.go:35-58` is a substring denylist on a read-write connection (no `mode=ro`, no `query_only`).
- Bypasses confirmed by probe:
  - A CTE followed by `\nDELETE` deletes rows.
  - `SELECT '--';CREATE TABLE …` runs multiple statements, because comment stripping is not string-aware.
  - `ATTACH DATABASE '/any/path'` creates arbitrary files.
- **Injection in view DDL:** `store.go:404-408` with `viewName` at `:423`. A crafted resource type in an ingested file **dropped the findings table** (probe).
- `Store.Query` ignores its context (`:439`), so the server's 30 s timeout does nothing.
- `Run` drops and recreates every view on each query (`query.go:66`), so reads write and race.

**Steampipe passthrough** (`cli/query.go:74`): shells out to `steampipe query` when a table is missing locally. No timeout. Column order is random. It is not reachable over HTTP.

**Python store** (`python/nimbus/store.py:160-166`): opened with `mode=ro` plus `PRAGMA query_only`, which is the correct design.

**Tests:** `TestRoundTripAndViews`, `TestViewsAndSafety`. The safety test covers only 4 naive payloads.

## 5. Graph + attack paths: partial

**Graph** (`internal/graph/graph.go`)
- **13 edge kinds** (`:19-31`): attached_to, can_assume, allows_traffic_to, member_of, contains, has_policy, grants_access_to, exposes, runs_as, bound_to, stores_data_in (never emitted), trusts, runs_on.
- **9 node classes** (`:36-44`): internet, compute, network, identity, datastore, cluster, saas, account, image.
- Class comes from substring matching in `ClassFor` (`:360-383`).
- Two build paths:
  - Collector resources go through `core.AddResource`, which adds real edges.
  - Findings-only graphs come from `AttachFindings` (`:247-286`). That path uses account `contains`, internet `exposes` for public weaknesses, and `Resource.Related` hints. It is mostly co-occurrence.
- Neo4j push (`internal/neo4j`) is parameterised Cypher. `TestStatements` and `TestPushWith` cover it (81.9%).

**Rules** (`internal/attackpath/rules.yaml`): **11 rules**
- INTERNET_TO_ACCOUNT_ADMIN, PUBLIC_BUCKET_SILENT_EXFIL, PUBLIC_DATABASE_BREACH, CREDENTIAL_THEFT_TO_ADMIN, STALE_KEY_ABUSE, CROSS_ACCOUNT_PIVOT, CONTAINER_ESCAPE_TO_CLUSTER_ADMIN, VULNERABLE_IMAGE_LATERAL_MOVEMENT, PUBLIC_K8S_API_TAKEOVER, SUPPLY_CHAIN_TO_CLOUD, IDENTITY_PROVIDER_TAKEOVER.
- Chains are weakness sequences, mostly linked by `same_account` (co-occurrence).
- The `any` link crosses providers (`engine.go:182`), contrary to the comment at `rules.yaml:6`.
- Containment is computed with an O(n²) substring heuristic (`engine.go:91-97`). Fan-out is capped at 3 per stage (`:269`).

**Traversal** (`traversal.go:235-334`)
- Iterative depth-first search with a per-path visited set.
- Limits: MaxHops 6, MaxBranching 25, prune when likelihood < 0.02, **cap of 20,000 explored frames per entry point (silent truncation, `:272`)**, MaxPaths 500.
- Entry points: internet, NO_MFA, STALE_CREDENTIALS, WEAK_AUTH, BRANCH_UNPROTECTED, SECRET_EXPOSURE.
- The `contains`, `trusts` and `runs_on` edges are never traversed, so pod→node escape is not modelled.

**Scoring as implemented**
- Traversal: likelihood = Π(exploitability × 0.95), then `score = round(lik × priority, 2)` capped at 10, with priority 4→10, 3→5, 2→2, 1→1 (`traversal.go:308,347-350`).
- Rule engine: mean severity rank × link tightness × (1 + 0.25(n−1)) (`engine.go:292-305`).
- The two scales are merged into one sort (`traversal.go:628-640`) even though they are not comparable.
- **The "OR semantics" claimed at `traversal.go:18-21` and ROADMAP:11 is not implemented.**
- **Prefix paths are emitted at every crown jewel**, which inflates path counts, TotalScore and choke-point counts.

**Choke points:** the 10 nodes that appear on the most paths (`:453-461`).

**Min-cut:** **greedy weighted set cover** (`MinFixSet`, `:530-562`), not the max-flow min-cut promised in IMPLEMENTATION_PLAN 2.5. "Breaks" is never re-verified by re-running the traversal. **The fix is attributed to the edge target, but the enabling weakness lives on the source**, so IMDSv1 shows only as a "reduce" fix (`:462-475`, verified).

**Blast radius:** breadth-first search over attack edges with criticality ≥ 3 (`:587-625`). The Python copilot has a different implementation.

**Defects**
- **`ClassFor` checks for "account" before identity or datastore** (`graph.go:365`). `k8s_service_account`, `gcp_service_account` and `azure_storage_account` all become `account`, and `runs_as` requires an identity target (`traversal.go:163`), so pod→SA→cluster-admin and GCE→SA paths **never fire** (probe: 0 paths).
- CVECount is off by one (`graph.go:263,268`), and the increment at `:268` is outside the lock.

**Tests:** `TestRuleChains`, `TestTraverseFindsMultiHopPaths`. Neither covers the K8s/GCP SA chains or fix attribution.

## 6. Risk scoring: partial

**Go** (`internal/risk/risk.go:204-205`)
- Formula: `x = 0.45·base + 0.55·ctx`, then `score = 1 + 9·sigmoid(7(x−0.42))`.
- base = severity, mapped 1 / .8 / .55 / .3 / .1.
- ctx weights (`:36`): exposure .22, identity .16, data .16, criticality .12, attack paths .12, vulns .08, compliance .06, recent change .05, orphaned .03.
- Bands: ≥9 Critical, ≥7 High, ≥4 Medium.

**Python** (`python/nimbus/risk.py:218-221`, `risk_weights.json`)
- Formula: `100/(1+e^−z)`, where `z = −4.2 + Σ w·f`.
- Weights: severity 3.0, exposure 1.8, data 1.4, identity 1.2, criticality 0.9, vulns 0.8, compliance 0.6, change 0.5, ownership 0.4, attack_path 2.2.
- **This is a different formula from Go, with different feature definitions.** `risk.go:2` claims they are the same.

**Selection:** Go runs `python -m nimbus.risk` whenever `import nimbus` succeeds from `./python` or `../python` (`scan.go:423-460`, `root.go:222-247`).
- The result is mapped as `int(p)/10`, but **Band/SLA/DueAt are kept from Go** (`scan.go:444-450`), so a finding can show score 9.5 with band "High".
- Running the binary in an untrusted checkout executes that checkout's `python/nimbus`.

**Inputs that actually exist at runtime**

| Input | What really feeds it |
|---|---|
| Exposure | Real graph edges from the collectors. Nothing populates the `internet_exposed` attribute that Python reads |
| Data sensitivity | Name/type/tag guesses only. "hr" matches as a substring, e.g. "three" |
| Criticality | Guessed from names/tags |
| CVE / exploit data | No EPSS, KEV or exploit availability. CVECount is off by one |
| Recent change | `ModifiedAt` is filled from creation time (`graphutil.go:77`) |
| Attack paths | Real, but inflated by prefix paths |

**Tests:** Go `TestPrioritize`. Python `test_ranking_order_and_reasons`, `test_context_changes_score`, `test_linear_model_json`, `test_cli_contract`, `test_builtin_weights_mirror_json`. Nothing tests the Go↔Python merge.

## 7. Remediation: partial

**Templates** (`internal/remediation/templates/`): **42 files covering 36 of 75 IDs.** ROADMAP says 38.

| Format | Count | Covers |
|---|---|---|
| Terraform | 24 | |
| CloudFormation | 6 | S3 public, S3 unencrypted, SG open port, IMDSv1, RDS public, CloudTrail |
| Bicep | 4 | KV soft delete, NSG, storage HTTPS, storage public blob |
| Kubernetes | 8 | cluster-admin, host namespaces, netpol, privilege escalation, privileged, limits, root, SA token |
| Generic fallback | — | |

- Rendering uses `text/template` with no HCL escaping.
- The suggested apply command is `terraform init && terraform apply -auto-approve` (`generator.go:229`).
- **Dangerous templates:**
  - `iam_admin_policy.tf` replaces the live admin policy with a placeholder `s3:GetObject` on `example-bucket`.
  - `iam_cross_account_trust.tf` uses an empty principal list plus `TODO-external-id`, which locks the role out.
  - `sg_open_port.tf` does not remove the existing 0.0.0.0/0 rule.

**Native HCL scanner** (`internal/iac/iac.go:244-436`): **20 rules**
- 14 AWS: S3 ACL, S3 PAB, SG ingress, SG rule, IMDSv1, public IP, EBS encryption, RDS public, RDS encryption, IAM `*:*`, CloudTrail validation, CloudTrail multi-region, KMS rotation, EKS public.
- 3 Azure, 3 GCP.
- Expressions are evaluated without a variable context, so `var`, modules, `jsonencode` and policy documents are skipped.
- Every open SG is reported as SSH.
- **Panics on unknown bool expressions** (`:366-367`, `:426-427`, verified).
- CloudFormation, Bicep, K8s, Helm etc. are covered only if checkov or trivy is installed.

**Patcher** (`applyFix`, `iac.go:575-693`)
- Handles 19 IDs.
- **Matches the target block by suffix** (`:556`). Probe: an EC2 fix was written into `aws_kms_key.logs`.
- Inserts undeclared variables (`var.allowed_cidrs` etc. at `:597,611,670,674,678`), so `terraform plan` fails.
- The never-widen guardrail is a substring count (`:697-705`).
- `UnifiedDiff` is O(n·m) and emits no hunk headers.

**Cloud-to-code mapping** (`:777-860`): tfstate arn/id/self_link/name/bucket/`yor_trace` → `type.name`. Module prefixes are ignored, and name collisions resolve first-wins.

**PR flow** (`internal/gitops/gitops.go`, 0% coverage)
- git via argv: checkout -b, add, commit, push. Then the GitHub pulls/labels API or GitLab MR.
- **GitLab is hard-coded to gitlab.com** (`:276`).
- **Writes the wrong file:** the patch is read from `--iac root + f.File` but written to `git toplevel + p.File` (`fix.go:230` vs `gitops.go:121-128`). There is no containment check, so `../` and absolute paths are allowed.
- The PR body contains boilerplate claims.

**Guardrails**
- `--dry-run` is not the default. `--patch` overwrites files in place.
- `verifyPatch` passes when it cannot create its temp file, and it does not run `terraform validate` (`fix.go:315-332`).
- The `fix --ai` file name uses the raw resource name, which allows path traversal (`fix.go:175`).

**Tests:** `TestEveryCatalogTemplateRenders`, `TestGenericFallbackAndFormats`, `TestScanAndPatch`, `TestIngestQueryPathsFix` (`--print` only). `runPatch`, `verifyPatch` and `mergePatches` have 0% coverage.

## 8. Compliance: partial

**Control counts per framework**

| Framework (label) | Go controls (`internal/compliance/frameworks.yaml` + `extra.yaml`) | Python controls (`python/nimbus/frameworks/frameworks.yaml`) |
|---|---|---|
| cis_aws (v3.0) | 42 | **19** |
| cis_azure 2.1 | 11 | 11 |
| cis_gcp 2.0 | 13 | 13 |
| cis_k8s 1.8 | 12 | 12 |
| cis_github 1.0 | 6 | 6 |
| nist_800_53 r5 | 30 (of ~1,000) | 30 |
| pci_dss (4.0) | 24 (**3.2.1 numbering**) | 24 |
| hipaa | 8 | 8 |
| gdpr | 4 | 4 |
| soc2 | 12 | 12 |
| iso_27001 | 2 "2013" in YAML + 17 injected in code and relabelled 2022 (`report.go:27,64-72`), 18 after overlap | 16 |

**Provenance:** all mappings are hand written, none generated from official catalogs. The catalog references 16 controls that are absent from the Go inventories. Weakness→SOC 2/ISO mappings: 23 in Go, 21 in Python, with 10 differing.

**Outputs:**
- Go: Markdown, JSON, and an evidence ZIP (per-control evidence.json plus a SHA-256 manifest). `zw.Close` errors are ignored.
- Python: HTML, PDF, MD, JSON (`python/nimbus/reports/render.py`).

**Defects:**
- Custom frameworks lose their inventory, because the code writes into a throwaway map (`cli/report.go:56`).
- `Frameworks()` re-parses on every call and writes globals without a lock (data race).

**Tests:** Go `TestReportAndDerivation`; Python `tests/test_compliance.py`.

## 9. Integrations / alerting: partial

All Go sinks share one HTTP client (20 s timeout, default TLS, `integrations.go:33`).

| Sink | Evidence | Auth | Tests |
|---|---|---|---|
| Slack | integrations.go:70 | webhook URL | **none** |
| GitHub Issues (only sink with Close) | integrations.go:117 | Bearer `GITHUB_TOKEN` | **none** |
| Splunk HEC / Elastic / webhook / syslog-CEF | integrations.go:281-373 | Splunk token / ApiKey / Bearer / none (syslog is plaintext) | **none** |
| Teams | teams.go | webhook | `TestTeamsDeliver`, `TestTeamsRequiresURL` |
| PagerDuty | pagerduty.go | routing key | `TestPagerDutyDeliver`, `TestPagerDutySeverityMap`, `TestPagerDutyRequiresKey` |
| Jira Cloud | jira.go | Basic | `TestJiraDeliver`, `TestJiraRequiresConfig` |
| Datadog | datadog.go | DD-API-KEY | `TestDatadogDeliver`, `TestDatadogDefaultURLs` |
| Sentinel (HTTP Data Collector API) | sentinel.go | HMAC SharedKey | `TestSentinelSignature`, `TestSentinelDeliver`, `TestSentinelInvalidKey` |

That is 11 delivery targets from 7 sink implementations.

**Behaviour**
- Retries: none, in Go or Python.
- Rules (`dispatch.go:21`) support severity, provider, account, ID glob, weakness and attack-path-only. **Only `min_severity` is reachable from config** (`root.go:203`).
- Suppressions: a JSON file via `alert --suppress`, with globs and expiry (`dispatch.go:69`).
- Dedup: store-backed per (finding, sink).
- **Auto-close works only for GitHub.** The PagerDuty resolve branch is dead code (`pagerduty.go:42`), and the comment at `dispatch.go:15` claims otherwise.
- Test: `TestDispatchRulesSuppressionsAutoClose` against a fake sink.

**Defects**
- Webhook URLs (secrets) are printed in error output (`integrations.go:59` → `report.go:198`).
- `alert` exits 0 when every delivery failed (`report.go:207`).
- A `siem` key without `type` is broken (`root.go:195`). Unknown sink names are silently ignored.
- GitHub dedup ignores the search status code, so it can create duplicates (`integrations.go:206-226`).
- CEF header newline injection (`:418`).
- Sentinel's Data Collector API may already be retired; this was not verified.

**Python** (`python/nimbus/integrations/clients.py`)
- 6 clients using httpx with a 15 s timeout. No rules or suppressions.
- Dedup keys differ from Go.
- **`POST /api/alerts` (`server.py:249`) accepts target dicts that override `api_url`/`base_url`/`site`**, which sends `GITHUB_TOKEN`, Jira or Datadog credentials to any host.
- Tests: `test_slack_payload_matches_go_shape`, `test_teams_jira_github_datadog_pagerduty`, `test_github_dedupes_existing_issue`, `test_dispatch_errors_and_unconfigured`, `test_event_and_issue_body`.

## 10. Monitor: partial (polling, not real-time)

`internal/monitor/monitor.go:372-396` polls on a ticker: 1 min in the library, 2 min from the CLI (`serve.go:230,233`).
- **Cursor:** a per-source watermark of max event time + 1 ns, saved atomically in `.cloud-posture/monitor-checkpoint.json`. The first poll looks back 1 h.
- **Dedup:** within a single poll only.
- **Event sources:**
  - **AWS CloudTrail** (`aws.go:21-26`, 20 events): PutBucketAcl, PutBucketPolicy, DeleteBucketPolicy, Put/DeletePublicAccessBlock, AuthorizeSecurityGroupIngress, Attach/Put Role/User Policy, CreateAccessKey, ConsoleLogin (root), StopLogging, DeleteTrail, UpdateTrail, ModifyDBInstance, DeactivateMFADevice, CreateUser, UpdateAssumeRolePolicy, ModifyInstanceMetadataOptions. One LookupEvents per event per region; regions default to us-east-1.
  - **Azure Activity Log** (5 ops): NSG rule, storage account, role assignment, vault, SQL firewall.
  - **GCP audit logs** (5 method substrings).
- **Output:** `--alert` turns events into `monitor`-source findings and dispatches them. `serve --monitor` pushes WebSocket events.
- GitHub, Okta, M365 and K8s are not monitored (`monitor.go:187`).

**Tests:** `TestMapCloudTrail`, `TestCloudTrailEventListCoversSpec`, `TestCloudTrailSourcePaginates`, `TestMapActivityLog`, `TestActivityLogSourcePoll`, `TestMapAuditLog`, `TestAuditLogSourcePoll`, `TestPollCheckpointsAndDedup`, `TestRunEmitsAndStops`, `TestToFinding`.

**Defects**
- **Poll errors are swallowed in continuous mode** (`serve.go:155`, `monitor.go:367-369`). Store and dispatch errors are ignored (`serve.go:162-180`).
- **Late-arriving events are lost** because of the watermark (`monitor.go:345-348`).
- A quiet source re-queries an ever-growing window (`:345`).
- A partial failure freezes the checkpoint and re-emits everything on each poll (`:343`).
- GCP raises HIGH on every project SetIamPolicy (`gcp.go:263-268`).
- IAM events are missed when us-east-1 is not in the regions list (`aws.go:91-94`).

## 11. Cost: partial (heuristic)

- **Pricing:** embedded `internal/cost/pricing.json` with list prices for one region per cloud. 113 compute SKUs (AWS 62, Azure 32, GCP 19) and 17 storage classes. Flat IP and egress rates. **No pricing API, and region is ignored.** AWS Cost Explorer spend is shown for information only.
- **Zombies** (`cost.go:167-203`): unattached volumes, unassociated IPs, stopped instances (priced as storage only, defaulting to 8 GB), and idle instances (×730 h).
- **Utilisation:** CPU-based idle/oversize detection exists only for AWS (14-day CloudWatch average: under 5% is idle, under 20% on xlarge-or-bigger is oversized, `aws/analyze.go:19-21`).
- **Rightsizing** (`:205-226`): the next-cheaper size in the same family. If none exists, it assumes 50% savings.
- **ROI** (`:100-106`, `:414-451`): `P = 1−exp(−Σscore/50)` and loss = $4.88M × P. Each fix gets loss × (score broken / total).
- **Tests:** `TestPriceLookup`, `TestStorageAndIPPrices`, `TestDownsize`, `TestItemPricing`, `TestBreachProbability`, `TestMoney`, `TestAnalyzeTextExact`, `TestROIMath`, `TestWinsGrouping`, `TestEmptyReportAndJSON`.
- **Defects:**
  - `scan --no-store` skips cost (`scan.go:349-360`).
  - Azure stopped VMs are priced as 8 GB of storage.
  - Unknown instance types are valued at $0 with no warning (`cost.go:192`).
  - Egress savings are double counted (`:141-149`, `:385`).
  - Write errors are ignored (`scan.go:389-392`).

## 12. Copilot / AI: partial

- **Uses:** natural language → SQL plus a result summary (`python/nimbus/ai/copilot.py`), explanations (`explain.py`), IaC fixes (`fix.py`), remediation guidance, Rego text.
- **Provider:** Anthropic only, via `client.beta.messages.create`. Model is `NIMBUS_MODEL` or `claude-opus-5-5`, with the server-side fallback beta (`llm.py:47-62`).
- **Offline mode** (`NIMBUS_OFFLINE` or no key): 10+ regex intents for NL→SQL, plus template fixes. `_binary_fix` calls `fix --finding <ID> --print`, which renders stored findings rather than the one requested (`fix.py:221`).
- **SQL guardrail** (`sqlsafety.py`): string-aware comment stripping, one statement, SELECT/WITH only, 22-keyword denylist, LIMIT added. It runs on a `mode=ro` + `query_only` connection.
  - **No timeout:** an infinite `WITH RECURSIVE` hangs it.
- **Prompt injection:** finding JSON is passed into prompts unwrapped. AI fix output gets only a shallow validation before `fix --ai` writes it to disk.
- **Key leakage:** none found.
- **Rego:** 8 `.rego` files that are never evaluated, so this is a **stub**.
- **Tests:** `test_offline_model_default`, `test_explain_offline`, `test_fix_templates_and_validation`, `test_llm_path_with_fake_client`, plus 16 in `test_copilot.py` (`test_sql_safety_rejections`, `test_copilot_rejects_unsafe_sql`, `test_investigate_blast_radius`, `test_policy_generation_offline`, …).

## 13. Server / API: partial (insecure)

**Go routes** (`internal/server/server.go:81-95`)
- Shell and health: `GET /`, `/healthz`, `/ws`.
- Findings and paths: `GET /api/summary`, `/api/findings`, `/api/findings/{id}`, `/api/attack-paths`, `/api/attack-paths/analysis`.
- Graph, risk, compliance, schema: `GET /api/graph`, `/api/graph/blast-radius/{id...}`, `/api/risk/top`, `/api/compliance/{framework}`, `/api/schema`.
- Actions: `POST /api/query`, `POST /api/scan`.

**Auth:** only `POST /api/scan` has auth. The token is optional, and the comparison is not constant-time (`:412`).

**Binding:** `:8080` on all interfaces by default (`cli/serve.go:226`), even though the startup message says "localhost".

**CORS / CSRF:**
- CORS is a same-host plus allowlist echo.
- Simple POSTs are not blocked and the body is parsed regardless of Content-Type, so CSRF reaches `/api/query`.
- There is no Host-header check, so DNS rebinding defeats CORS and the WebSocket origin check. The WebSocket also accepts an empty Origin and has no read limit.

**CSP:** applied on `/` only, with `script-src 'unsafe-inline'` and `connect-src ws: wss:`. No frame-ancestors or nosniff headers.

**Timeouts and limits:**
- Only `ReadHeaderTimeout` is set (10 s). No Read, Write or Idle timeouts, no body limit, no rate limit.
- `GET /` regenerates the dashboard on every request, including a Python subprocess.
- Rescans mutate global flags (`serve.go:65`).

**Tests:** `TestAPI`, `TestCORSRejectsForeignOrigin`, `TestCORSAllowsSameHostAndAllowlist`, `TestDashboardCSP`, `TestWebSocketOriginCheck`.

**Python FastAPI** (`python/nimbus/server.py`)
- 19 routes, including `POST /api/query|copilot|explain|investigate|fix|alerts` and `/ws`.
- **No auth.** Binds 127.0.0.1:8765. No Host check and no WebSocket origin check.
- `/api/alerts` exfiltrates credentials (see §9).

## 14. CLI UX: real

`cloud-posture` (built binary, `--help`) has **22 top-level commands**, **25 runnable leaf commands** and 3 global flags (`-c`, `--db`, `-q`):
- **Scan, ingest and fix:** scan (14 flags), fix (23), ingest (3), query (5), paths (4).
- **Reporting and alerting:** report (7), alert (8), prioritize (3), dashboard (2), cost (2).
- **Live and monitoring:** serve (6), monitor (4).
- **Setup and integration:** onboard (13), pr-comment (4), graph export (2), graph push (5), hook install (1).
- **No flags:** action init, ask, catalog, learn, version.

**Output formats:**
- scan: table / json / sarif / dashboard / markdown / summary
- paths: text / json / mermaid / dot
- query: table / json / csv
- report: md / json / html / pdf
- graph: json / cypher / mermaid / dot

**Onboarding:** `onboard` detects credentials by shelling out to the aws, az, gcloud, kubectl and gh CLIs. There is **no `init`, `doctor` or config `validate`.**

**Exit codes:** `--fail-on` exits 2 via `os.Exit` (`scan.go:576`). Other errors exit 1.

**Defects:**
- **Gates, SARIF, JSON and alerts use every stored finding, not just this scan's** (`res.Findings = stored`, `scan.go:383`, reproduced).
- Severity typos become INFO.
- Unknown `-o` values fall back to table.
- `serve --help` prints the `$CLOUD_POSTURE_TOKEN` value (`serve.go:232`).
- `onboard` panics on bad YAML (`cli/devx.go:52`). Its save drops comments and `crown_jewels`.
- Errors print twice.
- `action init` overwrites without asking.

**Tests:** `TestIngestQueryPathsFix` (cli coverage 30.5%).

## 15. DevX: partial

- **SARIF: real.** 2.1.0 with schema, rules, `security-severity`, `partialFingerprints` and regions. Defects:
  - URIs are relative to the scanned directory, with no `uriBaseId`.
  - Cloud findings use `cloud://` URIs.
  - The version is hard-coded.
  - `internal/output` has 0% coverage.
- **VS Code (`vscode-extension/`): partial, no tests.**
  - Runs `scan --iac … --output json --no-store` via `execFile` (no shell), producing diagnostics and 2 quick fixes.
  - "Fix in place" calls `fix --id` against a DB that a `--no-store` scan never wrote, so it **always fails on a fresh workspace** (`src/extension.js:37,92`).
  - `applyPatch` overwrites the active document.
  - `binaryPath`/`extraArgs` are workspace-scoped (`package.json:23-26`), so a repo's settings can choose the executable.
- **GitHub Action (`action.yml`): partial.**
  - 6 inputs. Installs with `curl …/main/install.sh | bash`: unpinned, no checksum (`:15`).
  - `${{ inputs.* }}` is interpolated into bash.
  - No release assets exist, so it falls back to `go install`.
  - `devx.ActionYAML` is a stale dead copy.
- **Pre-commit: partial.** `.pre-commit-hooks.yaml` passes `--no-store`, but the script written by `hook install` and the printed YAML both **omit it** (`devx.go:244,254`). Combined with the stored-findings bug, every commit is blocked on historical findings.

## 16. Release / distribution: stub

- **Missing entirely:** goreleaser, Homebrew tap, release workflow, signing, SBOM, provenance.
- **Build:** `make release` is a bare 5-target `go build`. The version is hard-coded `0.1.0` (`cli/root.go:25`, no ldflags). **The binary is 212 MB.**
- **Dockerfile:**
  - Runs as root, on a `python:3.12-slim` base, with no `.dockerignore` (so the local `.venv` is copied in).
  - trivy and steampipe are installed with `curl | sh` from `main`; steampipe uses `|| true`.
  - prowler and checkov are unpinned.
  - No image has been published.
- **`install.sh`:** no checksum or signature verification, a fixed `/tmp` path, `sudo mv`, no Windows support.

## 17. Docs: partial

**What exists:** README, CLAUDE_CONTEXT.md, `.planning/{PROJECT,ROADMAP,STATE,IMPLEMENTATION_PLAN}.md`, `docs/checks.md` (75 entries, accurate), the rulebook, research and design docs, one session log, `docs/neo4j-queries.cypher`, `python/README.md`.

**Accurate claims:** 75 checks, 58 boto3 checks, 157 Python tests, and "never validated live".

**Overstated or false claims:**
- IaC coverage beyond Terraform: it needs checkov or trivy.
- Auto-close: GitHub only.
- Alert rules: only `min_severity` is reachable from config.
- Windows install: not supported.
- Published ghcr image: none exists.
- "Credentials are never stored": config allows literal tokens and `onboard` persists them.
- "38 templates": there are 42.
- "OR semantics" and "exact min-cut": neither is implemented.
- "Same published formula" for risk: Go and Python differ.
- "Real-time": it is 2-minute polling.

## 18. Tests: partial

- **CI** (`.github/workflows/cloud-posture.yml`): IaC self-scan with SARIF and PR comment; `go vet` + `go test ./...` + `pytest`; Playwright UI smoke test.
- **Go:** 122 `Test*` functions across 31 files, all using fakes, httptest servers, client-go fake clientsets or golden JSON under `testdata/`.
- **Python:** 141 `def test_` functions, giving 157 cases (65 core, 76 boto3-check tests using moto).
- **Untested (0% coverage):** scanner runner, gitops, devx, config, output, graph (only indirectly), the Slack, GitHub Issues and SIEM sinks, the VS Code extension, the `scan` CLI path with collectors, `monitor`, `cost`, `runPatch`/`verifyPatch`.
- **E2E against real clouds: none.** No integration build tags or skip markers exist.

## 19. Config: partial

**Keys** (`internal/config/config.go`):
- Top level: `accounts[]`, `integrations{}`, `plugins`, `python{enabled,executable}`, `neo4j{…}` (**untagged struct**, so the real keys are `urienv` etc., and the example's `uri_env` is ignored, `:68-70`), `scan{iac_paths, attack_rules_file, work_dir, parallel, min_severity (unused)}`, `db`. `crown_jewels` is read by a separate raw parse.
- Account (14 keys): provider, profile, role_arn, regions, subscription_id, tenant_id, project_id, kube_context, org, domain, token_env, tools, criticality, owner.
- Sink (20 keys): enabled, min_severity, url, url_env, token, token_env, type, index, repo, labels, channel, project, issue_type, email, email_env, workspace_id, key_env, site, headers.

**Secrets:**
- Literal `token:`/`url:` values are allowed. There is no `${VAR}` expansion, and `headers` values are literal-only.
- `.env`, `nimbus.env` and `.cloud-posture/.env` are auto-loaded into the environment.

**Validation:** none. No `KnownFields`, unknown keys and sinks are ignored, and severity typos become INFO.

**Python packs:** `python/nimbus/plugin.py` provides a real `@check` SDK (tests: `test_okta_plugin_with_mock_transport`, `test_okta_plugin_skips_without_env`, `test_decorator_results_errors_and_cli`). There are 58 boto3 checks, all AWS: iam 17, ec2 10, s3 7, cloudtrail 6, cloudwatch 5, rds 4, and 1 each for kms, config, accessanalyzer, lambda, eks, vpc, guardduty, securityhub, efs.

## 20. Multi-tenant / RBAC / SSO / Postgres: absent

- Repo-wide greps find only scanned objects (K8s RBAC checks, Entra tenant IDs).
- The store is SQLite only (`modernc.org/sqlite`). There is no Postgres, no user model and no OIDC/SAML.
- The only auth is the optional shared bearer token on Go `POST /api/scan`.

---

## Top 20 defects/risks found

Ranked by severity, combining exploitability and blast radius. "Verified" means reproduced with a scratch probe during this audit.

1. **CRITICAL: the Go `/api/query` read-only guard is bypassable** (verified).
   - It is a substring denylist on a read-write connection. A CTE+DELETE, multi-statement via a `'--'` literal, and `ATTACH` (writes an arbitrary file) all get through.
   - Location: `internal/query/query.go:35-58`, `internal/store/store.go:439`.
   - Reachable unauthenticated on `0.0.0.0:8080` (#4).
2. **CRITICAL: Python `POST /api/alerts` leaks credentials to any host.**
   - Target dicts set `api_url`/`base_url`/`site`, so `GITHUB_TOKEN`, Jira and Datadog keys from the env are sent to the attacker. It is also SSRF.
   - Location: `python/nimbus/server.py:249`, `python/nimbus/integrations/clients.py:285-295`.
3. **CRITICAL: SQL injection through resource type in view DDL** (verified: a crafted ingest file dropped `findings`).
   - Location: `internal/store/store.go:404-408`, `:423`.
4. **HIGH: Go server exposure.** It binds all interfaces by default, has no auth on reads or `/api/query`, no Host check (DNS rebinding), simple-POST CSRF, no Read/Write timeouts and no body limit.
   - Location: `internal/cli/serve.go:226`, `internal/server/server.go:81-152,397,473`.
5. **HIGH: auto-PR commits the wrong file, with no path containment.**
   - It reads from `--iac root + f.File` but writes to `git toplevel + p.File`. `../` and absolute paths are allowed.
   - Location: `internal/cli/fix.go:230` vs `internal/gitops/gitops.go:121-128`, `iac.go:534-536`.
   - The `fix --ai` file name also allows traversal: `fix.go:175`.
6. **HIGH: destructive remediation templates suggested with `terraform apply -auto-approve`.**
   - The IAM admin template replaces the live policy with a placeholder. The cross-account trust template locks the role out. The SG template leaves 0.0.0.0/0 in place.
   - Location: `internal/remediation/generator.go:229`, `templates/iam_admin_policy.tf`, `iam_cross_account_trust.tf`, `sg_open_port.tf`.
7. **HIGH: the patcher edits the wrong resource** (verified: an EC2 fix was written into `aws_kms_key`), and it inserts undeclared variables so `terraform plan` fails.
   - Location: `internal/iac/iac.go:556`, `:597,611,670,674,678`.
8. **HIGH: `scan --fail-on`, SARIF, JSON and `--alert` operate on every stored finding, not this scan's** (verified). Together with the hook omitting `--no-store`, CI gates and pre-commit block on stale findings, and SARIF uploads them.
   - Location: `internal/cli/scan.go:383`, `internal/devx/devx.go:244,254`.
9. **HIGH: K8s and GCP service-account attack paths never fire.** `ClassFor` matches "account" before identity, so pod→SA→cluster-admin gives 0 paths (verified).
   - Location: `internal/graph/graph.go:365`, `internal/attackpath/traversal.go:163`.
10. **HIGH: the monitor is unreliable.** Continuous mode swallows poll errors, late events are lost to the time+1 ns watermark, a partial failure re-emits every event each poll, and the query window grows without bound.
    - Location: `internal/cli/serve.go:155`, `internal/monitor/monitor.go:343-348,367-369`.
11. **HIGH: secrets are disclosed.** Slack/Teams webhook URLs appear in alert error output, `serve --help` prints the `CLOUD_POSTURE_TOKEN` value, and the Neo4j password is accepted as a CLI flag.
    - Location: `internal/integrations/integrations.go:59` → `internal/cli/report.go:198`, `internal/cli/serve.go:232`, `internal/cli/paths.go:209`.
12. **HIGH: code execution from an untrusted checkout.** The Go CLI auto-runs `python -m nimbus.risk` from a cwd-relative `./python` or `../python`.
    - Location: `internal/cli/root.go:233-247`, `internal/cli/scan.go:423-460`.
13. **HIGH: supply chain.** The Action, install.sh and Dockerfile use `curl | sh` from `main` with no checksums, pinning or signing. The Docker image runs as root and copies the local `.venv`.
    - Location: `action.yml:15`, `install.sh:14`, `Dockerfile:9-15`.
14. **MEDIUM-HIGH: 5 reachable `golang.org/x/net` HTTP/2 vulnerabilities** (GO-2026-6617/6612/6611/6610/6603), fixed in v0.60.0.
    - Location: `go.mod` (x/net v0.59.0).
15. **MEDIUM-HIGH: detection logic produces false passes and false positives.**
    - M365 CA "any IncludeRoles" pass with exclusions ignored: `internal/collector/saas/m365.go:90-103`.
    - AWS `IsAdmin` ignores NotAction: `internal/collector/aws/policy.go:132-153`.
    - S3 ignores account-level Block Public Access: `aws/analyze.go:93`.
    - Azure NIC/subnet NSG combined with OR: `azure/build.go:236-255`.
    - GCP ignores deny/priority and never collects project IAM: `gcp/gcp.go:242-263`.
    - Okta "any rule": `saas/okta.go:233-239`.
16. **MEDIUM: VS Code workspace settings (`binaryPath`/`extraArgs`) choose which executable runs, automatically on activation.**
    - Location: `vscode-extension/package.json:23-26`, `src/extension.js:26`.
17. **MEDIUM: the native Terraform scanner panics** on an unknown bool expression (`!var.x`) (verified).
    - Location: `internal/iac/iac.go:366-367`, `:426-427`.
18. **MEDIUM: break-the-path is misleading.** The enabling weakness is attributed to the edge target, so IMDSv1 is reported as "reduce" only (verified). The min-cut is greedy set cover with no re-verification, prefix paths inflate counts, and the claimed OR semantics are absent.
    - Location: `internal/attackpath/traversal.go:462-475`, `:530-562`, `:278`, `:18-21`.
19. **MEDIUM: data-integrity gaps.**
    - Findings are never auto-resolved (upsert only): `internal/store/store.go:130`.
    - Trivy CVEs collapse across packages: `internal/model/model.go:140`.
    - The scanner runner discards valid output when stderr contains "error": `internal/scanner/runner.go:317`.
    - Custom compliance frameworks lose their inventory: `internal/cli/report.go:56`.
    - The Python risk score is swapped in but keeps the Go band and SLA: `internal/cli/scan.go:444-450`.
20. **MEDIUM: no timeouts or bounded failure handling in long-running paths.**
    - Native collectors have no per-account timeout: `internal/cli/scan.go:124`.
    - GitHub rate-limit 403s silently skip checks: `internal/collector/core/rest.go:97`, `saas/github.go:170`.
    - `Store.Query` ignores its context: `store.go:439`.
    - A Python recursive CTE hangs with no timeout: `python/nimbus/store.py:478-483`.
    - Steampipe passthrough has no timeout: `internal/cli/query.go:74`.
    - `alert` exits 0 on total failure: `internal/cli/report.go:207`.

## Remediated 2026-10-09

Security hardening track. Every fix had its failing test run first, and the full suites were green afterwards: `go vet ./... && go test ./...` all ok; `pytest -q` 177 passed. Session evidence is in `docs/sessions/2026-10-09-cwm-ui.md`, under "Security hardening track (Opus agent)".

| Defect | Fix | Tests |
|---|---|---|
| 1. `/api/query` guard bypass (Go) | `internal/store/readonly.go` `QueryReadOnly`, in layers: (1) a SQLite-aware lexer (single SELECT/WITH/VALUES; no ATTACH/DETACH/PRAGMA; no `sqlite_*`/`pragma_*`); (2) a separate `file:…?mode=ro&_pragma=query_only(1)` connection; (3) the engine prepares the statement with `sqlite3_prepare_v2`, and the tail must be empty and `sqlite3_stmt_readonly` must hold; (4) EXPLAIN `OpenRead` root pages must belong to schema-listed tables in `main`; (5) `sqlite3_interrupt` on the deadline. `query.Run`/`RunWith` use it. The unrestricted `Store.Query` was removed. | `internal/query/security_test.go`: `TestReadOnlyGuardBlocksBypasses` (14 payloads), `TestReadOnlyGuardAllowsLegitimateQueries`, `TestQueryTimeoutInterruptsRunawaySQL`. `internal/store/readonly_test.go`: `TestReadOnlyEngineLayers`, `TestCheckReadOnlySQLLexer`. |
| 1. `/api/query` (Python) | `Store.query_readonly`: a `mode=ro` connection with `query_only`, a `set_authorizer` allowlist (SELECT, READ on schema tables/views, FUNCTION, RECURSIVE) and a `set_progress_handler` timeout. Used by `queries.run_sql` and the copilot. | `python/tests/test_security.py`: `test_query_readonly_rejects_bypasses[8]`, `test_query_readonly_allows_views_and_ctes`, `test_query_readonly_times_out`, `test_api_query_rejects_bypasses`. |
| 2. Python `POST /api/alerts` SSRF and credential exfiltration | Returns 501 unless `CLOUD_POSTURE_TOKEN` is set, and 401 without a matching bearer token (constant-time compare). Targets must be channel names; any dict or URL gets 400. Destinations come only from the server's environment. | `test_alerts_disabled_without_server_token`, `test_alerts_requires_bearer_token`, `test_alerts_never_take_destinations_from_the_request[5]` (the mocked httpx records no outbound call), `test_alerts_use_server_side_destination`. `test_server.py::test_alerts_endpoint` now sends the token. |
| 3. View DDL injection | The derived view name must match `^[A-Za-z][A-Za-z0-9_]{0,63}$`; otherwise the view is skipped and `store.Warnf` logs it. Identifiers are double-quoted. The same check is applied in Python `ensure_views`. | `internal/cli/security_test.go`: `TestIngestCraftedResourceTypeCannotDropTables` (crafted ingest file). `test_crafted_resource_type_is_not_interpolated`. |
| 4. Go server exposure | `--addr` defaults to `127.0.0.1:8080`. `ValidateBind` refuses a non-loopback bind without a token. The token is enforced on `/`, `/ws` and `/api/*`: a bearer header everywhere, `?token=` on `/ws` only, and a `/?token=` exchange for an HttpOnly SameSite=Strict cookie so the browser dashboard works. A Host allowlist (bound host, localhost, 127.0.0.1, [::1], `--allowed-host`) returns 421 otherwise. A state-changing request is rejected unless `Sec-Fetch-Site` is same-origin/none or the Origin is allowed. `http.Server` sets RHT 10s, RT 30s, IT 60s and MHB 64 KiB. POST bodies are capped at 1 MiB (413). `/api/query` has a timeout (`--query-timeout`, 10 s). The WebSocket read limit is 4 KiB. | `internal/server/security_test.go`: `TestHostHeaderAllowlist`, `TestTokenEnforcedOnAPIAndWebSocket`, `TestCrossSitePostRejected`, `TestServerTimeoutsAndBodyLimit`, `TestQueryEndpointTimeout`, `TestBindRequiresTokenOffLoopback`. `TestServeDefaultsLoopbackAndHidesToken`. |
| 5. Auto-PR writes the wrong file; path traversal | `gitops.SafeJoin` (Clean plus EvalSymlinks, typed `*PathEscapeError`). `OpenFixPR` resolves reads and writes against `RepoDir` and checks containment in the repo before any git operation. `runPatch` checks before reading and before the in-place write. `aiFixFileName` sanitises the name and `writeFixFile` keeps writes inside `--out-dir`. | `internal/gitops/gitops_test.go`: `TestSafeJoinContainsPaths`, `TestOpenFixPRWritesTheFileItRead`, `TestOpenFixPRRejectsEscapingPaths`. `TestPatchRejectsFilesOutsideIaCRoot`, `TestFixOutputFileContained`. |
| 8. Gate, SARIF, JSON and `--alert` used every stored finding | `finishScan` returns only `scan_id = current` findings (graph, paths and risk still use history). `gateCount` was extracted. The hook script and `.pre-commit-hooks.yaml` pass `--no-store`. | `TestScanGateUsesOnlyCurrentScanFindings`, `TestPreCommitHookDoesNotStore`. |
| 11. Secret disclosure | Integrations go through `redactingClient`/`newRequest`, which rewrite `*url.Error` URLs to scheme://host. The `serve --token` default is resolved at run time, and the help shows "(default from $CLOUD_POSTURE_TOKEN)". `graph push --password` is hidden and fails with a pointer to `NEO4J_PASSWORD`. | `internal/integrations/redact_test.go`: `TestDeliveryErrorsRedactWebhookURLs`. `TestServeDefaultsLoopbackAndHidesToken` (child process with the token in env), `TestNeo4jPasswordFlagRemoved`. |
| 12. Python executed from an untrusted CWD | `pythonDir()` is only `$NIMBUS_PYTHON_DIR` or `python/` beside or above the real executable. `runPython` runs from an empty temp dir with `PYTHONSAFEPATH=1` and the trusted dir on `PYTHONPATH`. New `--python` / `$CLOUD_POSTURE_PYTHON`. | `TestPythonNotLoadedFromWorkingDirectory`. |
| 14. x/net HTTP/2 vulnerabilities | `go get golang.org/x/net@v0.60.0` (no tidy). | `govulncheck ./...`: "Your code is affected by 0 vulnerabilities" (before: 5). |

Still open from these items:
- `internal/scanner/runner.go` runs `python3 -m nimbus.checks` with the process cwd on `sys.path`. It was outside this track's edit scope.
- `modernc.org/libc` is now imported directly but is still marked `// indirect` in go.mod. That needs a tidy, which was not allowed.
- gosec has 2 new G103 findings: the deliberate `unsafe.Pointer` out-parameters passed to `sqlite3_prepare_v2`.
