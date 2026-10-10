# nimbus finding contract, v1

- **Spec version:** 1.0.0 (`spec_version` in the envelope; Go constant `output.FindingSpecVersion`)
- **Schema:** [`finding-v1.schema.json`](finding-v1.schema.json) (JSON Schema 2020-12). It is generated
  from `internal/model` by `go generate ./internal/output`, and `TestFindingSchemaMatchesModel` fails
  when the two drift apart or when a field is missing from this page.
- **Status:** stable for 1.x. Readers accept any `1.x` document. Fields may be added in a minor
  version. Removing a field, renaming one or changing its meaning needs a `2.0.0` and a new
  `finding-v2` schema file.

This is the format nimbus (`cloud-posture`) reads natively (`cloud-posture ingest --source native`,
Python SDK plugins) and the one it writes for `--format json` / `convert --to json`. Each adapter
(Prowler, Checkov, Trivy, Steampipe, ScoutSuite, Trivy Operator, Kubescape, kube-bench,
Cartography) produces these records, and the adapter golden files are checked against the schema
in `go test`.

## 1. Documents

A native document is one of:

1. **Envelope** (what nimbus writes):
   ```json
   {"spec_version": "1.0.0", "findings": [ {finding}, ... ]}
   ```
2. A **JSON array** of findings.
3. **JSON lines**: one finding object per line (`*.jsonl`).
4. The `scan --format json` document. Its `findings` array is read and the other keys are ignored.

Files named `*.findings.json` or `*.jsonl` are detected as native without content sniffing. A bare
array is detected when its first element has `canonical_id`, or both `source` and `check_id`.

## 2. Finding

Each finding must have `canonical_id`, or both `source` and `check_id`. Every other field is
optional on ingest. nimbus fills defaults in `Finding.Finalize` and enriches from the catalog.
Unknown fields are **not** part of the contract: the schema rejects them, and the Go reader drops
them.

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable fingerprint. When it is empty, nimbus computes the first 32 hex characters of `sha256(source\|check_id\|provider\|account\|region\|resource.id\|file)`. Keep it stable across scans of the same check on the same resource. |
| `source` | string | Producing tool, in lower case (`prowler`, `checkov`, `trivy`, `cloud-posture`, a plugin name). Part of the fingerprint. |
| `check_id` | string | The tool's native check id (`s3_bucket_public_access`, `CKV_AWS_20`, `CVE-2024-3094`). Part of the fingerprint. |
| `canonical_id` | string | nimbus catalog id (`S3_PUBLIC_BUCKET`). The catalog maps `source` + `check_id` onto it, and an unmapped check becomes `UPPER(source):check_id` (for example `PROWLER:s3_bucket_x`). |
| `title` | string | One-line title. Filled from the catalog when empty. |
| `description` | string | Longer explanation, or the tool's status detail. |
| `severity` | enum | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, in upper case. Native ingest does not normalise other spellings (adapters do). Empty means `INFO`, and an `INFO` finding takes the catalog severity. |
| `status` | enum | `FAIL` is an open misconfiguration. `PASS` means the check ran and found no problem. `SKIP` covers muted, manual or not-applicable checks. `ERROR` means the check could not be evaluated. An `ERROR` with `tags.scan_gap` is a scan gap, and scan gaps fail closed. Empty means `FAIL`. |
| `provider` | string | `aws`, `azure`, `gcp`, `oci`, `kubernetes`, `github`, `m365`, `okta`, `iac` or `unknown`. |
| `account` | string | Account, subscription, project, cluster or org id. Part of the fingerprint. |
| `region` | string | Region or location, for regional resources. Part of the fingerprint. |
| `resource` | object | The affected resource (§3). |
| `file` | string | IaC file path relative to the scanned root (IaC findings only). Part of the fingerprint. |
| `line_start` | integer ≥ 0 | First line of the offending block, counting from 1. |
| `line_end` | integer ≥ 0 | Last line of the offending block. |
| `remediation` | string | Fix guidance. |
| `weaknesses` | string[] | Weakness vocabulary used by the attack-path engine (`PUBLIC_DATA_STORE`, `IMDSV1_ENABLED`, ...). Merged with the catalog's list. |
| `compliance` | object | Map from framework key to control ids, for example `{"cis_aws": ["2.1.4"]}`. Merged with the catalog's mappings. |
| `tags` | object | String labels. Reserved keys: `account_label`, `scan_gap`, `service`, `cvss`, `primary_url`. |
| `scan_id` | string | Id of the scan that produced the finding (set by nimbus). |
| `first_seen` | RFC 3339 | When the finding was first observed. Set on ingest when absent. |
| `last_seen` | RFC 3339 | When it was last observed. Set on ingest. |
| `raw` | any | The tool's original record, kept verbatim as evidence and never rendered as HTML. |

## 3. Resource, `related` and `relations`

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Provider-native id: an ARN, an Azure resource id, a GCP self link, a Kubernetes id (`<namespace>/<kind>/<name>`, `cluster/<kind>/<name>`), or a Terraform address. It is the graph node id and part of the fingerprint. |
| `type` | string | Resource type, using Terraform naming where it exists (`aws_s3_bucket`). |
| `name` | string | Display name. Defaults to `id`. |
| `attributes` | object | Collector or tool attributes that rules and the graph read. |
| `related` | array | Related resource ids. On ingest each entry is either a **string**, an untyped hint that becomes an `attached_to` edge, or a **typed relation** object `{id, kind, attr}`. |
| `relations` | array | Typed relations, in the form nimbus writes. |

**What nimbus writes.** `related` holds strings only: every related id, typed or not. The typed
entries are written again under `relations`. Consumers that only understand a list of strings, such
as the Python SDK and the SQLite resources table, keep working. When reading, the typed objects in
`related` and the entries in `relations` are merged and de-duplicated by `(id, kind)`.

A **relation** has these fields:

| Field | Type | Meaning |
|---|---|---|
| `id` | string, required | Target resource id. |
| `kind` | string, required | The edge kind (see the list below). |
| `attr` | object | Attributes copied onto the graph edge. `attr.because` (a string) becomes the hop's explanation in attack paths. |

`kind` must be one of these graph edge kinds: `attached_to`, `runs_as`, `bound_to`, `member_of`,
`trusts`, `has_policy`, `grants_access_to`, `runs_on`, `allows_traffic_to`, `can_assume`,
`exposes`, `contains`, `stores_data_in`.

These aliases are also accepted (resolved by `graph.RelationEdge`):

| Alias | Becomes |
|---|---|
| `policy` | `has_policy` |
| `resource` | `grants_access_to` (a policy statement's Resource) |
| `sts_assume_role_allows` | `can_assume`, pointing from the related principal to this role |
| `exposed_to_internet` | `exposes`, pointing from the internet node to this resource |

Matching is case-insensitive. An unknown kind is kept, but only as an unverified `attached_to`
hint, and the edge records the declared kind. A relation without `id` or `kind` is rejected.
`TestRelationKindsResolveInGraph` keeps this list in step with the graph builder.

Example:

```json
{
  "source": "my-plugin", "check_id": "lambda_role", "status": "PASS",
  "provider": "aws", "account": "444455556666",
  "resource": {
    "id": "arn:aws:lambda:us-east-1:444455556666:function:report-export",
    "type": "aws_lambda_function",
    "related": [
      "arn:aws:ec2:us-east-1:444455556666:security-group/sg-1",
      {"id": "arn:aws:iam::444455556666:role/report-export-role", "kind": "runs_as",
       "attr": {"because": "function execution role"}}
    ]
  }
}
```

## 4. Format mappings

`cloud-posture convert <file> --from <fmt> --to <fmt>` is backed by `output.Convert`. It reads
`json`, `ocsf`, `sarif` and `asff`, and writes `json`, `sarif`, `ocsf`, `asff`, `gitlab`, `junit`,
`csv` and `html`.

| Target | Fidelity | Notes |
|---|---|---|
| OCSF 1.6 Detection Finding | **lossless** both ways (`raw` excepted) | Validated against the official OCSF 1.6.0 class schema (`testdata/ocsf/`) in `go test`. |
| SARIF 2.1.0 | open findings and scan gaps only; identity preserved | At most 25,000 results (GitHub's limit). When there are more, the most severe are kept and the run gets a `toolExecutionNotifications` warning plus `properties.truncated`. |
| ASFF (Security Hub) | identity, status, severity and placement preserved; attributes and relations dropped | `SchemaVersion` is `2018-10-08`. The `ProductArn` placeholder is `arn:aws:securityhub:<region>:<account>:product/<account>/default`. Field limits are enforced (Title 256, Description 1024, Recommendation 512, ProductFields 50 pairs, 240 KB per finding), with batches of 100. Non-AWS accounts use `ASFFOptions.AccountID`, or `000000000000` when that is not set. |
| GitLab SAST v15 | write only | `FAIL` findings and scan gaps. Cloud findings are located at `cloud://<provider>/<resource-id>`. The vulnerability id is a UUID derived from the fingerprint, so it stays stable across pipelines. |
| JUnit XML | write only | One test suite per provider. `FAIL` becomes `<failure>`, `ERROR` becomes `<error>`, `SKIP` becomes `<skipped>`. |
| CSV | write only | Cells that start with `= + - @`, a tab or a CR get a `'` prefix to block CSV formula injection. |
| HTML | write only | The single-file dashboard renderer, with all data embedded as escaped JSON. |

### 4.1 OCSF mapping (Detection Finding, `class_uid` 2004)

| nimbus | OCSF 1.6 attribute | Notes |
|---|---|---|
| (constant) | `class_uid` 2004, `category_uid` 2, `activity_id` 1, `type_uid` 200401, `metadata.version` "1.6.0", `metadata.profiles` ["cloud"] | `metadata.product` = {name "cloud-posture", vendor_name "nimbus"} |
| `id` | `finding_info.uid`, `metadata.uid` | |
| `source` | `finding_info.product.name` | |
| `check_id` | `metadata.event_code`, `finding_info.analytic.uid` | `metadata.event_code` is where Prowler puts its check id |
| `canonical_id` | `finding_info.types[0]`, `unmapped.canonical_id` | |
| `title` | `finding_info.title`, `message` | |
| `description` | `finding_info.desc` | |
| `severity` | `severity_id` / `severity` | INFO 1 Informational, LOW 2, MEDIUM 3, HIGH 4, CRITICAL 5. On read, Fatal (6) becomes CRITICAL |
| `status` | `status_code`, plus `status_id` / `status` | FAIL 1 New, PASS 4 Resolved, SKIP 3 Suppressed, ERROR 99 Other. `status_code` keeps the nimbus value, which is where Prowler writes PASS and FAIL |
| `provider` | `cloud.provider` | |
| `account` | `cloud.account.uid` | `tags.account_label` goes to `cloud.account.name` |
| `region` | `cloud.region`, `resources[0].region` | |
| `resource.id` / `name` / `type` / `attributes` | `resources[0].uid` / `name` / `type` / `data` | |
| `remediation` | `remediation.desc` | |
| `first_seen` / `last_seen` | `finding_info.first_seen_time(_dt)`, `last_seen_time(_dt)`; `time` = last_seen | Epoch milliseconds plus an RFC 3339 `_dt` sibling. Readers prefer `_dt` (nanosecond precision) |
| `scan_id` | `metadata.correlation_uid`, `unmapped.scan_id` | |
| CVE findings (`check_id` CVE-…) | `vulnerabilities[0].cve.uid`, `.cvss[0].base_score` (from `tags.cvss`), `.references` (from `tags.primary_url`) | |
| `weaknesses`, `compliance`, `tags`, `file`, `line_start`, `line_end`, `resource.related`, `resource.relations` | `unmapped.*` | `unmapped.compliance` uses the same place and shape as Prowler's json-ocsf |

The reader (`output.ParseOCSF`) accepts any Detection Finding producer, Prowler included. It falls
back to `metadata.product.name` for `source`, and treats epoch values below 10^11 as seconds.
Without the `unmapped` extras, a cloud finding still gets the same fingerprint from standard
attributes alone. IaC findings need `unmapped.file` for that.

## 5. Conformance

- Validate a document with any JSON Schema 2020-12 validator against
  `finding-v1.schema.json`. To check a single finding, use `#/$defs/finding`.
- nimbus validates the golden output of every adapter
  (`testdata/golden/adapters/*.golden.json`) and the fixture `testdata/native.findings.json`
  against the schema in `go test`.

## 6. Changelog

- **1.0.0** (2026-10-09): first published version. It covers the fields of `internal/model.Finding`
  as of P1-INTEROP, typed `related` / `relations` (Track B2), the envelope with `spec_version`,
  and the OCSF mapping table.
