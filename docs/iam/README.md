# Least-privilege read-only permissions

These files define the permissions nimbus's native cloud collectors need. They are
generated from the API calls the collectors actually make, so they grant nothing
more than that.

| File | What it is |
|---|---|
| `api-permissions.json` | Hand-maintained mapping from each collector SDK call to the IAM action(s) it needs. The `_keyFormat` block explains the key format for each cloud. Extra (pre-mapped) entries are allowed. |
| `readonly-policy-aws.json` | **Generated.** AWS customer-managed IAM policy (one `Allow` statement, `Resource: "*"`). |
| `../../internal/cli/iam/readonly-policy-aws.json` | **Generated.** An identical copy of the AWS policy. `onboard --deploy-role` embeds it with go:embed, which cannot reach `docs/`. |
| `readonly-role-azure.json` | **Generated.** Azure custom role definition named "Cloud Posture Reader". |
| `readonly-role-gcp.json` | **Generated.** GCP custom role for `gcloud iam roles create --file`. |

## How the files are generated

`internal/cli/iampolicy_test.go` (`TestReadOnlyPolicies`) parses the non-test sources
of `internal/collector/{aws,azure,gcp}` with `go/ast`:

- **AWS**: the methods of the narrow client interfaces, including embedded
  `<svc>.<Op>APIClient` paginator interfaces. It also checks that every service built
  with `NewFromConfig` has at least one extracted call.
- **Azure**: the interface methods whose signatures use ARM `<Client><Op>Options/Response`
  types. It also checks that every ARM client constructor has at least one extracted call.
- **GCP**: the calls made through a receiver's SDK-typed struct field
  (`c.svc.Instances.AggregatedList(...)`, `s.c.Bucket(n).IAM().Policy(...)`).

The test fails when:

- an extracted call has no entry in `api-permissions.json` ("unmapped collector call ...").
- a generated action is not read-only. AWS actions must be Get/List/Describe/Lookup/BatchGet,
  plus the allowlisted `iam:GenerateCredentialReport`. Azure actions must end in `/read`.
  GCP permissions must end in `.get`, `.list` or `.getIamPolicy`.
- a generated file on disk differs from what the source produces.

After you change a collector or the mapping, regenerate the files:

```sh
go test ./internal/cli -run TestReadOnlyPolicies -update
```

**Scope:** the extraction covers only the SDK client interfaces in
`internal/collector/{aws,azure,gcp}`. The Kubernetes and SaaS collectors use their own
tokens and scopes, so they are out of scope. If you use AssumeRole, the role's trust
policy is configured separately.

## Applying

AWS:

```sh
aws iam create-policy --policy-name CloudPostureReadOnly \
  --policy-document file://docs/iam/readonly-policy-aws.json
aws iam attach-role-policy --role-name <scanner-role> \
  --policy-arn arn:aws:iam::<account-id>:policy/CloudPostureReadOnly
```

Azure: before you create the role, replace the placeholder subscription
`00000000-0000-0000-0000-000000000000` in `AssignableScopes` with your subscription ID(s)
or a management-group scope.

```sh
az role definition create --role-definition @docs/iam/readonly-role-azure.json
az role assignment create --assignee <principal-id> --role "Cloud Posture Reader" \
  --scope /subscriptions/<subscription-id>
```

GCP:

```sh
gcloud iam roles create cloudPostureReader --project <project-id> \
  --file docs/iam/readonly-role-gcp.json
gcloud projects add-iam-policy-binding <project-id> \
  --member serviceAccount:<sa-email> --role projects/<project-id>/roles/cloudPostureReader
```

To create the role at organization level, use `--organization <org-id>` instead of `--project`.
