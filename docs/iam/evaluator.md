# `internal/iam`: the IAM evaluator, v1

`internal/iam` is a pure Go package that decides AWS IAM authorization. It does no I/O, imports no SDK and gives the same output for the same input. Collectors and the graph don't call it yet. Wiring it in is P1-IAM items I3 to I5 (`.planning/IMPLEMENTATION_PLAN_v3.md` §4).

## API

```go
p, err := iam.ParsePolicy(jsonBytes) // also accepts the URL-encoded form IAM APIs return
p.ID = "arn:aws:iam::111111111111:policy/x" // the caller sets this; used in statement references

d := iam.Evaluate(req, identity []iam.Policy, resource, boundary *iam.Policy, scps [][]iam.Policy, session *iam.Policy)
d := iam.EvaluateSet(req, iam.PolicySet{Identity, Resource, Boundary, Session, SCPs, RCPs})

req := iam.Request{
    Principal:       "arn:aws:sts::111111111111:assumed-role/app/s", // user/role/session ARN, service principal, IdP ARN, "" = anonymous
    Action:          "s3:GetObject",
    Resource:        "arn:aws:s3:::bucket/key",
    ResourceAccount: "111111111111", // needed when the ARN has no account segment (S3) and the access may be cross-account
    Context:         map[string]iam.ConditionValue{"aws:SourceIp": {"203.0.113.7"}},
    ContextComplete: false,
}

d.Effect               // iam.Allow | iam.ExplicitDeny | iam.ImplicitDeny | iam.Unknown
d.MatchedStatements    // []iam.Ref, in evaluation order; Ref.String() = "<policy>#<sid|index>", plus "?" when Conditional
d.DeniedBy             // *iam.Ref, the first explicit deny
d.Reasons              // why the request is denied or Unknown (empty for Allow)
d.UnknownConditionKeys // keys, variables or operators that left a matching statement undecidable

iam.IsAdmin(func(action, resource string) iam.Decision) iam.AdminLevel // AdminNone | AdminConditional | AdminFull
iam.AllowedActions(resourceARN, policies...) (allowed, unknown []string)
iam.ActionCatalog(policies...) []string
```

`scps` (and `RCPs`) holds **one slice per level of the OU chain**: root, then each OU, then the account. Each level can have several policies attached. A real chain has several SCPs per level (`FullAWSAccess` plus deny policies), so a flat `[]Policy` can't express "every level must allow".

## Semantics implemented

How a request is decided follows the [AWS policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html):

1. **Explicit deny wins.** A matching `Deny` in any layer (SCP, RCP, resource policy, identity policy, boundary, session policy) gives `ExplicitDeny`.
2. **SCPs gate the request.** Every level of the OU chain must contain an `Allow` that matches. A level with none gives `ImplicitDeny`, with the reason "no SCP at SCP level N". The following are exempt from SCPs: service principals, anonymous callers, web-identity/SAML IdP principals, and service-linked roles (`aws:PrincipalArn` containing `:role/aws-service-role/`, or a session ARN `arn:aws:sts::<acct>:assumed-role/AWSServiceRoleFor…/…`, whose role path is not visible). Exempt principals are not evaluated against SCPs at all, so an SCP `Deny` does not apply to them either (the exemption is applied before the SCP walk; before verify-4 it only lifted the Allow gate). SCPs apply to everyone else, including the root user of a member account. For a principal in the management account, pass no SCPs.
3. **RCPs are deny-only.** Their `Deny` statements count like any other explicit deny. Their `Allow` statements are ignored, which assumes `RCPFullAWSAccess`.
4. **Same account.** The request is allowed if any of the following holds:
   - a resource-policy `Allow` names the IAM user ARN, the role-session ARN, a service or IdP principal, or `"*"` for a non-role caller. This is enough on its own and isn't limited by the boundary or session policy.
   - a resource-policy `Allow` names the role ARN, or `"*"` for a role session. This grant is intersected with the permission boundary and the session policy.
   - identity ∩ boundary ∩ session allow.

   A resource-policy `Allow` that names only the **account** (`123456789012` or `arn:aws:iam::123456789012:root`) delegates to IAM, so the identity side must also allow.
5. **Cases where the resource policy is required.** For KMS keys (`arn:aws:kms:…:key/…`) and role trust (`sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity` and `sts:AssumeRoleWithSAML` on `arn:aws:iam::…:role/…`), an identity allow is never enough. The key policy or trust policy must name the principal, or name its account (the account form also needs an identity allow). A missing key policy gives `ImplicitDeny`.
6. **Cross account** (principal account ≠ resource account). Identity ∩ boundary ∩ session must allow, **and** the resource policy must allow the principal or its account. If the resource account can't be determined (an S3 ARN with no `ResourceAccount`) and a resource policy exists, the evaluator decides both the same-account and the cross-account case. If they disagree, the result is `Unknown`. With no resource policy it assumes the same account.
7. **Matching.**
   - Actions use `*`/`?` globs and are case-insensitive.
   - Resources are matched one ARN segment at a time and are case-sensitive. A wildcard in one of the first five segments never crosses a `:`. The last segment of the pattern covers the rest of the ARN, so `arn:*` matches everything. `bucket/*` does **not** cover the bucket ARN.
   - `NotAction` and `NotResource` invert the match. `NotResource: "*"` grants nothing.
   - A resource-policy statement with neither `Principal` nor `NotPrincipal` applies to nobody.
   - `NotPrincipal` is treated as exempting a caller only when every identity AWS evaluates is listed: the principal ARN, its role ARN for a session, and its account. So a `Deny` with `NotPrincipal` listing only a role ARN still denies that role's sessions.
   - `Effect` is case-sensitive. `"allow"` matches nothing.
8. **Policy variables** (`Version: 2012-10-17` only; `2008-10-17` keeps the text literal).
   - `${key}` and `${key, 'default'}` work in `Resource`, in `NotResource` and in the values of `String*`/`Arn*` conditions.
   - `${*}`, `${?}` and `${$}` produce literal characters. A substituted value is also treated literally, so a `*` inside it isn't a wildcard.
   - These keys are derived from the request when absent: `aws:PrincipalArn` (the role ARN for a session), `aws:PrincipalAccount`, `aws:PrincipalType`, `aws:username` (IAM users only) and `aws:ResourceAccount`.
   - A variable that can't be resolved makes the statement undecidable. So does a multi-valued key.
9. **Conditions.**
   - Supported operators: `String{Equals,NotEquals,EqualsIgnoreCase,NotEqualsIgnoreCase,Like,NotLike}`, `Numeric*`, `Date*` (RFC 3339, date-only or epoch seconds), `Bool`, `BinaryEquals`, `IpAddress`/`NotIpAddress` (IPv4/IPv6 CIDR or bare IP), `Arn{Equals,Like,NotEquals,NotLike}`, `Null`, the `…IfExists` suffix on every operator except `Null`, and the `ForAnyValue:`/`ForAllValues:` prefixes.
   - Operators are ANDed. Keys are ANDed. The values listed for one key are ORed. A negated operator holds only when no value matches.
   - Condition keys are case-insensitive. Values are case-sensitive except for `…IgnoreCase` and `Bool`.
10. **Unknown, never Allow.**
    - A condition key missing from `Context` makes the statement undecidable (Kleene three-valued logic: yes / maybe / no). The exceptions are `…IfExists`, where a missing key is true, and `Null`, where a missing key counts as absent.
    - An unsupported operator also makes the statement undecidable.
    - When `ContextComplete` is set, a missing key from the evaluator's catalog (the `aws:` global keys plus `s3:prefix`, `sts:ExternalId`, `kms:ViaService`, the GitHub OIDC `sub`/`aud`, …) follows AWS semantics: false, except true for negated operators and for `ForAllValues`. A key outside the catalog stays undecidable either way.
    - The outcome is `Unknown` exactly when `Allow` is possible but not certain. If no allow is possible, the result is `ImplicitDeny` even when a deny is also undecidable.
    - Undecidable statements appear in `MatchedStatements` with `Conditional`, and their keys appear in `UnknownConditionKeys`.

### Helpers for later tracks

- **`IsAdmin(fn)`** probes the collector's 14 privilege-escalation actions on three resources from unrelated services. It returns `AdminFull` when some escalation action is allowed on all three, `AdminConditional` when the best such action is `Unknown`, and `AdminNone` otherwise. `TestIsAdmin` ports the collector's 18 adversarial cases (`internal/collector/aws/policy_admin_v2_test.go`). 17 of them agree. One differs on purpose: `Allow *` plus a `Deny *` that has a condition is `conditional`, not `full`, because the deny may apply. An extra test case covers a second deliberate difference: a single escalation action granted on `*` (for example `iam:PutRolePolicy`) is `full`, where the collector says `none`.
- **`AllowedActions(resource, policies...)`** evaluates, with an empty context, the literal actions named in the policies plus a built-in list of sensitive data and escalation actions. It returns the allowed actions and the `Unknown` ones. It doesn't use a full service action list, so actions that appear only under a wildcard and aren't in the built-in list aren't reported.

## What v1 does NOT model

- **Service-specific authorization quirks**:
  - S3 ACLs, Object Ownership and Block Public Access
  - the S3 object-owner versus bucket-owner rules
  - KMS grants
  - the Lambda/SNS/SQS rules for `aws:SourceAccount`/`aws:SourceArn` beyond plain condition matching
  - EC2/EKS-specific resource types
  - checking that an action supports a given resource type (`s3:ListBucket` on an object ARN is evaluated as written)
  - actions with no resource-level permissions, which require `Resource: "*"`; v1 doesn't check this
- **VPC endpoint policies.**
- **RCPs beyond deny-only.** RCP `Allow` statements are ignored and assumed to be full access. The evaluator also doesn't model RCP exemptions for service principals or the management account.
- **Parity with IAM Access Analyzer and the policy simulator.** v1 hasn't been cross-checked against `iam:SimulatePrincipalPolicy`; that is item I6. The corpus derives from the AWS documentation.
- **The rest of the principal model.** Role paths can't be seen in assumed-role ARNs, so role ARNs are matched by account and name. The evaluator doesn't model:
  - the root user's implicit full access
  - the management-account SCP exemption (pass no SCPs instead)
  - session tags, source identity and transitive tags
  - federated-user session nuances
  - the permissions of an anonymous caller beyond `Principal: "*"`
- **Policy validation.** Malformed but parseable statements are not rejected. A statement with no `Action` matches nothing. One with no `Resource` matches any resource, as trust and key policies imply.
- **Time.** `aws:CurrentTime` and `aws:EpochTime` must be supplied in `Context`; the evaluator never reads the clock.

## Corpus: `internal/iam/testdata/corpus/*.yaml`

`TestCorpus` loads every file and requires the following for each case:
- a `source` that is an AWS documentation URL or a `lab/` fixture path
- a declared `expect.matched` (use `[]` for none)
- an exact decision, and an exact set of matched statement refs
- when given, an exact `unknown_keys` list

The corpus must have at least 60 cases and they must all pass. It contains no PMapper test content; PMapper is AGPL.

```yaml
category: conditions
cases:
  - name: BoolIfExists MFA true with key absent allows (long-term keys)
    source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_IfExists
    request:
      principal: "arn:aws:iam::111111111111:user/alice"
      action: ec2:StopInstances
      resource: "arn:aws:ec2:us-east-1:111111111111:instance/i-1"
      resource_account: "111111111111"   # optional
      context: {"aws:SourceIp": "10.0.0.1", "aws:TagKeys": [a, b]}  # optional
      context_complete: false            # optional
    identity:        [{id: p, document: {Version: "2012-10-17", Statement: [...]}}]
    resource_policy: {id: bucket, document: {...}}   # optional
    boundary:        {id: pb, document: {...}}       # optional
    session:         {id: sess, document: {...}}     # optional
    scps:            [[{id: root-full, document: {...}}], [{id: ou, ...}, {id: deny, ...}]]  # one list per OU level
    rcps:            [[{id: perimeter, document: {...}}]]
    expect:
      decision: allow            # allow | explicit_deny | implicit_deny | unknown
      matched: [p#WithMFA]       # "<policy id>#<Sid or statement index>", suffix "?" when undecidable
      unknown_keys: []           # optional
```

To add a case:
1. Find the AWS documentation section that states the behaviour and put its URL in `source`.
2. Write the case so that it fails first: run `go test ./internal/iam/ -run 'TestCorpus/<file>/<name>'`.
3. Fix the evaluator if needed.
4. Keep each file to one category.

The categories, with C's Phase-1 minimums in brackets (a 200-case total is the P1-IAM exit target):
- `deny_precedence` [20]
- `notaction_notresource` [20]
- `conditions`, `unknown_keys` [50 and 10]
- `scp_rcp` [25]
- `boundary` [15]
- `resource_policy_cross_account`, `trust_policy` [30]
- `kms` [10]
- `policy_variables` [10]
- `session_policy` [10]
- `wildcards`

## Graph wiring: permission-bearing edges (P1-IAM items 2–4)

`graph.EvaluatePermissions` (internal/graph/permissions.go) runs the evaluator over the AWS
identity part of the graph. `graph.AttachFindings` calls it after every batch (idempotent), and the
AWS collector calls it at the end of `analyze`.

### Inputs (node attributes)

| where | attribute | source |
|---|---|---|
| role / user | `inline_policy_document`, `inline_policy_documents` | ingested inventory (lab) |
| role / user / group | `has_policy` edges to `aws_iam_policy` nodes carrying `policy_document` (raw JSON, URL-decoded) and `policy_arn` | AWS collector |
| role / user | `attached_policies` (ARNs) | a policy node's `policy_document`, else the built-in copy (`iam.ManagedPolicy`: AdministratorAccess and FullAWSAccess are exact; PowerUserAccess, ReadOnlyAccess, AmazonS3FullAccess/ReadOnlyAccess, IAMFullAccess, SecretsManagerReadWrite, AmazonDynamoDBFullAccess and AmazonEC2FullAccess are their documented shapes, **not exact**) |
| user | `member_of` → group policies | both |
| role / user | `permissions_boundary` (ARN) or `permissions_boundary_document` | collector / inventory |
| account node `aws:account:<id>` | `scp_levels` / `rcp_levels` (`[[{id,name,arn,document}]]`, root → OUs → account), `scp_status` (`collected`, `not_in_org`, `denied`, `error`, `not_collected`) | collector: `organizations:ListParents`, `ListPoliciesForTarget`, `DescribePolicy` |
| role / user | `governing_scps` (`[{id,name,statement\|document}]`, read as one level beside FullAWSAccess) | lab |
| role | `trust_policy` (document), else `trust_principals` (synthesised trust, not exact) | both |
| data store / function | `resource_policy` (bucket, key, secret, function policy) and `resource_policy_status` (`collected`, `none`, `denied`, `error`). A KMS key with no collected key policy gets the default key policy (not exact) | collector |
| role / user | `iam_policies_complete: true` when every identity and boundary document was collected and parsed | collector |

Free-text `inline_policy` makes the principal incomplete. A document `internal/iam` cannot parse is
recorded as `policy_parse_error`.

### Edge construction rules

1. **Data reads** (`grants_access_to` principal → store). The pass evaluates the curated read
   actions for the store's type (`iam.ResourceProbes`):
   - S3: `s3:GetObject` on `<bucket>/*`
   - DynamoDB: GetItem / Query / Scan / BatchGetItem
   - KMS: `kms:Decrypt`
   - Secrets Manager: GetSecretValue
   - RDS: `rds-db:connect`, plus `rds:ModifyDBInstance`, which implies a read through a master-password reset
   - SQS: ReceiveMessage
   - SNS: Subscribe
   - SSM: GetParameter

   Write, admin and metadata actions are evaluated too, but they appear only as `other_actions` on a
   read edge. v1 does not draw write-only or admin-only edges.

   The outcome of the read evaluation decides the edge:
   - **Allow**: the edge is kept with `PermissionAttr{actions, effect: Allow, resources, statement "<policy>#<sid|index>", policy_arn}`.
   - **Unknown**: the edge is kept as inferred, with `unknown_conditions` and `requires_conditions`.
   - **Explicit Deny** in any layer (identity, boundary, SCP, RCP, resource policy): the edge is
     removed. The principal gets `denied_edges[{to, kind, actions, denied_by "<layer> <policy>#<sid>", because}]`
     and `denied_by`.
   - **Implicit deny** from complete documents: the edge is removed (`denied_by: implicit_deny`).
   - **Implicit deny** from incomplete documents: the edge is kept as hint.

   Principals marked `iam_policies_complete` also get evaluator-generated read edges to every
   readable store in their account, and to stores in other accounts that carry a resource policy.
   A guardrail Deny on such a pair is still recorded in `denied_edges`.
2. **Declared edges with no policy documents** (a typed relationship from an inventory, such as lab
   P06 and P17). The pass evaluates them with a stand-in identity Allow, so only guardrails can
   decide: an SCP, boundary or resource-policy Deny removes the edge (F09). Otherwise the declared
   attributes are kept, along with `evaluated_by: iam_evaluator (guardrails only: no identity document)`.
3. **`can_assume`** (caller → role). The request is `sts:AssumeRole`, or AssumeRoleWithWebIdentity / AssumeRoleWithSAML
   for an OIDC / SAML provider caller. The role's trust policy is the resource policy.
   - For an IAM caller, the caller's identity, boundary and SCPs are evaluated too, so a cross-account
     caller needs both its own Allow and the trust Allow.
   - A caller whose policies were not collected (an external account root, an account node) keeps the
     edge as inferred with `caller_permission: unknown`.
   - Explicit Deny removes the edge and records the denial on the caller.
   - Callers that are services, SaaS identities or Kubernetes identities are not evaluated.
4. **Escalation**: `iam:PassRole` on a role that trusts `ec2.amazonaws.com` and has an instance
   profile, plus `ec2:RunInstances`, adds `can_assume` with `technique: iam:PassRole+ec2:RunInstances`
   (pathfinding.cloud). This applies only to principals with documents, and not to principals that
   are already admin. It is the first `can_escalate_to` technique. It is drawn as `can_assume`
   because traversal already prices that kind; a dedicated edge kind waits for P1-ENGINE.
5. **Admin neutralisation**: this applies to a principal shown as admin (an `OVERPRIVILEGED_IDENTITY`
   weakness or an AdministratorAccess attachment) that has a boundary or SCPs. If `iam.IsAdmin` gives
   none with the guardrails and not-none without them, the weakness moves to `neutralised_weaknesses`
   and admin attachments move to `attached_policies_denied`. The pass also sets
   `effective_admin: none` and `denied_by` (for example `scp p-lab0quarantine#0`).
   Graph traversal then stops treating the role as an admin target (S01). The finding itself is untouched.

### Edge confidence rule

| confidence | when |
|---|---|
| `verified` | Allow from complete documents that are all exact (collected, or the exact built-in AdministratorAccess), with no undecidable condition, a known resource-policy status and known SCPs (`scp_status` not `denied` / `error`). Also a declared typed relationship that no collected guardrail denies (typed inventory relationship, model/edge_attrs.go). |
| `inferred` | Allow resting on an approximated managed policy, a synthesised trust (`trust_principals`), the default KMS key policy, an incomplete principal, unknown SCPs, or a cross-account caller whose policies are unknown (`caller_permission: unknown`). Also any Unknown decision. |
| `hint` | The statement heuristic fallback for documents the evaluator cannot parse (AWS collector `derived_from: statement_heuristic`), a scanner hint edge, or a claimed grant that incomplete documents do not show. |

Deviation, noted for review: the shared contract defines `verified` as "probe / simulator
evidence or typed inventory edge". This track's brief asked for `verified` on a complete-context
Allow. A complete-context evaluator Allow is the policy-evaluation case the contract calls
`inferred`. Until recorded simulator fixtures (O1) back the evaluator, the main session should
decide whether these edges stay `verified`.

### `who-can`

`cloud-posture who-can <action> <resource-arn> [--json] [--depth 4]` (`graph.WhoCan`) works in two steps:
1. It evaluates the action for every AWS principal against its policies plus the target's resource policy.
   - For `sts:AssumeRole*` on a role, the trust policy is used, and the sources of `can_assume` edges count as direct holders.
   - A principal with no documents counts only through a declared read edge.
2. It walks `can_assume` edges backwards, depth ≤ 4. Each result carries the principal, the
   `via` chain, the granting statement, the decision and the weakest confidence along the chain.
3. **Anonymous principal first** (competitive delta r2 #5). When the resource is anonymously reachable
   (`graph.AnonymousReach`, shared with the path engine: a Principal `*` resource / bucket policy without an
   organisation condition, a public-read ACL or AllUsers grant, `bucket_policy_principal: *`, an auth-less
   function URL, allUsers / public blob access) and the action matches a Principal `*` statement (or, with no
   document, is a read action), `anonymous (internet)` is listed first with Decision `allow` and the because
   (`verified` from a policy document, `inferred` from an attribute). A Principal `*` policy limited by
   `aws:PrincipalOrgID` & co. lists `anyone in the organisation (org-wide)` (Decision `conditional`) instead. An S3
   public access block, or a REACH-blocked resource, gets neither.

### Simulator parity hook

`internal/iam/parity.go` defines `SimulatorFixture` in the `iam:SimulatePrincipalPolicy` field names,
together with `FixtureSource`, `DirFixtures` and `Replay`. Replay runs with `ContextComplete`, because
the simulator treats missing keys as absent. `TestSimulatorParity` replays
`testdata/simulator/*.json`: 17 fixtures, 34 results, 0 disagreements. Every fixture is
**authored from an AWS documentation example and marked `provenance: "authored, not recorded live"`**
until O1 supplies a lab account and the `NIMBUS_E2E=1` recorder (deferred) captures live results.

### Deferred

- SQS / SNS / DynamoDB inventory and resource policies: the SDK modules are not dependencies
  (no `go mod tidy` in parallel sessions) and the node types are not registered. The action sets
  exist.
- `s3:GetObjectVersion` is not probed.
- Cross-account RCPs of the resource's account.
- VPC endpoint policies and session policies from STS.
- A dedicated `can_escalate_to` edge kind and the other nine techniques.
- The live simulator recorder (O1).
- The generated read-only policy must be regenerated for the new calls (see the P1-IAM items 2–4
  session log).
