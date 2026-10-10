# Effective internet reachability (P2-REACH v1)

nimbus decides whether a host on the internet can open a connection to a resource. It does not stop at
"a security group allows 0.0.0.0/0". The decision is a published, deterministic model, and every verdict
carries per-hop evidence.

* Bar: Microsoft Defender for Cloud internet-exposure analysis (wide/narrow width plus trusted IPs) and the AWS
  Security Hub reachability trait (an exposure counts only when routes, NACLs and security groups agree).
* Edge over the bar: the model, its corpus and its evidence format are public. Every verdict names the exact
  rule, route or flag that decides it, for example `NACL acl-… rule 90 denies 22/tcp from 0.0.0.0/0`.

Code: `internal/reach` (pure evaluator, stdlib + `internal/model` only), `internal/graph/reachability.go`
(graph adapter), `internal/collector/aws/network.go` and `elbv2.go` (collection). Corpus:
`internal/reach/testdata/*.yaml`, 70 cases. Each case cites the AWS (or Azure/GCP/Microsoft) documentation its
expectation follows. `go test ./internal/reach` runs the corpus and a determinism check.

## Model

`reach.Reachable(target, reach.Internet(trusted...), port) Result`

* `port.Number == 0` evaluates every candidate port and returns the best verdict. Candidates come from security
  group rules with a public source, NACL allow rules inside those ranges, listener target ports and the
  exposure's `ports`. The order of preference is reachable (widest first), then unknown, then blocked (with
  the blockers of every port).
* `Result{Reachable, Status reachable|blocked|unknown, Width wide|narrow|trusted|private, Port, Sources,
  Path []Hop, Blockers []Hop, Unknown []Hop, Confidence verified|inferred|hint}`
* `Hop{Kind, ID, Because}`. `Kind` is one of `public_ip`, `rds_public_flag`, `load_balancer`, `route`,
  `nacl_inbound`, `security_group`, `nacl_outbound`, `listener`, `target_group`, `managed_endpoint`,
  `eks_endpoint`, `subnet` or `model`.

Layers for VPC-attached targets, in network order. Each layer is a filter over the set of internet source
addresses (IPv4 and IPv6 interval sets; private, CGNAT, link-local and multicast ranges are never sources).

| Layer | Rule | AWS reference |
|---|---|---|
| Address | Instance/ENI: a public IPv4 or EIP is associated. RDS: `PubliclyAccessible`. LB: `scheme` is `internet-facing`. | vpc-ip-addressing, USER_VPC.WorkingWithRDSInstanceinaVPC |
| Route | Longest-prefix match of each source in the subnet's effective route table (explicit association, else the VPC main table). Only an active `igw-` route carries inbound traffic. `nat-` and `eigw-` are outbound only (blocker). A blackhole route, or no matching route, blocks. `tgw-`, `pcx-`, `vgw-`, `vpce-` and appliance ENIs are **unknown** (not modelled in v1). | VPC_Internet_Gateway, route-tables-priority, vpc-nat-gateway, egress-only-internet-gateway |
| NACL inbound | Rules are applied in rule-number order and the first match wins. The `*` rule (32767) denies whatever is left. Protocol matches by name or number (6 = tcp). | nacl-rules |
| Security group | Allow-only. The rules of every attached group are combined. Without collected rules, the exposure edge's `exposure_cidrs` are used and the verdict is marked `inferred`. | vpc-security-group-rules |
| NACL outbound | Stateless return path. Some outbound rule must allow the reply to an ephemeral client port in 1024–65535 for the surviving sources. Ports are sampled at every rule boundary. | custom-network-acl#nacl-ephemeral-ports |

Load balancers (ALB/NLB): internet → load balancer (the LB is evaluated as a target on the listener port) →
listener → target group → target.

* The target needs no public IP or IGW route of its own.
* The target's security group must admit the target port from the LB's security group or a VPC CIDR.
* For an NLB that preserves the client IP (the default for instance targets), the target's security group must
  admit the internet sources, and the width is computed from them.
* The target subnet's NACL is evaluated with the LB's private addresses as the source.
* An LB is reachable through any of its subnets.
* An RDS subnet group decides only when all of its subnets agree. A mixed group is unknown, because the
  instance's subnet decides.

Managed endpoints have no VPC network layer:

| Target | Verdict |
|---|---|
| Lambda function URL | Reachable on 443. The AuthType is recorded; the auth decision stays in attackpath. |
| API Gateway (EDGE/REGIONAL) | Reachable. |
| API Gateway PRIVATE | Blocked. |
| EKS endpoint | `endpoint_public_access` plus `public_access_cidrs`, which default to 0.0.0.0/0. |
| S3 and other AWS-managed public endpoints | Reachable. |

Three rules consumers rely on:

1. **A deny is decisive.** Layers only remove sources, so a blocker decides the verdict even when other layers
   are unknown. F03 is blocked by its NACL even though its subnet routes 0.0.0.0/0 to an internet gateway.
2. **Missing data is never reachable.** If there is no blocker and any layer is unknown, the status is
   `unknown` and `Unknown` gives the reason. Collection gaps are appended, for example
   `network collection incomplete: route_tables=access_denied`.
3. **Width is measured after every layer.**
   * `wide`: the surviving sources cover at least half of the IPv4 space, or an IPv6 /8 or larger.
   * `trusted`: every surviving source lies inside the trusted CIDRs.
   * `narrow`: neither of the above.
   * `private`: no public source at the security-group layer.

   A NACL that admits only a partner /24 therefore turns a 0.0.0.0/0 security group into `narrow`.

Confidence:

* `verified`: every deciding fact is a collected control.
* `inferred`: a summary or scanner fact decided it (`internet_gateway_route`, edge sources).
* `hint`: the status is unknown.

## Evidence format (graph attributes)

`graph.AnnotateReachability()` runs at the end of `graph.AttachFindings`. It therefore covers native
collectors, every ingest adapter and the multi-account merge, and it is idempotent. It writes these keys on
every internet edge (`exposes` / `allows_traffic_to` from `internet`) and on every exposed node, including
nodes reachable only through an exposed load balancer:

| Key | Type | Meaning |
|---|---|---|
| `reachability` | string | `reachable` \| `blocked` \| `unknown` |
| `reach_width` | string | `wide` \| `narrow` \| `trusted` \| `private` (trusted CIDRs are not applied here; attackpath applies them) |
| `reach_cidrs` | []string | sources that survive every layer |
| `reach_port` | string | `22/tcp` (`any/tcp` when no port could be named) |
| `reach_path` | []{kind,id,because} | hops that let traffic through |
| `reach_blocker` | string | joined `because` of the blockers (blocked only) |
| `reach_blocked_by` | []{kind,id,because} | the blocking controls (blocked only) |
| `reach_unknown` | string | why the verdict is unknown (unknown only) |
| `reach_confidence` | string | `verified` \| `inferred` \| `hint` |
| `reach_via` | string | nodes only: `direct`, or the ARN of the load balancer the verdict goes through |

* An **edge** carries the verdict of its own direct exposure.
* A **node** carries the best verdict over the direct path and every listener that forwards to it.
* A security group, NSG or firewall node (a scanner finding on the rule itself) takes the best verdict over the
  resources it admits traffic to.

Read the verdict with `g.ReachabilityOf(nodeID)` or `edge.Reachability()`. Both return
`graph.Reachability{Status, Width, Sources, Port, Path, Blocker, BlockedBy, Unknown, Confidence, Via}` and
parse both in-memory values and JSON-decoded ones.

The account node also carries `reach_coverage` (`{route_tables|network_acls|subnets|network_interfaces|
internet_gateways|nat_gateways|load_balancers: collected|access_denied|rate_limited|error|not_collected}`).

## Inputs

**AWS collector.** These calls are read-only and mapped in `docs/iam/api-permissions.json`:

* `ec2:DescribeRouteTables`, `DescribeNetworkAcls`, `DescribeSubnets`, `DescribeNetworkInterfaces`,
  `DescribeInternetGateways`, `DescribeNatGateways`
* `elasticloadbalancing:DescribeLoadBalancers`, `DescribeListeners`, `DescribeTargetGroups`,
  `DescribeTargetHealth` (hand-rolled SigV4 query client; the SDK module is not a dependency)

Each failed call is its own coverage row, for example `us-east-1:ec2:DescribeRouteTables`.

The collector adds no new node types. Facts are attributes:

* `aws_subnet`: `subnet_id`, `vpc_id`, `cidr`, `route_table{id,routes[{destination,target,state}]}`,
  `route_table_association`, `internet_gateway_route`, `network_acl_id`, `nat_gateways`.
* `aws_network_acl`: `network_acl_id`, `subnet_ids`, `ingress`/`egress` `[{rule_number,protocol,from_port,
  to_port,cidr,action}]`.
* `aws_security_group`: adds `ingress_rules[{protocol,from_port,to_port,cidrs,groups}]`.
* `aws_instance`: adds `public_ips` (an empty list means the collector found none).
* `aws_db_instance`: adds `subnet_ids` and `db_subnet_group`.
* `aws_lb`: `scheme`, `lb_type`, `subnet_ids`, `security_groups`, `listeners`.
* LB → target `allows_traffic_to` edges: `listener_arn`, `listener_port`, `listener_protocol`, `target_group`,
  `target_port`, `target_type`, `preserve_client_ip`, `listener_rule_unverified`.

**Native ingest (lab).** The same keys are honoured, plus summary forms:

* On the target: `subnet_id`, `network_acl` (bare id or ARN), `subnet_route_tables[{route_table,routes}]`,
  `internet_gateway_route`.
* On `aws_network_acl` inventory records: `subnet_ids` and `ingress` / `egress`.
* On `aws_security_group` records: `ingress[{protocol,from_port,to_port,cidr}]`.

Since wave 5 (competitive delta r3 #14) the lab estate carries the collector shape for every AWS instance and RDS
instance: `aws_subnet` records (`subnet_id`, `vpc_id`, `cidr`, `route_table {id, routes}`, `internet_gateway_route`,
`network_acl_id`), default and custom `aws_network_acl` records with `ingress` and `egress`, and `subnet_id` /
`subnet_ids` / `security_groups` on the targets. Every lab AWS instance and RDS instance gets a definite verdict
(`TestLabReachabilityCounts`): web-01, corp-tools-01, media-01, batch-01 and orders are `reachable`; sftp-01 and
the ledger are `blocked`.

Lab result: F03 is `blocked` (`NACL acl-0a1b2c3d4e5f60001 rule 90 denies 22/tcp from 0.0.0.0/0`, verified).
F04 is `blocked` (`route table rtb-0a1b2c3d4e5f60001 has no route to an internet gateway (routes: 10.20.0.0/16 →
local)`, verified). Both are suppressed in `make groundtruth`.

## Limits (v1)

* VPC peering, Transit Gateway, VPN/Direct Connect, PrivateLink, Gateway Load Balancer and appliance or
  firewall routes are not modelled. A route to them is `unknown`.
* Managed prefix lists (`pl-…`) are not expanded, so they never decide a verdict as `blocked`
  (verify-4 fixes, V4-ENGINE):
  * a security-group rule whose source is a prefix list (collector `prefix_lists`, Terraform
    `prefix_list_ids`) makes the sources it might admit **possible, not definite**: with no other internet
    source the verdict is `unknown` (hint), never `blocked`/`verified`. The same holds on the
    load balancer → target hop;
  * a route whose destination is a prefix list with an `igw-` target leaves every source no CIDR route
    carries to an IGW `unknown` (the "no route" blocker is withheld). Prefix-list routes to `vpce-`
    (gateway endpoints, AWS service ranges) and other targets do not open an inbound path.
* IPv6 is evaluated with the same interval arithmetic. A target with no public IPv4 is still reachable over
  IPv6 when it has an IPv6 address (`ipv6_addresses` / `ipv6_address`), its security groups admit an IPv6
  internet source and the route table sends `::/0` to an `igw-`. When the IPv6 addresses were not collected
  (attribute absent) and the SGs admit IPv6 sources, the verdict is `unknown`; collected-as-none is
  `blocked`. The native collector does not yet record `ipv6_addresses`.
* Port ranges are literal: `tcp` `0–0` is port 0 only. Only protocol `-1`, `from = -1` or `0–65535` covers
  every port.
* Blocker evidence names only layers that stop traffic on their own. When the security groups admit no
  internet source, an open route / NACL is judged against the whole public space and is not listed.
* Listener rules (`DescribeRules`) are not read. A target group reached only through rules is tied to every
  listener and its edge says `listener_rule_unverified: true`.
* Only the first listener per (LB, target) pair is kept, because edges are deduplicated.
* `ip` targets are not attached to nodes.
* Classic ELB is not collected.
* `preserve_client_ip` uses the AWS defaults (NLB with instance targets: true) rather than reading the target
  group attributes.
* The ALB → target hop accepts any VPC CIDR in the target security group as covering the LB.
* API Gateway resource-policy IP conditions apply only when an ingest supplies them as `exposure_cidrs`. API
  Gateway is not collected natively.
* **Azure / GCP / Kubernetes: NSG/firewall sources only.** Routes (UDRs, GCP routes, cloud LB paths) are not
  modelled, so a verdict that needs routes is `unknown`. A private-only source set or a missing external IP is
  still `blocked`.
* Resource types without a model (OpenSearch, Redshift, Bedrock agents, …) are `unknown`.

## How attackpath consumes it

The ENGINE track owns `internal/attackpath`.

* `reachability: blocked` on an internet edge (or on the exposed node) drops that edge from traversal. The
  resource moves to `Analysis.Exposures` with `Reachability: blocked` and `Reason = reach_blocker`, so the
  finding stands but no path starts there.
* `unknown` changes nothing in v1: the path is still reported. A later round may lower likelihood or flag the
  path "reachability unproven".
* `reachable` with `reach_width` narrower than the edge's `exposure` may replace the SG-only width.
  `trusted_cidrs` are applied by attackpath, as before.
* `reach_path` hops are the path's entry evidence for Issue pages and PR comments.

## One verdict everywhere (V4-ENGINE, competitive delta r2 #1)

`graph.Verdict(nodeID)` (`internal/graph/verdict.go`) folds the REACH attributes over every internet route into a
node (a direct internet edge, or an `allows_traffic_to` edge from an internet-exposed network control; each route's
own verdict, else the node's; collector-labelled `trusted` / `private` routes excluded): `reachable` if any route is,
`blocked` only if every route is (Reason = the first blocker), `unknown` if none is reachable and one is unknown or
unannotated next to a blocked one, `""` with no route and no verdict. `Label` is the one-line wording
(`not exposed (blocked: …)`, `exposure inferred (reachability unknown: …)`, `internet reachable (wide)`).

Wave 5 (competitive delta r3 #14, verification 5 C11):

* A route's verdict is the edge's, else the node's, else the **network control's** (the NSG / security group /
  firewall in front of it: its internet edge, then the control node itself). A VM exposed only through an NSG
  (lab `jump-01`) reads `unknown` with the NSG's reason, never `""`. A route with no verdict anywhere is `unknown`
  ("reachability not evaluated (no network verdict on this route)") whether or not the reachability pass ran:
  no exposure data is `unknown`; `""` means only "no internet route". `Width` is the route's `reach_width`, else
  its internet edge's exposure label. The risk `exposure` factor scores a resource reached only through such a
  control from this verdict (score 2.4.0; jump shape 3.6 → 5.0).
* The resource's own anonymous-access settings (`graph.AnonymousReachOf`: function URL auth type, S3 public access
  block, a resource policy only an in-organisation caller passes) suppress an internet `exposes` route even before
  exposure annotation labels the edge, so the raw ingest graph agrees with `paths --exposures`; a blocked route
  still reads `blocked`.
* When **every** internet route into the node (directly or through its control) is suppressed — exposure labelled
  `private` (auth-required function URL, org-conditioned bucket policy, private-only sources) or `trusted` — the
  status is `private` / `trusted` and the label `private (suppressed: <exposure_reason>)`. The node's own
  label-blind REACH verdict (e.g. an S3 service endpoint's `reachable (wide)`) no longer leaks through. `Blocked()`
  stays false for these: a suppressed exposure is not a network block.
* `Reason` is one short reason: node ids are replaced by node names, every clause appears once, at most two
  clauses (`+N more`). The full text stays in `reach_unknown` / `reach_blocker`.

Consumers: `paths --exposures` (attackpath, as above), the risk `exposure` factor (blocked ⇒ `exposure.none` with
`not exposed (blocked: <reason>)`; unknown ⇒ width kept, labelled inferred; docs/scoring.md changelog), and so the
Issue severity of single Issues (min of risk band and scanner severity). The copilot and MCP read the same helper
(PRODUCT track). `TestV4OneVerdictEverywhere` asserts graph.Verdict, `paths --exposures`, every finding's exposure
factor and single-Issue severity agree for every lab node.
