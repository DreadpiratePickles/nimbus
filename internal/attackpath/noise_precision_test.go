package attackpath

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// P1-ENGINE noise round (planning decisions 1–6). Fixtures are built from the hop lists of the
// independent noise estate (lab/local/noise/estate.yaml, docs/benchmark.md "Noise estate"):
// each one is the attribute set the estate gives that resource, trimmed to what the engine reads.

type nb struct{ g *graph.Graph }

func newNB() *nb { return &nb{graph.New()} }

func (b *nb) node(id, typ, name string, attrs map[string]any, weak ...string) *nb {
	n := &graph.Node{ID: id, Type: typ, Name: name, Attributes: attrs, Weaknesses: weak}
	if len(weak) > 0 {
		n.FindingIDs = []string{"f-" + name}
	}
	b.g.AddNode(n)
	return b
}

func (b *nb) sensitive(id string) *nb {
	n, _ := b.g.Node(id)
	n.Sensitive, n.Criticality = true, "production"
	return b
}

func (b *nb) edge(from, to, kind string, attr map[string]any) *nb {
	if attr == nil {
		attr = map[string]any{}
	}
	b.g.AddEdge(from, to, kind, attr)
	return b
}

func (b *nb) expose(to string, attr map[string]any) *nb {
	return b.edge(graph.InternetNodeID, to, graph.EdgeExposes, attr)
}

func pathsTo(an *Analysis, target string) []model.AttackPath {
	var out []model.AttackPath
	for _, p := range an.Paths {
		if len(p.Steps) > 0 && p.Steps[len(p.Steps)-1].Resource == target {
			out = append(out, p)
		}
	}
	return out
}

func hasExposure(an *Analysis, id string) *Exposure {
	for i := range an.Exposures {
		if an.Exposures[i].NodeID == id {
			return &an.Exposures[i]
		}
	}
	return nil
}

func suppressedOf(an *Analysis, id string) *Suppressed {
	for i := range an.Suppressed {
		if an.Suppressed[i].NodeID == id {
			return &an.Suppressed[i]
		}
	}
	return nil
}

// TP3 chain (noise NZT1): unauthenticated function URL → execution role → PII DynamoDB table.
const (
	tp3Fn    = "arn:aws:lambda:us-east-1:310000000001:function:partner-webhook-debug"
	tp3Role  = "arn:aws:iam::310000000001:role/partner-webhook-debug-role"
	tp3Table = "arn:aws:dynamodb:us-east-1:310000000001:table/halyard-customer-contacts"
)

func addTP3(b *nb) *nb {
	return b.node(tp3Fn, "aws_lambda_function", "partner-webhook-debug", map[string]any{"function_url_auth_type": "NONE", "exposure_cidrs": []any{"0.0.0.0/0"}}, "PUBLIC_NETWORK_EXPOSURE").
		node(tp3Role, "aws_iam_role", "partner-webhook-debug-role", map[string]any{"trust_principals": []any{"lambda.amazonaws.com"}}).
		node(tp3Table, "aws_dynamodb_table", "halyard-customer-contacts", map[string]any{"tags": map[string]any{"data_classification": "pii", "environment": "production"}}).
		sensitive(tp3Table).
		expose(tp3Fn, map[string]any{"exposure": "wide", "exposure_cidrs": []any{"0.0.0.0/0"}}).
		edge(tp3Fn, tp3Role, graph.EdgeRunsAs, nil).
		edge(tp3Role, tp3Table, graph.EdgeGrantsAccessTo, map[string]any{"via": "inline policy ContactsRead"})
}

// Decision 6 (missed TP3). Root cause: the internet node has more exploitable out-edges (45 in
// the noise estate) than MaxBranching (25), so whichever exposures came after the 25th edge in
// store order were never expanded. The DynamoDB table is a sensitive crown-jewel target already.
func TestTP3NotLostToInternetFanOut(t *testing.T) {
	b := newNB()
	for i := 0; i < 40; i++ { // exposures ordered before the TP3 function (decoys sort first)
		id := fmt.Sprintf("arn:aws:ec2:us-east-1:310000000001:instance/i-0000decoy%02d", i)
		b.node(id, "aws_instance", fmt.Sprintf("decoy-%02d", i), nil, "PUBLIC_NETWORK_EXPOSURE").expose(id, map[string]any{"exposure": "wide"})
	}
	addTP3(b)
	an := Traverse(b.g, DefaultTraversalOptions())
	ps := pathsTo(an, tp3Table)
	if len(ps) == 0 {
		t.Fatalf("TP3 (function URL → role → PII table) not reported behind %d other internet exposures", 40)
	}
	if ps[0].Score < 7 {
		t.Errorf("TP3 score %.2f, want >= 7 (exposed+sensitive)", ps[0].Score)
	}
	if got := ToxicCombination(ps[0]); got != ToxicSensitive {
		t.Errorf("TP3 toxic_combination %q, want %q", got, ToxicSensitive)
	}
}

// Decision 1: an attack path must reach an impact target. Exposed resources that are not one
// are exposures (Analysis.Exposures), never paths.
func TestExposureOnlyChainsAreNotPaths(t *testing.T) {
	const (
		www     = "arn:aws:s3:::halyard-www-static"
		redact  = "arn:aws:s3:::public-pii-redacted-reports"
		fixture = "arn:aws:s3:::halyard-sandbox-public-fixtures"
		gce     = "//compute.googleapis.com/projects/halyard-prod-gcp/zones/us-central1-a/instances/api-1"
		eks     = "arn:aws:eks:us-east-1:310000000004:cluster/halyard-eks-dev"
		sg      = "arn:aws:ec2:us-east-1:310000000001:security-group/sg-03c45372568aef802"
		lb      = "arn:aws:elasticloadbalancing:us-east-1:310000000001:loadbalancer/app/customer-portal-lb/abfc0863b14abbb3"
		ecs     = "arn:aws:ecs:us-east-1:310000000001:service/halyard-prod/customer-portal"
		pii     = "arn:aws:s3:::halyard-customer-pii-export"
	)
	b := newNB().
		// NZ01: public website bucket tagged data_classification=public.
		node(www, "aws_s3_bucket", "halyard-www-static", map[string]any{"bucket_policy_principal": "*", "public_access_block": false, "website_hosting": true,
			"tags": map[string]any{"data_classification": "public", "environment": "production"}}, "PUBLIC_DATA_STORE").
		expose(www, map[string]any{"exposure": "wide", "exposure_cidrs": []any{"0.0.0.0/0"}}).
		// NZ90 near miss: "pii" in the name, but classified public (name heuristics made it sensitive).
		node(redact, "aws_s3_bucket", "public-pii-redacted-reports", map[string]any{"bucket_policy_principal": "*", "public_access_block": false,
			"tags": map[string]any{"data_classification": "public", "environment": "production"}}, "PUBLIC_DATA_STORE").
		sensitive(redact).expose(redact, nil).
		// NZ15: sandbox fixtures classified none ("sandbox" contains "db" for the name heuristic).
		node(fixture, "aws_s3_bucket", "halyard-sandbox-public-fixtures", map[string]any{"bucket_policy_principal": "*", "public_access_block": false,
			"tags": map[string]any{"data_classification": "none", "environment": "sandbox"}}, "PUBLIC_DATA_STORE").
		sensitive(fixture).expose(fixture, nil).
		// NZ10: GCE instance with an external IP, 443 only, in a project whose id contains "prod".
		node(gce, "gcp_compute_instance", "api-1", map[string]any{"exposure_ports": []any{443}, "external_ip": "34.120.5.16"}, "PUBLIC_NETWORK_EXPOSURE").
		expose(gce, nil).
		// NZ15: dev EKS endpoint restricted to one public CIDR.
		node(eks, "aws_eks_cluster", "halyard-eks-dev", map[string]any{"public_access_cidrs": []any{"203.0.113.0/24"}}, "PUBLIC_NETWORK_EXPOSURE", "K8S_API").
		expose(eks, map[string]any{"exposure": "narrow", "exposure_cidrs": []any{"203.0.113.0/24"}}).
		// NZ90: SG 443 → ALB → private Fargate service named customer-portal (no jewel attributes).
		node(sg, "aws_security_group", "customer-portal-lb-sg", nil, "PUBLIC_NETWORK_EXPOSURE").
		node(lb, "aws_lb", "customer-portal-lb", map[string]any{"scheme": "internet-facing"}).
		node(ecs, "aws_ecs_service", "customer-portal", map[string]any{"assign_public_ip": false, "launch_type": "FARGATE"}).
		expose(sg, map[string]any{"exposure": "wide", "exposure_cidrs": []any{"0.0.0.0/0"}}).
		edge(sg, lb, graph.EdgeAllowsTrafficTo, map[string]any{"via": "tcp/443"}).
		edge(lb, ecs, graph.EdgeAllowsTrafficTo, map[string]any{"via": "443 -> 8443"}).
		// Control: a public bucket classified pii is still a path.
		node(pii, "aws_s3_bucket", "halyard-customer-pii-export", map[string]any{"bucket_policy_principal": "*", "public_access_block": false,
			"tags": map[string]any{"data_classification": "pii", "environment": "production"}}, "PUBLIC_DATA_STORE").
		sensitive(pii).expose(pii, nil)
	an := Traverse(b.g, DefaultTraversalOptions())
	for _, id := range []string{www, redact, fixture, gce, eks, ecs} {
		if ps := pathsTo(an, id); len(ps) > 0 {
			t.Errorf("%s: reported as a path (%.2f %s); it is an exposure, not an impact target", id, ps[0].Score, chainOf(ps[0]))
		}
		if e := hasExposure(an, id); e == nil {
			t.Errorf("%s: missing from Analysis.Exposures", id)
		} else if e.Width == "" || e.Because == "" || len(e.FindingIDs) == 0 {
			t.Errorf("%s: exposure lacks width/because/finding ids: %+v", id, *e)
		}
	}
	if e := hasExposure(an, ecs); e != nil && !contains(strings.Join(e.FindingIDs, ","), "f-customer-portal-lb-sg") {
		t.Errorf("customer-portal exposure must cite the SG finding that opens it: %+v", *e)
	}
	if e := hasExposure(an, eks); e != nil && e.Width != "narrow" {
		t.Errorf("eks exposure width %q, want narrow", e.Width)
	}
	if ps := pathsTo(an, pii); len(ps) == 0 || ps[0].Score < 7 {
		t.Fatalf("public pii bucket must stay a >= 7 path: %+v", ps)
	}
	for _, p := range an.Paths {
		if hasExposure(an, p.Steps[len(p.Steps)-1].Resource) != nil {
			t.Errorf("path target %s is also listed as an exposure", p.Steps[len(p.Steps)-1].Resource)
		}
	}
	// Priority comes from typed facts, not names: the ECS service named customer-portal in
	// cluster halyard-prod and the GCE instance in halyard-prod-gcp are not targets.
	for _, id := range []string{ecs, gce} {
		n, _ := b.g.Node(id)
		if c := Criticality(n, nil); c != 0 {
			t.Errorf("Criticality(%s) = %d, want 0 (no jewel / admin / sensitive attributes)", n.Name, c)
		}
	}
}

// Decision 2: exposure needs anonymous reachability. AWS_IAM function URLs, org-conditioned
// Principal * policies and storage with anonymous access disabled are private (Suppressed),
// with the reason; with no attribute to decide, the finding's label stands with confidence hint.
func TestExposureRequiresAnonymousReach(t *testing.T) {
	const (
		invoice  = "arn:aws:lambda:us-east-1:310000000001:function:invoice-pdf"
		invRole  = "arn:aws:iam::310000000001:role/invoice-pdf-fn-role"
		billing  = "arn:aws:s3:::halyard-billing-exports"
		tenant   = "arn:aws:lambda:us-east-1:310000000001:function:tenant-provisioner"
		tenRole  = "arn:aws:iam::310000000001:role/tenant-provisioner-fn-role"
		orgS3    = "arn:aws:s3:::halyard-partner-drop"
		azBackup = "/subscriptions/7a1e0000-0000-4000-8000-000000000010/resourceGroups/halyard-data-rg/providers/Microsoft.Storage/storageAccounts/halyardbackups"
		bare     = "arn:aws:lambda:us-east-1:310000000001:function:legacy-export"
		bareRole = "arn:aws:iam::310000000001:role/legacy-export-role"
	)
	orgPolicy := map[string]any{"Action": "lambda:InvokeFunctionUrl", "Principal": "*",
		"Condition": map[string]any{"StringEquals": map[string]any{"aws:PrincipalOrgID": "o-halyard01", "lambda:FunctionUrlAuthType": "AWS_IAM"}}}
	b := newNB().
		node(invoice, "aws_lambda_function", "invoice-pdf", map[string]any{"function_url_auth_type": "AWS_IAM", "resource_policy": orgPolicy}, "PUBLIC_NETWORK_EXPOSURE").
		node(invRole, "aws_iam_role", "invoice-pdf-fn-role", nil).
		node(billing, "aws_s3_bucket", "halyard-billing-exports", map[string]any{"public_access_block": true}).sensitive(billing).
		expose(invoice, nil).edge(invoice, invRole, graph.EdgeRunsAs, nil).edge(invRole, billing, graph.EdgeGrantsAccessTo, nil).
		// Org-conditioned Principal * policy, no auth type recorded.
		node(tenant, "aws_lambda_function", "tenant-provisioner", map[string]any{"resource_policy": map[string]any{"Principal": "*",
			"Condition": map[string]any{"StringEquals": map[string]any{"aws:PrincipalOrgID": "o-halyard01"}}}}, "PUBLIC_NETWORK_EXPOSURE").
		node(tenRole, "aws_iam_role", "tenant-provisioner-fn-role", nil).
		expose(tenant, nil).edge(tenant, tenRole, graph.EdgeRunsAs, nil).edge(tenRole, billing, graph.EdgeGrantsAccessTo, nil).
		// S3 Principal * conditioned on aws:SourceVpce (JSON policy string).
		node(orgS3, "aws_s3_bucket", "halyard-partner-drop", map[string]any{"bucket_policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1a2b"}}}]}`,
			"tags": map[string]any{"data_classification": "confidential"}}, "PUBLIC_DATA_STORE").
		sensitive(orgS3).expose(orgS3, nil).
		// Azure storage: a TLS finding the catalog used to alias to PUBLIC_DATA_STORE.
		node(azBackup, "azure_storage_account", "halyardbackups", map[string]any{"allow_blob_public_access": false, "public_network_access": "Disabled"}, "PUBLIC_DATA_STORE").
		sensitive(azBackup).expose(azBackup, nil).
		// No auth attribute at all: the finding's label stands, marked hint.
		node(bare, "aws_lambda_function", "legacy-export", nil, "PUBLIC_NETWORK_EXPOSURE").
		node(bareRole, "aws_iam_role", "legacy-export-role", nil).
		expose(bare, nil).edge(bare, bareRole, graph.EdgeRunsAs, nil).edge(bareRole, billing, graph.EdgeGrantsAccessTo, nil)
	an := Traverse(b.g, DefaultTraversalOptions())
	for id, reason := range map[string]string{invoice: "auth required", tenant: "org-conditioned", orgS3: "org-conditioned", azBackup: "anonymous access disabled"} {
		for _, p := range an.Paths {
			if touches(p, id) {
				t.Errorf("%s: path %s (%.2f) through a non-anonymous exposure", id, chainOf(p), p.Score)
			}
		}
		s := suppressedOf(an, id)
		if s == nil {
			t.Errorf("%s: not listed in Suppressed", id)
			continue
		}
		if s.Exposure != exposurePrivate || !strings.Contains(s.Reason, reason) {
			t.Errorf("%s: suppressed %q / %q, want private / %q", id, s.Exposure, s.Reason, reason)
		}
	}
	var bareP *model.AttackPath
	for i, p := range an.Paths {
		if touches(p, bare) {
			bareP = &an.Paths[i]
		}
	}
	if bareP == nil {
		t.Fatal("a function URL with no auth attribute keeps the finding's exposure label (path expected)")
	}
	if c, _ := bareP.Steps[0].Evidence["confidence"].(string); c != "hint" {
		t.Errorf("entry step confidence %q, want hint; evidence %v", c, bareP.Steps[0].Evidence)
	}
	// The rule engine applies the same check to the finding's own attributes.
	fs := []model.Finding{{ID: "N036", Status: model.Fail, Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"},
		Resource: model.Resource{ID: invoice, Type: "aws_lambda_function", Attributes: map[string]any{"function_url_auth_type": "AWS_IAM"}}}}
	if out := withoutTrustedExposure(fs, nil); out[0].HasWeakness("PUBLIC_NETWORK_EXPOSURE") {
		t.Error("rule engine: an AWS_IAM function URL must not count as PUBLIC_NETWORK_EXPOSURE")
	}
}

// Decision 3: an internet-facing load balancer that authenticates (OIDC / Cognito / IAM
// authorizer / WAF) in front of the workload lowers that hop ×0.3, shows `auth-lb ×0.3` in
// because, and the entry is no longer anonymous wide exposure (no toxic floor).
func TestAuthenticatedLBCompensatingControl(t *testing.T) {
	const (
		lb   = "arn:aws:elasticloadbalancing:us-east-1:310000000001:loadbalancer/app/admin-portal-lb/1"
		app  = "arn:aws:ec2:us-east-1:310000000001:instance/i-0app"
		role = "arn:aws:iam::310000000001:role/admin-portal-role"
	)
	build := func(lbAttrs map[string]any) *graph.Graph {
		return newNB().
			node(lb, "aws_lb", "admin-portal-lb", lbAttrs, "PUBLIC_NETWORK_EXPOSURE").
			node(app, "aws_instance", "admin-portal-app", map[string]any{"kev": true}, "UNPATCHED"). // KEV: CVE gate 0.9 (round 2)
			node(role, "aws_iam_role", "admin-portal-role", map[string]any{"attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}, "OVERPRIVILEGED_IDENTITY").
			expose(lb, map[string]any{"exposure": "wide", "exposure_cidrs": []any{"0.0.0.0/0"}}).
			edge(lb, app, graph.EdgeAllowsTrafficTo, map[string]any{"via": "443 -> 8080"}).
			edge(app, role, graph.EdgeRunsAs, nil).g
	}
	plain := pathsTo(Traverse(build(map[string]any{"scheme": "internet-facing"}), DefaultTraversalOptions()), role)
	authed := pathsTo(Traverse(build(map[string]any{"scheme": "internet-facing", "authentication": "OIDC (customer IdP)"}), DefaultTraversalOptions()), role)
	if len(plain) == 0 || len(authed) == 0 {
		t.Fatalf("both variants must report the path: plain %d authed %d", len(plain), len(authed))
	}
	if plain[0].Score < 7 {
		t.Errorf("unauthenticated LB control: %.2f, want >= 7", plain[0].Score)
	}
	if authed[0].Score >= plain[0].Score*0.5 || authed[0].Score >= 5 {
		t.Errorf("auth-lb: %.2f vs %.2f unauthenticated, want the hop ×0.3 and no toxic floor", authed[0].Score, plain[0].Score)
	}
	if ToxicCombination(authed[0]) != "" {
		t.Errorf("authenticated entry must not be a toxic combination")
	}
	var chip bool
	for _, s := range authed[0].Steps {
		if strings.Contains(s.Because, "auth-lb ×0.3") {
			chip = true
		}
	}
	if !chip {
		t.Errorf("no `auth-lb ×0.3` chip in because: %s", chainOf(authed[0]))
	}
	waf := pathsTo(Traverse(build(map[string]any{"waf_web_acl": "halyard-regional-waf"}), DefaultTraversalOptions()), role)
	if len(waf) == 0 || waf[0].Score >= plain[0].Score*0.5 {
		t.Errorf("WAF on the LB is a compensating control too: %+v", waf)
	}
}

// Decision 4: an identity entry needs a usable credential. A user with no console access, no
// active keys and no policies yields no path even with NO_MFA; without those attributes the path
// keeps confidence hint and scores ×0.5; a stale (existing) access key is a usable credential.
func TestUnusableIdentityIsNotAnEntry(t *testing.T) {
	admin := map[string]any{"attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range admin {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	const (
		dead    = "arn:aws:iam::310000000001:user/svc-prod-admin-legacy"
		unknown = "arn:aws:iam::310000000001:user/ops-unknown"
		stale   = "arn:aws:iam::310000000001:user/ops-jane"
		live    = "arn:aws:iam::310000000001:user/ops-live"
	)
	g := newNB().
		node(dead, "aws_iam_user", "svc-prod-admin-legacy", map[string]any{"console_access": false, "access_key_1_active": false, "access_key_2_active": false,
			"attached_policies": []any{}, "groups": []any{}, "mfa_active": false}, "NO_MFA").
		node(unknown, "aws_iam_user", "ops-unknown", with(nil), "NO_MFA", "OVERPRIVILEGED_IDENTITY").
		node(stale, "aws_iam_user", "ops-jane", with(map[string]any{"access_key_1_age_days": 400}), "NO_MFA", "STALE_CREDENTIALS", "OVERPRIVILEGED_IDENTITY").
		node(live, "aws_iam_user", "ops-live", with(map[string]any{"console_access": true}), "NO_MFA", "OVERPRIVILEGED_IDENTITY").g
	// The orphaned user stays unusable even when a scanner calls it admin.
	d, _ := g.Node(dead)
	d.Weaknesses = append(d.Weaknesses, "OVERPRIVILEGED_IDENTITY")
	an := Traverse(g, DefaultTraversalOptions())
	if ps := pathsTo(an, dead); len(ps) > 0 {
		t.Errorf("user with no console, no active keys and no policies: path %.2f reported", ps[0].Score)
	}
	for _, e := range an.EntryPoints {
		if e == dead {
			t.Error("unusable user listed as an entry point")
		}
	}
	u := pathsTo(an, unknown)
	if len(u) != 1 || u[0].Score != 2.5 {
		t.Fatalf("unknown credential state: %+v, want one path at 0.5 x 0.5 x 10 = 2.5", u)
	}
	if c, _ := u[0].Steps[0].Evidence["confidence"].(string); c != "hint" {
		t.Errorf("unknown credential state: confidence %q, want hint", c)
	}
	if s := pathsTo(an, stale); len(s) != 1 || s[0].Score != 7 {
		t.Errorf("stale access key is a usable credential: %+v, want 7.0 (P05 shape)", s)
	}
	if l := pathsTo(an, live); len(l) != 1 || l[0].Score != 5 {
		t.Errorf("console user without MFA: %+v, want 5.0", l)
	}
	// Fix re-evaluation sees the same entry rule.
	if !newFixView(g, nil).survives(u[0], DefaultTraversalOptions()) {
		t.Error("fix view must re-evaluate the hinted entry the same way")
	}
}
