package pathdiff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const (
	fixtureRole = "arn:aws:iam::123456789012:role/fixture-host-role"
	trustedCIDR = "203.0.113.0/24" // the fixture's (and the lab's) trusted corporate range
)

func opts() Options {
	o := Options{Traversal: attackpath.DefaultTraversalOptions()}
	o.Traversal.TrustedCIDRs = []string{trustedCIDR}
	return o
}

func plan(t *testing.T, name string) *iac.Plan {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "action-fixture", "plans", name))
	if err != nil {
		t.Fatal(err)
	}
	p, err := iac.ParsePlanJSON(b, iac.PlanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func planSrc(t *testing.T, src string) *iac.Plan {
	t.Helper()
	p, err := iac.ParsePlanJSON([]byte(src), iac.PlanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlanOnlyFixtureOpensAndCloses(t *testing.T) {
	bad := Diff(nil, nil, plan(t, "bad.plan.json"), opts())
	if bad.Mode != ModePlanOnly || bad.Confidence != model.ConfidenceHint || !strings.Contains(bad.ConfidenceNote, "no live graph") {
		t.Errorf("mode %q confidence %q note %q", bad.Mode, bad.Confidence, bad.ConfidenceNote)
	}
	if len(bad.Opened) != 1 || len(bad.Closed) != 0 {
		t.Fatalf("bad: opened %d closed %d: %+v", len(bad.Opened), len(bad.Closed), bad)
	}
	p := bad.Opened[0]
	if p.Anchor != fixtureRole || p.Entry != model.PathEntryInternet || p.Score < 7 || p.ToxicCombination != "exposed+admin" {
		t.Errorf("opened path: %+v", p)
	}
	if p.IssueID != model.PathIssueID(model.IssuePath, p.Entry, p.Anchor, model.PathRuleTraversal) {
		t.Errorf("issue id is not the path Issue id: %s", p.IssueID)
	}
	if p.ChangedHop < 0 || !strings.Contains(p.Why, "0.0.0.0/0") || p.FixCanonical != "EC2_SG_OPEN_SSH" || p.FixTemplate == "" {
		t.Errorf("changed hop %d why %q fix %q/%q", p.ChangedHop, p.Why, p.FixCanonical, p.FixTemplate)
	}
	if p.Confidence != model.ConfidenceHint {
		t.Errorf("plan-only path confidence %q", p.Confidence)
	}
	rev := Diff(nil, nil, plan(t, "revert.plan.json"), opts())
	if len(rev.Opened) != 0 || len(rev.Closed) != 1 || rev.Closed[0].Anchor != fixtureRole {
		t.Fatalf("revert: %+v", rev)
	}
	if !strings.Contains(rev.Closed[0].Why, "0.0.0.0/0") {
		t.Errorf("closed why %q", rev.Closed[0].Why)
	}
	cr := Diff(nil, nil, plan(t, "create.plan.json"), opts())
	if len(cr.Opened) != 1 || cr.Opened[0].Anchor != "tf:module.web.aws_iam_role.host" {
		t.Errorf("create: %+v", cr.Opened)
	}
}

func TestNoOpPlanIsZeroZero(t *testing.T) {
	p := plan(t, "bad.plan.json")
	for i := range p.Changes {
		p.Changes[i].After, p.Changes[i].Action = p.Changes[i].Before, iac.PlanNoOp
	}
	r := Diff(nil, nil, p, opts())
	if len(r.Opened)+len(r.Closed)+len(r.ChangedScore) != 0 {
		t.Fatalf("no-op: %+v", r)
	}
}

func labLive(t *testing.T) *graph.Graph {
	t.Helper()
	fs, _, err := adapters.ParseFile(filepath.Join("..", "..", "lab", "local", "out", "estate.findings.json"), "native", adapters.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	g.AttachFindings(fs)
	return g
}

const labSG = "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0a1b2c3d4e5f60002"

func labSGPlan(fromCIDR, toCIDR string) string {
	rule := func(c string) string {
		return `{"ingress":[{"cidr_blocks":["` + c + `"],"from_port":22,"to_port":22,"protocol":"tcp","ipv6_cidr_blocks":[],"description":"ssh"}],"id":"sg-0a1b2c3d4e5f60002","arn":"` + labSG + `","name":"nimbus-lab-corp-ssh"}`
	}
	return `{"format_version":"1.2","resource_changes":[{"address":"aws_security_group.corp_ssh","mode":"managed","type":"aws_security_group","name":"corp_ssh",
	 "change":{"actions":["update"],"before":` + rule(fromCIDR) + `,"after":` + rule(toCIDR) + `}}]}`
}

// AP10 acceptance: widening the F01 SG from 203.0.113.0/24 to 0.0.0.0/0 opens 1 path anchored at
// the PowerUser role (exposed+admin), not the PII bucket; the inverse closes it; no-op is 0/0.
func TestLiveOverlayLabF01(t *testing.T) {
	live := labLive(t)
	base := attackpath.Traverse(live, opts().Traversal)
	widen := planSrc(t, labSGPlan(trustedCIDR, "0.0.0.0/0"))
	r := Diff(live, base, widen, opts())
	if r.Mode != ModeLive || r.Confidence != model.ConfidenceInferred {
		t.Errorf("mode %q confidence %q", r.Mode, r.Confidence)
	}
	if len(r.Opened) != 1 || len(r.Closed) != 0 {
		t.Fatalf("widen: opened %+v closed %+v", r.Opened, r.Closed)
	}
	if a := r.Opened[0].Anchor; a != "arn:aws:iam::111111111111:role/nimbus-lab-corp-tools-role" {
		t.Errorf("anchor %s, want the corp-tools role", a)
	}
	if r.Opened[0].ToxicCombination != "exposed+admin" || r.Opened[0].Score < 7 {
		t.Errorf("opened: %+v", r.Opened[0])
	}
	// The live graph is not modified by the overlay.
	if again := attackpath.Traverse(live, opts().Traversal); len(again.Paths) != len(base.Paths) {
		t.Fatalf("live graph mutated: %d → %d paths", len(base.Paths), len(again.Paths))
	}
	widened := Overlay(live, widen, opts())
	inv := Diff(widened, nil, planSrc(t, labSGPlan("0.0.0.0/0", trustedCIDR)), opts())
	if len(inv.Opened) != 0 || len(inv.Closed) != 1 {
		t.Fatalf("inverse: opened %+v closed %+v", inv.Opened, inv.Closed)
	}
	noop := Diff(live, base, planSrc(t, labSGPlan(trustedCIDR, trustedCIDR)), opts())
	if len(noop.Opened)+len(noop.Closed)+len(noop.ChangedScore) != 0 {
		t.Fatalf("no-op: %+v", noop)
	}
}

// Paths are keyed by (entry, anchor, rule) with the internet entry refined by the exposed node
// (attackpath.EntryKey). A plan that puts a NEW public host in front of an admin role that is
// already reachable through another host opens a path (verify-4 D5; before, entry was always
// "internet" and this was counted as rerouted); the existing host's path is not closed.
func TestNewPublicHostInFrontOfReachableAnchorOpens(t *testing.T) {
	live := graph.New()
	live.AddNode(&graph.Node{ID: "arn:aws:iam::1:role/admin", Type: "aws_iam_role", Name: "admin", Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}})
	live.AddNode(&graph.Node{ID: "arn:aws:ec2:us-east-1:1:instance/i-a", Type: "aws_instance", Name: "a", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "IMDSV1_ENABLED"}})
	live.AddEdge(graph.InternetNodeID, "arn:aws:ec2:us-east-1:1:instance/i-a", graph.EdgeExposes, map[string]any{"exposure_cidrs": []string{"0.0.0.0/0"}})
	live.AddEdge("arn:aws:ec2:us-east-1:1:instance/i-a", "arn:aws:iam::1:role/admin", graph.EdgeRunsAs, nil)
	src := `{"resource_changes":[
	 {"address":"aws_security_group.b","mode":"managed","type":"aws_security_group","name":"b","change":{"actions":["create"],"before":null,"after":{"name":"b","ingress":[{"cidr_blocks":["0.0.0.0/0"],"from_port":443,"to_port":443,"protocol":"tcp"}]}}},
	 {"address":"aws_instance.b","mode":"managed","type":"aws_instance","name":"b","change":{"actions":["create"],"before":null,
	   "after":{"public_ip":"198.51.100.9","iam_instance_profile":"p","metadata_options":[{"http_tokens":"optional"}],"vpc_security_group_ids":[]},"after_unknown":{"vpc_security_group_ids":true}}},
	 {"address":"aws_iam_instance_profile.p","mode":"managed","type":"aws_iam_instance_profile","name":"p","change":{"actions":["create"],"before":null,"after":{"name":"p","role":"arn:aws:iam::1:role/admin"}}}],
	 "configuration":{"root_module":{"resources":[{"address":"aws_instance.b","mode":"managed","expressions":{"vpc_security_group_ids":{"references":["aws_security_group.b.id","aws_security_group.b"]}}}]}}}`
	r := Diff(live, nil, planSrc(t, src), opts())
	if len(r.Opened) != 1 || len(r.Closed) != 0 {
		t.Fatalf("new public host: opened %d closed %d, want 1 / 0", len(r.Opened), len(r.Closed))
	}
	if o := r.Opened[0]; o.Entry != "internet" || o.EntryKey != "internet:tf:aws_instance.b" || o.AnchorName != "admin" {
		t.Errorf("opened %s → %s (key %s), want internet:tf:aws_instance.b → admin", o.Entry, o.AnchorName, o.EntryKey)
	}
}

// Middle-hop churn is still not new: the same public host reaching the same admin role through
// a different middle hop keeps its entry key and is counted as rerouted.
func TestMiddleHopChurnIsNotNew(t *testing.T) {
	const a, m, admin = "arn:aws:ec2:us-east-1:1:instance/i-a", "arn:aws:iam::1:role/mid", "arn:aws:iam::1:role/admin"
	live := graph.New()
	live.AddNode(&graph.Node{ID: admin, Type: "aws_iam_role", Name: "admin", Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}})
	live.AddNode(&graph.Node{ID: m, Type: "aws_iam_role", Name: "mid"})
	live.AddNode(&graph.Node{ID: a, Type: "aws_instance", Name: "a", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "IMDSV1_ENABLED"}})
	live.AddEdge(graph.InternetNodeID, a, graph.EdgeExposes, map[string]any{"exposure_cidrs": []string{"0.0.0.0/0"}})
	live.AddEdge(a, m, graph.EdgeRunsAs, nil)
	live.AddEdge(m, admin, graph.EdgeCanAssume, nil)
	before := Diff(live, nil, planSrc(t, `{"resource_changes":[]}`), opts())
	if len(before.Opened) != 0 {
		t.Fatalf("empty plan opened %+v", before.Opened)
	}
	// the reroute: a now runs as mid2, which can also assume admin
	g2 := rerouted(live, a, m, "arn:aws:iam::1:role/mid2")
	g2.AddNode(&graph.Node{ID: "arn:aws:iam::1:role/mid2", Type: "aws_iam_role", Name: "mid2"})
	g2.AddEdge("arn:aws:iam::1:role/mid2", admin, graph.EdgeCanAssume, nil)
	b, c := issues(attackpath.Traverse(live, opts().Traversal)), issues(attackpath.Traverse(g2, opts().Traversal))
	if len(b) == 0 || len(b) != len(c) {
		t.Fatalf("entries before %d after %d", len(b), len(c))
	}
	for k, x := range b {
		y, ok := c[k]
		if !ok {
			t.Fatalf("entry %s (%s) lost on a middle-hop reroute", k, x.entry)
		}
		if sameKeys(x.keys, y.keys) {
			t.Errorf("entry %s: hop lists unchanged, want a reroute", k)
		}
	}
}

// rerouted returns g with from's runs_as edge to oldMid moved to newMid.
func rerouted(g *graph.Graph, from, oldMid, newMid string) *graph.Graph {
	out := graph.New()
	for _, n := range g.Nodes() {
		out.AddNode(n)
	}
	for _, e := range g.Edges() {
		if e.From == from && e.To == oldMid {
			out.AddEdge(from, newMid, e.Kind, e.Attr)
			continue
		}
		out.AddEdge(e.From, e.To, e.Kind, e.Attr)
	}
	return out
}

func ciLive() *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "github.com/acme/infra", Type: "github_repository", Name: "acme/infra", Provider: "github", Weaknesses: []string{"BRANCH_UNPROTECTED"}})
	g.AddNode(&graph.Node{ID: "github.com/acme/web", Type: "github_repository", Name: "acme/web", Provider: "github"})
	return g
}

func ciPlan(sub string) string {
	return `{"resource_changes":[{"address":"aws_iam_role.gha","mode":"managed","type":"aws_iam_role","name":"gha","change":{"actions":["create"],"before":null,"after":{"name":"gha",
	 "assume_role_policy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Principal\":{\"Federated\":\"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com\"},\"Condition\":{\"StringLike\":{\"token.actions.githubusercontent.com:sub\":\"` + sub + `\"}}}]}",
	 "managed_policy_arns":["arn:aws:iam::aws:policy/AdministratorAccess"]},"after_unknown":{"arn":true}}}]}`
}

// CI-entry overlay rule: a planned OIDC trust whose subject matches an unprotected live
// repository derives repo → role can_assume, and the CI-entry floor tags the path.
func TestCIEntryOverlay(t *testing.T) {
	r := Diff(ciLive(), nil, planSrc(t, ciPlan("repo:acme/infra:*")), opts())
	if len(r.Opened) != 1 || r.Opened[0].Entry != "github.com/acme/infra" || r.Opened[0].ToxicCombination != attackpath.ToxicCIEntry || r.Opened[0].Score < 7 {
		t.Fatalf("unpinned: %+v", r.Opened)
	}
	pinned := Diff(ciLive(), nil, planSrc(t, ciPlan("repo:acme/infra:ref:refs/heads/main")), opts())
	for _, p := range pinned.Opened {
		if p.ToxicCombination == attackpath.ToxicCIEntry || p.Score >= 7 {
			t.Errorf("pinned subject floored: %+v", p)
		}
	}
	other := Diff(ciLive(), nil, planSrc(t, ciPlan("repo:acme/web:*")), opts())
	if len(other.Opened) != 0 {
		t.Errorf("protected repo opened a path: %+v", other.Opened)
	}
}
