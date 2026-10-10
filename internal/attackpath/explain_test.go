package attackpath

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// fixtureGraph builds the findings-only graph from every scanner fixture in testdata/.
func fixtureGraph(t *testing.T) (*graph.Graph, []model.Finding) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "*"))
	var all []model.Finding
	for _, p := range files {
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			continue
		}
		fs, _, err := adapters.ParseFile(p, "", adapters.Options{})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		all = append(all, fs...)
	}
	if len(all) == 0 {
		t.Fatal("no fixture findings")
	}
	g := graph.New()
	g.AttachFindings(all)
	return g, all
}

func allGraphs(t *testing.T) map[string]*graph.Graph {
	fg, _ := fixtureGraph(t)
	return map[string]*graph.Graph{"demo": demoGraph(), "k8s": k8sSAGraph(), "gcp": gcpSAGraph(), "fixtures": fg}
}

// Defect 18(a): IMDSv1 is credited to the instance that carries it, never to the role.
func TestIMDSv1CreditedToInstance(t *testing.T) {
	an := Traverse(demoGraph(), DefaultTraversalOptions())
	for _, fx := range append(append([]Fix{}, an.BreakFixes...), an.ReduceFixes...) {
		if fx.Weakness == "IMDSV1_ENABLED" && fx.NodeID != "i-1" {
			t.Errorf("IMDSv1 credited to %s", fx.NodeID)
		}
	}
	var imds *Fix
	for _, list := range [][]Fix{an.BreakFixes, an.ReduceFixes} {
		for i := range list {
			if list[i].NodeID == "i-1" && list[i].Weakness == "IMDSV1_ENABLED" {
				imds = &list[i]
			}
		}
	}
	if imds == nil || len(imds.Enables) == 0 {
		t.Fatalf("IMDSv1 fix on i-1 should list the paths it enables: %+v", imds)
	}
	for _, p := range an.Paths {
		for _, s := range p.Steps {
			if s.Weakness == "IMDSV1_ENABLED" && s.WeaknessOn != "i-1" {
				t.Errorf("step %s: weakness_on=%q, want i-1", s.Resource, s.WeaknessOn)
			}
		}
	}
}

// Defect 18(d): the exact solver finds the optimum where greedy set cover does not.
func TestExactCoverBeatsGreedy(t *testing.T) {
	// Universe 0..5. Greedy takes the big set A first and then needs B and C (3 sets);
	// the optimum is {B, C}.
	sets := [][]int{{0, 1, 2, 3}, {0, 2, 4}, {1, 3, 5}}
	weights := []float64{1, 1, 1, 1, 1, 1}
	greedy := greedyCover(sets, weights)
	exact, ok := exactCover(sets, 6, 1_000_000)
	if !ok {
		t.Fatal("exact cover gave up on 3 candidates")
	}
	if len(greedy) != 3 || len(exact) != 2 {
		t.Fatalf("greedy=%v exact=%v", greedy, exact)
	}
}

// Defect 18(d): on a small graph MinFixSet is exact, minimal (checked by brute force with
// Simulate) and verified by re-traversal.
func TestMinFixSetIsExactAndVerified(t *testing.T) {
	for name, g := range map[string]*graph.Graph{"demo": demoGraph(), "k8s": k8sSAGraph(), "gcp": gcpSAGraph()} {
		an := Traverse(g, DefaultTraversalOptions())
		if !an.MinFixExact {
			t.Errorf("%s: min fix set not labelled exact", name)
		}
		if !an.MinFixVerified {
			t.Errorf("%s: min fix set claim not verified by re-traversal", name)
		}
		// Brute force: smallest subset of break fixes that removes every coverable path.
		coverable := map[string]bool{}
		for _, fx := range an.BreakFixes {
			for _, id := range fx.Breaks {
				coverable[id] = true
			}
		}
		best := len(an.BreakFixes) + 1
		n := len(an.BreakFixes)
		if n > 12 {
			t.Fatalf("%s: too many candidates for brute force: %d", name, n)
		}
		for mask := 0; mask < 1<<n; mask++ {
			var set []Fix
			for i := 0; i < n; i++ {
				if mask&(1<<i) != 0 {
					set = append(set, an.BreakFixes[i])
				}
			}
			if len(set) >= best {
				continue
			}
			after := Traverse(ApplyFixes(g, set), DefaultTraversalOptions())
			left := false
			for _, p := range after.Paths {
				left = left || coverable[p.ID]
			}
			if !left {
				best = len(set)
			}
		}
		if len(an.MinFixSet) != best {
			t.Errorf("%s: MinFixSet has %d fixes, brute-force minimum is %d: %+v", name, len(an.MinFixSet), best, an.MinFixSet)
		}
	}
}

// O4: every step on every path carries a non-empty `because`, and every graph edge has one.
func TestEveryStepHasBecause(t *testing.T) {
	total := 0
	for name, g := range allGraphs(t) {
		for _, e := range g.Edges() {
			if b, _ := e.Attr["because"].(string); b == "" {
				t.Errorf("%s: edge %s -%s-> %s has no because", name, e.From, e.Kind, e.To)
			}
		}
		an := Traverse(g, DefaultTraversalOptions())
		for _, p := range append(append([]model.AttackPath{}, an.Paths...), an.Incomplete...) {
			for _, s := range p.Steps {
				total++
				if s.Because == "" || len(s.Evidence) == 0 {
					t.Errorf("%s: path %s step %d (%s) because=%q evidence=%v", name, p.Name, s.Stage, s.Resource, s.Because, s.Evidence)
				}
			}
		}
	}
	if total == 0 {
		t.Fatal("no steps checked")
	}
	// Rule-engine paths too.
	_, fs := fixtureGraph(t)
	rules, _ := LoadRules(nil)
	for _, p := range Evaluate(fs, rules) {
		for _, s := range p.Steps {
			if s.Because == "" {
				t.Errorf("rule path %s step %d has no because", p.RuleID, s.Stage)
			}
		}
	}
}

// O4: the because string carries the collector's evidence (rule, ports, binding, role).
func TestBecauseCarriesEvidence(t *testing.T) {
	an := Traverse(gcpSAGraph(), DefaultTraversalOptions())
	want := map[string]bool{"default-allow-ssh": false, "roles/editor": false}
	for _, p := range an.Paths {
		for _, s := range p.Steps {
			for k := range want {
				if contains(s.Because, k) {
					want[k] = true
				}
			}
		}
	}
	an = Traverse(k8sSAGraph(), DefaultTraversalOptions())
	want["api-admin"] = false
	for _, p := range an.Paths {
		for _, s := range p.Steps {
			if contains(s.Because, "api-admin") {
				want["api-admin"] = true
			}
		}
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("no step because mentions %q", k)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// O11: every finding-bearing node is classified; dead ends are the ones on no complete path.
func TestDeadEnds(t *testing.T) {
	g := demoGraph()
	// A finding-bearing node that leads nowhere.
	g.AddNode(&graph.Node{ID: "lonely", Type: "aws_instance", Name: "lonely", Provider: "aws", Account: "1", Weaknesses: []string{"NO_LOGGING"}, FindingIDs: []string{"f-lonely"}})
	an := Traverse(g, DefaultTraversalOptions())
	onPath := map[string]bool{}
	for _, p := range an.Paths {
		for _, s := range p.Steps {
			onPath[s.Resource] = true
		}
	}
	var wantDead []string
	for _, n := range g.Nodes() {
		if len(n.FindingIDs) == 0 {
			continue
		}
		v, ok := an.ReachesCrownJewel[n.ID]
		if !ok {
			t.Errorf("finding-bearing node %s not classified", n.ID)
		}
		if v != onPath[n.ID] {
			t.Errorf("%s reaches_crown_jewel=%v, on complete path=%v", n.ID, v, onPath[n.ID])
		}
		if !onPath[n.ID] {
			wantDead = append(wantDead, n.ID)
		}
	}
	sort.Strings(wantDead)
	if an.DeadEnds.Count != len(wantDead) || len(an.DeadEnds.IDs) != len(wantDead) {
		t.Fatalf("dead ends %+v, want %v", an.DeadEnds, wantDead)
	}
	for i := range wantDead {
		if an.DeadEnds.IDs[i] != wantDead[i] {
			t.Errorf("dead ends %v, want %v", an.DeadEnds.IDs, wantDead)
		}
	}
	findings := []model.Finding{{ID: "f-lonely", Resource: model.Resource{ID: "lonely"}}, {ID: "f-bpub", Resource: model.Resource{ID: "bucket"}}}
	if r := an.FilterFindings(findings, true); len(r) != 1 || r[0].ID != "f-bpub" {
		t.Errorf("reaching filter: %+v", r)
	}
	if d := an.FilterFindings(findings, false); len(d) != 1 || d[0].ID != "f-lonely" {
		t.Errorf("dead-end filter: %+v", d)
	}
	// Fixture graph: every finding-bearing node is classified.
	fg, _ := fixtureGraph(t)
	fan := Traverse(fg, DefaultTraversalOptions())
	for _, n := range fg.Nodes() {
		if _, ok := fan.ReachesCrownJewel[n.ID]; len(n.FindingIDs) > 0 && !ok {
			t.Errorf("fixture node %s not classified", n.ID)
		}
	}
}

// O9: each choke point lists the paths through it, and ClosesN equals the measured drop when
// the node is removed and the traversal re-run.
func TestChokePointDrillIn(t *testing.T) {
	for name, g := range allGraphs(t) {
		an := Traverse(g, DefaultTraversalOptions())
		base := map[string]bool{}
		for _, p := range an.Paths {
			base[p.ID] = true
		}
		for _, cp := range an.ChokePoints {
			if len(cp.PathIDs) != cp.Paths {
				t.Errorf("%s: %s PathIDs=%d Paths=%d", name, cp.NodeID, len(cp.PathIDs), cp.Paths)
			}
			for _, id := range cp.PathIDs {
				if !base[id] {
					t.Errorf("%s: %s lists unknown path %s", name, cp.NodeID, id)
				}
			}
			c := g.Clone()
			c.RemoveNode(cp.NodeID)
			after := Traverse(c, DefaultTraversalOptions())
			still := map[string]bool{}
			for _, p := range after.Paths {
				still[p.ID] = true
			}
			delta := 0
			for id := range base {
				if !still[id] {
					delta++
				}
			}
			if cp.ClosesN != delta {
				t.Errorf("%s: choke %s ClosesN=%d, measured %d", name, cp.NodeID, cp.ClosesN, delta)
			}
		}
	}
}

// O7: Simulate applies fixes in-graph and re-traverses; its numbers match an independent
// re-traversal, and every single-fix Breaks claim is confirmed by it.
func TestSimulateMatchesRetraversal(t *testing.T) {
	g := demoGraph()
	an := Traverse(g, DefaultTraversalOptions())
	for _, fx := range an.BreakFixes {
		removed, remaining := Simulate(g, []Fix{fx})
		after := Traverse(ApplyFixes(g, []Fix{fx}), DefaultTraversalOptions())
		still := map[string]bool{}
		for _, p := range after.Paths {
			still[p.ID] = true
		}
		n := 0
		for _, p := range an.Paths {
			if !still[p.ID] {
				n++
			}
		}
		if removed != n || remaining != after.TotalScore {
			t.Errorf("fix %s/%s: Simulate=(%d, %.2f) re-traversal=(%d, %.2f)", fx.NodeID, fx.Weakness, removed, remaining, n, after.TotalScore)
		}
		if removed < len(fx.Breaks) {
			t.Errorf("fix %s/%s claims %d breaks, re-traversal removes %d", fx.NodeID, fx.Weakness, len(fx.Breaks), removed)
		}
		for _, id := range fx.Breaks {
			if still[id] {
				t.Errorf("fix %s/%s claims to break %s but it survives", fx.NodeID, fx.Weakness, id)
			}
		}
	}
	removed, remaining := Simulate(g, an.MinFixSet)
	if removed != len(an.Paths) {
		t.Errorf("min fix set removes %d of %d paths (remaining score %.2f)", removed, len(an.Paths), remaining)
	}
	// Simulate never mutates the input graph.
	if again := Traverse(g, DefaultTraversalOptions()); len(again.Paths) != len(an.Paths) {
		t.Errorf("Simulate mutated the graph: %d → %d paths", len(an.Paths), len(again.Paths))
	}
	// An edge fix: cutting runs_as removes the paths through the role.
	r, _ := Simulate(g, []Fix{{Edge: &EdgeRef{From: "i-1", To: "role", Kind: graph.EdgeRunsAs}}})
	if r == 0 {
		t.Error("edge fix removed nothing")
	}
}
