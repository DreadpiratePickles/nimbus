package attackpath_test

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verify-5 C6/C14: folding a rule chain into its traversal counterpart keeps the HIGHER score
// and band of the merged sources and names every source (traversal + rule ids); a rule chain
// whose entry is a different kind (identity entry vs internet) is not folded.
func v5fp(id, rule string, score float64, fids []string, hops ...string) model.AttackPath {
	p := model.AttackPath{ID: id, RuleID: rule, Score: score, Severity: attackpath.PathSeverity(score), FindingIDs: fids, Name: id}
	for i, h := range hops {
		rel := "next"
		if i == 0 {
			rel = "exposed"
		}
		p.Steps = append(p.Steps, model.Step{Stage: i, Resource: h, Relation: rel, Evidence: map[string]any{"k": "v"}})
	}
	return p
}

func v5sources(p model.AttackPath) []string {
	if len(p.Steps) == 0 {
		return nil
	}
	v, _ := p.Steps[len(p.Steps)-1].Evidence[attackpath.AttrFoldSources].([]string)
	return v
}

func TestV5FoldKeepsMaxScore(t *testing.T) {
	trav := v5fp("t1", "GRAPH_TRAVERSAL", 4.0, []string{"f1"}, "A", "X", "B")
	rule := v5fp("r1", "R", 9.5, []string{"f2"}, "A", "B")
	out := attackpath.Merge([]model.AttackPath{trav}, []model.AttackPath{rule})
	if len(out) != 1 {
		t.Fatalf("want one folded path, got %d", len(out))
	}
	p := out[0]
	if p.Score != 9.5 || p.Severity != attackpath.PathSeverity(9.5) {
		t.Errorf("folded score %.2f %s, want 9.50 %s (the higher source)", p.Score, p.Severity, attackpath.PathSeverity(9.5))
	}
	if got := attackpath.AlsoMatchesRules(p); !reflect.DeepEqual(got, []string{"R"}) {
		t.Errorf("also_matches_rule %v", got)
	}
	want := []string{"GRAPH_TRAVERSAL 4.00", "R 9.50"}
	if got := v5sources(p); !reflect.DeepEqual(got, want) {
		t.Errorf("fold sources %v, want %v", got, want)
	}
	if s, _ := p.Steps[len(p.Steps)-1].Evidence[attackpath.AttrFoldScoreFrom].(string); s != "R" {
		t.Errorf("score_from %q, want R", s)
	}
	if trav.Score != 4.0 || trav.Steps[2].Evidence[attackpath.AttrFoldSources] != nil {
		t.Error("input mutated")
	}
	// Traversal higher: its score stands; both sources still listed.
	out = attackpath.Merge([]model.AttackPath{v5fp("t1", "GRAPH_TRAVERSAL", 8.0, nil, "A", "X", "B")}, []model.AttackPath{v5fp("r1", "R", 5.0, nil, "A", "B")})
	if len(out) != 1 || out[0].Score != 8.0 {
		t.Fatalf("traversal-higher fold: %d paths, score %.2f", len(out), out[0].Score)
	}
	if got := v5sources(out[0]); !reflect.DeepEqual(got, []string{"GRAPH_TRAVERSAL 8.00", "R 5.00"}) {
		t.Errorf("fold sources %v", got)
	}
	if s, _ := out[0].Steps[2].Evidence[attackpath.AttrFoldScoreFrom].(string); s != "GRAPH_TRAVERSAL" {
		t.Errorf("score_from %q, want GRAPH_TRAVERSAL", s)
	}
}

func TestV5FoldRespectsEntryKind(t *testing.T) {
	tr := v5fp("t1", "GRAPH_TRAVERSAL", 7, []string{"f1"}, "U", "X", "B")
	rc := v5fp("r1", "R", 6, []string{"f2"}, "U", "B")
	rc.Steps[0].Relation = "entry"
	out := attackpath.Merge([]model.AttackPath{tr}, []model.AttackPath{rc})
	if len(out) != 2 {
		t.Errorf("identity-entry rule chain folded into an internet traversal path (%d paths)", len(out))
	}
	// Same entry kind on both sides folds.
	tr2 := tr
	tr2.Steps = append([]model.Step(nil), tr.Steps...)
	tr2.Steps[0].Relation = "entry"
	if out := attackpath.Merge([]model.AttackPath{tr2}, []model.AttackPath{rc}); len(out) != 1 {
		t.Errorf("same identity entry not folded (%d paths)", len(out))
	}
}

func TestV5FoldDeterministic(t *testing.T) {
	base := []model.AttackPath{
		v5fp("t1", "GRAPH_TRAVERSAL", 7, []string{"f1"}, "A", "X", "B"),
		v5fp("t2", "GRAPH_TRAVERSAL", 7, []string{"f9"}, "A", "Y", "B"),
		v5fp("r1", "R1", 9, []string{"f3", "f2"}, "A", "B"),
		v5fp("r2", "R2", 6, []string{"f5", "f4"}, "A", "B"),
	}
	seen := map[string]int{}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 100; i++ {
		ps := append([]model.AttackPath(nil), base...)
		rng.Shuffle(len(ps), func(a, b int) { ps[a], ps[b] = ps[b], ps[a] })
		o := attackpath.Merge(ps, nil)
		sort.SliceStable(o, func(a, b int) bool { return o[a].ID < o[b].ID })
		sig := ""
		for _, p := range o {
			sig += fmt.Sprintf("%s:%.2f:%v:%v:%v|", p.ID, p.Score, p.FindingIDs, attackpath.AlsoMatchesRules(p), v5sources(p))
		}
		seen[sig]++
	}
	if len(seen) != 1 {
		t.Errorf("fold output depends on input order: %v", seen)
	}
}

// Lab: every folded rule chain's score is at most the score of the path it was folded into, the
// union of finding ids is preserved, and every folded path lists its sources.
func TestV5FoldLabScores(t *testing.T) {
	fs, _, err := adapters.ParseFile(filepath.Join("..", "..", "lab", "local", "out", "estate.findings.json"), "native", adapters.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	g.AttachFindings(fs)
	o := attackpath.DefaultTraversalOptions()
	o.TrustedCIDRs = []string{"203.0.113.0/24"}
	an := attackpath.Traverse(g, o)
	rules, _ := attackpath.LoadRules(nil)
	rc := attackpath.EvaluateWith(fs, rules, attackpath.EvalOptions{TrustedCIDRs: o.TrustedCIDRs, Graph: g})
	trav := append([]model.AttackPath(nil), an.Paths...)
	merged := attackpath.Merge(trav, rc)
	fids := func(ps []model.AttackPath) []string {
		m := map[string]bool{}
		for _, p := range ps {
			for _, f := range p.FindingIDs {
				m[f] = true
			}
		}
		var out []string
		for f := range m {
			out = append(out, f)
		}
		sort.Strings(out)
		return out
	}
	if b, a := fids(append(append([]model.AttackPath{}, trav...), rc...)), fids(merged); !reflect.DeepEqual(b, a) {
		t.Errorf("finding union changed %d -> %d", len(b), len(a))
	}
	kept := map[string]bool{}
	for _, p := range merged {
		kept[p.ID] = true
	}
	nFolded := 0
	for _, r := range rc {
		if kept[r.ID] {
			continue
		}
		var into *model.AttackPath
		for i, p := range merged {
			for _, x := range attackpath.AlsoMatchesRules(p) {
				if x == r.RuleID && p.Steps[0].Resource == r.Steps[0].Resource && p.Steps[len(p.Steps)-1].Resource == r.Steps[len(r.Steps)-1].Resource {
					into = &merged[i]
				}
			}
		}
		if into == nil {
			t.Errorf("rule chain %s %s dropped without a folded counterpart", r.RuleID, r.ID)
			continue
		}
		nFolded++
		from, _ := into.Steps[len(into.Steps)-1].Evidence[attackpath.AttrFoldScoreFrom].(string)
		t.Logf("folded %s %.2f into %s %.2f (score from %s)", r.RuleID, r.Score, into.Name, into.Score, from)
		if into.Score < r.Score {
			t.Errorf("rule chain %s %.2f %s folded into %s at the lower %.2f %s", r.RuleID, r.Score, r.Severity, into.Name, into.Score, into.Severity)
		}
		if len(v5sources(*into)) < 2 {
			t.Errorf("%s: fold sources %v", into.Name, v5sources(*into))
		}
	}
	if nFolded == 0 {
		t.Error("no rule chain folded on the lab")
	}
	t.Logf("lab: %d traversal, %d rule chains, %d merged, %d folded", len(trav), len(rc), len(merged), nFolded)
}

// Verification 5 fold probe (determinism): equal-score traversal twins plus rule chains give one
// output order whatever the input order (Merge used a stable score-only sort).
func TestV5MergeOrderIndependentOfInput(t *testing.T) {
	base := []model.AttackPath{
		v5fp("t1", "GRAPH_TRAVERSAL", 7, []string{"f1"}, "A", "X", "B"),
		v5fp("t2", "GRAPH_TRAVERSAL", 7, []string{"f9"}, "A", "Y", "B"),
		v5fp("r1", "R1", 6, []string{"f3", "f2"}, "A", "B"),
		v5fp("r2", "R2", 6, []string{"f5", "f4"}, "A", "B"),
		v5fp("u1", "GRAPH_TRAVERSAL", 5, nil, "C", "D"),
		v5fp("u2", "GRAPH_TRAVERSAL", 5, nil, "E", "F"),
	}
	seen := map[string]bool{}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 200; i++ {
		ps := append([]model.AttackPath(nil), base...)
		rng.Shuffle(len(ps), func(a, b int) { ps[a], ps[b] = ps[b], ps[a] })
		sig := ""
		for _, p := range attackpath.Merge(ps, nil) {
			sig += fmt.Sprintf("%s:%v:%v|", p.ID, p.FindingIDs, attackpath.AlsoMatchesRules(p))
		}
		seen[sig] = true
	}
	if len(seen) != 1 {
		t.Fatalf("Merge output depends on input order: %d variants: %v", len(seen), seen)
	}
}
