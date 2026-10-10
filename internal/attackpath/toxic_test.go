package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Track B3 item 3 (planning decision): toxic-combination floor. A traversal path whose entry is
// wide internet exposure and whose target is admin-level or a sensitive data store gets a
// likelihood floor of 0.7 before priority, and is tagged toxic_combination exposed+admin /
// exposed+sensitive with a one-line reason in `because`. Not for narrow / trusted exposure, not
// for non-internet entries, not for targets that are neither admin-level nor sensitive, and it
// never rescues a path below the MinLikelihood reporting floor.

func lastBecause(p model.AttackPath) string {
	if len(p.Steps) == 0 {
		return ""
	}
	return p.Steps[len(p.Steps)-1].Because
}

func bestMatchPath(l gtLabel, paths []model.AttackPath) *model.AttackPath {
	var best *model.AttackPath
	for i := range paths {
		if gtMatch(l, paths[i]) && (best == nil || paths[i].Score > best.Score) {
			best = &paths[i]
		}
	}
	return best
}

func TestToxicFloorLab(t *testing.T) {
	gt := groundTruth(t)
	g, _ := labGraph(t, true)
	an := Traverse(g, labOptions())
	want := map[string]string{"P06": "exposed+sensitive", "P08": "exposed+admin", "P09": "exposed+admin", "P11": "exposed+admin"}
	for id, kind := range want {
		p := bestMatchPath(gt[id], an.Paths)
		if p == nil {
			t.Errorf("%s not found", id)
			continue
		}
		if p.Score < 7 {
			t.Errorf("%s: score %.2f, want >= 7 (toxic floor 0.7 x priority 10)", id, p.Score)
		}
		if got := ToxicCombination(*p); got != kind {
			t.Errorf("%s: toxic_combination %q, want %q", id, got, kind)
		}
		if !strings.Contains(lastBecause(*p), "toxic combination "+kind) {
			t.Errorf("%s: because lacks the toxic-combination reason: %q", id, lastBecause(*p))
		}
	}
	// Scores already above the floor are not changed by it.
	for id, score := range map[string]float64{"P01": 10, "P02": 7.6, "P03": 8, "P10": 10} {
		if p := bestMatchPath(gt[id], an.Paths); p == nil || p.Score != score {
			t.Errorf("%s: %v, want score %.2f unchanged", id, p, score)
		}
	}
	// Non-internet entry (unprotected repo → OIDC admin role): the exposed+* rule does not
	// apply; since P1-PLANDIFF the CI-entry floor does (ci_entry_test.go), and nothing else.
	if p := bestMatchPath(gt["P12"], an.Paths); p == nil || ToxicCombination(*p) != ToxicCIEntry {
		t.Errorf("P12 (repo entry) must carry only the ci-entry tag: %+v", p)
	}
	// The public EKS endpoint with the cluster itself as target: neither admin-level nor
	// sensitive, so no floor; it stays below 7.
	for _, p := range an.Paths {
		if len(p.Steps) == 1 && strings.HasSuffix(p.Steps[0].Resource, "cluster/nimbus-lab-eks") {
			if p.Score >= 7 || ToxicCombination(p) != "" {
				t.Errorf("internet > nimbus-lab-eks: %.2f toxic=%q, want < 7 and untagged", p.Score, ToxicCombination(p))
			}
		}
	}
	// Noise unchanged: F01 is suppressed with trusted_cidrs; without them it is narrow
	// exposure, which is never a toxic combination.
	for _, p := range an.Paths {
		if touches(p, corpTools) {
			t.Errorf("F01 reported with trusted_cidrs: %s", chainOf(p))
		}
	}
	for _, p := range Traverse(g, DefaultTraversalOptions()).Paths {
		if touches(p, corpTools) && (ToxicCombination(p) != "" || p.Score >= 7) {
			t.Errorf("narrow F01 path floored: %.2f toxic=%q %s", p.Score, ToxicCombination(p), chainOf(p))
		}
	}
	// Removing the exposure still breaks the floored path (P06: the function URL is the only
	// internet edge).
	lambda := "arn:aws:lambda:us-east-1:111111111111:function:nimbus-lab-export"
	p06 := bestMatchPath(gt["P06"], an.Paths)
	after := traverse(ApplyFixes(g, []Fix{{NodeID: lambda, Weakness: "PUBLIC_NETWORK_EXPOSURE"}}), labOptions())
	if p06 == nil || bestMatchPath(gt["P06"], after.Paths) != nil {
		t.Errorf("P06 survives removing the Lambda URL exposure")
	}
	if removed, _ := SimulateWith(g, labOptions(), []Fix{{NodeID: lambda, Weakness: "PUBLIC_NETWORK_EXPOSURE"}}); removed < 1 {
		t.Errorf("Simulate: removing the Lambda exposure removed %d paths", removed)
	}
}

// toxicGraph: internet (exposure attrs) → web (SSH open, no IMDS / CVE: credential hop 0.5) →
// role named roleName with the given weaknesses.
func toxicGraph(exposure map[string]any, roleName string, roleWeak ...string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "i-web", Type: "aws_instance", Name: "web", Provider: "aws", Account: "1",
		Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"}, FindingIDs: []string{"f-web"}})
	g.AddNode(&graph.Node{ID: "role", Type: "aws_iam_role", Name: roleName, Provider: "aws", Account: "1", Weaknesses: roleWeak})
	attr := map[string]any{"ports": "22"}
	for k, v := range exposure {
		attr[k] = v
	}
	g.AddEdge(graph.InternetNodeID, "i-web", graph.EdgeExposes, attr)
	g.AddEdge("i-web", "role", graph.EdgeRunsAs, nil)
	return g
}

func TestToxicFloorScope(t *testing.T) {
	wide := map[string]any{"exposure": "wide", "exposure_cidrs": []string{"0.0.0.0/0"}}
	narrow := map[string]any{"exposure_cidrs": []string{"198.51.100.0/24"}}
	cases := []struct {
		name  string
		g     *graph.Graph
		opts  TraversalOptions
		score float64 // 0: not reported
		toxic string
	}{
		// 0.8 wide x 0.5 SSH x 0.95 = 0.38 -> floor 0.7 x 10.
		{"wide + admin role", toxicGraph(wide, "web-role", "OVERPRIVILEGED_IDENTITY"), DefaultTraversalOptions(), 7, "exposed+admin"},
		// Narrow exposure: 0.4 x 0.5 x 0.95 x 10 = 1.9, no floor.
		{"narrow + admin role", toxicGraph(narrow, "web-role", "OVERPRIVILEGED_IDENTITY"), DefaultTraversalOptions(), 1.9, ""},
		// Named like a jewel (*payment*) but not admin-level, not a data store and not configured:
		// not an impact target at all since the P1-ENGINE noise round (names give no priority),
		// so no path (it was 3.8 with the built-in name catalog).
		{"wide + non-admin role named like a jewel", toxicGraph(wide, "payments-reader"), DefaultTraversalOptions(), 0, ""},
		// Configured crown jewel at level high (tier 3, priority 5): admin-level by config.
		{"wide + configured high jewel", toxicGraph(wide, "ledger"), jewelOpts("role", 3), 3.5, "exposed+admin"},
	}
	for _, c := range cases {
		an := Traverse(c.g, c.opts)
		var got *model.AttackPath
		for i := range an.Paths {
			if touches(an.Paths[i], "role") {
				got = &an.Paths[i]
			}
		}
		if c.score == 0 {
			if got != nil {
				t.Errorf("%s: reported %.2f, want no path", c.name, got.Score)
			}
			continue
		}
		if got == nil {
			t.Errorf("%s: no path", c.name)
			continue
		}
		if got.Score != c.score || ToxicCombination(*got) != c.toxic {
			t.Errorf("%s: score %.2f toxic %q, want %.2f %q", c.name, got.Score, ToxicCombination(*got), c.score, c.toxic)
		}
	}
	// The floor never rescues a path below the reporting floor: a plain exposed web server
	// (credential hop 0.1) in front of an admin role is still not reported, so disabling the
	// weakness that made the hop possible keeps breaking the path.
	g := imdsGraph("443")
	if an := Traverse(g, DefaultTraversalOptions()); len(an.Paths) != 0 {
		t.Errorf("plain exposed web -> admin role reported: %+v", an.Paths[0].Score)
	}
	g = imdsGraph("443", "IMDSV1_ENABLED")
	if removed, _ := Simulate(g, []Fix{{NodeID: "i-web", Weakness: "IMDSV1_ENABLED"}}); removed != 1 {
		t.Errorf("IMDSv1 fix removed %d paths, want 1", removed)
	}
	// Removing the exposure breaks the floored path.
	g = toxicGraph(wide, "web-role", "OVERPRIVILEGED_IDENTITY")
	if removed, _ := Simulate(g, []Fix{{NodeID: "i-web", Weakness: "PUBLIC_NETWORK_EXPOSURE"}}); removed != 1 {
		t.Errorf("exposure fix removed %d paths, want 1", removed)
	}
}

func jewelOpts(id string, crit int) TraversalOptions {
	o := DefaultTraversalOptions()
	o.CrownJewels = []JewelRule{{Pattern: id, Criticality: crit}}
	return o
}
