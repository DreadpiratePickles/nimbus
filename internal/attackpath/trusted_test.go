package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const corpTools = "arn:aws:ec2:us-east-1:111111111111:instance/i-0a1b2c3d4e5f60002"

// Item 3: exposure whose every source is inside trusted_cidrs is not an internet entry. The
// seeded false positive (F01, SSH open only to 203.0.113.0/24) yields 0 paths and exactly one
// suppressed entry, from traversal and from the rule engine.
func TestTrustedExposureSuppressesF01(t *testing.T) {
	gt := groundTruth(t)
	for _, typed := range []bool{false, true} {
		g, fs := labGraph(t, typed)
		an := Traverse(g, labOptions())
		rules, _ := LoadRules(nil)
		all := Merge(an.Paths, EvaluateWith(fs, rules, EvalOptions{TrustedCIDRs: []string{labTrustedCIDR}}))
		for _, p := range all {
			if gtMatch(gt["F01"], p) || (gtEntry(p) == "internet" && touches(p, corpTools)) {
				t.Errorf("typed=%v: F01 still reported: %.2f %s %s", typed, p.Score, p.RuleID, chainOf(p))
			}
		}
		// The lab has more trusted / auth-only scenarios (F06–F08): assert F01's entry is among
		// the suppressed ones and that every suppressed entry says why, not an exact count.
		var f01 *Suppressed
		for i, s := range an.Suppressed {
			if strings.TrimSpace(s.Reason) == "" {
				t.Errorf("typed=%v: suppressed entry without a reason: %+v", typed, s)
			}
			if s.NodeID == corpTools {
				f01 = &an.Suppressed[i]
			}
		}
		if f01 == nil {
			t.Fatalf("typed=%v: F01 (%s) not among suppressed entries %+v", typed, corpTools, an.Suppressed)
		}
		if s := *f01; s.Exposure != core.ExposureTrusted || !strings.Contains(s.Reason, labTrustedCIDR) || len(s.FindingIDs) == 0 {
			t.Errorf("suppressed entry: %+v", s)
		}
		// Without trusted_cidrs the same exposure is narrow (a specific public /24), still an
		// entry but far less likely than a 0.0.0.0/0 one.
		open := Traverse(g, DefaultTraversalOptions())
		var narrow, wide float64
		for _, p := range open.Paths {
			if touches(p, corpTools) && gtEntry(p) == "internet" {
				narrow = p.Score
			}
			if touches(p, "i-0a1b2c3d4e5f60001") && gtEntry(p) == "internet" && p.Score > wide {
				wide = p.Score
			}
		}
		if narrow == 0 || narrow >= wide/1.5 {
			t.Errorf("typed=%v: narrow exposure %.2f should be well below wide %.2f", typed, narrow, wide)
		}
		// Without trusted_cidrs nothing is suppressed as trusted (auth-only / org-conditioned
		// exposure is still private, F07/F08).
		for _, s := range open.Suppressed {
			if s.Exposure == core.ExposureTrusted || s.NodeID == corpTools {
				t.Errorf("no trusted_cidrs → nothing suppressed as trusted: %+v", s)
			}
		}
	}
}

func touches(p model.AttackPath, sub string) bool {
	for _, s := range p.Steps {
		if strings.Contains(s.Resource, sub) {
			return true
		}
	}
	return false
}

// A collector-built graph already labels the edge (core.Expose with trusted_cidrs); traversal
// honours the label without options, and AnnotateExposure labels ingested graphs in place.
func TestTrustedExposureLabelsAndAnnotation(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "i-9", Type: "aws_instance", Name: "corp", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "IMDSV1_ENABLED"}, FindingIDs: []string{"f9"}})
	g.AddNode(&graph.Node{ID: "admin", Type: "aws_iam_role", Name: "admin", Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}})
	core.Expose(g, "i-9", map[string]any{"via": "sg-corp"}, []string{"198.51.100.0/24"}, []string{"198.51.100.0/23"})
	g.AddEdge("i-9", "admin", graph.EdgeRunsAs, nil)
	an := Traverse(g, DefaultTraversalOptions())
	if len(an.Paths) != 0 || len(an.Suppressed) != 1 {
		t.Fatalf("collector-labelled trusted exposure: paths=%d suppressed=%+v", len(an.Paths), an.Suppressed)
	}

	ing := graph.New()
	ing.AttachFindings([]model.Finding{{ID: "w", Status: model.Fail, CanonicalID: "EC2_SG_OPEN_SSH", Provider: "aws", Account: "1", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"},
		Resource: model.Resource{ID: "i-8", Type: "aws_instance", Attributes: map[string]any{"exposure_cidrs": []any{"203.0.113.0/24"}}}}})
	sup := AnnotateExposure(ing, []string{labTrustedCIDR})
	n, _ := ing.Node("i-8")
	if len(sup) != 1 || n.Attributes["exposure"] != core.ExposureTrusted || n.Attributes["exposure_reason"] == nil {
		t.Errorf("AnnotateExposure: %+v node=%v", sup, n.Attributes)
	}
	for _, e := range ing.In("i-8") {
		if e.Kind == graph.EdgeExposes && e.Attr["exposure"] != core.ExposureTrusted {
			t.Errorf("edge not labelled: %v", e.Attr)
		}
	}
}
