package risk

import (
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Shortfall #3 (competitive delta 2026-10-09): 40 of 62 lab findings scored exactly 10.0 (raw up
// to 38.22), so the top of `prioritize` was a tie ordered by a hidden tie-breaker. 2.2.0 bounds
// the combination: above the High threshold the product is compressed with diminishing returns
// (bounded, strictly increasing), so at most 15 % of the labelled lab ties at 10.0.

func labRanked(t *testing.T) []Ranked {
	t.Helper()
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
	an.Paths = attackpath.Merge(an.Paths, attackpath.EvaluateWith(fs, rules, attackpath.EvalOptions{TrustedCIDRs: o.TrustedCIDRs, Graph: g}))
	return PrioritizeWith(fs, g, an.Paths, Options{Now: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), Analysis: an})
}

func TestSaturationLab(t *testing.T) {
	rs := labRanked(t)
	if len(rs) < 50 {
		t.Fatalf("lab ranked %d findings", len(rs))
	}
	at10, crit := 0, 0
	for _, r := range rs {
		if r.Score >= 10 {
			at10++
		}
		if r.Band == "Critical" {
			crit++
		}
	}
	if float64(at10) > 0.15*float64(len(rs)) {
		t.Errorf("%d of %d lab findings tie at 10.0 (> 15%%)", at10, len(rs))
	}
	t.Logf("lab: %d findings, %d at 10.0, %d Critical", len(rs), at10, crit)
	// Distinct raw products above the knee keep distinct, ordered scores (no new ties made by the
	// bound itself, beyond one-decimal rounding of nearly equal raws).
	for i := 1; i < len(rs); i++ {
		a, b := rs[i-1], rs[i]
		if a.Score < b.Score {
			t.Fatalf("not sorted: %.1f before %.1f", a.Score, b.Score)
		}
		// Below 10.0 the bound itself must not merge clearly different raws (at 10.0 one-decimal
		// rounding does, for raw ≥ ~25.4; the order still follows raw).
		if a.Score == b.Score && a.Score < 10 && a.Explanation.Raw-b.Explanation.Raw > 1.5 {
			t.Errorf("%s (raw %.2f) and %s (raw %.2f) tie at %.1f", a.Finding.ID, a.Explanation.Raw, b.Finding.ID, b.Explanation.Raw, a.Score)
		}
	}
}

func TestCombinationRule(t *testing.T) {
	w := DefaultWeights
	prev := -1.0
	for raw := 0.0; raw <= 60; raw += 0.25 {
		got := combine(raw, w)
		if got < prev-1e-12 {
			t.Fatalf("combine is not monotonic at raw %.2f: %.4f < %.4f", raw, got, prev)
		}
		if got > 10 || got < 0 {
			t.Fatalf("combine(%.2f) = %.4f out of 0–10", raw, got)
		}
		if raw <= w.CombineKnee && math.Abs(got-raw) > 1e-12 {
			t.Fatalf("combine changes raw %.2f below the knee: %.4f", raw, got)
		}
		prev = got
	}
	if combine(1e9, w) > 10 {
		t.Fatal("combine is not bounded by 10")
	}
}

// Every explanation still reproduces its score (base × Π multipliers), and a raw product above
// the knee is explained by a `combination` factor that states the rule, not by a flat cap.
func TestCombinationExplained(t *testing.T) {
	_, cal := rankCalibration(t)
	saw := false
	for _, r := range append(labRanked(t), cal...) {
		e := r.Explanation
		prod := e.Base
		for _, f := range e.Factors {
			prod *= f.Multiplier
			if f.Name == "cap" {
				t.Errorf("%s: flat cap factor in 2.2.0: %+v", r.Finding.ID, f)
			}
		}
		if math.Abs(prod-r.Score) > 0.01 {
			t.Errorf("%s: base × Π factors = %.4f, score %.1f", r.Finding.ID, prod, r.Score)
		}
		if e.Combination == "" {
			t.Errorf("%s: explanation does not state the combination rule", r.Finding.ID)
		}
		off := factorNamed(r, "off_path") != nil && factorNamed(r, "off_path").Multiplier != 1
		if e.Raw > DefaultWeights.CombineKnee && !off {
			f := factorNamed(r, "combination")
			if f == nil {
				t.Errorf("%s: raw %.2f above the knee has no combination factor", r.Finding.ID, e.Raw)
				continue
			}
			saw = true
			if !strings.Contains(f.Reason, "diminishing returns") || !strings.Contains(f.Reason, "raw") {
				t.Errorf("%s: combination reason %q", r.Finding.ID, f.Reason)
			}
		}
	}
	if !saw {
		t.Error("no ranked finding exercised the combination rule")
	}
}

// 2.4.0 (W5-ENGINE): a resource reached only through an internet-exposed network control (the
// jump-01 shape) is scored exposed, and a route with no network data reads "inferred:
// reachability unknown", so outputs changed and the version must change (docs/scoring.md); the
// 2.3.0 reachability-verdict exposure factor and the 2.2.0 bounded combination are unchanged.
func TestScoreVersion240(t *testing.T) {
	if ScoreVersion != "2.4.0" {
		t.Errorf("ScoreVersion %s: the network-control exposure route is published as 2.4.0", ScoreVersion)
	}
}
