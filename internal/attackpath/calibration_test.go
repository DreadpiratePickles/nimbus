package attackpath

import (
	"testing"
)

// Item 6: textbook critical chains reach the critical band (>= 7) on the lab without lifting
// noise. Calibration set = lab/ground_truth.yaml; the per-edge table is in docs/benchmark.md.
func TestLabCalibration(t *testing.T) {
	gt := groundTruth(t)
	for _, typed := range []bool{false, true} {
		g, _ := labGraph(t, typed)
		an := Traverse(g, labOptions())
		high := []string{"P01", "P02", "P03", "P04", "P05", "P10"}
		for _, id := range high {
			if ok, best := bestMatch(gt[id], an.Paths); !ok || best < 7 {
				t.Errorf("typed=%v %s: found=%v best=%.2f, want >= 7", typed, id, ok, best)
			}
		}
		// Every reported traversal path >= 7 is a labelled path (expected, or the SCP-denied
		// S01 that stays reported until SCP evaluation lands): no high-scoring noise.
		for _, p := range an.Paths {
			if p.Score < 7 {
				continue
			}
			labelled := false
			for _, l := range gt {
				labelled = labelled || (l.Status != "false_positive" && gtMatch(l, p))
			}
			if !labelled {
				t.Errorf("typed=%v: unlabelled path scores %.2f: %s", typed, p.Score, chainOf(p))
			}
		}
		// Without trusted_cidrs F01 is narrow exposure: reported, but well below the band.
		for _, p := range Traverse(g, DefaultTraversalOptions()).Paths {
			if touches(p, corpTools) && p.Score >= 7 {
				t.Errorf("typed=%v: narrow F01 path scores %.2f", typed, p.Score)
			}
		}
	}
}
