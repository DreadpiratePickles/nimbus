package groundtruth

import "testing"

// Track B3 item 4: an expected path may carry a band below the critical threshold
// (P07: medium, 5 <= score < 7). Scoring above the band is a failure too: a path the label
// says is not critical must not be ranked critical.
func TestBandOutcome(t *testing.T) {
	medium := gtPath{ID: "P07", Status: "expected", Band: "medium", MinScore: 5, MaxScore: 7}
	critical := gtPath{ID: "P08", Status: "expected", MinScore: 7}
	cases := []struct {
		g       gtPath
		found   int
		best    float64
		outcome string
		failure string
	}{
		{medium, 1, 5.15, "FOUND", ""},
		{medium, 1, 4.9, "LOW SCORE (4.90 < 5)", "low_score:P07"},
		{medium, 1, 7.0, "ABOVE BAND (7.00 >= 7)", "above_band:P07"},
		{medium, 0, 0, "MISSED", "missed:P07"},
		{critical, 1, 10, "FOUND", ""},
		{critical, 1, 6.86, "LOW SCORE (6.86 < 7)", "low_score:P08"},
	}
	for _, c := range cases {
		out, key := expectedOutcome(c.g, c.found, c.best)
		if out != c.outcome || key != c.failure {
			t.Errorf("%s found=%d best=%.2f: (%q, %q), want (%q, %q)", c.g.ID, c.found, c.best, out, key, c.outcome, c.failure)
		}
	}
	if !inBand(medium, 5.15) || inBand(medium, 7) || !inBand(critical, 7) {
		t.Error("inBand disagrees with the band bounds")
	}
}
