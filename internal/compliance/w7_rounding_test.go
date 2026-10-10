package compliance

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 7 defect 11: scores were truncated (soc2 4 pass / 7 fail = 36.36% → 36.3%,
// 2/3 = 66.67% → 66.6%); they are rounded to one decimal.
func TestScorePercentIsRounded(t *testing.T) {
	for _, c := range []struct {
		pass, fail int
		want       float64
	}{{4, 7, 36.4}, {2, 1, 66.7}, {1, 2, 33.3}, {3, 9, 25.0}, {1, 0, 100}} {
		if got := scorePercent(c.pass, c.fail); got != c.want {
			t.Errorf("%d pass / %d fail = %v, want %v", c.pass, c.fail, got, c.want)
		}
	}
	rep, _ := Build("custom-x", []model.Finding{}, "")
	if rep.ScorePercent != 0 {
		t.Errorf("no assessed control: %v", rep.ScorePercent)
	}
}
