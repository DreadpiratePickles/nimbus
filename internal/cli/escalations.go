package cli

import "github.com/DreadpiratePickles/nimbus/internal/pathdiff"

// escalatedPaths are the path Issues present on both sides whose band rises into High or
// Critical (delta shortfall #7: a plan that lifts a path 1.9 → 7.0 opens nothing but makes an
// existing path exploitable). pathdiff.Diff fills Result.Escalated; a Result built elsewhere
// (tests, older JSON) is derived from ChangedScore with the same pathdiff.Escalates rule.
func escalatedPaths(r pathdiff.Result) []pathdiff.ScoreChange {
	if r.Escalated != nil {
		return r.Escalated
	}
	var out []pathdiff.ScoreChange
	for _, c := range r.ChangedScore {
		if pathdiff.Escalates(c.Before, c.After) {
			out = append(out, c)
		}
	}
	return out
}

// planGateCount is what `pr-comment --fail-on-opened` counts: opened paths plus escalations,
// or opened paths only with --opened-only (pathdiff.Result.GateCount semantics).
func planGateCount(r pathdiff.Result, openedOnly bool) int {
	if openedOnly {
		return len(r.Opened)
	}
	return len(r.Opened) + len(escalatedPaths(r))
}
