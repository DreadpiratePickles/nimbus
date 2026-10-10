package risk

import (
	"sort"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
)

// CriticalOnNonExposed is the finding-level benchmark row (competitive delta r2 #1): how many
// ranked findings are in the Critical band although their resource is not exposed — REACH
// blocked (Analysis.Exposures with reachability blocked, the `paths --exposures` verdict) or
// listed in benign (resource ids the benchmark labels false positive / pending-feature, e.g.
// the ground-truth targets of F-labels). It returns the count and the "finding@resource" ids,
// sorted. The groundtruth harness prints it; the target is 0.
func CriticalOnNonExposed(ranked []Ranked, an *attackpath.Analysis, benign map[string]bool) (int, []string) {
	blocked := map[string]bool{}
	if an != nil {
		for _, e := range an.Exposures {
			if e.Reachability == attackpath.ReachBlocked {
				blocked[e.NodeID] = true
			}
		}
	}
	var out []string
	for _, r := range ranked {
		rid := r.Finding.Resource.ID
		if r.Band == "Critical" && (blocked[rid] || benign[rid]) {
			out = append(out, r.Finding.ID+"@"+rid)
		}
	}
	sort.Strings(out)
	return len(out), out
}
