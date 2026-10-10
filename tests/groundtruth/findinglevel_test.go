package groundtruth

// Finding-level benchmark row (competitive delta r2 #1, V4-ENGINE's risk.CriticalOnNonExposed):
// the path benchmark alone reported 100% precision while a blocked exposure (F04, the ledger)
// sat at #7 Critical in `prioritize`. This row scores the finding ranking against the same
// labels: Critical findings on a resource that `paths --exposures` reports blocked or that a
// false_positive / pending-feature label targets, and how many of those sit in the top 10.
// The target is 0 for both; the row is printed and written to benchmark.json.

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
)

// findingTopN is the prioritize window a buyer reads first.
const findingTopN = 10

type benchFindingLevel struct {
	CriticalOnNonExposed    int      `json:"critical_on_non_exposed"`
	CriticalOnNonExposedIDs []string `json:"critical_on_non_exposed_ids"`
	BenignInTopN            int      `json:"benign_in_top_n"`
	BenignInTopNIDs         []string `json:"benign_in_top_n_ids"`
	TopN                    int      `json:"top_n"`
	RankedFindings          int      `json:"ranked_findings"`
}

// benignTargets are the resources a false_positive or pending-feature label targets.
func benignTargets(paths []gtPath) map[string]bool {
	out := map[string]bool{}
	for _, g := range paths {
		if (g.Status == "false_positive" || g.Status == "pending-feature") && g.Target != "" {
			out[g.Target] = true
		}
	}
	return out
}

// findingLevel scores the stored ranking (prioritize --json) with the engine's own verdict
// (paths --format json --fixes: the Analysis, including blocked exposures).
func findingLevel(t *testing.T, home, db string, labels []gtPath) *benchFindingLevel {
	t.Helper()
	var ranked []risk.Ranked
	if err := json.Unmarshal(cli(t, home, db, "prioritize", "--json", "--top", "0"), &ranked); err != nil {
		t.Fatalf("prioritize --json: %v", err)
	}
	var an attackpath.Analysis
	if err := json.Unmarshal(cli(t, home, db, "paths", "--format", "json", "--fixes", "--limit", "0"), &an); err != nil {
		t.Fatalf("paths --format json --fixes: %v", err)
	}
	benign := benignTargets(labels)
	n, ids := risk.CriticalOnNonExposed(ranked, &an, benign)
	fl := &benchFindingLevel{CriticalOnNonExposed: n, CriticalOnNonExposedIDs: ids, TopN: findingTopN, RankedFindings: len(ranked)}
	blocked := map[string]bool{}
	for _, e := range an.Exposures {
		if e.Reachability == attackpath.ReachBlocked {
			blocked[e.NodeID] = true
		}
	}
	for i, r := range ranked {
		if i >= findingTopN {
			break
		}
		if rid := r.Finding.Resource.ID; benign[rid] || blocked[rid] {
			fl.BenignInTopNIDs = append(fl.BenignInTopNIDs, fmt.Sprintf("#%d %s@%s %.1f %s", i+1, r.Finding.ID, rid, r.Score, r.Band))
		}
	}
	fl.BenignInTopN = len(fl.BenignInTopNIDs)
	if fl.CriticalOnNonExposedIDs == nil {
		fl.CriticalOnNonExposedIDs = []string{}
	}
	if fl.BenignInTopNIDs == nil {
		fl.BenignInTopNIDs = []string{}
	}
	sort.Strings(fl.CriticalOnNonExposedIDs)
	return fl
}

func (fl *benchFindingLevel) String() string {
	if fl == nil {
		return "n/a"
	}
	return fmt.Sprintf("critical on non-exposed %d (target 0) | blocked/FP/pending resources in prioritize top %d: %d of %d ranked",
		fl.CriticalOnNonExposed, fl.TopN, fl.BenignInTopN, fl.RankedFindings)
}

func TestBenignTargetsFromLabels(t *testing.T) {
	got := benignTargets([]gtPath{{Status: "expected", Target: "a"}, {Status: "false_positive", Target: "b"}, {Status: "pending-feature", Target: "c"}})
	if got["a"] || !got["b"] || !got["c"] {
		t.Fatalf("benign targets %v", got)
	}
}
