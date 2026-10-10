package attackpath_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

const ledgerID = "arn:aws:rds:us-east-1:111111111111:db:nimbus-lab-ledger" // F04

type labRun struct {
	fs     []model.Finding
	g      *graph.Graph
	an     *attackpath.Analysis
	ranked []risk.Ranked
}

// v4Lab runs the lab the way the CLI does: findings → graph → traversal + rule chains (Merge)
// → the published risk score with the analysis.
func v4Lab(t *testing.T) labRun {
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
	ranked := risk.PrioritizeWith(fs, g, an.Paths, risk.Options{Now: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), Analysis: an})
	return labRun{fs, g, an, ranked}
}

// issueVerdictFor mirrors cli.issueVerdict: finding risk bands + best path band per resource.
func issueVerdictFor(r labRun) *store.IssueVerdict {
	v := &store.IssueVerdict{FindingBand: map[string]string{}, PathBand: map[string]string{}}
	for _, x := range r.ranked {
		v.FindingBand[x.Finding.ID] = x.Band
	}
	best := map[string]float64{}
	for _, p := range r.an.Paths {
		for _, s := range p.Steps {
			for _, id := range []string{s.Resource, s.WeaknessOn} {
				if id != "" && p.Score > best[id] {
					best[id] = p.Score
				}
			}
		}
	}
	for id, sc := range best {
		v.PathBand[id] = model.ScoreBand(sc)
	}
	return v
}

func exposureFactor(r risk.Ranked) *risk.Factor {
	for i, f := range r.Explanation.Factors {
		if f.Name == "exposure" {
			return &r.Explanation.Factors[i]
		}
	}
	return nil
}

// Delta r2 #1 (one verdict everywhere): for every lab node, `paths --exposures` (Analysis
// blocked exposures), graph.Verdict, the risk exposure factor of every finding on the node and
// the single Issue severity agree. F04 (the ledger, blocked: no IGW route) leaves the prioritize
// top 10 and its Issue drops below Critical.
func TestV4OneVerdictEverywhere(t *testing.T) {
	r := v4Lab(t)
	blocked := map[string]attackpath.Exposure{}
	for _, e := range r.an.Exposures {
		if e.Reachability == attackpath.ReachBlocked {
			blocked[e.NodeID] = e
		}
	}
	if _, ok := blocked[ledgerID]; !ok {
		t.Fatalf("precondition: paths --exposures does not list the ledger as blocked")
	}
	// graph.Verdict ⇔ paths --exposures, for every node.
	for _, n := range r.g.Nodes() {
		v := r.g.Verdict(n.ID)
		_, inExp := blocked[n.ID]
		if v.Blocked() != inExp {
			t.Errorf("node %s: graph.Verdict %q (%s), paths --exposures blocked=%v", n.ID, v.Status, v.Reason, inExp)
		}
		if v.Blocked() && !strings.HasPrefix(v.Label, "not exposed (blocked: ") {
			t.Errorf("node %s: label %q", n.ID, v.Label)
		}
	}
	// prioritize exposure factor ⇔ verdict.
	rank := map[string]int{}
	for i, x := range r.ranked {
		rank[x.Finding.ID] = i + 1
		f := exposureFactor(x)
		if f == nil {
			t.Fatalf("%s: no exposure factor", x.Finding.ID)
		}
		v := r.g.Verdict(x.Finding.Resource.ID)
		if v.Blocked() {
			if !strings.HasPrefix(f.Reason, "not exposed (blocked: ") || f.Multiplier != risk.DefaultWeights.ExposureNone {
				t.Errorf("%s on blocked %s: exposure %q ×%.2f", x.Finding.ID, x.Finding.Resource.ID, f.Reason, f.Multiplier)
			}
		} else if strings.HasPrefix(f.Reason, "not exposed (blocked") {
			t.Errorf("%s: blocked exposure factor on a node whose verdict is %q", x.Finding.ID, v.Status)
		}
		if v.Status == graph.VerdictUnknown && strings.HasPrefix(f.Reason, "internet exposed") && !strings.Contains(f.Reason, "inferred") {
			t.Errorf("%s: unknown reachability not labelled inferred: %q", x.Finding.ID, f.Reason)
		}
	}
	// F04 out of the top 10.
	for _, x := range r.ranked {
		if x.Finding.Resource.ID == ledgerID && rank[x.Finding.ID] <= 10 {
			t.Errorf("F04 %s is prioritize #%d at %.1f %s", x.Finding.ID, rank[x.Finding.ID], x.Score, x.Band)
		}
	}
	// Issue severity: single Issues on a blocked resource take the risk band; the ledger is not Critical.
	st, err := store.Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.UpsertFindings(r.fs); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssuesWithVerdict(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), issueVerdictFor(r)); err != nil {
		t.Fatal(err)
	}
	iss, err := st.Issues(store.IssueFilter{Kind: model.IssueSingle})
	if err != nil {
		t.Fatal(err)
	}
	band := map[string]string{}
	for _, x := range r.ranked {
		band[x.Finding.ID] = x.Band
	}
	sawLedger := false
	for _, is := range iss {
		if _, ok := blocked[is.ResourceID]; !ok {
			continue
		}
		best := model.Severity("")
		for _, id := range is.FindingIDs {
			if b := store.BandSeverity(band[id]); b != "" && (best == "" || b.Rank() > best.Rank()) {
				best = b
			}
		}
		if best != "" && is.Severity.Rank() > best.Rank() {
			t.Errorf("Issue %s on blocked %s: %s above its risk band %s", is.ID, is.ResourceID, is.Severity, best)
		}
		if is.ResourceID == ledgerID {
			sawLedger = true
			if is.Severity == model.Critical {
				t.Errorf("ledger Issue still CRITICAL")
			}
			t.Logf("ledger Issue %s: %s", is.CanonicalID, is.Severity)
		}
	}
	if !sawLedger {
		t.Errorf("no single Issue on the ledger")
	}
	var ids []string
	for id := range blocked {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	n, which := risk.CriticalOnNonExposed(r.ranked, r.an, nil)
	t.Logf("blocked exposures: %v; Critical findings on blocked resources: %d %v", ids, n, which)
	if n != 0 {
		t.Errorf("%d Critical finding(s) on blocked resources: %v", n, which)
	}
}
