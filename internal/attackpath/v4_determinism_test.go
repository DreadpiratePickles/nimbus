package attackpath_test

import (
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// v4Shuffled is the lab analysis (traversal + rule chains, merged as the CLI does) with the
// finding order, each finding's related list and weaknesses permuted by seed (0 = file order).
func v4Shuffled(t *testing.T, seed int64) *attackpath.Analysis {
	t.Helper()
	fs, _, err := adapters.ParseFile(filepath.Join("..", "..", "lab", "local", "out", "estate.findings.json"), "native", adapters.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if seed != 0 {
		r := rand.New(rand.NewSource(seed))
		r.Shuffle(len(fs), func(i, j int) { fs[i], fs[j] = fs[j], fs[i] })
		for k := range fs {
			rel := fs[k].Resource.Related
			r.Shuffle(len(rel), func(i, j int) { rel[i], rel[j] = rel[j], rel[i] })
			ws := fs[k].Weaknesses
			r.Shuffle(len(ws), func(i, j int) { ws[i], ws[j] = ws[j], ws[i] })
		}
	}
	g := graph.New()
	g.AttachFindings(fs)
	o := attackpath.DefaultTraversalOptions()
	o.TrustedCIDRs = []string{"203.0.113.0/24"}
	an := attackpath.Traverse(g, o)
	rules, _ := attackpath.LoadRules(nil)
	an.Paths = attackpath.Merge(an.Paths, attackpath.EvaluateWith(fs, rules, attackpath.EvalOptions{TrustedCIDRs: o.TrustedCIDRs, Graph: g}))
	return an
}

// Defect 3 (verify-4 D4): a path Issue's provider/account comes from its anchor node (entry
// as fallback) and never depends on ingest order: 100 shuffled ingests store identical
// provider/account on every path Issue.
func TestV4PathIssueProviderAccountDeterministic(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	rows := func(an *attackpath.Analysis) map[string]string {
		st, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.RebuildPathIssues("s", an, t0); err != nil {
			t.Fatal(err)
		}
		is, err := st.Issues(store.IssueFilter{Kind: model.IssuePath})
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, i := range is {
			// keyed by identity: stored ids are HMAC-keyed per database (store/idkey.go, MCP-1)
			m[i.EntryID+"|"+i.AnchorID+"|"+i.RuleID] = i.Provider + "/" + i.Account
		}
		return m
	}
	want := rows(v4Shuffled(t, 0))
	bad := 0
	for seed := int64(1); seed <= 100; seed++ {
		got := rows(v4Shuffled(t, seed))
		for id, w := range want {
			if got[id] != w {
				bad++
				if bad <= 5 {
					t.Errorf("seed %d issue %s: %q, want %q", seed, id, got[id], w)
				}
			}
		}
		if len(got) != len(want) {
			t.Errorf("seed %d: %d issues, want %d", seed, len(got), len(want))
		}
	}
	if bad > 0 {
		t.Errorf("%d (seed, issue) pairs differ over 100 seeds", bad)
	}
}
