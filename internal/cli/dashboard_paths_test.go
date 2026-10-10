package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// r2 shortfall #7: the dashboard's path list is the CLI's — one row per path Issue
// (Analysis.Grouped()), "25 attack path Issues" for the lab, not 28 raw hop variants.
func TestDashboardPathIssuesMatchCLI(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	cfg, err := filepath.Abs(filepath.Join("..", "..", "lab", "local", "cloud-posture.lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	flagConfig = cfg
	t.Cleanup(func() { flagConfig = "" })
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	run(t, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")

	out := run(t, "paths")
	m := regexp.MustCompile(`(\d+) attack path Issue\(s\) from (\d+) hop variant`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("paths header missing:\n%.400s", out)
	}
	cliIssues, _ := strconv.Atoi(m[1])
	cliVariants, _ := strconv.Atoi(m[2])

	html := filepath.Join(dir, "index.html")
	run(t, "dashboard", "--out", html)
	b, err := os.ReadFile(html)
	if err != nil {
		t.Fatal(err)
	}
	const open = `<script id="data" type="application/json">`
	s := string(b)
	s = s[strings.Index(s, open)+len(open):]
	s = s[:strings.Index(s, "</script>")]
	var d struct {
		Paths      []json.RawMessage `json:"paths"`
		PathGroups []struct {
			IssueID  string   `json:"issue_id"`
			BestID   string   `json:"best_id"`
			Score    float64  `json:"score"`
			Band     string   `json:"band"`
			Variants int      `json:"variants"`
			PathIDs  []string `json:"path_ids"`
		} `json:"path_groups"`
		Analysis attackpath.Analysis `json:"analysis"`
	}
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatal(err)
	}
	grouped := d.Analysis.Grouped()
	if len(d.PathGroups) != len(grouped) || len(d.PathGroups) != cliIssues {
		t.Fatalf("dashboard path Issues = %d, Grouped() = %d, CLI = %d", len(d.PathGroups), len(grouped), cliIssues)
	}
	if len(d.Paths) != cliVariants {
		t.Errorf("dashboard hop variants = %d, CLI = %d", len(d.Paths), cliVariants)
	}
	// The rows carry the stored (per-database keyed, MCP-1) path Issue ids, so a row links to its
	// Issue page; Grouped() over the payload's analysis has the unkeyed grouping digest.
	st := openTestStore(t)
	stored := map[string]bool{}
	if all, err := st.Issues(store.IssueFilter{Kind: model.IssuePath}); err == nil {
		for _, is := range all {
			stored[is.ID] = true
		}
	}
	// Rows are in the stored Issue order (W6-POLISH: one tie order with `issues` and `paths`;
	// TestPathTitlesAreTheIssueTitlesEverywhereOnLab pins it), so match Grouped() by id here.
	byID := map[string]attackpath.PathGroup{}
	for _, w := range grouped {
		byID[st.KeyID(w.IssueID)] = w
	}
	nv := 0
	for i, g := range d.PathGroups {
		w := byID[g.IssueID]
		if !stored[g.IssueID] {
			t.Errorf("row %d issue_id %s is not a stored path Issue id", i, g.IssueID)
		}
		if g.IssueID != st.KeyID(w.IssueID) || g.BestID != w.Best.ID || g.Score != w.Score || g.Band != w.Band || g.Variants != w.Variants {
			t.Errorf("row %d = %+v, Grouped() = %s %s %.1f %s +%d", i, g, w.IssueID, w.Best.ID, w.Score, w.Band, w.Variants)
		}
		nv += len(g.PathIDs)
	}
	if nv != cliVariants {
		t.Errorf("groups cover %d variants, CLI %d (grouping must be lossless)", nv, cliVariants)
	}
	if cliIssues >= cliVariants {
		t.Logf("lab has no multi-variant Issue (%d/%d)", cliIssues, cliVariants)
	}
}
