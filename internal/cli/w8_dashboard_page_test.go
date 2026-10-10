package cli

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/server"
)

// W8-FIX 1 (V8 defect 1; bar: Wiz/Upwind show the score journey and related escalations on every
// Issue page): the dashboard payload's issue_pages carry potential_escalations and score_history
// for every Issue, equal to what the API Issue page (server.BuildIssuePages) serves.
func TestDashboardIssuePagesCarryEscalationsAndScoreHistory(t *testing.T) {
	labDB(t)
	res, st, err := loadResult(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	o, err := issuePageOptions(context.Background(), cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.BuildIssuePages(st, o)
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	html, err := renderDashboard(res, "static", "")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<script id="data" type="application/json">(.*?)</script>`).FindSubmatch(html)
	if m == nil {
		t.Fatal("no data blob")
	}
	var d struct {
		Issues []model.Issue                         `json:"issues"`
		Pages  map[string]map[string]json.RawMessage `json:"issue_pages"`
	}
	if err := json.Unmarshal(m[1], &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Issues) == 0 || len(d.Pages) != len(d.Issues) {
		t.Fatalf("issue_pages %d for %d Issues", len(d.Pages), len(d.Issues))
	}
	withEsc, withHist := 0, 0
	for _, is := range d.Issues {
		pg := d.Pages[is.ID]
		for _, k := range []string{"potential_escalations", "score_history"} {
			if _, ok := pg[k]; !ok {
				t.Fatalf("dashboard Issue page %s lacks %q", is.ID, k)
			}
		}
		var esc []json.RawMessage
		json.Unmarshal(pg["potential_escalations"], &esc)
		if len(esc) != len(api[is.ID].PotentialEscalations) {
			t.Errorf("Issue %s: dashboard %d potential escalations, API %d", is.ID, len(esc), len(api[is.ID].PotentialEscalations))
		}
		if len(esc) > 0 {
			withEsc++
		}
		var h server.PageScoreHistory
		json.Unmarshal(pg["score_history"], &h)
		if len(h.Points) != len(api[is.ID].ScoreHistory.Points) || h.Line != api[is.ID].ScoreHistory.Line {
			t.Errorf("Issue %s: dashboard score history %d %q, API %d %q", is.ID, len(h.Points), h.Line, len(api[is.ID].ScoreHistory.Points), api[is.ID].ScoreHistory.Line)
		}
		if len(h.Points) > 0 {
			withHist++
		}
	}
	if withEsc == 0 || withHist != len(d.Issues) {
		t.Errorf("pages with escalations %d (want >0), with score history %d of %d", withEsc, withHist, len(d.Issues))
	}
}
