package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/store"
)

var timeZero time.Time

// W7-VERIFY r5 #11 (bar: Upwind Score Journey; Vanta's stated cadence): every scan records each
// active Issue's score; `issues trend --since 90d` aggregates the window per scan with the cadence
// statement, and `issues show` prints the Issue's own score line as a text sparkline.
func TestIssuesTrendAndScoreLine(t *testing.T) {
	labDB(t)
	run(t, "ingest", labFile(t, "estate.findings.json"), "-o", "summary") // a second scan
	p01 := p01Issue(t)

	st := openTestStore(t)
	j, err := st.IssueScoreHistory(p01, timeZero)
	if err != nil || len(j) != 2 || j[0].Score != 10 || j[1].Score != 10 {
		t.Fatalf("P01 journey after two scans = %+v %v", j, err)
	}
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	if fj, _ := st.IssueScoreHistory(w01.ID, timeZero); len(fj) != 2 || fj[0].Score <= 0 || fj[0].Band == "" {
		t.Fatalf("finding Issue journey (top ranked evidence score) = %+v", fj)
	}
	st.Close()

	out := run(t, "issues", "trend", "--since", "90d")
	for _, want := range []string{"history since", "2 scans", "CRIT", "MAX"} {
		if !strings.Contains(out, want) {
			t.Errorf("issues trend lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "\n") < 4 {
		t.Errorf("issues trend prints one row per scan:\n%s", out)
	}
	var doc struct {
		Since  string                `json:"since"`
		Span   store.HistorySpan     `json:"history"`
		Scans  []store.ScoreTrendRow `json:"scans"`
		Window string                `json:"window"`
	}
	if err := json.Unmarshal([]byte(run(t, "issues", "trend", "--since", "90d", "--json")), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Scans) != 2 || doc.Scans[1].Issues == 0 || doc.Span.Scans != 2 || doc.Window != "90d" {
		t.Fatalf("trend JSON = %+v", doc)
	}
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{"90d": now.AddDate(0, 0, -90), "12w": now.AddDate(0, 0, -84), "6m": now.AddDate(0, -6, 0),
		"1y": now.AddDate(-1, 0, 0), "36h": now.Add(-36 * time.Hour), "2026-07-01": time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), "all": {}} {
		if got, err := parseTrendSince(in, now); err != nil || !got.Equal(want) {
			t.Errorf("parseTrendSince(%q) = %v %v, want %v", in, got, err, want)
		}
	}
	if _, err := parseTrendSince("nonsense", now); err == nil || !strings.Contains(err.Error(), "--since") {
		t.Errorf("a bad --since must say how to write it: %v", err)
	}

	show := run(t, "issues", "show", p01)
	if !strings.Contains(show, "score journey:") || !strings.Contains(show, "10.0") || !strings.ContainsAny(show, "▁▂▃▄▅▆▇█") {
		t.Errorf("issues show lacks the score line:\n%s", show)
	}
}

// The cadence statement `doctor` prints (handed to W7-POLISH to call next to doctorOwnership).
func TestDoctorScoreCadence(t *testing.T) {
	labDB(t)
	var got []string
	doctorScoreCadence(flagDB, func(status, name, detail string) { got = append(got, status+"|"+name+"|"+detail) })
	if len(got) != 1 || !strings.Contains(got[0], "|history|history since ") || !strings.Contains(got[0], "1 scan") {
		t.Fatalf("cadence = %v", got)
	}
}
