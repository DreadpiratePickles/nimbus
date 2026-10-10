package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// Coordinator item 16 (after W6-VERIFY): `--diff` / `--diff-json` print the per-scan Issue trend
// the store records (store.ScanTrend), one line / one object.
func TestDiffPrintsTheScanTrend(t *testing.T) {
	cfg := w6IngestLab(t)
	out := run(t, "-c", cfg, "ingest", labFile(t, "estate.findings.json"), "-o", "summary", "--diff")
	if !strings.Contains(out, "Issues this scan: ") || !strings.Contains(out, "verified fixed") {
		t.Errorf("--diff lacks the Issue trend line:\n%s", out)
	}
	js := run(t, "-c", cfg, "ingest", labFile(t, "estate.findings.json"), "-o", "summary", "--diff-json", "-")
	i := strings.Index(js, "{")
	var doc struct {
		Trend *struct {
			New  int `json:"new"`
			Open int `json:"open"`
		} `json:"issue_trend"`
	}
	if i < 0 || json.Unmarshal([]byte(js[i:]), &doc) != nil || doc.Trend == nil || doc.Trend.Open == 0 {
		t.Errorf("--diff-json lacks issue_trend:\n%.800s", js)
	}
}
