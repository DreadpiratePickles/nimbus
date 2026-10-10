package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W6-VERIFY r4 #15: finding (and attack-path) ids leave the API keyed per database, the
// dashboard the server renders carries the same ids, and an inbound id resolves whether it is
// the external one or an old raw fingerprint. r4 #12: /api/scans and /api/governance/metrics
// carry the per-scan Issue trend.

func get(t *testing.T, ts *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// W7-POLISH flake hunt: the seed is a map, and this test used to pick "the first fingerprint id"
// in map order — bucket (open), logging or gcp (resolved by scan-2) — so it exercised a different
// finding each run. Every seeded fingerprint is now checked, in a fixed order, with the
// assertion that matches its state: /api/findings lists the open one; every one (open or
// resolved) resolves by external and by raw id, and no response carries a raw fingerprint.
func TestAPIKeysFindingIDsAndResolvesOldOnes(t *testing.T) {
	s, fs := seedLifecycle(t)
	var raws []string
	for _, name := range []string{"bucket", "logging", "gcp"} {
		if f := fs[name]; store.IsDigestID(f.ID) {
			raws = append(raws, f.ID)
		}
	}
	if len(raws) != 3 {
		t.Fatalf("seed has %d fingerprint ids, want 3", len(raws))
	}
	open := fs["bucket"].ID
	var data strings.Builder
	for i, raw := range raws {
		if i > 0 {
			data.WriteString(",")
		}
		data.WriteString(`{"id":"` + raw + `"}`)
	}
	s.dashboard = func() ([]byte, error) {
		return []byte(`<html><script id="data" type="application/json">{"findings":[` + data.String() + `]}</script></html>`), nil
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	for _, p := range []string{"/api/findings", "/api/issues?state=all", "/api/risk/top", "/api/graph", "/"} {
		code, body := get(t, ts, p)
		if code != 200 {
			t.Fatalf("%s: %d %s", p, code, body)
		}
		for _, raw := range raws {
			if strings.Contains(body, raw) {
				t.Errorf("%s carries the raw fingerprint %s", p, raw)
			}
		}
	}
	if _, body := get(t, ts, "/api/findings"); !strings.Contains(body, s.st.ExternalFindingID(open)) {
		t.Errorf("/api/findings lacks the open finding's external id")
	}
	for _, raw := range raws {
		ext := s.st.ExternalFindingID(raw)
		for _, id := range []string{ext, raw} {
			code, body := get(t, ts, "/api/findings/"+id)
			if code != 200 || !strings.Contains(body, ext) || strings.Contains(body, raw) {
				t.Errorf("/api/findings/%s (raw %s): %d %.200s", id, raw, code, body)
			}
		}
	}
	if code, _ := get(t, ts, "/api/findings/0123456789abcdef0123456789abcdef"); code != 404 {
		t.Errorf("unknown id: %d", code)
	}
}

func TestAPIScansCarryIssueTrend(t *testing.T) {
	s, _ := seedLifecycle(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	code, body := get(t, ts, "/api/scans")
	if code != 200 {
		t.Fatalf("/api/scans %d", code)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(body), &rows); err != nil || len(rows) != 2 {
		t.Fatalf("/api/scans: %v %s", err, body)
	}
	tr, ok := rows[0]["issue_trend"].(map[string]any)
	if !ok || rows[0]["scan_id"] != "scan-2" {
		t.Fatalf("newest scan row lacks issue_trend: %v", rows[0])
	}
	for _, k := range []string{"new", "resolved", "reopened", "verified_fixed", "regressed", "open", "verified_share"} {
		if _, ok := tr[k]; !ok {
			t.Errorf("issue_trend lacks %s", k)
		}
	}
	if _, ok := rows[0]["by_severity"]; !ok {
		t.Errorf("scan rows lost the summary fields")
	}
	code, body = get(t, ts, "/api/governance/metrics")
	var m struct {
		ScanTrend []store.ScanTrendRow `json:"scan_trend"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &m) != nil || len(m.ScanTrend) != 2 || m.ScanTrend[0].Trend == nil {
		t.Errorf("governance metrics scan_trend: %d %.300s", code, body)
	}
	_ = time.Now
	_ = model.Fail
}
