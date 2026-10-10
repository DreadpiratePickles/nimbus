package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// seedLifecycle stores two scans: scan-1 sees a CRITICAL public bucket and a LOW logging gap on
// aws/111; scan-2 re-examines the same scope and only the bucket is still there (the logging gap
// is resolved). A MEDIUM gcp finding from scan-1 stays open. Coverage is recorded for scan-2.
func seedLifecycle(t *testing.T) (*Server, map[string]model.Finding) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	t0 := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	mk := func(scan, check, canon string, sev model.Severity, prov, acct, res string, weak ...string) model.Finding {
		f := model.Finding{Source: "native", CheckID: check, CanonicalID: canon, Title: canon, Severity: sev, Status: model.Fail, Provider: prov, Account: acct,
			Resource: model.Resource{ID: res, Type: "aws_s3_bucket", Name: res}, Weaknesses: weak, ScanID: scan}
		f.Finalize(t0)
		return f
	}
	bucket := mk("scan-1", "s3_public", "S3_PUBLIC_BUCKET", model.Critical, "aws", "111", "pii", "PUBLIC_DATA_STORE")
	logging := mk("scan-1", "s3_logging", "S3_NO_LOGGING", model.Low, "aws", "111", "logs")
	gcp := mk("scan-1", "gcs_public", "GCS_PUBLIC", model.Medium, "gcp", "proj", "gcs-bucket")
	if _, err := st.ApplyScan("scan-1", []model.Finding{bucket, logging, gcp}, t0, store.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	st.SaveScan(model.ScanSummary{ScanID: "scan-1", StartedAt: t0, FinishedAt: t0.Add(time.Minute), Total: 3, Failed: 3,
		BySeverity: map[model.Severity]int{model.Critical: 1, model.Medium: 1, model.Low: 1}})
	if err := st.RebuildIssues(t0); err != nil {
		t.Fatal(err)
	}
	b2 := bucket
	b2.ScanID = "scan-2"
	t1 := t0.Add(time.Hour)
	if _, err := st.ApplyScan("scan-2", []model.Finding{b2}, t1, store.ApplyOptions{Scopes: store.ScopesOf([]model.Finding{b2})}); err != nil {
		t.Fatal(err)
	}
	st.SaveScan(model.ScanSummary{ScanID: "scan-2", StartedAt: t1, FinishedAt: t1.Add(time.Minute), Total: 1, Failed: 1,
		BySeverity: map[model.Severity]int{model.Critical: 1}})
	if err := st.RebuildIssues(t1); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordCoverage("scan-2", t1, []store.CoverageEntry{
		{Provider: "aws", Account: "111", API: "s3:ListBuckets", Status: store.CoverageOK},
		{Provider: "aws", Account: "111", API: "macie:ListFindings", Status: store.CoverageDenied, Reason: "access_denied: AccessDenied"},
	}); err != nil {
		t.Fatal(err)
	}
	s := New(st, func() ([]byte, error) { return []byte("<html>dash</html>"), nil })
	return s, map[string]model.Finding{"bucket": bucket, "logging": logging, "gcp": gcp}
}

func getJSON(t *testing.T, ts *httptest.Server, path string, v any) int {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if v != nil && resp.StatusCode == 200 {
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatalf("%s: %v\n%s", path, err, b)
		}
	}
	return resp.StatusCode
}

func TestSummaryCountsIssues(t *testing.T) {
	s, _ := seedLifecycle(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	var sum map[string]any
	if getJSON(t, ts, "/api/summary", &sum) != 200 {
		t.Fatal("summary status")
	}
	counts, _ := s.st.IssueCounts()
	if int(sum["open"].(float64)) != counts.Open || int(sum["resolved"].(float64)) != counts.Resolved || counts.Resolved == 0 {
		t.Errorf("summary open/resolved must come from IssueCounts %+v: %v", counts, sum)
	}
	bySev := sum["by_severity"].(map[string]any)
	if bySev["CRITICAL"].(float64) != 1 || bySev["LOW"] != nil {
		t.Errorf("by_severity must count open Issues only: %v", bySev)
	}
	fs, _ := sum["findings"].(map[string]any)
	if fs == nil || fs["open"].(float64) != 2 {
		t.Errorf("old finding counts must stay under findings: %v", sum["findings"])
	}
	if _, ok := sum["attack_paths"]; !ok {
		t.Error("attack_paths dropped from summary")
	}
}

func TestIssuesAPI(t *testing.T) {
	s, _ := seedLifecycle(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	var all []model.Issue
	if getJSON(t, ts, "/api/issues", &all) != 200 || len(all) < 3 {
		t.Fatalf("issues: %v", all)
	}
	cases := map[string]func(model.Issue) bool{
		"state=open":                          func(i model.Issue) bool { return model.IsActive(i.State) },
		"state=resolved":                      func(i model.Issue) bool { return i.State == model.StateResolved },
		"severity=critical":                   func(i model.Issue) bool { return i.Severity == model.Critical },
		"provider=gcp":                        func(i model.Issue) bool { return i.Provider == "gcp" },
		"account=111":                         func(i model.Issue) bool { return i.Account == "111" },
		"kind=single":                         func(i model.Issue) bool { return i.Kind == model.IssueSingle },
		"provider=aws&state=open&kind=single": func(i model.Issue) bool { return i.Provider == "aws" && model.IsActive(i.State) },
	}
	for q, pred := range cases {
		var got []model.Issue
		if code := getJSON(t, ts, "/api/issues?"+q, &got); code != 200 {
			t.Errorf("%s: %d", q, code)
			continue
		}
		want := 0
		for _, i := range all {
			if pred(i) {
				want++
			}
		}
		if len(got) != want || want == 0 {
			t.Errorf("/api/issues?%s returned %d, want %d (>0)", q, len(got), want)
		}
		for _, i := range got {
			if !pred(i) {
				t.Errorf("/api/issues?%s returned non-matching %+v", q, i)
			}
		}
	}
	if code := getJSON(t, ts, "/api/issues?state=bogus", nil); code != 400 {
		t.Errorf("unknown state: %d, want 400", code)
	}
	// V2 defect 12: an invalid min_severity is an error, not a silently dropped filter.
	if code := getJSON(t, ts, "/api/issues?min_severity=zzz", nil); code != 400 {
		t.Errorf("invalid min_severity: %d, want 400", code)
	}
	var hi []model.Issue
	if code := getJSON(t, ts, "/api/issues?min_severity=HIGH", &hi); code != 200 || len(hi) == 0 {
		t.Errorf("min_severity=HIGH: %d %d", code, len(hi))
	}
	for _, i := range hi {
		if i.Severity.Rank() < model.High.Rank() {
			t.Errorf("min_severity=HIGH returned %s", i.Severity)
		}
	}
	if code := getJSON(t, ts, "/api/issues?min_severity=info", nil); code != 200 {
		t.Errorf("min_severity=info is valid: %d", code)
	}
	var one struct {
		Issue    model.Issue     `json:"issue"`
		Findings []model.Finding `json:"findings"`
	}
	if getJSON(t, ts, "/api/issues/"+url.PathEscape(all[0].ID), &one) != 200 || one.Issue.ID != all[0].ID || len(one.Findings) == 0 {
		t.Errorf("issue detail: %+v", one)
	}
	if code := getJSON(t, ts, "/api/issues/nope", nil); code != 404 {
		t.Errorf("unknown issue: %d", code)
	}
}

func TestCoverageAndScansAPI(t *testing.T) {
	s, _ := seedLifecycle(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	var cov []store.CoverageEntry
	if getJSON(t, ts, "/api/coverage?scan_id=scan-2", &cov) != 200 || len(cov) != 2 {
		t.Fatalf("coverage: %v", cov)
	}
	denied := false
	for _, c := range cov {
		denied = denied || (c.Status == store.CoverageDenied && strings.Contains(c.Reason, "AccessDenied"))
	}
	if !denied {
		t.Errorf("coverage must report the denied call with its reason: %v", cov)
	}
	var latest []store.CoverageEntry
	if getJSON(t, ts, "/api/coverage", &latest) != 200 || len(latest) != 2 {
		t.Errorf("coverage without scan_id must default to the latest scan: %v", latest)
	}
	var none []store.CoverageEntry
	if getJSON(t, ts, "/api/coverage?scan_id=scan-1", &none) != 200 || len(none) != 0 {
		t.Errorf("scan-1 has no coverage rows: %v", none)
	}
	var scans []struct {
		ScanID     string         `json:"scan_id"`
		BySeverity map[string]int `json:"by_severity"`
		Failed     int            `json:"failed"`
	}
	if getJSON(t, ts, "/api/scans", &scans) != 200 || len(scans) != 2 {
		t.Fatalf("scans: %v", scans)
	}
	if scans[0].ScanID != "scan-2" || scans[1].ScanID != "scan-1" {
		t.Errorf("scan history must be newest first: %v", scans)
	}
	if scans[1].BySeverity["CRITICAL"] != 1 || scans[1].BySeverity["LOW"] != 1 || scans[0].BySeverity["CRITICAL"] != 1 {
		t.Errorf("per-severity counts: %+v", scans)
	}
	if getJSON(t, ts, "/api/scans?limit=1", &scans) != 200 || len(scans) != 1 {
		t.Errorf("limit: %v", scans)
	}
}

func TestFindingsIncludeResolved(t *testing.T) {
	s, f := seedLifecycle(t)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	var cur, all []model.Finding
	getJSON(t, ts, "/api/findings", &cur)
	getJSON(t, ts, "/api/findings?include_resolved=1", &all)
	has := func(fs []model.Finding, id string) bool {
		for _, x := range fs {
			if x.ID == id {
				return true
			}
		}
		return false
	}
	logging := s.st.ExternalFindingID(f["logging"].ID) // the API shows keyed ids (W6-VERIFY r4 #15)
	if has(cur, logging) || !has(all, logging) || len(all) != len(cur)+1 {
		t.Errorf("include_resolved: current %d, all %d", len(cur), len(all))
	}
}

// The new routes sit behind the same Host / token middleware as the rest of /api.
func TestNewRoutesBehindGuards(t *testing.T) {
	s, _ := seedLifecycle(t)
	s.Token = "secret-token-1"
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	for _, p := range []string{"/api/issues", "/api/issues/x", "/api/coverage", "/api/scans", "/api/findings?include_resolved=1"} {
		if got := send(t, "GET", ts.URL+p, "", nil).StatusCode; got != 401 {
			t.Errorf("%s without token: %d, want 401", p, got)
		}
		if got := send(t, "GET", ts.URL+p, "", map[string]string{"Authorization": "Bearer secret-token-1", "Host": "evil.example"}).StatusCode; got != 421 {
			t.Errorf("%s with foreign Host: %d, want 421", p, got)
		}
		if got := send(t, "GET", ts.URL+p, "", map[string]string{"Authorization": "Bearer secret-token-1"}).StatusCode; got == 401 || got == 421 {
			t.Errorf("%s with token: %d", p, got)
		}
		if got := send(t, "POST", ts.URL+p, "{}", map[string]string{"Authorization": "Bearer secret-token-1", "Origin": "https://evil.example"}).StatusCode; got != 403 {
			t.Errorf("cross-site POST %s: %d, want 403", p, got)
		}
	}
}

func TestValidateBindRejectsWhitespaceToken(t *testing.T) {
	if err := ValidateBind("0.0.0.0:8080", "   "); err == nil {
		t.Error("a whitespace-only token must not unlock a non-loopback bind")
	}
	if err := ValidateBind("0.0.0.0:8080", "real-token"); err != nil {
		t.Error(err)
	}
}
