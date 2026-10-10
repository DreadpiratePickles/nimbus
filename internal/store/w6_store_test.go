package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W6-VERIFY r4 #15 (Go-migrates-Python-DB guard) and #12 (per-scan Issue trend).

const pythonSchema = `CREATE TABLE findings (id TEXT PRIMARY KEY, source TEXT NOT NULL, check_id TEXT NOT NULL, canonical_id TEXT NOT NULL,
  title TEXT, description TEXT, severity TEXT NOT NULL, status TEXT NOT NULL, provider TEXT NOT NULL, account TEXT, region TEXT,
  resource_id TEXT, resource_type TEXT, resource_name TEXT, file TEXT, line_start INTEGER, line_end INTEGER, remediation TEXT,
  weaknesses TEXT, compliance TEXT, tags TEXT, scan_id TEXT, first_seen TEXT, last_seen TEXT, doc TEXT NOT NULL);
CREATE TABLE scans (id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT, doc TEXT NOT NULL);`

func rawDB(t *testing.T, path, ddl string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(ddl); err != nil {
		t.Fatal(err)
	}
}

func tableExists(t *testing.T, path, name string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name = ?", name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func withPolicy(t *testing.T, p ForeignPolicy) {
	t.Helper()
	prev := SetForeignPolicy(p)
	t.Cleanup(func() { SetForeignPolicy(prev) })
}

func TestReadOnlyOpenNeverMigratesPythonBuiltDB(t *testing.T) {
	for name, ddl := range map[string]string{
		"marked":   pythonSchema + "CREATE TABLE store_meta (k TEXT PRIMARY KEY, v BLOB NOT NULL); INSERT INTO store_meta VALUES ('built_by', 'python');",
		"unmarked": pythonSchema, // Python-built before the marker existed
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "py.db")
			rawDB(t, path, ddl)
			withPolicy(t, ForeignPolicy{Allow: false})
			st, err := Open(path)
			if err == nil {
				st.Close()
				t.Fatal("a read-only open migrated a Python-built database")
			}
			var fe *ForeignDBError
			if !errors.As(err, &fe) || !errors.Is(err, ErrForeignDB) || !strings.Contains(err.Error(), "ingest") {
				t.Fatalf("error = %v, want ForeignDBError naming ingest/scan", err)
			}
			for _, tb := range []string{"schema_migrations", "issues", "graph_nodes"} {
				if tableExists(t, path, tb) {
					t.Errorf("read-only open created %s", tb)
				}
			}
			var notice bytes.Buffer
			withPolicy(t, ForeignPolicy{Allow: true, Notice: &notice})
			st, err = Open(path)
			if err != nil {
				t.Fatalf("ingest/scan open: %v", err)
			}
			st.Close()
			if !strings.Contains(notice.String(), "Python") || !strings.Contains(notice.String(), "upgrad") {
				t.Errorf("migration notice = %q", notice.String())
			}
			// Now Go-built: a read-only open works and prints nothing.
			notice.Reset()
			withPolicy(t, ForeignPolicy{Allow: false, Notice: &notice})
			st, err = Open(path)
			if err != nil {
				t.Fatalf("read-only open after the upgrade: %v", err)
			}
			if o, _ := st.Origin(); o != OriginGo {
				t.Errorf("origin after upgrade = %q", o)
			}
			st.Close()
			if notice.Len() != 0 {
				t.Errorf("notice on a Go database: %q", notice.String())
			}
		})
	}
}

func TestReadOnlyOpenStillUpgradesGoDBs(t *testing.T) {
	withPolicy(t, ForeignPolicy{Allow: false})
	path := filepath.Join(t.TempDir(), "new.db")
	st, err := Open(path) // a new database is created and marked
	if err != nil {
		t.Fatal(err)
	}
	if o, _ := st.Origin(); o != OriginGo {
		t.Errorf("new database origin %q", o)
	}
	st.Close()
	// A Go database from before the marker (schema_migrations, no built_by) is Go-built.
	db, _ := sql.Open("sqlite", path)
	db.Exec("DELETE FROM store_meta WHERE k = 'built_by'")
	db.Close()
	st, err = Open(path)
	if err != nil {
		t.Fatalf("legacy Go database refused: %v", err)
	}
	st.Close()
}

func trendScan(t *testing.T, st *Store, scan string, at time.Time, fs ...model.Finding) *Diff {
	t.Helper()
	all := []model.Finding{mkFinding("prowler", "a", "CHECK_A", "arn:aws:s3:::a", model.High), mkFinding("prowler", "b", "CHECK_B", "arn:aws:s3:::b", model.High), mkFinding("prowler", "c", "CHECK_C", "arn:aws:s3:::c", model.High)}
	d, err := st.ApplyScan(scan, fs, at, ApplyOptions{Scopes: ScopesOf(all)})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(at); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveScan(model.ScanSummary{ScanID: scan, StartedAt: at, FinishedAt: at.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestScanTrendCountsPerScan(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a := mkFinding("prowler", "a", "CHECK_A", "arn:aws:s3:::a", model.High)
	b := mkFinding("prowler", "b", "CHECK_B", "arn:aws:s3:::b", model.High)
	c := mkFinding("prowler", "c", "CHECK_C", "arn:aws:s3:::c", model.High)
	trendScan(t, st, "s1", t0, a, b, c)             // 3 new
	trendScan(t, st, "s2", t0.Add(time.Hour), b, c) // a resolved
	idOf := func(canonical string) string {
		is, _ := st.Issues(IssueFilter{})
		for _, i := range is {
			if i.CanonicalID == canonical {
				return i.ID
			}
		}
		t.Fatalf("no Issue %s", canonical)
		return ""
	}
	verifyFixed(t, st, idOf("CHECK_B"), t0.Add(90*time.Minute)) // b verified between s2 and s3
	verifyFixed(t, st, idOf("CHECK_C"), t0.Add(95*time.Minute)) // c verified, then seen again
	d := trendScan(t, st, "s3", t0.Add(2*time.Hour), a, c)      // a reopened, b stays verified, c regressed

	rows, err := st.ScanTrends(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].ScanID != "s3" {
		t.Fatalf("trend rows = %+v", rows)
	}
	want := map[string]ScanTrend{
		"s1": {New: 3, Open: 3},
		"s2": {Resolved: 1, Open: 2},
		"s3": {Reopened: 1, VerifiedFixed: 2, Regressed: 1, Open: 2},
	}
	for _, r := range rows {
		if r.Trend == nil {
			t.Fatalf("scan %s has no trend", r.ScanID)
		}
		got := *r.Trend
		got.VerifiedShare = 0
		if got != want[r.ScanID] {
			t.Errorf("scan %s trend = %+v, want %+v", r.ScanID, got, want[r.ScanID])
		}
	}
	// After s3 the only closed Issue is b (verified_fixed); a reopened: every closure is verified.
	if rows[0].Trend.VerifiedShare != 1 || rows[1].Trend.VerifiedShare != 0 {
		t.Errorf("verified share s3 %v (want 1), s2 %v (want 0: a resolved by absence)", rows[0].Trend.VerifiedShare, rows[1].Trend.VerifiedShare)
	}
	if d.Issues == nil || d.Issues.Reopened != 1 || d.Issues.Regressed != 1 {
		t.Errorf("the scan's Diff does not carry the Issue trend: %+v", d.Issues)
	}
	if !strings.Contains(d.Issues.Text(), "1 reopened") || !strings.Contains(d.Issues.Text(), "2 verified fixed") {
		t.Errorf("trend text = %q", d.Issues.Text())
	}
	// A scan saved by another writer (Python) has no trend columns: nil, not zeros.
	if _, err := st.DB().Exec("INSERT INTO scans (id, started_at, finished_at, doc) VALUES ('py', '2026-10-02T00:00:00Z', '2026-10-02T00:00:00Z', '{}')"); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.ScanTrends(1)
	if len(rows) != 1 || rows[0].ScanID != "py" || rows[0].Trend != nil {
		t.Errorf("python scan row = %+v", rows)
	}
}

// r4 #15 / Verification 6: external finding ids are keyed per database; a stored raw
// fingerprint still resolves (old ids in tickets), and hashing candidate accounts never
// reproduces an external id.
func TestExternalFindingIDsKeyedAndResolvable(t *testing.T) {
	st := openTemp(t)
	f := model.Finding{Source: "prowler", CheckID: "s3_bucket_public_access", Provider: "aws", Account: "123456789012", Region: "us-east-1",
		Severity: model.High, Status: model.Fail, Resource: model.Resource{ID: "arn:aws:s3:::pii", Type: "aws_s3_bucket"}}
	f.Finalize(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if _, err := st.ApplyScan("s1", []model.Finding{f}, time.Now(), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	raw := f.ID
	ext := st.ExternalFindingID(raw)
	if ext == raw || len(ext) != len(raw) || !IsDigestID(ext) {
		t.Fatalf("external id %q for raw %q", ext, raw)
	}
	other := openTemp(t)
	if other.ExternalFindingID(raw) == ext {
		t.Errorf("external ids equal across databases")
	}
	if got, ok := st.ResolveFindingID(ext); !ok || got != raw {
		t.Errorf("resolve external = %q %v", got, ok)
	}
	if got, ok := st.ResolveFindingID(raw); !ok || got != raw {
		t.Errorf("an old raw fingerprint must keep resolving: %q %v", got, ok)
	}
	if _, ok := st.ResolveFindingID("0123456789abcdef0123456789abcdef"); ok {
		t.Errorf("unknown id resolved")
	}
	m, err := st.IDMapper()
	if err != nil {
		t.Fatal(err)
	}
	if got := m.MapString(`{"finding_ids":["` + raw + `"],"x":"lab-W01"}`); got != `{"finding_ids":["`+ext+`"],"x":"lab-W01"}` {
		t.Errorf("MapString = %s", got)
	}
	if m.Ext(ext) != ext || m.MapString(m.MapString(raw)) != ext {
		t.Errorf("mapping is not idempotent")
	}
	// Dictionary attack (the Verification 6 probe's method) over a window around the account.
	for acct := 123456700000; acct < 123456800000; acct++ {
		c := f
		c.Account = fmt.Sprint(acct)
		if c.Fingerprint() == ext {
			t.Fatalf("external id reproduced from account %d", acct)
		}
	}
}
