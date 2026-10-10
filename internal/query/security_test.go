package query

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func seededStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := model.Finding{Source: "prowler", CheckID: "x", CanonicalID: "RDS_PUBLIC", Title: "RDS public", Severity: model.Critical, Status: model.Fail, Provider: "aws", Account: "1",
		Resource: model.Resource{ID: "arn:aws:rds:::db:pay", Type: "aws_db_instance", Name: "pay"}, Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"}}
	f.Finalize(time.Now())
	if err := st.UpsertFindings([]model.Finding{f}); err != nil {
		t.Fatal(err)
	}
	return st
}

func findingCount(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow("SELECT COUNT(*) FROM findings").Scan(&n); err != nil {
		t.Fatalf("findings table damaged: %v", err)
	}
	return n
}

// runWithin runs query.Run and fails (instead of hanging) when it does not return in time.
func runWithin(t *testing.T, limit time.Duration, ctx context.Context, st *store.Store, sql string) (*Result, error) {
	t.Helper()
	type out struct {
		r   *Result
		err error
	}
	ch := make(chan out, 1)
	go func() { r, err := Run(ctx, st, sql, "local"); ch <- out{r, err} }()
	select {
	case o := <-ch:
		return o.r, o.err
	case <-time.After(limit):
		t.Fatalf("query did not return within %s: %s", limit, sql)
		return nil, nil
	}
}

// TestReadOnlyGuardBlocksBypasses reproduces inventory defect 1: each payload got past the old
// substring denylist on a read-write connection.
func TestReadOnlyGuardBlocksBypasses(t *testing.T) {
	st := seededStore(t)
	evil := filepath.Join(t.TempDir(), "evil.db")
	payloads := map[string]string{
		"cte+delete":          "WITH x AS (SELECT 1)\nDELETE FROM findings",
		"dashdash-multi":      "SELECT '--';DELETE FROM findings",
		"dashdash-create":     "SELECT '--';CREATE TABLE pwned(x)",
		"attach":              "ATTACH DATABASE '" + evil + "' AS evil",
		"attach-in-select":    "SELECT 1; ATTACH DATABASE '" + evil + "' AS evil",
		"pragma":              "PRAGMA writable_schema=1",
		"pragma-fn":           "SELECT * FROM pragma_table_info('findings')",
		"sqlite_master":       "SELECT sql FROM sqlite_master",
		"sqlite_schema-quote": `SELECT sql FROM "sqlite_schema"`,
		"sqlite_temp_master":  "SELECT * FROM sqlite_temp_master",
		"main.sqlite_master":  "SELECT name FROM main.sqlite_master",
		"string-as-table":     "SELECT sql FROM 'sqlite_master'",
		"replace-into":        "REPLACE INTO findings(id) VALUES('x')",
		"block-comment-multi": "SELECT 1 /* ; */ ; DELETE FROM findings",
	}
	for name, sql := range payloads {
		t.Run(name, func(t *testing.T) {
			res, err := runWithin(t, 5*time.Second, context.Background(), st, sql)
			if err == nil {
				t.Errorf("payload accepted (rows=%v): %s", res.Rows, sql)
			}
			if n := findingCount(t, st); n != 1 {
				t.Fatalf("findings mutated by %q: count=%d", sql, n)
			}
			if st.TableExists("pwned") {
				t.Fatalf("table created by %q", sql)
			}
			if _, err := os.Stat(evil); err == nil {
				t.Fatalf("ATTACH created %s", evil)
			}
		})
	}
}

func TestReadOnlyGuardAllowsLegitimateQueries(t *testing.T) {
	st := seededStore(t)
	for _, sql := range []string{
		"SELECT provider, severity, count FROM findings_summary",
		"select count(*) from findings -- trailing comment",
		"WITH f AS (SELECT * FROM findings) SELECT title FROM f;",
		"SELECT 'DELETE FROM findings; --' AS s",
		"SELECT name, internet_exposed FROM aws_db_instances",
		"SELECT f.title, fw.key FROM findings f, json_each(f.compliance) fw",
	} {
		res, err := runWithin(t, 5*time.Second, context.Background(), st, sql)
		if err != nil {
			t.Errorf("%q rejected: %v", sql, err)
			continue
		}
		if len(res.Rows) == 0 && !strings.Contains(sql, "json_each") {
			t.Errorf("%q returned no rows", sql)
		}
	}
	res, _ := runWithin(t, 5*time.Second, context.Background(), st, "SELECT provider, count FROM findings_summary")
	if len(res.Rows) != 1 || res.Rows[0][0] != "aws" || res.Rows[0][1] != int64(1) {
		t.Errorf("findings_summary: %+v", res.Rows)
	}
}

// TestQueryTimeoutInterruptsRunawaySQL: the deadline must interrupt SQLite itself, both while the
// first row is computed and while later rows are stepped.
func TestQueryTimeoutInterruptsRunawaySQL(t *testing.T) {
	st := seededStore(t)
	for _, sql := range []string{
		// ~10 s+ of work before the first row
		"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 2000000000) SELECT count(*) FROM c",
		// first row is immediate, the second never comes
		"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT x FROM c WHERE x = 1 OR x < 0",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		start := time.Now()
		_, err := runWithin(t, 5*time.Second, ctx, st, sql)
		cancel()
		if err == nil {
			t.Errorf("runaway query returned no error: %s", sql)
		} else if !strings.Contains(strings.ToLower(err.Error()), "timeout") && !strings.Contains(strings.ToLower(err.Error()), "deadline") {
			t.Errorf("want a timeout error, got %v", err)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Errorf("query ran %s past a 400ms deadline", el)
		}
	}
	// the store is still usable afterwards
	if _, err := runWithin(t, 5*time.Second, context.Background(), st, "SELECT count(*) FROM findings"); err != nil {
		t.Errorf("store unusable after timeout: %v", err)
	}
}

// N4: /api/schema is the allowlist; virtual tables, their shadow tables and *_config tables are
// neither listed nor queryable, and everything listed runs under the engine limits.
func TestSchemaIsTheQueryAllowlist(t *testing.T) {
	st := seededStore(t)
	for _, ddl := range []string{"CREATE VIRTUAL TABLE notes USING fts5(body)", "INSERT INTO notes VALUES ('secret')", "CREATE TABLE app_config(k, v)"} {
		if _, err := st.DB().Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	sch, err := Schema(st)
	if err != nil {
		t.Fatal(err)
	}
	for name := range sch {
		if strings.HasPrefix(name, "notes") || name == "app_config" || strings.HasPrefix(name, "sqlite_") {
			t.Errorf("schema lists %q", name)
		}
	}
	for _, q := range []string{"SELECT * FROM notes", "SELECT * FROM notes_content", "SELECT * FROM notes_config", "SELECT * FROM app_config", "SELECT * FROM dbstat"} {
		if _, err := runWithin(t, 5*time.Second, context.Background(), st, q); err == nil {
			t.Errorf("accepted %q", q)
		}
	}
	if len(sch) < 10 {
		t.Fatalf("schema too small: %v", sch)
	}
	for name := range sch {
		if _, err := runWithin(t, 5*time.Second, context.Background(), st, `SELECT * FROM "`+name+`" LIMIT 5`); err != nil {
			t.Errorf("schema object %q not queryable under the read-only limits: %v", name, err)
		}
	}
}

// N1: huge values are refused fast through the query entry point too.
func TestRunRefusesHugeValuesFast(t *testing.T) {
	st := seededStore(t)
	start := time.Now()
	cpu0, cpuOK := processCPU()
	_, err := runWithin(t, 30*time.Second, context.Background(), st, "SELECT length(randomblob(1000000000))")
	if err == nil || !strings.Contains(err.Error(), "too big") {
		t.Errorf("want 'too big', got %v", err)
	}
	// The point is "rejected before the blob is built": building a 1 GB blob costs seconds of CPU
	// and a GB of memory, the refusal costs milliseconds. Wall-clock bounds flaked under load
	// (500 ms: 577 ms in Verification 5; 2 s after W6 on a loaded machine), so the bound is on
	// process CPU time (1 s; the refusal uses ~10 ms), which other processes cannot inflate. The
	// wall bound stays only as a hang guard (runWithin's 30 s) where CPU time is unavailable.
	if cpu1, ok := processCPU(); ok && cpuOK {
		if el := cpu1 - cpu0; el > time.Second {
			t.Errorf("refusal used %s of CPU (> 1 s): the blob was built", el)
		}
	} else if el := time.Since(start); el > 10*time.Second {
		t.Errorf("took %s", el)
	}
}
