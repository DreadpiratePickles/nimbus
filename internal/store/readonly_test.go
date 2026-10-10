package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// TestReadOnlyEngineLayers checks each engine-side layer on its own, i.e. without the lexer,
// so a lexer bug alone cannot reopen defect 1.
func TestReadOnlyEngineLayers(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ro.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	f := model.Finding{Source: "x", CheckID: "x", CanonicalID: "X", Severity: model.High, Status: model.Fail, Provider: "aws", Resource: model.Resource{ID: "r", Type: "aws_s3_bucket"}}
	f.Finalize(time.Now())
	st.UpsertFindings([]model.Finding{f})
	ctx := context.Background()

	db, conn, handle := openRO(t, st)
	defer db.Close()
	defer conn.Close()

	// mode=ro + query_only: the engine refuses writes even when handed one directly.
	if _, err := conn.ExecContext(ctx, "DELETE FROM findings"); err == nil {
		t.Error("read-only connection accepted DELETE")
	}
	// prepare: SQLite's own tail says there is a second statement.
	for _, q := range []string{"SELECT 1; DELETE FROM findings", "SELECT '--';CREATE TABLE p(x)", "SELECT 1;/*c*/SELECT 2"} {
		if err := prepareCheck(conn, handle, q); !errors.Is(err, ErrUnsafeSQL) {
			t.Errorf("prepareCheck(%q) = %v, want ErrUnsafeSQL", q, err)
		}
	}
	for _, q := range []string{"SELECT 1;", "SELECT 1; -- done", "SELECT 1 /* x */ ;  "} {
		if err := prepareCheck(conn, handle, q); err != nil {
			t.Errorf("prepareCheck(%q) = %v, want nil", q, err)
		}
	}
	// bytecode: schema tables are not on the allowlist.
	allow, err := loadQueryable(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"SELECT * FROM sqlite_master", "SELECT * FROM sqlite_temp_master"} {
		if err := checkBytecode(ctx, conn, q, allow); !errors.Is(err, ErrUnsafeSQL) {
			t.Errorf("checkBytecode(%q) = %v, want ErrUnsafeSQL", q, err)
		}
	}
	if err := checkBytecode(ctx, conn, "SELECT id FROM findings WHERE id = 'x'", allow); err != nil {
		t.Errorf("checkBytecode(findings) = %v", err)
	}
	var n int
	st.DB().QueryRow("SELECT COUNT(*) FROM findings").Scan(&n)
	if n != 1 {
		t.Fatalf("findings changed: %d", n)
	}
}

func TestCheckReadOnlySQLLexer(t *testing.T) {
	ok := []string{"SELECT 1", "with a as (select 1) select * from a;", "SELECT ';' AS x", `SELECT "a;b" FROM findings`, "VALUES (1)"}
	bad := []string{"", ";", "DELETE FROM findings", "SELECT 1; SELECT 2", "SELECT '--';DROP TABLE findings", "ATTACH 'x' AS y",
		"SELECT * FROM [sqlite_master]", "SELECT * FROM `sqlite_schema`", "SELECT * FROM pragma_table_list", "SELECT 'unterminated",
		"EXPLAIN SELECT 1", "PRAGMA query_only=0"}
	for _, q := range ok {
		if err := CheckReadOnlySQL(q); err != nil {
			t.Errorf("CheckReadOnlySQL(%q) = %v", q, err)
		}
	}
	for _, q := range bad {
		if err := CheckReadOnlySQL(q); !errors.Is(err, ErrUnsafeSQL) {
			t.Errorf("CheckReadOnlySQL(%q) accepted", q)
		}
	}
}

func openRO(t *testing.T, st *Store) (*sql.DB, *sql.Conn, uintptr) {
	t.Helper()
	db, err := sql.Open("sqlite", st.readOnlyDSN())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h, err := sqliteHandle(conn)
	if err != nil {
		t.Fatal(err)
	}
	return db, conn, h
}

// ---------------------------------------------------------------- Track A2 (verifier follow-ups)

func seededRO(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "ro2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := model.Finding{Source: "x", CheckID: "x", CanonicalID: "X", Severity: model.High, Status: model.Fail, Provider: "aws", Resource: model.Resource{ID: "r", Type: "aws_s3_bucket"}}
	f.Finalize(time.Now())
	if err := st.UpsertFindings([]model.Finding{f}); err != nil {
		t.Fatal(err)
	}
	return st
}

// roWithin runs QueryReadOnly and fails the test instead of hanging past limit.
func roWithin(t *testing.T, limit time.Duration, st *Store, q string, opts ReadOnlyOptions) (*ReadOnlyResult, error, time.Duration) {
	t.Helper()
	type out struct {
		r   *ReadOnlyResult
		err error
	}
	ch := make(chan out, 1)
	start := time.Now()
	go func() { r, err := st.QueryReadOnly(context.Background(), q, opts); ch <- out{r, err} }()
	select {
	case o := <-ch:
		return o.r, o.err, time.Since(start)
	case <-time.After(limit):
		t.Fatalf("query did not return within %s: %s", limit, q)
		return nil, nil, 0
	}
}

// N1: one SQLite function call cannot be interrupted, so huge values must be refused by
// SQLITE_LIMIT_LENGTH before they are built.
func TestReadOnlyLengthLimitRejectsHugeValues(t *testing.T) {
	st := seededRO(t)
	for _, q := range []string{
		"SELECT length(randomblob(1000000000))",
		"SELECT length(zeroblob(1000000000))",
		"SELECT length(printf('%.*c', 1000000000, 'x'))",
		"SELECT length(replace(hex(zeroblob(1000)), '0', hex(zeroblob(1000))))",
	} {
		res, err, el := roWithin(t, 30*time.Second, st, q, ReadOnlyOptions{Timeout: 3 * time.Second})
		// SQLite's printf() yields NULL instead of an error when its output would be too big.
		nullResult := err == nil && len(res.Rows) == 1 && res.Rows[0][0] == nil
		if !nullResult && (err == nil || !strings.Contains(err.Error(), "too big")) {
			t.Errorf("%s: want a 'string or blob too big' error (or NULL), got %v %v", q, res, err)
		}
		if el > 100*time.Millisecond {
			t.Errorf("%s: took %s, want < 100ms", q, el)
		}
	}
}

// N1: three concurrent abusive requests must not delay an honest SELECT 1.
func TestReadOnlyHugeValuesDoNotStarveOthers(t *testing.T) {
	st := seededRO(t)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.QueryReadOnly(context.Background(), "SELECT length(randomblob(1000000000))", ReadOnlyOptions{Timeout: 3 * time.Second})
		}()
	}
	time.Sleep(20 * time.Millisecond)
	res, err, el := roWithin(t, 60*time.Second, st, "SELECT 1", ReadOnlyOptions{})
	if err != nil || len(res.Rows) != 1 {
		t.Fatalf("SELECT 1: %v %v", res, err)
	}
	if el > 200*time.Millisecond {
		t.Errorf("SELECT 1 took %s behind abusive queries, want < 200ms", el)
	}
	wg.Wait()
}

// Every engine limit is set on the read-only connection (read back through the reflected
// handle, which also proves it is the same connection the public sqlite.Limit API changed).
func TestReadOnlyConnectionLimits(t *testing.T) {
	st := seededRO(t)
	db, conn, h, err := st.openReadOnly(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer conn.Close()
	for id, want := range readOnlyLimits {
		if got := limitOf(h, id); got != want {
			t.Errorf("limit %d = %d, want %d", id, got, want)
		}
	}
	for _, q := range []string{
		"SELECT '" + strings.Repeat("a", 70<<10) + "'",          // SQL_LENGTH
		"SELECT 1" + strings.Repeat(" UNION ALL SELECT 1", 100), // COMPOUND_SELECT
	} {
		if _, err := st.QueryReadOnly(context.Background(), q, ReadOnlyOptions{}); err == nil {
			t.Errorf("over-limit query accepted (%d bytes)", len(q))
		}
	}
}

// The reflected sqlite3* must be the store's own database, or every query is refused.
func TestReadOnlyHandleSelfCheck(t *testing.T) {
	a, b := seededRO(t), seededRO(t)
	db, conn, hb, err := b.openReadOnly(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer conn.Close()
	if err := verifyHandle(conn, hb, b.path); err != nil {
		t.Fatalf("own handle rejected: %v", err)
	}
	if err := verifyHandle(conn, hb, a.path); err == nil {
		t.Fatal("handle of another database file accepted")
	}
}

// N1: a per-store cap on in-flight read-only queries; excess requests fail fast (HTTP 429).
func TestReadOnlyConcurrencyCap(t *testing.T) {
	st := seededRO(t)
	runaway := "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c"
	var wg sync.WaitGroup
	for i := 0; i < MaxConcurrentReadOnly; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.QueryReadOnly(context.Background(), runaway, ReadOnlyOptions{Timeout: 1500 * time.Millisecond})
		}()
	}
	time.Sleep(300 * time.Millisecond)
	_, err, el := roWithin(t, 5*time.Second, st, "SELECT 1", ReadOnlyOptions{})
	if !errors.Is(err, ErrQueryBusy) {
		t.Errorf("query over the cap: got %v, want ErrQueryBusy", err)
	}
	if el > 100*time.Millisecond {
		t.Errorf("busy rejection took %s", el)
	}
	wg.Wait()
	if _, err, _ := roWithin(t, 5*time.Second, st, "SELECT 1", ReadOnlyOptions{}); err != nil {
		t.Errorf("slots not released: %v", err)
	}
}

// N4: only json_each/json_tree virtual tables; no dbstat, FTS tables or their shadow tables.
func TestReadOnlyVirtualTableAllowlist(t *testing.T) {
	st := seededRO(t)
	for _, ddl := range []string{
		"CREATE VIRTUAL TABLE ft USING fts5(a)",
		"INSERT INTO ft VALUES ('secret words')",
		"CREATE VIEW fjson AS SELECT f.id, j.value FROM findings f, json_each(f.weaknesses) j",
		"CREATE TABLE app_config(k, v)",
	} {
		if _, err := st.DB().Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	bad := []string{
		"SELECT * FROM dbstat", "SELECT * FROM main.dbstat", "SELECT * FROM dbstat AS json_each",
		"SELECT * FROM 'dbstat'", `SELECT * FROM "DBSTAT"`, "SELECT * FROM findings WHERE id IN (SELECT name FROM dbstat)",
		"SELECT * FROM sqlite_dbpage", "SELECT * FROM sqlite_stmt",
		"SELECT * FROM ft", "SELECT * FROM ft WHERE ft MATCH 'secret'", "SELECT * FROM ft_config", "SELECT * FROM ft_data",
		"SELECT * FROM ft_content", "SELECT * FROM ft_idx", "SELECT * FROM ft_docsize", "SELECT * FROM app_config",
		"SELECT * FROM fts5vocab", "WITH x AS (SELECT * FROM 'ft_content') SELECT * FROM x",
	}
	for _, q := range bad {
		if res, err, _ := roWithin(t, 5*time.Second, st, q, ReadOnlyOptions{}); err == nil {
			t.Errorf("accepted %q: %v", q, res.Rows)
		}
	}
	good := []string{
		"SELECT * FROM fjson",
		"SELECT key FROM json_each('[1,2]') AS dbstat_like",
		"SELECT f.id FROM findings f, json_tree(f.weaknesses) t",
		"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 10) SELECT count(*) FROM c",
	}
	for _, q := range good {
		if _, err, _ := roWithin(t, 5*time.Second, st, q, ReadOnlyOptions{}); err != nil {
			t.Errorf("rejected %q: %v", q, err)
		}
	}
	names, err := st.QueryableTables()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if strings.HasPrefix(n, "ft") || n == "app_config" || strings.HasPrefix(n, "sqlite_") {
			t.Errorf("QueryableTables lists %q", n)
		}
	}
	if !contains(names, "findings") || !contains(names, "fjson") {
		t.Errorf("QueryableTables = %v", names)
	}
}

// The prepare out-parameters live in C memory per call: concurrent prepares are safe without
// a process-wide lock (run with -race).
func TestPrepareCheckConcurrent(t *testing.T) {
	st := seededRO(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := st.QueryReadOnly(context.Background(), "SELECT id FROM findings; -- tail", ReadOnlyOptions{}); err != nil && !errors.Is(err, ErrQueryBusy) {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
