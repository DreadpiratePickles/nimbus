package store

// Read-only SQL for untrusted callers (POST /api/query, `cloud-posture query`, copilots).
//
// Threat model: the SQL text is attacker-controlled (any holder of the API token, or any local
// process when no token is set). It must not write, must not read anything outside the tables and
// views that /api/schema lists, must not touch other files, and must not exhaust CPU/memory or
// starve other callers. Enforcement is layered so that no single check is load-bearing:
//
//  1. Lexer (CheckReadOnlySQL): one SELECT/WITH/VALUES statement; no ATTACH/DETACH/PRAGMA; no
//     sqlite_*/pragma_* names; no names of non-queryable schema objects (virtual tables, their
//     shadow tables, *_config tables) or of virtual-table modules other than json_each/json_tree.
//  2. Admission: at most MaxConcurrentReadOnly queries per database are in flight; more fail
//     fast with ErrQueryBusy (HTTP 429) instead of queueing behind an abusive client.
//  3. Separate connection: `mode=ro` + PRAGMA query_only=1, so the engine refuses writes. This is
//     NOT sufficient on its own: verified on modernc v1.39.0, ATTACH of a new path still creates
//     a 0-byte file and ATTACH of an existing file makes it readable, VACUUM INTO creates a
//     0-byte file, and PRAGMA query_only=0 is accepted. Those are stopped by layers 1 and 5 and by
//     SQLITE_LIMIT_ATTACHED=0 (layer 4).
//  4. Engine limits (sqlite3_limit via modernc's public sqlite.Limit): values are capped at 1 MiB,
//     SQL text at 64 KiB, no attached databases, and tight caps on columns, compound SELECTs,
//     VDBE program size, function arguments, LIKE patterns, variables, triggers and expression
//     depth. A single SQLite function call (randomblob, zeroblob, printf, replace, ...) cannot be
//     interrupted, so size caps are the only defence against one call running for minutes.
//  5. Handle self-check: the sqlite3* is read from the driver by reflection (modernc does not
//     export it). Before use it must report the store's own file (sqlite3_db_filename) and the
//     limits just set through the public API (sqlite3_limit), else every query is refused.
//  6. Prepare: SQLite parses the text; the unused tail must be empty (exactly one statement) and
//     sqlite3_stmt_readonly must hold. Out-parameters live in C memory (sqlite3_malloc), so no Go
//     pointer is handed to transpiled C and no process-wide lock is needed.
//  7. Bytecode (EXPLAIN): every b-tree opened (OpenRead/ReopenIdx) must be a root page of a
//     queryable table or its index in the main schema; every virtual-table cursor (VOpen) must be
//     the connection's eponymous json_each/json_tree table (matched by vtab pointer, so aliases
//     such as `dbstat AS json_each` do not help); write/schema opcodes are refused.
//  8. Deadline: sqlite3_interrupt is called when the deadline passes, also between later steps
//     (modernc's context cancellation only covers the first step).

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"modernc.org/libc"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrUnsafeSQL is matched (errors.Is) by every rejection of a read-only query.
var ErrUnsafeSQL = errors.New("unsafe SQL")

// UnsafeSQLError says why a query was rejected before it ran.
type UnsafeSQLError struct{ Reason string }

func (e *UnsafeSQLError) Error() string        { return "rejected: " + e.Reason }
func (e *UnsafeSQLError) Is(target error) bool { return target == ErrUnsafeSQL }

func unsafeSQL(format string, args ...any) error {
	return &UnsafeSQLError{Reason: fmt.Sprintf(format, args...)}
}

// ErrQueryTimeout is matched (errors.Is) when a read-only query hits its deadline (HTTP 408).
var ErrQueryTimeout = errors.New("query timeout")

// ErrQueryBusy is returned when MaxConcurrentReadOnly queries are already running against the
// same database (HTTP 429).
var ErrQueryBusy = errors.New("too many concurrent queries; retry shortly")

// ReadOnlyResult is the output of QueryReadOnly.
type ReadOnlyResult struct {
	Columns   []string
	Rows      [][]any
	Truncated bool // more than MaxRows rows were available
}

// ReadOnlyOptions bound a read-only query. Zero values pick the defaults.
type ReadOnlyOptions struct {
	Timeout time.Duration // used when ctx has no earlier deadline (default DefaultQueryTimeout)
	MaxRows int           // default DefaultMaxRows
}

const (
	DefaultQueryTimeout = 30 * time.Second
	DefaultMaxRows      = 10000
	// MaxConcurrentReadOnly caps in-flight read-only queries per database file.
	MaxConcurrentReadOnly = 4
	// MaxValueBytes is SQLITE_LIMIT_LENGTH on the read-only connection: no string or blob
	// (stored, computed or returned) may exceed it.
	MaxValueBytes = 1 << 20
	// MaxSQLBytes is SQLITE_LIMIT_SQL_LENGTH on the read-only connection.
	MaxSQLBytes = 64 << 10
)

// readOnlyLimits are applied to every read-only connection before any untrusted text is parsed.
var readOnlyLimits = map[int32]int32{
	sqlite3.SQLITE_LIMIT_LENGTH:              MaxValueBytes,
	sqlite3.SQLITE_LIMIT_SQL_LENGTH:          MaxSQLBytes,
	sqlite3.SQLITE_LIMIT_COLUMN:              1000,
	sqlite3.SQLITE_LIMIT_EXPR_DEPTH:          200,
	sqlite3.SQLITE_LIMIT_COMPOUND_SELECT:     64,
	sqlite3.SQLITE_LIMIT_VDBE_OP:             250000,
	sqlite3.SQLITE_LIMIT_FUNCTION_ARG:        100,
	sqlite3.SQLITE_LIMIT_ATTACHED:            0,
	sqlite3.SQLITE_LIMIT_LIKE_PATTERN_LENGTH: 1000,
	sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER:     32,
	sqlite3.SQLITE_LIMIT_TRIGGER_DEPTH:       1,
}

// allowedVTabs are the only virtual-table modules untrusted SQL may use (table-valued JSON functions).
var allowedVTabs = []string{"json_each", "json_tree"}

// deniedModules are always refused by name, whether or not this build registers them.
var deniedModules = []string{"dbstat", "sqlite_dbpage", "sqlite_stmt", "fts3", "fts4", "fts4aux", "fts5", "fts5vocab",
	"fts3tokenize", "rtree", "rtree_i32", "geopoly", "generate_series", "carray", "completion", "csv", "zipfile", "fsdir"}

// CheckReadOnlySQL is the lexical layer of QueryReadOnly. It never touches a database.
func CheckReadOnlySQL(sqlText string) error { return checkReadOnlySQL(sqlText, nil) }

// checkReadOnlySQL also refuses any word or quoted identifier in denied (lower-case names).
func checkReadOnlySQL(sqlText string, denied map[string]bool) error {
	if len(sqlText) > MaxSQLBytes {
		return unsafeSQL("query longer than %d bytes", MaxSQLBytes)
	}
	toks, err := lexSQL(sqlText)
	if err != nil {
		return unsafeSQL("%v", err)
	}
	for len(toks) > 0 && toks[len(toks)-1].kind == tokPunct && toks[len(toks)-1].text == ";" {
		toks = toks[:len(toks)-1]
	}
	if len(toks) == 0 {
		return unsafeSQL("empty query")
	}
	first := strings.ToUpper(toks[0].text)
	if toks[0].kind != tokWord || (first != "SELECT" && first != "WITH" && first != "VALUES") {
		return unsafeSQL("only a single SELECT / WITH query is allowed")
	}
	for _, t := range toks {
		switch t.kind {
		case tokPunct:
			if t.text == ";" {
				return unsafeSQL("multiple statements are not allowed")
			}
		case tokWord:
			switch strings.ToUpper(t.text) {
			case "ATTACH", "DETACH", "PRAGMA":
				return unsafeSQL("%s is not allowed", strings.ToUpper(t.text))
			}
		}
		if t.kind == tokWord || t.kind == tokIdent || t.kind == tokString {
			l := strings.ToLower(t.text)
			if strings.HasPrefix(l, "sqlite_") || strings.HasPrefix(l, "pragma_") {
				return unsafeSQL("internal table %q is not queryable", t.text)
			}
		}
		if t.kind == tokWord || t.kind == tokIdent {
			l := strings.ToLower(t.text)
			if denied[l] || isDeniedModule(l) {
				return unsafeSQL("%q is not queryable (see /api/schema)", t.text)
			}
		}
	}
	return nil
}

func isDeniedModule(l string) bool {
	for _, m := range deniedModules {
		if l == m {
			return true
		}
	}
	return false
}

var (
	roSlotsMu sync.Mutex
	roSlots   = map[string]chan struct{}{}
)

// acquireSlot admits at most MaxConcurrentReadOnly queries per database file; it never waits.
func (s *Store) acquireSlot() (release func(), ok bool) {
	roSlotsMu.Lock()
	ch, found := roSlots[s.path]
	if !found {
		ch = make(chan struct{}, MaxConcurrentReadOnly)
		roSlots[s.path] = ch
	}
	roSlotsMu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, true
	default:
		return nil, false
	}
}

// QueryReadOnly runs one untrusted SELECT on a separate read-only connection (see package doc).
func (s *Store) QueryReadOnly(ctx context.Context, sqlText string, opts ReadOnlyOptions) (*ReadOnlyResult, error) {
	if err := CheckReadOnlySQL(sqlText); err != nil {
		return nil, err
	}
	release, ok := s.acquireSlot()
	if !ok {
		return nil, ErrQueryBusy
	}
	defer release()
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultQueryTimeout
	}
	maxRows := opts.MaxRows
	if maxRows <= 0 {
		maxRows = DefaultMaxRows
	}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	db, conn, handle, err := s.openReadOnly(qctx)
	if err != nil {
		return nil, wrapQueryErr(qctx, ctx, timeout, err)
	}
	defer db.Close()
	defer conn.Close()

	// Interrupt SQLite when the deadline passes; stopped (and waited for) before the
	// connection closes so a late interrupt can never hit a freed handle.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-qctx.Done():
			tls := libc.NewTLS()
			sqlite3.Xsqlite3_interrupt(tls, handle)
			tls.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); wg.Wait() }()

	q, err := loadQueryable(qctx, conn)
	if err != nil {
		return nil, wrapQueryErr(qctx, ctx, timeout, err)
	}
	if err := checkReadOnlySQL(sqlText, q.denied); err != nil {
		return nil, err
	}
	if err := prepareCheck(conn, handle, sqlText); err != nil {
		return nil, err
	}
	if err := checkBytecode(qctx, conn, sqlText, q); err != nil {
		return nil, wrapQueryErr(qctx, ctx, timeout, err)
	}

	rows, err := conn.QueryContext(qctx, sqlText)
	if err != nil {
		return nil, wrapQueryErr(qctx, ctx, timeout, err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	res := &ReadOnlyResult{Columns: cols}
	for rows.Next() {
		if len(res.Rows) >= maxRows {
			res.Truncated = true
			break
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, wrapQueryErr(qctx, ctx, timeout, err)
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		res.Rows = append(res.Rows, vals)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapQueryErr(qctx, ctx, timeout, err)
	}
	if qctx.Err() != nil {
		return nil, wrapQueryErr(qctx, ctx, timeout, qctx.Err())
	}
	return res, nil
}

func wrapQueryErr(qctx, parent context.Context, timeout time.Duration, err error) error {
	if qctx.Err() != nil {
		if parent.Err() == context.Canceled {
			return fmt.Errorf("query cancelled: %w", context.Canceled)
		}
		return fmt.Errorf("query exceeded the %s timeout: %w", timeout, ErrQueryTimeout)
	}
	return err
}

// readOnlyDSN opens the same file as a read-only URI with query_only, so the engine itself
// refuses writes. This does not stop ATTACH/VACUUM INTO from creating empty files or ATTACH
// from reading other files (see layer 3 in the package doc); SQLITE_LIMIT_ATTACHED=0 and the
// lexer/prepare/bytecode layers do.
func (s *Store) readOnlyDSN() string {
	u := url.URL{Scheme: "file", Path: s.path, RawQuery: "mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"}
	return u.String()
}

// openReadOnly opens the read-only connection, applies readOnlyLimits through the public
// sqlite.Limit API and returns the verified sqlite3* handle. Callers close conn, then db.
func (s *Store) openReadOnly(ctx context.Context) (*sql.DB, *sql.Conn, uintptr, error) {
	db, err := sql.Open("sqlite", s.readOnlyDSN())
	if err != nil {
		return nil, nil, 0, err
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, nil, 0, err
	}
	fail := func(err error) (*sql.DB, *sql.Conn, uintptr, error) {
		conn.Close()
		db.Close()
		return nil, nil, 0, err
	}
	for id, v := range readOnlyLimits {
		if _, err := sqlite.Limit(conn, int(id), int(v)); err != nil {
			return fail(fmt.Errorf("read-only query: set limit %d: %w", id, err))
		}
	}
	handle, err := sqliteHandle(conn)
	if err != nil {
		return fail(err)
	}
	if err := verifyHandle(conn, handle, s.path); err != nil {
		return fail(err)
	}
	return db, conn, handle, nil
}

// sqliteHandle returns the sqlite3* behind a modernc connection. modernc does not export it,
// so it is read by reflection; an unexpected driver layout fails closed, and verifyHandle
// checks the value before it is used.
func sqliteHandle(conn *sql.Conn) (uintptr, error) {
	var h uintptr
	err := conn.Raw(func(dc any) error {
		v := reflect.ValueOf(dc)
		if v.Kind() == reflect.Pointer {
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct {
			return fmt.Errorf("read-only query: unsupported sqlite driver connection %T", dc)
		}
		f := v.FieldByName("db")
		if !f.IsValid() || f.Kind() != reflect.Uintptr || f.Uint() == 0 {
			return fmt.Errorf("read-only query: unsupported sqlite driver connection %T", dc)
		}
		h = uintptr(f.Uint())
		return nil
	})
	return h, err
}

// verifyHandle refuses a reflected handle unless (a) sqlite3_limit through it reports exactly
// the limits set through the driver's public sqlite.Limit API on this conn, and (b)
// sqlite3_db_filename(handle, "main") is the store's own database file. A driver upgrade that
// changes the meaning of the reflected field therefore disables untrusted queries instead of
// handing them an unrelated connection.
func verifyHandle(conn *sql.Conn, handle uintptr, path string) error {
	return conn.Raw(func(any) error {
		for id, want := range readOnlyLimits {
			if got := limitOf(handle, id); got != want {
				return fmt.Errorf("read-only query: sqlite handle self-check failed (limit %d = %d, want %d); refusing queries", id, got, want)
			}
		}
		tls := libc.NewTLS()
		defer tls.Close()
		zMain, err := libc.CString("main")
		if err != nil {
			return err
		}
		defer libc.Xfree(tls, zMain)
		got := libc.GoString(sqlite3.Xsqlite3_db_filename(tls, handle, zMain))
		if got == "" || !samePath(got, path) {
			return fmt.Errorf("read-only query: sqlite handle self-check failed (handle is %q, store is %q); refusing queries", got, path)
		}
		return nil
	})
}

// limitOf reads one sqlite3_limit through the reflected handle (-1 leaves it unchanged).
func limitOf(handle uintptr, id int32) int32 {
	tls := libc.NewTLS()
	defer tls.Close()
	return sqlite3.Xsqlite3_limit(tls, handle, id, -1)
}

func samePath(a, b string) bool {
	norm := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		return filepath.Clean(p)
	}
	return norm(a) == norm(b)
}

// ptrSize is the size of a C pointer on this platform.
const ptrSize = 4 << (^uintptr(0) >> 63)

// prepareCheck has SQLite parse the text: exactly one statement (empty tail, ignoring
// whitespace/comments) that sqlite3_stmt_readonly reports as read-only.
func prepareCheck(conn *sql.Conn, handle uintptr, sqlText string) error {
	return conn.Raw(func(any) error {
		tls := libc.NewTLS()
		defer tls.Close()
		zSQL, err := libc.CString(sqlText)
		if err != nil {
			return err
		}
		defer libc.Xfree(tls, zSQL)
		// Out-parameters in C memory: [0] = sqlite3_stmt*, [1] = tail pointer.
		out := sqlite3.Xsqlite3_malloc(tls, 2*ptrSize)
		if out == 0 {
			return fmt.Errorf("read-only query: out of memory")
		}
		defer sqlite3.Xsqlite3_free(tls, out)

		stmt, tail, rc := prepareOnce(tls, handle, zSQL, out)
		if rc != sqlite3.SQLITE_OK {
			return unsafeSQL("%s", libc.GoString(sqlite3.Xsqlite3_errmsg(tls, handle)))
		}
		if stmt == 0 {
			return unsafeSQL("empty query")
		}
		readonly := sqlite3.Xsqlite3_stmt_readonly(tls, stmt)
		sqlite3.Xsqlite3_finalize(tls, stmt)
		if readonly == 0 {
			return unsafeSQL("statement is not read-only")
		}
		// Anything after the first statement must compile to nothing (whitespace/comments).
		if tail >= zSQL && tail < zSQL+uintptr(len(sqlText)) {
			next, _, rc := prepareOnce(tls, handle, tail, out)
			if next != 0 {
				sqlite3.Xsqlite3_finalize(tls, next)
			}
			if rc != sqlite3.SQLITE_OK || next != 0 {
				return unsafeSQL("multiple statements are not allowed")
			}
		}
		return nil
	})
}

// prepareOnce calls sqlite3_prepare_v2 with its out-parameters in the C buffer out and copies
// them back with libc.GoBytes (no Go pointer is passed to C).
func prepareOnce(tls *libc.TLS, handle, zSQL, out uintptr) (stmt, tail uintptr, rc int32) {
	zero := make([]byte, 2*ptrSize)
	copy(libc.GoBytes(out, 2*ptrSize), zero)
	rc = sqlite3.Xsqlite3_prepare_v2(tls, handle, zSQL, -1, out, out+ptrSize)
	b := libc.GoBytes(out, 2*ptrSize)
	if ptrSize == 8 {
		return uintptr(binary.NativeEndian.Uint64(b[:8])), uintptr(binary.NativeEndian.Uint64(b[8:])), rc
	}
	return uintptr(binary.NativeEndian.Uint32(b[:4])), uintptr(binary.NativeEndian.Uint32(b[4:])), rc
}

// queryable is the per-connection allowlist: what /api/schema exposes and what the bytecode may open.
type queryable struct {
	names  []string        // tables and views untrusted SQL may name (sorted)
	roots  map[int64]bool  // b-tree root pages of those tables and their indexes
	vtabs  map[string]bool // EXPLAIN P4 of VOpen on the allowed eponymous virtual tables
	denied map[string]bool // schema objects and registered modules that must not be named
}

// QueryableTables lists the tables and views untrusted SQL may read (what /api/schema shows):
// everything in the main schema except sqlite_* internals, virtual tables and their shadow
// tables, and *_config tables.
func (s *Store) QueryableTables() ([]string, error) {
	db, conn, _, err := s.openReadOnly(context.Background())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	defer conn.Close()
	q, err := loadQueryable(context.Background(), conn)
	if err != nil {
		return nil, err
	}
	return q.names, nil
}

func loadQueryable(ctx context.Context, conn *sql.Conn) (*queryable, error) {
	type obj struct {
		name, typ, tbl, sql string
		root                int64
	}
	rows, err := conn.QueryContext(ctx, `SELECT name, type, tbl_name, coalesce(rootpage, 0), coalesce(sql, '') FROM sqlite_schema`)
	if err != nil {
		return nil, err
	}
	var objs []obj
	for rows.Next() {
		var o obj
		if err := rows.Scan(&o.name, &o.typ, &o.tbl, &o.root, &o.sql); err != nil {
			rows.Close()
			return nil, err
		}
		objs = append(objs, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var virtual []string
	for _, o := range objs {
		if o.typ == "table" && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(o.sql)), "CREATE VIRTUAL TABLE") {
			virtual = append(virtual, strings.ToLower(o.name))
		}
	}
	excluded := func(name string) bool {
		l := strings.ToLower(name)
		if strings.HasPrefix(l, "sqlite_") || strings.HasSuffix(l, "_config") || internalTables[l] {
			return true
		}
		for _, v := range virtual {
			if l == v || strings.HasPrefix(l, v+"_") {
				return true
			}
		}
		return false
	}
	q := &queryable{roots: map[int64]bool{}, vtabs: map[string]bool{}, denied: map[string]bool{}}
	ok := map[string]bool{}
	for _, o := range objs {
		if o.typ != "table" && o.typ != "view" {
			continue
		}
		if excluded(o.name) {
			q.denied[strings.ToLower(o.name)] = true
			continue
		}
		ok[strings.ToLower(o.name)] = true
		q.names = append(q.names, o.name)
	}
	sort.Strings(q.names)
	for _, o := range objs {
		if (o.typ == "table" || o.typ == "index") && o.root > 0 && ok[strings.ToLower(o.tbl)] {
			q.roots[o.root] = true
		}
	}
	// Registered virtual-table modules other than the allowed ones must not be named.
	mrows, err := conn.QueryContext(ctx, `SELECT name FROM pragma_module_list`)
	if err == nil {
		for mrows.Next() {
			var m string
			if mrows.Scan(&m) == nil && !ok[strings.ToLower(m)] {
				q.denied[strings.ToLower(m)] = true
			}
		}
		mrows.Close()
	}
	for _, m := range allowedVTabs {
		delete(q.denied, m)
		p4, err := vopenP4(ctx, conn, "SELECT * FROM "+m+"('[]')")
		if err != nil {
			return nil, err
		}
		if len(p4) != 1 || len(p4[0]) <= len("vtab:") || q.vtabs[p4[0]] {
			return nil, fmt.Errorf("read-only query: cannot identify the %s virtual table; refusing queries", m)
		}
		q.vtabs[p4[0]] = true
	}
	return q, nil
}

// vopenP4 returns the P4 operand ("vtab:<pointer>") of every VOpen in the statement's bytecode.
func vopenP4(ctx context.Context, conn *sql.Conn, stmt string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, "EXPLAIN "+stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var addr, p1, p2, p3, p5 sql.NullInt64
		var opcode, comment sql.NullString
		var p4 any
		if err := rows.Scan(&addr, &opcode, &p1, &p2, &p3, &p4, &p5, &comment); err != nil {
			return nil, err
		}
		if opcode.String == "VOpen" {
			out = append(out, fmt.Sprint(p4))
		}
	}
	return out, rows.Err()
}

// checkBytecode compiles the statement with EXPLAIN (nothing runs) and requires every b-tree it
// opens to be a queryable table/index in the main schema and every virtual table it opens to be
// json_each/json_tree.
func checkBytecode(ctx context.Context, conn *sql.Conn, sqlText string, q *queryable) error {
	rows, err := conn.QueryContext(ctx, "EXPLAIN "+sqlText)
	if err != nil {
		return unsafeSQL("%v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var addr, p1, p2, p3, p5 sql.NullInt64
		var opcode, comment sql.NullString
		var p4 any
		if err := rows.Scan(&addr, &opcode, &p1, &p2, &p3, &p4, &p5, &comment); err != nil {
			return err
		}
		switch opcode.String {
		case "OpenRead", "ReopenIdx":
			const p2IsReg = 0x10 // OPFLAG_P2ISREG (sqliteInt.h): root page comes from a register
			if p3.Int64 != 0 || p5.Int64&p2IsReg != 0 || !q.roots[p2.Int64] {
				return unsafeSQL("query reads a table outside the queryable schema (see /api/schema)")
			}
		case "VOpen":
			if !q.vtabs[fmt.Sprint(p4)] {
				return unsafeSQL("query reads a virtual table other than json_each/json_tree")
			}
		case "OpenWrite", "CreateBtree", "Destroy", "Clear", "ParseSchema", "VUpdate", "VCreate", "VDestroy", "Vacuum", "JournalMode":
			return unsafeSQL("statement is not read-only")
		}
	}
	return rows.Err()
}

// ---------------------------------------------------------------- lexer

type tokKind int

const (
	tokWord   tokKind = iota // bare keyword or identifier
	tokIdent                 // "quoted", `quoted` or [bracketed] identifier (text unquoted)
	tokString                // 'string literal' (text unquoted)
	tokNumber                // numeric literal or blob/parameter
	tokPunct                 // any other single character, including ';'
)

type sqlTok struct {
	kind tokKind
	text string
}

// lexSQL tokenizes SQLite SQL well enough to find statement boundaries and identifiers:
// it understands '...', "...", backtick and [...] quoting (with doubled-quote escapes) and both comment forms.
func lexSQL(s string) ([]sqlTok, error) {
	var out []sqlTok
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < n && s[i+1] == '-':
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				i = n
			} else {
				i += j + 1
			}
		case c == '/' && i+1 < n && s[i+1] == '*':
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				i = n // SQLite treats an unterminated block comment as running to the end
			} else {
				i += j + 4
			}
		case c == '\'' || c == '"' || c == '`':
			text, next, ok := scanQuoted(s, i, c)
			if !ok {
				return nil, fmt.Errorf("unterminated quoted text")
			}
			kind := tokIdent
			if c == '\'' {
				kind = tokString
			}
			out = append(out, sqlTok{kind, text})
			i = next
		case c == '[':
			j := strings.IndexByte(s[i:], ']')
			if j < 0 {
				return nil, fmt.Errorf("unterminated [identifier]")
			}
			out = append(out, sqlTok{tokIdent, s[i+1 : i+j]})
			i += j + 1
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentPart(s[j]) {
				j++
			}
			out = append(out, sqlTok{tokWord, s[i:j]})
			i = j
		case c >= '0' && c <= '9' || c == '?' || c == ':' || c == '@' || c == '$':
			j := i + 1
			for j < n && (isIdentPart(s[j]) || s[j] == '.') {
				j++
			}
			out = append(out, sqlTok{tokNumber, s[i:j]})
			i = j
		default:
			out = append(out, sqlTok{tokPunct, string(c)})
			i++
		}
	}
	return out, nil
}

func scanQuoted(s string, i int, q byte) (string, int, bool) {
	var b strings.Builder
	j := i + 1
	for j < len(s) {
		if s[j] == q {
			if j+1 < len(s) && s[j+1] == q {
				b.WriteByte(q)
				j += 2
				continue
			}
			return b.String(), j + 1, true
		}
		b.WriteByte(s[j])
		j++
	}
	return "", j, false
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isIdentPart(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' || c == '$' }
