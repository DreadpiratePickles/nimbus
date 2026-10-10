package mcp

// SQL-level redaction for the sql tool (verify-4 defect 2).
//
// Redacting the result cells is not enough: a client can compute over a raw value before it
// leaves SQLite (hex(account), substr, CAST, concatenation, unicode(), group_concat, aliasing, or
// a `LIKE '1111%'` yes/no oracle in a WHERE clause) and no pattern on the output recognises the
// result. So in a redacted session the client's query never sees a raw column at all:
//
//   - Every queryable table or view the query names is shadowed by a common table expression of
//     the same name whose every column is nimbus_redact(<session>, <column>, <value>), i.e. the
//     placeholder form (redactor.cell). The CTE body reads `main.<name>`; a schema-qualified
//     name never matches a CTE, an unqualified one always does, so the client's `findings` is
//     the redacted copy and every function, comparison, join and LIKE runs on placeholders.
//   - The client's text may not name `main`/`temp` (the only way to reach the raw table past a
//     CTE of the same name) or the nimbus_redact function itself (calling it on a guessed value
//     would be an equality oracle against the placeholder).
//   - Placeholders in the SQL are NOT re-hydrated: `WHERE account = 'ACCT_…'` matches the
//     redacted column directly, and a raw id in the SQL matches nothing.
//   - The cells are then redacted again by value (redactor.table), including a substring pass for
//     every raw account/subscription/IP value seen in the session.
//
// Residual risk (docs/mcp.md): an identifier in a shape the redactor does not recognise (an
// account id written with dashes, a hostname, an e-mail, a tag value inside free text such as a
// title) is not redacted in any column, so it is visible and computable like any other text.
// Redaction minimises what an assistant sees; it is not an access-control boundary.

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"modernc.org/sqlite"

	"github.com/DreadpiratePickles/nimbus/internal/store"
)

const redactFunc = "nimbus_redact"

var (
	redactFuncOnce sync.Once
	redactFuncErr  error
	redactSessions sync.Map // session id -> *redactor
)

// registerRedactFunc registers nimbus_redact(session, column, value) with the SQLite driver (once
// per process; it applies to every connection opened afterwards, including the read-only ones
// QueryReadOnly opens per query). An unknown session fails the query (closed, not open).
func registerRedactFunc() error {
	redactFuncOnce.Do(func() {
		redactFuncErr = sqlite.RegisterScalarFunction(redactFunc, 3, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
			sid, _ := args[0].(string)
			key, _ := args[1].(string)
			r, ok := redactSessions.Load(sid)
			if !ok {
				return nil, errors.New("redaction session closed")
			}
			return r.(*redactor).cell(key, args[2]), nil
		})
	})
	return redactFuncErr
}

// sqlRedaction rewrites one client query for a redacted session.
type sqlRedaction struct {
	sid  string
	rd   Reader
	mu   sync.Mutex
	cols map[string][]string // lower-case table/view name -> columns
	name map[string]string   // lower-case -> schema spelling
}

func newSQLRedaction(sid string, rd Reader) *sqlRedaction {
	return &sqlRedaction{sid: sid, rd: rd}
}

func (x *sqlRedaction) load() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.cols != nil {
		return nil
	}
	names, err := x.rd.QueryableTables()
	if err != nil {
		return err
	}
	cols, name := map[string][]string{}, map[string]string{}
	for _, n := range names {
		c, err := x.rd.TableColumns(n)
		if err != nil || len(c) == 0 {
			continue
		}
		cols[strings.ToLower(n)], name[strings.ToLower(n)] = c, n
	}
	x.cols, x.name = cols, name
	return nil
}

// forbiddenNames may not appear in a client query in a redacted session (any token kind).
var forbiddenNames = map[string]string{
	"main":          "schema-qualified names (main.) are not allowed in a redacted session",
	"temp":          "schema-qualified names (temp.) are not allowed in a redacted session",
	"temporary":     "schema-qualified names are not allowed in a redacted session",
	redactFunc:      redactFunc + " is internal",
	"sqlite_schema": "internal table",
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func quoteLit(s string) string   { return `'` + strings.ReplaceAll(s, `'`, `''`) + `'` }

// rewrite returns the query to run: the client's query behind redacting CTEs.
func (x *sqlRedaction) rewrite(q string) (string, error) {
	if err := store.CheckReadOnlySQL(q); err != nil {
		return "", err
	}
	if err := x.load(); err != nil {
		return "", err
	}
	words, err := sqlWords(q)
	if err != nil {
		return "", err
	}
	used := map[string]bool{}
	for _, w := range words {
		l := strings.ToLower(w)
		if why, bad := forbiddenNames[l]; bad {
			return "", errf("rejected: %s", why)
		}
		if _, ok := x.cols[l]; ok {
			used[l] = true
		}
	}
	var names []string
	for n := range used {
		names = append(names, n)
	}
	sort.Strings(names)
	var ctes []string
	for _, l := range names {
		var sel []string
		for _, c := range x.cols[l] {
			sel = append(sel, fmt.Sprintf("%s(%s,%s,%s) AS %s", redactFunc, quoteLit(x.sid), quoteLit(c), quoteIdent(c), quoteIdent(c)))
		}
		ctes = append(ctes, fmt.Sprintf("%s AS (SELECT %s FROM main.%s)", quoteIdent(x.name[l]), strings.Join(sel, ", "), quoteIdent(x.name[l])))
	}
	if len(ctes) == 0 {
		return q, nil
	}
	prefix := strings.Join(ctes, ", ")
	rest, recursive, isWith := afterWith(q)
	if isWith {
		kw := "WITH "
		if recursive {
			kw = "WITH RECURSIVE "
		}
		return kw + prefix + ", " + rest, nil
	}
	return "WITH " + prefix + "\n" + q, nil
}

// sqlWords returns every bare word, quoted identifier and string literal in q (a string literal
// is accepted by SQLite where a name is expected, e.g. FROM 'findings').
func sqlWords(q string) ([]string, error) {
	var out []string
	i, n := 0, len(q)
	for i < n {
		c := q[i]
		switch {
		case c == '-' && i+1 < n && q[i+1] == '-':
			j := strings.IndexByte(q[i:], '\n')
			if j < 0 {
				return out, nil
			}
			i += j + 1
		case c == '/' && i+1 < n && q[i+1] == '*':
			j := strings.Index(q[i+2:], "*/")
			if j < 0 {
				return out, nil
			}
			i += j + 4
		case c == '\'' || c == '"' || c == '`':
			var b strings.Builder
			j := i + 1
			closed := false
			for j < n {
				if q[j] == c {
					if j+1 < n && q[j+1] == c {
						b.WriteByte(c)
						j += 2
						continue
					}
					closed = true
					break
				}
				b.WriteByte(q[j])
				j++
			}
			if !closed {
				return nil, errf("rejected: unterminated quoted text")
			}
			out = append(out, b.String())
			i = j + 1
		case c == '[':
			j := strings.IndexByte(q[i:], ']')
			if j < 0 {
				return nil, errf("rejected: unterminated [identifier]")
			}
			out = append(out, q[i+1:i+j])
			i += j + 1
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80:
			j := i + 1
			for j < n && (q[j] == '_' || q[j] == '$' || q[j] >= 'a' && q[j] <= 'z' || q[j] >= 'A' && q[j] <= 'Z' || q[j] >= '0' && q[j] <= '9' || q[j] >= 0x80) {
				j++
			}
			out = append(out, q[i:j])
			i = j
		case c >= '0' && c <= '9':
			j := i + 1
			for j < n && (q[j] == '_' || q[j] == '.' || q[j] >= 'a' && q[j] <= 'z' || q[j] >= 'A' && q[j] <= 'Z' || q[j] >= '0' && q[j] <= '9') {
				j++
			}
			i = j
		default:
			i++
		}
	}
	return out, nil
}

// afterWith: if q starts (after whitespace and comments) with WITH [RECURSIVE], the text after
// those keywords.
func afterWith(q string) (rest string, recursive, ok bool) {
	i := skipSpace(q, 0)
	if !keywordAt(q, i, "WITH") {
		return "", false, false
	}
	i = skipSpace(q, i+4)
	if keywordAt(q, i, "RECURSIVE") {
		return q[skipSpace(q, i+9):], true, true
	}
	return q[i:], false, true
}

func keywordAt(q string, i int, kw string) bool {
	if i+len(kw) > len(q) || !strings.EqualFold(q[i:i+len(kw)], kw) {
		return false
	}
	if j := i + len(kw); j < len(q) {
		c := q[j]
		if c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80 {
			return false
		}
	}
	return true
}

func skipSpace(q string, i int) int {
	for i < len(q) {
		switch {
		case q[i] == ' ' || q[i] == '\t' || q[i] == '\n' || q[i] == '\r' || q[i] == '\f' || q[i] == '\v':
			i++
		case strings.HasPrefix(q[i:], "--"):
			j := strings.IndexByte(q[i:], '\n')
			if j < 0 {
				return len(q)
			}
			i += j + 1
		case strings.HasPrefix(q[i:], "/*"):
			j := strings.Index(q[i+2:], "*/")
			if j < 0 {
				return len(q)
			}
			i += j + 4
		default:
			return i
		}
	}
	return i
}
