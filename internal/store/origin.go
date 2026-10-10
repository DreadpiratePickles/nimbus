package store

// Which layer built a database, and who may migrate it (W6-VERIFY, r4 #15).
//
// The Python layer (python/nimbus/store.py) creates the same base tables without the Go
// migrations and marks the database store_meta built_by=python. Opening such a database used to
// migrate it on any Go command — `paths`, `issues`, `mcp` and `serve` silently added tables,
// re-keyed ids and back-filled Issues behind the user's back (seen through the copilot overlay,
// W5-PR-MCP). Now only commands that write posture (`ingest`, `scan`) may upgrade a foreign
// database, and they print a notice; read-only commands refuse with ErrForeignDB and leave the
// file untouched. Go databases (marker built_by=go, or schema_migrations from before the
// marker) keep upgrading on every open as before.

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Database origins.
const (
	OriginGo     = "go"
	OriginPython = "python"
	OriginNew    = "new"
)

const builtByKey = "built_by"

// ErrForeignDB: the database was built by another layer and this command may not migrate it.
var ErrForeignDB = errors.New("database built by another layer")

// ForeignDBError names the database and how to upgrade it.
type ForeignDBError struct {
	Path, Origin string
}

func (e *ForeignDBError) Error() string {
	return fmt.Sprintf("%s was built by the Python layer and has not been upgraded to the Go schema; this command only reads and never migrates it — run `cloud-posture ingest <findings>` or `cloud-posture scan` once to upgrade it (they migrate and say so)", e.Path)
}

func (e *ForeignDBError) Unwrap() error { return ErrForeignDB }

// ForeignPolicy decides what Open does with a database another layer built. The library
// default allows the upgrade silently (tests, embedders); the CLI sets Allow only for ingest and
// scan, with Notice = stderr.
type ForeignPolicy struct {
	Allow  bool
	Notice io.Writer // where the one-line upgrade notice goes (nil: nowhere)
}

var (
	policyMu sync.Mutex
	policy   = ForeignPolicy{Allow: true}
)

// SetForeignPolicy sets the process-wide policy and returns the previous one.
func SetForeignPolicy(p ForeignPolicy) ForeignPolicy {
	policyMu.Lock()
	defer policyMu.Unlock()
	prev := policy
	policy = p
	return prev
}

func currentPolicy() ForeignPolicy {
	policyMu.Lock()
	defer policyMu.Unlock()
	return policy
}

func hasTable(q interface {
	QueryRow(string, ...any) *sql.Row
}, name string) (bool, error) {
	var n int
	err := q.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", name).Scan(&n)
	return n > 0, err
}

// dbOrigin inspects a database before any migration runs.
func dbOrigin(db *sql.DB) (string, error) {
	if ok, err := hasTable(db, "store_meta"); err != nil {
		return "", err
	} else if ok {
		var v []byte
		err := db.QueryRow("SELECT v FROM store_meta WHERE k = ?", builtByKey).Scan(&v)
		if err == nil {
			if string(v) == OriginGo {
				return OriginGo, nil
			}
			return OriginPython, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
	}
	if ok, err := hasTable(db, "schema_migrations"); err != nil {
		return "", err
	} else if ok {
		return OriginGo, nil // a Go database from before the marker
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'").Scan(&n); err != nil {
		return "", err
	}
	if n == 0 {
		return OriginNew, nil
	}
	return OriginPython, nil // tables without Go migrations: the Python layer (or a pre-versioning build)
}

// markGoIfNeeded records built_by=go unless it is already there (no write on a plain open).
func markGoIfNeeded(db *sql.DB, origin string) error {
	if origin == OriginGo {
		var v []byte
		if db.QueryRow("SELECT v FROM store_meta WHERE k = ?", builtByKey).Scan(&v) == nil && string(v) == OriginGo {
			return nil
		}
	}
	return markGo(db)
}

// fileOrigin is dbOrigin on a read-only handle (OriginNew for a missing or empty file).
func fileOrigin(path string) (string, error) {
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		return OriginNew, nil
	}
	db, err := sql.Open("sqlite", fileURI(path, "mode=ro&_pragma=busy_timeout(5000)"))
	if err != nil {
		return "", err
	}
	defer db.Close()
	return dbOrigin(db)
}

// fileURI is a SQLite file: URI for path with query, escaped (Verification 7 defect 4: a '#',
// '?' or '%' in a concatenated URI cut or changed the path). The path is made absolute first so
// it is always the URI path, never an authority.
func fileURI(path, query string) string {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: query}
	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path // Windows drive paths: file:///C:/...
	}
	return u.String()
}

func markGo(db *sql.DB) error {
	_, err := db.Exec("INSERT INTO store_meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", builtByKey, []byte(OriginGo))
	return err
}

// Origin reports who built this database (always OriginGo once opened by Go).
func (s *Store) Origin() (string, error) { return dbOrigin(s.db) }
