package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// auditRecord is one line of the MCP audit log (JSONL).
//
// Migration to a table: when the store owner adds `agent_audit`, these fields map 1:1 to its
// columns (ts TEXT, session TEXT, seq INTEGER, method TEXT, tool TEXT, uri TEXT, scope TEXT
// (JSON array), outcome TEXT, error TEXT, duration_ms INTEGER, args TEXT (JSON), sql TEXT,
// rows INTEGER, result_bytes INTEGER, client TEXT); an importer replays the JSONL file once and
// the writer switches to an INSERT on the store's write connection, kept outside the tools'
// Reader so tools stay read-only by construction.
type auditRecord struct {
	Time        string          `json:"ts"`
	Session     string          `json:"session"`
	Seq         int             `json:"seq"`
	Method      string          `json:"method"`
	Tool        string          `json:"tool,omitempty"`
	URI         string          `json:"uri,omitempty"`
	Scope       []string        `json:"scope"`
	Outcome     string          `json:"outcome"` // ok | error | refused
	Error       string          `json:"error,omitempty"`
	DurationMS  int64           `json:"duration_ms"`
	Args        json.RawMessage `json:"args,omitempty"`
	SQL         string          `json:"sql,omitempty"` // the SQL that ran (re-hydrated)
	Rows        int             `json:"rows,omitempty"`
	ResultBytes int             `json:"result_bytes,omitempty"`
	Client      string          `json:"client,omitempty"`
	Transport   string          `json:"transport,omitempty"` // "http" for the streamable HTTP transport
	Principal   string          `json:"principal,omitempty"` // HTTP: the token's name (never the token)
}

// maxAuditArgs caps the arguments copied into one record.
const maxAuditArgs = 16 << 10

// DefaultAuditPath is mcp-audit.jsonl next to the database (".cloud-posture/mcp-audit.jsonl"
// for the default store).
func DefaultAuditPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "mcp-audit.jsonl")
}

type auditLog struct {
	mu sync.Mutex
	f  *os.File
}

func openAudit(path string) (*auditLog, error) {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mcp audit: %w", err)
		}
		_ = os.Chmod(dir, 0o700) // MkdirAll is subject to umask
	}
	// Never follow a symlink planted at the audit path (it would redirect, and chmod, another
	// file): refuse a symlink by lstat, then open with O_NOFOLLOW so a swap in between fails too.
	if fi, err := os.Lstat(path); err == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular()) {
		return nil, fmt.Errorf("mcp audit: %s is not a regular file (symlinks are refused)", path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|oNoFollow, 0o600)
	if err != nil {
		return nil, fmt.Errorf("mcp audit: %w", err)
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("mcp audit: %s is not a regular file", path)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("mcp audit: %w", err)
	}
	return &auditLog{f: f}, nil
}

func (a *auditLog) write(r auditRecord) error {
	if len(r.Args) > maxAuditArgs {
		r.Args, _ = json.Marshal(map[string]any{"truncated": true, "bytes": len(r.Args)})
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.f.Write(append(b, '\n'))
	return err
}

func (a *auditLog) close() error { return a.f.Close() }
