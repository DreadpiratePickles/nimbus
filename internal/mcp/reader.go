package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Reader is everything a tool may do with the posture database. It has no write-shaped method
// (TestReadOnlyByConstruction checks the method set), so a tool cannot write even by mistake.
type Reader interface {
	QueryReadOnly(ctx context.Context, sqlText string, opts store.ReadOnlyOptions) (*store.ReadOnlyResult, error)
	QueryableTables() ([]string, error)
	TableColumns(table string) ([]string, error)
	Findings(fl store.Filter) ([]model.Finding, error)
	Finding(id string) (*model.Finding, error)
	AttackPaths() ([]model.AttackPath, error)
	Issues(fl store.IssueFilter) ([]model.Issue, error)
	IssueCounts() (*store.IssueCounts, error)
	PathIssueHistory(id string) ([]store.PathIssueHistoryEntry, error)
	Coverage(scanID string) ([]store.CoverageEntry, error)
	LastScan() (*model.ScanSummary, error)
	LoadGraph() (*graph.Graph, error)
	Headline() (*store.Headline, error)
	Verifications(issueID string) ([]store.Verification, error)
	// IDMapper keys finding and attack-path ids for output (store/extid.go, Verification 6).
	IDMapper() (*store.IDMapper, error)
	// PathIssueIDOf is the stored (keyed) path Issue id of a path (store/idkey.go).
	PathIssueIDOf(p model.AttackPath) string
}

// storeReader narrows *store.Store to Reader. The store pointer is unexported, so tools cannot
// reach its write methods.
type storeReader struct{ st *store.Store }

// NewReader wraps a store as a Reader.
func NewReader(st *store.Store) Reader { return storeReader{st} }

func (r storeReader) QueryReadOnly(ctx context.Context, q string, o store.ReadOnlyOptions) (*store.ReadOnlyResult, error) {
	return r.st.QueryReadOnly(ctx, q, o)
}
func (r storeReader) QueryableTables() ([]string, error)                 { return r.st.QueryableTables() }
func (r storeReader) Findings(fl store.Filter) ([]model.Finding, error)  { return r.st.Findings(fl) }
func (r storeReader) Finding(id string) (*model.Finding, error)          { return r.st.Finding(id) }
func (r storeReader) AttackPaths() ([]model.AttackPath, error)           { return r.st.AttackPaths() }
func (r storeReader) Issues(fl store.IssueFilter) ([]model.Issue, error) { return r.st.Issues(fl) }
func (r storeReader) IssueCounts() (*store.IssueCounts, error)           { return r.st.IssueCounts() }
func (r storeReader) PathIssueHistory(id string) ([]store.PathIssueHistoryEntry, error) {
	return r.st.PathIssueHistory(id)
}
func (r storeReader) Coverage(scanID string) ([]store.CoverageEntry, error) {
	return r.st.Coverage(scanID)
}
func (r storeReader) LastScan() (*model.ScanSummary, error) { return r.st.LastScan() }
func (r storeReader) PathIssueIDOf(p model.AttackPath) string { return r.st.PathIssueIDOf(p) }
func (r storeReader) Headline() (*store.Headline, error)    { return r.st.Headline() }
func (r storeReader) Verifications(id string) ([]store.Verification, error) {
	return r.st.Verifications(id)
}

func (r storeReader) IDMapper() (*store.IDMapper, error) { return r.st.IDMapper() }

// idReader is the Reader every tool of a session sees: an inbound finding id is the external
// (keyed) id; a raw stored fingerprint is accepted only in an unredacted session — in a
// redacted one it answers exactly like an unknown id, so it is no lookup oracle.
type idReader struct {
	Reader
	ids      *store.IDMapper
	allowRaw bool
}

func (r idReader) Finding(id string) (*model.Finding, error) {
	if r.ids != nil {
		if raw, ok := r.ids.Raw(id); ok {
			return r.Reader.Finding(raw)
		}
		if r.ids.IsRaw(id) && !r.allowRaw {
			return nil, sql.ErrNoRows
		}
	}
	return r.Reader.Finding(id)
}

// TableColumns lists a queryable table's columns (only names QueryableTables returns).
func (r storeReader) TableColumns(table string) ([]string, error) {
	names, err := r.st.QueryableTables()
	if err != nil {
		return nil, err
	}
	ok := false
	for _, n := range names {
		if n == table {
			ok = true
		}
	}
	if !ok {
		return nil, fmt.Errorf("%q is not queryable", table)
	}
	rows, err := r.st.DB().Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LoadGraph rebuilds the in-memory graph from the stored nodes and edges (as internal/cli does).
func (r storeReader) LoadGraph() (*graph.Graph, error) {
	nodes, edges, err := r.st.LoadGraph()
	if err != nil {
		return nil, err
	}
	g := graph.New()
	for _, n := range nodes {
		var gn graph.Node
		if json.Unmarshal(n.Doc, &gn) == nil {
			g.AddNode(&gn)
		}
	}
	for _, e := range edges {
		var attr map[string]any
		_ = json.Unmarshal(e.Attr, &attr)
		g.AddEdge(e.From, e.To, e.Kind, attr)
	}
	return g, nil
}
