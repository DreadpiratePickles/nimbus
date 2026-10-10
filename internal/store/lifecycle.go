package store

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"sort"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// TagScanRoot is the Finding.Tags key holding the IaC root a finding was scanned under,
// so scanning ./b never resolves findings that were found under ./a.
const TagScanRoot = "scan_root"

// TagAccountLabel is the Finding.Tags key holding the config account label (account
// name in the config) a finding was collected under.
const TagAccountLabel = "account_label"

// Scope is the unit of "we looked again": findings of this source, provider, account
// and config label (and IaC root, when set) that a scan did not re-observe are
// resolved. Label keeps two config labels for the same cloud account id (e.g. one per
// region set) from resolving each other's findings.
type Scope struct {
	Source   string `json:"source"`
	Provider string `json:"provider"`
	Account  string `json:"account"`
	Label    string `json:"label,omitempty"`
	Root     string `json:"root,omitempty"`
}

// FileScope is one file under an IaC root that a scan could not examine (it did not
// parse or exceeded the parser limits): stored findings in it are never resolved by
// absence, whatever the scope.
type FileScope struct {
	Root string `json:"root"`
	File string `json:"file"`
}

// ScopesOf derives the scopes a set of observed findings covers.
func ScopesOf(fs []model.Finding) []Scope {
	seen := map[Scope]bool{}
	var out []Scope
	for _, f := range fs {
		sc := Scope{Source: f.Source, Provider: f.Provider, Account: f.Account, Label: f.Tags[TagAccountLabel], Root: f.Tags[TagScanRoot]}
		if !seen[sc] {
			seen[sc] = true
			out = append(out, sc)
		}
	}
	return out
}

// Target is something a scan declared it would examine in full (an IaC root, a native
// collector account), whether or not it still produced findings. Empty fields match
// anything; AccountLabel matches the account id or the finding's account_label tag.
type Target struct {
	Source       string `json:"source"`
	Provider     string `json:"provider,omitempty"`
	AccountLabel string `json:"account_label,omitempty"`
	Root         string `json:"root,omitempty"`
}

// ScopesForTargets returns the scopes of stored active findings that fall under the
// declared targets, so a target whose last resource disappeared still has its old
// findings resolved by absence (ScopesOf only sees what this scan observed).
func (s *Store) ScopesForTargets(targets []Target) ([]Scope, error) {
	seen := map[Scope]bool{}
	var out []Scope
	for _, t := range targets {
		q := `SELECT DISTINCT source, provider, COALESCE(account,''), COALESCE(json_extract(tags, '$.` + TagAccountLabel + `'), ''),
		  COALESCE(json_extract(tags, '$.` + TagScanRoot + `'), '')
		  FROM findings WHERE source = ? AND state IN ('open','reopened')`
		args := []any{t.Source}
		if t.Provider != "" {
			q += " AND provider = ?"
			args = append(args, t.Provider)
		}
		if t.AccountLabel != "" {
			q += " AND (COALESCE(account,'') = ? OR COALESCE(json_extract(tags, '$.account_label'), '') = ?)"
			args = append(args, t.AccountLabel, t.AccountLabel)
		}
		if t.Root != "" {
			q += " AND COALESCE(json_extract(tags, '$." + TagScanRoot + "'), '') = ?"
			args = append(args, t.Root)
		}
		rows, err := s.db.Query(q, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var sc Scope
			if err := rows.Scan(&sc.Source, &sc.Provider, &sc.Account, &sc.Label, &sc.Root); err != nil {
				rows.Close()
				return nil, err
			}
			if !seen[sc] {
				seen[sc] = true
				out = append(out, sc)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ApplyOptions controls resolution by absence.
type ApplyOptions struct {
	// Scopes the scan fully re-examined; open findings in them that were not observed
	// become resolved. Empty means "observed transitions only" (no resolution by absence).
	Scopes []Scope
	// SkipScopes are never resolved by absence (the source had coverage errors, or the
	// scan was partial, e.g. --changed-only).
	SkipScopes []Scope
	// SkipFiles are IaC files the scan could not examine: findings whose scan root and
	// file match one are never resolved by absence, in any scope.
	SkipFiles []FileScope
}

// Diff is what changed in one scan.
type Diff struct {
	ScanID   string   `json:"scan_id"`
	New      []string `json:"new"`
	Resolved []string `json:"resolved"`
	Reopened []string `json:"reopened"`
	// Issues is the scan's Issue trend, filled when the scan is saved (SaveScan, trend.go).
	Issues *ScanTrend `json:"issues,omitempty"`
}

// Lifecycle is the stored lifecycle of one finding.
type Lifecycle struct {
	ID         string     `json:"id"`
	State      string     `json:"state"`
	FirstSeen  time.Time  `json:"first_seen"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	ReopenedAt *time.Time `json:"reopened_at,omitempty"`
}

// HistoryEntry is one lifecycle transition.
type HistoryEntry struct {
	Fingerprint string    `json:"fingerprint"`
	State       string    `json:"state"`
	At          time.Time `json:"at"`
	ScanID      string    `json:"scan_id"`
}

// UpsertFindings stores findings and applies observed lifecycle transitions (open,
// resolved on PASS, reopened) without resolving anything by absence. It keeps
// first_seen from an earlier row and refreshes everything else.
func (s *Store) UpsertFindings(findings []model.Finding) error {
	_, err := s.ApplyScan("", findings, time.Now().UTC(), ApplyOptions{})
	return err
}

type priorRow struct {
	state      string
	firstSeen  string
	resolvedAt sql.NullString
	reopenedAt sql.NullString
}

// ApplyScan upserts one scan's findings, records lifecycle transitions in
// finding_history, resolves open findings in opts.Scopes that were not re-observed,
// and returns the new / resolved / reopened fingerprints. It is one transaction.
func (s *Store) ApplyScan(scanID string, findings []model.Finding, now time.Time, opts ApplyOptions) (*Diff, error) {
	now = now.UTC()
	nowS := now.Format(time.RFC3339)
	d := &Diff{ScanID: scanID}
	s.snapshotForTrend(scanID, d)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO findings (id, source, check_id, canonical_id, title, description, severity, status, provider, account, region,
	  resource_id, resource_type, resource_name, file, line_start, line_end, remediation, weaknesses, compliance, tags, scan_id, first_seen, last_seen, doc,
	  state, resolved_at, reopened_at)
	  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
	  ON CONFLICT(id) DO UPDATE SET
	    status=excluded.status, severity=excluded.severity, title=excluded.title, description=excluded.description,
	    canonical_id=excluded.canonical_id, resource_name=excluded.resource_name, resource_type=excluded.resource_type,
	    remediation=excluded.remediation, weaknesses=excluded.weaknesses, compliance=excluded.compliance, tags=excluded.tags,
	    scan_id=excluded.scan_id, last_seen=excluded.last_seen, line_start=excluded.line_start, line_end=excluded.line_end,
	    doc=excluded.doc, state=excluded.state, resolved_at=excluded.resolved_at, reopened_at=excluded.reopened_at`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	resStmt, err := tx.Prepare(`INSERT INTO resources (id, type, name, provider, account, region, attributes, related, last_seen)
	  VALUES (?,?,?,?,?,?,?,?,?)
	  ON CONFLICT(id) DO UPDATE SET type=COALESCE(NULLIF(excluded.type,''), resources.type), name=excluded.name,
	    attributes=excluded.attributes, related=excluded.related, last_seen=excluded.last_seen`)
	if err != nil {
		return nil, err
	}
	defer resStmt.Close()
	hist, err := tx.Prepare("INSERT INTO finding_history (fingerprint, state, at, scan_id) VALUES (?,?,?,?)")
	if err != nil {
		return nil, err
	}
	defer hist.Close()

	observed := map[string]bool{}
	for i := range findings {
		f := &findings[i]
		if f.ID == "" {
			f.Finalize(now)
		}
		observed[f.ID] = true
		histScan := firstNonEmptyStr(scanID, f.ScanID)
		var p priorRow
		err := tx.QueryRow("SELECT state, COALESCE(first_seen,''), resolved_at, reopened_at FROM findings WHERE id = ?", f.ID).
			Scan(&p.state, &p.firstSeen, &p.resolvedAt, &p.reopenedAt)
		exists := err == nil
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		if exists {
			// first_seen is preserved for the whole history, in the column and in the doc.
			if t, perr := time.Parse(time.RFC3339, p.firstSeen); perr == nil && (f.FirstSeen.IsZero() || t.Before(f.FirstSeen)) {
				f.FirstSeen = t
			}
		}
		state, resolvedAt, reopenedAt := model.StateOpen, p.resolvedAt, p.reopenedAt
		transition := ""
		switch {
		case f.Status == model.Fail && !exists:
			transition = model.StateOpen
		case f.Status == model.Fail && model.IsActive(p.state):
			state = p.state
		case f.Status == model.Fail: // prior resolved
			var opened int
			if err := tx.QueryRow("SELECT COUNT(*) FROM finding_history WHERE fingerprint = ?", f.ID).Scan(&opened); err != nil {
				return nil, err
			}
			if opened > 0 {
				state, transition = model.StateReopened, model.StateReopened
				reopenedAt = sql.NullString{String: nowS, Valid: true}
			} else { // only ever seen passing: this is its first failure
				transition = model.StateOpen
			}
		case f.Status == model.Pass && exists && model.IsActive(p.state):
			state, transition = model.StateResolved, model.StateResolved
			resolvedAt = sql.NullString{String: nowS, Valid: true}
		case f.Status == model.Pass:
			state = model.StateResolved
		case exists: // SKIP / ERROR: the check could not decide; keep the prior state
			state = p.state
		}
		doc, _ := json.Marshal(f)
		weak, _ := json.Marshal(f.Weaknesses)
		comp, _ := json.Marshal(f.Compliance)
		tags, _ := json.Marshal(f.Tags)
		if _, err := stmt.Exec(f.ID, f.Source, f.CheckID, f.CanonicalID, f.Title, f.Description, string(f.Severity), string(f.Status),
			f.Provider, f.Account, f.Region, f.Resource.ID, f.Resource.Type, f.Resource.Name, f.File, f.LineStart, f.LineEnd,
			f.Remediation, string(weak), string(comp), string(tags), f.ScanID, f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339), string(doc),
			state, resolvedAt, reopenedAt); err != nil {
			return nil, err
		}
		if transition != "" {
			if _, err := hist.Exec(f.ID, transition, nowS, histScan); err != nil {
				return nil, err
			}
			switch transition {
			case model.StateOpen:
				d.New = append(d.New, f.ID)
			case model.StateResolved:
				d.Resolved = append(d.Resolved, f.ID)
			case model.StateReopened:
				d.Reopened = append(d.Reopened, f.ID)
			}
		}
		if f.Resource.ID != "" {
			attrs, _ := json.Marshal(f.Resource.Attributes)
			rel, _ := json.Marshal(f.Resource.Related)
			if _, err := resStmt.Exec(f.Resource.ID, f.Resource.Type, f.Resource.Name, f.Provider, f.Account, f.Region, string(attrs), string(rel), f.LastSeen.Format(time.RFC3339)); err != nil {
				return nil, err
			}
		}
	}

	skip := map[Scope]bool{}
	for _, sc := range opts.SkipScopes {
		skip[sc] = true
	}
	skipFile := map[FileScope]bool{}
	for _, fsc := range opts.SkipFiles {
		skipFile[FileScope{Root: fsc.Root, File: filepath.ToSlash(fsc.File)}] = true
	}
	for _, sc := range opts.Scopes {
		if skip[sc] {
			continue
		}
		rows, err := tx.Query(`SELECT id, COALESCE(file,'') FROM findings WHERE source = ? AND provider = ? AND COALESCE(account,'') = ?
		  AND COALESCE(json_extract(tags, '$.`+TagAccountLabel+`'), '') = ?
		  AND COALESCE(json_extract(tags, '$.`+TagScanRoot+`'), '') = ? AND state IN ('open','reopened')`, sc.Source, sc.Provider, sc.Account, sc.Label, sc.Root)
		if err != nil {
			return nil, err
		}
		var gone []string
		for rows.Next() {
			var id, file string
			if err := rows.Scan(&id, &file); err != nil {
				rows.Close()
				return nil, err
			}
			if !observed[id] && !skipFile[FileScope{Root: sc.Root, File: filepath.ToSlash(file)}] {
				gone = append(gone, id)
			}
		}
		rows.Close()
		for _, id := range gone {
			if _, err := tx.Exec("UPDATE findings SET state = 'resolved', resolved_at = ? WHERE id = ?", nowS, id); err != nil {
				return nil, err
			}
			if _, err := hist.Exec(id, model.StateResolved, nowS, scanID); err != nil {
				return nil, err
			}
			d.Resolved = append(d.Resolved, id)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	sort.Strings(d.New)
	sort.Strings(d.Resolved)
	sort.Strings(d.Reopened)
	return d, nil
}

// Lifecycle returns the stored lifecycle of one finding.
func (s *Store) Lifecycle(id string) (*Lifecycle, error) {
	var lc Lifecycle
	var first string
	var res, reo sql.NullString
	if err := s.db.QueryRow("SELECT id, state, COALESCE(first_seen,''), resolved_at, reopened_at FROM findings WHERE id = ?", id).
		Scan(&lc.ID, &lc.State, &first, &res, &reo); err != nil {
		return nil, err
	}
	lc.FirstSeen, _ = time.Parse(time.RFC3339, first)
	lc.ResolvedAt, lc.ReopenedAt = parseNullTime(res), parseNullTime(reo)
	return &lc, nil
}

// History returns a finding's lifecycle transitions, oldest first.
func (s *Store) History(fingerprint string) ([]HistoryEntry, error) {
	rows, err := s.db.Query("SELECT fingerprint, state, at, COALESCE(scan_id,'') FROM finding_history WHERE fingerprint = ? ORDER BY at, rowid", fingerprint)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var h HistoryEntry
		var at string
		if err := rows.Scan(&h.Fingerprint, &h.State, &at, &h.ScanID); err != nil {
			return nil, err
		}
		h.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, h)
	}
	return out, rows.Err()
}

func parseNullTime(v sql.NullString) *time.Time {
	if !v.Valid || v.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, v.String)
	if err != nil {
		return nil
	}
	return &t
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
