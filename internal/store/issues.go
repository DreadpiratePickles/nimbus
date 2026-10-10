package store

import (
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const issuesSchema = `
CREATE TABLE IF NOT EXISTS issues (
  id TEXT PRIMARY KEY,
  canonical_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  provider TEXT,
  account TEXT,
  severity TEXT NOT NULL,
  state TEXT NOT NULL,
  first_seen TEXT,
  last_seen TEXT,
  resolved_at TEXT,
  finding_ids TEXT NOT NULL,  -- JSON array of finding fingerprints (the evidence)
  sources TEXT NOT NULL,      -- JSON array of distinct tools that agree
  confidence REAL NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('single','combination')),
  title TEXT,
  UNIQUE (kind, canonical_id, resource_id)
);
CREATE INDEX IF NOT EXISTS idx_issues_state ON issues(state, severity);
CREATE INDEX IF NOT EXISTS idx_issues_resource ON issues(resource_id);
`

// IssueFilter narrows Issues().
type IssueFilter struct {
	OpenOnly bool   // state open or reopened
	Kind     string // model.IssueSingle | model.IssueCombination | model.IssuePath
	Provider string
	Account  string
	// Owner selects Issues whose governance owner equals it (case-insensitive);
	// "(unassigned)" selects Issues without an owner.
	Owner string
	// OverdueOnly keeps open/reopened Issues strictly past due_at at Now (suppressed and
	// resolved Issues are never overdue).
	OverdueOnly bool
	// Now is the clock Issue.Overdue is computed against (time.Now when zero).
	Now time.Time
}

// IssueCounts are the header numbers derived from Issues (not raw findings), so two
// tools reporting the same problem on the same resource count once.
// The top-level numbers cover finding-derived Issues (single, combination); path Issues
// are counted under Paths so existing headers keep their meaning.
type IssueCounts struct {
	Total      int `json:"total"`
	Open       int `json:"open"`
	Resolved   int `json:"resolved"`
	Suppressed int `json:"suppressed"`
	// VerifiedFixed / Pending: closure sub-states (verified_fixed is closed and confirmed;
	// pending_verification awaits the next scan or verify). Resolved is closure by absence only.
	VerifiedFixed int             `json:"verified_fixed"`
	Pending       int             `json:"pending_verification"`
	Combinations  int             `json:"combinations"`
	BySeverity    map[string]int  `json:"by_severity"`
	ByProvider    map[string]int  `json:"by_provider"`
	ByAccount     map[string]int  `json:"by_account"`
	Paths         PathIssueCounts `json:"paths"`
}

// PathIssueCounts summarizes kind=path Issues (open = open|reopened).
type PathIssueCounts struct {
	Total         int            `json:"total"`
	Open          int            `json:"open"`
	Resolved      int            `json:"resolved"`
	Suppressed    int            `json:"suppressed"`
	VerifiedFixed int            `json:"verified_fixed"`
	Pending       int            `json:"pending_verification"`
	BySeverity    map[string]int `json:"by_severity"`
	ByBand        map[string]int `json:"by_band"`
}

type activeFinding struct {
	id, source, canonical, resource, provider, account, title string
	severity                                                  model.Severity
	weaknesses                                                []string
	firstSeen                                                 time.Time
}

type issueDraft struct {
	model.Issue
	sources map[string]bool
}

func (d *issueDraft) add(f activeFinding, v *IssueVerdict) {
	d.FindingIDs = append(d.FindingIDs, f.id)
	d.sources[f.source] = true
	if sev := v.findingSeverity(f); d.Kind == model.IssueSingle && (len(d.FindingIDs) == 1 || sev.Rank() > d.Severity.Rank()) {
		d.Severity = sev
	} else if d.Kind == model.IssueCombination && sev.Rank() > d.Severity.Rank() {
		d.Severity = sev
	}
	if !f.firstSeen.IsZero() && (d.FirstSeen.IsZero() || f.firstSeen.Before(d.FirstSeen)) {
		d.FirstSeen = f.firstSeen
	}
	if d.Provider == "" {
		d.Provider, d.Account = f.provider, f.account
	}
}

// IssueVerdict is the analysis verdict an Issue's severity derives from (integration pass 2
// item 2). FindingBand maps a finding id to the band of its published risk score
// (internal/risk: Critical|High|Medium|Low); PathBand maps a resource id to the best band of
// the complete attack paths through it. Exposures (Analysis.Exposures) are deliberately not an
// input: an internet-reachable resource that is not on a path never raises a severity.
type IssueVerdict struct {
	FindingBand map[string]string
	PathBand    map[string]string
}

// BandSeverity maps a risk / path band to a severity ("" for an unknown band).
func BandSeverity(band string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(band)) {
	case "critical":
		return model.Critical
	case "high":
		return model.High
	case "medium":
		return model.Medium
	case "low":
		return model.Low
	}
	return ""
}

func maxSeverity(a, b model.Severity) model.Severity {
	if b != "" && (a == "" || b.Rank() > a.Rank()) {
		return b
	}
	return a
}

// findingSeverity is one finding's verdict severity: the risk band when one is known, never
// above the scanner severity (the risk score's exposure / data multipliers alone must not
// raise an Issue — only a complete path does, via PathBand); else the scanner severity.
func (v *IssueVerdict) findingSeverity(f activeFinding) model.Severity {
	if v == nil {
		return f.severity
	}
	b := BandSeverity(v.FindingBand[f.id])
	if b == "" || b.Rank() > f.severity.Rank() {
		return f.severity
	}
	return b
}

// RebuildIssues derives Issues from the current findings with scanner severities
// (RebuildIssuesWithVerdict with no verdict).
func (s *Store) RebuildIssues(now time.Time) error {
	return s.RebuildIssuesWithVerdict(now, nil)
}

// RebuildIssuesWithVerdict derives Issues from the current findings: one `single` Issue per
// (canonical_id, resource) over active failing findings, plus one `combination` Issue
// per declared model.ToxicCombinations match on a resource. Issues that are no longer
// supported by any active finding become resolved; a resolved Issue that comes back is
// reopened. first_seen is kept across rebuilds.
//
// Severity (v non-nil): a single Issue is max(min(risk band, scanner severity) over its
// findings, best path band through its resource); a combination Issue keeps its declared
// severity as a floor and is raised the same way. With v nil the scanner severity stands.
func (s *Store) RebuildIssuesWithVerdict(now time.Time, v *IssueVerdict) error {
	now = now.UTC()
	nowS := now.Format(time.RFC3339)
	rows, err := s.db.Query(`SELECT id, source, canonical_id, COALESCE(resource_id,''), provider, COALESCE(account,''), COALESCE(title,''),
	  severity, COALESCE(weaknesses,'[]'), COALESCE(first_seen,''), COALESCE(file,'')
	  FROM findings WHERE status = 'FAIL' AND state IN ('open','reopened') ORDER BY id`)
	if err != nil {
		return err
	}
	var active []activeFinding
	for rows.Next() {
		var f activeFinding
		var sev, weak, first, file string
		if err := rows.Scan(&f.id, &f.source, &f.canonical, &f.resource, &f.provider, &f.account, &f.title, &sev, &weak, &first, &file); err != nil {
			rows.Close()
			return err
		}
		f.severity = model.Severity(sev)
		_ = json.Unmarshal([]byte(weak), &f.weaknesses)
		f.firstSeen, _ = time.Parse(time.RFC3339, first)
		if f.resource == "" { // code findings: the file is the resource
			if file != "" {
				f.resource = "file:" + file
			} else {
				f.resource = "account:" + f.provider + "/" + f.account
			}
		}
		active = append(active, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	sensitive := map[string]bool{}
	if srows, err := s.db.Query("SELECT id FROM graph_nodes WHERE sensitive = 1"); err == nil {
		for srows.Next() {
			var id string
			if srows.Scan(&id) == nil {
				sensitive[id] = true
			}
		}
		srows.Close()
	}

	drafts := map[string]*issueDraft{}
	get := func(kind, canonical, resource, title string, sev model.Severity) *issueDraft {
		id := s.KeyID(legacyIssueDigest(kind, canonical, resource))
		d, ok := drafts[id]
		if !ok {
			d = &issueDraft{Issue: model.Issue{ID: id, Kind: kind, CanonicalID: canonical, ResourceID: resource, Title: title, Severity: sev}, sources: map[string]bool{}}
			drafts[id] = d
		}
		return d
	}
	byResource := map[string][]activeFinding{}
	for _, f := range active {
		get(model.IssueSingle, f.canonical, f.resource, f.title, f.severity).add(f, v)
		byResource[f.resource] = append(byResource[f.resource], f)
	}
	for res, fs := range byResource {
		for _, combo := range model.ToxicCombinations {
			var evidence []activeFinding
			ok := true
			for _, cond := range combo.AllOf {
				matched := false
				for _, f := range fs {
					if hasWeakness(f.weaknesses, cond) {
						evidence = append(evidence, f)
						matched = true
					}
				}
				if !matched && !(cond == model.ConditionSensitive && sensitive[res]) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			d := get(model.IssueCombination, combo.ID, res, combo.Title, combo.Severity)
			seen := map[string]bool{}
			for _, f := range evidence {
				if !seen[f.id] {
					seen[f.id] = true
					d.add(f, v)
				}
			}
		}
	}

	type prior struct {
		state, firstSeen, expiresAt, reason string
	}
	existing := map[string]prior{}
	// Only finding-derived kinds: path Issues are owned by RebuildPathIssues.
	erows, err := s.db.Query("SELECT id, state, COALESCE(first_seen,''), COALESCE(expires_at,''), COALESCE(reason,'') FROM issues WHERE kind IN ('single','combination')")
	if err != nil {
		return err
	}
	for erows.Next() {
		var id string
		var p prior
		if err := erows.Scan(&id, &p.state, &p.firstSeen, &p.expiresAt, &p.reason); err != nil {
			erows.Close()
			return err
		}
		existing[id] = p
	}
	erows.Close()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// reason/expires_at are carried into the would-be-inserted row (the suppression CHECK is
	// evaluated on it before the conflict is resolved); the UPDATE leaves them untouched.
	up, err := tx.Prepare(`INSERT INTO issues (id, canonical_id, resource_id, provider, account, severity, state, first_seen, last_seen, resolved_at,
	  finding_ids, sources, confidence, kind, title, reason, expires_at) VALUES (?,?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,NULLIF(?,''),NULLIF(?,''))
	  ON CONFLICT(id) DO UPDATE SET provider=excluded.provider, account=excluded.account, severity=excluded.severity, state=excluded.state,
	    last_seen=excluded.last_seen, resolved_at=NULL, finding_ids=excluded.finding_ids, sources=excluded.sources,
	    confidence=excluded.confidence, title=excluded.title`)
	if err != nil {
		return err
	}
	defer up.Close()
	for id, d := range drafts {
		if v != nil {
			d.Severity = maxSeverity(d.Severity, BandSeverity(v.PathBand[d.ResourceID]))
		}
		state := model.StateOpen
		first := d.FirstSeen
		p, had := existing[id]
		if had {
			var regressed bool
			state, regressed = nextState(p.state, true, p.expiresAt, now)
			if state != p.state && (p.state == model.StateSuppressed || regressed || p.state == model.StatePendingVerification) {
				// Issue-level transitions its evidence findings' history cannot show (verify-4 D3):
				// the expiry reopen and the regression after verify start a fresh episode; a pending
				// mark settled by "still observed" returns to open.
				detail := ""
				if p.state == model.StatePendingVerification {
					detail = "fix not observed: problem still present"
				} else if regressed {
					detail = "problem observed again after verified_fixed"
				}
				if _, err := tx.Exec("INSERT INTO path_issue_history (issue_id, state, at, scan_id, score, secondary_key, regressed_after_verify, detail) VALUES (?,?,?,NULL,NULL,NULL,?,NULLIF(?,''))",
					id, state, nowS, regressed, detail); err != nil {
					return err
				}
			}
			if regressed {
				if _, err := tx.Exec("UPDATE issues SET regressed_after_verify = 1 WHERE id = ?", id); err != nil {
					return err
				}
			}
			if p.state == model.StatePendingVerification && state != p.state {
				if _, err := tx.Exec("UPDATE issues SET pending_at = NULL, pending_by = NULL WHERE id = ?", id); err != nil {
					return err
				}
			}
			if t, err := time.Parse(time.RFC3339, p.firstSeen); err == nil {
				first = t
			}
		}
		if first.IsZero() {
			first = now
		}
		for src := range d.sources {
			d.Sources = append(d.Sources, src)
		}
		sort.Strings(d.Sources)
		sort.Strings(d.FindingIDs)
		fids, _ := json.Marshal(d.FindingIDs)
		srcs, _ := json.Marshal(d.Sources)
		if _, err := up.Exec(id, d.CanonicalID, d.ResourceID, d.Provider, d.Account, string(d.Severity), state, first.Format(time.RFC3339), nowS,
			string(fids), string(srcs), model.IssueConfidence(len(d.Sources)), d.Kind, d.Title, p.reason, p.expiresAt); err != nil {
			return err
		}
	}
	for id, p := range existing {
		if _, ok := drafts[id]; ok {
			continue
		}
		state, _ := nextState(p.state, false, p.expiresAt, now)
		if state == p.state {
			continue // resolved stays resolved; verified_fixed survives absence
		}
		if _, err := tx.Exec("UPDATE issues SET state = ?, resolved_at = ?, pending_at = NULL, pending_by = NULL WHERE id = ?", state, nowS, id); err != nil {
			return err
		}
		if p.state == model.StatePendingVerification {
			if _, err := tx.Exec("INSERT INTO path_issue_history (issue_id, state, at, scan_id, score, secondary_key, detail) VALUES (?,?,?,NULL,NULL,NULL,?)",
				id, state, nowS, "pending fix: problem no longer observed"); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func hasWeakness(ws []string, w string) bool {
	for _, x := range ws {
		if x == w {
			return true
		}
	}
	return false
}

// Issues lists stored Issues: path Issues by score, then finding Issues by severity.
func (s *Store) Issues(fl IssueFilter) ([]model.Issue, error) {
	var where []string
	var args []any
	if fl.OpenOnly {
		where = append(where, "state IN ('open','reopened')")
	}
	if fl.Kind != "" {
		where = append(where, "kind = ?")
		args = append(args, fl.Kind)
	}
	if fl.Provider != "" {
		where = append(where, "provider = ?")
		args = append(args, fl.Provider)
	}
	if fl.Account != "" {
		where = append(where, "account = ?")
		args = append(args, fl.Account)
	}
	if o := strings.TrimSpace(fl.Owner); o != "" {
		if o == unassignedOwner {
			where = append(where, "COALESCE(owner,'') = ''")
		} else {
			where = append(where, "owner = ? COLLATE NOCASE")
			args = append(args, o)
		}
	}
	now := fl.Now
	if now.IsZero() {
		now = time.Now()
	}
	if fl.OverdueOnly {
		where = append(where, "state IN ('open','reopened') AND due_at IS NOT NULL AND due_at <> '' AND due_at < ?")
		args = append(args, now.UTC().Format(time.RFC3339))
	}
	q := `SELECT id, canonical_id, resource_id, COALESCE(provider,''), COALESCE(account,''), severity, state, COALESCE(first_seen,''), COALESCE(last_seen,''),
	  resolved_at, finding_ids, sources, confidence, kind, COALESCE(title,''), ` + issuePathColumns + ` FROM issues`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	// Path Issues first by score (the Wiz Issues queue: the toxic path above any single finding),
	// then finding Issues by severity, combinations before singles (r3 #4 / E10).
	q += ` ORDER BY CASE kind WHEN 'path' THEN 0 ELSE 1 END, CASE WHEN kind = 'path' THEN -COALESCE(score,0) ELSE 0 END,
	  CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, kind DESC, canonical_id, resource_id, id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Issue
	for rows.Next() {
		var is model.Issue
		var sev, first, last, fids, srcs string
		var resolved sql.NullString
		var pc pathCols
		if err := rows.Scan(append([]any{&is.ID, &is.CanonicalID, &is.ResourceID, &is.Provider, &is.Account, &sev, &is.State, &first, &last,
			&resolved, &fids, &srcs, &is.Confidence, &is.Kind, &is.Title}, pc.dest()...)...); err != nil {
			return nil, err
		}
		pc.apply(&is)
		is.Severity = model.Severity(sev)
		is.FirstSeen, _ = time.Parse(time.RFC3339, first)
		is.LastSeen, _ = time.Parse(time.RFC3339, last)
		is.ResolvedAt = parseNullTime(resolved)
		_ = json.Unmarshal([]byte(fids), &is.FindingIDs)
		_ = json.Unmarshal([]byte(srcs), &is.Sources)
		is.Overdue = is.IsOverdue(now)
		if fl.OverdueOnly && !is.Overdue {
			continue
		}
		out = append(out, is)
	}
	return out, rows.Err()
}

// IssueCounts summarizes Issues for /api/summary-style headers (open = open|reopened).
func (s *Store) IssueCounts() (*IssueCounts, error) {
	c := &IssueCounts{BySeverity: map[string]int{}, ByProvider: map[string]int{}, ByAccount: map[string]int{},
		Paths: PathIssueCounts{BySeverity: map[string]int{}, ByBand: map[string]int{}}}
	rows, err := s.db.Query("SELECT COALESCE(provider,''), COALESCE(account,''), severity, state, kind, COALESCE(band,'') FROM issues")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var prov, acct, sev, state, kind, band string
		if err := rows.Scan(&prov, &acct, &sev, &state, &kind, &band); err != nil {
			return nil, err
		}
		if kind == model.IssuePath {
			p := &c.Paths
			p.Total++
			switch {
			case state == model.StateSuppressed:
				p.Suppressed++
			case state == model.StateVerifiedFixed:
				p.VerifiedFixed++
			case state == model.StatePendingVerification:
				p.Pending++
			case !model.IsActive(state):
				p.Resolved++
			default:
				p.Open++
				p.BySeverity[sev]++
				p.ByBand[band]++
			}
			continue
		}
		if kind != model.IssueSingle && kind != model.IssueCombination {
			continue // chokepoint / correlated: reserved, not yet produced
		}
		c.Total++
		if state == model.StateSuppressed {
			c.Suppressed++
			continue
		}
		if state == model.StateVerifiedFixed {
			c.VerifiedFixed++
			continue
		}
		if state == model.StatePendingVerification {
			c.Pending++
			continue
		}
		if !model.IsActive(state) {
			c.Resolved++
			continue
		}
		c.Open++
		c.BySeverity[sev]++
		c.ByProvider[prov]++
		c.ByAccount[prov+"/"+acct]++
		if kind == model.IssueCombination {
			c.Combinations++
		}
	}
	return c, rows.Err()
}
