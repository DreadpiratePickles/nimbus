package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Path-level Issues (plan v3 P1-ISSUES item 10, AP3/RP5/RP7). One Issue per
// model.PathIssueID(path, entry, anchor, rule) over the complete paths of an analysis; the
// hop lists are evidence (secondary keys), so a re-routed path keeps its Issue.

// issuePathColumns are the migration-6 columns Issues() reads after the v5 ones.
const issuePathColumns = `entry_id, COALESCE(anchor_id,''), COALESCE(rule_id,''), COALESCE(secondary_key,''), COALESCE(secondary_keys,''),
	  COALESCE(path_ids,''), score, COALESCE(band,''), COALESCE(confidence_label,''), validation_json, weak_link, COALESCE(toxic_combination,''),
	  COALESCE(reason,''), expires_at, COALESCE(approved_by,''), verified_at, COALESCE(verified_by,''),
	  COALESCE(owner,''), COALESCE(owner_source,''), COALESCE(owner_rule,''), COALESCE(owner_why,''), COALESCE(sla_days,0), due_at, grace_until,
	  COALESCE(ticket_sink,''), COALESCE(ticket_key,''), COALESCE(ticket_url,''), COALESCE(ticket_state,''),
	  pending_at, COALESCE(pending_by,''), COALESCE(regressed_after_verify,0)`

type pathCols struct {
	entry, anchor, rule, key, keys, pathIDs, band, conf, validation, toxic, reason, approved, verifiedBy string
	score                                                                                                sql.NullFloat64
	weak                                                                                                 bool
	expires, verifiedAt                                                                                  sql.NullString
	owner, ownerSource, ownerRule, ownerWhy                                                              string
	slaDays                                                                                              int
	dueAt, graceUntil                                                                                    sql.NullString
	ticketSink, ticketKey, ticketURL, ticketState                                                        string
	pendingAt                                                                                            sql.NullString
	pendingBy                                                                                            string
	regressed                                                                                            bool
}

func (c *pathCols) dest() []any {
	return []any{&c.entry, &c.anchor, &c.rule, &c.key, &c.keys, &c.pathIDs, &c.score, &c.band, &c.conf, &c.validation, &c.weak, &c.toxic,
		&c.reason, &c.expires, &c.approved, &c.verifiedAt, &c.verifiedBy,
		&c.owner, &c.ownerSource, &c.ownerRule, &c.ownerWhy, &c.slaDays, &c.dueAt, &c.graceUntil,
		&c.ticketSink, &c.ticketKey, &c.ticketURL, &c.ticketState, &c.pendingAt, &c.pendingBy, &c.regressed}
}

func (c *pathCols) apply(is *model.Issue) {
	is.EntryID, is.AnchorID, is.RuleID, is.SecondaryKey, is.Band = c.entry, c.anchor, c.rule, c.key, c.band
	is.ConfidenceLabel, is.WeakLink, is.ToxicCombination = model.Confidence(c.conf), c.weak, c.toxic
	is.Reason, is.ApprovedBy, is.VerifiedBy = c.reason, c.approved, c.verifiedBy
	is.Score = c.score.Float64
	is.ExpiresAt, is.VerifiedAt = parseNullTime(c.expires), parseNullTime(c.verifiedAt)
	is.Owner, is.OwnerSource, is.OwnerRule, is.OwnerWhy, is.SLADays = c.owner, c.ownerSource, c.ownerRule, c.ownerWhy, c.slaDays
	is.DueAt, is.GraceUntil = parseNullTime(c.dueAt), parseNullTime(c.graceUntil)
	is.TicketSink, is.TicketKey, is.TicketURL, is.TicketState = c.ticketSink, c.ticketKey, c.ticketURL, c.ticketState
	is.PendingAt, is.PendingBy, is.RegressedAfterVerify = parseNullTime(c.pendingAt), c.pendingBy, c.regressed
	if c.keys != "" {
		_ = json.Unmarshal([]byte(c.keys), &is.SecondaryKeys)
	}
	if c.pathIDs != "" {
		_ = json.Unmarshal([]byte(c.pathIDs), &is.PathIDs)
	}
	if is.Kind == model.IssuePath || c.validation != `{"status":"theoretical"}` {
		var v model.ValidationResult
		if json.Unmarshal([]byte(c.validation), &v) == nil {
			is.Validation = &v
		}
	}
}

func suppressionExpired(expiresAt string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, expiresAt)
	return err != nil || !now.Before(t)
}

// PathIssueResult reports what one RebuildPathIssues call changed.
type PathIssueResult struct {
	Opened   int `json:"opened"`   // new Issues
	Reopened int `json:"reopened"` // resolved (or expired suppression) Issues observed again
	Resolved int `json:"resolved"` // Issues whose every path is gone
	Updated  int `json:"updated"`  // still-present Issues (score / secondary key refreshed)
	// OutOfScope counts paths of the analysis that touch a node outside a scoped rebuild's
	// accounts: they are neither written nor used to resolve anything (RebuildPathIssuesScoped).
	OutOfScope int      `json:"out_of_scope,omitempty"`
	IDs        []string `json:"ids"` // present path Issue ids, sorted
	// The ids behind Opened / Reopened / Resolved (scan --diff), sorted.
	OpenedIDs   []string `json:"opened_ids,omitempty"`
	ReopenedIDs []string `json:"reopened_ids,omitempty"`
	ResolvedIDs []string `json:"resolved_ids,omitempty"`
	// RegressedIDs are the reopened Issues that had been verified_fixed (sorted).
	RegressedIDs []string `json:"regressed_ids,omitempty"`
}

type pathDraft struct {
	id, entry, anchor, rule string
	best                    model.AttackPath
	score                   float64
	severity                model.Severity
	weakAll                 bool
	keys, pathIDs, findings map[string]bool
}

// RebuildPathIssues upserts one kind=path Issue per (entry, anchor, rule) over an.Paths
// (complete paths only: an.Incomplete is never an Issue, and exposure-only results are not
// path Issues). Score is the max over the Issue's paths, band follows the score, the
// confidence label, toxic combination and secondary key come from the highest-scoring path,
// and weak_link is set only when every path is a weak-link chain. Path Issues absent from
// the analysis are resolved; a resolved Issue that returns is reopened with first_seen
// kept; a suppressed Issue stays suppressed until its expires_at, then reopens. Every state
// change and every secondary-key change is appended to path_issue_history.
//
// The analysis is taken as the whole estate: callers must pass the traversal of the full
// stored graph, not of a single account's subset.
func (s *Store) RebuildPathIssues(scanID string, an *attackpath.Analysis, now time.Time) (*PathIssueResult, error) {
	return s.RebuildPathIssuesScoped(scanID, an, now, nil)
}

// PathScope bounds a path-Issue rebuild to what a partial scan observed (integration pass 2
// item 8): `scan --accounts A` must not resolve path Issues of accounts it did not look at.
type PathScope struct {
	// Accounts are the "provider/account" keys the scan examined.
	Accounts map[string]bool
	// NodeAccount returns a node's "provider/account" key; known=false for a node not in the
	// graph. A known node with an empty key (the internet, global pseudo-nodes) is neutral.
	NodeAccount func(id string) (key string, known bool)
}

// nodeIn reports a known node inside the scope (neutral nodes count as inside); unknownOK
// decides an unknown node.
func (sc *PathScope) nodeIn(id string, unknownOK bool) bool {
	if id == model.PathEntryInternet {
		return true
	}
	if sc.NodeAccount == nil {
		return unknownOK
	}
	key, known := sc.NodeAccount(id)
	if !known {
		return unknownOK
	}
	return key == "" || strings.HasSuffix(key, "/") || sc.Accounts[key]
}

// pathIn: every hop is a known node inside the scope.
func (sc *PathScope) pathIn(p model.AttackPath) bool {
	if sc == nil {
		return true
	}
	for _, st := range p.Steps {
		if !sc.nodeIn(st.Resource, false) {
			return false
		}
	}
	return true
}

// issueIn decides whether a stored path Issue lies inside the scope and may be resolved by
// absence: its entry and anchor must not be known nodes of another account, and its own
// provider/account (or a known entry/anchor) must be one the scan examined.
func (sc *PathScope) issueIn(provider, account, entry, anchor string) bool {
	if sc == nil {
		return true
	}
	if !sc.nodeIn(entry, true) || !sc.nodeIn(anchor, true) {
		return false
	}
	if sc.Accounts[provider+"/"+account] {
		return true
	}
	for _, id := range []string{entry, anchor} {
		if sc.NodeAccount == nil || id == model.PathEntryInternet {
			continue
		}
		if key, known := sc.NodeAccount(id); known && key != "" && sc.Accounts[key] {
			return true
		}
	}
	return false
}

// RebuildPathIssuesScoped is RebuildPathIssues limited to scope: only paths whose every hop
// is inside the scope are written, and only stored path Issues inside the scope are resolved
// by absence. A nil scope is the whole estate (RebuildPathIssues).
func (s *Store) RebuildPathIssuesScoped(scanID string, an *attackpath.Analysis, now time.Time, scope *PathScope) (*PathIssueResult, error) {
	if an == nil {
		return nil, errors.New("store: RebuildPathIssues needs an analysis (nil would resolve every path Issue)")
	}
	now = now.UTC()
	nowS := now.Format(time.RFC3339)
	res := &PathIssueResult{}

	drafts := map[string]*pathDraft{}
	for _, p := range an.Paths {
		if len(p.Steps) == 0 {
			continue
		}
		if !scope.pathIn(p) {
			res.OutOfScope++
			continue
		}
		entry, anchor, rule := model.PathIssueKey(p)
		id := s.KeyID(model.PathIssueID(model.IssuePath, entry, anchor, rule))
		d, ok := drafts[id]
		if !ok {
			d = &pathDraft{id: id, entry: entry, anchor: anchor, rule: rule, best: p, score: p.Score, severity: p.Severity, weakAll: true,
				keys: map[string]bool{}, pathIDs: map[string]bool{}, findings: map[string]bool{}}
			drafts[id] = d
		} else if p.Score > d.score || (p.Score == d.score && model.PathSecondaryKey(p) < model.PathSecondaryKey(d.best)) {
			d.best, d.score = p, p.Score
		}
		if p.Severity.Rank() > d.severity.Rank() {
			d.severity = p.Severity
		}
		d.weakAll = d.weakAll && p.WeakLink
		d.keys[s.KeyID(model.PathSecondaryKey(p))] = true
		if p.ID != "" {
			d.pathIDs[p.ID] = true
		}
		for _, f := range p.FindingIDs {
			d.findings[f] = true
		}
	}

	type prior struct {
		state, firstSeen, expiresAt, key string
		provider, account, entry, anchor string
	}
	existing := map[string]prior{}
	rows, err := s.db.Query(`SELECT id, state, COALESCE(first_seen,''), COALESCE(expires_at,''), COALESCE(secondary_key,''),
	  COALESCE(provider,''), COALESCE(account,''), entry_id, COALESCE(anchor_id,'') FROM issues WHERE kind = ?`, model.IssuePath)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var p prior
		if err := rows.Scan(&id, &p.state, &p.firstSeen, &p.expiresAt, &p.key, &p.provider, &p.account, &p.entry, &p.anchor); err != nil {
			rows.Close()
			return nil, err
		}
		existing[id] = p
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Titles read the stored graph: computed before the write transaction opens.
	title := s.pathTitler()
	titles := make(map[string]string, len(drafts))
	for id, d := range drafts {
		titles[id] = title(d.best)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// New Issues are inserted; existing ones updated in place (an UPSERT would CHECK the
	// would-be-inserted row, which has no suppression reason, before resolving the conflict).
	ins, err := tx.Prepare(`INSERT INTO issues (provider, account, severity, state, first_seen, last_seen,
	  finding_ids, sources, confidence, title, secondary_key, secondary_keys, path_ids, score, band,
	  confidence_label, weak_link, toxic_combination, id, canonical_id, resource_id, kind, entry_id, anchor_id, rule_id)
	  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return nil, err
	}
	defer ins.Close()
	upd, err := tx.Prepare(`UPDATE issues SET provider=?, account=?, severity=?, state=?, first_seen=?, last_seen=?, resolved_at=NULL,
	  finding_ids=?, sources=?, confidence=?, title=?, secondary_key=?, secondary_keys=?, path_ids=?, score=?, band=?,
	  confidence_label=?, weak_link=?, toxic_combination=? WHERE id=?`)
	if err != nil {
		return nil, err
	}
	defer upd.Close()
	hist, err := tx.Prepare("INSERT INTO path_issue_history (issue_id, state, at, scan_id, score, secondary_key, regressed_after_verify, detail) VALUES (?,?,?,?,?,?,?,NULLIF(?,''))")
	if err != nil {
		return nil, err
	}
	defer hist.Close()

	ids := make([]string, 0, len(drafts))
	for id := range drafts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := drafts[id]
		key := s.KeyID(model.PathSecondaryKey(d.best))
		state, first := model.StateOpen, nowS
		p, had := existing[id]
		regressed := false
		if !had {
			res.Opened++
			res.OpenedIDs = append(res.OpenedIDs, id)
		} else {
			state, regressed = nextState(p.state, true, p.expiresAt, now)
			switch {
			case state == model.StateReopened && p.state != model.StateReopened:
				res.Reopened++
				res.ReopenedIDs = append(res.ReopenedIDs, id)
				if regressed {
					res.RegressedIDs = append(res.RegressedIDs, id)
				}
			default:
				res.Updated++
			}
		}
		if had && p.firstSeen != "" {
			first = p.firstSeen
		}
		keys, pids, fids := sortedKeys(d.keys), sortedKeys(d.pathIDs), sortedKeys(d.findings)
		kj, _ := json.Marshal(keys)
		pj, _ := json.Marshal(pids)
		fj, _ := json.Marshal(fids)
		var toxic any
		if t := attackpath.ToxicCombination(d.best); t != "" {
			toxic = t
		}
		// Path Issue severity is its band (integration pass 2 item 2), not the path's label.
		args := []any{d.best.Provider, d.best.Account, string(BandSeverity(model.ScoreBand(d.score))), state, first, nowS,
			string(fj), `["attackpath"]`, model.IssueConfidence(1), titles[id], key, string(kj), string(pj), d.score, model.ScoreBand(d.score),
			string(model.PathConfidence(d.best)), d.weakAll, toxic, id}
		if had {
			_, err = upd.Exec(args...)
		} else {
			_, err = ins.Exec(append(args, d.rule, d.anchor, model.IssuePath, d.entry, d.anchor, d.rule)...)
		}
		if err != nil {
			return nil, fmt.Errorf("write path issue %s: %w", id, err)
		}
		if !had || state != p.state || key != p.key {
			detail := ""
			if had && p.state == model.StatePendingVerification && state != p.state {
				detail = "fix not observed: problem still present"
			} else if regressed {
				detail = "problem observed again after verified_fixed"
			}
			if _, err := hist.Exec(id, state, nowS, scanID, d.score, key, regressed, detail); err != nil {
				return nil, err
			}
		}
		if regressed {
			if _, err := tx.Exec("UPDATE issues SET regressed_after_verify = 1 WHERE id = ?", id); err != nil {
				return nil, err
			}
		}
		if had && p.state == model.StatePendingVerification && state != p.state {
			if _, err := tx.Exec("UPDATE issues SET pending_at = NULL, pending_by = NULL WHERE id = ?", id); err != nil {
				return nil, err
			}
		}
		res.IDs = append(res.IDs, id)
	}
	for id, p := range existing {
		if _, ok := drafts[id]; ok {
			continue
		}
		next, _ := nextState(p.state, false, p.expiresAt, now)
		if next == p.state {
			continue // resolved stays resolved; verified_fixed survives absence
		}
		if !scope.issueIn(p.provider, p.account, p.entry, p.anchor) {
			continue // not examined by this (partial) scan: never resolved by absence
		}
		if _, err := tx.Exec("UPDATE issues SET state = ?, resolved_at = ?, pending_at = NULL, pending_by = NULL WHERE id = ?", next, nowS, id); err != nil {
			return nil, err
		}
		detail := ""
		if p.state == model.StatePendingVerification {
			detail = "pending fix: problem no longer observed"
		}
		if _, err := hist.Exec(id, next, nowS, scanID, nil, p.key, false, detail); err != nil {
			return nil, err
		}
		res.Resolved++
		res.ResolvedIDs = append(res.ResolvedIDs, id)
	}
	sort.Strings(res.ResolvedIDs)
	return res, tx.Commit()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ErrIssueNotFound is returned for an Issue id that is not stored.
var ErrIssueNotFound = errors.New("store: issue not found")

// Suppression bounds (verify-4 LOW): an accepted risk is re-reviewed at least yearly, and the
// stored free text is bounded.
const (
	MaxSuppression           = 366 * 24 * time.Hour // expires_at at most this far after now
	MaxSuppressionReason     = 2 << 10              // bytes
	MaxSuppressionApprovedBy = 256                  // bytes
)

// Suppression is an accepted risk on one Issue (plan v3 RP7).
type Suppression struct {
	Reason     string
	ExpiresAt  time.Time
	ApprovedBy string // optional
}

// SuppressionError rejects a suppression without a reason, without an expiry, with an expiry
// that is not in the future or more than MaxSuppression ahead, or with oversized text.
type SuppressionError struct {
	Problems []string
}

func (e *SuppressionError) Error() string {
	return "store: invalid suppression: " + strings.Join(e.Problems, "; ")
}

// SuppressIssue moves an Issue (any kind) to state suppressed. The Issue reopens on the
// next rebuild after ExpiresAt if it is still observed (RebuildPathIssues, RebuildIssues).
func (s *Store) SuppressIssue(id string, sup Suppression, now time.Time) error {
	var problems []string
	if strings.TrimSpace(sup.Reason) == "" {
		problems = append(problems, "reason is required")
	}
	if sup.ExpiresAt.IsZero() {
		problems = append(problems, "expires_at is required")
	} else if !sup.ExpiresAt.After(now) {
		problems = append(problems, "expires_at must be in the future")
	} else if sup.ExpiresAt.After(now.Add(MaxSuppression)) {
		problems = append(problems, "expires_at must be within one year (re-review an accepted risk at least yearly)")
	}
	if len(sup.Reason) > MaxSuppressionReason {
		problems = append(problems, fmt.Sprintf("reason is longer than %d bytes", MaxSuppressionReason))
	}
	if len(sup.ApprovedBy) > MaxSuppressionApprovedBy {
		problems = append(problems, fmt.Sprintf("approved_by is longer than %d bytes", MaxSuppressionApprovedBy))
	}
	if len(problems) > 0 {
		return &SuppressionError{Problems: problems}
	}
	now = now.UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var kind string
	var score sql.NullFloat64
	var key sql.NullString
	if err := tx.QueryRow("SELECT kind, score, secondary_key FROM issues WHERE id = ?", id).Scan(&kind, &score, &key); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrIssueNotFound, id)
		}
		return err
	}
	var approved any
	if sup.ApprovedBy != "" {
		approved = sup.ApprovedBy
	}
	if _, err := tx.Exec(`UPDATE issues SET state = ?, reason = ?, expires_at = ?, approved_by = ?, suppressed_at = ? WHERE id = ?`,
		model.StateSuppressed, strings.TrimSpace(sup.Reason), sup.ExpiresAt.UTC().Format(time.RFC3339), approved, now.Format(time.RFC3339), id); err != nil {
		return err
	}
	// Every kind records the transition (path_issue_history is keyed by Issue id): a single or
	// combination Issue's suppression and its expiry reopen are Issue-level episode boundaries
	// that its evidence findings' history cannot show (verify-4 D3).
	if _, err := tx.Exec("INSERT INTO path_issue_history (issue_id, state, at, scan_id, score, secondary_key) VALUES (?,?,?,NULL,?,?)",
		id, model.StateSuppressed, now.Format(time.RFC3339), score, key); err != nil {
		return err
	}
	return tx.Commit()
}

// PathIssueHistoryEntry is one path_issue_history row.
type PathIssueHistoryEntry struct {
	State        string    `json:"state"`
	At           time.Time `json:"at"`
	ScanID       string    `json:"scan_id,omitempty"`
	Score        float64   `json:"score,omitempty"`
	SecondaryKey string    `json:"secondary_key,omitempty"`
	// RegressedAfterVerify marks a reopen of an Issue that had been verified_fixed.
	RegressedAfterVerify bool   `json:"regressed_after_verify,omitempty"`
	Detail               string `json:"detail,omitempty"`
}

// PathIssueHistory lists a path Issue's transitions and secondary-key changes, oldest first.
func (s *Store) PathIssueHistory(id string) ([]PathIssueHistoryEntry, error) {
	rows, err := s.db.Query(`SELECT state, at, COALESCE(scan_id,''), score, COALESCE(secondary_key,''), COALESCE(regressed_after_verify,0), COALESCE(detail,'')
	  FROM path_issue_history WHERE issue_id = ? ORDER BY at, rowid`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PathIssueHistoryEntry
	for rows.Next() {
		var e PathIssueHistoryEntry
		var at string
		var score sql.NullFloat64
		if err := rows.Scan(&e.State, &at, &e.ScanID, &score, &e.SecondaryKey, &e.RegressedAfterVerify, &e.Detail); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339, at)
		e.Score = score.Float64
		out = append(out, e)
	}
	return out, rows.Err()
}

// pathTitler titles path Issues with model.PathIssueTitle against the stored graph (names and
// attached policies of the entry and anchor nodes); a node missing from the graph falls back to
// its id's last segment.
func (s *Store) pathTitler() func(model.AttackPath) string {
	cache := map[string]*model.PathNode{}
	lookup := func(id string) (model.PathNode, bool) {
		if n, ok := cache[id]; ok {
			if n == nil {
				return model.PathNode{}, false
			}
			return *n, true
		}
		var name, doc sql.NullString
		err := s.db.QueryRow("SELECT name, doc FROM graph_nodes WHERE id = ?", id).Scan(&name, &doc)
		if err != nil {
			cache[id] = nil
			return model.PathNode{}, false
		}
		n := &model.PathNode{Name: name.String}
		var d struct {
			Name  string         `json:"name"`
			Attrs map[string]any `json:"attributes"`
		}
		if json.Unmarshal([]byte(doc.String), &d) == nil {
			n.Attrs = d.Attrs
			if n.Name == "" {
				n.Name = d.Name
			}
		}
		cache[id] = n
		return *n, true
	}
	return func(p model.AttackPath) string { return model.PathIssueTitle(p, lookup) }
}
