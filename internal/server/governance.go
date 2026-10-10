package server

// Governance read side (integration pass 4): the metrics view every surface prints (CLI
// `issues metrics`, GET /api/governance/metrics, the dashboard owners panel) and the single
// due date: risk.Ranked's owner / sla_days / due_at are filled from the Issue that carries the
// finding, so no output shows the retired risk band SLA.

import (
	"math"
	"sort"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/governance"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// OwnerRow is one owner's open and overdue Issue counts.
type OwnerRow struct {
	Owner   string `json:"owner"`
	Open    int    `json:"open"`
	Overdue int    `json:"overdue"`
}

// GovernanceMetrics is governance.Report with durations in hours and an owner table.
type GovernanceMetrics struct {
	GeneratedAt         time.Time          `json:"generated_at"`
	MTTRHoursBySeverity map[string]float64 `json:"mttr_hours_by_severity"`
	ResolvedBySeverity  map[string]int     `json:"resolved_by_severity"`
	Open                int                `json:"open"`
	Suppressed          int                `json:"suppressed"`
	OpenPastDue         int                `json:"open_past_due"`
	OpenPastGrace       int                `json:"open_past_grace"`
	OnTime              int                `json:"on_time"`
	Late                int                `json:"late"`
	OnTimeRate          float64            `json:"on_time_rate"`
	OverdueByOwner      map[string]int     `json:"overdue_by_owner"`
	OpenByOwner         map[string]int     `json:"open_by_owner"`
	Owners              []OwnerRow         `json:"owners"` // overdue desc, open desc, owner
	// PendingVerification counts Issues awaiting the next scan or verify (never open/overdue).
	PendingVerification int `json:"pending_verification"`
	// Closure: verified-fixed vs resolved-by-absence and regressions after verify (W5-ISSUES).
	Closure *store.ClosureMetrics `json:"closure"`
	// ScanTrend is the per-scan Issue trend, newest first (store.ScanTrends, r4 #12): new /
	// resolved / reopened / verified fixed / regressed per scan, open and verified share after
	// it. The dashboard trend panel plots it (the payload carries governance, the server too).
	ScanTrend []store.ScanTrendRow `json:"scan_trend"`
}

// graceDays is the stored grace period of an Issue (grace_until − due_at).
func graceDays(is model.Issue) int {
	if is.DueAt == nil || is.GraceUntil == nil {
		return 0
	}
	return int(math.Round(is.GraceUntil.Sub(*is.DueAt).Hours() / 24))
}

// AssignmentOf is the stored governance assignment of an Issue.
func AssignmentOf(is model.Issue) governance.Assignment {
	a := governance.Assignment{Owner: is.Owner, Source: is.OwnerSource, RuleID: is.OwnerRule, SLADays: is.SLADays, GraceDays: graceDays(is), Why: is.OwnerWhy}
	if is.DueAt != nil {
		a.DueAt = is.DueAt.UTC()
	}
	if is.GraceUntil != nil {
		a.GraceUntil = is.GraceUntil.UTC()
	}
	return a
}

// BuildGovernanceMetrics computes MTTR / on-time / overdue from the stored lifecycle history,
// attributing each Issue with its stored owner and SLA.
func BuildGovernanceMetrics(st *store.Store, now time.Time) (*GovernanceMetrics, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	events, err := governance.CollectEvents(st, AssignmentOf)
	if err != nil {
		return nil, err
	}
	r := governance.Metrics(events, now)
	m := &GovernanceMetrics{GeneratedAt: now.UTC(), MTTRHoursBySeverity: map[string]float64{}, ResolvedBySeverity: map[string]int{},
		Open: r.Open, Suppressed: r.Suppressed, OpenPastDue: r.OpenPastDue, OpenPastGrace: r.OpenPastGrace, OnTime: r.OnTime, Late: r.Late,
		OnTimeRate: r.OnTimeRate, OverdueByOwner: r.OverdueByOwner, OpenByOwner: r.OpenByOwner, Owners: []OwnerRow{}}
	for sev, d := range r.MTTRBySeverity {
		m.MTTRHoursBySeverity[string(sev)] = math.Round(d.Hours()*10) / 10
	}
	for sev, n := range r.ResolvedBySeverity {
		m.ResolvedBySeverity[string(sev)] = n
	}
	// Open / overdue / past grace are read from the stored due_at (the date every other surface
	// shows), so `issues --overdue`, the API filter and these counts can never disagree.
	issues, err := st.Issues(store.IssueFilter{Now: now})
	if err != nil {
		return nil, err
	}
	if m.Closure, err = st.ClosureMetrics(); err != nil {
		return nil, err
	}
	m.PendingVerification = m.Closure.PendingVerification
	if m.ScanTrend, err = st.ScanTrends(24); err != nil {
		return nil, err
	}
	m.Open, m.Suppressed, m.OpenPastDue, m.OpenPastGrace = 0, 0, 0, 0
	m.OpenByOwner, m.OverdueByOwner = map[string]int{}, map[string]int{}
	for _, is := range issues {
		switch {
		case is.State == model.StateSuppressed:
			m.Suppressed++
		case model.IsActive(is.State):
			m.Open++
			o := governance.OwnerKey(is.Owner)
			m.OpenByOwner[o]++
			if is.Overdue {
				m.OpenPastDue++
				m.OverdueByOwner[o]++
			}
			if is.GraceUntil != nil && now.After(*is.GraceUntil) {
				m.OpenPastGrace++
			}
		}
	}
	for o, n := range m.OpenByOwner {
		m.Owners = append(m.Owners, OwnerRow{Owner: o, Open: n, Overdue: m.OverdueByOwner[o]})
	}
	sort.Slice(m.Owners, func(i, j int) bool {
		a, b := m.Owners[i], m.Owners[j]
		if a.Overdue != b.Overdue {
			return a.Overdue > b.Overdue
		}
		if a.Open != b.Open {
			return a.Open > b.Open
		}
		return a.Owner < b.Owner
	})
	return m, nil
}

// GovernRanked replaces the retired risk band owner / SLA / due date of each ranked finding
// with the governance assignment of the Issue that carries it (single Issue first, then the
// most severe combination or path Issue). A finding no Issue carries keeps its owner tag and
// has no SLA (sla_days 0, due_at zero).
func GovernRanked(ranked []risk.Ranked, issues []model.Issue) {
	best := map[string]model.Issue{}
	rank := func(is model.Issue) int {
		r := is.Severity.Rank()
		if is.Kind == model.IssueSingle {
			r += 100
		}
		return r
	}
	for _, is := range issues {
		if is.OwnerSource == "" {
			continue // never resolved (no governance run on this database yet)
		}
		for _, f := range is.FindingIDs {
			if cur, ok := best[f]; !ok || rank(is) > rank(cur) {
				best[f] = is
			}
		}
	}
	for i := range ranked {
		r := &ranked[i]
		r.SLADays, r.DueAt = 0, time.Time{}
		is, ok := best[r.Finding.ID]
		if !ok {
			continue
		}
		r.Owner, r.SLADays = is.Owner, is.SLADays
		if is.DueAt != nil {
			r.DueAt = is.DueAt.UTC()
		}
	}
}
