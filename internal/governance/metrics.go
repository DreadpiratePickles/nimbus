package governance

import (
	"sort"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// LifecycleEvent is one state transition of one Issue, carrying the Issue's current
// governance attribution (severity, owner, SLA, grace).
type LifecycleEvent struct {
	IssueID   string         `json:"issue_id"`
	Severity  model.Severity `json:"severity"`
	Owner     string         `json:"owner"`
	SLADays   int            `json:"sla_days"`   // 0 = no SLA
	GraceDays int            `json:"grace_days"` // days after due before escalation
	State     string         `json:"state"`      // open | reopened | resolved | suppressed
	At        time.Time      `json:"at"`
}

// Report is MTTR / SLA performance computed from lifecycle history. Every open
// episode (open/reopened → resolved) is due SLADays after it started.
type Report struct {
	MTTRBySeverity     map[model.Severity]time.Duration `json:"mttr_by_severity"`     // mean open→resolved per severity
	ResolvedBySeverity map[model.Severity]int           `json:"resolved_by_severity"` // episodes behind MTTR
	Open               int                              `json:"open"`                 // currently open/reopened Issues
	Suppressed         int                              `json:"suppressed"`           // currently suppressed (accepted risk; never overdue)
	// PendingVerification: a fix was marked (PR merge, `issues mark-pending`) and awaits the next
	// scan or verify. The episode continues (its MTTR ends at resolution / verification), but the
	// Issue is not counted open and is never overdue.
	PendingVerification int            `json:"pending_verification"`
	OpenPastDue         int            `json:"open_past_due"`    // open and past due_at
	OpenPastGrace       int            `json:"open_past_grace"`  // open and past due_at + grace
	OnTime              int            `json:"on_time"`          // resolved episodes resolved by their due date
	Late                int            `json:"late"`             // resolved episodes resolved after it
	OnTimeRate          float64        `json:"on_time_rate"`     // OnTime/(OnTime+Late); 0 when none
	OverdueByOwner      map[string]int `json:"overdue_by_owner"` // open past due, by owner (Unassigned for none)
	OpenByOwner         map[string]int `json:"open_by_owner"`
}

// Metrics computes the report at now. Events are grouped by IssueID and ordered by
// time (input order breaks ties); a repeated open state is a no-op; a suppressed
// event closes the episode without counting it as resolved. Severity, owner and SLA
// are read from each Issue's last event. Deterministic for a given input and clock.
func Metrics(history []LifecycleEvent, now time.Time) Report {
	r := Report{
		MTTRBySeverity:     map[model.Severity]time.Duration{},
		ResolvedBySeverity: map[model.Severity]int{},
		OverdueByOwner:     map[string]int{},
		OpenByOwner:        map[string]int{},
	}
	total := map[model.Severity]time.Duration{}
	for _, evs := range groupEvents(history) {
		last := evs[len(evs)-1]
		var start time.Time
		open, suppressed := false, false
		for _, e := range evs {
			switch {
			case model.IsActive(e.State):
				if !open {
					open, suppressed, start = true, false, e.At
				}
			case e.State == model.StatePendingVerification:
				// neither closes nor restarts the episode
			case e.State == model.StateResolved || e.State == model.StateVerifiedFixed:
				if open {
					sev := last.Severity
					total[sev] += e.At.Sub(start)
					r.ResolvedBySeverity[sev]++
					if last.SLADays > 0 {
						if e.At.After(start.Add(days(last.SLADays))) {
							r.Late++
						} else {
							r.OnTime++
						}
					}
				}
				open, suppressed = false, false
			case e.State == model.StateSuppressed:
				open, suppressed = false, true
			}
		}
		switch {
		case open && last.State == model.StatePendingVerification:
			r.PendingVerification++
		case open:
			r.Open++
			owner := OwnerKey(last.Owner)
			r.OpenByOwner[owner]++
			if last.SLADays > 0 {
				due := start.Add(days(last.SLADays))
				if now.After(due) {
					r.OpenPastDue++
					r.OverdueByOwner[owner]++
				}
				if now.After(due.Add(days(last.GraceDays))) {
					r.OpenPastGrace++
				}
			}
		case suppressed:
			r.Suppressed++
		}
	}
	for sev, n := range r.ResolvedBySeverity {
		r.MTTRBySeverity[sev] = total[sev] / time.Duration(n)
	}
	if n := r.OnTime + r.Late; n > 0 {
		r.OnTimeRate = float64(r.OnTime) / float64(n)
	}
	return r
}

// groupEvents groups by IssueID (sorted ids) with each group stable-sorted by time.
func groupEvents(history []LifecycleEvent) [][]LifecycleEvent {
	by := map[string][]LifecycleEvent{}
	var ids []string
	for _, e := range history {
		if _, ok := by[e.IssueID]; !ok {
			ids = append(ids, e.IssueID)
		}
		by[e.IssueID] = append(by[e.IssueID], e)
	}
	sort.Strings(ids)
	out := make([][]LifecycleEvent, 0, len(ids))
	for _, id := range ids {
		evs := by[id]
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].At.Before(evs[j].At) })
		out = append(out, evs)
	}
	return out
}

// CurrentEpisodeStart is when issueID's current open episode began (its last open
// or reopen after a resolution/suppression); zero when it is not open. Pass it as
// Subject.OpenedAt so a reopened Issue gets a fresh SLA clock.
func CurrentEpisodeStart(history []LifecycleEvent, issueID string) time.Time {
	var evs []LifecycleEvent
	for _, e := range history {
		if e.IssueID == issueID {
			evs = append(evs, e)
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].At.Before(evs[j].At) })
	var start time.Time
	open := false
	for _, e := range evs {
		switch {
		case model.IsActive(e.State):
			if !open {
				open, start = true, e.At
			}
		case e.State == model.StatePendingVerification:
			// a pending fix mark does not end the episode: settling it back to open keeps the clock
		default:
			open = false
		}
	}
	if !open {
		return time.Time{}
	}
	return start
}

// HistoryStore is the read side of the store that metrics need. *store.Store
// satisfies it as is.
type HistoryStore interface {
	Issues(store.IssueFilter) ([]model.Issue, error)
	History(fingerprint string) ([]store.HistoryEntry, error)
	PathIssueHistory(id string) ([]store.PathIssueHistoryEntry, error)
}

// CollectEvents turns stored history into LifecycleEvents, one Issue at a time in
// the store's order, attributing each Issue with assign (usually Resolver.Resolve of
// its subject, or the stored owner/due columns once the integration pass adds them).
//
//   - path Issues: path_issue_history rows (repeated open rows from secondary-key
//     changes are dropped);
//   - single/combination Issues: the union of their evidence findings'
//     finding_history — the Issue is open while any evidence finding is active —
//     merged by time with the Issue's own path_issue_history rows (suppress, reopen
//     on suppression expiry), so a reopen starts a fresh clock as for path Issues;
//   - Issues with no history rows: synthesised from first_seen / resolved_at.
//
// A current state of suppressed or resolved that the history does not end in is
// appended (at last_seen / resolved_at), so Metrics sees the Issue as it is now.
func CollectEvents(hs HistoryStore, assign func(model.Issue) Assignment) ([]LifecycleEvent, error) {
	issues, err := hs.Issues(store.IssueFilter{})
	if err != nil {
		return nil, err
	}
	var out []LifecycleEvent
	for _, is := range issues {
		var a Assignment
		if assign != nil {
			a = assign(is)
		}
		mk := func(state string, at time.Time) LifecycleEvent {
			return LifecycleEvent{IssueID: is.ID, Severity: is.Severity, Owner: a.Owner, SLADays: a.SLADays, GraceDays: a.GraceDays, State: state, At: at}
		}
		var evs []LifecycleEvent
		if is.Kind == model.IssuePath {
			rows, err := hs.PathIssueHistory(is.ID)
			if err != nil {
				return nil, err
			}
			for _, h := range rows {
				evs = appendTransition(evs, mk(h.State, h.At))
			}
		} else {
			type fe struct {
				fp    string
				state string
				at    time.Time
			}
			var all []fe
			for _, fp := range is.FindingIDs {
				rows, err := hs.History(fp)
				if err != nil {
					return nil, err
				}
				for _, h := range rows {
					all = append(all, fe{fp, h.State, h.At})
				}
			}
			sort.SliceStable(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
			// The Issue's own transitions (suppressed, reopened on suppression expiry, verified)
			// are recorded in path_issue_history under its id (verify-4 D3); its evidence
			// findings' history cannot show them. Merge both streams by time; on a tie the
			// finding transition goes first.
			type ev struct {
				state string
				at    time.Time
			}
			var merged []ev
			active := map[string]bool{}
			for _, x := range all {
				was := len(active) > 0
				if model.IsActive(x.state) {
					active[x.fp] = true
				} else {
					delete(active, x.fp)
				}
				switch now := len(active) > 0; {
				case !was && now:
					merged = append(merged, ev{model.StateOpen, x.at})
				case was && !now:
					merged = append(merged, ev{x.state, x.at})
				}
			}
			own, err := hs.PathIssueHistory(is.ID)
			if err != nil {
				return nil, err
			}
			nFinding := len(merged)
			for _, h := range own {
				merged = append(merged, ev{h.State, h.At})
			}
			if len(own) > 0 {
				idx := make([]int, len(merged))
				for i := range idx {
					idx[i] = i
				}
				sort.SliceStable(idx, func(a, b int) bool {
					ta, tb := merged[idx[a]].at, merged[idx[b]].at
					if !ta.Equal(tb) {
						return ta.Before(tb)
					}
					return idx[a] < nFinding && idx[b] >= nFinding
				})
				sorted := make([]ev, len(merged))
				for i, j := range idx {
					sorted[i] = merged[j]
				}
				merged = sorted
			}
			for _, e := range merged {
				evs = appendTransition(evs, mk(e.state, e.at))
			}
		}
		if len(evs) == 0 && !is.FirstSeen.IsZero() {
			evs = append(evs, mk(model.StateOpen, is.FirstSeen))
		}
		evs = reconcileState(evs, is, mk)
		out = append(out, evs...)
	}
	return out, nil
}

// appendTransition appends e, renaming an open after a closed episode to reopened and
// dropping an active state when the Issue is already active.
func appendTransition(evs []LifecycleEvent, e LifecycleEvent) []LifecycleEvent {
	// pending_verification continues the episode it was marked in (an open after it is a no-op).
	active := len(evs) > 0 && (model.IsActive(evs[len(evs)-1].State) || evs[len(evs)-1].State == model.StatePendingVerification)
	if model.IsActive(e.State) {
		if active {
			return evs
		}
		if len(evs) > 0 {
			e.State = model.StateReopened
		} else {
			e.State = model.StateOpen
		}
	} else if len(evs) > 0 && evs[len(evs)-1].State == e.State {
		return evs
	}
	return append(evs, e)
}

func reconcileState(evs []LifecycleEvent, is model.Issue, mk func(string, time.Time) LifecycleEvent) []LifecycleEvent {
	if len(evs) == 0 {
		return evs
	}
	lastState := evs[len(evs)-1].State
	lastAt := evs[len(evs)-1].At
	at := func(t time.Time) time.Time {
		if t.IsZero() || t.Before(lastAt) {
			return lastAt
		}
		return t
	}
	switch {
	case is.State == model.StateSuppressed && lastState != model.StateSuppressed:
		return append(evs, mk(model.StateSuppressed, at(is.LastSeen)))
	case is.State == model.StateResolved && model.IsActive(lastState):
		var t time.Time
		if is.ResolvedAt != nil {
			t = *is.ResolvedAt
		}
		return append(evs, mk(model.StateResolved, at(t)))
	case is.State == model.StateVerifiedFixed && lastState != model.StateVerifiedFixed:
		var t time.Time
		if is.VerifiedAt != nil {
			t = *is.VerifiedAt
		}
		return append(evs, mk(model.StateVerifiedFixed, at(t)))
	case is.State == model.StatePendingVerification && model.IsActive(lastState):
		var t time.Time
		if is.PendingAt != nil {
			t = *is.PendingAt
		}
		return append(evs, mk(model.StatePendingVerification, at(t)))
	}
	return evs
}
