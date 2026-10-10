package governance

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// *store.Store must satisfy HistoryStore without any store edits.
var _ HistoryStore = (*store.Store)(nil)

func ev(id string, sev model.Severity, owner string, sla, grace int, state string, at time.Time) LifecycleEvent {
	return LifecycleEvent{IssueID: id, Severity: sev, Owner: owner, SLADays: sla, GraceDays: grace, State: state, At: at}
}

func metricsFixture() []LifecycleEvent {
	sep := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	aug := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	may := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	return []LifecycleEvent{
		// deliberately out of order
		ev("A", model.Critical, "alice", 7, 0, model.StateResolved, day(3)),
		ev("A", model.Critical, "alice", 7, 0, model.StateOpen, t0),
		ev("B", model.High, "bob", 14, 2, model.StateOpen, sep),
		ev("B", model.High, "bob", 14, 2, model.StateResolved, sep.Add(20*24*time.Hour)),
		ev("B", model.High, "bob", 14, 2, model.StateReopened, t0),
		ev("C", model.High, "", 14, 0, model.StateOpen, day(9)),
		ev("D", model.Medium, "alice", 30, 0, model.StateOpen, aug),
		ev("D", model.Medium, "alice", 30, 0, model.StateSuppressed, aug.Add(4*24*time.Hour)),
		ev("E", model.Critical, "alice", 7, 0, model.StateOpen, day(4)),
		ev("E", model.Critical, "alice", 7, 0, model.StateOpen, day(4).Add(12*time.Hour)), // secondary-key change: no-op
		ev("E", model.Critical, "alice", 7, 0, model.StateResolved, day(5)),
		ev("F", model.Low, "carol", 90, 0, model.StateOpen, may),
		ev("G", model.Info, "carol", 0, 0, model.StateOpen, may),
	}
}

func TestMetrics(t *testing.T) {
	now := day(19) // 2026-10-20
	r := Metrics(metricsFixture(), now)
	d := 24 * time.Hour
	if r.MTTRBySeverity[model.Critical] != 2*d || r.MTTRBySeverity[model.High] != 20*d {
		t.Errorf("MTTR = %v", r.MTTRBySeverity)
	}
	if r.ResolvedBySeverity[model.Critical] != 2 || r.ResolvedBySeverity[model.High] != 1 {
		t.Errorf("resolved = %v", r.ResolvedBySeverity)
	}
	if r.Open != 4 || r.OpenPastDue != 2 || r.OpenPastGrace != 2 || r.Suppressed != 1 {
		t.Errorf("open=%d pastDue=%d pastGrace=%d suppressed=%d", r.Open, r.OpenPastDue, r.OpenPastGrace, r.Suppressed)
	}
	if r.OnTime != 2 || r.Late != 1 || math.Abs(r.OnTimeRate-2.0/3) > 1e-9 {
		t.Errorf("on-time %d late %d rate %v", r.OnTime, r.Late, r.OnTimeRate)
	}
	if !reflect.DeepEqual(r.OverdueByOwner, map[string]int{"bob": 1, "carol": 1}) {
		t.Errorf("overdue by owner = %v", r.OverdueByOwner)
	}
	if !reflect.DeepEqual(r.OpenByOwner, map[string]int{"bob": 1, Unassigned: 1, "carol": 2}) {
		t.Errorf("open by owner = %v", r.OpenByOwner)
	}
	// at an earlier clock B is overdue but inside its grace period
	r = Metrics(metricsFixture(), day(15))
	if r.OpenPastDue != 2 || r.OpenPastGrace != 1 {
		t.Errorf("at 10-16: pastDue=%d pastGrace=%d", r.OpenPastDue, r.OpenPastGrace)
	}
}

func TestMetricsEmptyAndDeterministic(t *testing.T) {
	r := Metrics(nil, t0)
	if r.Open != 0 || r.OnTimeRate != 0 || r.MTTRBySeverity == nil || r.OverdueByOwner == nil {
		t.Errorf("empty = %+v", r)
	}
	a, b := Metrics(metricsFixture(), day(19)), Metrics(metricsFixture(), day(19))
	if !reflect.DeepEqual(a, b) {
		t.Error("Metrics not deterministic")
	}
}

func TestCurrentEpisodeStart(t *testing.T) {
	evs := metricsFixture()
	if got := CurrentEpisodeStart(evs, "B"); !got.Equal(t0) {
		t.Errorf("B episode start = %v", got)
	}
	if got := CurrentEpisodeStart(evs, "A"); !got.IsZero() {
		t.Errorf("A is resolved: want zero, got %v", got)
	}
}

type fakeStore struct {
	issues []model.Issue
	fh     map[string][]store.HistoryEntry
	ph     map[string][]store.PathIssueHistoryEntry
}

func (f *fakeStore) Issues(store.IssueFilter) ([]model.Issue, error) { return f.issues, nil }
func (f *fakeStore) History(fp string) ([]store.HistoryEntry, error) { return f.fh[fp], nil }
func (f *fakeStore) PathIssueHistory(id string) ([]store.PathIssueHistoryEntry, error) {
	return f.ph[id], nil
}

func TestCollectEvents(t *testing.T) {
	res := day(-21)
	fs := &fakeStore{
		issues: []model.Issue{
			{ID: "single", Kind: model.IssueSingle, Severity: model.High, State: model.StateReopened, FindingIDs: []string{"f1", "f2"}, FirstSeen: t0},
			{ID: "path", Kind: model.IssuePath, Severity: model.Critical, State: model.StateResolved, FirstSeen: t0},
			{ID: "legacy", Kind: model.IssueSingle, Severity: model.Low, State: model.StateResolved, FindingIDs: []string{"nohist"}, FirstSeen: day(-30), ResolvedAt: &res},
			{ID: "muted", Kind: model.IssueSingle, Severity: model.Medium, State: model.StateSuppressed, FindingIDs: []string{"nohist2"}, FirstSeen: day(-10), LastSeen: day(-5)},
		},
		fh: map[string][]store.HistoryEntry{
			"f1": {{State: model.StateOpen, At: t0}, {State: model.StateResolved, At: day(2)}, {State: model.StateReopened, At: day(6)}},
			"f2": {{State: model.StateOpen, At: day(1)}, {State: model.StateResolved, At: day(4)}},
		},
		ph: map[string][]store.PathIssueHistoryEntry{
			"path": {{State: model.StateOpen, At: t0}, {State: model.StateOpen, At: day(1), SecondaryKey: "k2"}, {State: model.StateResolved, At: day(3)}},
		},
	}
	assign := func(is model.Issue) Assignment {
		return Assignment{Owner: "own-" + is.ID, SLADays: 7, GraceDays: 1}
	}
	evs, err := CollectEvents(fs, assign)
	if err != nil {
		t.Fatal(err)
	}
	type st struct {
		id, state string
		at        time.Time
	}
	var got []st
	for _, e := range evs {
		got = append(got, st{e.IssueID, e.State, e.At})
		if e.Owner != "own-"+e.IssueID || e.SLADays != 7 || e.GraceDays != 1 {
			t.Errorf("assignment not carried: %+v", e)
		}
	}
	want := []st{
		{"single", model.StateOpen, t0}, {"single", model.StateResolved, day(4)}, {"single", model.StateReopened, day(6)},
		{"path", model.StateOpen, t0}, {"path", model.StateResolved, day(3)},
		{"legacy", model.StateOpen, day(-30)}, {"legacy", model.StateResolved, res},
		{"muted", model.StateOpen, day(-10)}, {"muted", model.StateSuppressed, day(-5)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("events\n got %v\nwant %v", got, want)
	}
	r := Metrics(evs, day(20))
	if r.MTTRBySeverity[model.High] != 4*24*time.Hour || r.MTTRBySeverity[model.Critical] != 3*24*time.Hour {
		t.Errorf("MTTR from collected events = %v", r.MTTRBySeverity)
	}
}
