package governance

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W5-ISSUES item 1: verified_fixed closes an episode like resolved (it counts toward MTTR and
// on-time), pending_verification neither closes nor restarts it, and a pending Issue is not open.
func TestMetricsClosureStates(t *testing.T) {
	d := 24 * time.Hour
	evs := []LifecycleEvent{
		ev("V", model.Critical, "alice", 7, 0, model.StateOpen, t0),
		ev("V", model.Critical, "alice", 7, 0, model.StateVerifiedFixed, t0.Add(3*d)),
		ev("P", model.High, "bob", 14, 0, model.StateOpen, t0),
		ev("P", model.High, "bob", 14, 0, model.StatePendingVerification, t0.Add(2*d)),
		ev("Q", model.High, "bob", 14, 0, model.StateOpen, t0),
		ev("Q", model.High, "bob", 14, 0, model.StatePendingVerification, t0.Add(2*d)),
		ev("Q", model.High, "bob", 14, 0, model.StateOpen, t0.Add(3*d)), // fix did not take
	}
	r := Metrics(evs, t0.Add(5*d))
	if r.ResolvedBySeverity[model.Critical] != 1 || r.MTTRBySeverity[model.Critical] != 3*d || r.OnTime != 1 {
		t.Errorf("verified_fixed must close the episode: resolved %v mttr %v on-time %d", r.ResolvedBySeverity, r.MTTRBySeverity, r.OnTime)
	}
	if r.Open != 1 || r.PendingVerification != 1 {
		t.Errorf("open %d pending %d, want 1/1", r.Open, r.PendingVerification)
	}
	// Q's SLA clock did not restart when the pending mark was settled.
	if s := CurrentEpisodeStart(evs, "Q"); !s.Equal(t0) {
		t.Errorf("episode start %v, want %v", s, t0)
	}
	// appendTransition keeps one episode across pending → open.
	var got []LifecycleEvent
	for _, e := range evs[4:] {
		got = appendTransition(got, e)
	}
	if len(got) != 2 || got[1].State != model.StatePendingVerification {
		t.Errorf("transitions %+v", got)
	}
}
