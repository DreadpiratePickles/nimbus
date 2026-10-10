package store

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// r5 #9: the evidence period reads scan finish times and each finding's failing intervals
// (open/reopened → resolved) from the lifecycle history.
func TestFindingFailIntervalsAndScanTimes(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	a := mkFinding("prowler", "a", "CHECK_A", "arn:aws:s3:::a", model.High)
	trendScan(t, st, "s1", t0, a)                   // a opens
	trendScan(t, st, "s2", t0.Add(24*time.Hour))    // a resolved
	trendScan(t, st, "s3", t0.Add(48*time.Hour), a) // a reopens
	iv, err := st.FindingFailIntervals([]string{a.ID})
	if err != nil {
		t.Fatal(err)
	}
	got := iv[a.ID]
	if len(got) != 2 || !got[0].From.Equal(t0) || !got[0].To.Equal(t0.Add(24*time.Hour)) || !got[1].From.Equal(t0.Add(48*time.Hour)) || !got[1].To.IsZero() {
		t.Fatalf("intervals = %+v", got)
	}
	ts, err := st.ScanTimes(t0, t0.Add(30*time.Hour))
	if err != nil || len(ts) != 2 {
		t.Fatalf("scan times = %v %v", ts, err)
	}
}
