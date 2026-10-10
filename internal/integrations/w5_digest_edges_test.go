package integrations

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Verify-4/5 D7: the dedup window defaults to the schedule period, so a weekly cron that fires a
// little earlier than last week (scheduler jitter) must still re-send an unchanged digest instead
// of skipping it for a whole extra period. Inside the window (well before the next run) it stays
// deduplicated.
func TestDedupWindowToleratesSchedulerJitter(t *testing.T) {
	d := BuildDigests(digestFixture(), DigestOptions{Now: dNow, Since: dSince})[1]
	l := NewMemoryLedger()
	week := 7 * 24 * time.Hour
	if err := l.Record(d.Key, d.Fingerprint(), dNow); err != nil {
		t.Fatal(err)
	}
	for _, early := range []time.Duration{0, time.Second, 5 * time.Minute, 59 * time.Minute} {
		if !ShouldSend(d, l, week, dNow.Add(week-early)) {
			t.Errorf("weekly run %v early: unchanged digest skipped for a whole extra week", early)
		}
	}
	for _, at := range []time.Duration{time.Hour, 24 * time.Hour, 6 * 24 * time.Hour} {
		if ShouldSend(d, l, week, dNow.Add(at)) {
			t.Errorf("unchanged digest re-sent %v after the last send (inside the window)", at)
		}
	}
	// a short window gets a proportional tolerance (10%), never a zero window
	if ShouldSend(d, l, time.Hour, dNow.Add(50*time.Minute)) || !ShouldSend(d, l, time.Hour, dNow.Add(55*time.Minute)) {
		t.Error("1h window: tolerance is not 10% of the window")
	}
}

// Verify-4/5 clip LOW: clip cut bytes, so a multi-byte rune at the cut left U+FFFD and the
// result could exceed Slack's character limit semantics. clip counts runes and never splits one.
func TestClipIsRuneSafe(t *testing.T) {
	for pad := 0; pad < 4; pad++ {
		s := strings.Repeat("a", pad) + strings.Repeat("—é", 2000)
		c := clip(s, 3000)
		if !utf8.ValidString(c) || strings.ContainsRune(c, utf8.RuneError) {
			t.Fatalf("pad %d: clipped text has an invalid / replacement rune", pad)
		}
		if n := utf8.RuneCountInString(c); n != 3000 || !strings.HasSuffix(c, "...") {
			t.Fatalf("pad %d: clipped to %d runes, want 3000 ending in ...", pad, n)
		}
	}
	if clip("short", 3000) != "short" || clip(strings.Repeat("é", 150), 150) != strings.Repeat("é", 150) {
		t.Error("text within the limit must be unchanged")
	}
}
