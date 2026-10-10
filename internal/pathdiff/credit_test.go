package pathdiff

import (
	"strings"
	"testing"
)

// Shortfall #14 (competitive delta 2026-10-09 r2): a plan that keeps a path Issue but drops its
// band (revert.plan.json: 7.0 High → 1.9 Low) is a de-escalation. It earns headline credit
// ("lowers N") and never trips the --fail-on-opened gate.
func TestLowersIsABandDrop(t *testing.T) {
	for _, c := range []struct {
		before, after float64
		want          bool
	}{
		{7.0, 1.9, true},  // High → Low (revert.plan.json)
		{9.5, 7.5, true},  // Critical → High
		{5.0, 2.0, true},  // Medium → Low
		{1.9, 7.0, false}, // escalation
		{7.5, 7.0, false}, // inside one band: a score change, not a de-escalation
		{3.0, 3.0, false},
	} {
		if got := Lowers(c.before, c.after); got != c.want {
			t.Errorf("Lowers(%.1f, %.1f) = %v, want %v", c.before, c.after, got, c.want)
		}
	}
}

func TestLoweredNeverTripsTheGate(t *testing.T) {
	r := Result{ChangedScore: []ScoreChange{{Before: 7.0, After: 1.9}, {Before: 7.5, After: 7.0}}}
	if n := len(r.Lowered()); n != 1 {
		t.Fatalf("Lowered() = %d, want 1", n)
	}
	if r.GateTripped(false) || r.GateTripped(true) {
		t.Error("a lowered path tripped the gate")
	}
}

func TestSingleHunk(t *testing.T) {
	before := "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n"
	h, ok := SingleHunk(before, strings.Replace(before, "c\nd\n", "C\nD\nD2\n", 1), 50)
	if !ok || h.Start != 3 || h.End != 4 || strings.Join(h.Lines, ",") != "C,D,D2" {
		t.Fatalf("one-region change: %+v %v", h, ok)
	}
	// a pure insertion is anchored to the preceding line
	h, ok = SingleHunk(before, strings.Replace(before, "c\n", "c\nnew\n", 1), 50)
	if !ok || h.Start != 3 || h.End != 3 || strings.Join(h.Lines, ",") != "c,new" {
		t.Fatalf("insertion: %+v %v", h, ok)
	}
	// two edits far apart are two hunks: no single suggestion
	two := strings.Replace(strings.Replace(before, "b\n", "B\n", 1), "i\n", "I\n", 1)
	if h, ok := SingleHunk(before, two, 50); ok {
		t.Fatalf("two distant edits accepted as one hunk: %+v", h)
	}
	if _, ok := SingleHunk(before, before, 50); ok {
		t.Fatal("no change accepted")
	}
	if _, ok := SingleHunk(before, strings.Replace(before, "c\nd\n", "C\nD\n", 1), 1); ok {
		t.Fatal("hunk larger than the cap accepted")
	}
}

func TestSuggestionFenceOutlastsContent(t *testing.T) {
	for content, want := range map[string]string{
		"plain":                         "```",
		"x = \"```\"":                   "````",
		"````\n## injected\n`````x":     "``````",
		"~~~\n```suggestion\nevil\n```": "````",
	} {
		if got := Fence(content); got != want {
			t.Errorf("Fence(%q) = %q, want %q", content, got, want)
		}
	}
}

// Shortfall #6 (competitive delta r3): a patch with two separated edits (the rewritten rule and
// an appended variable block) is two hunks, each its own one-click suggestion.
func TestHunksSplitsSeparatedEdits(t *testing.T) {
	before := "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n"
	two := strings.Replace(strings.Replace(before, "b\n", "B\n", 1), "i\n", "I\n", 1)
	hs, ok := Hunks(before, two, 50)
	if !ok || len(hs) != 2 {
		t.Fatalf("two distant edits: %+v %v, want 2 hunks", hs, ok)
	}
	if hs[0].Start != 2 || hs[0].End != 2 || strings.Join(hs[0].Lines, ",") != "B" || hs[1].Start != 9 || hs[1].End != 9 || strings.Join(hs[1].Lines, ",") != "I" {
		t.Errorf("hunks %+v", hs)
	}
	// an appended block at the end of the file anchors to the last line
	app := before + "variable \"x\" {\n}\n"
	hs, ok = Hunks(before, strings.Replace(app, "c\n", "C\n", 1), 50)
	if !ok || len(hs) != 2 || hs[1].Start != 10 || hs[1].End != 10 || strings.Join(hs[1].Lines, "|") != "j|variable \"x\" {|}" {
		t.Fatalf("edit + append: %+v %v", hs, ok)
	}
	// edits closer than the gap merge into one hunk carrying the unchanged lines between them
	near := strings.Replace(strings.Replace(before, "b\n", "B\n", 1), "d\n", "D\n", 1)
	hs, ok = Hunks(before, near, 50)
	if !ok || len(hs) != 1 || hs[0].Start != 2 || hs[0].End != 4 || strings.Join(hs[0].Lines, ",") != "B,c,D" {
		t.Fatalf("near edits: %+v %v", hs, ok)
	}
	// SingleHunk agrees: one hunk only
	if _, ok := SingleHunk(before, near, 50); !ok {
		t.Error("SingleHunk refused a one-hunk change")
	}
	// any hunk over the cap refuses the whole patch (never a partial fix)
	big := strings.Replace(before, "i\n", strings.Repeat("x\n", 60), 1)
	if _, ok := Hunks(before, strings.Replace(big, "b\n", "B\n", 1), 50); ok {
		t.Error("a hunk over the cap accepted")
	}
	if _, ok := Hunks(before, before, 50); ok {
		t.Error("no change accepted")
	}
	// applying the hunks bottom-up reproduces the patched file exactly
	for _, after := range []string{two, near, strings.Replace(app, "c\n", "C\n", 1), "z\n" + before} {
		hs, ok := Hunks(before, after, 50)
		if !ok {
			t.Fatalf("refused %q", after)
		}
		if got := ApplyHunks(before, hs); got != after {
			t.Errorf("ApplyHunks = %q, want %q", got, after)
		}
	}
}

// An appended block whose last lines repeat the file's closing braces slides below them (the
// alignment git shows), so the suggestion is anchored to the last line, not mid-resource.
func TestHunksSlidesAppendedBlockToTheEnd(t *testing.T) {
	before := "resource \"a\" \"b\" {\n  tags {\n    x = 1\n  }\n}\n"
	after := before + "\nvariable \"v\" {\n  validation {\n    y = 1\n  }\n}\n"
	hs, ok := Hunks(before, after, 50)
	if !ok || len(hs) != 1 || hs[0].Start != 5 || hs[0].End != 5 || hs[0].Lines[0] != "}" {
		t.Fatalf("appended block: %+v %v, want one hunk anchored to line 5", hs, ok)
	}
	if ApplyHunks(before, hs) != after {
		t.Error("apply mismatch")
	}
}
