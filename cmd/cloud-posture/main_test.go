package main

import "testing"

func TestBuildVersion(t *testing.T) {
	saveV, saveC, saveD := version, commit, date
	t.Cleanup(func() { version, commit, date = saveV, saveC, saveD })

	version, commit, date = "0.1.0-dev", "", ""
	if got := buildVersion(); got != "0.1.0-dev" {
		t.Fatalf("dev build: got %q", got)
	}
	version, commit, date = "0.2.0", "abc1234", "2026-10-09T00:00:00Z"
	if got, want := buildVersion(), "0.2.0 (commit abc1234, built 2026-10-09T00:00:00Z)"; got != want {
		t.Fatalf("release build: got %q want %q", got, want)
	}
	version, commit, date = "0.2.0", "abc1234", ""
	if got, want := buildVersion(), "0.2.0 (commit abc1234)"; got != want {
		t.Fatalf("no date: got %q want %q", got, want)
	}
}
