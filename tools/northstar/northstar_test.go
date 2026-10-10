package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestSumFixture(t *testing.T) {
	b, err := os.ReadFile("testdata/search.json")
	if err != nil {
		t.Fatal(err)
	}
	var s Summary
	if err := s.Add(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	// 101: 3, 102: 2, 103: 0 (+1 opened), 104: footer over the cap is ignored, duplicate 101 once.
	if s.Closes != 5 || s.Opens != 1 || s.Items != 4 || s.WithFooter != 3 || s.Rejected != 1 {
		t.Fatalf("summary %+v", s)
	}
	if s.Repos["acme/infra"] != 3 || s.Repos["acme/web"] != 2 {
		t.Errorf("per-repo %v", s.Repos)
	}
	var out strings.Builder
	s.Print(&out)
	if !strings.Contains(out.String(), "nimbus-closes-paths total: 5") {
		t.Errorf("print: %s", out.String())
	}
}

func TestRejectsGarbage(t *testing.T) {
	var s Summary
	if err := s.Add(strings.NewReader(`{"items": "x"}`)); err == nil {
		t.Fatal("wrong shape accepted")
	}
	if err := s.Add(strings.NewReader(strings.Repeat("[", 1<<20))); err == nil {
		t.Fatal("garbage accepted")
	}
}

// Shortfall #14: plan-diff comments also carry nimbus-escalates-paths and nimbus-lowers-paths
// (de-escalation credit); both are summed, a lowered path is not a closed one.
func TestSumsEscalatesAndLowers(t *testing.T) {
	var s Summary
	in := `{"items":[
	 {"id":1,"repository_url":"https://api.github.com/repos/acme/infra","body":"<!-- nimbus-plan-diff -->\nnimbus-opens-paths: 0\nnimbus-escalates-paths: 0\nnimbus-lowers-paths: 2\nnimbus-closes-paths: 0\n"},
	 {"id":2,"repository_url":"https://api.github.com/repos/acme/infra","body":"nimbus-opens-paths: 0\r\nnimbus-escalates-paths: 1\r\nnimbus-lowers-paths: 0\r\nnimbus-closes-paths: 0\r\n"},
	 {"id":3,"repository_url":"https://api.github.com/repos/acme/web","body":"quoted inline nimbus-lowers-paths: 50 is not a footer\n"}]}`
	if err := s.Add(strings.NewReader(in)); err != nil {
		t.Fatal(err)
	}
	if s.Lowers != 2 || s.Escalates != 1 || s.Closes != 0 {
		t.Fatalf("summary %+v", s)
	}
	var out strings.Builder
	s.Print(&out)
	if !strings.Contains(out.String(), "nimbus-lowers-paths total: 2") || !strings.Contains(out.String(), "nimbus-escalates-paths total: 1") {
		t.Errorf("print: %s", out.String())
	}
}
