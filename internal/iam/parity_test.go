package iam

import (
	"path/filepath"
	"testing"
)

// The evaluator must agree with every recorded iam:SimulatePrincipalPolicy result. Until O1
// (a live lab account) the fixtures are authored from AWS documentation examples and say so.
func TestSimulatorParity(t *testing.T) {
	src := DirFixtures(filepath.Join("testdata", "simulator"))
	fixtures, err := src.Fixtures()
	if err != nil {
		t.Fatal(err)
	}
	results := 0
	for _, f := range fixtures {
		if f.Source == "" {
			t.Errorf("fixture %s: source (AWS documentation URL) is required", f.ID)
		}
		if f.Provenance != ProvenanceAuthored && f.Provenance != ProvenanceRecorded {
			t.Errorf("fixture %s: provenance %q", f.ID, f.Provenance)
		}
		results += len(f.Results)
		for _, d := range Replay(f) {
			t.Errorf("disagreement: %s", d)
		}
	}
	if results < 20 {
		t.Fatalf("%d simulator results, want >= 20", results)
	}
	t.Logf("%d fixtures, %d simulator results, 0 disagreements", len(fixtures), results)
}

// Replay reports a disagreement (it does not paper over one).
func TestReplayReportsDisagreement(t *testing.T) {
	f := SimulatorFixture{ID: "neg", Source: "test", Provenance: ProvenanceAuthored, CallerArn: "arn:aws:iam::111111111111:user/u",
		PolicyInputList: []string{`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`},
		Results:         []SimulatorResult{{EvalActionName: "s3:GetObject", EvalResourceName: "arn:aws:s3:::b/k", EvalDecision: "implicitDeny"}}}
	if ds := Replay(f); len(ds) != 1 {
		t.Fatalf("Replay = %v, want one disagreement", ds)
	}
}
