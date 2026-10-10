package mcp

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W6-VERIFY r4 #8: the MCP verify tool evaluates the Issue's current state read-only — what a
// verification would re-read (and with which targeted reader), the last verification, and
// whether the stored evidence already shows the problem gone — instead of only returning the
// command. It never re-collects or writes.
func TestVerifyToolEvaluatesStoredState(t *testing.T) {
	fx := newFixture(t)
	issues, _ := fx.st.Issues(store.IssueFilter{})
	var single, path *model.Issue
	for i := range issues {
		is := &issues[i]
		if is.Kind == model.IssueSingle && single == nil && len(is.FindingIDs) > 0 && is.ResourceID != "" && model.IsActive(is.State) {
			single = is
		}
		if is.Kind == model.IssuePath && path == nil && model.IsActive(is.State) {
			path = is
		}
	}
	if single == nil || path == nil {
		t.Fatal("fixture lacks an open finding Issue or path Issue")
	}
	at := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	if err := fx.st.RecordVerification(store.Verification{IssueID: path.ID, Result: store.VerifyOpen, At: at, VerifiedBy: "rescan", Reads: 1, Required: 3, Reason: "path survives"}); err != nil {
		t.Fatal(err)
	}
	before := dbDigest(t, fx.st)
	c := startServer(t, fx.st, Options{Traversal: labTraversal, NoRedact: true})
	c.initialize()

	out := c.toolOK("verify", map[string]any{"issue_id": path.ID})
	ev, _ := out["evaluation"].(map[string]any)
	if ev == nil || ev["stored_evidence"] != "present" || ev["surviving_paths"].(float64) < 1 {
		t.Fatalf("path Issue evaluation = %v", out["evaluation"])
	}
	lv, _ := out["last_verification"].(map[string]any)
	if lv == nil || lv["result"] != store.VerifyOpen || lv["reason"] != "path survives" {
		t.Errorf("last_verification = %v", out["last_verification"])
	}
	wc, _ := out["would_check"].([]any)
	if len(wc) == 0 {
		t.Fatal("would_check empty")
	}
	readers := 0
	for _, x := range wc {
		m := x.(map[string]any)
		if _, ok := m["reader"]; !ok {
			t.Errorf("would_check entry without reader: %v", m)
		}
		if m["reader"] != "" {
			readers++
		}
	}
	if readers == 0 || out["coverage"] == nil {
		t.Errorf("no targeted reader named for any hop (coverage %v)", out["coverage"])
	}
	if out["mutates"] != false || out["command"] == "" {
		t.Errorf("mutates %v command %v", out["mutates"], out["command"])
	}

	out = c.toolOK("verify", map[string]any{"issue_id": single.ID})
	ev = out["evaluation"].(map[string]any)
	if ev["stored_evidence"] != "present" || ev["failing_findings"].(float64) < 1 {
		t.Errorf("open finding Issue evaluation = %v", ev)
	}
	if out["last_verification"] != nil {
		t.Errorf("never-verified Issue has a last verification: %v", out["last_verification"])
	}

	// A later scan no longer observes the finding: the stored evidence shows it gone (a
	// verification would be expected to confirm), and the call still writes nothing.
	f, err := fx.st.Finding(single.FindingIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.st.ApplyScan("scan-2", nil, at.Add(time.Hour), store.ApplyOptions{Scopes: store.ScopesOf([]model.Finding{*f})}); err != nil {
		t.Fatal(err)
	}
	if err := fx.st.RebuildIssues(at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	before = dbDigest(t, fx.st)
	out = c.toolOK("verify", map[string]any{"issue_id": single.ID})
	ev = out["evaluation"].(map[string]any)
	if ev["stored_evidence"] != "gone" {
		t.Errorf("resolved finding Issue evaluation = %v", ev)
	}
	if dbDigest(t, fx.st) != before {
		t.Errorf("the verify tool changed the database")
	}
}
