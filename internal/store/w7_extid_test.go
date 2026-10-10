package store

import (
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 7 defect 2 (HIGH): a resolved path Issue keeps its raw path ids in issues.path_ids
// but its attack_paths row is gone, so the mapper (findings + attack_paths only) left them raw —
// an offline oracle (account recovered in 0.1 s). Every id an Issue row exposes is keyed from the
// Issue table itself.
func TestMapperKeysIdsOfResolvedPathIssues(t *testing.T) {
	st, _ := openTempPath(t)
	rawPath, rawFinding := "0123456789abcdef", strings.Repeat("c4", 16)
	if _, err := st.db.Exec(`INSERT INTO issues (id, canonical_id, resource_id, severity, state, finding_ids, sources, confidence, kind, path_ids)
	  VALUES ('px', 'PATH', 'r', 'HIGH', 'resolved', ?, '[]', 1, 'path', ?)`, `["`+rawFinding+`"]`, `["`+rawPath+`"]`); err != nil {
		t.Fatal(err)
	}
	m, err := st.IDMapper()
	if err != nil {
		t.Fatal(err)
	}
	if got := m.MapString("paths " + rawPath + " ev " + rawFinding); strings.Contains(got, rawPath) || strings.Contains(got, rawFinding) ||
		!strings.Contains(got, st.ExternalPathID(rawPath)) || !strings.Contains(got, st.ExternalFindingID(rawFinding)) {
		t.Fatalf("resolved path Issue ids not keyed: %q", got)
	}
	if raw, ok := m.Raw(st.ExternalPathID(rawPath)); !ok || raw != rawPath {
		t.Errorf("keyed path id does not resolve back: %q %v", raw, ok)
	}
}

// Verification 7 defect 3 (MED-HIGH): for ~1 s after a reload the mapper returned an unknown
// digest unchanged (fail open), so a session polling during an ingest saw raw fingerprints.
// A digest the mapper has not seen now triggers a reload whenever the id set changed since the
// last one (no time window), and the reload builds the new maps before swapping them in.
func TestMapperHasNoStaleWindow(t *testing.T) {
	st, _ := openTempPath(t)
	m, err := st.IDMapper()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ { // five "ingests" inside one second of the last reload
		f := model.Finding{Source: "prowler", CheckID: "c" + string(rune('a'+i)), Provider: "aws", Account: "123456789012", Status: model.Fail,
			Resource: model.Resource{ID: "arn:aws:s3:::b" + string(rune('a'+i))}}
		f.Finalize(now)
		if _, err := st.ApplyScan("s", []model.Finding{f}, now, ApplyOptions{}); err != nil {
			t.Fatal(err)
		}
		if got := m.MapString("id " + f.ID); strings.Contains(got, f.ID) {
			t.Fatalf("ingest %d: a fresh stored fingerprint came back raw: %q", i, got)
		}
	}
	// An unknown digest still comes back unchanged (not stored: nothing to key, no oracle).
	if unk := strings.Repeat("ab", 16); m.MapString(unk) != unk {
		t.Errorf("unknown digest changed")
	}
}

// The inbound side has no window either: a raw id stored after the mapper loaded is still
// recognised as raw (a redacted session refuses it).
func TestMapperIsRawSeesFreshIDs(t *testing.T) {
	st, _ := openTempPath(t)
	m, _ := st.IDMapper()
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	f := model.Finding{Source: "prowler", CheckID: "x", Provider: "aws", Account: "123456789012", Status: model.Fail, Resource: model.Resource{ID: "arn:aws:s3:::z"}}
	f.Finalize(now)
	st.ApplyScan("s", []model.Finding{f}, now, ApplyOptions{})
	if !m.IsRaw(f.ID) || m.IsRaw(st.ExternalFindingID(f.ID)) || m.IsRaw(strings.Repeat("ab", 16)) {
		t.Fatalf("IsRaw fresh=%v ext=%v unknown=%v", m.IsRaw(f.ID), m.IsRaw(st.ExternalFindingID(f.ID)), m.IsRaw(strings.Repeat("ab", 16)))
	}
}
