package pathdiff

import (
	"encoding/json"
	"strings"
	"testing"
)

type prefixKeyer struct{}

func (prefixKeyer) ID(id string) string {
	if id == "" {
		return ""
	}
	return "run-" + strings.Repeat("k", 4) + id[len(id)-2:]
}
func (prefixKeyer) Scheme() string { return "run-keyed" }

// Verification 7 defect 10 (W7-POLISH item 10): a run-keyed diff keys every digest id it
// carries — the Issue ids and also each PathRef's path_ids and finding_ids — so redacted
// `pr-comment --diff-json` holds no raw 16-hex path id.
func TestWithKeyedIDsKeysPathAndFindingIDs(t *testing.T) {
	raw := []string{"533b2edbc4e82881", "0123456789abcdef"}
	fid := "0123456789abcdef0123456789abcdef"
	ref := PathRef{IssueID: "aaaaaaaaaaaaaaaa", PathIDs: raw, FindingIDs: []string{fid}}
	r := Result{Opened: []PathRef{ref}, Closed: []PathRef{ref}, ChangedScore: []ScoreChange{{Path: ref}}, Escalated: []ScoreChange{{Path: ref}},
		Moved: []MovedPath{{From: ref, To: ref}}}
	k := r.WithKeyedIDs(prefixKeyer{})
	b, _ := json.Marshal(k)
	for _, id := range append(raw, fid, "aaaaaaaaaaaaaaaa") {
		if strings.Contains(string(b), id) {
			t.Errorf("keyed result still carries raw id %s: %s", id, b)
		}
	}
	if r.Opened[0].PathIDs[0] != raw[0] || r.Opened[0].FindingIDs[0] != fid {
		t.Error("WithKeyedIDs changed the original result")
	}
	if len(k.Opened[0].PathIDs) != 2 || !strings.HasPrefix(k.Opened[0].PathIDs[0], "run-") {
		t.Errorf("path_ids %v", k.Opened[0].PathIDs)
	}
}
