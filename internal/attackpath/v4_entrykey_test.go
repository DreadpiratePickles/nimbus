package attackpath

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Defect 10c (verify-4 D5): two internet paths into one anchor through different public hosts
// share the path Issue id but not the EntryKey, so pathdiff can report the second host.
func TestV4EntryKeyDistinguishesInternetEntries(t *testing.T) {
	mk := func(host string) model.AttackPath {
		return model.AttackPath{RuleID: "GRAPH_TRAVERSAL", Steps: []model.Step{{Relation: "exposes", Resource: host}, {Relation: "runs_as", Resource: "role/r"}}}
	}
	a, b := mk("i-1"), mk("i-2")
	ea, aa, ra := model.PathIssueKey(a)
	eb, ab, rb := model.PathIssueKey(b)
	if model.PathIssueID(model.IssuePath, ea, aa, ra) != model.PathIssueID(model.IssuePath, eb, ab, rb) {
		t.Fatal("precondition: same Issue id")
	}
	ka, _, _ := EntryKey(a)
	kb, _, _ := EntryKey(b)
	if ka == kb || ka != "internet:i-1" || InternetEntryNode(b) != "i-2" {
		t.Errorf("EntryKey %q %q", ka, kb)
	}
	id := model.AttackPath{Steps: []model.Step{{Relation: "entry", Resource: "user/u"}, {Resource: "role/r"}}}
	if InternetEntryNode(id) != "" {
		t.Errorf("identity entry has an internet entry node")
	}
}
