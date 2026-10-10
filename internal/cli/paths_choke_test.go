package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// V2 integration (a): `paths --choke` counts rule-chain paths through the node, not only
// traversal paths (`paths` lists both).
func TestChokeCountsRuleChainPaths(t *testing.T) {
	web := "arn:aws:ec2:us-east-1:1:instance/web-1"
	res := &scanResult{
		Analysis: &attackpath.Analysis{ChokePoints: []attackpath.ChokePoint{{NodeID: web, Name: "web-1", Type: "aws_instance", Paths: 1, PathIDs: []string{"t1"}, ClosesN: 1}}},
		Paths: []model.AttackPath{
			{ID: "t1", Name: "traversal", Steps: []model.Step{{Resource: "internet"}, {Resource: web}, {Resource: "db"}}},
			{ID: "r1", RuleID: "R_PUBLIC_IMDS", Name: "rule chain", Steps: []model.Step{{Resource: web}, {Resource: "role"}}},
			{ID: "r2", RuleID: "R_OTHER", Name: "ends at web", Steps: []model.Step{{Resource: "x"}, {Resource: web}}}, // target, not through
			{ID: "r3", RuleID: "R_UNRELATED", Name: "elsewhere", Steps: []model.Step{{Resource: "a"}, {Resource: "b"}}},
		},
	}
	var buf bytes.Buffer
	if err := printChoke(&buf, res, "web-1", "table"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "on 2 path(s); removing it closes 2") || !strings.Contains(buf.String(), "r1") {
		t.Fatalf("rule-chain path not counted:\n%s", buf.String())
	}
	buf.Reset()
	if err := printChoke(&buf, res, web, "json"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ChokePoint attackpath.ChokePoint `json:"choke_point"`
		Paths      []model.AttackPath    `json:"paths"`
	}
	json.Unmarshal(buf.Bytes(), &doc)
	if strings.Join(doc.ChokePoint.PathIDs, ",") != "t1,r1" || len(doc.Paths) != 2 {
		t.Fatalf("json: %+v", doc)
	}
	// a node only rule chains pass through can be drilled into too
	buf.Reset()
	if err := printChoke(&buf, res, "a", "table"); err != nil || !strings.Contains(buf.String(), "on 1 path(s)") {
		t.Fatalf("rule-chain-only node: %v\n%s", err, buf.String())
	}
	if err := printChoke(&buf, res, "nowhere", "table"); err == nil {
		t.Fatal("unknown node must be refused")
	}
}
